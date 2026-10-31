package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const logBodyLimit = 1 << 20

type statusWriter struct {
	http.ResponseWriter
	code    int
	bytes   int
	capture bool
	body    []byte
}

func (s *statusWriter) WriteHeader(c int) {
	if s.code != 0 {
		return
	}
	s.ResponseWriter.WriteHeader(c)
	if c >= 200 {
		s.code = c
	}
}
func (s *statusWriter) Write(b []byte) (int, error) {
	if s.code == 0 {
		s.WriteHeader(http.StatusOK)
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	if s.capture && len(s.body) < logBodyLimit+1 {
		take := min(n, logBodyLimit+1-len(s.body))
		s.body = append(s.body, b[:take]...)
	}
	return n, err
}
func (s *statusWriter) Flush() {
	if s.code == 0 {
		s.WriteHeader(http.StatusOK)
	}
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// loggedBody only logs complete JSON or SSE JSON events. OAuth bodies, headers,
// malformed bodies and oversized bodies are omitted to avoid exposing credentials.
func loggedBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	if len(body) > logBodyLimit {
		return "[omitted: body exceeds 1 MiB]"
	}
	var v any
	if json.Unmarshal(body, &v) == nil {
		redactLogValue(v)
		out, _ := json.Marshal(v)
		return string(out)
	}
	// MCP may return JSON-RPC messages over server-sent events.
	lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
	var events []string
	var data []string
	flush := func() bool {
		if len(data) == 0 {
			return true
		}
		var event any
		if json.Unmarshal([]byte(strings.Join(data, "\n")), &event) != nil {
			return false
		}
		redactLogValue(event)
		out, _ := json.Marshal(event)
		events = append(events, string(out))
		data = nil
		return true
	}
	for _, line := range lines {
		if line == "" {
			if !flush() {
				return "[omitted: non-JSON body]"
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			continue
		}
		if strings.HasPrefix(line, ":") || strings.HasPrefix(line, "event:") || strings.HasPrefix(line, "id:") || strings.HasPrefix(line, "retry:") {
			continue
		}
		return "[omitted: non-JSON body]"
	}
	if !flush() || len(events) == 0 {
		return "[omitted: non-JSON body]"
	}
	return strings.Join(events, "\n")
}

func redactLogValue(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, value := range x {
			key := strings.NewReplacer("-", "", "_", "", " ", "").Replace(strings.ToLower(k))
			if strings.Contains(key, "token") || strings.Contains(key, "password") || strings.Contains(key, "secret") || strings.Contains(key, "authorization") || strings.Contains(key, "cookie") || key == "apikey" || key == "codeverifier" {
				x[k] = "[REDACTED]"
			} else {
				redactLogValue(value)
			}
		}
	case []any:
		for _, value := range x {
			redactLogValue(value)
		}
	}
}

// accessLog logs request metadata at INFO and redacted MCP bodies at DEBUG.
func (g *gateway) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		mcp := strings.HasSuffix(p, "/mcp") && !strings.HasPrefix(p, "/.well-known/")
		if !(mcp || strings.HasPrefix(p, "/oauth/") || strings.HasPrefix(p, "/.well-known/")) {
			next.ServeHTTP(w, r)
			return
		}
		debug := mcp && g.log.Enabled(r.Context(), slog.LevelDebug)
		rpc, requestBody := "", ""
		if mcp && r.Body != nil {
			original := r.Body
			body, _ := io.ReadAll(io.LimitReader(original, logBodyLimit+1))
			// Replay the prefix and preserve the remainder, including Close propagation.
			r.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(bytes.NewReader(body), original), original}
			if debug {
				requestBody = loggedBody(body)
			}
			var m struct {
				Method string `json:"method"`
			}
			if json.Unmarshal(body, &m) == nil {
				rpc = m.Method
			}
		}
		sw := &statusWriter{ResponseWriter: w, capture: debug}
		span := trace.SpanFromContext(r.Context())
		if rpc != "" {
			span.SetAttributes(attribute.String("rpc.system.name", "jsonrpc"), attribute.String("rpc.method", rpc))
		}
		start := time.Now()
		next.ServeHTTP(sw, r)
		if sw.code == 0 {
			sw.code = http.StatusOK
		}
		attrs := []any{"method", r.Method, "path", p, "rpc", rpc, "status", sw.code, "bytes", sw.bytes,
			"ms", time.Since(start).Milliseconds(), "auth", r.Header.Get("Authorization") != "", "ua", r.UserAgent()}
		if sc := span.SpanContext(); sc.IsValid() {
			attrs = append(attrs, "trace_id", sc.TraceID().String(), "span_id", sc.SpanID().String())
		}
		g.log.InfoContext(r.Context(), "request", attrs...)
		if debug {
			attrs = append(attrs, "request_body", requestBody, "response_body", loggedBody(sw.body))
			g.log.DebugContext(r.Context(), "mcp bodies", attrs...)
		}
	})
}
