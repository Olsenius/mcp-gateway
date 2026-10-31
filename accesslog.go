package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

type statusWriter struct {
	http.ResponseWriter
	code  int
	bytes int
}

func (s *statusWriter) WriteHeader(c int) { s.code = c; s.ResponseWriter.WriteHeader(c) }
func (s *statusWriter) Write(b []byte) (int, error) {
	if s.code == 0 {
		s.code = 200
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}
func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// accessLog logs OAuth and MCP requests: method, path, JSON-RPC method,
// status and time. Tokens and bodies are never logged.
func (g *gateway) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if !(strings.HasSuffix(p, "/mcp") || strings.HasPrefix(p, "/oauth/") || strings.HasPrefix(p, "/.well-known/")) {
			next.ServeHTTP(w, r)
			return
		}
		rpc := ""
		if r.Method == http.MethodPost && strings.HasSuffix(p, "/mcp") && r.Body != nil {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			r.Body = io.NopCloser(bytes.NewReader(body))
			var m struct {
				Method string `json:"method"`
			}
			if json.Unmarshal(body, &m) == nil {
				rpc = m.Method
			}
		}
		sw := &statusWriter{ResponseWriter: w}
		start := time.Now()
		next.ServeHTTP(sw, r)
		g.log.Info("request", "method", r.Method, "path", p, "rpc", rpc, "status", sw.code, "bytes", sw.bytes,
			"ms", time.Since(start).Milliseconds(), "auth", r.Header.Get("Authorization") != "", "ua", r.UserAgent())
	})
}
