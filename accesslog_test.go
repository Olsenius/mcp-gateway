package main

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccessLogBodies(t *testing.T) {
	var logs bytes.Buffer
	g := &gateway{log: slog.New(slog.NewJSONHandler(&logs, nil))}
	request := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"access_token":"request-secret"}}`
	response := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"Unknown method\"},\"refresh_token\":\"response-secret\"}\n\n"
	handler := g.accessLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != request {
			t.Errorf("request altered: %s", body)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush()
		io.WriteString(w, response)
	}))
	req := httptest.NewRequest("POST", "/bibliofil/mcp", strings.NewReader(request))
	req.Header.Set("Authorization", "Bearer header-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Body.String() != response {
		t.Fatal("response altered")
	}
	log := logs.String()
	for _, secret := range []string{"request-secret", "response-secret", "header-secret"} {
		if strings.Contains(log, secret) {
			t.Errorf("secret leaked: %s", secret)
		}
	}
	for _, expected := range []string{"request_body", "response_body", "server/discover", "Unknown method", "-32601", "REDACTED"} {
		if !strings.Contains(log, expected) {
			t.Errorf("missing %q: %s", expected, log)
		}
	}
}

func TestAccessLogLargeRequestAndOAuth(t *testing.T) {
	for _, path := range []string{"/bibliofil/mcp", "/oauth/token"} {
		t.Run(path, func(t *testing.T) {
			var logs bytes.Buffer
			g := &gateway{log: slog.New(slog.NewJSONHandler(&logs, nil))}
			body := strings.Repeat("x", logBodyLimit+100)
			handler := g.accessLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got, _ := io.ReadAll(r.Body)
				if string(got) != body {
					t.Fatalf("body truncated: got %d want %d", len(got), len(body))
				}
				io.WriteString(w, `{"access_token":"oauth-secret"}`)
			}))
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", path, strings.NewReader(body)))
			if strings.Contains(logs.String(), "oauth-secret") {
				t.Fatal("token leaked")
			}
			if path == "/oauth/token" && strings.Contains(logs.String(), "response_body") {
				t.Fatal("OAuth body logged")
			}
		})
	}
}

func TestLoggedBodyRedaction(t *testing.T) {
	got := loggedBody([]byte(`{"params":{"api-key":"secret","nested":[{"client_secret":"secret","password":"secret"}]},"error":{"code":-32601}}`))
	if strings.Contains(got, `:"secret"`) || !strings.Contains(got, "-32601") {
		t.Fatal(got)
	}
	for _, body := range []string{"not json", `{"access_token":"truncated`, strings.Repeat("x", logBodyLimit+1)} {
		if !strings.HasPrefix(loggedBody([]byte(body)), "[omitted:") {
			t.Fatal("unsafe body logged")
		}
	}
}
