package main

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type setupTransport func(*http.Request) (*http.Response, error)

func (f setupTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSetupURLPolicy(t *testing.T) {
	for _, raw := range []string{"javascript:alert(1)", "http://login.example", "https://user:pass@login.example", "//login.example"} {
		if safeLoginURL(raw) {
			t.Fatal(raw)
		}
	}
	if !safeLoginURL("https://login.example/authorize?state=test") {
		t.Fatal("valid URL rejected")
	}
}

func TestSetupSessionBindingAndCSRF(t *testing.T) {
	u, _ := url.Parse("http://backend.example")
	var logs bytes.Buffer
	g := &gateway{log: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})), sessions: map[string]*session{"session": {CSRF: "csrf", Expires: time.Now().Add(time.Hour)}}, upstreams: map[string]*upstream{"test": {Name: "test", URL: u, Token: "internal"}}}
	// Use a hashed cookie session key, as production does.
	g.sessions[sha("cookie")] = g.sessions["session"]
	old := upstreamHTTP
	defer func() { upstreamHTTP = old }()
	calls := 0
	upstreamHTTP = &http.Client{Transport: setupTransport(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer internal" {
			t.Fatal("wrong internal token")
		}
		body := `{"name":"test","setup":{"status":"login_required"}}`
		if r.URL.Path == "/setup/start" {
			body = fmt.Sprintf(`{"attempt_id":"attempt","authorization_url":"https://login.example/authorize","expires_at":%d}`, time.Now().Add(5*time.Minute).Unix())
		}
		if r.URL.Path == "/setup/complete" {
			calls++
			body = `{"ok":true}`
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	send := func(action, csrf, cookie string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://gateway.example/admin/u/test/setup/"+action, strings.NewReader(url.Values{"csrf": {csrf}, "attempt_id": {"attempt"}, "input": {"sensitive-return"}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
		}
		r.SetPathValue("name", "test")
		r.SetPathValue("action", action)
		w := httptest.NewRecorder()
		g.accessLog(http.HandlerFunc(g.handleSetup)).ServeHTTP(w, r)
		return w
	}
	send("start", "wrong", "cookie")
	if _, ok := g.setupAttempts.Load("test:attempt"); ok {
		t.Fatal("CSRF accepted")
	}
	send("start", "csrf", "")
	if _, ok := g.setupAttempts.Load("test:attempt"); ok {
		t.Fatal("anonymous accepted")
	}
	w := send("start", "csrf", "cookie")
	if !strings.Contains(w.Body.String(), "Opne innlogging") {
		t.Fatal(w.Body.String())
	}
	g.sessions[sha("other-cookie")] = &session{CSRF: "other-csrf", Expires: time.Now().Add(time.Hour)}
	send("complete", "other-csrf", "other-cookie")
	if calls != 0 {
		t.Fatal("cross-session completion accepted")
	}
	send("complete", "csrf", "cookie")
	send("complete", "csrf", "cookie")
	if strings.Contains(logs.String(), "sensitive-return") || strings.Contains(logs.String(), "login.example/authorize") {
		t.Fatal("setup data leaked into logs")
	}
	if calls != 1 {
		t.Fatalf("complete calls=%d", calls)
	}
}

// A failed completion shows the gateway's own text for known error codes,
// and never text from the backend, which could echo the pasted input.
func TestSetupErrorCodes(t *testing.T) {
	cases := []struct{ code, want string }{
		{"authorize_url_pasted", "Du limte inn innloggingslenka"},
		{"state_mismatch", "anna innloggingsforsøk"},
		{"exchange_failed", "godtok ikkje koden"},
		{"something_new", "Login failed. Check the settings and start again."},
		{"", "Login failed. Check the settings and start again."},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			u, _ := url.Parse("http://backend.example")
			g := &gateway{log: slog.New(slog.NewTextHandler(io.Discard, nil)),
				sessions:  map[string]*session{sha("cookie"): {CSRF: "csrf", Expires: time.Now().Add(time.Hour)}},
				upstreams: map[string]*upstream{"test": {Name: "test", URL: u, Token: "internal"}}}
			old := upstreamHTTP
			defer func() { upstreamHTTP = old }()
			upstreamHTTP = &http.Client{Transport: setupTransport(func(r *http.Request) (*http.Response, error) {
				code, body := 200, `{"name":"test","setup":{"status":"login_required"}}`
				if r.URL.Path == "/setup/complete" {
					code, body = 400, fmt.Sprintf(`{"error":"echo sensitive-return","code":%q}`, tc.code)
				}
				return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			g.setupAttempts.Store("test:attempt", boundSetup{"test", "csrf", time.Now().Add(time.Minute)})
			r := httptest.NewRequest("POST", "http://gateway.example/admin/u/test/setup/complete", strings.NewReader(url.Values{"csrf": {"csrf"}, "attempt_id": {"attempt"}, "input": {"sensitive-return"}}.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "cookie"})
			r.SetPathValue("name", "test")
			r.SetPathValue("action", "complete")
			w := httptest.NewRecorder()
			g.handleSetup(w, r)
			page := w.Body.String()
			if !strings.Contains(page, tc.want) {
				t.Fatalf("missing %q in page", tc.want)
			}
			if strings.Contains(page, "sensitive-return") {
				t.Fatal("backend error text or pasted input shown")
			}
		})
	}
}
