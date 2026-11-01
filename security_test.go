package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMetadataAddressPolicy(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "100.100.100.100", "100.127.255.254", "::ffff:100.64.0.1", "::1", "fd7a:115c:a1e0::1", "0.1.2.3", "198.18.0.1", "64:ff9b::a00:1"} {
		if publicMetadataIP(net.ParseIP(s)) {
			t.Errorf("unsafe address accepted: %s", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !publicMetadataIP(net.ParseIP(s)) {
			t.Errorf("public address rejected: %s", s)
		}
	}
}

func TestMetadataTransportRejectsNonPublicAddress(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "100.64.0.1", "[::ffff:100.64.0.1]"} {
		resp, err := safeHTTP.Get("https://" + host + "/client.json")
		if resp != nil {
			resp.Body.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "refusing to fetch from a non-public address") {
			t.Fatalf("%s: expected address-policy rejection, got %v", host, err)
		}
	}
}
func TestTrustedClientIP(t *testing.T) {
	prefixes, err := parseTrustedProxies("127.0.0.1/32, 10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	g := &gateway{trustedProxies: prefixes}
	for _, tc := range []struct{ remote, forwarded, want string }{
		{"192.0.2.1:123", "1.2.3.4", "192.0.2.1"},
		{"127.0.0.1:123", "1.2.3.4, 192.0.2.1, 10.0.0.2", "192.0.2.1"},
		{"127.0.0.1:123", "bad", "127.0.0.1"},
		{"[::ffff:127.0.0.1]:123", "192.0.2.1", "192.0.2.1"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remote
		r.Header.Set("X-Forwarded-For", tc.forwarded)
		if got := g.clientIP(r); got != tc.want {
			t.Errorf("got %s want %s", got, tc.want)
		}
	}
}
func TestLoginCannotGloballyLockOutAdmin(t *testing.T) {
	g := &gateway{adminPW: strings.Repeat("p", 40), limiter: newLimiter()}
	for i := 0; i < 100; i++ {
		g.limiter.fail(fmt.Sprint(i))
	}
	for i := 0; i < 10; i++ {
		g.limiter.fail("192.0.2.1")
	}
	r := httptest.NewRequest("POST", "/admin/login", nil)
	r.RemoteAddr = "192.0.2.1:123"
	if ok, _ := g.checkAdmin(r, g.adminPW); !ok {
		t.Fatal("correct password locked out")
	}
	if !g.limiter.blocked("192.0.2.1") || g.limiter.blocked("192.0.2.2") {
		t.Fatal("per-IP isolation broken")
	}
}
func TestRegistrationLimitsAndExpiry(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	g := &gateway{log: log, store: openStore("", log), limiter: newLimiter()}
	for i := 0; i < 6; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(`{"redirect_uris":["https://example.com/callback"]}`))
		r.Header.Set("X-Forwarded-For", fmt.Sprint(i))
		g.handleRegister(w, r)
		want := 201
		if i == 5 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("request %d: got %d", i, w.Code)
		}
	}
	old := time.Now().Add(-2 * time.Hour)
	g.store.update(func(p *persisted) {
		p.Clients["pending"] = &client{Created: old}
		p.Clients["approved"] = &client{Created: old, Approved: true}
		p.Clients["legacy-used"] = &client{Created: old, LastUsed: old}
		p.Clients["manual"] = &client{Created: old, Manual: true}
	})
	g.store.read(func(p *persisted) {
		if p.Clients["pending"] != nil || p.Clients["approved"] == nil || p.Clients["legacy-used"] == nil || p.Clients["manual"] == nil {
			t.Fatal("client expiry policy failed")
		}
	})
}

type forbiddenBody struct{ t *testing.T }

func (b forbiddenBody) Read([]byte) (int, error) {
	b.t.Error("unauthenticated body consumed")
	return 0, io.EOF
}
func (b forbiddenBody) Close() error { return nil }
func TestUnauthorizedBodyNeverRead(t *testing.T) {
	up := fakeUpstream(t, "secret")
	defer up.Close()
	g, srv := newTestGateway(t, up.URL, "secret", strings.Repeat("p", 40))
	defer srv.Close()
	r := httptest.NewRequest("POST", "/fake/mcp", nil)
	r.Body = forbiddenBody{t}
	w := httptest.NewRecorder()
	g.routes().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
}
func TestAdminPasswordMustBeRetrievable(t *testing.T) {
	t.Setenv("ADMIN_PASSWORD", "")
	if _, _, err := adminPassword(""); err == nil {
		t.Fatal("unretrievable in-memory password accepted")
	}
}

func TestRequestReadTimeoutPreservesStreaming(t *testing.T) {
	g := &gateway{}
	config := g.httpServer()
	if config.ReadTimeout != 30*time.Second || config.WriteTimeout != 0 {
		t.Fatal("request/read timeout policy changed")
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, "timed out", 408)
			return
		}
		io.WriteString(w, "first")
		w.(http.Flusher).Flush()
		time.Sleep(150 * time.Millisecond)
		io.WriteString(w, "last")
	}))
	srv.Config.ReadTimeout = 50 * time.Millisecond
	srv.Start()
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "firstlast" {
		t.Fatalf("stream interrupted: %s %v", body, err)
	}
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 100\r\n\r\nx")
	reply := make([]byte, 4096)
	n, err := conn.Read(reply)
	if err != nil || !strings.Contains(string(reply[:n]), "408") {
		t.Fatalf("slow body not rejected: %s %v", reply[:n], err)
	}
}

func TestRegistrationGlobalBudget(t *testing.T) {
	l := newLimiter()
	for i := 0; i < 60; i++ {
		if !l.allowRegistration(fmt.Sprint(i / 5)) {
			t.Fatalf("budget rejected at %d", i)
		}
	}
	if l.allowRegistration("fresh") {
		t.Fatal("global budget bypassed")
	}
	l.mu.Lock()
	for i := range l.registrationGlobal {
		l.registrationGlobal[i] = time.Now().Add(-2 * time.Hour)
	}
	l.mu.Unlock()
	if !l.allowRegistration("fresh") {
		t.Fatal("global budget never expires")
	}
}

func TestRegistrationCapacityConcurrent(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	g := &gateway{log: log, store: openStore("", log), limiter: newLimiter()}
	if err := g.store.update(func(p *persisted) {
		for i := 0; i < 199; i++ {
			p.Clients[fmt.Sprint(i)] = &client{Manual: true}
		}
	}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	statuses := make(chan int, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(`{"redirect_uris":["https://example.com/callback"]}`))
			r.RemoteAddr = fmt.Sprintf("192.0.2.%d:123", i+1)
			g.handleRegister(w, r)
			statuses <- w.Code
		}(i)
	}
	wg.Wait()
	close(statuses)
	created := 0
	for code := range statuses {
		if code == http.StatusCreated {
			created++
		} else if code != http.StatusTooManyRequests {
			t.Errorf("unexpected status: %d", code)
		}
	}
	if created != 1 {
		t.Fatalf("created %d clients with only one slot available", created)
	}
	g.store.read(func(p *persisted) {
		if len(p.Clients) != 200 {
			t.Fatalf("capacity exceeded: %d", len(p.Clients))
		}
	})
}

func TestExpiredClientLookup(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	g := &gateway{store: openStore("", log)}
	// Model stale state loaded from disk, before any update has pruned it.
	g.store.st.Clients["c_expired"] = &client{Created: time.Now().Add(-2 * time.Hour)}
	if _, err := g.lookupClient(context.Background(), "c_expired"); err == nil {
		t.Fatal("expired registration accepted before cleanup")
	}
}

func TestRequestCaptureConcurrentSnapshot(t *testing.T) {
	body := strings.Repeat("x", logBodyLimit+100)
	c := &requestCapture{ReadCloser: io.NopCloser(strings.NewReader(body))}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	}()
	for i := 0; i < 100; i++ {
		snapshot := c.snapshot()
		if len(snapshot) > logBodyLimit+1 {
			t.Fatal("capture exceeds limit")
		}
	}
	<-done
	if got := c.snapshot(); string(got) != body[:logBodyLimit+1] {
		t.Fatal("captured prefix changed")
	}
}
