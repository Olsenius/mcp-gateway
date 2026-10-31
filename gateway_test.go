package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// fakeUpstream is an MCP server that follows the gateway contract.
func fakeUpstream(t *testing.T, token string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	auth := func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer "+token }
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("check") == "" {
			w.Write([]byte("ok"))
			return
		}
		if !auth(r) {
			w.WriteHeader(401)
			return
		}
		writeJSON(w, 200, health{OK: true, Status: "ok", Checks: []check{{Name: "login", OK: true}}})
	})
	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			w.WriteHeader(401)
			return
		}
		writeJSON(w, 200, configDoc{Name: "fake", Configured: true, Fields: []field{{Key: "FOO", Label: "Foo", Type: "text"}}})
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			w.WriteHeader(401)
			return
		}
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	})
	return httptest.NewServer(mux)
}

func newTestGateway(t *testing.T, upURL, upToken, adminPW string) (*gateway, *httptest.Server) {
	t.Helper()
	t.Setenv("UPSTREAM_TOKEN", upToken)
	ups, order, err := parseUpstreams("fake=" + upURL)
	if err != nil {
		t.Fatal(err)
	}
	g := &gateway{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)), store: openStore("", slog.New(slog.NewTextHandler(io.Discard, nil))),
		adminEnv: adminPW, upstreams: ups, order: order, accessTTL: time.Hour, refreshTT: time.Hour,
		sessions: map[string]*session{}, tokens: map[string]accessToken{}, pending: map[string]*pendingAuth{},
		codes: map[string]*authCode{}, limiter: newLimiter(),
	}
	srv := httptest.NewServer(g.routes())
	g.publicURL = srv.URL
	return g, srv
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func TestOAuthFlowAndProxy(t *testing.T) {
	up := fakeUpstream(t, "up-secret")
	defer up.Close()
	_, gw := newTestGateway(t, up.URL, "up-secret", "correct horse battery")
	defer gw.Close()
	c := &http.Client{CheckRedirect: noRedirect}

	// Unauthenticated MCP call points at the resource metadata.
	resp, _ := c.Post(gw.URL+"/fake/mcp", "application/json", strings.NewReader(`{}`))
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "/.well-known/oauth-protected-resource/fake/mcp") {
		t.Fatalf("want 401 with resource_metadata, got %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}

	// Register.
	redirect := "https://client.example/cb"
	resp, _ = c.Post(gw.URL+"/oauth/register", "application/json", strings.NewReader(`{"client_name":"Test","redirect_uris":["`+redirect+`"]}`))
	var reg map[string]any
	json.NewDecoder(resp.Body).Decode(&reg)
	cid, _ := reg["client_id"].(string)
	if resp.StatusCode != 201 || cid == "" {
		t.Fatalf("register: %d %v", resp.StatusCode, reg)
	}

	// Authorize with PKCE.
	verifier := strings.Repeat("v", 50)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {cid}, "redirect_uri": {redirect}, "state": {"s1"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"resource": {gw.URL + "/fake/mcp"}}
	resp, _ = c.Get(gw.URL + "/oauth/authorize?" + q.Encode())
	body, _ := io.ReadAll(resp.Body)
	m := regexp.MustCompile(`name="req" value="([^"]+)"`).FindSubmatch(body)
	if m == nil {
		t.Fatalf("no consent form: %s", body)
	}
	resp, _ = c.PostForm(gw.URL+"/oauth/authorize", url.Values{"req": {string(m[1])}, "password": {"correct horse battery"}, "action": {"allow"}})
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != 302 || loc.Query().Get("state") != "s1" || loc.Query().Get("code") == "" {
		t.Fatalf("authorize redirect: %d %s", resp.StatusCode, loc)
	}

	// Token.
	resp, _ = c.PostForm(gw.URL+"/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"client_id": {cid}, "redirect_uri": {redirect}, "code_verifier": {verifier}})
	var tok map[string]any
	json.NewDecoder(resp.Body).Decode(&tok)
	access, _ := tok["access_token"].(string)
	if resp.StatusCode != 200 || access == "" {
		t.Fatalf("token: %d %v", resp.StatusCode, tok)
	}

	// Proxy swaps the token for the upstream's.
	req, _ := http.NewRequest("POST", gw.URL+"/fake/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+access)
	resp, _ = c.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("proxied MCP call: %d", resp.StatusCode)
	}

	// Refresh rotates.
	refresh, _ := tok["refresh_token"].(string)
	resp, _ = c.PostForm(gw.URL+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {cid}})
	if resp.StatusCode != 200 {
		t.Fatalf("refresh: %d", resp.StatusCode)
	}
	resp, _ = c.PostForm(gw.URL+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {cid}})
	if resp.StatusCode != 400 {
		t.Fatalf("reused refresh token should fail, got %d", resp.StatusCode)
	}
}

func TestWrongPasswordAndBadPKCE(t *testing.T) {
	up := fakeUpstream(t, "x")
	defer up.Close()
	_, gw := newTestGateway(t, up.URL, "x", "correct horse battery")
	defer gw.Close()
	c := &http.Client{CheckRedirect: noRedirect}
	resp, _ := c.Post(gw.URL+"/oauth/register", "application/json", strings.NewReader(`{"redirect_uris":["https://c.example/cb"]}`))
	var reg map[string]any
	json.NewDecoder(resp.Body).Decode(&reg)
	cid := reg["client_id"].(string)

	q := url.Values{"response_type": {"code"}, "client_id": {cid}, "redirect_uri": {"https://c.example/cb"}, "code_challenge": {"abc"}, "code_challenge_method": {"plain"}}
	resp, _ = c.Get(gw.URL + "/oauth/authorize?" + q.Encode())
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "error=invalid_request") {
		t.Fatalf("plain PKCE should be refused, got %d %s", resp.StatusCode, loc)
	}

	q.Set("code_challenge_method", "S256")
	resp, _ = c.Get(gw.URL + "/oauth/authorize?" + q.Encode())
	body, _ := io.ReadAll(resp.Body)
	id := regexp.MustCompile(`name="req" value="([^"]+)"`).FindSubmatch(body)[1]
	resp, _ = c.PostForm(gw.URL+"/oauth/authorize", url.Values{"req": {string(id)}, "password": {"wrong"}, "action": {"allow"}})
	if resp.StatusCode == 302 {
		t.Fatal("wrong password must not redirect with a code")
	}

	resp, _ = c.Post(gw.URL+"/oauth/register", "application/json", strings.NewReader(`{"redirect_uris":["http://evil.example/cb"]}`))
	if resp.StatusCode != 400 {
		t.Fatalf("plain http redirect should be refused, got %d", resp.StatusCode)
	}
}

func TestAdminSettingsAndTest(t *testing.T) {
	up := fakeUpstream(t, "tok")
	defer up.Close()
	_, gw := newTestGateway(t, up.URL, "tok", "correct horse battery")
	defer gw.Close()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	resp, _ := c.PostForm(gw.URL+"/admin/login", url.Values{"password": {"correct horse battery"}})
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "MCP servers") {
		t.Fatalf("login failed: %s", body)
	}
	resp, _ = c.Get(gw.URL + "/admin/u/fake")
	body, _ = io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `name="f_FOO"`) {
		t.Fatalf("settings form missing: %s", body)
	}
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(body)[1]
	resp, _ = c.PostForm(gw.URL+"/admin/u/fake/test", url.Values{"csrf": {string(csrf)}})
	body, _ = io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Everything works.") {
		t.Fatalf("test button: %s", body)
	}
}

func TestParseUpstreams(t *testing.T) {
	if _, _, err := parseUpstreams("Bad Name=http://x"); err == nil {
		t.Fatal("want error for bad name")
	}
	if _, _, err := parseUpstreams("a=ftp://x"); err == nil {
		t.Fatal("want error for bad scheme")
	}
	ups, order, err := parseUpstreams("b=http://b:8080, a=http://a:8080/")
	if err != nil || len(ups) != 2 || order[0] != "a" || ups["a"].URL.String() != "http://a:8080" {
		t.Fatalf("got %v %v %v", ups, order, err)
	}
}
