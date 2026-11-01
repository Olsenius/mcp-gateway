package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeIdP is a minimal OpenID Connect provider. Each test sets the claims
// it wants in the next ID token through edit.
type fakeIdP struct {
	srv  *httptest.Server
	key  *rsa.PrivateKey
	mu   sync.Mutex
	auth map[string]url.Values // code -> authorize params
	edit func(map[string]any)
	sign *rsa.PrivateKey // overrides key when set
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, auth: map[string]url.Values{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		id, secret, _ := r.BasicAuth()
		f.mu.Lock()
		a := f.auth[r.PostFormValue("code")]
		delete(f.auth, r.PostFormValue("code"))
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
		if id != "gw" || secret != "s3cret" || a == nil ||
			a.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) ||
			r.PostFormValue("redirect_uri") != a.Get("redirect_uri") {
			writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
			return
		}
		claims := map[string]any{
			"iss": f.srv.URL, "aud": "gw", "sub": "user-1", "nonce": a.Get("nonce"),
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
			"email": "admin@example.com", "email_verified": true, "groups": []string{"family"},
		}
		if f.edit != nil {
			f.edit(claims)
		}
		writeJSON(w, 200, map[string]string{"id_token": f.token(t, claims), "token_type": "Bearer"})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) token(t *testing.T, claims map[string]any) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	in := enc(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"}) + "." + enc(claims)
	key := f.key
	if f.sign != nil {
		key = f.sign
	}
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// approve plays the provider's login page: it takes the gateway's
// authorize redirect and returns the callback URL with a fresh code.
func (f *fakeIdP) approve(t *testing.T, authorizeURL string) string {
	t.Helper()
	u, err := url.Parse(authorizeURL)
	if err != nil || !strings.HasPrefix(authorizeURL, f.srv.URL+"/authorize") {
		t.Fatalf("not sent to the provider: %q", authorizeURL)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("client_id") != "gw" {
		t.Fatalf("bad authorize request: %v", q)
	}
	code := randomToken(16)
	f.mu.Lock()
	f.auth[code] = q
	f.mu.Unlock()
	return q.Get("redirect_uri") + "?" + url.Values{"code": {code}, "state": {q.Get("state")}, "iss": {f.srv.URL}}.Encode()
}

func newOIDCGateway(t *testing.T, users, groups string) (*gateway, *httptest.Server, *fakeIdP) {
	t.Helper()
	idp := newFakeIdP(t)
	up := fakeUpstream(t, "up-secret")
	t.Cleanup(up.Close)
	g, srv := newTestGateway(t, up.URL, "up-secret", strings.Repeat("p", 40))
	t.Cleanup(srv.Close)
	t.Setenv("OIDC_ISSUER", idp.srv.URL)
	t.Setenv("OIDC_CLIENT_ID", "gw")
	t.Setenv("OIDC_CLIENT_SECRET", "s3cret")
	t.Setenv("OIDC_ALLOWED_USERS", users)
	t.Setenv("OIDC_ALLOWED_GROUPS", groups)
	cfg, err := oidcFromEnv(g.publicURL)
	if err != nil {
		t.Fatal(err)
	}
	g.oidc = newOIDCProvider(*cfg)
	return g, srv, idp
}

func browser(t *testing.T) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: noRedirect}
}

// runOIDCLogin runs a full login and returns the final redirect target, or
// the status code and body of the callback when it did not redirect.
func runOIDCLogin(t *testing.T, c *http.Client, srv *httptest.Server, idp *fakeIdP, path string) (string, int, string) {
	t.Helper()
	resp, err := c.Get(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login start: %d", resp.StatusCode)
	}
	resp, err = c.Get(idp.approve(t, resp.Header.Get("Location")))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := new(strings.Builder)
	b := make([]byte, 4096)
	n, _ := resp.Body.Read(b)
	body.Write(b[:n])
	return resp.Header.Get("Location"), resp.StatusCode, body.String()
}

func loggedIn(t *testing.T, c *http.Client, srv *httptest.Server) bool {
	resp, err := c.Get(srv.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b := make([]byte, 1<<16)
	n, _ := resp.Body.Read(b)
	return strings.Contains(string(b[:n]), "Personal tokens")
}

func TestOIDCAdminLogin(t *testing.T) {
	_, srv, idp := newOIDCGateway(t, "", "family")
	c := browser(t)
	loc, code, body := runOIDCLogin(t, c, srv, idp, "/admin/oidc/login")
	if code != http.StatusSeeOther || loc != "/admin" {
		t.Fatalf("callback: %d %q %s", code, loc, body)
	}
	if !loggedIn(t, c, srv) {
		t.Fatal("not logged in after OIDC login")
	}
}

func TestOIDCRejections(t *testing.T) {
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := []struct {
		name   string
		users  string
		groups string
		edit   func(map[string]any)
		sign   *rsa.PrivateKey
	}{
		{name: "not in allowed group", groups: "admins"},
		{name: "unverified email", users: "admin@example.com", edit: func(m map[string]any) { m["email_verified"] = false }},
		{name: "wrong audience", groups: "family", edit: func(m map[string]any) { m["aud"] = "someone-else" }},
		{name: "wrong issuer", groups: "family", edit: func(m map[string]any) { m["iss"] = "https://evil.example" }},
		{name: "expired", groups: "family", edit: func(m map[string]any) { m["exp"] = time.Now().Add(-time.Hour).Unix() }},
		{name: "wrong nonce", groups: "family", edit: func(m map[string]any) { m["nonce"] = "x" }},
		{name: "bad signature", groups: "family", sign: other},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, srv, idp := newOIDCGateway(t, tc.users, tc.groups)
			idp.edit, idp.sign = tc.edit, tc.sign
			c := browser(t)
			loc, code, _ := runOIDCLogin(t, c, srv, idp, "/admin/oidc/login")
			if code == http.StatusSeeOther || loc != "" {
				t.Fatalf("login accepted: %d %q", code, loc)
			}
			if loggedIn(t, c, srv) {
				t.Fatal("session created")
			}
		})
	}
}

func TestOIDCAllowedByVerifiedEmailOrSubject(t *testing.T) {
	for _, users := range []string{"Admin@Example.com", "user-1"} {
		_, srv, idp := newOIDCGateway(t, users, "")
		c := browser(t)
		if _, code, body := runOIDCLogin(t, c, srv, idp, "/admin/oidc/login"); code != http.StatusSeeOther {
			t.Fatalf("%s: %d %s", users, code, body)
		}
	}
}

// A callback without this browser's state cookie (for example a login an
// attacker started and sent to the victim) must not create a session.
func TestOIDCCallbackNeedsStateCookie(t *testing.T) {
	_, srv, idp := newOIDCGateway(t, "", "family")
	attacker := browser(t)
	resp, err := attacker.Get(srv.URL + "/admin/oidc/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	callback := idp.approve(t, resp.Header.Get("Location"))

	victim := browser(t)
	resp, err = victim.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusSeeOther || loggedIn(t, victim, srv) {
		t.Fatal("callback accepted without the state cookie")
	}
	// The state is single use: replaying in the attacker's browser fails too.
	resp, _ = attacker.Get(callback)
	resp.Body.Close()
	resp, _ = attacker.Get(callback)
	resp.Body.Close()
	if resp.StatusCode == http.StatusSeeOther {
		t.Fatal("callback replay accepted")
	}
}

// Connecting an app: log in with OIDC from the consent page, come back to
// it, and still have to press Allow.
func TestOIDCConsentFlow(t *testing.T) {
	g, srv, idp := newOIDCGateway(t, "", "family")
	c := browser(t)
	verifier := strings.Repeat("v", 50)
	sum := sha256.Sum256([]byte(verifier))
	cid := "c1"
	g.store.update(func(p *persisted) {
		p.Clients[cid] = &client{ID: cid, Name: "App", RedirectURIs: []string{"https://app.example/cb"}, Manual: true, Created: time.Now()}
	})
	q := url.Values{
		"client_id": {cid}, "redirect_uri": {"https://app.example/cb"}, "response_type": {"code"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "state": {"st"},
	}
	resp, err := c.Get(srv.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1<<16)
	n, _ := resp.Body.Read(b)
	resp.Body.Close()
	page := string(b[:n])
	i := strings.Index(page, `/admin/oidc/login?req=`)
	if i < 0 {
		t.Fatal("consent page has no OIDC login link")
	}
	link := page[i:]
	link = link[:strings.IndexByte(link, '"')]
	req := strings.TrimPrefix(link, "/admin/oidc/login?req=")

	loc, code, body := runOIDCLogin(t, c, srv, idp, link)
	if code != http.StatusSeeOther || loc != "/oauth/authorize/resume?req="+req {
		t.Fatalf("callback: %d %q %s", code, loc, body)
	}
	resp, err = c.Get(srv.URL + loc)
	if err != nil {
		t.Fatal(err)
	}
	n, _ = resp.Body.Read(b)
	resp.Body.Close()
	page = string(b[:n])
	if !strings.Contains(page, `name="csrf"`) || strings.Contains(page, `type="password"`) {
		t.Fatal("resumed consent page is not logged in")
	}
	g.mu.Lock()
	_, stillPending := g.pending[req]
	g.mu.Unlock()
	if !stillPending {
		t.Fatal("login alone approved the app; Allow must still be pressed")
	}
	i = strings.Index(page, `name="csrf" value="`)
	csrf := page[i+len(`name="csrf" value="`):]
	csrf = csrf[:strings.IndexByte(csrf, '"')]
	resp, err = c.PostForm(srv.URL+"/oauth/authorize", url.Values{"req": {req}, "csrf": {csrf}, "action": {"allow"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if l := resp.Header.Get("Location"); !strings.HasPrefix(l, "https://app.example/cb?") || !strings.Contains(l, "code=") {
		t.Fatalf("allow: %d %q", resp.StatusCode, l)
	}
}

func TestOIDCConfig(t *testing.T) {
	set := func(kv ...string) {
		for _, k := range []string{"OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_ALLOWED_USERS", "OIDC_ALLOWED_GROUPS", "OIDC_LABEL"} {
			t.Setenv(k, "")
		}
		for i := 0; i < len(kv); i += 2 {
			t.Setenv(kv[i], kv[i+1])
		}
	}
	full := []string{"OIDC_ISSUER", "https://id.example", "OIDC_CLIENT_ID", "gw", "OIDC_CLIENT_SECRET", "s", "OIDC_ALLOWED_GROUPS", "admins"}

	set()
	if c, err := oidcFromEnv("https://gw.example"); c != nil || err != nil {
		t.Fatal("OIDC should be off without OIDC_ISSUER")
	}
	set(full...)
	c, err := oidcFromEnv("https://gw.example")
	if err != nil || c.RedirectURL != "https://gw.example/admin/oidc/callback" || c.Label != "id.example" {
		t.Fatalf("%+v %v", c, err)
	}
	for name, kv := range map[string][]string{
		"no allowlist":    full[:6],
		"no secret":       append(append([]string{}, full[:4]...), full[6:]...),
		"http issuer":     append([]string{"OIDC_ISSUER", "http://id.example"}, full[2:]...),
		"no public url":   full,
		"http public url": full,
	} {
		set(kv...)
		pub := "https://gw.example"
		switch name {
		case "no public url":
			pub = ""
		case "http public url":
			pub = "http://gw.example"
		}
		if _, err := oidcFromEnv(pub); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOIDCDisabledRoutes(t *testing.T) {
	up := fakeUpstream(t, "x")
	defer up.Close()
	_, srv := newTestGateway(t, up.URL, "x", strings.Repeat("p", 40))
	defer srv.Close()
	for _, p := range []string{"/admin/oidc/login", "/admin/oidc/callback?state=a&code=b"} {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
}
