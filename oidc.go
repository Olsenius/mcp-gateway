package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// Optional login through an OpenID Connect provider (for example Pocket ID),
// in addition to the admin password. Only users or groups listed in
// OIDC_ALLOWED_USERS / OIDC_ALLOWED_GROUPS are let in.

const (
	oidcCookie     = "gw_oidc"
	oidcLoginTTL   = 10 * time.Minute
	oidcMaxPending = 1000
	oidcClockSkew  = time.Minute
)

type oidcConfig struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	Label         string
	RedirectURL   string
	AllowedUsers  []string // verified e-mail addresses or subject IDs
	AllowedGroups []string
}

type oidcMeta struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type oidcProvider struct {
	cfg  oidcConfig
	http *http.Client

	mu     sync.Mutex
	meta   *oidcMeta
	metaAt time.Time
	keys   map[string]*rsa.PublicKey
	keysAt time.Time
}

// oidcLogin is a login started at the provider and not yet finished.
type oidcLogin struct {
	Nonce    string
	Verifier string
	Req      string // pending OAuth consent to return to, or "" for /admin
	Expires  time.Time
}

type idClaims struct {
	Iss           string          `json:"iss"`
	Sub           string          `json:"sub"`
	Aud           json.RawMessage `json:"aud"`
	Azp           string          `json:"azp"`
	Exp           int64           `json:"exp"`
	Iat           int64           `json:"iat"`
	Nonce         string          `json:"nonce"`
	Email         string          `json:"email"`
	EmailVerified bool            `json:"email_verified"`
	Groups        []string        `json:"groups"`
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// localHTTP reports whether u is plain http to the local machine, which is
// accepted only so tests can run a fake provider.
func localHTTP(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	h := u.Hostname()
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func secureURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Host != "" && u.User == nil && (u.Scheme == "https" || localHTTP(u))
}

// oidcFromEnv reads the OIDC_* settings. It returns nil when OIDC_ISSUER is
// unset, and an error for any incomplete or unsafe configuration.
func oidcFromEnv(publicURL string) (*oidcConfig, error) {
	issuer := strings.TrimRight(env("OIDC_ISSUER", ""), "/")
	if issuer == "" {
		return nil, nil
	}
	if !secureURL(issuer) {
		return nil, fmt.Errorf("OIDC_ISSUER must be an https URL, got %q", issuer)
	}
	c := &oidcConfig{
		Issuer:        issuer,
		ClientID:      env("OIDC_CLIENT_ID", ""),
		ClientSecret:  env("OIDC_CLIENT_SECRET", ""),
		AllowedUsers:  splitList(env("OIDC_ALLOWED_USERS", "")),
		AllowedGroups: splitList(env("OIDC_ALLOWED_GROUPS", "")),
	}
	if c.ClientID == "" || c.ClientSecret == "" {
		return nil, errors.New("OIDC_ISSUER is set, so OIDC_CLIENT_ID and OIDC_CLIENT_SECRET are required")
	}
	if len(c.AllowedUsers) == 0 && len(c.AllowedGroups) == 0 {
		return nil, errors.New("OIDC_ISSUER is set, so OIDC_ALLOWED_USERS or OIDC_ALLOWED_GROUPS is required (otherwise every account at the provider could log in)")
	}
	if publicURL == "" || !secureURL(publicURL) {
		return nil, errors.New("OIDC login needs PUBLIC_URL set to the gateway's https URL")
	}
	c.RedirectURL = publicURL + "/admin/oidc/callback"
	u, _ := url.Parse(issuer)
	c.Label = env("OIDC_LABEL", u.Host)
	return c, nil
}

func newOIDCProvider(cfg oidcConfig) *oidcProvider {
	return &oidcProvider{
		cfg: cfg,
		http: &http.Client{
			Timeout:       10 * time.Second,
			Transport:     tracingTransport{},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (p *oidcProvider) getJSON(ctx context.Context, rawURL string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", rawURL, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

// metadata returns the provider's discovery document, cached for an hour.
func (p *oidcProvider) metadata(ctx context.Context) (*oidcMeta, error) {
	p.mu.Lock()
	m, at := p.meta, p.metaAt
	p.mu.Unlock()
	if m != nil && time.Since(at) < time.Hour {
		return m, nil
	}
	var doc oidcMeta
	if err := p.getJSON(ctx, p.cfg.Issuer+"/.well-known/openid-configuration", &doc); err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	if doc.Issuer != p.cfg.Issuer {
		return nil, fmt.Errorf("OIDC discovery: issuer is %q, expected %q", doc.Issuer, p.cfg.Issuer)
	}
	for _, e := range []string{doc.AuthorizationEndpoint, doc.TokenEndpoint, doc.JWKSURI} {
		if !secureURL(e) {
			return nil, fmt.Errorf("OIDC discovery: endpoint %q is not https", e)
		}
	}
	p.mu.Lock()
	p.meta, p.metaAt = &doc, time.Now()
	p.mu.Unlock()
	return &doc, nil
}

// key returns the signing key with the given ID. The key set is refetched
// when the ID is unknown (key rotation), at most once a minute.
func (p *oidcProvider) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	p.mu.Lock()
	k, n, at := p.keys[kid], len(p.keys), p.keysAt
	if kid == "" && n == 1 {
		for _, only := range p.keys {
			k = only
		}
	}
	p.mu.Unlock()
	if k != nil {
		return k, nil
	}
	if !at.IsZero() && time.Since(at) < time.Minute {
		return nil, errors.New("unknown signing key")
	}
	m, err := p.metadata(ctx)
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []struct {
			Kty, Use, Kid, Alg, N, E string
		} `json:"keys"`
	}
	if err := p.getJSON(ctx, m.JWKSURI, &set); err != nil {
		return nil, fmt.Errorf("OIDC keys: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, jk := range set.Keys {
		if jk.Kty != "RSA" || (jk.Use != "" && jk.Use != "sig") || (jk.Alg != "" && jk.Alg != "RS256") {
			continue
		}
		nb, err1 := base64.RawURLEncoding.DecodeString(jk.N)
		eb, err2 := base64.RawURLEncoding.DecodeString(jk.E)
		if err1 != nil || err2 != nil || len(eb) == 0 || len(eb) > 4 {
			continue
		}
		e := int(new(big.Int).SetBytes(eb).Int64())
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}
		if pub.N.BitLen() < 2048 || e < 3 {
			continue
		}
		keys[jk.Kid] = pub
	}
	p.mu.Lock()
	p.keys, p.keysAt = keys, time.Now()
	k = keys[kid]
	if kid == "" && len(keys) == 1 {
		for _, only := range keys {
			k = only
		}
	}
	p.mu.Unlock()
	if k == nil {
		return nil, errors.New("unknown signing key")
	}
	return k, nil
}

// verifyIDToken checks the ID token's RS256 signature, issuer, audience,
// lifetime and nonce, and returns its claims.
func (p *oidcProvider) verifyIDToken(ctx context.Context, raw, nonce string) (*idClaims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed ID token")
	}
	var hdr struct{ Alg, Kid string }
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &hdr) != nil {
		return nil, errors.New("malformed ID token header")
	}
	if hdr.Alg != "RS256" {
		return nil, fmt.Errorf("ID token algorithm %q not accepted", hdr.Alg)
	}
	key, err := p.key(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("malformed ID token signature")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return nil, errors.New("ID token signature is invalid")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed ID token payload")
	}
	var c idClaims
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, errors.New("malformed ID token payload")
	}
	if c.Iss != p.cfg.Issuer {
		return nil, errors.New("ID token has the wrong issuer")
	}
	var aud []string
	if json.Unmarshal(c.Aud, &aud) != nil {
		var one string
		if json.Unmarshal(c.Aud, &one) != nil {
			return nil, errors.New("ID token has no audience")
		}
		aud = []string{one}
	}
	if !slices.Contains(aud, p.cfg.ClientID) || (len(aud) > 1 && c.Azp != p.cfg.ClientID) || (c.Azp != "" && c.Azp != p.cfg.ClientID) {
		return nil, errors.New("ID token is for another client")
	}
	now := time.Now()
	if c.Exp == 0 || now.After(time.Unix(c.Exp, 0).Add(oidcClockSkew)) {
		return nil, errors.New("ID token has expired")
	}
	if c.Iat != 0 && time.Unix(c.Iat, 0).After(now.Add(oidcClockSkew)) {
		return nil, errors.New("ID token is issued in the future")
	}
	if nonce == "" || !constEq(c.Nonce, nonce) {
		return nil, errors.New("ID token nonce does not match")
	}
	if c.Sub == "" {
		return nil, errors.New("ID token has no subject")
	}
	return &c, nil
}

// allowed reports whether the user may log in. E-mail only counts when the
// provider says it is verified.
func (p *oidcProvider) allowed(c *idClaims) bool {
	for _, u := range p.cfg.AllowedUsers {
		if u == c.Sub || (c.EmailVerified && c.Email != "" && strings.EqualFold(u, c.Email)) {
			return true
		}
	}
	for _, g := range c.Groups {
		if slices.Contains(p.cfg.AllowedGroups, g) {
			return true
		}
	}
	return false
}

// exchange trades the authorization code for tokens at the provider.
func (p *oidcProvider) exchange(ctx context.Context, m *oidcMeta, code, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.cfg.RedirectURL},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.cfg.ClientSecret))
	resp, err := p.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	var tr struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request: HTTP %d %s", resp.StatusCode, tr.Error)
	}
	if tr.IDToken == "" {
		return "", errors.New("token response has no id_token")
	}
	return tr.IDToken, nil
}

// ---------- handlers ----------

// handleOIDCLogin sends the browser to the provider. With ?req=<id> the
// user comes back to that pending OAuth consent page afterwards.
func (g *gateway) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if g.oidc == nil {
		http.NotFound(w, r)
		return
	}
	req := r.URL.Query().Get("req")
	if req != "" {
		g.mu.Lock()
		p := g.pending[req]
		g.mu.Unlock()
		if p == nil || time.Now().After(p.Expires) {
			g.renderError(w, "Request expired", "Go back to the app and connect again.")
			return
		}
	}
	m, err := g.oidc.metadata(r.Context())
	if err != nil {
		g.log.Error("oidc", "err", err)
		g.renderError(w, "Login unavailable", "Could not reach "+g.oidc.cfg.Label+". Use the admin password instead.")
		return
	}
	state, login := randomToken(24), &oidcLogin{
		Nonce: randomToken(24), Verifier: randomToken(48), Req: req, Expires: time.Now().Add(oidcLoginTTL),
	}
	g.mu.Lock()
	if g.oidcLogins == nil {
		g.oidcLogins = map[string]*oidcLogin{}
	}
	full := len(g.oidcLogins) >= oidcMaxPending
	if !full {
		g.oidcLogins[sha(state)] = login
	}
	g.mu.Unlock()
	if full {
		g.renderError(w, "Too many logins in progress", "Try again in a few minutes.")
		return
	}
	// The state cookie ties the callback to this browser, so nobody can
	// make you finish a login they started.
	http.SetCookie(w, &http.Cookie{
		Name: oidcCookie, Value: state, Path: "/admin/oidc/", HttpOnly: true,
		Secure: g.secureCookies(r), SameSite: http.SameSiteLaxMode, MaxAge: int(oidcLoginTTL / time.Second),
	})
	challenge := sha256.Sum256([]byte(login.Verifier))
	u, _ := url.Parse(m.AuthorizationEndpoint)
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", g.oidc.cfg.ClientID)
	q.Set("redirect_uri", g.oidc.cfg.RedirectURL)
	q.Set("scope", "openid email profile groups")
	q.Set("state", state)
	q.Set("nonce", login.Nonce)
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (g *gateway) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if g.oidc == nil {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: "", Path: "/admin/oidc/", MaxAge: -1, HttpOnly: true, Secure: g.secureCookies(r)})
	c, err := r.Cookie(oidcCookie)
	state := q.Get("state")
	if err != nil || state == "" || !constEq(c.Value, state) {
		g.renderError(w, "Login failed", "The login was not started in this browser, or it took too long. Try again.")
		return
	}
	g.mu.Lock()
	login := g.oidcLogins[sha(state)]
	delete(g.oidcLogins, sha(state))
	g.mu.Unlock()
	if login == nil || time.Now().After(login.Expires) {
		g.renderError(w, "Login failed", "The login took too long. Try again.")
		return
	}
	if iss := q.Get("iss"); iss != "" && iss != g.oidc.cfg.Issuer {
		g.renderError(w, "Login failed", "The answer came from the wrong provider.")
		return
	}
	if e := q.Get("error"); e != "" {
		g.log.Warn("oidc login refused by provider", "error", e)
		g.renderError(w, "Login cancelled", g.oidc.cfg.Label+" did not log you in ("+e+").")
		return
	}
	m, err := g.oidc.metadata(r.Context())
	var idt string
	if err == nil {
		idt, err = g.oidc.exchange(r.Context(), m, q.Get("code"), login.Verifier)
	}
	var claims *idClaims
	if err == nil {
		claims, err = g.oidc.verifyIDToken(r.Context(), idt, login.Nonce)
	}
	if err != nil {
		g.log.Warn("oidc login failed", "ip", g.clientIP(r), "err", err)
		g.renderError(w, "Login failed", "Could not verify the login from "+g.oidc.cfg.Label+".")
		return
	}
	if !g.oidc.allowed(claims) {
		g.log.Warn("oidc user not allowed", "sub", claims.Sub, "email", claims.Email, "ip", g.clientIP(r))
		g.renderError(w, "Not allowed", "Your account at "+g.oidc.cfg.Label+" may not log in to this gateway.")
		return
	}
	g.log.Info("admin login via oidc", "sub", claims.Sub, "email", claims.Email, "ip", g.clientIP(r))
	g.startSession(w, r)
	next := "/admin"
	if login.Req != "" {
		next = "/oauth/authorize/resume?req=" + url.QueryEscape(login.Req)
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// handleAuthorizeResume shows a pending consent page again after an OIDC
// login. The user still has to press Allow.
func (g *gateway) handleAuthorizeResume(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("req")
	g.mu.Lock()
	p := g.pending[id]
	g.mu.Unlock()
	if p == nil || time.Now().After(p.Expires) {
		g.renderError(w, "Request expired", "Go back to the app and connect again.")
		return
	}
	g.renderConsent(w, r, id, p, "")
}
