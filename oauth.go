package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, code int, errCode, desc string) {
	writeJSON(w, code, map[string]string{"error": errCode, "error_description": desc})
}

func cors(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID")
	h.Set("Access-Control-Expose-Headers", "Mcp-Session-Id, WWW-Authenticate")
}

// ---------- discovery ----------

func (g *gateway) handleASMetadata(w http.ResponseWriter, r *http.Request) {
	cors(w)
	b := g.base(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                b,
		"authorization_endpoint":                b + "/oauth/authorize",
		"token_endpoint":                        b + "/oauth/token",
		"registration_endpoint":                 b + "/oauth/register",
		"revocation_endpoint":                   b + "/oauth/revoke",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"},
		"scopes_supported":                      []string{"mcp"},
		"client_id_metadata_document_supported": true,
		"service_documentation":                 "https://github.com/Olsenius/mcp-gateway",
	})
}

// handleResourceMetadata serves RFC 9728 metadata for /<name>/mcp, at
// /.well-known/oauth-protected-resource/<name>/mcp. The bare path answers
// for the only upstream when there is just one.
func (g *gateway) handleResourceMetadata(w http.ResponseWriter, r *http.Request) {
	cors(w)
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/.well-known/oauth-protected-resource"), "/")
	name := strings.TrimSuffix(rest, "/mcp")
	if name == "" && len(g.order) == 1 {
		name = g.order[0]
	}
	if _, ok := g.upstreams[name]; !ok {
		http.NotFound(w, r)
		return
	}
	b := g.base(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 b + "/" + name + "/mcp",
		"authorization_servers":    []string{b},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{"mcp"},
		"resource_name":            name,
	})
}

// ---------- clients: dynamic registration and metadata documents ----------

func validRedirect(u string) bool {
	p, err := url.Parse(u)
	if err != nil || p.Fragment != "" || p.Host == "" {
		return false
	}
	if p.Scheme == "https" {
		return true
	}
	host := p.Hostname()
	return p.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1")
}

type registration struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ClientID                string   `json:"client_id"`
}

func (g *gateway) handleRegister(w http.ResponseWriter, r *http.Request) {
	cors(w)
	var reg registration
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&reg); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid JSON")
		return
	}
	if len(reg.RedirectURIs) == 0 || len(reg.RedirectURIs) > 10 {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "1 to 10 redirect_uris are required")
		return
	}
	for _, u := range reg.RedirectURIs {
		if !validRedirect(u) {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris must be https, or http on localhost: "+u)
			return
		}
	}
	name := strings.TrimSpace(reg.ClientName)
	if len(name) > 100 {
		name = name[:100]
	}
	var count int
	g.store.read(func(p *persisted) { count = len(p.Clients) })
	if count >= 200 {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "too many registered clients; remove some on the admin page")
		return
	}
	c := &client{ID: "c_" + randomToken(16), Name: name, RedirectURIs: reg.RedirectURIs, Created: time.Now()}
	method := reg.TokenEndpointAuthMethod
	if method == "" {
		method = "none"
	}
	secret := ""
	switch method {
	case "none":
	case "client_secret_post", "client_secret_basic":
		secret = randomToken(32)
		c.SecretHash = sha(secret)
	default:
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported token_endpoint_auth_method")
		return
	}
	if err := g.store.update(func(p *persisted) { p.Clients[c.ID] = c }); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	g.log.Info("registered OAuth client", "client_id", c.ID, "name", c.Name, "redirect", strings.Join(c.RedirectURIs, " "))
	resp := map[string]any{
		"client_id":                  c.ID,
		"client_id_issued_at":        c.Created.Unix(),
		"client_name":                c.Name,
		"redirect_uris":              c.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": method,
	}
	if secret != "" {
		resp["client_secret"] = secret
		resp["client_secret_expires_at"] = 0
	}
	writeJSON(w, http.StatusCreated, resp)
}

// safeHTTP refuses to connect to private, loopback or link-local
// addresses, so a client metadata URL cannot reach the internal network.
var safeHTTP = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
			Control: func(_, address string, _ syscall.RawConn) error {
				host, _, _ := net.SplitHostPort(address)
				ip := net.ParseIP(host)
				if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
					return errors.New("refusing to fetch from a non-public address")
				}
				return nil
			},
		}).DialContext,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// lookupClient finds a registered client, or fetches a Client ID Metadata
// Document when the client_id is an https URL.
func (g *gateway) lookupClient(ctx context.Context, id string) (*client, error) {
	var c *client
	g.store.read(func(p *persisted) {
		if v, ok := p.Clients[id]; ok {
			cp := *v
			c = &cp
		}
	})
	if c != nil {
		return c, nil
	}
	u, err := url.Parse(id)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path == "" || u.Path == "/" {
		return nil, errors.New("unknown client_id")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, id, nil)
	req.Header.Set("Accept", "application/json")
	resp, err := safeHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not fetch client metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client metadata: HTTP %d", resp.StatusCode)
	}
	var reg registration
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&reg); err != nil {
		return nil, errors.New("client metadata is not valid JSON")
	}
	if reg.ClientID != id {
		return nil, errors.New("client metadata client_id does not match")
	}
	for _, ru := range reg.RedirectURIs {
		if !validRedirect(ru) {
			return nil, errors.New("client metadata has an invalid redirect_uri")
		}
	}
	return &client{ID: id, Name: reg.ClientName, RedirectURIs: reg.RedirectURIs}, nil
}

// ---------- authorize ----------

// resourceName maps the RFC 8707 resource parameter to an upstream name.
// Without one, the token covers every upstream.
func (g *gateway) resourceName(r *http.Request, resource string) (string, error) {
	if resource == "" {
		return "*", nil
	}
	u, err := url.Parse(resource)
	if err != nil {
		return "", errors.New("invalid resource")
	}
	path := strings.Trim(u.Path, "/")
	name := strings.TrimSuffix(path, "/mcp")
	if _, ok := g.upstreams[name]; ok {
		return name, nil
	}
	if path == "" {
		return "*", nil
	}
	return "", fmt.Errorf("unknown resource %q", resource)
}

func (g *gateway) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c, err := g.lookupClient(r.Context(), q.Get("client_id"))
	if err != nil {
		g.renderError(w, "Unknown client", err.Error())
		return
	}
	redirect := q.Get("redirect_uri")
	if redirect == "" && len(c.RedirectURIs) == 1 {
		redirect = c.RedirectURIs[0]
	}
	if !slices.Contains(c.RedirectURIs, redirect) {
		g.renderError(w, "Invalid redirect_uri", "The address the app wants to send you back to is not registered: "+redirect)
		return
	}
	// From here, errors go back to the client.
	fail := func(code, desc string) {
		u, _ := url.Parse(redirect)
		v := u.Query()
		v.Set("error", code)
		v.Set("error_description", desc)
		if s := q.Get("state"); s != "" {
			v.Set("state", s)
		}
		v.Set("iss", g.base(r))
		u.RawQuery = v.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
	if q.Get("response_type") != "code" {
		fail("unsupported_response_type", "only response_type=code is supported")
		return
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		fail("invalid_request", "PKCE with S256 is required")
		return
	}
	res, err := g.resourceName(r, q.Get("resource"))
	if err != nil {
		fail("invalid_target", err.Error())
		return
	}
	id := randomToken(18)
	p := &pendingAuth{
		ClientID: c.ID, ClientName: c.Name, RedirectURI: redirect, State: q.Get("state"),
		CodeChallenge: q.Get("code_challenge"), Resource: res, Scope: q.Get("scope"),
		Expires: time.Now().Add(10 * time.Minute),
	}
	g.mu.Lock()
	g.pending[id] = p
	g.mu.Unlock()
	g.renderConsent(w, r, id, p, "")
}

func (g *gateway) handleAuthorizePost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	id := r.PostFormValue("req")
	g.mu.Lock()
	p := g.pending[id]
	g.mu.Unlock()
	if p == nil || time.Now().After(p.Expires) {
		g.renderError(w, "Request expired", "Go back to the app and connect again.")
		return
	}
	sess := g.currentSession(r)
	if sess != nil {
		if !constEq(r.PostFormValue("csrf"), sess.CSRF) {
			g.renderError(w, "Invalid form", "Reload the page and try again.")
			return
		}
	} else if ok, msg := g.checkAdmin(r, r.PostFormValue("password")); !ok {
		g.renderConsent(w, r, id, p, msg)
		return
	}
	g.mu.Lock()
	delete(g.pending, id)
	g.mu.Unlock()

	u, _ := url.Parse(p.RedirectURI)
	v := u.Query()
	if r.PostFormValue("action") != "allow" {
		v.Set("error", "access_denied")
		v.Set("error_description", "the user denied access")
	} else {
		code := randomToken(32)
		g.mu.Lock()
		g.codes[sha(code)] = &authCode{pendingAuth: *p}
		g.codes[sha(code)].Expires = time.Now().Add(5 * time.Minute)
		g.mu.Unlock()
		v.Set("code", code)
		g.log.Info("authorized client", "client_id", p.ClientID, "name", p.ClientName, "resource", p.Resource)
	}
	if p.State != "" {
		v.Set("state", p.State)
	}
	v.Set("iss", g.base(r))
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// ---------- token ----------

func pkceOK(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return constEq(base64.RawURLEncoding.EncodeToString(sum[:]), challenge)
}

// clientAuth checks client credentials, when the client has a secret.
func (g *gateway) clientAuth(r *http.Request) (*client, bool) {
	id, secret, basic := r.BasicAuth()
	if !basic {
		id, secret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	} else {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	}
	c, err := g.lookupClient(r.Context(), id)
	if err != nil {
		return nil, false
	}
	if c.SecretHash != "" && !constEq(sha(secret), c.SecretHash) {
		return nil, false
	}
	return c, true
}

func (g *gateway) issue(w http.ResponseWriter, clientID, resource string) {
	access, refresh := randomToken(32), randomToken(32)
	now := time.Now()
	g.mu.Lock()
	g.tokens[sha(access)] = accessToken{ClientID: clientID, Resource: resource, Expires: now.Add(g.accessTTL)}
	g.mu.Unlock()
	err := g.store.update(func(p *persisted) {
		p.Grants = append(p.Grants, grant{Hash: sha(refresh), Kind: "refresh", ClientID: clientID, Resource: resource, Created: now, Expires: now.Add(g.refreshTT)})
		if c, ok := p.Clients[clientID]; ok {
			c.LastUsed = now
		}
	})
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(g.accessTTL.Seconds()),
		"refresh_token": refresh,
		"scope":         "mcp",
	})
}

func (g *gateway) handleToken(w http.ResponseWriter, r *http.Request) {
	cors(w)
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "bad form")
		return
	}
	c, ok := g.clientAuth(r)
	if !ok {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "unknown client or bad client secret")
		return
	}
	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		h := sha(r.PostFormValue("code"))
		g.mu.Lock()
		ac := g.codes[h]
		if ac != nil {
			delete(g.codes, h) // single use
		}
		g.mu.Unlock()
		switch {
		case ac == nil || time.Now().After(ac.Expires):
			oauthError(w, http.StatusBadRequest, "invalid_grant", "code is invalid or expired")
		case ac.ClientID != c.ID:
			oauthError(w, http.StatusBadRequest, "invalid_grant", "code was issued to another client")
		case r.PostFormValue("redirect_uri") != "" && r.PostFormValue("redirect_uri") != ac.RedirectURI:
			oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match")
		case !pkceOK(r.PostFormValue("code_verifier"), ac.CodeChallenge):
			oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		default:
			res := ac.Resource
			if rr := r.PostFormValue("resource"); rr != "" {
				if n, err := g.resourceName(r, rr); err == nil && (res == "*" || n == res) {
					res = n
				}
			}
			g.issue(w, c.ID, res)
		}
	case "refresh_token":
		h := sha(r.PostFormValue("refresh_token"))
		var found *grant
		g.store.update(func(p *persisted) {
			for i, gr := range p.Grants {
				if gr.Kind == "refresh" && constEq(gr.Hash, h) {
					cp := gr
					found = &cp
					p.Grants = append(p.Grants[:i], p.Grants[i+1:]...) // rotate
					break
				}
			}
		})
		switch {
		case found == nil || (!found.Expires.IsZero() && time.Now().After(found.Expires)):
			oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid or expired")
		case found.ClientID != c.ID:
			oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token was issued to another client")
		default:
			g.issue(w, c.ID, found.Resource)
		}
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "use authorization_code or refresh_token")
	}
}

func (g *gateway) handleRevoke(w http.ResponseWriter, r *http.Request) {
	cors(w)
	r.ParseForm()
	h := sha(r.PostFormValue("token"))
	g.mu.Lock()
	delete(g.tokens, h)
	g.mu.Unlock()
	g.store.update(func(p *persisted) {
		p.Grants = slices.DeleteFunc(p.Grants, func(gr grant) bool { return gr.Kind == "refresh" && constEq(gr.Hash, h) })
	})
	w.WriteHeader(http.StatusOK)
}

// ---------- verifying access to an upstream ----------

// allowed reports whether a bearer token may use upstream name. OAuth
// access tokens are bound to one upstream (or all); personal tokens made
// on the admin page work like long-lived access tokens.
func (g *gateway) allowed(token, name string) bool {
	if token == "" {
		return false
	}
	h := sha(token)
	g.mu.Lock()
	t, ok := g.tokens[h]
	g.mu.Unlock()
	if ok {
		return time.Now().Before(t.Expires) && (t.Resource == "*" || t.Resource == name)
	}
	var good bool
	g.store.read(func(p *persisted) {
		for _, gr := range p.Grants {
			if gr.Kind == "personal" && constEq(gr.Hash, h) && (gr.Resource == "*" || gr.Resource == name) && (gr.Expires.IsZero() || time.Now().Before(gr.Expires)) {
				good = true
			}
		}
	})
	return good
}
