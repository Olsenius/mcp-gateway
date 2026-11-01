package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"
)

const sessionCookie = "gw_session"

func (g *gateway) currentSession(r *http.Request) *session {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.sessions[sha(c.Value)]
	if s == nil || time.Now().After(s.Expires) {
		return nil
	}
	return s
}

func (g *gateway) startSession(w http.ResponseWriter, r *http.Request) {
	tok := randomToken(32)
	g.mu.Lock()
	g.sessions[sha(tok)] = &session{CSRF: randomToken(18), Expires: time.Now().Add(12 * time.Hour)}
	g.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true,
		Secure: g.secureCookies(r), SameSite: http.SameSiteLaxMode, MaxAge: 12 * 3600,
	})
}

// requireAdmin returns the session for a logged-in admin POST with a
// valid CSRF token, or renders the login page.
func (g *gateway) requireAdmin(w http.ResponseWriter, r *http.Request) *session {
	r.ParseForm()
	s := g.currentSession(r)
	if s == nil {
		g.renderLogin(w, r, "Please log in first.")
		return nil
	}
	if r.Method == http.MethodPost && !constEq(r.PostFormValue("csrf"), s.CSRF) {
		g.renderError(w, "Invalid form", "Reload the page and try again.")
		return nil
	}
	return s
}

// ---------- login and first setup ----------

func (g *gateway) handleAdmin(w http.ResponseWriter, r *http.Request) {
	s := g.currentSession(r)
	if s == nil {
		g.renderLogin(w, r, "")
		return
	}
	g.renderDashboard(w, r, s, "", "")
}

func (g *gateway) handleLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if ok, msg := g.checkAdmin(r, r.PostFormValue("password")); !ok {
		g.renderLogin(w, r, msg)
		return
	}
	g.startSession(w, r)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (g *gateway) handleLogout(w http.ResponseWriter, r *http.Request) {
	if g.requireAdmin(w, r) == nil {
		return
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		g.mu.Lock()
		delete(g.sessions, sha(c.Value))
		g.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: g.secureCookies(r)})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// ---------- dashboard ----------

type upstreamRow struct {
	Name   string
	MCPURL string
	Alive  bool
	Token  bool
}

type grantRow struct {
	ID, Kind, Label, Resource string
	Created, Expires          time.Time
}

type clientRow struct {
	ID, Name, Redirects string
	Manual              bool
	Created, LastUsed   time.Time
	Grants              int
}

func (g *gateway) renderDashboard(w http.ResponseWriter, r *http.Request, s *session, msg, errMsg string) {
	p := page{Title: "Overview", CSRF: s.CSRF, Message: msg, Error: errMsg, Base: g.base(r), OIDCLabel: g.oidcLabel()}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	type res struct {
		i  int
		ok bool
	}
	ch := make(chan res, len(g.order))
	for i, n := range g.order {
		u := g.upstreams[n]
		p.Upstreams = append(p.Upstreams, upstreamRow{Name: n, MCPURL: p.Base + "/" + n + "/mcp", Token: u.Token != ""})
		go func(i int, u *upstream) { ch <- res{i, g.alive(ctx, u)} }(i, u)
	}
	for range g.order {
		x := <-ch
		p.Upstreams[x.i].Alive = x.ok
	}
	g.store.read(func(st *persisted) {
		counts := map[string]int{}
		for _, gr := range st.Grants {
			switch gr.Kind {
			case "refresh":
				counts[gr.ClientID]++
			case "personal":
				p.Personal = append(p.Personal, grantRow{ID: gr.Hash[:16], Kind: gr.Kind, Label: gr.Name, Resource: gr.Resource, Created: gr.Created, Expires: gr.Expires})
			}
		}
		for _, c := range st.Clients {
			p.Clients = append(p.Clients, clientRow{ID: c.ID, Name: c.Name, Redirects: strings.Join(c.RedirectURIs, " "), Manual: c.Manual, Created: c.Created, LastUsed: c.LastUsed, Grants: counts[c.ID]})
		}
	})
	sort.Slice(p.Clients, func(i, j int) bool { return p.Clients[i].Created.After(p.Clients[j].Created) })
	g.render(w, "dashboard", p)
}

// handleCreatePersonalToken makes a long-lived token for clients that take
// a fixed header, like Claude Code or MCP Inspector.
func (g *gateway) handleCreatePersonalToken(w http.ResponseWriter, r *http.Request) {
	s := g.requireAdmin(w, r)
	if s == nil {
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		name = "token"
	}
	res := r.PostFormValue("resource")
	if _, ok := g.upstreams[res]; !ok {
		res = "*"
	}
	var exp time.Time
	if d, err := time.ParseDuration(r.PostFormValue("ttl")); err == nil && d > 0 {
		exp = time.Now().Add(d)
	}
	tok := "gw_" + randomToken(32)
	if err := g.store.update(func(p *persisted) {
		p.Grants = append(p.Grants, grant{Hash: sha(tok), Kind: "personal", Name: name, Resource: res, Created: time.Now(), Expires: exp})
	}); err != nil {
		g.renderDashboard(w, r, s, "", err.Error())
		return
	}
	g.log.Info("personal token created", "name", name, "resource", res)
	g.renderDashboard(w, r, s, "New token \""+name+"\" (shown only now): "+tok, "")
}

// handleCreateClient makes an OAuth client with a fixed id and secret, for
// apps that want "static credentials" instead of registering themselves.
func (g *gateway) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	s := g.requireAdmin(w, r)
	if s == nil {
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	var redirects []string
	for _, f := range strings.Fields(r.PostFormValue("redirect_uris")) {
		if !validRedirect(f) {
			g.renderDashboard(w, r, s, "", "Invalid redirect URI: "+f)
			return
		}
		redirects = append(redirects, f)
	}
	if len(redirects) == 0 {
		g.renderDashboard(w, r, s, "", "Add at least one redirect URI (the app you connect shows it).")
		return
	}
	secret := randomToken(32)
	c := &client{ID: "c_" + randomToken(16), Name: name, RedirectURIs: redirects, SecretHash: sha(secret), Manual: true, Created: time.Now()}
	if err := g.store.update(func(p *persisted) { p.Clients[c.ID] = c }); err != nil {
		g.renderDashboard(w, r, s, "", err.Error())
		return
	}
	g.renderDashboard(w, r, s, "OAuth client created. Client ID: "+c.ID+"  Client secret (shown only now): "+secret, "")
}

func (g *gateway) handleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	s := g.requireAdmin(w, r)
	if s == nil {
		return
	}
	kind, id := r.PostFormValue("kind"), r.PostFormValue("id")
	var msg string
	err := g.store.update(func(p *persisted) {
		switch kind {
		case "client":
			delete(p.Clients, id)
			p.Grants = slices.DeleteFunc(p.Grants, func(gr grant) bool { return gr.ClientID == id })
			msg = "The app was removed and logged out."
		case "personal":
			p.Grants = slices.DeleteFunc(p.Grants, func(gr grant) bool { return gr.Kind == "personal" && strings.HasPrefix(gr.Hash, id) })
			msg = "Token deleted."
		case "all":
			p.Grants = slices.DeleteFunc(p.Grants, func(gr grant) bool { return gr.Kind == "refresh" })
			msg = "All apps were logged out."
		}
	})
	if err != nil {
		g.renderDashboard(w, r, s, "", err.Error())
		return
	}
	// Drop matching live access tokens too.
	g.mu.Lock()
	for k, t := range g.tokens {
		if kind == "all" || (kind == "client" && t.ClientID == id) {
			delete(g.tokens, k)
		}
	}
	g.mu.Unlock()
	g.renderDashboard(w, r, s, msg, "")
}

// ---------- upstream settings and test ----------

func (g *gateway) upstreamFromPath(w http.ResponseWriter, r *http.Request) *upstream {
	u, ok := g.upstreams[r.PathValue("name")]
	if !ok {
		http.NotFound(w, r)
		return nil
	}
	return u
}

func (g *gateway) loadConfig(ctx context.Context, u *upstream) (*configDoc, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var doc configDoc
	if _, err := g.upstreamCall(ctx, u, http.MethodGet, "/config", nil, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func (g *gateway) renderUpstream(w http.ResponseWriter, r *http.Request, s *session, u *upstream, doc *configDoc, h *health, msg, errMsg string) {
	p := page{Title: u.Name, CSRF: s.CSRF, Message: msg, Error: errMsg, Base: g.base(r), Upstream: u.Name, Config: doc, Health: h}
	p.MCPURL = p.Base + "/" + u.Name + "/mcp"
	if u.Token == "" {
		p.Error = strings.TrimSpace(p.Error + " UPSTREAM_TOKEN is not set, so the gateway cannot read or save the settings.")
	}
	g.render(w, "upstream", p)
}

func (g *gateway) handleUpstreamPage(w http.ResponseWriter, r *http.Request) {
	s := g.requireAdmin(w, r)
	if s == nil {
		return
	}
	u := g.upstreamFromPath(w, r)
	if u == nil {
		return
	}
	doc, err := g.loadConfig(r.Context(), u)
	errMsg := ""
	if err != nil {
		errMsg = "Could not load the settings: " + err.Error()
	}
	g.renderUpstream(w, r, s, u, doc, nil, "", errMsg)
}

func (g *gateway) handleUpstreamSave(w http.ResponseWriter, r *http.Request) {
	s := g.requireAdmin(w, r)
	if s == nil {
		return
	}
	u := g.upstreamFromPath(w, r)
	if u == nil {
		return
	}
	doc, err := g.loadConfig(r.Context(), u)
	if err != nil {
		g.renderUpstream(w, r, s, u, nil, nil, "", "Could not load the settings: "+err.Error())
		return
	}
	values := map[string]string{}
	for _, f := range doc.Fields {
		if f.Locked {
			continue
		}
		v := r.PostFormValue("f_" + f.Key)
		switch f.Type {
		case "bool":
			if v != "" {
				v = "true"
			} else {
				v = "false"
			}
		case "secret":
			if v == "" {
				continue // keep the current secret
			}
		}
		if f.Type != "bool" && v == f.Value && f.Type != "secret" {
			continue
		}
		values[f.Key] = v
	}
	body, _ := json.Marshal(map[string]any{"values": values})
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	var updated configDoc
	if _, err := g.upstreamCall(ctx, u, http.MethodPost, "/config", bytes.NewReader(body), &updated); err != nil {
		g.renderUpstream(w, r, s, u, doc, nil, "", "Saving failed: "+err.Error())
		return
	}
	g.log.Info("upstream settings saved", "upstream", u.Name, "keys", len(values))
	g.renderUpstream(w, r, s, u, &updated, nil, "Saved. Press Test to check that the settings work.", "")
}

func (g *gateway) handleUpstreamTest(w http.ResponseWriter, r *http.Request) {
	s := g.requireAdmin(w, r)
	if s == nil {
		return
	}
	u := g.upstreamFromPath(w, r)
	if u == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	var h health
	_, err := g.upstreamCall(ctx, u, http.MethodGet, "/healthz?check=1", nil, &h)
	if err != nil && h.Status == "" {
		h = health{OK: false, Status: "error", Checks: []check{{Name: "Contact with " + u.Name, OK: false, Detail: err.Error()}}}
	}
	doc, cerr := g.loadConfig(r.Context(), u)
	errMsg := ""
	if cerr != nil {
		errMsg = "Could not load the settings: " + cerr.Error()
	}
	g.renderUpstream(w, r, s, u, doc, &h, "", errMsg)
}
