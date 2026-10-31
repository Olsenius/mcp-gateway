// mcp-gateway puts OAuth 2.1 login in front of one or more MCP servers so
// that claude.ai, ChatGPT and other remote MCP clients can use them, and
// gives an admin page to set each server's settings and test them.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

var version = "0.1.0"

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

type upstream struct {
	Name  string
	URL   *url.URL
	Token string // sent as "Authorization: Bearer" to the upstream
}

type session struct {
	CSRF    string
	Expires time.Time
}

type accessToken struct {
	ClientID string
	Resource string
	Expires  time.Time
}

type pendingAuth struct {
	ClientID      string
	ClientName    string
	RedirectURI   string
	State         string
	CodeChallenge string
	Resource      string
	Scope         string
	Expires       time.Time
}

type authCode struct {
	pendingAuth
	Used bool
}

type gateway struct {
	log       *slog.Logger
	store     *store
	publicURL string
	adminEnv  string
	setupCode string
	upstreams map[string]*upstream
	order     []string
	accessTTL time.Duration
	refreshTT time.Duration

	mu       sync.Mutex
	sessions map[string]*session
	tokens   map[string]accessToken // sha(token) -> info
	pending  map[string]*pendingAuth
	codes    map[string]*authCode // sha(code) -> code
	limiter  *limiter
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)

// parseUpstreams reads UPSTREAMS="name=http://host:port,other=http://...".
// The token for each is UPSTREAM_TOKEN_<NAME> or else UPSTREAM_TOKEN.
func parseUpstreams(spec string) (map[string]*upstream, []string, error) {
	out := map[string]*upstream{}
	var order []string
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, raw, ok := strings.Cut(part, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if !ok || !nameRe.MatchString(name) {
			return nil, nil, fmt.Errorf("UPSTREAMS: bad entry %q (want name=http://host:port, name in a-z0-9-)", part)
		}
		u, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, nil, fmt.Errorf("UPSTREAMS: bad URL for %s: %q", name, raw)
		}
		if _, dup := out[name]; dup {
			return nil, nil, fmt.Errorf("UPSTREAMS: %s listed twice", name)
		}
		tok := env("UPSTREAM_TOKEN_"+strings.ToUpper(strings.ReplaceAll(name, "-", "_")), env("UPSTREAM_TOKEN", ""))
		out[name] = &upstream{Name: name, URL: u, Token: tok}
		order = append(order, name)
	}
	if len(out) == 0 {
		return nil, nil, fmt.Errorf("UPSTREAMS is empty (e.g. UPSTREAMS=bibliofil=http://bibliofil-mcp:8080)")
	}
	sort.Strings(order)
	return out, order, nil
}

func parseDur(key string, def time.Duration) time.Duration {
	if v := env(key, ""); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

func main() {
	healthcheck := flag.Bool("healthcheck", false, "check that the server answers, for Docker HEALTHCHECK")
	flag.Parse()
	if *healthcheck {
		resp, err := http.Get("http://127.0.0.1:" + env("PORT", "8080") + "/healthz")
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		os.Exit(0)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ups, order, err := parseUpstreams(env("UPSTREAMS", ""))
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}
	g := &gateway{
		log:       log,
		store:     openStore(env("DATA_DIR", "/data"), log),
		publicURL: strings.TrimRight(env("PUBLIC_URL", ""), "/"),
		adminEnv:  os.Getenv("ADMIN_PASSWORD"),
		upstreams: ups,
		order:     order,
		accessTTL: parseDur("ACCESS_TOKEN_TTL", time.Hour),
		refreshTT: parseDur("REFRESH_TOKEN_TTL", 30*24*time.Hour),
		sessions:  map[string]*session{},
		tokens:    map[string]accessToken{},
		pending:   map[string]*pendingAuth{},
		codes:     map[string]*authCode{},
		limiter:   newLimiter(),
	}
	if g.publicURL == "" {
		log.Warn("PUBLIC_URL is not set; it is guessed from each request (set it to your public https URL)")
	}
	if !g.hasAdmin() {
		g.setupCode = randomToken(9)
		log.Warn("no admin password yet: open /admin and use this one-time setup code", "setup_code", g.setupCode)
	}
	for _, n := range order {
		if ups[n].Token == "" {
			log.Warn("no UPSTREAM_TOKEN for upstream; settings page and test need one", "upstream", n)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go g.janitor(ctx)

	srv := &http.Server{
		Addr:              ":" + env("PORT", "8080"),
		Handler:           g.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	log.Info("listening", "addr", srv.Addr, "upstreams", strings.Join(order, ","), "public_url", g.publicURL, "version", version)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("http", "err", err)
		os.Exit(1)
	}
}

func (g *gateway) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/admin", http.StatusFound) })

	// OAuth discovery and endpoints.
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", g.handleASMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server/", g.handleASMetadata)
	mux.HandleFunc("GET /.well-known/openid-configuration", g.handleASMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", g.handleResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/", g.handleResourceMetadata)
	mux.HandleFunc("POST /oauth/register", g.handleRegister)
	mux.HandleFunc("GET /oauth/authorize", g.handleAuthorize)
	mux.HandleFunc("POST /oauth/authorize", g.handleAuthorizePost)
	mux.HandleFunc("POST /oauth/token", g.handleToken)
	mux.HandleFunc("POST /oauth/revoke", g.handleRevoke)

	// Admin.
	mux.HandleFunc("GET /admin", g.handleAdmin)
	mux.HandleFunc("POST /admin/login", g.handleLogin)
	mux.HandleFunc("POST /admin/setup", g.handleFirstSetup)
	mux.HandleFunc("POST /admin/logout", g.handleLogout)
	mux.HandleFunc("POST /admin/password", g.handleChangePassword)
	mux.HandleFunc("GET /admin/u/{name}", g.handleUpstreamPage)
	mux.HandleFunc("POST /admin/u/{name}/save", g.handleUpstreamSave)
	mux.HandleFunc("POST /admin/u/{name}/test", g.handleUpstreamTest)
	mux.HandleFunc("POST /admin/tokens", g.handleCreatePersonalToken)
	mux.HandleFunc("POST /admin/clients", g.handleCreateClient)
	mux.HandleFunc("POST /admin/revoke", g.handleAdminRevoke)

	// MCP proxy: /<name>/mcp
	mux.HandleFunc("/{name}/mcp", g.handleMCP)
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions { // CORS preflight for browser-based MCP clients
			cors(w)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		if !strings.HasSuffix(r.URL.Path, "/mcp") {
			h.Set("X-Frame-Options", "DENY")
			h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self' https: http://localhost:* http://127.0.0.1:*; frame-ancestors 'none'; base-uri 'none'")
		}
		next.ServeHTTP(w, r)
	})
}

// base is the public URL of the gateway, used as OAuth issuer.
func (g *gateway) base(r *http.Request) string {
	if g.publicURL != "" {
		return g.publicURL
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host
}

func (g *gateway) secureCookies(r *http.Request) bool {
	return strings.HasPrefix(g.base(r), "https://")
}

// janitor drops expired sessions, tokens and codes.
func (g *gateway) janitor(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			g.mu.Lock()
			for k, s := range g.sessions {
				if now.After(s.Expires) {
					delete(g.sessions, k)
				}
			}
			for k, v := range g.tokens {
				if now.After(v.Expires) {
					delete(g.tokens, k)
				}
			}
			for k, v := range g.pending {
				if now.After(v.Expires) {
					delete(g.pending, k)
				}
			}
			for k, v := range g.codes {
				if now.After(v.Expires) {
					delete(g.codes, k)
				}
			}
			g.mu.Unlock()
		}
	}
}

// ---------- login rate limiting ----------

type limiter struct {
	mu     sync.Mutex
	perIP  map[string][]time.Time
	global []time.Time
}

func newLimiter() *limiter { return &limiter{perIP: map[string][]time.Time{}} }

const (
	limitWindow = 15 * time.Minute
	limitPerIP  = 5
	limitGlobal = 30
)

func prune(ts []time.Time, now time.Time) []time.Time {
	out := ts[:0]
	for _, t := range ts {
		if now.Sub(t) < limitWindow {
			out = append(out, t)
		}
	}
	return out
}

// blocked reports whether logins from ip are paused after too many failures.
func (l *limiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.perIP[ip] = prune(l.perIP[ip], now)
	l.global = prune(l.global, now)
	return len(l.perIP[ip]) >= limitPerIP || len(l.global) >= limitGlobal
}

func (l *limiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.perIP[ip] = append(l.perIP[ip], now)
	l.global = append(l.global, now)
}

func clientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		ip, _, _ := strings.Cut(xf, ",")
		return strings.TrimSpace(ip)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---------- admin password ----------

func (g *gateway) hasAdmin() bool {
	if g.adminEnv != "" {
		return true
	}
	var h string
	g.store.read(func(p *persisted) { h = p.AdminHash })
	return h != ""
}

// checkAdmin verifies the admin password, with rate limiting.
func (g *gateway) checkAdmin(r *http.Request, pw string) (ok bool, msg string) {
	ip := clientIP(r)
	if g.limiter.blocked(ip) {
		return false, "Too many failed attempts. Wait 15 minutes."
	}
	good := false
	if pw != "" {
		if g.adminEnv != "" {
			good = constEq(pw, g.adminEnv)
		} else {
			var h string
			g.store.read(func(p *persisted) { h = p.AdminHash })
			good = h != "" && checkPassword(h, pw)
		}
	}
	if !good {
		g.limiter.fail(ip)
		time.Sleep(700 * time.Millisecond)
		g.log.Warn("failed admin login", "ip", ip)
		return false, "Wrong password."
	}
	return true, ""
}
