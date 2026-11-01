// mcp-gateway puts OAuth 2.1 login in front of one or more MCP servers so
// that claude.ai, ChatGPT and other remote MCP clients can use them, and
// gives an admin page to set each server's settings and test them.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
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
	log            *slog.Logger
	store          *store
	publicURL      string
	adminPW        string // ADMIN_PASSWORD, or generated and kept in DATA_DIR
	upstreams      map[string]*upstream
	order          []string
	accessTTL      time.Duration
	refreshTT      time.Duration
	trustedProxies []netip.Prefix
	oidc           *oidcProvider // nil unless OIDC_ISSUER is set

	mu         sync.Mutex
	sessions   map[string]*session
	tokens     map[string]accessToken // sha(token) -> info
	pending    map[string]*pendingAuth
	codes      map[string]*authCode  // sha(code) -> code
	oidcLogins map[string]*oidcLogin // sha(state) -> login
	limiter    *limiter
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
	printPassword := flag.Bool("print-admin-password", false, "print the admin password explicitly")
	rotatePassword := flag.Bool("rotate-admin-password", false, "rotate the stored admin password; restart gateway afterwards")
	flag.Parse()
	if *printPassword || *rotatePassword {
		dir := env("DATA_DIR", "/data")
		if *rotatePassword {
			if os.Getenv("ADMIN_PASSWORD") != "" {
				fmt.Fprintln(os.Stderr, "ADMIN_PASSWORD is set; rotate it in the deployment configuration")
				os.Exit(2)
			}
			path := filepath.Join(dir, "admin-password")
			tmp, err := os.CreateTemp(dir, ".admin-password-*")
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			name := tmp.Name()
			defer os.Remove(name)
			_, err = tmp.WriteString(randomToken(36) + "\n")
			closeErr := tmp.Close()
			if err == nil {
				err = closeErr
			}
			if err == nil {
				err = os.Rename(name, path)
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			fmt.Fprintln(os.Stdout, "Admin password rotated; restart the gateway to activate it.")
			return
		}
		pw, _, err := adminPassword(dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stdout, pw)
		return
	}
	if *healthcheck {
		resp, err := http.Get("http://127.0.0.1:" + env("PORT", "8080") + "/healthz")
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		os.Exit(0)
	}

	log, err := newLogger(os.Stderr)
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(2)
	}
	shutdownTracing, err := initTracing(context.Background())
	if err != nil {
		log.Error("tracing config", "err", err)
		os.Exit(2)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTracing(ctx); err != nil {
			log.Warn("trace shutdown", "err", err)
		}
	}()
	ups, order, err := parseUpstreams(env("UPSTREAMS", ""))
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}
	trusted, err := parseTrustedProxies(env("TRUSTED_PROXIES", ""))
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}
	g := &gateway{
		trustedProxies: trusted,
		log:            log,
		store:          openStore(env("DATA_DIR", "/data"), log),
		publicURL:      strings.TrimRight(env("PUBLIC_URL", ""), "/"),
		upstreams:      ups,
		order:          order,
		accessTTL:      parseDur("ACCESS_TOKEN_TTL", time.Hour),
		refreshTT:      parseDur("REFRESH_TOKEN_TTL", 30*24*time.Hour),
		sessions:       map[string]*session{},
		tokens:         map[string]accessToken{},
		pending:        map[string]*pendingAuth{},
		codes:          map[string]*authCode{},
		oidcLogins:     map[string]*oidcLogin{},
		limiter:        newLimiter(),
	}
	if g.publicURL == "" {
		log.Warn("PUBLIC_URL is not set; it is guessed from each request (set it to your public https URL)")
	}
	oc, err := oidcFromEnv(g.publicURL)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}
	if oc != nil {
		g.oidc = newOIDCProvider(*oc)
		log.Info("OIDC login enabled", "issuer", oc.Issuer, "redirect_url", oc.RedirectURL,
			"allowed_users", len(oc.AllowedUsers), "allowed_groups", strings.Join(oc.AllowedGroups, ","))
	}
	pw, source, err := adminPassword(env("DATA_DIR", "/data"))
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}
	g.adminPW = pw
	if source != "env" {
		log.Info("admin password stored; use -print-admin-password to retrieve it", "file", source)
	}
	for _, n := range order {
		if ups[n].Token == "" {
			log.Warn("no UPSTREAM_TOKEN for upstream; settings page and test need one", "upstream", n)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go g.janitor(ctx)

	srv := g.httpServer()
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
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
	<-shutdownDone
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
	mux.HandleFunc("GET /oauth/authorize/resume", g.handleAuthorizeResume)
	mux.HandleFunc("POST /oauth/token", g.handleToken)
	mux.HandleFunc("POST /oauth/revoke", g.handleRevoke)

	// Admin.
	mux.HandleFunc("GET /admin", g.handleAdmin)
	mux.HandleFunc("POST /admin/login", g.handleLogin)
	mux.HandleFunc("POST /admin/logout", g.handleLogout)
	mux.HandleFunc("GET /admin/oidc/login", g.handleOIDCLogin)
	mux.HandleFunc("GET /admin/oidc/callback", g.handleOIDCCallback)
	mux.HandleFunc("GET /admin/u/{name}", g.handleUpstreamPage)
	mux.HandleFunc("POST /admin/u/{name}/save", g.handleUpstreamSave)
	mux.HandleFunc("POST /admin/u/{name}/test", g.handleUpstreamTest)
	mux.HandleFunc("POST /admin/tokens", g.handleCreatePersonalToken)
	mux.HandleFunc("POST /admin/clients", g.handleCreateClient)
	mux.HandleFunc("POST /admin/revoke", g.handleAdminRevoke)

	// MCP proxy: /<name>/mcp
	mux.HandleFunc("/{name}/mcp", g.handleMCP)
	return traceHTTP(g.accessLog(securityHeaders(mux)))
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
			for k, v := range g.oidcLogins {
				if now.After(v.Expires) {
					delete(g.oidcLogins, k)
				}
			}
			g.mu.Unlock()
		}
	}
}

// ---------- login rate limiting ----------

type limiter struct {
	mu                 sync.Mutex
	perIP              map[string][]time.Time
	registrations      map[string][]time.Time
	registrationGlobal []time.Time
}

func newLimiter() *limiter { return &limiter{perIP: map[string][]time.Time{}} }

const (
	limitWindow = 15 * time.Minute
	limitPerIP  = 5
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
	return len(l.perIP[ip]) >= limitPerIP
}

func (l *limiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.perIP[ip] = append(l.perIP[ip], now)
	for key, ts := range l.perIP {
		ts = prune(ts, now)
		if len(ts) == 0 {
			delete(l.perIP, key)
		} else {
			l.perIP[key] = ts
		}
	}
	// Bound memory even when many independent source addresses fail.
	if len(l.perIP) > 10000 {
		delete(l.perIP, ip)
	}
}

// ---------- admin password ----------

const minAdminPassword = 40

// adminPassword returns ADMIN_PASSWORD (at least 40 characters), or a
// random password generated on first start and kept in DATA_DIR. source
// is "env" or the file path. An unwritable DATA_DIR fails closed.
func adminPassword(dir string) (pw, source string, err error) {
	if v := os.Getenv("ADMIN_PASSWORD"); v != "" {
		if n := len([]rune(v)); n < minAdminPassword {
			return "", "", fmt.Errorf("ADMIN_PASSWORD must have at least %d characters (has %d); leave it unset to get a generated one", minAdminPassword, n)
		}
		return v, "env", nil
	}
	if dir != "" {
		path := filepath.Join(dir, "admin-password")
		if data, err := os.ReadFile(path); err == nil {
			if v := strings.TrimSpace(string(data)); len(v) >= minAdminPassword {
				return v, path, nil
			}
		}
		pw = randomToken(36) // 48 characters
		if err := os.MkdirAll(dir, 0o700); err == nil {
			if err := os.WriteFile(path, []byte(pw+"\n"), 0o600); err == nil {
				return pw, path, nil
			}
		}
	}
	return "", "", fmt.Errorf("cannot persist admin password in DATA_DIR; set ADMIN_PASSWORD or use a writable DATA_DIR")
}

// checkAdmin verifies the admin password, with rate limiting.
func (g *gateway) checkAdmin(r *http.Request, pw string) (ok bool, msg string) {
	if pw != "" && constEq(pw, g.adminPW) {
		return true, ""
	}
	ip := g.clientIP(r)
	if g.limiter.blocked(ip) {
		return false, "Too many failed attempts. Wait 15 minutes."
	}
	g.limiter.fail(ip)
	time.Sleep(700 * time.Millisecond)
	g.log.Warn("failed admin login", "ip", ip)
	return false, "Wrong password."
}

func (g *gateway) httpServer() *http.Server {
	return &http.Server{
		Addr:              ":" + env("PORT", "8080"),
		Handler:           g.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}
