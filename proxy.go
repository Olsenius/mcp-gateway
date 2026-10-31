package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"
)

var proxies sync.Map // name -> *httputil.ReverseProxy

func (g *gateway) proxyFor(u *upstream) *httputil.ReverseProxy {
	if p, ok := proxies.Load(u.Name); ok {
		return p.(*httputil.ReverseProxy)
	}
	p := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u.URL)
			pr.Out.URL.Path = strings.TrimRight(u.URL.Path, "/") + "/mcp"
			pr.Out.URL.RawPath = ""
			pr.Out.Host = u.URL.Host
			pr.Out.Header.Del("Cookie")
			pr.Out.Header.Del("Authorization")
			if u.Token != "" {
				pr.Out.Header.Set("Authorization", "Bearer "+u.Token)
			}
			pr.SetXForwarded()
		},
		FlushInterval: -1, // stream server-sent events at once
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			g.log.Warn("upstream error", "upstream", u.Name, "err", err)
			http.Error(w, "upstream MCP server is not reachable", http.StatusBadGateway)
		},
	}
	actual, _ := proxies.LoadOrStore(u.Name, p)
	return actual.(*httputil.ReverseProxy)
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func (g *gateway) handleMCP(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	name := r.PathValue("name")
	u, ok := g.upstreams[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !g.allowed(bearer(r), name) {
		meta := g.base(r) + "/.well-known/oauth-protected-resource/" + name + "/mcp"
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata=%q, scope="mcp"`, meta))
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token", "error_description": "log in via OAuth or use a token from the admin page"})
		return
	}
	g.proxyFor(u).ServeHTTP(w, r)
}

// ---------- upstream settings API (the gateway contract) ----------

type option struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

type field struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Type     string   `json:"type"`
	Required bool     `json:"required"`
	Help     string   `json:"help"`
	Value    string   `json:"value"`
	Set      bool     `json:"set"`
	Locked   bool     `json:"locked"`
	Options  []option `json:"options"`
	Default  string   `json:"default"`
}

type configDoc struct {
	Name       string  `json:"name"`
	Version    string  `json:"version"`
	Configured bool    `json:"configured"`
	Fields     []field `json:"fields"`
}

type check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type health struct {
	OK     bool    `json:"ok"`
	Status string  `json:"status"`
	Checks []check `json:"checks"`
}

var upstreamHTTP = &http.Client{Timeout: 60 * time.Second}

func (g *gateway) upstreamCall(ctx context.Context, u *upstream, method, path string, body io.Reader, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(u.URL.String(), "/")+path, body)
	if err != nil {
		return 0, err
	}
	if u.Token != "" {
		req.Header.Set("Authorization", "Bearer "+u.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := upstreamHTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if out != nil && len(data) > 0 && data[0] == '{' {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("upstream answered with invalid JSON: %w", err)
		}
	}
	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(data))
		}
		if len(e.Error) > 300 {
			e.Error = e.Error[:300]
		}
		return resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, e.Error)
	}
	return resp.StatusCode, nil
}

// alive does a quick GET /healthz on the upstream.
func (g *gateway) alive(ctx context.Context, u *upstream) bool {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	code, err := g.upstreamCall(ctx, u, http.MethodGet, "/healthz", nil, nil)
	return err == nil && code == http.StatusOK
}
