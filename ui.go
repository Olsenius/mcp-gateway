package main

import (
	"html/template"
	"net/http"
	"time"
)

type page struct {
	Title, CSRF, Message, Error, Base string

	Upstreams []upstreamRow
	Personal  []grantRow
	Clients   []clientRow

	Upstream string
	MCPURL   string
	Config   *configDoc
	Health   *health

	// consent
	ReqID, ClientName, ClientID, Redirect, Resource string
	LoggedIn                                        bool

	OIDCLabel string // set when login through an OIDC provider is enabled
}

var funcs = template.FuncMap{
	"date": func(t time.Time) string {
		if t.IsZero() {
			return "–"
		}
		return t.In(time.Local).Format("02.01.2006 15:04")
	},
	"isSelected": func(a, b string) bool { return a == b },
}

var tmpl = template.Must(template.New("").Funcs(funcs).Parse(`
{{define "head"}}<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} · MCP gateway</title>
<style>
:root{--fg:#1d1d1f;--muted:#6e6e73;--line:#e3e3e8;--bg:#f6f6f8;--card:#fff;--accent:#1f5bd8;--ok:#1a7f37;--bad:#c62828}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:var(--fg);background:var(--bg)}
main{max-width:860px;margin:0 auto;padding:24px 16px 64px}
header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
h1{font-size:22px;margin:0}h2{font-size:17px;margin:0 0 12px}
a{color:var(--accent)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px;margin:14px 0}
.msg{border-radius:8px;padding:10px 12px;margin:12px 0;word-break:break-all}
.ok{background:#e8f5ec;color:var(--ok)}.err{background:#fdecec;color:var(--bad)}
label{display:block;font-weight:600;margin:14px 0 4px}
.help{color:var(--muted);font-size:13px;margin:2px 0 0}
input[type=text],input[type=url],input[type=password],select,textarea{width:100%;padding:8px 10px;border:1px solid var(--line);border-radius:7px;font:inherit;background:#fff}
input:disabled,select:disabled{background:#f2f2f4;color:var(--muted)}
button{font:inherit;padding:8px 14px;border-radius:7px;border:1px solid var(--accent);background:var(--accent);color:#fff;cursor:pointer}
a.button{display:inline-block;text-decoration:none;font:inherit;padding:8px 14px;border-radius:7px;border:1px solid var(--accent);background:var(--accent);color:#fff}
button.secondary{background:#fff;color:var(--accent)}button.danger{background:#fff;border-color:var(--bad);color:var(--bad)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:6px 4px;border-bottom:1px solid var(--line);vertical-align:top}
code{background:#f2f2f4;padding:2px 6px;border-radius:5px;word-break:break-all}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}.up{background:var(--ok)}.down{background:var(--bad)}
.lock{color:var(--muted);font-size:13px}
.check{display:flex;gap:8px;margin:4px 0}.check b{min-width:18px}
form.inline{display:inline}
</style></head><body><main>{{end}}

{{define "foot"}}</main></body></html>{{end}}

{{define "msgs"}}{{if .Message}}<div class="msg ok">{{.Message}}</div>{{end}}{{if .Error}}<div class="msg err">{{.Error}}</div>{{end}}{{end}}

{{define "login"}}{{template "head" .}}
<h1>MCP gateway</h1>{{template "msgs" .}}
{{if .OIDCLabel}}<div class="card"><p><a class="button" href="/admin/oidc/login">Log in with {{.OIDCLabel}}</a></p></div>{{end}}
<div class="card"><form method="post" action="/admin/login">
<label>Admin password</label><input type="password" name="password" autocomplete="current-password" autofocus required>
<p><button>Log in</button></p></form></div>
{{template "foot"}}{{end}}

{{define "error"}}{{template "head" .}}
<h1>{{.Title}}</h1><div class="msg err">{{.Error}}</div>
{{template "foot"}}{{end}}

{{define "consent"}}{{template "head" .}}
<h1>Allow access?</h1>{{template "msgs" .}}
<div class="card">
<p><b>{{if .ClientName}}{{.ClientName}}{{else}}An app{{end}}</b> wants to use
{{if eq .Resource "*"}}<b>all</b> MCP servers{{else}}<b>{{.Resource}}</b>{{end}} on this gateway.</p>
<p class="help">You will be sent back to: <code>{{.Redirect}}</code><br>Client: <code>{{.ClientID}}</code></p>
<p class="help">Only allow this if you just started connecting from the app yourself.</p>
<form method="post" action="/oauth/authorize">
<input type="hidden" name="req" value="{{.ReqID}}">
{{if .LoggedIn}}<input type="hidden" name="csrf" value="{{.CSRF}}">{{else}}
{{if .OIDCLabel}}<p><a class="button" href="/admin/oidc/login?req={{.ReqID}}">Log in with {{.OIDCLabel}}</a></p>
<p class="help">or use the admin password:</p>{{end}}
<label>Admin password</label><input type="password" name="password" autocomplete="current-password" autofocus required>{{end}}
<p class="row"><button name="action" value="allow">Allow</button>
<button class="secondary" name="action" value="deny" formnovalidate>Deny</button></p>
</form></div>
{{template "foot"}}{{end}}

{{define "dashboard"}}{{template "head" .}}
<header><h1>MCP gateway</h1>
<form method="post" action="/admin/logout" class="inline"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="secondary">Log out</button></form></header>
{{template "msgs" .}}

<div class="card"><h2>MCP servers</h2>
<table><tr><th>Name</th><th>URL for apps</th><th></th></tr>
{{range .Upstreams}}<tr>
<td><span class="dot {{if .Alive}}up{{else}}down{{end}}"></span>{{.Name}}</td>
<td><code>{{.MCPURL}}</code></td>
<td><a href="/admin/u/{{.Name}}">Settings and test</a></td></tr>{{end}}
</table>
<p class="help">Paste the URL into claude.ai (Settings → Connectors → Add custom connector) or ChatGPT (Developer mode → Create connector, authentication: OAuth).</p></div>

<div class="card"><h2>Connected apps (OAuth)</h2>
{{if .Clients}}<table><tr><th>App</th><th>Created</th><th>Last used</th><th>Sessions</th><th></th></tr>
{{range .Clients}}<tr><td>{{if .Name}}{{.Name}}{{else}}<i>no name</i>{{end}}{{if .Manual}} (manual){{end}}<br><span class="help">{{.Redirects}}</span></td>
<td>{{date .Created}}</td><td>{{date .LastUsed}}</td><td>{{.Grants}}</td>
<td><form method="post" action="/admin/revoke" class="inline"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="kind" value="client"><input type="hidden" name="id" value="{{.ID}}"><button class="danger">Remove</button></form></td></tr>{{end}}
</table>
<form method="post" action="/admin/revoke"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="kind" value="all"><p><button class="danger">Log out all apps</button></p></form>
{{else}}<p class="help">None yet.</p>{{end}}
<details><summary>Create an OAuth client with a fixed ID and secret</summary>
<p class="help">For apps that want static credentials instead of registering themselves.</p>
<form method="post" action="/admin/clients"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Name</label><input type="text" name="name">
<label>Redirect URIs (space separated)</label><input type="text" name="redirect_uris" placeholder="https://chatgpt.com/connector_platform_oauth_redirect">
<p><button class="secondary">Create client</button></p></form></details></div>

<div class="card"><h2>Personal tokens</h2>
<p class="help">For clients that take a fixed header, like Claude Code: <code>Authorization: Bearer &lt;token&gt;</code>.</p>
{{if .Personal}}<table><tr><th>Name</th><th>Scope</th><th>Created</th><th>Expires</th><th></th></tr>
{{range .Personal}}<tr><td>{{.Label}}</td><td>{{if eq .Resource "*"}}all{{else}}{{.Resource}}{{end}}</td><td>{{date .Created}}</td><td>{{date .Expires}}</td>
<td><form method="post" action="/admin/revoke" class="inline"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="kind" value="personal"><input type="hidden" name="id" value="{{.ID}}"><button class="danger">Delete</button></form></td></tr>{{end}}</table>{{end}}
<form method="post" action="/admin/tokens"><input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="row"><input type="text" name="name" placeholder="Name, e.g. claude-code" style="flex:2">
<select name="resource" style="flex:1"><option value="*">All servers</option>{{range .Upstreams}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select>
<select name="ttl" style="flex:1"><option value="">Never expires</option><option value="720h">30 days</option><option value="2160h">90 days</option></select>
<button class="secondary">Create token</button></div></form></div>

<div class="card"><h2>Admin login</h2>
<p class="help">Admin password: set with <code>ADMIN_PASSWORD</code> (at least 40 characters), or generated on first start and retrieved with <code>-print-admin-password</code>.</p>
<p class="help">{{if .OIDCLabel}}Login with <b>{{.OIDCLabel}}</b> is also enabled.{{else}}Login with an OpenID Connect provider is off; set <code>OIDC_ISSUER</code> to enable it.{{end}}</p></div>
{{template "foot"}}{{end}}

{{define "upstream"}}{{template "head" .}}
<header><h1>{{.Upstream}}</h1><a href="/admin">← Overview</a></header>
<p>URL for apps: <code>{{.MCPURL}}</code></p>
{{template "msgs" .}}

<div class="card"><h2>Test</h2>
<p class="help">Asks {{.Upstream}} whether its settings work (calls <code>/healthz?check=1</code>).</p>
{{with .Health}}<div class="msg {{if .OK}}ok{{else}}err{{end}}">{{if .OK}}Everything works.{{else}}Something is failing ({{.Status}}).{{end}}</div>
{{range .Checks}}<div class="check"><b>{{if .OK}}✓{{else}}✗{{end}}</b><span><b>{{.Name}}</b>{{if .Detail}} – {{.Detail}}{{end}}</span></div>{{end}}{{end}}
<form method="post" action="/admin/u/{{.Upstream}}/test"><input type="hidden" name="csrf" value="{{.CSRF}}"><p><button class="secondary">Test</button></p></form></div>

{{with .Config}}<div class="card"><h2>Settings {{if not .Configured}}<span class="lock">(not set up yet)</span>{{end}}</h2>
<p class="help">Values are stored by {{.Name}} {{.Version}}. Fields set with environment variables are locked.</p>
<form method="post" action="/admin/u/{{$.Upstream}}/save" autocomplete="off"><input type="hidden" name="csrf" value="{{$.CSRF}}">
{{range .Fields}}
<label for="f_{{.Key}}">{{.Label}}{{if .Required}} *{{end}}</label>
{{if eq .Type "bool"}}<input type="checkbox" id="f_{{.Key}}" name="f_{{.Key}}" value="true" {{if eq .Value "true"}}checked{{end}} {{if .Locked}}disabled{{end}}>
{{else if eq .Type "secret"}}<input type="password" id="f_{{.Key}}" name="f_{{.Key}}" autocomplete="new-password" placeholder="{{if .Set}}•••••• (set – leave empty to keep){{end}}" {{if .Locked}}disabled{{end}}>
{{else if and (eq .Type "select") .Options}}<select id="f_{{.Key}}" name="f_{{.Key}}" {{if .Locked}}disabled{{end}}><option value="">(default)</option>
{{$v := .Value}}{{range .Options}}<option value="{{.Value}}" {{if isSelected .Value $v}}selected{{end}}>{{.Label}}</option>{{end}}</select>
{{else}}<input type="{{if eq .Type "url"}}url{{else}}text{{end}}" id="f_{{.Key}}" name="f_{{.Key}}" value="{{.Value}}" placeholder="{{.Default}}" {{if .Locked}}disabled{{end}}>{{end}}
<p class="help">{{if .Help}}{{.Help}} {{end}}<code>{{.Key}}</code>{{if .Locked}} <span class="lock">– locked by environment variable</span>{{end}}{{if and (eq .Type "select") (not .Options)}} <span class="lock">– choices appear once the account works</span>{{end}}</p>
{{end}}
<p class="row"><button>Save</button></p></form></div>{{end}}
{{template "foot"}}{{end}}
`))

func (g *gateway) render(w http.ResponseWriter, name string, p page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := tmpl.ExecuteTemplate(w, name, p); err != nil {
		g.log.Error("render", "template", name, "err", err)
	}
}

func (g *gateway) renderLogin(w http.ResponseWriter, r *http.Request, msg string) {
	g.render(w, "login", page{Title: "Log in", Error: msg, OIDCLabel: g.oidcLabel()})
}

func (g *gateway) renderError(w http.ResponseWriter, title, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	if err := tmpl.ExecuteTemplate(w, "error", page{Title: title, Error: msg}); err != nil {
		g.log.Error("render", "template", "error", "err", err)
	}
}

func (g *gateway) renderConsent(w http.ResponseWriter, r *http.Request, id string, p *pendingAuth, errMsg string) {
	pg := page{Title: "Allow access", Error: errMsg, ReqID: id, ClientName: p.ClientName, ClientID: p.ClientID, Redirect: p.RedirectURI, Resource: p.Resource, OIDCLabel: g.oidcLabel()}
	if s := g.currentSession(r); s != nil {
		pg.LoggedIn, pg.CSRF = true, s.CSRF
	}
	g.render(w, "consent", pg)
}

func (g *gateway) oidcLabel() string {
	if g.oidc == nil {
		return ""
	}
	return g.oidc.cfg.Label
}
