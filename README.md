# mcp-gateway

Put OAuth 2.1 login in front of your self-hosted [MCP](https://modelcontextprotocol.io) servers,
so **claude.ai**, **ChatGPT** and other remote MCP clients can use them over the internet.

- One admin password protects everything. No external identity provider needed, but you can add
  login through an OpenID Connect provider such as [Pocket ID](https://pocket-id.org).
- An admin page shows each MCP server's settings as a form, and a **Test** button checks that they work.
- The MCP servers stay on an internal Docker network with no open ports.
- Static Go binary in a distroless image, with optional OpenTelemetry tracing.

```
internet ─► tunnel ─► mcp-gateway ─► your MCP servers
            (Tailscale   (OAuth,         (internal network only)
            Funnel or    admin page)
            cloudflared)
```

## Quick start (Docker Compose)

The included [`docker-compose.yml`](docker-compose.yml) runs the gateway and Tailscale Funnel
with these MCP servers on an internal network:

| Server | What it does | URL path |
|---|---|---|
| [bibliofil-mcp](https://github.com/Olsenius/bibliofil-mcp) | Norwegian public libraries: loans, renewals, reservations | `/bibliofil/mcp` |
| [vigilo-connector](https://github.com/Olsenius/vigilo-connector) | Vigilo for parents: messages, timetable, absences | `/vigilo/mcp` |
| [fribo-mcp](https://github.com/Olsenius/fribo-mcp) | Fribo cabin road plowing: register stays | `/fribo/mcp` |
| [tibi-mcp](https://github.com/Olsenius/tibi-mcp) | Tibi e-books: search, borrow, Kindle and EPUB links | `/tibi/mcp` |
| [spond-no-match-mcp](https://github.com/Olsenius/spond-no-match-mcp) | Spond: the kids' activities, responses and participants | `/spond/mcp` |

```sh
cp .env.example .env      # fill in PUBLIC_URL, the five *_TOKEN values and TS_AUTHKEY
docker compose up -d
docker compose exec gateway /mcp-gateway -print-admin-password
```

Open `https://<your-host>/admin` and log in with the admin password.
Then open each server's **Settings and test** page, fill in the settings, save, and press **Test**.
For Vigilo, log in from the same page.

To leave out a server, remove its service and volume from `docker-compose.yml` and its entry from
`UPSTREAMS`. Any MCP server with Streamable HTTP works; see [The upstream contract](#the-upstream-contract).
For developing the servers and the gateway together, see [mcp-workspace](https://github.com/Olsenius/mcp-workspace).

## Connect an app

Each MCP server gets its own URL: `https://<your-host>/<name>/mcp`.

- **claude.ai:** Settings → Connectors → Add custom connector → paste the URL. Claude registers itself,
  and you approve it with the admin password (or your OIDC login, if enabled).
- **ChatGPT:** Developer mode → create a connector → paste the URL, authentication OAuth.
- **Claude Code and other clients with a fixed header:** make a personal token on the admin page and use
  `Authorization: Bearer <token>`:

  ```sh
  claude mcp add --transport http bibliofil https://<your-host>/bibliofil/mcp \
    --header "Authorization: Bearer gw_..."
  ```

The admin page lists connected apps, and you can log out one or all of them.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `UPSTREAMS` | – | Required. `name=http://host:port`, comma separated, e.g. `bibliofil=http://bibliofil:8080,vigilo=http://vigilo:8080` |
| `UPSTREAM_TOKEN` | – | Shared secret the gateway sends to the MCP servers as `Authorization: Bearer` |
| `UPSTREAM_TOKEN_<NAME>` | – | Per-server token, overrides `UPSTREAM_TOKEN` (name upper-cased, `-` → `_`) |
| `PUBLIC_URL` | guessed | The public https URL, e.g. `https://mcp.example.ts.net`. Set it. |
| `ADMIN_PASSWORD` | generated | Admin password, at least 40 characters, or the gateway refuses to start. If unset, a random 48-character password is generated on first start, stored in `DATA_DIR/admin-password` and retrieved explicitly with `-print-admin-password` |
| `OIDC_ISSUER` | unset | Turns on "Log in with …" through an OpenID Connect provider, e.g. `https://id.example.com`. The admin password keeps working. Needs `PUBLIC_URL` |
| `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | – | Required with `OIDC_ISSUER` |
| `OIDC_ALLOWED_GROUPS` | – | Comma-separated groups (from the `groups` claim) that may log in |
| `OIDC_ALLOWED_USERS` | – | Comma-separated verified e-mail addresses or subject IDs that may log in. At least one of the two lists is required |
| `OIDC_LABEL` | issuer host | Text on the login button |
| `DATA_DIR` | `/data` | Where clients, refresh tokens and the generated admin password are stored |
| `ACCESS_TOKEN_TTL` | `1h` | Lifetime of OAuth access tokens |
| `REFRESH_TOKEN_TTL` | `720h` | Lifetime of refresh tokens (rotated on every use) |
| `TRUSTED_PROXIES` | unset | Comma-separated proxy CIDRs allowed to supply X-Forwarded-For; otherwise the socket peer is used |
| `PORT` | `8080` | |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`; invalid values stop startup |
| `OTEL_SERVICE_NAME` | `mcp-gateway` | Service name in traces |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | OTLP/HTTP base URL, e.g. `http://jaeger:4318`; exporter appends `/v1/traces` |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | unset | Full traces URL; overrides the base endpoint |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` | Only OTLP over HTTP/protobuf is supported |
| `OTEL_SDK_DISABLED` | `false` | Disable trace export even with an endpoint configured |
| `OTEL_TRACES_SAMPLER` | `parentbased_always_on` | Standard OpenTelemetry sampler, e.g. `parentbased_traceidratio` |
| `OTEL_TRACES_SAMPLER_ARG` | unset | Ratio for ratio-based samplers, e.g. `0.1` |

## Login with OpenID Connect (optional)

Besides the admin password, the admin page and the "Allow access?" page can offer
**Log in with &lt;provider&gt;**. Example with Pocket ID:

1. In Pocket ID, add an OIDC client with callback URL `https://<your-host>/admin/oidc/callback`.
   Keep it a confidential client (not public) and note the client ID and secret.
2. Make a group, e.g. `mcp-admins`, and add yourself to it.
3. Set `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` and `OIDC_ALLOWED_GROUPS=mcp-admins`, and restart.

Groups are the safer choice: in some providers users can edit their own e-mail address, while
groups are set by the provider's admin. Anyone who passes the check gets full admin access to the gateway.

The gateway uses the authorization code flow with PKCE, a nonce and a state cookie bound to the
browser, and checks the ID token's RS256 signature, issuer, audience and expiry. Logging in with
OIDC from the "Allow access?" page brings you back to it, and you still have to press **Allow**.
If the provider is down, the admin password still works.

## Exposing it to the internet

**Tailscale Funnel** (no domain needed): the compose file includes a `tailscale` service with
[`funnel.json`](funnel.json). Create an auth key, enable Funnel for your tailnet, and set
`PUBLIC_URL=https://<TS_HOSTNAME>.<tailnet>.ts.net`.

**Cloudflare Tunnel** (your own domain): use the commented `cloudflared` service, and in the Cloudflare
dashboard point the public hostname to `http://gateway:8080`.

## The upstream contract

The gateway works with any MCP server. To get a settings form and a Test button, the server can implement
these endpoints next to `/mcp`. All except plain `/healthz` require `Authorization: Bearer <UPSTREAM_TOKEN>`.

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Liveness, no auth. `200 ok` |
| `GET /healthz?check=1` | Runs real checks with the current settings. `200` when all pass, else `503` |
| `GET /config` | The settings schema and current values. Secrets are never returned |
| `POST /config` | `{"values": {"KEY": "value"}, "clear": ["KEY"]}`. Store and apply, answer like `GET /config` |

`GET /healthz?check=1`:

```json
{"ok": true, "status": "ok", "checks": [{"name": "Login", "ok": true, "detail": "logged in"}]}
```

`GET /config`:

```json
{
  "name": "my-mcp", "version": "1.0.0", "configured": true,
  "fields": [
    {"key": "API_URL", "label": "API URL", "type": "url", "required": true,
     "help": "…", "value": "https://…", "set": true, "locked": false},
    {"key": "API_KEY", "label": "API key", "type": "secret", "required": true, "value": "", "set": true},
    {"key": "REGION", "label": "Region", "type": "select",
     "options": [{"value": "eu", "label": "Europe"}], "value": "eu", "set": true},
    {"key": "READ_ONLY", "label": "Read-only", "type": "bool", "value": "false"}
  ]
}
```

- `type` is `text`, `url`, `secret`, `bool` or `select`.
- `locked: true` means the value comes from an environment variable. The form shows it disabled.
- Use environment variable names as keys, so the same setting works both ways.
- An empty secret in `POST /config` means "keep the current one".

See [bibliofil-mcp](https://github.com/Olsenius/bibliofil-mcp/blob/main/configapi.go),
[fribo-mcp](https://github.com/Olsenius/fribo-mcp/blob/main/configapi.go) and
[tibi-mcp](https://github.com/Olsenius/tibi-mcp/blob/main/configapi.go) for implementations in Go.

## Security notes

- OAuth 2.1 with PKCE (S256 only), dynamic client registration (RFC 7591), client ID metadata documents,
  protected resource metadata (RFC 9728) and resource indicators (RFC 8707). Tokens are bound to one MCP server.
- Every new app must be approved on a consent page that shows where it will be sent, by the admin password
  or an allowed OIDC login followed by pressing **Allow**.
- With OIDC on, the gateway is only as safe as the provider account: protect it with a passkey, and keep
  the allowed group small.
- Failed logins are rate limited (5 per IP per 15 minutes). Correct credentials remain usable even after failed attempts.
- Tokens and client secrets are stored only as SHA-256 hashes.
- The admin password has at least 40 characters. To change a generated one, run
  `-rotate-admin-password` and restart, or set `ADMIN_PASSWORD`.
- The gateway replaces the client's token with the upstream token, so MCP servers never see OAuth tokens.
- Anyone who can reach the gateway can try to log in, which is why short passwords are refused.
- The generated password is never logged. Use `docker compose exec gateway /mcp-gateway -print-admin-password` to retrieve it through an authorized terminal.

## Development

```sh
go test ./...
docker build -t mcp-gateway .
```

[mcp-workspace](https://github.com/Olsenius/mcp-workspace) checks out the gateway and the MCP
servers side by side, with shared test tasks and a local Compose environment built from source.

## Logging and tracing

`LOG_LEVEL=info` logs OAuth and MCP request metadata: method, path, RPC method,
HTTP status and duration. Request and response bodies are excluded by default.
`warn` and `error` suppress access logs. With `LOG_LEVEL=debug`, separate
`mcp bodies` entries include redacted JSON or SSE JSON bodies, bounded to 1 MiB.
Known credential field names are redacted. Other MCP arguments and results may
contain private data. OAuth bodies and HTTP headers are never logged. Oversized
or non-JSON bodies are omitted. Streaming responses are logged when they end.

Tracing is enabled when an OTLP endpoint is set. Incoming requests create server
spans, and calls to upstream MCP and settings/health endpoints create child
client spans. W3C `traceparent`/`tracestate` context is accepted and propagated.
Access logs include `trace_id` and `span_id` when a trace context is available.
Spans include route, method, status and RPC method, but no query strings,
credentials or request/response bodies, even at debug level. Incoming `/healthz`
requests are excluded. Buffered spans are flushed during graceful shutdown.

The exporter supports the standard OTLP/HTTP endpoint, headers, TLS and timeout
settings, resource attributes, and trace sampler environment variables.
`OTEL_TRACES_EXPORTER=none` also disables export. See the
[OTLP/HTTP exporter documentation](https://pkg.go.dev/go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp).
When using Compose, add any extra OTEL variables to the gateway's `environment`.

### Jaeger test receiver

```sh
docker compose -f docker-compose.yml -f compose.telemetry.yaml up -d
```

The override configures the gateway and the MCP servers to export to `http://jaeger:4318` at info
level, with `always_on` sampling so that requests are recorded even when a
client sends an unsampled parent trace. Set `OTEL_TRACES_SAMPLER` to override
this test policy. Jaeger accepts OTLP/HTTP on port 4318 and OTLP/gRPC on 4317. Its UI is on
16686. Published ports bind to the Docker host's loopback interface by default.
For direct access over a private network, set `JAEGER_BIND_ADDRESS` to the VM's
private IP in `.env` and recreate Jaeger; for example `10.116.0.151` exposes the
UI at `http://10.116.0.151:16686` and OTLP/HTTP at `http://10.116.0.151:4318`.
Alternatively, forward the loopback ports from a remote VM to your machine:

```sh
ssh -N -L 16686:127.0.0.1:16686 -L 4318:127.0.0.1:4318 -L 4317:127.0.0.1:4317 ubuntu@vigilo-mcp
```

Open <http://localhost:16686> and select service `mcp-gateway`, `bibliofil-mcp`, `vigilo-mcp`
or `fribo-mcp`. The servers continue the gateway trace and add spans for tools and their own
HTTP requests, so the gateway and the server appear in the same trace. Other applications
can send OTLP/HTTP traces to `http://localhost:4318` through the tunnel. Jaeger
uses temporary in-memory storage: traces disappear when its container restarts.
See the [Jaeger getting started guide](https://www.jaegertracing.io/docs/2.22/getting-started/).

### Security limits

Anonymous OAuth registration is limited to 5 attempts per source IP and 60
globally per hour. Unapproved, unused dynamic clients expire after one hour;
approved clients, previously used clients and manually created clients persist.
The 200-client capacity check is atomic. Metadata fetches reject private and
special-use addresses, including the Tailscale/CGNAT range.

Request reads have a 30-second deadline. Streaming responses have no write
deadline. Access logging observes request bytes only as handlers consume them,
so it does not read unauthenticated MCP bodies.

To rotate a generated password without printing it:

```sh
docker compose exec gateway /mcp-gateway -rotate-admin-password
docker compose restart gateway
```

Retrieve it with `-print-admin-password` afterwards. If `ADMIN_PASSWORD` is set,
rotate that value in your deployment configuration instead.

## Optional backend login actions

A backend may add `"setup":{"status":"login_required"}` to its `/config` response.
An optional `status_label` inside `setup` provides a human-readable status; otherwise `status` is displayed.
The admin page then renders login actions next to the ordinary settings. Backends
without this capability retain the existing form and Test button.

All calls use the internal upstream bearer token. The browser never receives it:

| Backend endpoint | JSON contract |
|---|---|
| `POST /setup/start` | Request `{}`. Response `{"attempt_id":"opaque","authorization_url":"https://login.example/authorize?...","expires_at":1893456000,"instructions":"Plain text"}` |
| `POST /setup/complete` | Request `{"attempt_id":"opaque","input":"pasted return URL"}`. Response uses the health contract with `ok`, `status`, `checks`; optionally `tokens_saved`. On failure: HTTP 400 `{"error":"text","code":"…"}` |
| `POST /setup/cancel` | Request `{"attempt_id":"opaque"}`. Idempotent response `{"ok":true}` |

Gateway routes are `/admin/u/{name}/setup/{start,complete,cancel}` (POST only),
requiring an admin cookie and CSRF token. Attempts are bound to that admin session
and backend, expire, and are consumed on completion/cancel. Reloading or restarting
the gateway loses the browser's pending form; start login again. Starting another
attempt does not overwrite state in other tabs. The backend must also enforce its
own expiry, one-time completion and state validation. Credential updates should
invalidate its pending attempts.

The gateway never shows a backend's error text, because it could echo the pasted
input. For these `code` values it shows its own message instead; any other code gets
a generic one: `attempt_expired`, `paste_required`, `authorize_url_pasted` (the login
link was pasted instead of the return URL), `provider_error`, `missing_code`,
`state_mismatch`, `exchange_failed` and `service_unreachable`.

Login links must use HTTPS without embedded credentials. They are opened by the
browser, never fetched by the gateway. Instructions are plain escaped text. This
is a fixed set of actions, not arbitrary backend URL proxying. Upstream errors
from these actions are hidden behind a generic failure to avoid returning pasted
credentials. Request bodies and login links must not be logged or traced.

Vigilo uses these login actions. The Compose file sets `PUBLIC_URL` as Vigilo's allowed MCP
Origin. Use the [backend migration guide](https://github.com/Olsenius/vigilo-connector/blob/main/docs/remote-gateway.md)
before moving an existing rotating-token account. No existing Vigilo volume is imported automatically.
