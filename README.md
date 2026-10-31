# mcp-gateway

Put OAuth 2.1 login in front of your self-hosted [MCP](https://modelcontextprotocol.io) servers,
so **claude.ai**, **ChatGPT** and other remote MCP clients can use them over the internet.

- One admin password protects everything. No external identity provider needed.
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

The included [`docker-compose.yml`](docker-compose.yml) runs the gateway, [bibliofil-mcp](https://github.com/Olsenius/bibliofil-mcp)
and Tailscale Funnel.

```sh
cp .env.example .env      # fill in PUBLIC_URL, BIBLIOFIL_TOKEN, TS_AUTHKEY
docker compose up -d
docker compose logs gateway   # shows the generated admin password
```

Open `https://<your-host>/admin` and log in with the admin password.
Then open the server's **Settings and test** page, fill in the settings, save, and press **Test**.

## Connect an app

Each MCP server gets its own URL: `https://<your-host>/<name>/mcp`.

- **claude.ai:** Settings → Connectors → Add custom connector → paste the URL. Claude registers itself,
  and you approve it with the admin password.
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
| `ADMIN_PASSWORD` | generated | Admin password, at least 40 characters, or the gateway refuses to start. If unset, a random 48-character password is generated on first start, stored in `DATA_DIR/admin-password` and printed in the log at every start |
| `DATA_DIR` | `/data` | Where clients, refresh tokens and the generated admin password are stored |
| `ACCESS_TOKEN_TTL` | `1h` | Lifetime of OAuth access tokens |
| `REFRESH_TOKEN_TTL` | `720h` | Lifetime of refresh tokens (rotated on every use) |
| `PORT` | `8080` | |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`; invalid values stop startup |
| `OTEL_SERVICE_NAME` | `mcp-gateway` | Service name in traces |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | OTLP/HTTP base URL, e.g. `http://jaeger:4318`; exporter appends `/v1/traces` |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | unset | Full traces URL; overrides the base endpoint |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` | Only OTLP over HTTP/protobuf is supported |
| `OTEL_SDK_DISABLED` | `false` | Disable trace export even with an endpoint configured |
| `OTEL_TRACES_SAMPLER` | `parentbased_always_on` | Standard OpenTelemetry sampler, e.g. `parentbased_traceidratio` |
| `OTEL_TRACES_SAMPLER_ARG` | unset | Ratio for ratio-based samplers, e.g. `0.1` |

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

See [bibliofil-mcp](https://github.com/Olsenius/bibliofil-mcp/blob/main/configapi.go) for an implementation.

## Security notes

- OAuth 2.1 with PKCE (S256 only), dynamic client registration (RFC 7591), client ID metadata documents,
  protected resource metadata (RFC 9728) and resource indicators (RFC 8707). Tokens are bound to one MCP server.
- Every new app must be approved with the admin password on a consent page that shows where it will be sent.
- Failed logins are rate limited (5 per IP and 30 in total per 15 minutes).
- Tokens and client secrets are stored only as SHA-256 hashes.
- The admin password has at least 40 characters. To change a generated one, delete `DATA_DIR/admin-password`
  and restart, or set `ADMIN_PASSWORD`.
- The gateway replaces the client's token with the upstream token, so MCP servers never see OAuth tokens.
- Anyone who can reach the gateway can try to log in, which is why short passwords are refused.
- The generated password is printed in the container log. Anyone who can read the log can log in.

## Development

```sh
go test ./...
docker build -t mcp-gateway .
```

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
docker compose -f docker-compose.yml -f compose.telemetry.yaml up -d gateway jaeger
```

The override configures the gateway to export to `http://jaeger:4318` at info
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

Open <http://localhost:16686> and select service `mcp-gateway`. Other applications
can send OTLP/HTTP traces to `http://localhost:4318` through the tunnel. Jaeger
uses temporary in-memory storage: traces disappear when its container restarts.
See the [Jaeger getting started guide](https://www.jaegertracing.io/docs/2.22/getting-started/).
