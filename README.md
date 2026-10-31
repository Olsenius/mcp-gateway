# mcp-gateway

Put OAuth 2.1 login in front of your self-hosted [MCP](https://modelcontextprotocol.io) servers,
so **claude.ai**, **ChatGPT** and other remote MCP clients can use them over the internet.

- One admin password protects everything. No external identity provider needed.
- An admin page shows each MCP server's settings as a form, and a **Test** button checks that they work.
- The MCP servers stay on an internal Docker network with no open ports.
- Small static Go binary, distroless image, no dependencies beyond the Go standard library.

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
docker compose logs gateway   # shows a one-time setup code
```

Open `https://<your-host>/admin`, enter the setup code and choose an admin password.
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
| `ADMIN_PASSWORD` | – | Admin password. If unset, you choose one on first visit with a setup code from the log |
| `DATA_DIR` | `/data` | Where clients, refresh tokens and the password hash are stored |
| `ACCESS_TOKEN_TTL` | `1h` | Lifetime of OAuth access tokens |
| `REFRESH_TOKEN_TTL` | `720h` | Lifetime of refresh tokens (rotated on every use) |
| `PORT` | `8080` | |

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
- Tokens and secrets are stored only as SHA-256 hashes; the admin password as PBKDF2-SHA256.
- The gateway replaces the client's token with the upstream token, so MCP servers never see OAuth tokens.
- Anyone who can reach the gateway can try to log in. Use a long password.

## Development

```sh
go test ./...
docker build -t mcp-gateway .
```
