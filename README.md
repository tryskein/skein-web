# skein-web

The backend-for-frontend (BFF) of [Skein](https://github.com/tryskein/skein), a
task tracker for AI agents and humans. skein-web is an ASP.NET Core (.NET 10)
service that sits between the browser and
[skein-api](https://github.com/tryskein/skein-api):

- **Browser sessions.** Cookie authentication with the session ticket stored
  server-side in Redis; the cookie-encryption keys live in Redis too, so any
  replica can serve any session and a redeploy does not sign users out.
- **Login and account flows** under `/api/auth/*`: password login, logout,
  current user, client configuration for the SPA, sign-up, password reset,
  email confirmation and invitations. Native OIDC (Keycloak) and
  trust-headers SSO behind oauth2-proxy are supported as well.
- **Live updates.** A SignalR hub at `/hub` relays skein-api's event stream from
  NATS to the browser, with a Redis backplane for multiple replicas.
- **Reverse proxy** to skein-api for `/api/v1/*` (REST, forwarded to skein-api's
  internal API `/ui/v1/*`), `/mcp` (MCP Streamable
  HTTP), `/agent/v1/*` and the `/.well-known/oauth-protected-resource*`
  metadata. Identity is forwarded as headers the BFF sets from the session;
  inbound copies of those headers are stripped.

It does not serve the web UI: the SPA is the separate
[skein-frontend](https://github.com/tryskein/skein-frontend) image (nginx),
which also routes backend paths to skein-web. skein-web is not meant to be
exposed directly.

For how the three services fit together, see the umbrella repository's
[README](https://github.com/tryskein/skein/blob/main/README.md) and
[ARCHITECTURE.md](https://github.com/tryskein/skein/blob/main/ARCHITECTURE.md).

## Stack

- .NET 10, ASP.NET Core controllers, Swashbuckle (OpenAPI, Swagger UI in
  `Development` only)
- StackExchange.Redis — session ticket store, DataProtection key ring, login
  rate limiting; `Microsoft.AspNetCore.SignalR.StackExchangeRedis` — SignalR
  backplane
- NATS.Net — subscription to skein-api's event stream
- `Microsoft.AspNetCore.Authentication.OpenIdConnect` — native OIDC
- Polly — retries on the typed skein-api client
- prometheus-net — HTTP, runtime and system metrics
- xUnit + Moq for tests

## Build and run

### As part of Skein (recommended)

Skein is developed as a workspace: the umbrella repository at the top, with the
services cloned into `skein/projects/<service>/`. Setup is described in the
umbrella's
[DEVELOPMENT.md](https://github.com/tryskein/skein/blob/main/DEVELOPMENT.md).
From the top of `skein/`:

```bash
docker compose --env-file versions.env -f docker-compose.local.yml \
  -f docker-compose.local.build.yml up -d --build   # builds the services from projects/
# UI: http://localhost:8080 (served by skein-frontend, which proxies to skein-web)
```

### On its own

skein-web needs skein-api, Redis and NATS. Four settings are required and the
process refuses to start without them (`SKEIN_API_URL is not set`, and so on);
`appsettings.Development.json` holds logging levels only. With the
dependencies reachable on localhost:

```bash
cd src
dotnet restore
ASPNETCORE_ENVIRONMENT=Development PORT=8080 \
SKEIN_API_URL=http://localhost:5100 \
SKEIN_INTERNAL_SECRET=local-dev-internal-secret-change-me-32chars-min \
REDIS_URL=redis://localhost:6379 \
NATS_URL=nats://localhost:4222 \
dotnet run
```

`SKEIN_INTERNAL_SECRET` must match the value skein-api is configured with; the
one above is the local development value of the umbrella's compose file. At
startup skein-web asks skein-api for the authentication mode and does not start
if skein-api does not answer in time.

Quick checks once it runs:

```bash
curl -i http://localhost:8080/healthz          # 200 {"status":"ok"}
curl -i http://localhost:8080/ready            # 200 when Redis is reachable, 503 otherwise
curl    http://localhost:8080/metrics          # Prometheus exposition format
curl    http://localhost:8080/api/auth/config  # runtime configuration the SPA reads at boot
```

### Docker image

```bash
docker build -t skein-web:dev .
```

The image listens on `8080` (override with `PORT`) and runs as a non-root
user. Published images: `ghcr.io/tryskein/skein-web` — tags and release
process in the umbrella's
[RELEASING.md](https://github.com/tryskein/skein/blob/main/RELEASING.md).

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/healthz` | Liveness — always 200, no dependency checks |
| GET | `/ready` | Readiness — pings Redis |
| GET | `/metrics` | Prometheus metrics |
| POST | `/api/auth/login` | Email + password login (410 in pure SSO mode) |
| POST | `/api/auth/logout` | Clears the session; may return `redirectTo` for the upstream sign-out |
| GET | `/api/auth/me` | Current user of the session |
| GET | `/api/auth/config` | Runtime client configuration (auth mode, MCP URL, sign-up and email flags, …) |
| GET | `/api/auth/oidc-signout` | Starts OIDC RP-initiated logout (native OIDC only) |
| POST | `/api/auth/signup` | Self-service sign-up |
| GET | `/api/auth/username-suggestions` | Username suggestions from an email |
| POST | `/api/auth/password-reset`, `/api/auth/password-reset/{token}` | Request / complete a password reset |
| POST | `/api/auth/confirm-email/{token}` | Confirm an email address |
| GET / POST | `/api/auth/invitations/{token}`, `/api/auth/invitations/{token}/signup` | Preview an invitation / register by invitation |
| GET | `/oauth2/start?rd=<path>` | OIDC challenge (native OIDC only) |
| `*` | `/api/v1/*` | Proxied to skein-api as `/ui/v1/*`; needs a session cookie (401 without). The service path class — everything under `/api/v1/auth/` except `GET /api/v1/auth/me`, and everything under `/api/v1/hub/` and `/api/v1/internal/`, in any equivalent path form (letter case, repeated or trailing slashes, plain or encoded dot segments, encoded `/`, backslash) — answers 404 with or without a cookie and is never proxied |
| `*` | `/mcp`, `/agent/v1/*` | Proxied to skein-api |
| GET | `/.well-known/oauth-protected-resource[/mcp]` | Proxied to skein-api (RFC 9728 metadata, unauthenticated) |
| WS | `/hub` | SignalR hub (live events, authenticated) |

Each `/api/auth/*` action is documented in code with Swashbuckle annotations;
in `Development` the spec and UI are at `/swagger`.

## Session cookie, HTTPS and early failures

The browser session cookie is `__Host-skein.sid`: `Secure`, `HttpOnly`, `Path=/`, no `Domain`,
`SameSite=Lax`. A browser sends a `Secure` cookie only over HTTPS, so the deployment must be served over
HTTPS end to end as the browser sees it; behind a TLS-terminating edge, make sure the edge tells skein-web
the scheme (forwarded headers from a trusted proxy). A deployment served over plain http would let users
sign in and then lose the session at once; skein-web logs a warning (at most once a minute) when it issues a
session on a request it sees as http.

For local work over plain http there is one switch, `SKEIN_ALLOW_INSECURE_HTTP`, valid only in the
`Development` environment: the cookie becomes `skein.sid` without `Secure`. It is not a production
setting, and it is not needed for a self-signed HTTPS certificate. Its full description is in
[`docs/env-reference.md`](docs/env-reference.md), the only place settings are described.

Every new sign-in (password login, sign-up, sign-up by invitation, the end of a password reset, native OIDC,
trust-headers sign-in) is stored under a new random key, and the key the browser sent is revoked first.

When the session store (Redis) is technically unavailable while the session is read, traffic that passes
the session cookie handler is refused early with `502` and no `Set-Cookie`, instead of an unhandled error:
the `/api/v1` proxy, the hub and the `/api/auth/*` endpoints. The body depends on the request:

- `application/problem+json` with `error` `upstream_unavailable` (login carries no `error`);
- in the trust-headers mode, a trusted-proxy request with both identity headers gets
  `{"error":"sso_unavailable","message":...}`, unless it is an explicit sign-in operation (login, sign-up,
  sign-up by invitation, completing a password reset) or one of the service paths that skip the SSO step
  (`/healthz`, `/ready`, `/metrics`, `/api/auth/config`, `/mcp`, `/agent/v1`): those keep the
  `application/problem+json` form of their own endpoint. A failure to establish the session from the
  identity headers is `sso_provisioning_failed`.

`/mcp` is not in this list: it is served before the session handler and authenticates separately with
`X-Skein-Api-Key`, so a session store outage does not touch it.

## Configuration

Every setting — environment variables and their `appsettings.json` spelling —
is documented in [`docs/env-reference.md`](docs/env-reference.md): purpose,
whether it is required, default, format and what happens when it is unset.
No other list of settings is kept.

Required: `SKEIN_API_URL`, `SKEIN_INTERNAL_SECRET`, `REDIS_URL`, `NATS_URL`.
`SKEIN_TRUSTED_PROXIES` may be empty locally but must be set behind any
reverse proxy or ingress.

### Authentication

The identity source is skein-api's `SKEIN_AUTH_MODE` (`local` | `keycloak` |
`hybrid`). skein-web has no mode setting of its own: before the host is built
it reads the mode from skein-api and waits at most
`SKEIN_API_STARTUP_TIMEOUT_SECONDS`. Changing the mode means restarting both
services. The mode maps onto a web scheme:

| skein-api `SKEIN_AUTH_MODE` | `Authentication__Oidc__Authority` | Web scheme |
|------|------|------|
| `local` | any | `Local` |
| `keycloak` | set | `KeycloakOidc` |
| `keycloak` | empty | `Keycloak` (trust-headers) |
| `hybrid` | set / empty | `KeycloakOidc` / `Keycloak`, password login open for external users |

| Web scheme | When to use | How a session starts |
|------|-------------|--------------------|
| `Local` | Standalone Skein without an identity provider | `POST /api/auth/login` with email + password sets the cookie. Every user is local. |
| `Keycloak` | Behind an authenticating proxy (oauth2-proxy) at the ingress | The proxy forwards `X-Auth-Request-User` and `X-Auth-Request-Email`; `SsoSessionMiddleware` sets the cookie |
| `KeycloakOidc` | Native OIDC | skein-web runs Authorization Code + PKCE against Keycloak itself; the cookie is set after the group-membership check |

In pure SSO mode (`keycloak`, either web scheme) password login is disabled —
`POST /api/auth/login` returns 410 Gone and the SPA navigates to
`/oauth2/start?rd=<return-url>`. Logout clears the cookie and returns a
`redirectTo` so the upstream session ends too (proxy sign-out in trust-headers
mode, realm `end_session` via `/api/auth/oidc-signout` in native mode).

#### Logout redirect

`Authentication__LogoutRedirectUrl` is the absolute sign-out URL of the
authenticating proxy in front of a trust-headers deployment. The proxy, not
skein-web, owns the session that lets a user in, and its sign-out address
depends on your topology, so there is no default. Left unset, logout still
clears the session cookie (`__Host-skein.sid`, or `skein.sid` with the Development-only insecure-http setting) but returns no `redirectTo`, and a startup warning
says the external session survives logout. The value is also published to the
SPA on `GET /api/auth/config` as `logoutRedirectUrl` and is the only absolute
URL the client follows after logout (same-origin `/oauth2/*` paths are always
allowed).

#### Hybrid mode and external users

With `SKEIN_AUTH_MODE=hybrid` on skein-api, organisation members sign in with
SSO while external collaborators use password login.

- **External users** are local accounts flagged `is_external`, created by a
  global admin (`POST /api/v1/users` with `is_external: true`, or the MCP tool
  `skein_user` with `action="create"`). They live in the same `users` table;
  external is a flag, not a separate identity store.
- An external user is never an admin or a project owner (at most `member`),
  sees only the projects they are added to and only people who share a project
  with them. Add externals to dedicated projects — membership exposes that
  project's members and backlog.
- In hybrid mode password login authenticates only external users; an internal
  user who tries a password gets the same generic "invalid credentials" as a
  wrong password.
- **Break-glass:** `SKEIN_BREAKGLASS_ADMIN=<admin-email>` on skein-api lets
  exactly that admin use password login while OIDC is active, so a fresh
  deployment can create its first external user. Clear it once a working SSO
  admin exists; the login throttle (per email and per IP) covers it.

skein-web does not split a "public" and an "internal" surface by the request
`Host`: that header is client-controlled, so it cannot carry a privilege
decision. If a separately exposed surface is ever needed, it has to be built on
a signal the server controls, such as the listener port (rationale in
`src/Middleware/McpProxyMiddleware.cs`).

#### Native OIDC settings

| Setting | Default | Description |
|---------|---------|-------------|
| `Authentication__Oidc__Authority` | — | Realm URL, e.g. `https://keycloak.example.com/realms/myrealm`. Setting it selects `KeycloakOidc` in an SSO mode. |
| `Authentication__Oidc__ClientId` | — (required) | Client id of the confidential client registered for Skein. |
| `Authentication__Oidc__ClientSecret` | — (required) | Secret of that client. Inject it from your secret store; never commit it. |
| `Authentication__Oidc__AllowedGroup` | `skein-users` | Realm group whose members may sign in. Non-members get 403 and no cookie. |
| `Authentication__Oidc__CallbackPath` | `/api/auth/oidc-callback` | Redirect path after the handshake; must be registered on the client. It sits under `/api/` so an existing ingress route covers it. |
| `Authentication__Oidc__SignedOutCallbackPath` | `/api/auth/oidc-signout-callback` | Redirect path after `end_session`; register it as a valid post-logout redirect URI. |
| `Authentication__Oidc__SignedOutRedirectUri` | `/login` | Final page after the full logout chain. |

Setting up Keycloak, assuming Skein is published at `https://skein.example.com`:

1. **Client.** In the realm, create an OIDC client with **Client
   authentication ON** (confidential). Put its id in
   `Authentication__Oidc__ClientId` and the secret from Credentials in
   `Authentication__Oidc__ClientSecret`.
2. **Redirect URIs.** Valid redirect URI
   `https://skein.example.com/api/auth/oidc-callback`; valid post-logout
   redirect URI `https://skein.example.com/api/auth/oidc-signout-callback`.
3. **Group claim.** Group membership is read from the **id_token**, not the
   access token. On the client: Client scopes → `groups` scope → group
   membership mapper → enable **Add to ID token**. Without it every login is
   rejected with 403.
4. **Group.** Create the group named in `Authentication__Oidc__AllowedGroup`
   and add your users to it.
5. **Authority.** Set `Authentication__Oidc__Authority` to
   `https://keycloak.example.com/realms/<realm>`.

## Tests

```bash
cd src/Tests && dotnet test --nologo
```

Unit tests need only the .NET 10 SDK. skein-web has no integration suite of its
own; the live path (hub, session, proxy) is covered by the product-wide e2e
suite, run from the top of the umbrella workspace with
`./scripts/e2e-test.sh`. For all test kinds, narrowed runs and pitfalls, see
the `## Testing` section of [`AGENTS.md`](AGENTS.md).

## Contributing

See the umbrella's
[CONTRIBUTING.md](https://github.com/tryskein/skein/blob/main/CONTRIBUTING.md).
A change that spans several services needs one pull request per repository.

## License

Business Source License 1.1 — see [`LICENSE`](LICENSE).

Report vulnerabilities as described in [SECURITY.md](https://github.com/tryskein/skein/blob/main/SECURITY.md). The Skein name and logo are covered by [TRADEMARKS.md](https://github.com/tryskein/skein/blob/main/TRADEMARKS.md).
