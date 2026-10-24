# skein-web — environment variable reference

**This file is the single source of truth for skein-web configuration.** Every
setting the BFF reads is listed here exactly once. The README and deployment
manifests link here; they do not keep lists of their own.

skein-web is an ASP.NET Core application, so a setting can arrive from two
places, with environment variables winning:

1. environment variables;
2. `src/appsettings.{ASPNETCORE_ENVIRONMENT}.json`, then `src/appsettings.json`.

Hierarchical settings (those written `Section:Key` in JSON) map to an
environment variable by replacing every `:` with a **double underscore**:
`Authentication:Oidc:ClientSecret` is `Authentication__Oidc__ClientSecret`. Both
spellings are shown below; the environment form is the one used in deployments.

## Rules that apply to every setting

- **Required settings fail fast.** `SKEIN_API_URL`, `SKEIN_INTERNAL_SECRET`,
  `REDIS_URL` and `NATS_URL` are read at startup with no fallback; a missing one
  throws `InvalidOperationException: <NAME> is not set` before the server binds a
  port. This is deliberate — a default pointing at another service would be a
  silent misroute.
- **Empty is not unset.** An environment variable set to an empty string is
  present as far as ASP.NET Core is concerned, so it satisfies the null-check
  above and then fails later (or, for optional settings, behaves as an explicitly
  empty value). Omit the variable instead.
- **Booleans** are parsed by the configuration binder: `true` / `false`
  (case-insensitive). Anything else throws at bind time.

<!-- prod-required:begin -->
## Must be set in production — no safe default exists

| Setting | Why it has no default |
|---|---|
| `SKEIN_API_URL` | Address of skein-api. Deployment-specific; required. |
| `SKEIN_INTERNAL_SECRET` | Shared secret authenticating this BFF to skein-api. A default would be a published credential. Required, and must match skein-api's value exactly. |
| `REDIS_URL` | Backs the session store, the cookie-encryption key ring, the login throttle and the SignalR backplane. Required. |
| `NATS_URL` | Source of the live event feed pushed to browsers. Required. |
| `SKEIN_TRUSTED_PROXIES` | Not required to start, but **empty is a functional default, not a safe-for-every-topology one**: behind an ingress it must list the proxy addresses, or `X-Forwarded-*` is ignored and every per-IP limit (login throttle, IP buckets of the public account routes) stays off. |
<!-- prod-required:end -->

---

## Service wiring

#### `PORT`

- **Purpose:** TCP port the Kestrel server binds
  (`builder.WebHost.UseUrls("http://0.0.0.0:{PORT}")`).
- **Required:** no · **Default:** `8080` · **Format:** decimal port number.
- **If unset:** binds 8080. The container image also sets `ENV PORT=8080`.
- **Note:** the port is taken from this setting, not from `ASPNETCORE_URLS`;
  `ASPNETCORE_URLS` is not read by application code.

#### `SKEIN_API_URL`

- **Purpose:** base URL of skein-api. Used by the typed `SkeinApiClient`, by the
  `/api/v1/*` reverse proxy, by the `/mcp` proxy and by the `/agent/v1` proxy.
- **Required:** **yes** · **Default:** none · **Format:** absolute URL, e.g.
  `http://skein-api:5100`.
- **If unset:** startup throws `SKEIN_API_URL is not set`.
- **Related:** every request forwarded there carries `SKEIN_INTERNAL_SECRET`.

#### `SKEIN_INTERNAL_SECRET`

- **Purpose:** value of the `X-Skein-Internal-Secret` header added to every call
  into skein-api.
- **Required:** **yes** · **Default:** none · **Format:** opaque string; skein-api
  rejects anything shorter than 16 characters at *its* startup.
- **If unset:** startup throws `SKEIN_INTERNAL_SECRET is not set`.
- **Careful:** the two services must carry the identical value. A mismatch stops
  startup at once: skein-api answers the installation-settings request with 401
  and the process exits with an error naming the secret.

#### `SKEIN_API_STARTUP_TIMEOUT_SECONDS`

- **Purpose:** how long startup waits for skein-api to answer
  `GET /api/v1/internal/instance-config` — the installation settings, among them
  the authentication mode, which must be known before the host is built (plan
  K-12). Failed attempts (connection refused, no answer within 10 s, a non-2xx
  status other than 401/404) are retried with backoff from 0.5 s doubling to 5 s
  until the window ends.
- **Required:** no · **Default:** `60` · **Format:** whole number of seconds,
  `1`–`3600`.
- **If skein-api gives no valid answer within the window:** the process logs a
  critical error naming the last failure and exits with code 1 — the pod never
  becomes ready. There is no default mode to fall back on (E-13). A 401 (wrong
  `SKEIN_INTERNAL_SECRET`), a 404 (wrong `SKEIN_API_URL` or a skein-api without the
  route) and a 200 whose body is not the contract (for example an unknown
  `authMode`) fail at once, without waiting out the window.
- **If set but empty, not an integer or out of range:** startup throws
  `InvalidOperationException` naming the variable.

#### `REDIS_URL`

- **Purpose:** Redis/Valkey connection. One multiplexer serves four consumers:
  the server-side session ticket store (`skein:session:<sid>`), the
  DataProtection key ring (`skein:dataprotection:keys`, which is what lets
  several replicas read each other's cookies), the login rate limiter, and the
  SignalR Redis backplane.
- **Required:** **yes** · **Default:** none · **Format:** either a
  `redis://[user:password@]host[:port]` URL (port defaults to 6379) or a raw
  StackExchange.Redis configuration string (`host:port,opt=val`). The URL form is
  detected by its `redis://` prefix; anything else is handed to
  `ConfigurationOptions.Parse`.
- **If unset:** startup throws `REDIS_URL is not set`.
- **Note:** the URL form sets `AbortOnConnectFail=false`, so a Redis that is
  briefly unreachable at startup is retried rather than crashing the process. A
  raw configuration string is used exactly as written, including whatever it says
  about that option.
- **Careful:** Redis holds sessions *and* cookie-encryption keys. A Redis without
  persistence logs everyone out when it restarts.

#### `NATS_URL`

- **Purpose:** NATS Core endpoint the SignalR hub subscribes to for the live
  event feed that skein-api publishes.
- **Required:** **yes** · **Default:** none (`appsettings.json` deliberately
  carries no URL, only the connection name) · **Format:** `nats://host:port`.
- **If unset:** startup throws `NATS_URL is not set`.

#### `SKEIN_MCP_URL`

- **Purpose:** absolute URL of the MCP endpoint agents should connect to. It is
  published to the SPA on `GET /api/auth/config` and rendered into the
  `.mcp.json` snippet on the API-keys settings page. It exists so the browser
  does not have to guess the address by rewriting its own hostname.
- **Required:** no · **Default:** empty · **Format:** absolute `http(s)` URL,
  e.g. `https://skein-mcp.example.com/mcp`.
- **If unset:** the SPA renders a same-origin `/mcp` URL built from the page's
  own origin — correct for every deployment where the same host serves both the
  UI and `/mcp`. Set it only when MCP is served from a different origin, for
  example a dedicated ingress that bypasses the authenticating proxy so agents
  can present a static `ska_…` key.
- **If set but not an absolute http(s) URL:** startup throws a
  `ValidationException` naming the variable, rather than shipping a snippet the
  agent operator would have to debug.

#### `SKEIN_MCP_UPSTREAM_HEADERS_TIMEOUT_SECONDS`

- **Purpose:** how long the `/mcp` proxy waits for skein-api to send response
  headers. When it runs out, the proxy answers `504` with
  `{"error":"upstream_timeout", …}` and drops the upstream connection. Only the
  connect/headers phase is bounded; an SSE body that is already streaming is not
  cut by it.
- **Required:** no · **Default:** `120` · **Format:** whole number of seconds,
  `30`–`3600`.
- **If unset:** 120 seconds. It is not 30 (the old fixed value) because MCP calls
  observed in production ran for 30 s or longer: the proxy cut them at 30 s while the
  writes they carried were already committed, and the retried calls duplicated
  them (sk-608). The window must cover the slowest legitimate call.
- **If set but empty, not an integer or out of range:** startup throws
  `InvalidOperationException` naming the variable.
- **Careful — a timeout is not a failure.** A `POST` (or `DELETE`) that times
  out has reached skein-api and may already be committed. The 504 body for such
  a request carries `"outcome":"unknown"` next to `"error":"upstream_timeout"`;
  a client must re-read the state before retrying a write, or it duplicates it.
  The 502 `"error":"upstream_unavailable"` body carries the same field for the
  same methods: a connection that breaks after the request was sent cannot be
  told apart from one refused before it. `GET`/`HEAD`/`OPTIONS` get both bodies
  without `outcome`.
- **Related:** skein-api's batch tools stop their own loop at 20 s
  (`batchLoopDeadline` in `skein-api/src/internal/mcp/tools/batch_deadline.go`),
  sized to land inside this window. With the 120 s default it stays well below,
  so that stop-and-report path keeps working; the lower bound of 30 is the
  smallest window that still leaves it room. The
  upper bound is the `proxy_read_timeout` of the `/mcp` location in
  skein-frontend's `nginx.conf` — any proxy in front with a shorter read timeout
  cuts the request first, with its own error instead of this body.
- **Not covered:** the `/agent/v1` proxy (`AgentProxyMiddleware`) keeps its own
  fixed 30 s headers timeout.

#### `Nats__Name` (`Nats:Name` in appsettings)

- **Purpose:** client name the NATS connection announces, visible in NATS server
  monitoring.
- **Required:** no · **Default:** `skein-web-hub` (set in `appsettings.json`, and
  repeated as a code fallback) · **Format:** free text.
- **If unset:** `skein-web-hub`.

## Live delivery (SignalR hub)

#### `HUB_MAX_PROJECTS_PER_CONNECTION`

- **Purpose:** the maximum number of projects one hub connection (one browser
  tab) may have declared at a time for live project events (sk-622.21 US-9). A tab declares
  the projects it shows with the hub method `DeclareProjects`; ids past the
  limit, in declaration order, are rejected with reason `limit`, and their
  issues stay on the last snapshot until the tab narrows its set or reconnects.
  The "all projects visible to me" mode of `/activity` (`DeclareAllVisible`) is
  not subject to it.
- **Required:** no · **Default:** `50` · **Format:** positive whole number.
- **If unset:** 50.
- **If set but empty, not an integer or not positive:** startup throws
  `InvalidOperationException` naming the variable.
- **Related:** independently of this limit a connection may change its declared
  set at most 10 times per 10 s (fixed, not configurable); a change past that
  is rejected with reason `rate`.

#### `COUNTS_SIGNAL_WINDOW_MS`

- **Purpose:** coalescing window for personal signals (sk-622.21 US-11). skein-api
  publishes a data-less signal on `skein.user.{uid}.signal` after every
  committed change that may move a user's header counters or personal screens;
  every replica of skein-web delivers it to its own connections of that user,
  at most one `signal` frame per connection per window, with the areas of all
  signals within the window merged. The window of a connection opens with the
  first signal for it.
- **Required:** no · **Default:** `2000` · **Format:** positive whole number of
  milliseconds.
- **If unset:** 2000 ms.
- **If set but empty, not an integer or not positive:** startup throws
  `InvalidOperationException` naming the variable.
- **Careful:** a larger window means fewer re-reads but a later header update;
  reminder frames are never coalesced and are not affected.

## Proxy trust

#### `SKEIN_TRUSTED_PROXIES`

- **Purpose:** the allowlist of proxies whose `X-Forwarded-*` headers are
  trusted. It drives both the `ForwardedHeaders` middleware and the opt-in for
  every per-IP limit — the login throttle and the "action + IP" buckets of the
  public account routes (`/api/auth/signup`, `/username-suggestions`,
  `/password-reset`, `/password-reset/{token}`, `/confirm-email/{token}`,
  `/invitations/{token}`, `/invitations/{token}/signup`) — and the
  `X-Skein-Client-Ip` value forwarded to skein-api, which keys skein-api's own
  per-IP limits.
- **Required:** no, but see below · **Default:** empty · **Format:**
  comma-separated IP addresses and/or CIDR networks, e.g.
  `10.244.0.0/16,192.168.1.5`. Whitespace around entries is trimmed.
- **If unset (empty):** **fail-closed.** The framework's loopback defaults are
  cleared, and neither `X-Forwarded-For` nor `X-Forwarded-Host` is applied —
  `RemoteIpAddress` stays the immediate TCP peer and `Request.Host` stays the
  literal `Host` header. Every per-IP limit is off, because behind a proxy every
  request would otherwise share the ingress IP and one attacker would lock out
  everyone: no per-IP login throttle, no IP buckets on the public account routes,
  and no `X-Skein-Client-Ip` to skein-api (so its per-IP limits do not apply
  either). The routes with an email in the input (signup, password-reset request,
  username suggestions) are then limited per email only; the token routes
  (`/password-reset/{token}`, `/confirm-email/{token}`, `/invitations/{token}`,
  `/invitations/{token}/signup`) by neither IP nor email — they rely on the token itself
  being secret, expiring and single-use. Only `X-Forwarded-Proto` is still
  honoured, since it carries no authority and the OIDC callback needs the https
  scheme.
- **Careful:** any deployment behind an ingress or another proxy **must** set
  this. Leaving it empty there does not fail loudly; it silently disables every
  per-IP limit (login and public account routes) and makes `Request.Host` the
  client's own `Host` header — which the OIDC same-origin return-URL check reads.

## Authentication

The authentication **mode** is not a skein-web setting. skein-web reads skein-api's
`SKEIN_AUTH_MODE` from `GET /api/v1/internal/instance-config` at startup (see
`SKEIN_API_STARTUP_TIMEOUT_SECONDS`) and maps it onto a web scheme
(`src/Auth/SsoOptions.cs#FromApi`, plan K-13):

| skein-api `SKEIN_AUTH_MODE` | `Authentication__Oidc__Authority` | web scheme |
|---|---|---|
| `local` | any | `Local` — password form; the BFF forwards credentials to skein-api |
| `keycloak` | set | `KeycloakOidc` — the BFF is the OIDC relying party itself (Authorization Code + PKCE against Keycloak, no oauth2-proxy) |
| `keycloak` | empty | `Keycloak` — legacy trust-headers: an `oauth2-proxy` at the edge forwards `X-Auth-Request-User` / `X-Auth-Request-Email`, which the BFF trusts inside the cluster boundary |
| `hybrid` | set / empty | `KeycloakOidc` / `Keycloak`, with the password channel kept open for external collaborators and the break-glass admin (skein-api decides which accounts it authenticates) |

An `authMode` outside these three values stops startup; there is no web-side
default. Changing the mode means restarting both services. The former
`Authentication__Mode` and `Authentication__Hybrid` settings are gone — if a
deployment still sets them, they are ignored.

#### `Authentication__LogoutRedirectUrl` (`Authentication:LogoutRedirectUrl`)

- **Purpose:** absolute sign-out URL of the authenticating proxy in front of this
  deployment (for an oauth2-proxy edge, its `/oauth2/sign_out`). Consulted only
  in the legacy `Keycloak` mode: in `KeycloakOidc` the BFF drives RP-initiated
  logout itself, and in `Local` there is no external session at all. The value is
  also published to the SPA, which accepts an absolute logout redirect **only**
  when it equals this URL — the allow-list follows the deployment instead of a
  compiled-in constant.
- **Required:** no · **Default:** empty · **Format:** absolute `http(s)` URL.
- **If unset in `Keycloak` mode:** the BFF degrades rather than fails — logout
  clears the local `skein.sid` cookie, returns `redirectTo: null`, and a startup
  warning says the external proxy session survives, so the next request signs the
  user straight back in. Making it required would break proxy-less local runs of
  this mode for the sake of a value only a proxied deployment can supply.
- **If set but not an absolute http(s) URL:** startup throws a
  `ValidationException`. This shape check runs in **every** mode, not just
  `Keycloak`, so a typo cannot go unnoticed until somebody logs out.

#### `Authentication__Oidc__Authority` (`Authentication:Oidc:Authority`)

- **Purpose:** OIDC issuer URL — the realm discovery root. The handler fetches
  `{Authority}/.well-known/openid-configuration` at startup.
- **Required:** no — setting it selects `KeycloakOidc` in an SSO mode · **Default:**
  empty · **Format:** absolute URL, e.g. `https://iden.example.com/realms/skein`.
- **If unset:** an SSO mode runs the legacy `Keycloak` trust-headers scheme;
  `Local` ignores it.
- **Note:** consulted only at startup; changing it needs a restart.

#### `Authentication__Oidc__ClientId` (`Authentication:Oidc:ClientId`)

- **Purpose:** the Keycloak client id this BFF authenticates as.
- **Required:** only in `KeycloakOidc` mode · **Default:** empty · **Format:**
  client id string.
- **If unset in `KeycloakOidc` mode:** startup throws a `ValidationException`.
- **Related:** the client's "Valid Redirect URIs" must contain this app's origin
  plus `Authentication__Oidc__CallbackPath`.

#### `Authentication__Oidc__ClientSecret` (`Authentication:Oidc:ClientSecret`)

- **Purpose:** the Keycloak client secret.
- **Required:** only in `KeycloakOidc` mode · **Default:** empty · **Format:**
  opaque string.
- **If unset in `KeycloakOidc` mode:** startup throws a `ValidationException`.
- **Careful:** inject it from a secret store as an environment variable. Never
  commit a literal value into `appsettings.json`.

#### `Authentication__Oidc__AllowedGroup` (`Authentication:Oidc:AllowedGroup`)

- **Purpose:** the value that must appear in the token's `groups` claim for the
  user to be let in. Checked in `OnTokenValidated`; a user without it gets 403 and
  no Skein cookie.
- **Required:** only in `KeycloakOidc` mode · **Default:** `skein-users` ·
  **Format:** group name as it appears in the claim.
- **If explicitly emptied in `KeycloakOidc` mode:** startup throws a
  `ValidationException` — there is no "allow everyone" spelling.

#### `Authentication__Oidc__CallbackPath` (`Authentication:Oidc:CallbackPath`)

- **Purpose:** path the browser is redirected to after Keycloak completes the
  Authorization Code handshake.
- **Required:** no · **Default:** `/api/auth/oidc-callback` · **Format:** a
  same-origin path starting with a single `/`; `//` anywhere is rejected.
- **If unset:** the default, chosen so the path falls under the existing `/api/`
  route to skein-web without a separate ingress entry.
- **Careful:** whatever value is used must be registered on the Keycloak client
  as a valid redirect URI.

#### `Authentication__Oidc__SignedOutCallbackPath` (`Authentication:Oidc:SignedOutCallbackPath`)

- **Purpose:** path Keycloak redirects to when front-channel logout finishes.
- **Required:** no · **Default:** `/api/auth/oidc-signout-callback` · **Format:**
  same-origin path, validated like `CallbackPath`.
- **If unset:** the default. Must be registered on the Keycloak client as a valid
  post-logout redirect URI.

#### `Authentication__Oidc__SignedOutRedirectUri` (`Authentication:Oidc:SignedOutRedirectUri`)

- **Purpose:** where the browser lands after the whole logout chain (cookie
  cleared, Keycloak `end_session` done).
- **Required:** no · **Default:** `/login` · **Format:** path relative to the app
  origin. Not validated at startup.
- **If unset:** `/login`, which renders the SPA login page.

---

## Not read by skein-web's own code

Nothing in skein-web's own code reads these names. They are listed because an
operator will come across them anyway.

- **`ASPNETCORE_ENVIRONMENT`** — framework-owned. Selects which
  `appsettings.{Environment}.json` overlay is applied and whether the developer
  exception page is used. Defaults to `Production`. The local stack sets
  `Development`, which pulls in `appsettings.Development.json` (debug logging
  only).
- **`Logging__LogLevel__Default` and friends** — framework-owned logging
  configuration, present in `appsettings.json`. Overridable by environment
  variable in the usual `Logging__LogLevel__<Category>` form.
- **`AllowedHosts`** — framework-owned host filtering, `*` in `appsettings.json`.
- **`ASPNETCORE_URLS`** — not read by application code; the listen address is
  built from `PORT` and applied with `UseUrls`. Use `PORT`.
- **`ASPNETCORE_FORWARDEDHEADERS_ENABLED`** — a framework hosting-startup flag
  that also configures `ForwardedHeadersOptions`. skein-web applies its own
  configuration in `PostConfigure`, which runs last, so its trusted-proxy gating
  is the final word whether or not this flag is present.
- **`Authentication:Keycloak:Issuer` / `:Audience` / `:JwksUri` /
  `:JwksCacheDuration`** — present in `appsettings.json` but **dead**: no class
  binds them (`SsoOptions` has no `Keycloak` member) and no code reads them. In
  the legacy `Keycloak` mode this BFF validates no tokens — the edge proxy does —
  so no realm configuration is needed here. Setting them has no effect.
