# skein-web

.NET 10 BFF of Skein: cookie sessions with the ticket in Redis, login and
account flows (`/api/auth/*`), the SignalR hub (`/hub`, fed from NATS), and a
reverse proxy to skein-api for `/api/v1/*`, `/mcp`, `/agent/v1/*` and
`/.well-known/oauth-protected-resource*`. It does not serve the SPA
(skein-frontend does).

Cross-service rules (error codes, health endpoints, `PORT`, no env fallbacks,
logging, git tags, compatibility between services) live in the umbrella
`CLAUDE.md` at the top of the `skein/` workspace (`../../CLAUDE.md` from here).
They are not repeated here.

## Layout

```
src/
├── SkeinWeb.csproj        the service (net10.0); excludes Tests/** from its own compile
├── Program.cs             wiring, required settings, middleware order, routes
├── Auth/                  sessions (RedisTicketStore), SkeinApiClient, instance-config bootstrap, SSO, rate limiters
├── Controllers/           /api/auth/* — AuthController, AccountController, AuthConfigController
├── Hubs/                  SkeinHub, NatsBridge, access control, delivery, HubMetrics
├── Middleware/            ApiProxy, McpProxy, AgentProxy, SsoSession, ServiceWorker
├── appsettings*.json      logging and OIDC client defaults only — no addresses
└── Tests/                 SkeinWeb.Tests.csproj (xUnit + Moq)
docs/env-reference.md      every setting the service reads
Dockerfile                 build context is the repo root
```

## Build and run

```bash
cd src && dotnet build SkeinWeb.csproj -c Release /warnaserror   # the lint gate
docker build -t skein-web:dev .                                  # image, from the repo root
```

Running it on its own needs skein-api, Redis and NATS to be reachable; see `README.md`. The
normal way to run it is the umbrella's local stack (from the top of `skein/`):
`docker compose --env-file versions.env -f docker-compose.local.yml -f docker-compose.local.build.yml up -d --build`
(the second file builds the services from `projects/`; without it the published images run). There skein-web is
internal; the browser reaches it through skein-frontend's nginx on `:8080`.

## Invariants

- **Required settings fail at startup**: `SKEIN_API_URL`,
  `SKEIN_INTERNAL_SECRET`, `REDIS_URL`, `NATS_URL`. No fallbacks in code.
- **`docs/env-reference.md` is the only list of settings.** Adding, renaming or
  dropping a setting changes that file in the same commit. Do not keep a copy
  of the list in `README.md` or anywhere else.
- **The auth mode comes from skein-api** (`GET /api/v1/internal/instance-config`,
  read before the host is built). skein-web has no mode setting; it maps the
  answer in `WebAuthMode.FromApi`. Behaviour flags are read from skein-api per
  request, not cached here.
- **Trust boundary.** Identity reaches skein-api only as headers this BFF sets
  from the cookie principal; every inbound `X-Skein-*` header is stripped first
  (`Middleware/ApiProxyMiddleware.cs`). Never derive a
  privilege decision from a client-controlled header such as `Host` (rationale
  in `Middleware/McpProxyMiddleware.cs`). `SKEIN_TRUSTED_PROXIES` governs only
  `X-Forwarded-*`.
- **Redis holds shared state**: session tickets, the DataProtection key ring,
  login throttling and the SignalR backplane. Anything per-replica in memory
  breaks multi-replica deployments.
- **Endpoint documentation**: `/api/auth/*` endpoints are controllers
  (`[ApiController]`, attribute routing), each action with `[SwaggerOperation]` (Summary, Description,
  OperationId), `[ProducesResponseType]` for every status, XML `<summary>` /
  `<remarks>` / `<param>` / `<response>`; errors as `Problem(...)`. Change the
  docs in the same commit as the endpoint. Swagger UI is mapped only in
  `Development`.
- **Custom Prometheus metrics** carry `[MetricInfo]` and `[MetricLabel]`
  describing meaning, unit, where they change and every label (see
  `Hubs/HubMetrics.cs`).
- **Package pins** in `SkeinWeb.csproj` (`MessagePack`, `Microsoft.OpenApi`)
  override vulnerable transitive versions; NuGet audit fails the `/warnaserror`
  build without them. Do not drop a pin without checking the advisory.

## Testing

### Kinds

| Kind | Status | What it is here | Command (local) | Narrowed run | Location |
|---|---|---|---|---|---|
| unit | enabled | xUnit + Moq, in-process; `*Integration*` classes are mock-based too, no live NATS or Redis | `cd src/Tests && dotnet test --nologo` | `cd src/Tests && dotnet test --nologo --filter "FullyQualifiedName~<Class or Method>"` | `src/Tests/**` |
| integration | not used | the BFF is tested at its boundaries with HTTP handler stubs and a mocked hub | — | — | — |
| e2e | covered by skein-frontend | no own suite; the `e2e` group of skein-frontend exercises the hub, the cookie session and the proxy on a live stack built from `projects/*` | from the top of `skein/`: `./scripts/e2e-test.sh` | from the top of `skein/`: `./scripts/e2e-test.sh -- -g '<test title>'` | `projects/skein-frontend/browser/e2e/` |
| smoke (image contract) | not used | — | — | — | — |
| mutation | not used | — | — | — | — |
| source-reading checks | not used | — | — | — | — |
| artifact contract | not used | — | — | — | — |

### Project specifics

- Live NATS, Redis and SignalR are exercised only by the product e2e suite.
  There is no e2e job in this repository; the e2e harness builds this image
  from the working tree.
- Do not add checks that read source code without a maintainer's decision.

### Prerequisites

- Unit: .NET 10 SDK only. No environment variables, no secrets, no Docker.
- e2e: Docker and the full `skein/` workspace with all three services cloned
  into `projects/`. Inside a devcontainer export `HOST_WORKSPACE` (see the
  umbrella `CLAUDE.md`).

### When what runs

| Event | unit | integration | e2e | smoke | mutation |
|---|---|---|---|---|---|
| pull request / push to `main` | `ci.yml`: lint + unit | — | — | — | — |
| release tag `X.Y.Z` | `release.yml` runs `ci.yml` first | — | — | — | — |
| release tag `X.Y.Z-rc.N` | nothing (publishes nothing) | — | — | — | — |
| manual | local only | — | local only (`./scripts/e2e-test.sh`) | — | — |

`.github/workflows/ci.yml` runs on pull requests, on pushes to `main` and as a
reusable workflow: the lint build (`/warnaserror`) and the unit suite, with a
guard that fails a run which executed zero tests. `release.yml` runs only on a
final `X.Y.Z` tag: it re-validates the tag format, requires the tagged commit
to be on `main`, runs `ci.yml`, waits for approval on the `release`
environment, builds `linux/amd64` and `linux/arm64` natively, publishes the
multi-arch image `ghcr.io/tryskein/skein-web` as `X.Y.Z` and `latest`, and then
creates a GitHub Release. e2e and mutation are never run on GitHub.

### Pitfalls

- A run with zero executed tests is not green. Read the summary line
  (`Passed`, `Failed`, `Total`); a `--filter` that matches nothing is a
  mistake, not a pass.
- `src/Tests` lives under `src/`; `SkeinWeb.csproj` removes `Tests/**` from its
  compile items. A new test file outside `src/Tests` is compiled into the
  service.
- `NatsBridgeIntegrationTests` is a unit test with mocks, despite the name.

### Kinds without automatic runs

- e2e for this service is run only by hand, through the umbrella harness.
