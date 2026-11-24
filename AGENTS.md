# skein-web

.NET 10 BFF of Skein: cookie sessions with the ticket in Redis, login and
account flows (`/api/auth/*`), the SignalR hub (`/hub`, fed from NATS), and a
reverse proxy to skein-api for `/api/v1/*` (forwarded to skein-api's internal
API `/ui/v1/*`), `/mcp`, `/agent/v1/*` and
`/.well-known/oauth-protected-resource*`. It does not serve the SPA
(skein-frontend does).

Cross-service rules (error codes, health endpoints, `PORT`, no env fallbacks,
logging, git tags, compatibility between services) live in the umbrella
`AGENTS.md` at the top of the `skein/` workspace (`../../AGENTS.md` from here).
They are not repeated here.

## Layout

```
src/
├── SkeinWeb.csproj        the service (net10.0); excludes Tests/** from its own compile
├── Program.cs             wiring, required settings, middleware order, routes
├── Auth/                  sessions (RedisTicketStore), SkeinApiClient, instance-config bootstrap, SSO, rate limiters
├── Controllers/           /api/auth/* — AuthController, AccountController, AuthConfigController
├── Hubs/                  SkeinHub, NatsBridge, access control, delivery, HubMetrics
├── Health/                readiness probe (/ready)
├── Logging/               console formatter (logfmt, JSON errors, secret masking), LoggablePath
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
- **The auth mode comes from skein-api** (`GET /ui/v1/internal/instance-config`,
  read before the host is built). skein-web has no mode setting; it maps the
  answer in `WebAuthMode.FromApi`. Behaviour flags are read from skein-api per
  request, not cached here.
- **Trust boundary.** Identity reaches skein-api only as headers this BFF sets
  from the cookie principal; every inbound `X-Skein-*` header is stripped first
  (`Middleware/ApiProxyMiddleware.cs`). The service-call marker
  `X-Skein-Service-Call: 1` (`Auth/SkeinHeaders.cs#MarkServiceCall`) is set
  only by the BFF's own calls to skein-api, per request or per own client;
  a channel that forwards someone else's request (the `/api/v1` proxy, its
  shared `InternalApiHandler`) never sets it. Never derive a
  privilege decision from a client-controlled header such as `Host` (rationale
  in `Middleware/McpProxyMiddleware.cs`). `SKEIN_TRUSTED_PROXIES` governs
  `X-Forwarded-*` and, in the legacy trust-headers mode, which transport peers
  may send `X-Auth-Request-*` (`Middleware/SsoSessionMiddleware.cs`); the peer
  is the connection address recorded before forwarded headers apply
  (`Middleware/EdgeSnapshotMiddleware.cs`), never a header.
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
- **NuGet audit** fails the `/warnaserror` build on a vulnerable package,
  transitive ones included. When a transitive version is vulnerable, pin a
  patched version directly in `SkeinWeb.csproj` with a comment naming the
  advisory; drop the pin once the parent package brings a patched version.
- **Packages released with ASP.NET Core** stay on the servicing line of the
  target framework (10.0.x for `net10.0`) when their next major either has no
  `net10.0` build or pulls a newer major of an assembly that ships in the
  `Microsoft.AspNetCore.App` shared framework. Check the dependency groups in
  the package's nuspec. In 11.0.0, `Microsoft.AspNetCore.Authentication.OpenIdConnect`
  and `Microsoft.AspNetCore.SignalR.StackExchangeRedis` target only `net11.0`.
  `Microsoft.AspNetCore.DataProtection.StackExchangeRedis`,
  `Microsoft.Extensions.Caching.StackExchangeRedis` and
  `Microsoft.Extensions.Http.Polly` bring in `Microsoft.AspNetCore.DataProtection`,
  `Microsoft.Extensions.*.Abstractions`, `Microsoft.Extensions.Options` or
  `Microsoft.Extensions.Http` 11.0.0. A package with a `net10.0` build and no
  such dependency may take its latest major, for example
  `Microsoft.Extensions.TimeProvider.Testing` 11.0.0.

## Testing

### Kinds

| Kind | Status | What it is here | Command (local) | Narrowed run | Location |
|---|---|---|---|---|---|
| unit | enabled | xUnit + Moq, in-process; infrastructure-dependent tests skip without their settings | `cd src/Tests && dotnet test --nologo --filter 'Category!=Integration'` | `cd src/Tests && dotnet test --nologo --filter 'Category!=Integration&FullyQualifiedName~<Class or Method>'` | `src/Tests/**` |
| integration | enabled | Session revocation through real NATS subscriptions and the shared Redis ticket store; the start with Redis behind Sentinel | `./scripts/integration-test.sh` | `./scripts/integration-test.sh 'FullyQualifiedName~<Class or Method>'` | `src/Tests/**`, trait `Category=Integration` |
| e2e | covered by skein-frontend | no own suite; the `e2e` group of skein-frontend exercises the hub, the cookie session and the proxy on a live stack built from `projects/*` | from the top of `skein/`: `./scripts/e2e-test.sh` | from the top of `skein/`: `./scripts/e2e-test.sh -- -g '<test title>'` | `projects/skein-frontend/browser/e2e/` |
| smoke (image contract) | not used | — | — | — | — |
| mutation | on demand, a final gate for a large change | Stryker.NET on VSTest, only on lines changed since a base commit; runs on the test VMs only | see "Running on the test VMs" | one or more `--mutate` globs | `.progon/web.toml` |
| source-reading checks | not used | — | — | — | — |
| artifact contract | not used | — | — | — | — |

### Running on the test VMs (progon)

The profile is `.progon/web.toml`; run from the repository root:

| Kind | Command | Narrowed run |
|---|---|---|
| unit | `progon web unit` | `progon web unit 'FullyQualifiedName~<Class or Method>'` |
| integ | `progon web integ` | `progon web integ 'FullyQualifiedName~<Class or Method>'` |
| mutation | `progon web mutation --since <BASE> --keep --split <N> --quota-wait 7200 --background <targets>` (see below) | the targets are files, e.g. `src/Health/ReadinessEndpoint.cs` |

`integ` starts NATS, Redis and Redis-behind-Sentinel fixtures and sets
`TEST_NATS_URL`, `TEST_NATS_MONITOR_URL`, `TEST_REDIS_URL` and
`TEST_REDIS_SENTINEL_URL`. `mutation` runs Stryker.NET on its
default VSTest runner, with the same fixtures. Not on the Microsoft Testing
Platform: there its coverage relay goes stale after the tests that start a child
SkeinWeb (stryker-net#3871) and the later mutants end as timeouts.
A full mutation run is long; always name targets.

Mutation of everything changed since a base commit (`<BASE>`, the commit the
work started from), in bash:

```bash
mapfile -t T < <(git diff --name-only <BASE>..HEAD -- src | grep -v '^src/Tests/' | grep '\.cs$')
progon web mutation --since <BASE> --keep --split 3 --quota-wait 7200 --background "${T[@]}"
progon wait <group id printed by the command>
```

- Name each target as a file path relative to the repository root, as
  `git diff --name-only` prints it (`src/Auth/SessionIssuer.cs`), one target
  per argument. progon anchors a target where it finds the file; a glob is
  anchored at the workdir `src/Tests`, so a bare glob such as `**/Health/*.cs`
  selects the test project's files, not the service's, and the run measures
  no service code.
- `--split` needs the targets named; it divides them into parts that run as one
  group. The whole-run ceiling is 7200 s per part, so a change of a few
  thousand mutants must be split (a run of about 3300 mutants was estimated at
  about 3 hours, over the ceiling).
- A verdict `no mutant measured` means the tool tested nothing: read the raw
  log of the run (`results/stryker-net/stream.log` under the run directory in
  the progon cache) before running again.

### Project specifics

- Session revocation is tested against isolated NATS and Redis containers;
  SignalR is exercised live by the product e2e suite. There is no e2e job
  in this repository; the e2e harness builds this image from the working tree.
- Do not add checks that read source code without a maintainer's decision.

### Prerequisites

- Unit: .NET 10 SDK only. No environment variables, no secrets, no Docker.
- Integration: Docker, Bash and Python 3; run from a checkout on the Docker
  daemon's host (container bind mounts must resolve to that checkout).
  `TEST_NATS_URL`, `TEST_NATS_MONITOR_URL` and `TEST_REDIS_URL` are set by
  the harness; without any of them the integration theory is skipped.
  `TEST_REDIS_SENTINEL_URL` (a Redis behind Sentinel, also started by the
  harness) gates the start through Sentinel; without it that test is skipped.
  The harness uses .NET SDK 10; `SKEIN_TEST_RUNNER_IMAGE`, `SKEIN_TEST_CPUS`
  and `SKEIN_TEST_MEMORY` override its runner image and resource limits.
- e2e: Docker and the full `skein/` workspace with all three services cloned
  into `projects/`. Inside a devcontainer export `HOST_WORKSPACE` (see the
  umbrella `AGENTS.md`).

### When what runs

| Event | unit | integration | e2e | smoke | mutation |
|---|---|---|---|---|---|
| pull request / push to `main` | `ci.yml`: lint + unit | — | — | — | — |
| release tag `X.Y.Z` | `release.yml` runs `ci.yml` first | — | — | — | — |
| release tag `X.Y.Z-rc.N` | nothing (publishes nothing) | — | — | — | — |
| manual | local only | local only (`./scripts/integration-test.sh`) | local only (`./scripts/e2e-test.sh`) | — | — |

`.github/workflows/ci.yml` runs on pull requests, on pushes to `main` and as a
reusable workflow: the lint build (`/warnaserror`) and the unit suite, with a
guard that fails a run which executed zero tests. `release.yml` runs only on a
final `X.Y.Z` tag: it re-validates the tag format, requires the tagged commit
to be on `main`, runs `ci.yml`, waits for approval on the `release`
environment, builds `linux/amd64` and `linux/arm64` natively, publishes the
multi-arch image `ghcr.io/tryskein/skein-web` as `X.Y.Z` and `latest`, and then
creates a GitHub Release. e2e and mutation are never run on GitHub.

CI runs the unfiltered xUnit suite; integration tests skip because their
infrastructure settings are absent. The local unit command excludes that trait.

### Pitfalls

- A run with zero executed tests is not green. Read the summary line
  (`Passed`, `Failed`, `Total`); a `--filter` that matches nothing is a
  mistake, not a pass.
- `src/Tests` lives under `src/`; `SkeinWeb.csproj` removes `Tests/**` from its
  compile items. A new test file outside `src/Tests` is compiled into the
  service.
- `NatsBridgeIntegrationTests` is a unit test with mocks, despite the name.

### Kinds without automatic runs

- Integration is run only by hand, through `./scripts/integration-test.sh`.
- e2e for this service is run only by hand, through the umbrella harness.
