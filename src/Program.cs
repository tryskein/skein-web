using System.Reflection;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.OpenApi;
using NATS.Client.Core;
using Prometheus;
using Prometheus.DotNetRuntime;
using Prometheus.SystemMetrics;
using SkeinWeb.Auth;
using SkeinWeb.Hubs;
using SkeinWeb.Middleware;
using StackExchange.Redis;

// .NET runtime metrics — must be configured BEFORE WebApplication.CreateBuilder
// so the collectors install their event listeners early in process startup.
DotNetRuntimeStatsBuilder
    .Customize()
    .WithThreadPoolStats()
    .WithGcStats()
    .WithExceptionStats()
    .WithContentionStats()
    .StartCollecting();

var builder = WebApplication.CreateBuilder(args);

// ---- Required env (no fallbacks) ------------------
// Configuration sources are layered: env vars > appsettings.{Env}.json >
// appsettings.json. We allow "PORT" to fall back to 8080 (it's a port
// number, not a service address), but everything that points at another
// service or carries a secret must be set explicitly.
var port = builder.Configuration["PORT"] ?? "8080";

var skeinApiUrl = builder.Configuration["SKEIN_API_URL"]
    ?? throw new InvalidOperationException("SKEIN_API_URL is not set");
var internalSecret = builder.Configuration["SKEIN_INTERNAL_SECRET"]
    ?? throw new InvalidOperationException("SKEIN_INTERNAL_SECRET is not set");
var redisUrl = builder.Configuration["REDIS_URL"]
    ?? throw new InvalidOperationException("REDIS_URL is not set");

// R3.2c — NATS Core for the SignalR live-events bridge. Required: no
// fallback. NATS_URL must be set explicitly
// — appsettings.json carries no default for the URL (only the connection
// Name). docker-compose.local.yml sets NATS_URL on skein-web for local
// development; production deployments inject it via env.
var natsUrl = builder.Configuration["NATS_URL"]
    ?? throw new InvalidOperationException("NATS_URL is not set");
var natsName = builder.Configuration["Nats:Name"] ?? "skein-web-hub";

// StackExchange.Redis expects a comma-separated config string ("host:port,..."),
// not a redis:// URL. Translate the URL form (which is what every other
// service in this stack uses) into the SE.Redis form.
var redisConfig = ParseRedisConfig(redisUrl);

builder.Services.UseHttpClientMetrics();
builder.WebHost.UseUrls($"http://0.0.0.0:{port}");

// ---- Redis: shared multiplexer ---------------------------------------------
// One IConnectionMultiplexer per process — SE.Redis is internally
// thread-safe and connects lazily per endpoint. Used by IDistributedCache,
// DataProtection, and LoginRateLimiter (the last needs raw IDatabase access
// for atomic INCR which IDistributedCache cannot express).
var muxer = ConnectionMultiplexer.Connect(redisConfig);
builder.Services.AddSingleton<IConnectionMultiplexer>(muxer);

// IDistributedCache backed by Redis — used by RedisTicketStore.
builder.Services.AddStackExchangeRedisCache(o =>
{
    o.ConnectionMultiplexerFactory = () => Task.FromResult<IConnectionMultiplexer>(muxer);
});

// DataProtection: persist the AES keyring to Redis. This is what makes
// multi-replica skein-web deployments work — without it, each pod
// generates its own keyring on first start, and a cookie issued by pod A
// is gibberish to pod B. SetApplicationName isolates this app's keyring
// from anything else that might share the same Redis.
builder.Services.AddDataProtection()
    .PersistKeysToStackExchangeRedis(muxer, "skein:dataprotection:keys")
    .SetApplicationName("Skein");

// ---- System metrics + health checks ----------------------------------------
builder.Services.AddSystemMetrics();
builder.Services.AddHealthChecks();

// ---- Authentication: Cookie + RedisTicketStore ------------------------------
// The cookie carries only an opaque session id; the AuthenticationTicket
// itself is stored in Redis under skein:session:<sid>. SecurePolicy is
// SameAsRequest because in dev we ride plain HTTP on localhost:8080;
// production HTTPS termination at the ingress flips it to Secure
// automatically.
//
// TODO R5+: add Antiforgery double-submit cookie. We currently rely on
// SameSite=Lax + same-origin to block CSRF, which is fine for a same-
// origin React SPA (cookies don't ride along on third-party POSTs) but
// not enough for cross-origin clients or older browsers. Confirmed
// acceptable risk by user for R1.1.
builder.Services.AddSingleton<RedisTicketStore>();
builder.Services.AddSingleton<IUserSessionRevoker>(sp => sp.GetRequiredService<RedisTicketStore>());
builder.Services.AddSingleton<ISessionTicketProbe>(sp => sp.GetRequiredService<RedisTicketStore>());

// ---- Installation settings from skein-api (plan K-12, D-7, E-13) ------------
// The authentication MODE is skein-api's (SKEIN_AUTH_MODE), not ours: read it
// here, before builder.Build(), because AddAuthentication must see every scheme
// up front. Bounded retry inside SKEIN_API_STARTUP_TIMEOUT_SECONDS (skein-api
// may be starting next to us); no answer → log Critical and exit non-zero, so
// the pod never becomes ready. There is no web-side default mode.
var apiStartupTimeout = InstanceConfigBootstrap.ParseStartupTimeout(
    builder.Configuration["SKEIN_API_STARTUP_TIMEOUT_SECONDS"]);
InstanceConfig instanceConfig;
// Bootstrap logger: the host's logging is not built yet. Console defaults
// (Information and up) carry the per-attempt warnings and the Critical exit line.
using (var bootstrapLogging = LoggerFactory.Create(logging => logging.AddConsole()))
using (var bootstrapHttp = InstanceConfigBootstrap.CreateHttpClient(skeinApiUrl, internalSecret))
{
    var bootstrapLogger = bootstrapLogging.CreateLogger("InstanceConfigBootstrap");
    try
    {
        instanceConfig = await InstanceConfigBootstrap.LoadAsync(
            bootstrapHttp, apiStartupTimeout, TimeProvider.System, bootstrapLogger, CancellationToken.None);
    }
    catch (InstanceConfigUnavailableException ex)
    {
        bootstrapLogger.LogCritical(ex, "skein-web cannot start: {Reason}", ex.Message);
        return 1;
    }
}

// Mode mapping (plan K-13): api local/keycloak/hybrid → web Local / Keycloak or
// KeycloakOidc (by whether Authentication:Oidc:Authority is set) / + Hybrid.
var ssoSnapshot = new SsoOptions();
builder.Configuration.GetSection(SsoOptions.SectionName).Bind(ssoSnapshot);
var authMode = WebAuthMode.FromApi(instanceConfig.AuthMode, ssoSnapshot.Oidc.Authority);

// ---- Client runtime addresses (sk-303.42) -----------------------------------
// Deployment-specific endpoint addresses published to the SPA on
// GET /api/auth/config. Read from env in the same style as SKEIN_API_URL above.
var clientRuntime = new ClientRuntimeOptions
{
    McpUrl = builder.Configuration["SKEIN_MCP_URL"] ?? string.Empty,
};
clientRuntime.Validate();
builder.Services.AddSingleton(Microsoft.Extensions.Options.Options.Create(clientRuntime));

// Cookie scheme always, OpenIdConnect only in KeycloakOidc mode; validates the
// OIDC-client settings and registers the WebAuthMode singleton the mode-dependent
// surfaces read. See AuthenticationRegistration.
builder.Services.AddSkeinAuthentication(authMode, ssoSnapshot);

builder.Services.AddAuthorization();

// HttpContextAccessor — InternalApiHandler reads claims from
// HttpContext.User to build the X-Skein-User-* headers.
builder.Services.AddHttpContextAccessor();

// ---- skein-api: typed client + named proxy client ---------------------------
// sk-303.8 — the Host-based internal/public surface classifier (sk-163 S7a,
// SKEIN_INTERNAL_HOSTS) was removed outright rather than hardened: it derived
// a privilege decision from Request.Host, a header the client controls, and
// in the one deployment shape this service actually runs in (behind the
// internal gateway, no public route) it never divided anything — every
// configured host was already internal. See McpProxyMiddleware for where the
// internal-surface marker is stamped now, and for the note on how to build
// this boundary again on a server-controlled signal if a public surface ever
// ships.

// sk-163 S9 — trusted proxy chain. Drives BOTH the ForwardedHeaders config
// (below) and the per-IP throttle opt-in: the per-IP login bucket and the
// X-Skein-Client-Ip forward are enabled ONLY when at least one trusted proxy
// is configured (otherwise RemoteIpAddress is the constant ingress IP and a
// per-IP bucket would be a global lockout vector). See TrustedProxyConfig.
var trustedProxies = (builder.Configuration["SKEIN_TRUSTED_PROXIES"] ?? "")
    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
var clientIpTrusted = TrustedProxyConfig.PerIpThrottleEnabled(trustedProxies);

// sk-608 — /mcp upstream headers timeout. Optional (a duration, not an
// address or a secret), so it has a default; a set-but-invalid value throws
// here, before the server binds a port. See docs/env-reference.md.
var mcpUpstreamHeadersTimeout = SkeinApiOptions.ParseMcpUpstreamHeadersTimeout(
    builder.Configuration["SKEIN_MCP_UPSTREAM_HEADERS_TIMEOUT_SECONDS"]);

builder.Services.Configure<SkeinApiOptions>(o =>
{
    o.Url = skeinApiUrl;
    o.InternalSecret = internalSecret;
    o.ClientIpTrusted = clientIpTrusted;
    o.McpUpstreamHeadersTimeout = mcpUpstreamHeadersTimeout;
});

// McpProxyMiddleware schedules its headers timeout on this clock; tests swap
// in a fake one. TryAdd: keep any registration the framework already made.
builder.Services.TryAddSingleton(TimeProvider.System);

builder.Services.AddTransient<InternalApiHandler>();

// Polly retry: handle transient HttpRequestException + 5xx + 408. Three
// retries, 200ms exponential backoff — see SkeinApiRetryPolicy.
builder.Services.AddHttpClient<SkeinApiClient>(client =>
{
    client.BaseAddress = new Uri(skeinApiUrl);
    client.Timeout = TimeSpan.FromSeconds(15);
})
.AddHttpMessageHandler<InternalApiHandler>()
.AddPolicyHandler(SkeinApiRetryPolicy.Create());

// Service-to-service client (sk-622.21 T031): hub methods and background
// access re-checks call skein-api on skein-web's own behalf. NO
// InternalApiHandler, secret redacted from logs, shared retry policy, 15 s
// budget per call — see SkeinServiceApiClientRegistration.
builder.Services.AddSkeinServiceApiClient(skeinApiUrl);

// Public account routes (plan K-17, AccountController): skein-api
// /api/v1/auth/* with the service secret and the trusted client IP only — NO
// InternalApiHandler (a logged-in tab must not put its identity on them),
// retry on GET only (a replayed signup would turn into email_taken).
SkeinAccountsApiClient.Register(builder.Services, skeinApiUrl);

// Named client for ApiProxyMiddleware: same internal-secret + identity
// headers, but no Polly (a proxied request streams body and we don't want
// to retry POSTs whose body is already consumed), and no HttpClient request
// logging (paths carry invitation tokens) — see AddProxyHttpClient.
ApiProxyMiddleware.AddProxyHttpClient(builder.Services, skeinApiUrl);

// Dedicated client for the MCP proxy. NO InternalApiHandler (it would
// inject X-Skein-User-* headers from the cookie principal, which is
// wrong for /mcp where authentication is API-key-driven). NO Polly
// retry: MCP responses are streaming + sometimes long-lived (SSE),
// retrying mid-stream would corrupt the response. The McpProxyMiddleware
// adds the X-Skein-Internal-Secret channel-auth header itself.
//
// Timeout is InfiniteTimeSpan: HttpClient.Timeout covers the WHOLE call
// including response-body completion, so a finite value would kill
// healthy SSE streams that legitimately stay open for the duration of a
// long agent conversation. The per-attempt headers timeout (upstream
// must return response headers within a fixed window) is enforced in
// McpProxyMiddleware via a linked CancellationTokenSource — that is the
// correct place to bound the connect/headers phase without capping the
// stream length.
builder.Services.AddHttpClient("skein-api-mcp", client =>
{
    client.BaseAddress = new Uri(skeinApiUrl);
    client.Timeout = Timeout.InfiniteTimeSpan;
});

// Dedicated client for the agent data-plane proxy (/agent/v1/*, sk-142).
// Identical config to "skein-api-mcp": NO InternalApiHandler (it would inject
// X-Skein-User-* from the cookie principal, wrong for the api-key door), NO
// Polly (the poll endpoint can degrade to a long-poll and a streaming body
// must not be retried). Timeout is InfiniteTimeSpan because HttpClient.Timeout
// would also bound the long-poll body; the connect/headers phase is bounded by
// a linked CancellationTokenSource inside AgentProxyMiddleware. The middleware
// adds X-Skein-Internal-Secret itself.
builder.Services.AddHttpClient("skein-api-agent", client =>
{
    client.BaseAddress = new Uri(skeinApiUrl);
    client.Timeout = Timeout.InfiniteTimeSpan;
});

// ---- OIDC-client options ------------------------------------------------------
// The Authentication section now carries only what the BFF alone knows — its
// OIDC client and the edge proxy's sign-out address; the mode is WebAuthMode
// (registered by AddSkeinAuthentication above). Logout and the SPA config read
// these through IOptions<SsoOptions>.
builder.Services.Configure<SsoOptions>(builder.Configuration.GetSection(SsoOptions.SectionName));

// Middleware — registered as transient (matches ApiProxyMiddleware /
// McpProxyMiddleware) so its IServiceProvider dependency stays scoped
// per-request.
builder.Services.AddTransient<SsoSessionMiddleware>();

// ---- Login rate limiter -----------------------------------------------------
builder.Services.AddSingleton<LoginRateLimiter>();
// Public account routes (plan K-17): «action + email» / «action + IP» buckets.
builder.Services.AddSingleton<ActionRateLimiter>();

// ---- Trusted proxy / client-IP resolution (sk-163 S9) ----------------------
// The per-IP login throttle (LoginRateLimiter) and the X-Skein-Client-Ip the
// BFF forwards to skein-api are only as trustworthy as the client IP we
// derive. Connection.RemoteIpAddress is the immediate TCP peer — behind an
// ingress / frontend nginx that is the PROXY, not the real client. We honour
// X-Forwarded-For ONLY from explicitly trusted proxies; a raw XFF from an
// arbitrary client is never trusted (an attacker rotating XFF would otherwise
// defeat the per-IP bucket — worse than no per-IP throttle at all).
//
// SKEIN_TRUSTED_PROXIES is a comma-separated list of proxy IPs and/or CIDR
// networks (e.g. "10.0.0.0/8,192.168.1.5"). For each request the
// ForwardedHeaders middleware peels exactly one XFF hop, and applies
// X-Forwarded-Host, but only when the immediate peer is in this allowlist.
// EMPTY (the default) trusts NOTHING that carries authority: the loopback
// defaults are cleared, neither X-Forwarded-For nor X-Forwarded-Host is
// applied — RemoteIpAddress stays the immediate peer and Request.Host stays
// the literal Host header (sk-194.6.52: with an empty allowlist the framework
// cannot gate a forwarded header at all, so honouring X-Forwarded-Host there
// would let any client forge Request.Host — read today by the OIDC
// same-origin return-URL whitelist). Only X-Forwarded-Proto survives the
// empty case, because it carries no authority
// and the OIDC callback needs the https scheme (sk-163.17). Operators putting
// skein-web behind a proxy (S10) MUST populate this with the proxy's
// address(es) — it is required, not optional, for a public surface.
// PostConfigure (NOT Configure): runs AFTER every IConfigureOptions callback,
// including the one the ASPNETCORE_FORWARDEDHEADERS_ENABLED hosting-startup
// registers. This guarantees Apply is the final word on ForwardedHeadersOptions
// regardless of that env flag's presence or registration order — so the sk-163
// image is safe to deploy under the current configmap (env flag still set) AND
// after it's removed, with no window where the env flag's defaults override
// Apply's Proto/Host + trusted-proxy gating. (sk-163.17)
builder.Services.PostConfigure<ForwardedHeadersOptions>(o =>
    TrustedProxyConfig.Apply(o, trustedProxies));

// ---- Reverse-proxy middleware ----------------------------------------------
builder.Services.AddTransient<ApiProxyMiddleware>();
builder.Services.AddTransient<McpProxyMiddleware>();
builder.Services.AddTransient<AgentProxyMiddleware>();

// Service-worker serving rule for /sw.js (root scope + Service-Worker-Allowed
// + no-cache). A no-op when the SPA bundle is not co-hosted in wwwroot — the
// public entrypoint is the skein-frontend nginx image, which serves /sw.js
// itself in production. See ServiceWorkerMiddleware for the dev/prod split.
builder.Services.AddTransient<ServiceWorkerMiddleware>();

// ---- R3.2c — SignalR Hub + NATS bridge --------------------------------------
// NATS connection, SignalR hub + Redis backplane and the sk-622.21 hub-delivery
// services (connection registry, access re-check, declaration limiter,
// personal-signal coalescing, bridge, control events, transport health) — one
// composition, shared with the test that resolves it. Neither NATS nor the
// backplane connects here; both connect on first use.
builder.Services.AddSkeinHubDelivery(
    natsUrl,
    natsName,
    redisConfig,
    builder.Configuration["HUB_MAX_PROJECTS_PER_CONNECTION"],
    builder.Configuration["COUNTS_SIGNAL_WINDOW_MS"]);

// Event-driven cookie session invalidation (R5.x):
// when skein-api publishes a claim-relevant per-field event on
// skein.user.{uid}.field.{kebab} (role, deactivated-at, name, username),
// the subscriber wipes every active Valkey ticket for that user via
// RedisTicketStore.RemoveByUserIdAsync. Sub-second invalidation in the
// happy path; SsoSessionMiddleware's TTL-refresh loop is the fallback
// for the case where NATS lag or a queue-group drop swallows the event.
builder.Services.AddHostedService<UserChangedSubscriber>();

// ---- Controllers + ProblemDetails + Swagger --------------------------------
builder.Services.AddControllers();
// AddProblemDetails wires RFC 7807 responses for unhandled exceptions and
// status-code-only results, plus auto-fills the 400 model for validation
// failures.
builder.Services.AddProblemDetails();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Skein BFF",
        Version = "v1",
        Description = "Cookie-backed gateway for the Skein web client. " +
                      "Authentication endpoints under /api/auth, transparent reverse-proxy " +
                      "for /api/v1/* with X-Skein-User-* identity forwarding.",
    });
    c.EnableAnnotations();

    var xmlPath = Path.Combine(AppContext.BaseDirectory,
        $"{Assembly.GetExecutingAssembly().GetName().Name}.xml");
    if (File.Exists(xmlPath))
    {
        c.IncludeXmlComments(xmlPath);
    }
});

var app = builder.Build();

// sk-194.6.52 — with NO trusted proxy declared, the ForwardedHeaders
// middleware has no allowlist to check a forwarded header against, so
// X-Forwarded-Host is NOT honoured (it would otherwise be accepted from any
// client, letting a public caller forge Request.Host). Request.Host is then
// the literal Host header, and the per-IP login throttle is off. Both are
// safe defaults, but they are NOT the intended shape behind an ingress — so
// say so at startup rather than leaving an operator to discover it from a
// throttle that never fires. WARN, not fail: running with no proxy in front
// is a legitimate deployment (local compose, direct exposure), and killing
// the pod over it would turn a degraded mode into an outage.
if (!TrustedProxyConfig.ForwardedHostHonoured(trustedProxies))
{
    app.Logger.LogWarning(
        "SKEIN_TRUSTED_PROXIES is empty — X-Forwarded-Host and X-Forwarded-For are " +
        "NOT honoured (fail-closed): Request.Host stays the literal Host header and " +
        "the per-IP login throttle is disabled. If this service sits behind an " +
        "ingress or reverse proxy, set SKEIN_TRUSTED_PROXIES to the proxy " +
        "IP(s)/CIDR(s) — it is required for any deployment with a public host " +
        "(sk-194.6.52).");
}

// sk-303.42 — same shape of decision, one layer up. In legacy trust-headers
// mode an authenticating proxy owns the session that actually lets a user in;
// clearing only our own cookie leaves that session alive, so the next request
// silently re-authenticates and "log out" did nothing the user can observe.
// The proxy's sign-out address is deployment-specific, so it is configuration —
// and it is WARN, not fail: a proxy-less run of this mode is a legitimate
// (if odd) local shape, and refusing to boot would turn an incomplete logout
// into an outage. Same trade-off as SKEIN_TRUSTED_PROXIES above (sk-194.6.52).
if (authMode.IsKeycloakMode && string.IsNullOrWhiteSpace(ssoSnapshot.LogoutRedirectUrl))
{
    app.Logger.LogWarning(
        "Authentication__LogoutRedirectUrl is empty in the legacy trust-headers mode " +
        "(skein-api SKEIN_AUTH_MODE=keycloak|hybrid, no Authentication__Oidc__Authority) " +
        "— logout clears the local skein.sid cookie only and returns no redirect. The " +
        "EXTERNAL proxy session survives, so the user is signed straight back in on the " +
        "next request. Set Authentication__LogoutRedirectUrl to the sign-out endpoint of " +
        "the proxy in front of this deployment (for an oauth2-proxy edge: " +
        "https://<your-proxy-host>/oauth2/sign_out).");
}

// ---- HTTP pipeline ----------------------------------------------------------
// Order matters:
// 1) Routing & metrics first so /metrics is collected for everything else.
// 2) Authentication BEFORE Authorization (and BEFORE ApiProxyMiddleware,
//    which checks IsAuthenticated for /api/v1/* gating).
// 3) Controllers run for matched routes (/api/auth/*, /healthz, /ready, /metrics).
// 4) ApiProxyMiddleware terminates anything under /api/v1/*.
// 5) Static files + SPA fallback for everything else.

// ForwardedHeaders FIRST (sk-163 S9): apply X-Forwarded-Proto/Host (so OIDC
// builds an https redirect_uri and cookies see the real scheme/host) and, when
// a trusted proxy is configured, rewrite Connection.RemoteIpAddress from the
// trusted X-Forwarded-For hop BEFORE any middleware reads the client IP — the
// per-IP login throttle (AuthController) and the X-Skein-Client-Ip the BFF
// forwards both depend on it. This is the SINGLE ForwardedHeaders path: the
// options come from TrustedProxyConfig.Apply (sk-163.17), NOT from
// ASPNETCORE_FORWARDEDHEADERS_ENABLED. When SKEIN_TRUSTED_PROXIES is empty,
// only Proto is applied: Host and XFF are not (Request.Host stays the literal
// Host header, RemoteIpAddress stays the peer) — sk-194.6.52.
app.UseForwardedHeaders();

app.UseRouting();

// HTTP request metrics — registered before MapMetrics so /metrics itself
// is excluded by the prometheus-net middleware's own filter.
app.UseHttpMetrics();

// Service worker (/sw.js): served at root scope with Service-Worker-Allowed
// + no-cache. Placed BEFORE UseAuthentication because the SW file is a public
// asset (no cookie required) and must not be gated; the middleware
// short-circuits on any other path, so all other traffic flows on unchanged.
// In the standard deployment (SPA hosted by the skein-frontend nginx image)
// nginx answers /sw.js before it reaches the BFF, so this is a no-op there.
app.UseMiddleware<ServiceWorkerMiddleware>();

// MCP proxy runs BEFORE UseAuthentication: the /mcp endpoint
// authenticates with X-Skein-Api-Key, NOT a cookie, so we don't want
// the cookie middleware to attempt validation (it would set 401
// challenges on unauthenticated MCP requests). The middleware
// short-circuits on path mismatch, so REST + SPA traffic still flows
// through UseAuthentication below.
app.UseMiddleware<McpProxyMiddleware>();

// Agent data-plane proxy (/agent/v1/*, sk-142) runs BEFORE UseAuthentication
// for the same reason as the MCP proxy: external agents authenticate with a
// short-lived monitor token on X-Skein-Api-Key (not a cookie), so the cookie
// middleware must not attempt validation. Unlike /mcp (a single exact path),
// /agent/v1 has sub-paths and is matched by segment boundary inside the
// middleware; it short-circuits on any non-/agent/v1 path so REST + SPA
// traffic still flows through UseAuthentication below.
app.UseMiddleware<AgentProxyMiddleware>();

app.UseAuthentication();

// R5.1 — SSO session bootstrapper. In keycloak mode this middleware
// reads the trust headers (X-Auth-Request-User + X-Auth-Request-Email,
// set by oauth2-proxy), calls skein-api /auth/oidc/provision and signs
// the user in with the same cookie scheme the local password flow uses.
// JWT validation is NOT done here — it lives in oauth2-proxy at the
// cluster edge (trust-headers org pattern). In local mode the
// middleware is a no-op.
//
// Position: AFTER UseAuthentication (we need to see whether the cookie
// middleware already attached an authenticated principal — if so, this
// middleware short-circuits) and BEFORE UseAuthorization (so the fresh
// principal we mint via context.SignInAsync is visible to [Authorize]
// gates on /api/auth/me and friends; otherwise AuthZ short-circuits
// with 401 before this middleware ever runs and the first /me on a
// just-arrived oauth2-proxy redirect never provisions).
app.UseMiddleware<SsoSessionMiddleware>();

app.UseAuthorization();
// TODO R5+: app.UseAntiforgery() with double-submit cookie.

// Health endpoints: liveness never checks dependencies (failing on
// transient outages causes restart
// storms). Readiness today only confirms Redis is reachable; the DB
// is on skein-api, not directly on us.
app.MapGet("/healthz", () => Results.Json(new { status = "ok" }))
   .AllowAnonymous();
app.MapGet("/ready", async (IConnectionMultiplexer redis) =>
{
    try
    {
        await redis.GetDatabase().PingAsync();
        return Results.Json(new { status = "ready" });
    }
    catch (Exception ex)
    {
        return Results.Json(
            new { status = "not ready", error = ex.Message },
            statusCode: StatusCodes.Status503ServiceUnavailable);
    }
}).AllowAnonymous();
app.MapMetrics();

// sk-9 — Native OIDC challenge endpoint. Same path the SPA already
// navigates to in the legacy trust-headers Keycloak mode ("/oauth2/start"
// was the oauth2-proxy challenge URL); in native OIDC mode skein-web
// owns this path itself so the front-end need not change. `rd` is the
// return-to URL (full origin) — we accept only same-origin paths under
// the request origin to block open-redirect attacks. Active only in
// KeycloakOidc mode; the legacy Keycloak mode still expects the path
// to be served by the oauth2-proxy reverse-proxy, so we 404 there to
// avoid intercepting traffic that wasn't meant for us.
app.MapGet("/oauth2/start", (HttpContext http, string? rd) =>
{
    if (!http.RequestServices.GetRequiredService<WebAuthMode>().IsKeycloakOidcMode)
    {
        return Results.NotFound();
    }

    // Whitelist same-origin, single-slash paths. `rd` can come from
    // anywhere on the URL — defence-in-depth against a redirect chain
    // that hops the user off-site after Keycloak.
    var returnPath = "/";
    if (!string.IsNullOrEmpty(rd))
    {
        if (Uri.TryCreate(rd, UriKind.Absolute, out var abs))
        {
            // Absolute URL accepted only if it matches the request origin
            // (host + scheme). Anything else collapses to "/".
            var origin = $"{http.Request.Scheme}://{http.Request.Host.Value}";
            if (string.Equals(abs.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
            {
                returnPath = abs.PathAndQuery.StartsWith('/') ? abs.PathAndQuery : "/";
            }
        }
        else if (rd.StartsWith('/') && !rd.StartsWith("//", StringComparison.Ordinal))
        {
            returnPath = rd;
        }
    }

    return Results.Challenge(
        new AuthenticationProperties { RedirectUri = returnPath },
        new[] { OpenIdConnectDefaults.AuthenticationScheme });
}).AllowAnonymous();

app.MapControllers();

// R3.2c — SignalR hub for live event streams. Authorisation is required
// (cookie principal). Mapped after MapControllers (so our /api/auth/*
// routes win) but before ApiProxyMiddleware (so the catch-all proxy does
// not swallow /hub negotiate / WebSocket upgrades).
app.MapHub<SkeinHub>("/hub").RequireAuthorization();

// Catch-all proxy for /api/v1/*; must run after MapControllers so our own
// /api/auth/* routes are not swallowed.
app.UseMiddleware<ApiProxyMiddleware>();

// NOTE: skein-web no longer serves the React SPA. The SPA lives in a
// separate skein-frontend image (nginx-unprivileged) which is the
// public entrypoint; it path-routes /api/*, /hub, /oauth2/* here and
// serves everything else as static. This image only carries auth
// controllers, the SignalR Hub, and the api-proxy middleware — any
// request that misses those produces a 404, by design.

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.Run();
return 0;

// -- Helpers ---------------------------------------------------------------

// Convert a redis:// URL into a StackExchange.Redis ConfigurationOptions.
// SE.Redis accepts host:port[,...] format; passing redis://host:port works
// only on very recent versions and is not portable. Doing the parse here
// keeps REDIS_URL identical across our Go (skein-api) and .NET (skein-web)
// services.
static ConfigurationOptions ParseRedisConfig(string redisUrl)
{
    if (redisUrl.StartsWith("redis://", StringComparison.OrdinalIgnoreCase))
    {
        var uri = new Uri(redisUrl);
        var opts = new ConfigurationOptions
        {
            EndPoints = { { uri.Host, uri.Port > 0 ? uri.Port : 6379 } },
            // AbortOnConnectFail=false lets the multiplexer retry rather
            // than throwing during startup if Redis is briefly unreachable.
            AbortOnConnectFail = false,
        };
        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            var parts = uri.UserInfo.Split(':', 2);
            if (parts.Length == 2)
            {
                opts.User = Uri.UnescapeDataString(parts[0]);
                opts.Password = Uri.UnescapeDataString(parts[1]);
            }
            else
            {
                opts.Password = Uri.UnescapeDataString(parts[0]);
            }
        }
        return opts;
    }
    // Fallback: assume the string is already in SE.Redis "host:port,opt=val" form.
    return ConfigurationOptions.Parse(redisUrl);
}
