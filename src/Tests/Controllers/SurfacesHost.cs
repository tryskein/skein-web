using System.Net;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using SkeinWeb.Auth;
using SkeinWeb.Hubs;
using SkeinWeb.Middleware;
using SkeinWeb.Tests.Auth;
using SkeinWeb.Tests.Hubs;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Controllers;

/// <summary>
/// skein-api stand-in with a small state model: two users, an epoch per user that a password reset
/// moves, the reset tokens it has spent, and a call counter per path. Every request is recorded.
/// A test can take over any answer with <see cref="Override"/>.
/// </summary>
internal sealed class SurfacesApi : HttpMessageHandler
{
    public static readonly Guid UserA = Guid.Parse("0199a1b2-0000-7000-8000-00000000000a");
    public static readonly Guid UserB = Guid.Parse("0199a1b2-0000-7000-8000-00000000000b");

    private readonly object _gate = new();
    private readonly List<string> _calls = [];

    /// <summary>The epoch of user A; a confirmed reset moves it by one.</summary>
    public long EpochA { get; set; } = 3;

    public HashSet<string> SpentTokens { get; } = [];

    /// <summary>First look at every request: a non-null answer replaces the model's.</summary>
    public Func<HttpRequestMessage, HttpResponseMessage?>? Override { get; set; }

    public IReadOnlyList<string> Calls
    {
        get { lock (_gate) { return [.. _calls]; } }
    }

    public int CallsTo(string path) => Calls.Count(c => c == path);

    public static string UserJson(Guid id, string email, long epoch, bool space = false) =>
        $"{{\"id\":\"{id}\",\"email\":\"{email}\",\"username\":\"{email.Split('@')[0]}\",\"name\":\"{email.Split('@')[0]}\"," +
        $"\"role\":\"user\",\"isExternal\":false,\"createdAt\":\"2026-10-12T18:13:03Z\",\"lastLoginAt\":null,\"sessionEpoch\":{epoch}" +
        (space ? ",\"space\":{\"id\":\"k3x9p2qa\",\"slug\":\"acme\",\"name\":\"Acme\"}" : "") + "}";

    private static HttpResponseMessage Json(string body, HttpStatusCode status = HttpStatusCode.OK) => new(status)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json"),
    };

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var path = request.RequestUri!.AbsolutePath;
        var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
        lock (_gate) { _calls.Add(path); }
        if (Override?.Invoke(request) is { } taken)
        {
            return taken;
        }
        var post = request.Method == HttpMethod.Post;
        if (path == "/ui/v1/auth/login" && post)
        {
            var doc = System.Text.Json.JsonDocument.Parse(body).RootElement;
            var email = doc.GetProperty("email").GetString()!;
            if (doc.GetProperty("password").GetString() != "pw")
            {
                return Json("{\"error\":\"invalid_credentials\"}", HttpStatusCode.UnprocessableEntity);
            }
            return email.StartsWith('b')
                ? Json(UserJson(UserB, "b@x.io", 3))
                : Json(UserJson(UserA, "a@x.io", EpochA));
        }
        if (path == "/ui/v1/auth/oidc/provision" && post)
        {
            var email = System.Text.Json.JsonDocument.Parse(body).RootElement.GetProperty("email").GetString()!;
            return email.StartsWith('b')
                ? Json(UserJson(UserB, "b@x.io", 3))
                : Json(UserJson(UserA, "a@x.io", EpochA));
        }
        if (path == "/ui/v1/auth/signup" && post)
        {
            return Json(UserJson(UserA, "a@x.io", 4));
        }
        if (post && path.StartsWith("/ui/v1/auth/invitations/", StringComparison.Ordinal) && path.EndsWith("/signup", StringComparison.Ordinal))
        {
            return Json(UserJson(UserA, "a@x.io", 4, space: true));
        }
        if (post && path.StartsWith("/ui/v1/auth/password-reset/", StringComparison.Ordinal))
        {
            var token = path["/ui/v1/auth/password-reset/".Length..];
            if (!SpentTokens.Add(token))
            {
                return Json("{\"error\":\"token_invalid\"}", HttpStatusCode.UnprocessableEntity);
            }
            EpochA++;
            return Json(UserJson(UserA, "a@x.io", EpochA));
        }
        if (path == "/ui/v1/projects")
        {
            // The authoritative revocation: a session of the account's former epoch is refused.
            var user = request.Headers.TryGetValues(SkeinHeaders.UserId, out var ids) ? ids.FirstOrDefault() : null;
            var epoch = request.Headers.TryGetValues(SkeinHeaders.SessionEpoch, out var eps) ? eps.FirstOrDefault() : null;
            if (user == UserA.ToString() && epoch != EpochA.ToString())
            {
                return Json("{\"error\":\"session_revoked\"}", HttpStatusCode.Unauthorized);
            }
            return Json("{\"ok\":true}");
        }
        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }
}

/// <summary>
/// The real login and account controllers and the <c>/api/v1</c> proxy on a loopback port, with the
/// real issuer, store (real Redis, database 14), cookie schemes and early refusal, a fault-injecting
/// database proxy and a hub endpoint over the real hub; the API is <see cref="SurfacesApi"/>.
/// The Development insecure-http mode is on, so the cookie is <c>skein.sid</c> and travels over http.
/// </summary>
internal sealed class SurfacesHost : IAsyncDisposable
{
    public const int Database = 14;
    private const string HandlerSessionIdClaim = "Microsoft.AspNetCore.Authentication.Cookies-SessionId";
    private static int _connection;

    private readonly WebApplication _app;
    private readonly HttpClient _client;

    private SurfacesHost(WebApplication app, HttpClient client, ConnectionMultiplexer mux, DbProxy faults,
        SurfacesApi api, HubTestReplica replica, SessionPipelineHost.ErrorLogs logs, TaskCompletionSource aborted,
        System.Collections.Concurrent.ConcurrentQueue<string> chain)
    {
        RequestAbortedSeen = aborted.Task;
        ChainConnections = chain;
        _app = app;
        _client = client;
        Mux = mux;
        Faults = faults;
        Api = api;
        Replica = replica;
        Logs = logs;
    }

    /// <summary>Completes when the server sees the client abort a request (RequestAborted fires).</summary>
    public Task RequestAbortedSeen { get; }

    /// <summary>Hub connections opened by <c>/test/chain</c> inside the request that then went to the proxy.</summary>
    public System.Collections.Concurrent.ConcurrentQueue<string> ChainConnections { get; }

    public ConnectionMultiplexer Mux { get; }
    public DbProxy Faults { get; }
    public SurfacesApi Api { get; }
    public HubTestReplica Replica { get; }
    public SessionPipelineHost.ErrorLogs Logs { get; }
    public IDatabase Db => Mux.GetDatabase(Database);
    public IServiceProvider Services => _app.Services;
    public string CookieName => "skein.sid";

    /// <param name="mode">Authentication mode; local by default.</param>
    /// <param name="sso">Settings for the mode (the OIDC client for the native mode).</param>
    /// <param name="configure">Extra registrations, after the standard ones.</param>
    /// <param name="trustHeaders">The legacy trust-headers mode with the SSO middleware in the pipeline.</param>
    /// <param name="time">The clock of the cookie schemes, the store and the issuer; the system clock when omitted.</param>
    /// <param name="timeouts">The session limits; the defaults of the settings when omitted.</param>
    public static async Task<SurfacesHost> StartAsync(
        WebAuthMode? mode = null, SsoOptions? sso = null, Action<IServiceCollection>? configure = null, bool trustHeaders = false,
        TimeProvider? time = null, SessionTimeouts? timeouts = null)
    {
        // The legacy trust-headers mode with passwords kept (hybrid), so the explicit operations work too.
        mode = trustHeaders ? new WebAuthMode(WebAuthKind.Keycloak, Hybrid: true) : mode;
        var mux = TestRedis.Connect(Database);
        mux.GetServers().First(s => !s.IsReplica).FlushDatabase(Database);
        var db = DbProxy.Create(mux.GetDatabase(Database), out var faults);
        var api = new SurfacesApi();
        var logs = new SessionPipelineHost.ErrorLogs();

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = Environments.Development });
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        builder.Logging.SetMinimumLevel(LogLevel.Trace);
        builder.Logging.AddProvider(logs);
        var services = builder.Services;

        services.AddSingleton(TestRedis.Over(mux, db));
        services.AddDataProtection();
        services.AddSingleton(new SessionCookiePolicy(AllowInsecureHttp: true));
        services.AddSingleton<RedisTicketStore>();
        services.AddSingleton<SessionIssuer>();
        services.AddSingleton<IUserSessionRevoker>(sp => sp.GetRequiredService<RedisTicketStore>());
        var replica = new HubTestReplica(new HubTestWorld(), new FakeTimeProvider(DateTimeOffset.UtcNow));
        services.AddSingleton(replica.Registry);
        services.AddSingleton(time ?? TimeProvider.System);
        services.AddSingleton(timeouts ?? new SessionTimeouts(SessionTimeouts.DefaultIdleTimeoutHours, SessionTimeouts.DefaultAbsoluteTimeoutHours));
        services.AddSkeinAuthentication(mode ?? WebAuthMode.FromApi("local", null), sso ?? new SsoOptions());
        configure?.Invoke(services);
        services.AddAuthorization();
        services.AddHttpContextAccessor();
        services.Configure<SsoOptions>(_ => { });
        services.Configure<SkeinApiOptions>(o =>
        {
            o.Url = "http://skein-api.test";
            o.InternalSecret = "svc-secret";
        });
        services.AddTransient<InternalApiHandler>();
        services.AddHttpClient<SkeinApiClient>(c => c.BaseAddress = new Uri("http://skein-api.test"))
            .AddHttpMessageHandler<InternalApiHandler>()
            .ConfigurePrimaryHttpMessageHandler(() => api);
        SkeinAccountsApiClient.Register(services, "http://skein-api.test/").ConfigurePrimaryHttpMessageHandler(() => api);
        ApiProxyMiddleware.AddProxyHttpClient(services, "http://skein-api.test/").ConfigurePrimaryHttpMessageHandler(() => api);
        services.AddSingleton<LoginRateLimiter>();
        services.AddSingleton<ActionRateLimiter>();
        services.AddTransient<ApiProxyMiddleware>();
        services.AddTransient<SessionStoreFailureMiddleware>();
        services.AddSingleton(TrustedProxyConfig.FromEntries(trustHeaders ? ["10.0.0.1"] : []));
        services.AddTransient<SsoSessionMiddleware>();
        services.AddControllers().AddApplicationPart(typeof(SkeinWeb.Controllers.AccountController).Assembly);
        services.AddProblemDetails();

        var app = builder.Build();
        var world = replica.World;
        var aborted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        app.Use(async (ctx, next) =>
        {
            ctx.RequestAborted.Register(() => aborted.TrySetResult());
            await next();
        });
        if (trustHeaders)
        {
            // The transport peer is whatever the test says; the trusted one by default.
            app.Use((ctx, next) =>
            {
                var peer = ctx.Request.Headers["X-Test-Peer"].FirstOrDefault() ?? "10.0.0.1";
                ctx.Features.Set(new EdgeSnapshot(IPAddress.Parse(peer), AmbiguousForwardedHost: false));
                return next();
            });
        }
        app.UseRouting();
        app.UseMiddleware<SessionStoreFailureMiddleware>();
        app.UseAuthentication();
        if (trustHeaders)
        {
            app.UseMiddleware<SsoSessionMiddleware>();
        }
        app.UseAuthorization();

        app.MapGet("/test/me", (HttpContext ctx) =>
            ctx.User.Identity?.IsAuthenticated == true
                ? Results.Json(new
                {
                    user = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier),
                    key = SessionPrincipal.SessionKeyOf(ctx.User),
                })
                : Results.Unauthorized());
        async Task<string> ConnectAsync(HttpContext ctx)
        {
            var user = Guid.Parse(ctx.User.FindFirstValue(ClaimTypes.NameIdentifier)!);
            world.AccessApi.SetUser(user);
            var id = $"surf-{Interlocked.Increment(ref _connection)}";
            world.AddConnection(id, user);
            var context = new Mock<HubCallerContext>();
            context.SetupGet(c => c.UserIdentifier).Returns(user.ToString());
            context.SetupGet(c => c.ConnectionId).Returns(id);
            context.SetupGet(c => c.User).Returns(ctx.User);
            context.SetupGet(c => c.ConnectionAborted).Returns(CancellationToken.None);
            context.Setup(c => c.Abort()).Callback(() =>
            {
                replica.Registry.Remove(id);
                replica.Limiter.Remove(id);
                world.RemoveConnection(id);
                lock (replica.Aborted)
                {
                    replica.Aborted.Add(id);
                }
            });
            var hub = new SkeinHub(replica.Access, replica.Registry, replica.Limiter, replica.Options, replica.Logger<SkeinHub>())
            {
                Context = context.Object,
                Groups = world.GroupManager,
            };
            await hub.OnConnectedAsync();
            return id;
        }

        app.MapGet("/test/hub", async (HttpContext ctx) =>
            ctx.User.Identity?.IsAuthenticated != true
                ? Results.Unauthorized()
                : Results.Json(new { connection = await ConnectAsync(ctx) }));
        if (mode?.IsKeycloakOidcMode == true)
        {
            // As Program.cs maps it.
            app.MapGet("/oauth2/start", (HttpContext http, string? rd) => Results.Challenge(
                new AuthenticationProperties { RedirectUri = OidcReturnPath.Resolve(rd, http.Request.Scheme, http.Request.Host.Value ?? string.Empty) },
                new[] { Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectDefaults.AuthenticationScheme }))
                .AllowAnonymous();
        }
        app.MapControllers();
        // One request: the connection is opened from the principal the SSO step left on THIS context, then the
        // same context is sent on to the real /api/v1 proxy.
        var chain = new System.Collections.Concurrent.ConcurrentQueue<string>();
        app.Use(async (ctx, next) =>
        {
            if (ctx.Request.Path == "/test/chain" && ctx.User.Identity?.IsAuthenticated == true)
            {
                chain.Enqueue(await ConnectAsync(ctx));
                ctx.Request.Path = "/api/v1/projects";
            }
            await next();
        });
        app.UseMiddleware<ApiProxyMiddleware>();

        await app.StartAsync();
        var client = new HttpClient(new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false })
        {
            BaseAddress = new Uri(app.Urls.First()),
        };
        return new SurfacesHost(app, client, mux, faults, api, replica, logs, aborted, chain);
    }

    public async Task<SessionPipelineHost.Reply> SendAsync(
        HttpMethod method, string path, object? body = null, string? cookie = null, params (string, string)[] headers)
    {
        using var request = new HttpRequestMessage(method, path);
        if (cookie is not null)
        {
            request.Headers.TryAddWithoutValidation("Cookie", cookie);
        }
        foreach (var (name, value) in headers)
        {
            request.Headers.TryAddWithoutValidation(name, value);
        }
        if (body is not null)
        {
            request.Content = new StringContent(System.Text.Json.JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        }
        using var response = await _client.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();
        var cookies = response.Headers.TryGetValues("Set-Cookie", out var values)
            ? values.Select(SessionPipelineHost.SetCookie.Parse).ToList()
            : [];
        return new SessionPipelineHost.Reply(response.StatusCode, text, cookies);
    }

    public Task<SessionPipelineHost.Reply> LoginAsync(string email, string password = "pw", string? cookie = null) =>
        SendAsync(HttpMethod.Post, "/api/auth/login", new { email, password }, cookie);

    /// <summary>Signs a user in by the login route with no cookie; returns the request cookie and the key.</summary>
    public async Task<(string Cookie, string Key)> SignInAsync(string email)
    {
        var reply = await LoginAsync(email);
        var set = reply.Sessions(CookieName).Single();
        return (set.AsRequestCookie(), KeyOf(set));
    }

    public string KeyOf(SessionPipelineHost.SetCookie cookie) =>
        Services.GetRequiredService<TicketDataFormat>().Unprotect(Uri.UnescapeDataString(cookie.Value))
            ?.Principal.FindFirst(HandlerSessionIdClaim)?.Value
        ?? throw new InvalidOperationException("the cookie carries no session key");

    public IReadOnlyList<string> IndexOf(Guid user) =>
        Db.SetMembers("skein:user-tickets:" + user).Select(m => (string)m!).ToList();

    public async ValueTask DisposeAsync()
    {
        _client.Dispose();
        await _app.StopAsync();
        await _app.DisposeAsync();
        Mux.GetServers().First(s => !s.IsReplica).FlushDatabase(Database);
        Mux.Dispose();
    }
}
