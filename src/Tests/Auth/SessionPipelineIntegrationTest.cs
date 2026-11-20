using System.Globalization;
using System.Net;
using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using Moq;
using SkeinWeb.Auth;
using SkeinWeb.Controllers;
using SkeinWeb.Hubs;
using SkeinWeb.Middleware;
using SkeinWeb.Tests.Hubs;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// The stand of the session tests: Kestrel on a loopback port with the order of Program.cs (edge,
/// routing, early refusal, authentication), the real cookie schemes, the real store on a real Redis
/// (database 9, serialised by the collection), a fault-injecting database proxy, and test endpoints
/// that call the issuer and the revocation on the request context. A hub endpoint registers a
/// connection through the real <see cref="SkeinHub"/> from <c>context.User</c> of the same request.
/// The session limits are a parameter (the defaults when not given); the cookie schemes and the
/// issuer read the clock of the stand (<see cref="Time"/>). <c>/test/issue</c> takes the
/// persistence and the window of the incoming properties, <c>/test/renew</c> is an explicit
/// renewal of the request's session through Main, and <c>/test/hold</c> is a protected endpoint
/// that, once authenticated, waits for the test (<see cref="Hold"/>).
/// </summary>
internal sealed class SessionPipelineHost : IAsyncDisposable
{
    public const int Database = 9;
    private static int _connection;

    private readonly WebApplication _app;
    private readonly HttpClient _client;

    public ConnectionMultiplexer Mux { get; }
    public DbProxy Faults { get; }
    public RedisTicketStore Store { get; }
    public SessionCookiePolicy Policy { get; }
    public FakeTimeProvider Time { get; }
    public HubTestWorld World { get; } = new();
    public HubTestReplica Replica { get; }
    public SessionTimeouts Timeouts { get; }
    public HoldGate Hold { get; }
    public ErrorLogs Logs { get; }
    public FormatterLogs Formatted { get; }
    public IServiceProvider Services => _app.Services;
    public string CookieName => Policy.CookieName;
    public string OtherName => Policy.AllowInsecureHttp ? "__Host-skein.sid" : "skein.sid";

    /// <summary>
    /// The gate of <c>/test/hold</c>: the request signals <see cref="Reached"/> once it is
    /// authenticated and then waits until the test calls <see cref="Release"/>. One use per host.
    /// </summary>
    public sealed class HoldGate
    {
        private readonly TaskCompletionSource _reached = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);

        /// <summary>Completes when a held request has been authenticated.</summary>
        public Task Reached => _reached.Task;

        /// <summary>Lets the held request finish.</summary>
        public void Release() => _release.TrySetResult();

        internal async Task WaitAsync(CancellationToken ct)
        {
            _reached.TrySetResult();
            await _release.Task.WaitAsync(TimeSpan.FromSeconds(30), ct);
        }
    }

    /// <summary>Everything logged at any level, as text (for the redaction checks).</summary>
    public sealed class ErrorLogs : ILoggerProvider
    {
        public List<(LogLevel Level, string Category, string Text)> Entries { get; } = [];

        public ILogger CreateLogger(string categoryName) => new Capture(this, categoryName);

        public void Dispose()
        {
        }

        private sealed class Capture(ErrorLogs owner, string category) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                lock (owner.Entries)
                {
                    owner.Entries.Add((logLevel, category, formatter(state, exception) + (exception is null ? "" : " " + exception)));
                }
            }
        }
    }

    private SessionPipelineHost(WebApplication app, HttpClient client, ConnectionMultiplexer mux, DbProxy faults,
        RedisTicketStore store, SessionCookiePolicy policy, FakeTimeProvider time, HubTestReplica replica, SessionTimeouts timeouts,
        HoldGate hold, ErrorLogs logs, FormatterLogs formatted)
    {
        Hold = hold;
        _app = app;
        _client = client;
        Mux = mux;
        Faults = faults;
        Store = store;
        Policy = policy;
        Time = time;
        Replica = replica;
        Timeouts = timeouts;
        Logs = logs;
        Formatted = formatted;
    }

    /// <param name="insecureHttp">The Development insecure-http mode.</param>
    /// <param name="apiAuthMode">skein-api <c>authMode</c>; the trust-headers mode is <c>keycloak</c>.</param>
    /// <param name="trustLoopback">Whether the loopback peer is a trusted proxy.</param>
    /// <param name="timeouts">The session limits; the defaults when not given.</param>
    public static async Task<SessionPipelineHost> StartAsync(
        bool insecureHttp = false, string apiAuthMode = "local", bool trustLoopback = false, SessionTimeouts? timeouts = null)
    {
        timeouts ??= new SessionTimeouts(SessionTimeouts.DefaultIdleTimeoutHours, SessionTimeouts.DefaultAbsoluteTimeoutHours);
        var mux = TestRedis.Connect(Database);
        mux.GetServers().First(s => !s.IsReplica).FlushDatabase(Database);
        var db = DbProxy.Create(mux.GetDatabase(Database), out var faults);
        var fakeMux = TestRedis.Over(mux, db);
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var logs = new ErrorLogs();
        var policy = new SessionCookiePolicy(insecureHttp);

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = Environments.Development });
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        builder.Logging.SetMinimumLevel(LogLevel.Trace);
        builder.Logging.AddProvider(logs);
        var formatted = new FormatterLogs();
        builder.Logging.AddProvider(formatted);

        var services = builder.Services;
        services.AddSingleton(fakeMux);
        services.AddSingleton<TimeProvider>(time);
        services.AddSingleton(policy);
        services.AddSingleton<RedisTicketStore>();
        var replica = new HubTestReplica(new HubTestWorld(), time);
        services.AddSingleton(replica.Registry);
        services.AddSingleton<SessionIssuer>();
        services.AddDataProtection();
        var proxies = TrustedProxyConfig.FromEntries(trustLoopback ? ["127.0.0.1", "::1"] : []);
        services.AddSkeinEdge(proxies, AllowedHostsConfig.Parse(""));
        services.AddSingleton(timeouts);
        var hold = new HoldGate();
        services.AddSingleton(hold);
        services.AddSkeinAuthentication(WebAuthMode.FromApi(apiAuthMode, oidcAuthority: null), new SsoOptions());
        services.AddSingleton(proxies);
        services.AddTransient<SessionStoreFailureMiddleware>();
        var app = builder.Build();
        var world = replica.World;

        app.UseSkeinEdge();
        app.UseRouting();
        app.UseMiddleware<SessionStoreFailureMiddleware>();
        app.UseAuthentication();

        static IEndpointConventionBuilder Explicit(IEndpointConventionBuilder b, Type controller, string method) =>
            b.WithMetadata(controller.GetMethod(method)!.GetCustomAttribute<ExplicitSignInAttribute>()
                ?? throw new InvalidOperationException(method + " carries no ExplicitSignIn marker"));

        ClaimsPrincipal PrincipalOf(Guid user, string role = "user") => new(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, user.ToString()), new Claim(ClaimTypes.Role, role), new Claim(ClaimTypes.Email, "alice@example.com")], "test"));

        // ---- issue, renew, end, revoke ---------------------------------------------------------
        // The incoming properties: persistence and a window (Unix seconds) the caller hands the issuer.
        app.MapGet("/test/issue", async (HttpContext ctx, SessionIssuer issuer, Guid user, bool? persistent, long? issuedUnix, long? expiresUnix) =>
        {
            var properties = new AuthenticationProperties
            {
                IsPersistent = persistent == true,
                IssuedUtc = issuedUnix is { } i ? DateTimeOffset.FromUnixTimeSeconds(i) : null,
                ExpiresUtc = expiresUnix is { } e ? DateTimeOffset.FromUnixTimeSeconds(e) : null,
            };
            var issued = await issuer.RotateAsync(ctx, PrincipalOf(user), properties, "Test");
            return Results.Json(new { key = issued.Key, hadPreviousKey = issued.HadPreviousKey });
        });
        // An explicit renewal of the request's session through Main, as the SSO renewal does it: the
        // properties are the ones Main read for this request.
        app.MapGet("/test/renew", async (HttpContext ctx) =>
        {
            var read = await ctx.AuthenticateAsync(SessionSchemes.Main);
            if (!read.Succeeded)
            {
                return Results.Unauthorized();
            }
            await ctx.SignInAsync(
                SessionSchemes.Main,
                PrincipalOf(Guid.Parse(read.Principal!.FindFirstValue(ClaimTypes.NameIdentifier)!)),
                read.Properties!.Clone());
            return Results.Json(new { outcome = SessionRequestState.Of(ctx).RenewOutcome?.ToString() });
        });
        app.MapGet("/test/issue-then-hub", async (HttpContext ctx, SessionIssuer issuer, Guid user) =>
        {
            await issuer.RotateAsync(ctx, PrincipalOf(user), new AuthenticationProperties(), "Test");
            var connection = await ConnectAsync(ctx.User);
            return Results.Json(new { key = SessionPrincipal.SessionKeyOf(ctx.User), connection });
        });
        app.MapGet("/test/revoke-then-issue", async (HttpContext ctx, SessionIssuer issuer, Guid user) =>
        {
            // The two steps the password-reset sequence calls on their own.
            issuer.MarkSessionWriteSuppressed(ctx);
            await issuer.RevokeIncomingAsync(ctx);
            await issuer.IssueAsync(ctx, PrincipalOf(user), new AuthenticationProperties(), "Reset");
            return Results.Ok();
        });
        app.MapGet("/test/issue-twice", async (HttpContext ctx, SessionIssuer issuer, Guid user) =>
        {
            await issuer.RotateAsync(ctx, PrincipalOf(user), new AuthenticationProperties(), "Test");
            await issuer.RotateAsync(ctx, PrincipalOf(user), new AuthenticationProperties(), "Test");
            return Results.Ok();
        });
        app.MapGet("/test/end-current", async (HttpContext ctx, SessionIssuer issuer) =>
        {
            await issuer.EndCurrentAsync(ctx);
            return Results.Json(new { authenticated = ctx.User.Identity?.IsAuthenticated == true });
        });
        app.MapGet("/test/end-session", async (HttpContext ctx) =>
        {
            await SessionRevocation.EndSessionAsync(ctx);
            return Results.Ok();
        });
        app.MapGet("/test/issue-then-end-session", async (HttpContext ctx, SessionIssuer issuer, Guid user) =>
        {
            await issuer.RotateAsync(ctx, PrincipalOf(user), new AuthenticationProperties(), "Test");
            var connection = await ConnectAsync(ctx.User);
            await SessionRevocation.EndSessionAsync(ctx);
            return Results.Json(new { key = SessionPrincipal.SessionKeyOf(ctx.User), connection });
        });
        app.MapGet("/test/logout", async (HttpContext ctx) =>
        {
            await SessionRevocation.EndSessionAsync(ctx);
            return Results.Ok();
        });

        // ---- the protected endpoint and the hub ----------------------------------------------
        app.MapGet("/test/me", (HttpContext ctx) =>
            ctx.User.Identity?.IsAuthenticated == true
                ? Results.Json(new
                {
                    user = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier),
                    key = SessionPrincipal.SessionKeyOf(ctx.User),
                })
                : Results.Unauthorized());
        app.MapGet("/test/hub", async (HttpContext ctx) =>
            ctx.User.Identity?.IsAuthenticated == true
                ? Results.Json(new { connection = await ConnectAsync(ctx.User) })
                : Results.Unauthorized());
        app.MapGet("/test/hold", async (HttpContext ctx, SessionPipelineHost.HoldGate gate) =>
        {
            if (ctx.User.Identity?.IsAuthenticated != true)
            {
                return Results.Unauthorized();
            }
            await gate.WaitAsync(ctx.RequestAborted);
            return Results.Json(new { user = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier) });
        });

        // ---- the four explicit operations, with the metadata of the real controllers ----------
        Explicit(app.MapPost("/api/auth/login", () => Results.Ok()), typeof(AuthController), nameof(AuthController.Login));
        Explicit(app.MapPost("/api/auth/signup", () => Results.Ok()), typeof(AccountController), nameof(AccountController.Signup));
        Explicit(app.MapPost("/api/auth/invitations/{token}/signup", () => Results.Ok()), typeof(AccountController), nameof(AccountController.InvitationSignup));
        Explicit(app.MapPost("/api/auth/password-reset/{token}", () => Results.Ok()), typeof(AccountController), nameof(AccountController.PasswordResetComplete));
        app.MapGet("/api/auth/other", (HttpContext ctx) => Results.Ok());

        async Task<string> ConnectAsync(ClaimsPrincipal principal)
        {
            var user = Guid.Parse(principal.FindFirstValue(ClaimTypes.NameIdentifier)!);
            world.AccessApi.SetUser(user);
            var id = $"pipe-{Interlocked.Increment(ref _connection)}";
            world.AddConnection(id, user);
            var context = new Mock<HubCallerContext>();
            context.SetupGet(c => c.UserIdentifier).Returns(user.ToString());
            context.SetupGet(c => c.ConnectionId).Returns(id);
            context.SetupGet(c => c.User).Returns(principal);
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

        await app.StartAsync();
        var client = new HttpClient(new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false })
        {
            BaseAddress = new Uri(app.Urls.First()),
        };
        var store = app.Services.GetRequiredService<RedisTicketStore>();
        return new SessionPipelineHost(app, client, mux, faults, store, policy, time, replica, timeouts, hold, logs, formatted);
    }

    // ---- client ----------------------------------------------------------------------------------

    public sealed record SetCookie(string Name, string Value, string Raw)
    {
        public bool IsDeletion => IsDeletionHeader(Raw);

        /// <summary>
        /// A deletion: an <c>expires</c> attribute at or before the Unix epoch, as
        /// <c>Response.Cookies.Delete</c> writes it. Only the attributes are read: the value of a live
        /// cookie is random and may carry any digits, "1970" included.
        /// </summary>
        public static bool IsDeletionHeader(string raw) =>
            raw.Split(';').Skip(1).Select(a => a.Trim()).Any(a =>
                a.StartsWith("expires=", StringComparison.OrdinalIgnoreCase)
                && DateTimeOffset.TryParse(a["expires=".Length..], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var at)
                && at <= DateTimeOffset.UnixEpoch);

        public static SetCookie Parse(string raw)
        {
            var pair = raw.Split(';', 2)[0];
            var eq = pair.IndexOf('=');
            return new SetCookie(pair[..eq], pair[(eq + 1)..], raw);
        }

        public string AsRequestCookie(string? asName = null) => $"{asName ?? Name}={Value}";
    }

    public sealed record Reply(HttpStatusCode Status, string Body, IReadOnlyList<SetCookie> Cookies)
    {
        public IReadOnlyList<SetCookie> Sessions(string name) => Cookies.Where(c => c.Name == name && !c.IsDeletion).ToList();

        /// <summary>
        /// Every Set-Cookie of a session cookie, deletions included, under the name of either mode
        /// and any chunk of it.
        /// </summary>
        public IReadOnlyList<SetCookie> SessionWrites() => Cookies
            .Where(c => c.Name.StartsWith(SessionCookiePolicy.SecureCookieName, StringComparison.Ordinal)
                || c.Name.StartsWith(SessionCookiePolicy.InsecureCookieName, StringComparison.Ordinal))
            .ToList();
    }

    public async Task<Reply> SendAsync(string path, string? cookie = null, HttpMethod? method = null,
        params (string Name, string Value)[] headers)
    {
        using var request = new HttpRequestMessage(method ?? HttpMethod.Get, path);
        if (cookie is not null)
        {
            request.Headers.TryAddWithoutValidation("Cookie", cookie);
        }
        foreach (var (name, value) in headers)
        {
            request.Headers.TryAddWithoutValidation(name, value);
        }
        using var response = await _client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        var cookies = response.Headers.TryGetValues("Set-Cookie", out var values)
            ? values.Select(SetCookie.Parse).ToList()
            : [];
        return new Reply(response.StatusCode, body, cookies);
    }

    /// <summary>Signs <paramref name="user"/> in through the issuer without a cookie; returns the request cookie and the key.</summary>
    public async Task<(string Cookie, string Key, SetCookie Set)> SignInAsync(Guid user)
    {
        var reply = await SendAsync($"/test/issue?user={user}");
        var set = reply.Sessions(CookieName).Single();
        var key = System.Text.Json.JsonDocument.Parse(reply.Body).RootElement.GetProperty("key").GetString()!;
        return (set.AsRequestCookie(), key, set);
    }

    public IDatabase Db => Mux.GetDatabase(Database);

    public async ValueTask DisposeAsync()
    {
        _client.Dispose();
        await _app.StopAsync();
        await _app.DisposeAsync();
        Mux.GetServers().First(s => !s.IsReplica).FlushDatabase(Database);
        Mux.Dispose();
    }
}

/// <summary>Cookie attributes and identity choice on the real pipeline (US-4, US-5, US-1 incoming session).</summary>
[Trait("Category", "Integration")]
[Collection("session-pipeline")]
public sealed class SessionPipelineIntegrationTest
{
    private static readonly Guid Alice = Guid.Parse("0199a1b2-0000-7000-8000-00000000000a");
    private static readonly Guid Bob = Guid.Parse("0199a1b2-0000-7000-8000-00000000000b");

    private static void AssertAttributes(SessionPipelineHost host, SessionPipelineHost.SetCookie set)
    {
        var raw = set.Raw.ToLowerInvariant();
        Assert.Equal(host.CookieName, set.Name);
        Assert.Contains("httponly", raw);
        Assert.Equal("/", AttributeOf(set, "path"));
        Assert.Contains("samesite=lax", raw);
        Assert.DoesNotContain("domain=", raw);
        if (host.Policy.AllowInsecureHttp)
        {
            Assert.DoesNotContain("secure", raw.Replace("samesite", ""));
        }
        else
        {
            Assert.Contains("secure", raw);
        }
    }

    // R16: both write paths, the mode × X-Forwarded-Proto × trusted peer matrix.
    [RedisTheory]
    [InlineData(false, null, false)]
    [InlineData(false, "http", false)]
    [InlineData(false, "https", false)]
    [InlineData(false, null, true)]
    [InlineData(false, "http", true)]
    [InlineData(false, "https", true)]
    [InlineData(true, null, false)]
    [InlineData(true, "http", false)]
    [InlineData(true, "https", false)]
    [InlineData(true, null, true)]
    [InlineData(true, "http", true)]
    [InlineData(true, "https", true)]
    public async Task SetCookie_OfBothWritePaths_HasTheAttributesOfTheMode_WhateverTheSchemeOrTheProxy(
        bool insecureHttp, string? forwardedProto, bool trustedPeer)
    {
        await using var host = await SessionPipelineHost.StartAsync(insecureHttp, trustLoopback: trustedPeer);
        var headers = forwardedProto is null ? [] : new[] { ("X-Forwarded-Proto", forwardedProto) };

        // Issue path.
        var issue = await host.SendAsync($"/test/issue?user={Alice}", null, null, headers);
        var issued = Assert.Single(issue.Sessions(host.CookieName));
        AssertAttributes(host, issued);

        // Main path: an explicit renewal of the same key, the one remaining ticket write of Main.
        var main = await host.SendAsync("/test/renew", issued.AsRequestCookie(), null, headers);
        Assert.Equal(HttpStatusCode.OK, main.Status); // control: the host accepts its own cookie
        AssertAttributes(host, Assert.Single(main.Sessions(host.CookieName)));
    }

    // D-1: no request without a sign-in writes the ticket or sets a session cookie, past half of the
    // window and just before its end (absolute limit 11 h, shifts counted from the issued ticket).
    [RedisFact]
    public async Task AnOrdinaryRequest_NeverRenewsTheSession_PastHalfOfTheWindowOrJustBeforeItsEnd()
    {
        await using var host = await SessionPipelineHost.StartAsync(timeouts: new SessionTimeouts(120, 11));
        // Control on the same stand: the issue writes the row and sets the cookie.
        var (cookie, key, _) = await host.SignInAsync(Alice);
        byte[]? written = await host.Db.StringGetAsync(key);
        Assert.NotNull(written);
        var ticket = await host.Store.RetrieveAsync(key, new DefaultHttpContext(), CancellationToken.None);
        var issuedAt = ticket!.Properties.IssuedUtc!.Value;
        Assert.Equal(issuedAt.AddHours(11), ticket.Properties.ExpiresUtc);

        foreach (var shift in new[] { TimeSpan.FromHours(6), TimeSpan.FromHours(10) + TimeSpan.FromMinutes(59) })
        {
            host.Time.SetUtcNow(issuedAt + shift);

            var reply = await host.SendAsync("/test/me", cookie);

            Assert.Equal(HttpStatusCode.OK, reply.Status);
            Assert.Empty(reply.SessionWrites());
            Assert.Equal(written, (byte[]?)await host.Db.StringGetAsync(key));
        }
    }

    public static TheoryData<string, bool, long?, long?> IncomingWindows()
    {
        // Relative to the stand's clock at the issue, in seconds: in the past, in the future, longer
        // than the limit, and none.
        var data = new TheoryData<string, bool, long?, long?>();
        foreach (var persistent in new[] { true, false })
        {
            data.Add("in the past", persistent, -10 * 86_400, -9 * 86_400);
            data.Add("in the future", persistent, 3_600, 7_200);
            data.Add("longer than the limit", persistent, -60, 400 * 86_400);
            data.Add("none", persistent, null, null);
        }
        return data;
    }

    // INV-7, INV-6, E-9: the issuer replaces whatever window the incoming properties carry and keeps
    // their persistence.
    [RedisTheory]
    [MemberData(nameof(IncomingWindows))]
    public async Task AnIssue_StartsTheWindowOfItsOwnMoment_WhateverTheIncomingProperties_AndKeepsThePersistence(
        string _, bool persistent, long? issuedOffset, long? expiresOffset)
    {
        await using var host = await SessionPipelineHost.StartAsync(timeouts: new SessionTimeouts(120, 11));
        host.Time.Advance(TimeSpan.FromMinutes(42));
        var now = host.Time.GetUtcNow();
        var query = $"/test/issue?user={Alice}&persistent={persistent.ToString().ToLowerInvariant()}";
        if (issuedOffset is { } i && expiresOffset is { } e)
        {
            query += $"&issuedUnix={now.ToUnixTimeSeconds() + i}&expiresUnix={now.ToUnixTimeSeconds() + e}";
        }

        var reply = await host.SendAsync(query);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        var set = Assert.Single(reply.Sessions(host.CookieName));
        var key = System.Text.Json.JsonDocument.Parse(reply.Body).RootElement.GetProperty("key").GetString()!;
        var ticket = await host.Store.RetrieveAsync(key, new DefaultHttpContext(), CancellationToken.None);
        // The window of the row: [now of the stand, + 11 h]; the ticket keeps times to the second.
        Assert.Equal(now.ToUnixTimeSeconds(), ticket!.Properties.IssuedUtc!.Value.ToUnixTimeSeconds());
        Assert.Equal(now.AddHours(11).ToUnixTimeSeconds(), ticket.Properties.ExpiresUtc!.Value.ToUnixTimeSeconds());
        Assert.Equal(persistent, ticket.Properties.IsPersistent);
        var expires = ExpiresOf(set);
        if (persistent)
        {
            Assert.Equal(ticket.Properties.ExpiresUtc!.Value.ToUnixTimeSeconds(), expires!.Value.ToUnixTimeSeconds());
        }
        else
        {
            Assert.Null(expires);
            Assert.Null(AttributeOf(set, "max-age"));
        }
    }

    /// <summary>The <c>expires</c> attribute of a Set-Cookie, or null when it has none.</summary>
    internal static DateTimeOffset? ExpiresOf(SessionPipelineHost.SetCookie set) =>
        AttributeOf(set, "expires") is { } value
            ? DateTimeOffset.Parse(value, System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal)
            : null;

    /// <summary>
    /// The value of the attribute <paramref name="name"/> of a Set-Cookie (names compared without
    /// regard to case), an empty string for a flag attribute, or null when the cookie has none.
    /// </summary>
    internal static string? AttributeOf(SessionPipelineHost.SetCookie set, string name)
    {
        foreach (var part in set.Raw.Split(';').Skip(1))
        {
            var attribute = part.Trim();
            var eq = attribute.IndexOf('=');
            var attributeName = eq < 0 ? attribute : attribute[..eq].TrimEnd();
            if (string.Equals(attributeName, name, StringComparison.OrdinalIgnoreCase))
            {
                return eq < 0 ? "" : attribute[(eq + 1)..].Trim();
            }
        }
        return null;
    }

    [RedisFact]
    public async Task Control_AnInjectedRedisFailureIsExecuted_ByTheHost()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, _, _) = await host.SignInAsync(Alice);
        host.Faults.Before = (name, _) => name == nameof(IDatabase.StringGetAsync) ? new InvalidOperationException("injected") : null;

        var reply = await host.SendAsync("/test/me", cookie);

        Assert.Equal(HttpStatusCode.BadGateway, reply.Status);
    }

    // R71: the identity comes from the cookie of the mode, in both modes.
    [RedisTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Identity_IsTheOneOfTheCookieOfTheMode_WhenBothNamesArePresent(bool insecureHttp)
    {
        await using var host = await SessionPipelineHost.StartAsync(insecureHttp);
        var (aliceCookie, _, _) = await host.SignInAsync(Alice);
        var (_, _, bobSet) = await host.SignInAsync(Bob);
        var bobUnderOtherName = bobSet.AsRequestCookie(host.OtherName);

        var both = await host.SendAsync("/test/me", $"{bobUnderOtherName}; {aliceCookie}");
        var onlyOther = await host.SendAsync("/test/me", bobUnderOtherName);
        var onlyMode = await host.SendAsync("/test/me", aliceCookie);

        Assert.Equal(HttpStatusCode.OK, both.Status);
        Assert.Contains(Alice.ToString(), both.Body);
        Assert.Equal(HttpStatusCode.Unauthorized, onlyOther.Status);
        Assert.Equal(HttpStatusCode.OK, onlyMode.Status); // control: A under the mode name alone works
    }
}
