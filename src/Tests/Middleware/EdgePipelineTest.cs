using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Moq;
using SkeinWeb.Auth;
using SkeinWeb.Hubs;
using SkeinWeb.Middleware;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Middleware;

/// <summary>
/// The edge of skein-web assembled as in <c>Program.cs</c>, with the product's
/// own registrations: <see cref="SkeinEdgePipeline.UseSkeinEdge"/> (transport
/// peer snapshot → forwarded headers → host check), then authentication, then
/// <see cref="SsoSessionMiddleware"/> in the legacy trust-headers mode on both
/// of its arms (keycloak and hybrid without an OIDC authority). skein-api is a
/// recorder behind the transport of <see cref="SkeinApiClient"/>, which carries
/// <see cref="InternalApiHandler"/> as in <c>Program.cs</c>; Redis is an
/// in-memory cache with a mocked multiplexer.
/// </summary>
/// <remarks>
/// <para>Each request is a <see cref="DefaultHttpContext"/> with a chosen
/// <c>Connection.RemoteIpAddress</c> — the transport peer — sent through the
/// <see cref="RequestDelegate"/> built from the <see cref="WebApplication"/>, so
/// any peer address can be used. Trust headers count only from a trusted
/// transport peer: never by <c>X-Forwarded-For</c> or <c>X-Original-For</c>,
/// the same for an IPv4 address and its mapped IPv6 form, and from no one with
/// an empty <c>SKEIN_TRUSTED_PROXIES</c>. The visitor address from a trusted
/// peer's <c>X-Forwarded-For</c> still reaches the rest of the pipeline and
/// skein-api. With <c>SKEIN_ALLOWED_HOSTS</c> set, the actual host is checked
/// before anything else, an ambiguous <c>X-Forwarded-Host</c> of a trusted peer
/// included.</para>
/// <para>An "expired session" is a principal put in <c>HttpContext.User</c>
/// before the request: the refresh interval runs on the wall clock, and
/// authentication without a cookie leaves that principal in place.</para>
/// </remarks>
public sealed class EdgePipelineTest
{
    private const string VisitorEmail = "visitor.person@example.com";
    private const string VisitorUsername = "visitor-handle";
    private const string ProvisionPath = "/ui/v1/auth/oidc/provision";
    private const string SessionUserId = "0199a1b2-0000-7000-8000-000000000001";

    /// <summary>The two arms of the legacy trust-headers mode.</summary>
    public static TheoryData<string> LegacyModes => new() { "keycloak", "hybrid" };

    /// <summary>skein-api stand-in: answers provision with a fixed session epoch and records every request.</summary>
    private sealed class RecordingApi(long sessionEpoch) : HttpMessageHandler
    {
        public ConcurrentQueue<HttpRequestMessage> Requests { get; } = new();

        public HttpRequestMessage[] Provisions =>
            Requests.Where(r => r.RequestUri!.AbsolutePath == ProvisionPath).ToArray();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Enqueue(request);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    "{\"id\":\"" + SessionUserId + "\",\"email\":\"" + VisitorEmail + "\"," +
                    "\"username\":\"" + VisitorUsername + "\",\"name\":\"" + VisitorUsername + "\"," +
                    "\"role\":\"user\",\"isExternal\":false,\"sessionEpoch\":" + sessionEpoch + "}",
                    Encoding.UTF8, "application/json"),
            });
        }
    }

    /// <summary>Records every log entry: category, level, message and structured values.</summary>
    private sealed class CapturingLogs : ILoggerProvider
    {
        public ConcurrentQueue<(string Category, LogLevel Level, string Text)> Entries { get; } = new();

        public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);

        public void Dispose() { }

        private sealed class Logger(CapturingLogs owner, string category) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                var values = state is IEnumerable<KeyValuePair<string, object?>> kv
                    ? string.Join(";", kv.Select(p => $"{p.Key}={p.Value}"))
                    : "";
                owner.Entries.Enqueue((category, logLevel, formatter(state, exception) + " | " + values));
            }
        }
    }

    /// <summary>What the request looked like when it left the pipeline.</summary>
    private sealed record Outcome(
        int Status,
        string? Error,
        bool Reached,
        ClaimsPrincipal? User,
        IPAddress? RemoteIp,
        bool SetCookie,
        HttpRequestMessage[] Provisions);

    /// <summary>One assembled pipeline: product registrations, edge, authentication, trust-header bootstrap.</summary>
    private sealed class World
    {
        private readonly WebApplication _app;
        private readonly RequestDelegate _pipeline;
        private ClaimsPrincipal? _seenUser;
        private IPAddress? _seenRemoteIp;
        private bool _reached;

        public RecordingApi Api { get; }
        public CapturingLogs Logs { get; } = new();

        /// <param name="apiAuthMode">skein-api <c>authMode</c>; no OIDC authority (legacy trust headers).</param>
        /// <param name="trustedProxies">Entries of <c>SKEIN_TRUSTED_PROXIES</c>.</param>
        /// <param name="allowedHosts">Raw <c>SKEIN_ALLOWED_HOSTS</c>.</param>
        /// <param name="apiEpoch">Session epoch the skein-api stand-in answers with.</param>
        /// <param name="likeTheHost">Build the pipeline the way the web host does when
        /// it starts: the application's links wrapped by every registered
        /// <see cref="IStartupFilter"/>, the default host's included.</param>
        /// <param name="forwardedHeadersFlag">Run with <c>ForwardedHeaders_Enabled=true</c>
        /// (what <c>ASPNETCORE_FORWARDEDHEADERS_ENABLED=true</c> sets).</param>
        public World(
            string apiAuthMode, string[] trustedProxies, string allowedHosts = "", long apiEpoch = 3,
            bool likeTheHost = false, bool forwardedHeadersFlag = false)
        {
            Api = new RecordingApi(apiEpoch);
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                EnvironmentName = "Testing",
                Args = forwardedHeadersFlag ? ["--ForwardedHeaders_Enabled=true"] : [],
            });
            builder.Logging.ClearProviders();
            builder.Logging.SetMinimumLevel(LogLevel.Trace);
            builder.Logging.AddProvider(Logs);
            var services = builder.Services;

            var mux = new Mock<IConnectionMultiplexer>();
            mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(new Mock<IDatabase>().Object);
            services.AddSingleton(mux.Object);
            services.AddDistributedMemoryCache();
            services.AddSingleton(TimeProvider.System);
            services.AddSingleton<ConnectionRegistry>();
            services.AddSingleton<RedisTicketStore>();

            var proxies = TrustedProxyConfig.FromEntries(trustedProxies);
            services.AddSkeinEdge(proxies, AllowedHostsConfig.Parse(allowedHosts));
            services.AddSkeinAuthentication(WebAuthMode.FromApi(apiAuthMode, oidcAuthority: null), new SsoOptions());
            services.AddHttpContextAccessor();
            services.Configure<SkeinApiOptions>(o =>
            {
                o.Url = "http://skein-api.test";
                o.InternalSecret = "svc-secret";
                o.ClientIpTrusted = proxies.PerIpThrottleEnabled;
            });
            services.AddTransient<InternalApiHandler>();
            services.AddHttpClient<SkeinApiClient>(c => c.BaseAddress = new Uri("http://skein-api.test"))
                .AddHttpMessageHandler<InternalApiHandler>()
                .ConfigurePrimaryHttpMessageHandler(() => Api);
            services.AddTransient<SsoSessionMiddleware>();

            _app = builder.Build();
            if (!likeTheHost)
            {
                Configure(_app);
                _pipeline = ((IApplicationBuilder)_app).Build();
                return;
            }

            // As the web host composes it on start: the startup filters wrap the
            // application's configuration, the last registered innermost.
            Action<IApplicationBuilder> configure = Configure;
            foreach (var filter in _app.Services.GetServices<IStartupFilter>().Reverse())
            {
                configure = filter.Configure(configure);
            }
            var hostBuilder = new ApplicationBuilder(_app.Services);
            configure(hostBuilder);
            _pipeline = hostBuilder.Build();
        }

        private void Configure(IApplicationBuilder app)
        {
            app.UseSkeinEdge();
            app.UseAuthentication();
            app.UseMiddleware<SsoSessionMiddleware>();
            app.Run(ctx =>
            {
                _reached = true;
                _seenUser = ctx.User;
                _seenRemoteIp = ctx.Connection.RemoteIpAddress;
                return Task.CompletedTask;
            });
        }

        public async Task<Outcome> Send(string peer, Action<HttpContext> arrange)
        {
            await using var scope = _app.Services.CreateAsyncScope();
            var ctx = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
            _app.Services.GetRequiredService<IHttpContextAccessor>().HttpContext = ctx;
            ctx.Connection.RemoteIpAddress = IPAddress.Parse(peer);
            ctx.Request.Method = HttpMethods.Get;
            ctx.Request.Scheme = "https";
            ctx.Request.Protocol = "HTTP/1.1";
            ctx.Request.Path = "/api/auth/me";
            ctx.Request.Host = new HostString("skein.example.com");
            ctx.Response.Body = new MemoryStream();
            arrange(ctx);

            await _pipeline(ctx);

            string? error = null;
            if (ctx.Response.StatusCode == StatusCodes.Status400BadRequest && ctx.Response.Body.Length > 0)
            {
                ctx.Response.Body.Position = 0;
                using var doc = await JsonDocument.ParseAsync(ctx.Response.Body);
                error = doc.RootElement.GetProperty("error").GetString();
            }
            return new Outcome(
                ctx.Response.StatusCode,
                error,
                _reached,
                _seenUser,
                _seenRemoteIp,
                ctx.Response.Headers.SetCookie.Count > 0,
                Api.Provisions);
        }

        public (LogLevel Level, string Text)[] SsoLogs =>
            Logs.Entries
                .Where(e => e.Category == typeof(SsoSessionMiddleware).FullName)
                .Select(e => (e.Level, e.Text))
                .ToArray();
    }

    private static void TrustHeaders(HttpContext ctx)
    {
        ctx.Request.Headers["X-Auth-Request-Email"] = VisitorEmail;
        ctx.Request.Headers["X-Auth-Request-User"] = VisitorUsername;
    }

    /// <summary>A session principal issued with epoch 3 whose refresh is long overdue.</summary>
    private static ClaimsPrincipal ExpiredSession() => new(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, SessionUserId),
            new Claim(ClaimTypes.Email, VisitorEmail),
            new Claim("username", VisitorUsername),
            new Claim(ClaimTypes.Name, VisitorUsername),
            new Claim(ClaimTypes.Role, "user"),
            new Claim("is_external", "false"),
            new Claim(SessionPrincipal.SessionEpochClaim, "3"),
            new Claim("urn:skein:refreshed-at",
                DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)),
        ],
        authenticationType: "Cookies"));

    private static bool IsAnonymous(ClaimsPrincipal? user) => user?.Identity is not { IsAuthenticated: true };

    // ---- US-4: trust headers only from a trusted transport peer ----

    [Theory]
    [MemberData(nameof(LegacyModes))]
    public async Task UntrustedPeer_NamingAListedAddressInHeaders_GetsNoSession(string mode)
    {
        var world = new World(mode, ["10.0.0.1"]);

        var outcome = await world.Send("203.0.113.9", ctx =>
        {
            TrustHeaders(ctx);
            ctx.Request.Headers["X-Forwarded-For"] = "10.0.0.1";
            ctx.Request.Headers["X-Original-For"] = "10.0.0.1:1234";
        });

        Assert.Empty(outcome.Provisions);
        Assert.False(outcome.SetCookie);
        Assert.True(outcome.Reached);
        Assert.True(IsAnonymous(outcome.User));
    }

    public static TheoryData<string, string> LegacyModesByLoneTrustHeader()
    {
        var data = new TheoryData<string, string>();
        foreach (var mode in new[] { "keycloak", "hybrid" })
        {
            data.Add(mode, "X-Auth-Request-Email");
            data.Add(mode, "X-Auth-Request-User");
        }
        return data;
    }

    // Either trust header alone, from an untrusted peer, is refused the same
    // way as both: no session, and the refusal Warning.
    [Theory]
    [MemberData(nameof(LegacyModesByLoneTrustHeader))]
    public async Task UntrustedPeer_WithOneTrustHeader_GetsNoSession_AndTheRefusalWarning(string mode, string header)
    {
        var world = new World(mode, ["10.0.0.1"]);

        var outcome = await world.Send("203.0.113.9", ctx =>
            ctx.Request.Headers[header] = header == "X-Auth-Request-Email" ? VisitorEmail : VisitorUsername);

        Assert.Empty(outcome.Provisions);
        Assert.False(outcome.SetCookie);
        Assert.True(outcome.Reached);
        Assert.True(IsAnonymous(outcome.User));
        Assert.Contains(world.SsoLogs, e =>
            e.Level == LogLevel.Warning && e.Text.Contains("SKEIN_TRUSTED_PROXIES", StringComparison.Ordinal));
    }

    public static TheoryData<string, string> LegacyModesByPeerForm()
    {
        var data = new TheoryData<string, string>();
        foreach (var mode in new[] { "keycloak", "hybrid" })
        {
            data.Add(mode, "10.0.0.1");
            data.Add(mode, "::ffff:10.0.0.1");
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(LegacyModesByPeerForm))]
    public async Task TrustedPeer_InEitherAddressForm_GetsASession_AndTheVisitorAddressIsKept(string mode, string peer)
    {
        var world = new World(mode, ["10.0.0.1"]);

        var outcome = await world.Send(peer, ctx =>
        {
            TrustHeaders(ctx);
            ctx.Request.Headers["X-Forwarded-For"] = "198.51.100.23";
        });

        var provision = Assert.Single(outcome.Provisions);
        Assert.True(outcome.SetCookie);
        Assert.Equal(IPAddress.Parse("198.51.100.23"), outcome.RemoteIp);
        Assert.True(provision.Headers.TryGetValues(SkeinHeaders.ClientIp, out var clientIp));
        Assert.Equal(["198.51.100.23"], clientIp);
    }

    [Theory]
    [MemberData(nameof(LegacyModes))]
    public async Task TrustedPeer_ExpiredSession_IsRefreshedAndReissued(string mode)
    {
        var world = new World(mode, ["10.0.0.1"], apiEpoch: 3);

        var outcome = await world.Send("10.0.0.1", ctx =>
        {
            TrustHeaders(ctx);
            ctx.User = ExpiredSession();
        });

        Assert.Single(outcome.Provisions);
        Assert.True(outcome.SetCookie);
    }

    [Theory]
    [MemberData(nameof(LegacyModes))]
    public async Task UntrustedPeer_WithASession_LeavesItUnchanged(string mode)
    {
        // skein-api would answer epoch 4, which would end an epoch-3 session if
        // the refresh ran.
        var world = new World(mode, ["10.0.0.1"], apiEpoch: 4);

        var outcome = await world.Send("203.0.113.9", ctx =>
        {
            ctx.Request.Headers["X-Auth-Request-Email"] = "someone.else@example.com";
            ctx.Request.Headers["X-Auth-Request-User"] = "someone-else";
            ctx.User = ExpiredSession();
        });

        Assert.Empty(outcome.Provisions);
        Assert.False(outcome.SetCookie);
        Assert.True(outcome.Reached);
        Assert.False(IsAnonymous(outcome.User));
        Assert.Equal(SessionUserId, outcome.User!.FindFirstValue(ClaimTypes.NameIdentifier));
        Assert.Equal("3", outcome.User!.FindFirstValue(SessionPrincipal.SessionEpochClaim));
    }

    public static TheoryData<string, string, bool> EmptyListCases()
    {
        var data = new TheoryData<string, string, bool>();
        foreach (var mode in new[] { "keycloak", "hybrid" })
        foreach (var peer in new[] { "127.0.0.1", "10.0.0.1", "::1" })
        {
            data.Add(mode, peer, false);
            data.Add(mode, peer, true);
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(EmptyListCases))]
    public async Task EmptyTrustedProxyList_AcceptsTrustHeadersFromNoOne(string mode, string peer, bool withSession)
    {
        var world = new World(mode, [], apiEpoch: 4);

        var outcome = await world.Send(peer, ctx =>
        {
            TrustHeaders(ctx);
            if (withSession)
            {
                ctx.User = ExpiredSession();
            }
        });

        Assert.Empty(outcome.Provisions);
        Assert.False(outcome.SetCookie);
        Assert.True(outcome.Reached);
        if (withSession)
        {
            Assert.Equal(SessionUserId, outcome.User!.FindFirstValue(ClaimTypes.NameIdentifier));
            Assert.Equal("3", outcome.User!.FindFirstValue(SessionPrincipal.SessionEpochClaim));
        }
        else
        {
            Assert.True(IsAnonymous(outcome.User));
        }
    }

    public static TheoryData<string, string, string, bool> RefusedTrustHeaderRuns()
    {
        var data = new TheoryData<string, string, string, bool>();
        foreach (var mode in new[] { "keycloak", "hybrid" })
        {
            // The untrusted-peer run with a listed address in its headers.
            data.Add(mode, "10.0.0.1", "203.0.113.9", false);
            // The empty-list runs.
            foreach (var peer in new[] { "127.0.0.1", "10.0.0.1", "::1" })
            {
                data.Add(mode, "", peer, false);
                data.Add(mode, "", peer, true);
            }
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(RefusedTrustHeaderRuns))]
    public async Task RefusedTrustHeaders_LogAWarning_WithoutPersonalDataOrAddresses(
        string mode, string trustedProxies, string peer, bool withSession)
    {
        var world = new World(
            mode, trustedProxies.Length == 0 ? [] : [trustedProxies], apiEpoch: 4);

        await world.Send(peer, ctx =>
        {
            TrustHeaders(ctx);
            ctx.Request.Headers["X-Forwarded-For"] = "10.0.0.1";
            ctx.Request.Headers["X-Original-For"] = "10.0.0.1:1234";
            if (withSession)
            {
                ctx.User = ExpiredSession();
            }
        });

        var logs = world.SsoLogs;
        Assert.Contains(logs, e => e.Level == LogLevel.Warning);
        foreach (var (_, text) in logs)
        {
            Assert.DoesNotContain(VisitorEmail, text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(VisitorUsername, text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(peer, text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("10.0.0.1", text, StringComparison.OrdinalIgnoreCase);
        }
    }

    // ---- US-5: the actual host against SKEIN_ALLOWED_HOSTS ----

    /// <summary>X-Forwarded-Host shapes that name more than one host or none: one array item per header line.</summary>
    public static TheoryData<string[]> AmbiguousForwardedHosts => new()
    {
        new[] { "skein.example.com, skein.example.com" },
        new[] { "skein.example.com", "skein.example.com" },
        new[] { "" },
    };

    [Theory]
    [MemberData(nameof(AmbiguousForwardedHosts))]
    public async Task AmbiguousForwardedHost_FromATrustedPeer_Is400InvalidHost(string[] forwardedHost)
    {
        var world = new World("keycloak", ["10.0.0.1"], allowedHosts: "skein.example.com");

        var outcome = await world.Send("10.0.0.1", ctx =>
        {
            TrustHeaders(ctx);
            ctx.Request.Headers["X-Forwarded-Host"] = new StringValues(forwardedHost);
        });

        Assert.Equal(StatusCodes.Status400BadRequest, outcome.Status);
        Assert.Equal("invalid_host", outcome.Error);
        Assert.Empty(outcome.Provisions);
        Assert.False(outcome.Reached);
    }

    [Theory]
    [MemberData(nameof(AmbiguousForwardedHosts))]
    public async Task AmbiguousForwardedHost_FromAnUntrustedPeer_IsIgnored(string[] forwardedHost)
    {
        var world = new World("keycloak", ["10.0.0.1"], allowedHosts: "skein.example.com");

        var outcome = await world.Send("203.0.113.9", ctx =>
        {
            ctx.Request.Host = new HostString("skein.example.com");
            ctx.Request.Headers["X-Forwarded-Host"] = new StringValues(forwardedHost);
        });

        Assert.True(outcome.Reached);
        Assert.Equal(StatusCodes.Status200OK, outcome.Status);
    }

    [Fact]
    public async Task TrustedPeer_WithoutForwardedHost_LiteralHostInTheList_Passes()
    {
        var world = new World("keycloak", ["10.0.0.1"], allowedHosts: "skein.example.com");

        var outcome = await world.Send("10.0.0.1", ctx => ctx.Request.Host = new HostString("skein.example.com"));

        Assert.True(outcome.Reached);
        Assert.Equal(StatusCodes.Status200OK, outcome.Status);
    }

    [Fact]
    public async Task TrustedPeer_ForwardedHostInTheList_PassesWhateverTheLiteralHost()
    {
        var world = new World("keycloak", ["10.0.0.1"], allowedHosts: "skein.example.com");

        var outcome = await world.Send("10.0.0.1", ctx =>
        {
            ctx.Request.Host = new HostString("10.244.1.7");
            ctx.Request.Headers["X-Forwarded-Host"] = "skein.example.com";
        });

        Assert.True(outcome.Reached);
        Assert.Equal(StatusCodes.Status200OK, outcome.Status);
    }

    [Fact]
    public async Task TrustedPeer_ForwardedHostOutsideTheList_Is400InvalidHost_BeforeTheSession()
    {
        var world = new World("keycloak", ["10.0.0.1"], allowedHosts: "skein.example.com");

        var outcome = await world.Send("10.0.0.1", ctx =>
        {
            TrustHeaders(ctx);
            ctx.Request.Host = new HostString("skein.example.com");
            ctx.Request.Headers["X-Forwarded-Host"] = "evil.example";
        });

        Assert.Equal(StatusCodes.Status400BadRequest, outcome.Status);
        Assert.Equal("invalid_host", outcome.Error);
        Assert.Empty(outcome.Provisions);
        Assert.False(outcome.Reached);
    }

    [Fact]
    public async Task UntrustedPeer_LiteralHostOutsideTheList_Is400InvalidHost_WhateverItsForwardedHost()
    {
        var world = new World("keycloak", ["10.0.0.1"], allowedHosts: "skein.example.com");

        var outcome = await world.Send("203.0.113.9", ctx =>
        {
            ctx.Request.Host = new HostString("evil.example");
            ctx.Request.Headers["X-Forwarded-Host"] = "skein.example.com";
        });

        Assert.Equal(StatusCodes.Status400BadRequest, outcome.Status);
        Assert.Equal("invalid_host", outcome.Error);
        Assert.False(outcome.Reached);
    }

    // ---- One pass of forwarded headers, after the snapshot, whatever the host flag ----

    public static TheoryData<bool, string> HostFlagByPeerForm()
    {
        var data = new TheoryData<bool, string>();
        foreach (var flag in new[] { true, false })
        {
            data.Add(flag, "10.0.0.1");
            data.Add(flag, "::ffff:10.0.0.1");
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(HostFlagByPeerForm))]
    public async Task HostComposedPipeline_TrustedPeer_GetsASession_WhateverTheForwardedHeadersFlag(
        bool forwardedHeadersFlag, string peer)
    {
        var world = new World("keycloak", ["10.0.0.1"], likeTheHost: true, forwardedHeadersFlag: forwardedHeadersFlag);

        var outcome = await world.Send(peer, ctx =>
        {
            TrustHeaders(ctx);
            ctx.Request.Headers["X-Forwarded-For"] = "198.51.100.23";
        });

        var provision = Assert.Single(outcome.Provisions);
        Assert.True(outcome.SetCookie);
        Assert.Equal(IPAddress.Parse("198.51.100.23"), outcome.RemoteIp);
        Assert.True(provision.Headers.TryGetValues(SkeinHeaders.ClientIp, out var clientIp));
        Assert.Equal(["198.51.100.23"], clientIp);
    }

    public static TheoryData<bool, string[]> HostFlagByAmbiguousForwardedHost()
    {
        var data = new TheoryData<bool, string[]>();
        foreach (var flag in new[] { true, false })
        {
            data.Add(flag, ["skein.example.com, skein.example.com"]);
            data.Add(flag, ["skein.example.com", "skein.example.com"]);
            data.Add(flag, [""]);
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(HostFlagByAmbiguousForwardedHost))]
    public async Task HostComposedPipeline_AmbiguousForwardedHostFromATrustedPeer_Is400InvalidHost_WhateverTheFlag(
        bool forwardedHeadersFlag, string[] forwardedHost)
    {
        var world = new World(
            "keycloak", ["10.0.0.1"], allowedHosts: "skein.example.com",
            likeTheHost: true, forwardedHeadersFlag: forwardedHeadersFlag);

        var outcome = await world.Send("10.0.0.1", ctx =>
        {
            TrustHeaders(ctx);
            ctx.Request.Headers["X-Forwarded-Host"] = new StringValues(forwardedHost);
        });

        Assert.Equal(StatusCodes.Status400BadRequest, outcome.Status);
        Assert.Equal("invalid_host", outcome.Error);
        Assert.Empty(outcome.Provisions);
        Assert.False(outcome.Reached);
    }
}
