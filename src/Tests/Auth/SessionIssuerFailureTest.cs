using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using Moq;
using SkeinWeb.Auth;
using SkeinWeb.Hubs;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// The issuer without a network: which key an incoming cookie names (R11), that failures carry no
/// source text (R12), the process-wide http warning (R13) and one issue per request (R14).
/// </summary>
public class SessionIssuerFailureTest
{
    private const string ModeName = "__Host-skein.sid";
    private const string OtherName = "skein.sid";
    private const string HandlerSessionIdClaim = "Microsoft.AspNetCore.Authentication.Cookies-SessionId";
    private const string SecretKey = "skein:session:SECRET-KEY-VALUE";
    private static readonly Guid User = Guid.Parse("0199a1b2-0000-7000-8000-000000000001");

    private sealed class LogCapture : ILoggerProvider
    {
        public List<(LogLevel Level, string Category, string Text)> Entries { get; } = [];

        public ILogger CreateLogger(string categoryName) => new Capture(this, categoryName);

        public void Dispose()
        {
        }

        private sealed class Capture(LogCapture owner, string category) : ILogger
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

    private sealed class World
    {
        public required IServiceProvider Services { get; init; }
        public required SessionIssuer Issuer { get; init; }
        public required TicketDataFormat Format { get; init; }
        public required LogCapture Log { get; init; }
        public required FakeTimeProvider Time { get; init; }
        public required Mock<IDatabase> Db { get; init; }

        public DefaultHttpContext Request(string scheme = "https", string? cookie = null)
        {
            var ctx = new DefaultHttpContext { RequestServices = Services.CreateScope().ServiceProvider };
            ctx.Request.Scheme = scheme;
            if (cookie is not null)
            {
                ctx.Request.Headers.Cookie = cookie;
            }
            return ctx;
        }

        public string CookieOf(string key, string name = ModeName) =>
            $"{name}={Uri.EscapeDataString(Format.Protect(new AuthenticationTicket(
                new ClaimsPrincipal(new ClaimsIdentity([new Claim(HandlerSessionIdClaim, key)], "Cookies")), "Cookies")))}";
    }

    private static World Build(bool insecureHttp = false)
    {
        var db = new Mock<IDatabase>();
        db.Setup(d => d.StringSetAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<TimeSpan?>(), It.IsAny<When>()))
            .ReturnsAsync(true);
        var mux = new Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(db.Object);

        var log = new LogCapture();
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(log).SetMinimumLevel(LogLevel.Trace));
        services.AddDataProtection();
        services.AddSingleton(mux.Object);
        services.AddSingleton<TimeProvider>(time);
        services.AddSingleton(new SessionCookiePolicy(insecureHttp));
        services.AddSingleton<RedisTicketStore>();
        services.AddSingleton(new ConnectionRegistry(time));
        services.AddSingleton<SessionIssuer>();
        services.AddSingleton(new SessionTimeouts(SessionTimeouts.DefaultIdleTimeoutHours, SessionTimeouts.DefaultAbsoluteTimeoutHours));
        services.AddSkeinAuthentication(WebAuthMode.FromApi("local", null), new SsoOptions());
        var provider = services.BuildServiceProvider();
        return new World
        {
            Services = provider,
            Issuer = provider.GetRequiredService<SessionIssuer>(),
            Format = provider.GetRequiredService<TicketDataFormat>(),
            Log = log,
            Time = time,
            Db = db,
        };
    }

    private static ClaimsPrincipal Principal() =>
        new(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, User.ToString()), new Claim(ClaimTypes.Email, "a@example.com")], "spike"));

    // ---- R11 ----------------------------------------------------------------------------------

    [Fact]
    public void IncomingKey_IsReadFromTheCookieOfTheMode()
    {
        var w = Build();

        Assert.Equal("K1", w.Issuer.IncomingSessionKey(w.Request(cookie: w.CookieOf("K1"))));
    }

    [Fact]
    public void IncomingKey_WithBothNames_TakesTheNameOfTheMode()
    {
        var w = Build();
        var both = $"{w.CookieOf("OLD", OtherName)}; {w.CookieOf("CURRENT")}";

        Assert.Equal("CURRENT", w.Issuer.IncomingSessionKey(w.Request(cookie: both)));
    }

    [Fact]
    public void IncomingKey_UnderAnotherName_IsNull()
    {
        var w = Build();

        Assert.Null(w.Issuer.IncomingSessionKey(w.Request(cookie: w.CookieOf("OLD", OtherName))));
    }

    [Theory]
    [InlineData("")]
    [InlineData("garbage-not-a-protected-value")]
    public void IncomingKey_OfAnUnusableValue_IsNullWithoutAnException(string value)
    {
        var w = Build();

        Assert.Null(w.Issuer.IncomingSessionKey(w.Request(cookie: $"{ModeName}={value}")));
    }

    [Fact]
    public void IncomingKey_OfAForeignPurpose_IsNull()
    {
        var w = Build();
        var foreign = new TicketDataFormat(w.Services.GetRequiredService<IDataProtectionProvider>().CreateProtector("another", "v1"));
        var value = foreign.Protect(new AuthenticationTicket(
            new ClaimsPrincipal(new ClaimsIdentity([new Claim(HandlerSessionIdClaim, "K")], "Cookies")), "Cookies"));

        Assert.Null(w.Issuer.IncomingSessionKey(w.Request(cookie: $"{ModeName}={Uri.EscapeDataString(value)}")));
    }

    // ---- R12 ----------------------------------------------------------------------------------

    [Fact]
    public async Task RevocationFailure_CarriesNeitherTheKeyNorAnInnerException_AndTheTypeIsLogged()
    {
        var w = Build();
        w.Db.Setup(d => d.ScriptEvaluateAsync(It.IsAny<string>(), It.IsAny<RedisKey[]>(), It.IsAny<RedisValue[]>(), It.IsAny<CommandFlags>()))
            .ThrowsAsync(new RedisConnectionException(ConnectionFailureType.SocketFailure, $"no connection for {SecretKey}"));
        var ctx = w.Request(cookie: w.CookieOf(SecretKey));

        var ex = await Assert.ThrowsAsync<SessionIssueException>(() => w.Issuer.RevokeIncomingAsync(ctx));

        Assert.Null(ex.InnerException);
        Assert.DoesNotContain("SECRET-KEY-VALUE", ex.ToString());
        var logged = string.Join('\n', w.Log.Entries.Select(e => e.Text));
        Assert.DoesNotContain("SECRET-KEY-VALUE", logged);
        Assert.Contains("SessionStoreUnavailableException", logged);
        Assert.Equal(0, ctx.Response.Headers.SetCookie.Count);
    }

    [Fact]
    public async Task StoreFailureDuringTheIssue_CarriesNoSourceText_AndWritesNoCookie()
    {
        var w = Build();
        w.Db.Setup(d => d.StringSetAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<TimeSpan?>(), It.IsAny<When>()))
            .ThrowsAsync(new RedisConnectionException(ConnectionFailureType.SocketFailure, $"no connection for {SecretKey}"));
        var ctx = w.Request();

        var ex = await Assert.ThrowsAsync<SessionIssueException>(
            () => w.Issuer.RotateAsync(ctx, Principal(), new AuthenticationProperties(), "Login"));

        Assert.Null(ex.InnerException);
        Assert.DoesNotContain("SECRET-KEY-VALUE", ex.ToString());
        Assert.Equal(0, ctx.Response.Headers.SetCookie.Count);
    }

    // ---- R13 ----------------------------------------------------------------------------------

    private static int Warnings(World w) => w.Log.Entries.Count(e =>
        e.Level == LogLevel.Warning && e.Category.EndsWith(nameof(SessionIssuer), StringComparison.Ordinal)
        && e.Text.Contains("SKEIN_ALLOW_INSECURE_HTTP", StringComparison.Ordinal));

    [Fact]
    public async Task HttpScheme_WithTheNormalMode_WarnsOncePerMinuteForTheProcess()
    {
        var w = Build();

        await w.Issuer.RotateAsync(w.Request("http"), Principal(), new AuthenticationProperties(), "Login");
        await w.Issuer.RotateAsync(w.Request("http"), Principal(), new AuthenticationProperties(), "Signup");
        Assert.Equal(1, Warnings(w));

        w.Time.Advance(TimeSpan.FromSeconds(61));
        await w.Issuer.RotateAsync(w.Request("http"), Principal(), new AuthenticationProperties(), "Login");
        Assert.Equal(2, Warnings(w));
    }

    [Fact]
    public async Task HttpsScheme_DoesNotWarn()
    {
        var w = Build();

        await w.Issuer.RotateAsync(w.Request("https"), Principal(), new AuthenticationProperties(), "Login");

        Assert.Equal(0, Warnings(w));
    }

    [Fact]
    public async Task InsecureHttpMode_DoesNotWarn()
    {
        var w = Build(insecureHttp: true);

        await w.Issuer.RotateAsync(w.Request("http"), Principal(), new AuthenticationProperties(), "Login");

        Assert.Equal(0, Warnings(w));
    }

    // ---- R14 ----------------------------------------------------------------------------------

    [Fact]
    public async Task SecondIssueOnOneRequest_IsRefused_AndAddsNoSecondCookie()
    {
        var w = Build();
        var ctx = w.Request();
        await w.Issuer.RotateAsync(ctx, Principal(), new AuthenticationProperties(), "Login");

        await Assert.ThrowsAsync<SessionIssueException>(
            () => w.Issuer.RotateAsync(ctx, Principal(), new AuthenticationProperties(), "Login"));
        await Assert.ThrowsAsync<SessionIssueException>(
            () => w.Issuer.IssueAsync(ctx, Principal(), new AuthenticationProperties(), "Login"));

        Assert.Single(ctx.Response.Headers.SetCookie);
    }

    [Fact]
    public async Task TwoDifferentRequests_IssueOneKeyEach()
    {
        var w = Build();
        var first = w.Request();
        var second = w.Request();

        var a = await w.Issuer.RotateAsync(first, Principal(), new AuthenticationProperties(), "Login");
        var b = await w.Issuer.RotateAsync(second, Principal(), new AuthenticationProperties(), "Login");

        Assert.NotEqual(a.Key, b.Key);
        Assert.Single(first.Response.Headers.SetCookie);
        Assert.Single(second.Response.Headers.SetCookie);
    }
}
