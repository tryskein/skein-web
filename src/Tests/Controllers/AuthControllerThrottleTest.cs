using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using SkeinWeb.Auth;
using SkeinWeb.Controllers;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Controllers;

/// <summary>
/// sk-163 S9 — exercises the BFF login throttle through <see cref="AuthController.Login"/>
/// against a STATEFUL fake Redis (real INCR semantics), proving both buckets:
/// per-email lockout AND the per-IP spray lockout (one IP walking many emails).
/// The break-glass admin rides the same path, so it is covered by both.
/// </summary>
public class AuthControllerThrottleTest
{
    private static readonly WebAuthMode LocalMode = new(WebAuthKind.Local, Hybrid: false);

    // ---- Stateful fake Redis ------------------------------------------------
    // A Dictionary-backed IDatabase that honours INCR / GET / SET / DEL so the
    // LoginRateLimiter thresholds actually count across calls (the existing
    // never-locked mock cannot express accumulation).
    private static Mock<IConnectionMultiplexer> StatefulMux()
    {
        var store = new Dictionary<string, string>();
        var db = new Mock<IDatabase>();

        db.Setup(d => d.StringIncrementAsync(It.IsAny<RedisKey>(), It.IsAny<long>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync((RedisKey k, long v, CommandFlags _) =>
            {
                var ks = k.ToString();
                long cur = store.TryGetValue(ks, out var s) && long.TryParse(s, out var n) ? n : 0;
                cur += v;
                store[ks] = cur.ToString();
                return cur;
            });

        db.Setup(d => d.StringGetAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync((RedisKey k, CommandFlags _) =>
                store.TryGetValue(k.ToString(), out var s) ? (RedisValue)s : RedisValue.Null);

        // SE.Redis 2.12 binds the 3-arg StringSetAsync(key, value, expiry) call
        // to this Expiration/ValueCondition overload — mock exactly that one.
        db.Setup(d => d.StringSetAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(),
                It.IsAny<Expiration>(), It.IsAny<ValueCondition>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync((RedisKey k, RedisValue v, Expiration _, ValueCondition _, CommandFlags _) =>
            {
                store[k.ToString()] = v.ToString();
                return true;
            });

        db.Setup(d => d.KeyExpireAsync(It.IsAny<RedisKey>(), It.IsAny<TimeSpan?>(),
                It.IsAny<ExpireWhen>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync(true);

        db.Setup(d => d.KeyDeleteAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync((RedisKey k, CommandFlags _) => store.Remove(k.ToString()));

        var mux = new Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(db.Object);
        return mux;
    }

    private sealed class StubApiHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        private readonly string? _json;
        public StubApiHandler(HttpStatusCode status, string? json) { _status = status; _json = json; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var resp = new HttpResponseMessage(_status);
            if (_json is not null) resp.Content = new StringContent(_json, Encoding.UTF8, "application/json");
            return Task.FromResult(resp);
        }
    }

    private sealed class TestProblemDetailsFactory : ProblemDetailsFactory
    {
        public override ProblemDetails CreateProblemDetails(HttpContext httpContext, int? statusCode = null,
            string? title = null, string? type = null, string? detail = null, string? instance = null) =>
            new() { Status = statusCode, Title = title, Type = type, Detail = detail };
        public override ValidationProblemDetails CreateValidationProblemDetails(HttpContext httpContext,
            ModelStateDictionary modelStateDictionary, int? statusCode = null, string? title = null,
            string? type = null, string? detail = null, string? instance = null) =>
            new(modelStateDictionary) { Status = statusCode, Title = title };
    }

    /// <summary>
    /// Build a controller whose throttle store persists across Login calls, with
    /// a fixed client IP. The API always returns 422 invalid-credentials so every
    /// attempt records a failure. <paramref name="clientIpTrusted"/> mirrors a
    /// configured trusted proxy — the per-IP bucket engages only when true.
    /// </summary>
    private static AuthController BuildThrottled(string? clientIp, bool clientIpTrusted = true)
    {
        var http = new HttpClient(new StubApiHandler(HttpStatusCode.UnprocessableEntity,
            "{\"error\":\"invalid credentials\"}"))
        { BaseAddress = new Uri("http://skein-api.test/") };
        var apiClient = new SkeinApiClient(http, NullLogger<SkeinApiClient>.Instance);

        var sso = Options.Create(new SsoOptions());
        var apiOpts = Options.Create(new SkeinApiOptions
        {
            Url = "http://skein-api.test",
            InternalSecret = "s",
            ClientIpTrusted = clientIpTrusted,
        });

        var controller = new AuthController(
            apiClient, new LoginRateLimiter(StatefulMux().Object), LocalMode, sso, apiOpts,
            NullLogger<AuthController>.Instance);

        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IAuthenticationService>());
        var ctx = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
        ctx.Request.Host = new HostString("skein.test");
        if (clientIp is not null)
        {
            ctx.Connection.RemoteIpAddress = IPAddress.Parse(clientIp);
        }

        controller.ControllerContext = new ControllerContext { HttpContext = ctx };
        controller.ProblemDetailsFactory = new TestProblemDetailsFactory();
        return controller;
    }

    private static int Status(ActionResult<UserDto> action) =>
        ((ObjectResult)action.Result!).StatusCode!.Value;

    // Mirror the limiter constants (private there; pinned here so the test
    // breaks loudly if the thresholds are retuned without updating the test).
    private const int EmailThreshold = 10;
    private const int IpThreshold = 30;

    [Fact]
    public async Task PerEmail_LocksOut_After_Threshold()
    {
        var c = BuildThrottled("203.0.113.5");

        // Same email, same IP. The per-email bucket trips first (10 < 30).
        for (var i = 0; i < EmailThreshold; i++)
        {
            var r = await c.Login(new LoginRequest("victim@x.io", "wrong"), CancellationToken.None);
            Assert.Equal(422, Status(r));
        }

        var locked = await c.Login(new LoginRequest("victim@x.io", "wrong"), CancellationToken.None);
        Assert.Equal(429, Status(locked));
        // sk-674.18 T044 (PublicAuthRoutes "Refusals"): the BFF's one 429 frame
        // carries the machine code rate_limited in the `error` extension.
        var problem = Assert.IsAssignableFrom<ProblemDetails>(((ObjectResult)locked.Result!).Value);
        Assert.Equal("rate_limited", problem.Extensions["error"]);
    }

    [Fact]
    public async Task PerIp_Spray_LocksOut_Across_Different_Emails()
    {
        var c = BuildThrottled("198.51.100.77");

        // Distinct email each time so NO per-email bucket reaches its ceiling;
        // only the shared per-IP bucket accumulates. IpThreshold failures.
        for (var i = 0; i < IpThreshold; i++)
        {
            var r = await c.Login(new LoginRequest($"u{i}@x.io", "wrong"), CancellationToken.None);
            Assert.Equal(422, Status(r));
        }

        // A brand-new email from the SAME IP is throttled — the spray vector is
        // closed even though that email never failed before.
        var locked = await c.Login(new LoginRequest("fresh@x.io", "wrong"), CancellationToken.None);
        Assert.Equal(429, Status(locked));
    }

    [Fact]
    public async Task NoClientIp_OnlyPerEmailApplies()
    {
        // With no RemoteIpAddress (off-pipeline), the per-IP bucket is skipped:
        // distinct emails never lock out (each stays at one failure).
        var c = BuildThrottled(clientIp: null);

        for (var i = 0; i < IpThreshold + 5; i++)
        {
            var r = await c.Login(new LoginRequest($"u{i}@x.io", "wrong"), CancellationToken.None);
            Assert.Equal(422, Status(r)); // never 429 — no IP bucket engaged
        }
    }

    [Fact]
    public async Task RedisDown_FailsOpen_LoginStillProceeds()
    {
        // Fail-OPEN: a Redis outage must NOT 500/429 every login. The throttle
        // pre-check and record both throw; the controller swallows them and lets
        // the attempt proceed to the API (here a 200), minting a session.
        var db = new Mock<IDatabase>();
        db.Setup(d => d.StringGetAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
            .ThrowsAsync(new RedisConnectionException(ConnectionFailureType.UnableToConnect, "down"));
        db.Setup(d => d.StringIncrementAsync(It.IsAny<RedisKey>(), It.IsAny<long>(), It.IsAny<CommandFlags>()))
            .ThrowsAsync(new RedisConnectionException(ConnectionFailureType.UnableToConnect, "down"));
        var mux = new Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(db.Object);

        var http = new HttpClient(new StubApiHandler(HttpStatusCode.OK,
            "{\"id\":\"1\",\"email\":\"u@x.io\",\"username\":\"u\",\"name\":\"U\",\"role\":\"user\",\"isExternal\":false,\"sessionEpoch\":1}"))
        { BaseAddress = new Uri("http://skein-api.test/") };
        var apiClient = new SkeinApiClient(http, NullLogger<SkeinApiClient>.Instance);
        var sso = Options.Create(new SsoOptions());
        var apiOpts = Options.Create(new SkeinApiOptions { Url = "http://skein-api.test", InternalSecret = "s" });

        var controller = new AuthController(apiClient, new LoginRateLimiter(mux.Object), LocalMode, sso, apiOpts,
            NullLogger<AuthController>.Instance);
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IAuthenticationService>());
        var ctx = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
        ctx.Request.Host = new HostString("skein.test");
        ctx.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.5");
        controller.ControllerContext = new ControllerContext { HttpContext = ctx };
        controller.ProblemDetailsFactory = new TestProblemDetailsFactory();

        var action = await controller.Login(new LoginRequest("u@x.io", "pw"), CancellationToken.None);

        // Login succeeds (200) despite Redis being unreachable — not a 500/429.
        Assert.Equal(200, ((ObjectResult)action.Result!).StatusCode);
    }

    [Fact]
    public async Task NoTrustedProxy_PerIpDisabled_NoGlobalLockout()
    {
        // HIGH fix: behind an ingress with NO trusted proxy configured,
        // RemoteIpAddress is the constant ingress IP. The per-IP bucket MUST be
        // disabled — otherwise an attacker spraying many emails from that single
        // (apparent) IP would lock out login for the whole org. Even far past
        // the per-IP threshold, distinct emails keep returning 422, never 429.
        var c = BuildThrottled(clientIp: "10.0.0.1", clientIpTrusted: false);

        for (var i = 0; i < IpThreshold + 5; i++)
        {
            var r = await c.Login(new LoginRequest($"u{i}@x.io", "wrong"), CancellationToken.None);
            Assert.Equal(422, Status(r)); // per-IP disabled → no global lockout
        }
    }
}
