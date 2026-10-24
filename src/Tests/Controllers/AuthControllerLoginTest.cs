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
/// sk-163 S4b — pins the 410→403/200/422 translation contract of
/// <see cref="AuthController.Login"/> across local / hybrid / keycloak modes.
/// sk-674.18: the mode is the one taken from skein-api
/// (D-7), and a successful login carries the <c>sessionEpoch</c> of skein-api's
/// answer in the session (K-16).
/// </summary>
/// <remarks>
/// sk-303.8 — this used to also pin a "break-glass host logic": Request.Host
/// classified against the S7a SKEIN_INTERNAL_HOSTS allowlist gated whether the
/// password channel short-circuited to 410 without forwarding, and whether a
/// successful non-external auth was collapsed into 422 as an "oracle guard".
/// Both were removed along with the allowlist (see AuthController.Login for
/// the rationale) — the request is now ALWAYS forwarded to skein-api, and any
/// successful auth mints a cookie, matching the behaviour the internal host
/// always had. That is pinned below without any host parameter.
/// </remarks>
public class AuthControllerLoginTest
{
    // ---- Test doubles -------------------------------------------------------

    /// <summary>Returns one canned skein-api response; records whether it was hit.</summary>
    private sealed class StubApiHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        private readonly string? _json;
        public bool Called { get; private set; }

        public StubApiHandler(HttpStatusCode status, string? json)
        {
            _status = status;
            _json = json;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Called = true;
            var resp = new HttpResponseMessage(_status);
            if (_json is not null)
            {
                resp.Content = new StringContent(_json, Encoding.UTF8, "application/json");
            }
            return Task.FromResult(resp);
        }
    }

    /// <summary>Minimal ProblemDetailsFactory so ControllerBase.Problem works off-pipeline.</summary>
    private sealed class TestProblemDetailsFactory : ProblemDetailsFactory
    {
        public override ProblemDetails CreateProblemDetails(
            HttpContext httpContext, int? statusCode = null, string? title = null,
            string? type = null, string? detail = null, string? instance = null) =>
            new()
            {
                Status = statusCode,
                Title = title,
                Type = type,
                Detail = detail,
                Instance = instance,
            };

        public override ValidationProblemDetails CreateValidationProblemDetails(
            HttpContext httpContext, ModelStateDictionary modelStateDictionary,
            int? statusCode = null, string? title = null, string? type = null,
            string? detail = null, string? instance = null) =>
            new(modelStateDictionary) { Status = statusCode, Title = title };
    }

    private sealed record Harness(
        AuthController Controller,
        StubApiHandler ApiHandler,
        Func<ClaimsPrincipal?> CapturedPrincipal);

    private static LoginRateLimiter NeverLockedLimiter()
    {
        var db = new Mock<IDatabase>();
        db.Setup(d => d.StringGetAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync(RedisValue.Null); // never locked
        db.Setup(d => d.StringIncrementAsync(It.IsAny<RedisKey>(), It.IsAny<long>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync(1);
        db.Setup(d => d.KeyExpireAsync(It.IsAny<RedisKey>(), It.IsAny<TimeSpan?>(), It.IsAny<ExpireWhen>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync(true);
        db.Setup(d => d.StringSetAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<TimeSpan?>(), It.IsAny<bool>(), It.IsAny<When>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync(true);
        db.Setup(d => d.KeyDeleteAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync(true);
        var mux = new Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(db.Object);
        return new LoginRateLimiter(mux.Object);
    }

    private const string Authority = "https://keycloak.example.com/realms/skein";

    /// <summary>
    /// Controller of a process whose mode was taken from skein-api
    /// (<paramref name="apiAuthMode"/> + the configured OIDC authority, plan
    /// K-13) — D-7: there is no web-side mode setting any more.
    /// </summary>
    private static Harness Build(
        string apiAuthMode, string? authority, HttpStatusCode apiStatus, string? apiJson)
    {
        var apiHandler = new StubApiHandler(apiStatus, apiJson);
        var http = new HttpClient(apiHandler) { BaseAddress = new Uri("http://skein-api.test/") };
        var apiClient = new SkeinApiClient(http, NullLogger<SkeinApiClient>.Instance);

        var sso = Options.Create(new SsoOptions());
        var apiOpts = Options.Create(new SkeinApiOptions
        {
            Url = "http://skein-api.test",
            InternalSecret = "s",
        });

        var controller = new AuthController(
            apiClient, NeverLockedLimiter(), WebAuthMode.FromApi(apiAuthMode, authority), sso, apiOpts,
            NullLogger<AuthController>.Instance);

        ClaimsPrincipal? captured = null;
        var authService = new Mock<IAuthenticationService>();
        authService
            .Setup(a => a.SignInAsync(
                It.IsAny<HttpContext>(), It.IsAny<string>(),
                It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()))
            .Callback<HttpContext, string, ClaimsPrincipal, AuthenticationProperties>(
                (_, _, p, _) => captured = p)
            .Returns(Task.CompletedTask);

        var services = new ServiceCollection();
        services.AddSingleton(authService.Object);
        var provider = services.BuildServiceProvider();

        var ctx = new DefaultHttpContext { RequestServices = provider };

        controller.ControllerContext = new ControllerContext { HttpContext = ctx };
        controller.ProblemDetailsFactory = new TestProblemDetailsFactory();

        return new Harness(controller, apiHandler, () => captured);
    }

    private static string UserJson(string role, bool isExternal) =>
        $"{{\"id\":\"11111111-1111-1111-1111-111111111111\",\"email\":\"u@x.io\"," +
        $"\"username\":\"u\",\"name\":\"U\",\"role\":\"{role}\",\"isExternal\":{(isExternal ? "true" : "false")},\"sessionEpoch\":{AnswerEpoch}}}";

    // sessionEpoch of skein-api's answer (T012 AuthResponse) — the value the
    // cookie principal must carry (K-16).
    private const int AnswerEpoch = 9;

    private static LoginRequest Req() => new("u@x.io", "pw");

    private static (int? status, object? value) Inspect(ActionResult<UserDto> action)
    {
        var obj = Assert.IsAssignableFrom<ObjectResult>(action.Result);
        return (obj.StatusCode, obj.Value);
    }

    // ---- Hybrid mode --------------------------------------------------------

    [Fact]
    public async Task Hybrid_Api200_MintsCookie_WithIsExternalClaimFromResponse()
    {
        var h = Build("hybrid", Authority,
            HttpStatusCode.OK, UserJson("user", isExternal: true));

        var action = await h.Controller.Login(Req(), CancellationToken.None);

        var (status, value) = Inspect(action);
        Assert.Equal(200, status);
        var user = Assert.IsType<UserDto>(value);
        Assert.True(user.IsExternal);

        var principal = h.CapturedPrincipal();
        Assert.NotNull(principal);
        Assert.Equal(AnswerEpoch.ToString(), principal!.FindFirstValue(SessionPrincipal.SessionEpochClaim));
        // is_external must come from the API response, not be hardcoded.
        Assert.Equal("true", principal!.FindFirstValue("is_external"));
    }

    [Fact]
    public async Task Hybrid_Api200_NonExternal_MintsCookie()
    {
        // sk-303.8 — no oracle guard any more: a non-external (break-glass)
        // account that authenticates successfully mints a cookie same as an
        // external one, regardless of which host the request arrived on.
        var h = Build("hybrid", Authority,
            HttpStatusCode.OK, UserJson("admin", isExternal: false));

        var action = await h.Controller.Login(Req(), CancellationToken.None);

        var (status, _) = Inspect(action);
        Assert.Equal(200, status);
        var principal = h.CapturedPrincipal();
        Assert.NotNull(principal);
        Assert.Equal(AnswerEpoch.ToString(), principal!.FindFirstValue(SessionPrincipal.SessionEpochClaim));
        Assert.Equal("false", principal!.FindFirstValue("is_external"));
    }

    [Fact]
    public async Task Hybrid_Api422_InvalidCredentials_NoCookie()
    {
        var h = Build("hybrid", Authority,
            HttpStatusCode.UnprocessableEntity, "{\"error\":\"invalid credentials\"}");

        var action = await h.Controller.Login(Req(), CancellationToken.None);

        var (status, _) = Inspect(action);
        Assert.Equal(422, status);
        Assert.Null(h.CapturedPrincipal());
    }

    [Fact]
    public async Task Hybrid_Api403_SsoRequiredAffordance_NoCookie_NoLoop()
    {
        var h = Build("hybrid", Authority,
            HttpStatusCode.Forbidden, "{\"error\":\"sso_required\"}");

        var action = await h.Controller.Login(Req(), CancellationToken.None);

        var (status, value) = Inspect(action);
        Assert.Equal(403, status);
        var pd = Assert.IsType<ProblemDetails>(value);
        Assert.Equal("sso_required", pd.Extensions["error"]);
        Assert.Null(h.CapturedPrincipal());
    }

    [Fact]
    public async Task Hybrid_Api410_MappedToSsoAffordance_NotALiveChannel410()
    {
        // The hybrid API does not 410, but if it ever does we steer to SSO
        // rather than 410-ing a channel the SPA believes is open.
        var h = Build("hybrid", Authority,
            HttpStatusCode.Gone, "{\"error\":\"login_disabled\"}");

        var action = await h.Controller.Login(Req(), CancellationToken.None);

        var (status, value) = Inspect(action);
        Assert.Equal(403, status);
        var pd = Assert.IsType<ProblemDetails>(value);
        Assert.Equal("sso_required", pd.Extensions["error"]);
    }

    // ---- Pure keycloak (break-glass) — always forwarded, no host gating -----

    [Fact]
    public async Task PureKeycloak_Api200_NonExternal_MintsCookie()
    {
        // Break-glass admin (non-external) authenticates under active OIDC —
        // cookie minted, no lockout. No host distinction any more: this is
        // the only path (used to be "internal host only").
        var h = Build("keycloak", null,
            HttpStatusCode.OK, UserJson("admin", isExternal: false));

        var action = await h.Controller.Login(Req(), CancellationToken.None);

        var (status, _) = Inspect(action);
        Assert.Equal(200, status);
        var principal = h.CapturedPrincipal();
        Assert.NotNull(principal);
        Assert.Equal(AnswerEpoch.ToString(), principal!.FindFirstValue(SessionPrincipal.SessionEpochClaim));
        Assert.Equal("false", principal!.FindFirstValue("is_external"));
        Assert.True(h.ApiHandler.Called);
    }

    [Fact]
    public async Task PureKeycloak_Api410_NonBreakGlass_Returns410()
    {
        // sk-303.8 — pure keycloak used to short-circuit to 410 WITHOUT
        // forwarding on a host classified public. That short-circuit is gone:
        // every request is forwarded, and the API's 410 for a non-break-glass
        // account is what produces today's 410 contract.
        var h = Build("keycloak", null,
            HttpStatusCode.Gone, "{\"error\":\"login_disabled\"}");

        var action = await h.Controller.Login(Req(), CancellationToken.None);

        var (status, value) = Inspect(action);
        Assert.Equal(410, status);
        var pd = Assert.IsType<ProblemDetails>(value);
        Assert.Equal("login_disabled", pd.Extensions["error"]);
        Assert.True(h.ApiHandler.Called); // always forwarded — no host short-circuit
    }

    // ---- Local mode (must be unchanged) ------------------------------------

    [Fact]
    public async Task Local_Api200_MintsCookie_Unchanged()
    {
        var h = Build("local", null,
            HttpStatusCode.OK, UserJson("user", isExternal: false));

        var action = await h.Controller.Login(Req(), CancellationToken.None);

        var (status, value) = Inspect(action);
        Assert.Equal(200, status);
        var user = Assert.IsType<UserDto>(value);
        Assert.False(user.IsExternal);
        Assert.NotNull(h.CapturedPrincipal());
        Assert.Equal(AnswerEpoch.ToString(), h.CapturedPrincipal()!.FindFirstValue(SessionPrincipal.SessionEpochClaim));
    }

    [Fact]
    public async Task Local_Api422_InvalidCredentials_Unchanged()
    {
        var h = Build("local", null,
            HttpStatusCode.UnprocessableEntity, "{\"error\":\"invalid credentials\"}");

        var action = await h.Controller.Login(Req(), CancellationToken.None);

        var (status, _) = Inspect(action);
        Assert.Equal(422, status);
        Assert.Null(h.CapturedPrincipal());
    }

    [Fact]
    public async Task Local_WithOidcAuthorityConfigured_StaysLocal()
    {
        // skein-api local + an OIDC client left configured in web is still
        // plain local (the mode is skein-api's): a non-external account logs
        // in normally — zero behaviour change.
        var h = Build("local", Authority,
            HttpStatusCode.OK, UserJson("user", isExternal: false));

        var action = await h.Controller.Login(Req(), CancellationToken.None);

        var (status, _) = Inspect(action);
        Assert.Equal(200, status);
        Assert.NotNull(h.CapturedPrincipal()); // sk-303.8: no host-based guard left in any mode
        Assert.Equal(AnswerEpoch.ToString(), h.CapturedPrincipal()!.FindFirstValue(SessionPrincipal.SessionEpochClaim));
    }
}
