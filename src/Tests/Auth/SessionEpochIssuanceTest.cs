using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using SkeinWeb.Auth;
using SkeinWeb.Controllers;
using SkeinWeb.Hubs;
using SkeinWeb.Middleware;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// INV-26, K-16 — the class of authentication
/// responses of the T012 contract: password login, OIDC provisioning (both
/// doors that turn it into a session: native OIDC and the trust-headers
/// bootstrap), signup, signup by invitation and a successful password reset.
/// On every door the session claims carry the <c>sessionEpoch</c> of THAT
/// answer; an answer without it issues (or re-issues) no session and logs an
/// error — never a default, never the epoch of an older session.
/// </summary>
public class SessionEpochIssuanceTest
{
    private const string U1 = "0199a1b2-0000-7000-8000-000000000001";
    private const string AnswerEpoch = "4";
    private const string OldEpoch = "1";

    private static string AuthBody(bool withEpoch) =>
        "{\"id\":\"" + U1 + "\",\"email\":\"dev@client.io\",\"username\":\"dev\",\"name\":\"dev\"," +
        "\"role\":\"user\",\"isExternal\":false,\"createdAt\":\"2026-10-12T18:13:03Z\",\"lastLoginAt\":null" +
        (withEpoch ? ",\"sessionEpoch\":" + AnswerEpoch : "") + "}";

    private static string InvitationSignupBody(bool withEpoch) =>
        AuthBody(withEpoch).TrimEnd('}') + ",\"space\":{\"id\":\"k3x9p2qa\",\"slug\":\"acme\",\"name\":\"Acme\"}}";

    /// <summary>skein-api answering every route with the given 200 body.</summary>
    private sealed class Api(string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            });
    }

    /// <summary>Collects the levels of everything logged.</summary>
    private sealed class LevelLog : ILoggerProvider, ILogger
    {
        public List<LogLevel> Levels { get; } = [];
        public ILogger CreateLogger(string categoryName) => this;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => Levels.Add(logLevel);
        public void Dispose() { }
    }

    private sealed class PlainProblemDetailsFactory : ProblemDetailsFactory
    {
        public override ProblemDetails CreateProblemDetails(HttpContext httpContext, int? statusCode = null,
            string? title = null, string? type = null, string? detail = null, string? instance = null) =>
            new() { Status = statusCode, Title = title, Type = type, Detail = detail };

        public override ValidationProblemDetails CreateValidationProblemDetails(HttpContext httpContext,
            ModelStateDictionary modelStateDictionary, int? statusCode = null, string? title = null,
            string? type = null, string? detail = null, string? instance = null) =>
            new(modelStateDictionary) { Status = statusCode, Title = title };
    }

    private static ClaimsPrincipal ExistingSession() => new(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, U1),
            new Claim(ClaimTypes.Email, "dev@client.io"),
            new Claim("username", "dev"),
            new Claim(ClaimTypes.Name, "dev"),
            new Claim(ClaimTypes.Role, "user"),
            new Claim("is_external", "false"),
            new Claim(SessionPrincipal.SessionEpochClaim, OldEpoch),
        ],
        CookieAuthenticationDefaults.AuthenticationScheme));

    /// <summary>What a door did: the principals it signed in, and the log levels.</summary>
    private sealed record Outcome(IReadOnlyList<ClaimsPrincipal> Sessions, IReadOnlyList<LogLevel> Levels);

    /// <summary>A request context whose sign-ins are captured.</summary>
    private static (DefaultHttpContext Ctx, List<ClaimsPrincipal> SignIns) Context(
        IServiceCollection services, ClaimsPrincipal? user = null)
    {
        var signIns = new List<ClaimsPrincipal>();
        var auth = new Mock<IAuthenticationService>();
        auth.Setup(a => a.SignInAsync(It.IsAny<HttpContext>(), It.IsAny<string>(),
                It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()))
            .Callback((HttpContext _, string _, ClaimsPrincipal p, AuthenticationProperties _) => signIns.Add(p))
            .Returns(Task.CompletedTask);
        services.AddSingleton(auth.Object);
        services.AddSingleton<ProblemDetailsFactory, PlainProblemDetailsFactory>();
        var ctx = new DefaultHttpContext
        {
            RequestServices = services.BuildServiceProvider(),
            User = user ?? new ClaimsPrincipal(new ClaimsIdentity()),
        };
        ctx.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.7");
        ctx.Response.Body = new MemoryStream();
        return (ctx, signIns);
    }

    private static HttpClient Http(string body) => new(new Api(body)) { BaseAddress = new Uri("http://skein-api.test/") };

    private static IOptions<SkeinApiOptions> ApiOptions() =>
        Options.Create(new SkeinApiOptions { Url = "http://skein-api.test", InternalSecret = "s" });

    private static IConnectionMultiplexer QuietRedis()
    {
        var mux = new Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(new Mock<IDatabase>().Object);
        return mux.Object;
    }

    private static ILogger<T> Logger<T>(LevelLog log) => new LoggerFactory([log]).CreateLogger<T>();

    // ---- the doors -------------------------------------------------------------

    private static async Task<Outcome> PasswordLogin(bool withEpoch)
    {
        var log = new LevelLog();
        var controller = new AuthController(
            new SkeinApiClient(Http(AuthBody(withEpoch)), NullLogger<SkeinApiClient>.Instance),
            new LoginRateLimiter(QuietRedis()),
            new WebAuthMode(WebAuthKind.Local, Hybrid: false),
            Options.Create(new SsoOptions()),
            ApiOptions(),
            Logger<AuthController>(log));
        var (ctx, signIns) = Context(new ServiceCollection());
        controller.ControllerContext = new ControllerContext { HttpContext = ctx };

        await controller.Login(new LoginRequest("dev@client.io", "pw"), CancellationToken.None);
        return new Outcome(signIns, log.Levels);
    }

    private static async Task<Outcome> NativeOidc(bool withEpoch)
    {
        var log = new LevelLog();
        var sso = new SsoOptions();
        sso.Oidc.Authority = "https://keycloak.example.com/realms/skein";
        sso.Oidc.ClientId = "skein";
        sso.Oidc.ClientSecret = "secret";
        var registration = new ServiceCollection();
        registration.AddLogging();
        registration.AddSkeinAuthentication(WebAuthMode.FromApi("keycloak", sso.Oidc.Authority), sso);
        await using var composed = registration.BuildServiceProvider();
        var options = composed.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);

        var requestServices = new ServiceCollection();
        requestServices.AddSingleton<ILoggerFactory>(new LoggerFactory([log]));
        requestServices.AddSingleton(new SkeinApiClient(Http(AuthBody(withEpoch)), NullLogger<SkeinApiClient>.Instance));
        var (ctx, _) = Context(requestServices);
        var idToken = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("groups", "/skein-users"),
                new Claim("email", "dev@client.io"),
                new Claim("preferred_username", "dev"),
            ],
            "oidc"));
        var validated = new TokenValidatedContext(
            ctx,
            new AuthenticationScheme(OpenIdConnectDefaults.AuthenticationScheme, null, typeof(OpenIdConnectHandler)),
            options,
            idToken,
            new AuthenticationProperties());

        await options.Events.OnTokenValidated(validated);

        // The OIDC door "signs in" by handing the cookie scheme its principal;
        // a refused answer ends the response and keeps the id_token principal.
        var sessions = validated.Result?.Handled == true || validated.Principal?.FindFirst(ClaimTypes.NameIdentifier) is null
            ? []
            : new[] { validated.Principal! };
        return new Outcome(sessions, log.Levels);
    }

    private static async Task<Outcome> TrustHeaders(bool withEpoch)
    {
        var log = new LevelLog();
        var services = new ServiceCollection();
        services.AddSingleton(new SkeinApiClient(Http(AuthBody(withEpoch)), NullLogger<SkeinApiClient>.Instance));
        var (ctx, signIns) = Context(services);
        ctx.Request.Path = "/";
        ctx.Request.Headers["X-Auth-Request-Email"] = "dev@client.io";
        ctx.Request.Headers["X-Auth-Request-User"] = "dev";
        var middleware = new SsoSessionMiddleware(
            new WebAuthMode(WebAuthKind.Keycloak, Hybrid: false), ctx.RequestServices, Logger<SsoSessionMiddleware>(log));

        await middleware.InvokeAsync(ctx, _ => Task.CompletedTask);
        return new Outcome(signIns, log.Levels);
    }

    private static AccountController Accounts(string body, LevelLog log) => new(
        new SkeinAccountsApiClient(Http(body), ApiOptions()),
        new ActionRateLimiter(QuietRedis(), NullLogger<ActionRateLimiter>.Instance),
        ApiOptions(),
        CompleteRevoker(),
        new ConnectionRegistry(TimeProvider.System),
        Logger<AccountController>(log));

    private static async Task<Outcome> Signup(bool withEpoch)
    {
        var log = new LevelLog();
        var controller = Accounts(AuthBody(withEpoch), log);
        var (ctx, signIns) = Context(new ServiceCollection());
        controller.ControllerContext = new ControllerContext { HttpContext = ctx };

        await controller.Signup(new SignupRequest("dev@client.io", "dev", "pw", true, null, "en"), CancellationToken.None);
        return new Outcome(signIns, log.Levels);
    }

    private static async Task<Outcome> InvitationSignup(bool withEpoch)
    {
        var log = new LevelLog();
        var controller = Accounts(InvitationSignupBody(withEpoch), log);
        var (ctx, signIns) = Context(new ServiceCollection());
        controller.ControllerContext = new ControllerContext { HttpContext = ctx };

        await controller.InvitationSignup("tok-1", new InvitationSignupRequest("dev", "pw", true), CancellationToken.None);
        return new Outcome(signIns, log.Levels);
    }

    private static async Task<Outcome> PasswordReset(bool withEpoch)
    {
        var log = new LevelLog();
        var controller = Accounts(AuthBody(withEpoch), log);
        // The tab resetting its own password: a session of the same user,
        // carrying an OLDER epoch that must not survive into the re-issue.
        var (ctx, signIns) = Context(new ServiceCollection(), ExistingSession());
        controller.ControllerContext = new ControllerContext { HttpContext = ctx };

        await controller.PasswordResetComplete("tok-1", new PasswordResetCompleteRequest("new"), CancellationToken.None);
        return new Outcome(signIns, log.Levels);
    }

    private static Task<Outcome> Through(string door, bool withEpoch) => door switch
    {
        "password-login" => PasswordLogin(withEpoch),
        "oidc-native" => NativeOidc(withEpoch),
        "oidc-trust-headers" => TrustHeaders(withEpoch),
        "signup" => Signup(withEpoch),
        "invitation-signup" => InvitationSignup(withEpoch),
        "password-reset" => PasswordReset(withEpoch),
        _ => throw new ArgumentOutOfRangeException(nameof(door)),
    };

    public static TheoryData<string> Doors => new()
    {
        "password-login", "oidc-native", "oidc-trust-headers", "signup", "invitation-signup", "password-reset",
    };

    [Theory]
    [MemberData(nameof(Doors))]
    public async Task AnswerWithEpoch_SessionCarriesTheEpochOfTheAnswer(string door)
    {
        var outcome = await Through(door, withEpoch: true);

        var session = Assert.Single(outcome.Sessions);
        Assert.Equal(U1, session.FindFirstValue(ClaimTypes.NameIdentifier));
        Assert.Equal(AnswerEpoch, session.FindFirstValue(SessionPrincipal.SessionEpochClaim));
    }

    [Theory]
    [MemberData(nameof(Doors))]
    public async Task AnswerWithoutEpoch_NoSessionIssued_ErrorLogged(string door)
    {
        var outcome = await Through(door, withEpoch: false);

        Assert.Empty(outcome.Sessions);
        Assert.Contains(LogLevel.Error, outcome.Levels);
    }

    /// <summary>A session store whose removals always complete.</summary>
    private static IUserSessionRevoker CompleteRevoker()
    {
        var revoker = new Mock<IUserSessionRevoker>();
        revoker.Setup(r => r.RemoveSessionsAsync(It.IsAny<Guid>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SessionRemovalResult(0, 0, IndexRead: true));
        return revoker.Object;
    }
}
