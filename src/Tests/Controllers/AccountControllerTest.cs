using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using SkeinWeb.Auth;
using SkeinWeb.Hubs;
using SkeinWeb.Controllers;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Controllers;

/// <summary>
/// The public account routes of the BFF (<see cref="AccountController"/>,
/// contract <see cref="PublicAuthRoutes"/>).
/// </summary>
/// <remarks>
/// <para>The skein-api client is built by its production registration
/// (<see cref="SkeinAccountsApiClient.Register"/>) with only the transport
/// replaced by a recorder. The same container holds an authenticated user in
/// <see cref="IHttpContextAccessor"/> and a resolvable
/// <see cref="InternalApiHandler"/>, so a registration that attached that
/// handler would put the user's identity on the wire, and row 211 would see
/// it.</para>
/// <para>The limiter is the real <see cref="ActionRateLimiter"/> over a fake
/// Redis that honours INCR and key TTLs on a <see cref="FakeTimeProvider"/>:
/// "after the window" is reached by advancing the fake clock.</para>
/// </remarks>
public class AccountControllerTest
{
    private const string Secret = "svc-secret-aaaaaa";
    private const string U1 = "0199a1b2-0000-7000-8000-000000000001";
    private const string U2 = "0199a1b2-0000-7000-8000-000000000002";

    // T012 godoc literals (internal/accounts/contract.go).
    private const string AuthResponseU1 = """
        {"id":"0199a1b2-0000-7000-8000-000000000001","email":"dev@client.io",
         "username":"dev","name":"dev","role":"user","isExternal":false,
         "createdAt":"2026-10-12T18:13:03Z","lastLoginAt":"2026-10-12T18:13:03Z",
         "sessionEpoch":4}
        """;

    private const string InvitationSignupLiteral = """
        {"id":"0199a1b2-0000-7000-8000-000000000001","email":"dev@client.io",
         "username":"dev","name":"dev","role":"user","isExternal":false,
         "createdAt":"2026-10-12T18:13:03Z","lastLoginAt":null,"sessionEpoch":0,
         "space":{"id":"k3x9p2qa","slug":"acme","name":"Acme"}}
        """;

    private const string PreviewLiteral = """
        {"status":"valid","space":{"id":"k3x9p2qa","slug":"acme","name":"Acme"},
         "inviterUsername":"anna","email":"dev@client.io","hasAccount":false}
        """;

    // ---- fakes ---------------------------------------------------------------

    /// <summary>Fake Redis: INCR and EXPIRE with TTLs on the fake clock.</summary>
    private static IConnectionMultiplexer FakeRedis(FakeTimeProvider time)
    {
        var counters = new Dictionary<string, long>();
        var expiry = new Dictionary<string, DateTimeOffset>();

        void DropIfExpired(string key)
        {
            if (expiry.TryGetValue(key, out var at) && time.GetUtcNow() >= at)
            {
                counters.Remove(key);
                expiry.Remove(key);
            }
        }

        var db = new Mock<IDatabase>();
        db.Setup(d => d.StringIncrementAsync(It.IsAny<RedisKey>(), It.IsAny<long>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync((RedisKey k, long by, CommandFlags _) =>
            {
                var key = k.ToString();
                DropIfExpired(key);
                counters[key] = counters.GetValueOrDefault(key) + by;
                return counters[key];
            });
        db.Setup(d => d.KeyExpireAsync(It.IsAny<RedisKey>(), It.IsAny<TimeSpan?>(),
                It.IsAny<ExpireWhen>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync((RedisKey k, TimeSpan? ttl, ExpireWhen _, CommandFlags _) =>
            {
                expiry[k.ToString()] = time.GetUtcNow() + ttl!.Value;
                return true;
            });

        var mux = new Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(db.Object);
        return mux.Object;
    }

    /// <summary>Stands in for skein-api's public routes and records every request.</summary>
    private sealed class RecordingApi : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = [];

        /// <summary>Body of the reset-complete answer (default: user U1, epoch 4).</summary>
        public string ResetCompleteBody { get; set; } = AuthResponseU1;

        /// <summary>When set, answers every request instead of the contract answers.</summary>
        public Func<HttpResponseMessage>? Override { get; set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add(request);
            if (Override is not null)
            {
                return Task.FromResult(Override());
            }
            var path = request.RequestUri!.AbsolutePath;
            var post = request.Method == HttpMethod.Post;
            return Task.FromResult(path switch
            {
                "/api/v1/auth/signup" when post => Json(AuthResponseU1),
                "/api/v1/auth/username-suggestions" => Json("""{"suggestions":["dev","dev2","dev-client"]}"""),
                "/api/v1/auth/password-reset" when post => new HttpResponseMessage(HttpStatusCode.NoContent),
                _ when post && path.StartsWith("/api/v1/auth/password-reset/") => Json(ResetCompleteBody),
                _ when post && path.StartsWith("/api/v1/auth/confirm-email/") => new HttpResponseMessage(HttpStatusCode.NoContent),
                _ when post && path.EndsWith("/signup") => Json(InvitationSignupLiteral),
                _ when path.StartsWith("/api/v1/auth/invitations/") => Json(PreviewLiteral),
                _ => new HttpResponseMessage(HttpStatusCode.NotFound),
            });
        }

        private static HttpResponseMessage Json(string body) => new(HttpStatusCode.OK)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
    }

    /// <summary>ProblemDetails without the framework's defaults; the controller adds the extensions.</summary>
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

    private static ClaimsPrincipal SignedIn(string userId) => new(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, userId),
            new Claim(ClaimTypes.Email, "someone@client.io"),
            new Claim("username", "someone"),
            new Claim(ClaimTypes.Name, "Someone"),
            new Claim(ClaimTypes.Role, "user"),
            new Claim("is_external", "false"),
            new Claim(SessionPrincipal.SessionEpochClaim, "1"),
        ],
        CookieAuthenticationDefaults.AuthenticationScheme));

    private sealed class Harness
    {
        public required AccountController Controller { get; init; }
        public required RecordingApi Api { get; init; }
        public required FakeTimeProvider Time { get; init; }
        public required List<ClaimsPrincipal> SignIns { get; init; }

        /// <summary>The session store the reset ends the other sessions in.</summary>
        public required Mock<IUserSessionRevoker> Sessions { get; init; }

        /// <summary>This replica's hub connections (real registry).</summary>
        public required ConnectionRegistry Hub { get; init; }

        /// <summary>Levels and lines the controller logged.</summary>
        public required SkeinWeb.Tests.Hubs.CapturingLoggerProvider Logs { get; init; }

        /// <summary>Starts a fresh request on the same controller, limiter and api.</summary>
        public void NewRequest(string remoteIp, ClaimsPrincipal? user = null, string? forgedClientIp = null)
        {
            var services = new ServiceCollection();
            var auth = new Mock<IAuthenticationService>();
            auth.Setup(a => a.SignInAsync(It.IsAny<HttpContext>(), It.IsAny<string>(),
                    It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()))
                .Callback((HttpContext _, string _, ClaimsPrincipal p, AuthenticationProperties _) => SignIns.Add(p))
                .Returns(Task.CompletedTask);
            services.AddSingleton(auth.Object);
            services.AddSingleton<ProblemDetailsFactory, PlainProblemDetailsFactory>();
            var ctx = new DefaultHttpContext
            {
                RequestServices = services.BuildServiceProvider(),
                User = user ?? new ClaimsPrincipal(new ClaimsIdentity()),
            };
            ctx.Connection.RemoteIpAddress = IPAddress.Parse(remoteIp);
            if (forgedClientIp is not null)
            {
                ctx.Request.Headers[SkeinHeaders.ClientIp] = forgedClientIp;
            }
            Controller.ControllerContext = new ControllerContext { HttpContext = ctx };
        }
    }

    private static Harness Build(bool clientIpTrusted = true)
    {
        var api = new RecordingApi();
        var time = new FakeTimeProvider();

        var services = new ServiceCollection();
        services.AddLogging();
        // An authenticated user ambient in the container: a client wired
        // through InternalApiHandler would forward this identity.
        var ambient = new DefaultHttpContext { User = SignedIn(U2) };
        services.AddSingleton<IHttpContextAccessor>(new HttpContextAccessor { HttpContext = ambient });
        services.AddTransient<InternalApiHandler>();
        services.Configure<SkeinApiOptions>(o =>
        {
            o.Url = "http://skein-api.test";
            o.InternalSecret = Secret;
            o.ClientIpTrusted = clientIpTrusted;
        });
        SkeinAccountsApiClient.Register(services, "http://skein-api.test/")
            .ConfigurePrimaryHttpMessageHandler(() => api);
        var provider = services.BuildServiceProvider();

        var sessions = new Mock<IUserSessionRevoker>();
        sessions.Setup(r => r.RemoveSessionsAsync(It.IsAny<Guid>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SessionRemovalResult(0, 0, IndexRead: true));
        var hub = new ConnectionRegistry(time);
        var logs = new SkeinWeb.Tests.Hubs.CapturingLoggerProvider();
        var controller = new AccountController(
            provider.GetRequiredService<SkeinAccountsApiClient>(),
            new ActionRateLimiter(FakeRedis(time), NullLogger<ActionRateLimiter>.Instance),
            provider.GetRequiredService<IOptions<SkeinApiOptions>>(),
            sessions.Object,
            hub,
            new LoggerFactory([logs]).CreateLogger<AccountController>());
        var harness = new Harness
        {
            Controller = controller, Api = api, Time = time, SignIns = [], Sessions = sessions, Hub = hub, Logs = logs,
        };
        harness.NewRequest("203.0.113.7");
        return harness;
    }

    private static int StatusOf(IActionResult result) => result switch
    {
        ObjectResult o => o.StatusCode ?? StatusCodes.Status200OK,
        StatusCodeResult s => s.StatusCode,
        _ => throw new InvalidOperationException($"unexpected result {result.GetType().Name}"),
    };

    private static IActionResult Unwrap<T>(ActionResult<T> r) => r.Result ?? new ObjectResult(r.Value);

    // ---- routes as callable descriptors -------------------------------------

    /// <summary>One request to a public route; a route ignores the inputs it
    /// does not have (a token route has no email, only signups have a username).</summary>
    private delegate Task<IActionResult> Call(
        AccountController c, string email, string token, string username, string password);

    private sealed record Route(string Name, ActionRateLimiter.Policy Policy, Call Invoke)
    {
        public override string ToString() => Name;
    }

    private static readonly Route Signup = new("signup", ActionRateLimiter.Signup,
        async (c, email, _, username, password) => Unwrap(await c.Signup(
            new SignupRequest(email, username, password, true, null, "en"), CancellationToken.None)));

    private static readonly Route UsernameSuggestions = new("username-suggestions", ActionRateLimiter.UsernameSuggestions,
        async (c, email, _, _, _) => Unwrap(await c.UsernameSuggestions(email, CancellationToken.None)));

    private static readonly Route PasswordReset = new("password-reset", ActionRateLimiter.PasswordReset,
        async (c, email, _, _, _) => await c.PasswordReset(new PasswordResetRequest(email, "ru"), CancellationToken.None));

    private static readonly Route PasswordResetComplete = new("password-reset/{token}", ActionRateLimiter.PasswordResetComplete,
        async (c, _, token, _, password) => await c.PasswordResetComplete(
            token, new PasswordResetCompleteRequest(password), CancellationToken.None));

    private static readonly Route ConfirmEmail = new("confirm-email/{token}", ActionRateLimiter.ConfirmEmail,
        async (c, _, token, _, _) => await c.ConfirmEmail(token, CancellationToken.None));

    private static readonly Route Invitation = new("invitations/{token}", ActionRateLimiter.InvitationPreview,
        async (c, _, token, _, _) => Unwrap(await c.Invitation(token, CancellationToken.None)));

    private static readonly Route InvitationSignup = new("invitations/{token}/signup", ActionRateLimiter.InvitationSignup,
        async (c, _, token, username, password) => Unwrap(await c.InvitationSignup(
            token, new InvitationSignupRequest(username, password, true), CancellationToken.None)));

    private static readonly Route[] All =
        [Signup, UsernameSuggestions, PasswordReset, PasswordResetComplete, ConfirmEmail, Invitation, InvitationSignup];

    public static TheoryData<string> AllRoutes => new(All.Select(r => r.Name));
    public static TheoryData<string> EmailRoutes => new(new[] { Signup, UsernameSuggestions, PasswordReset }.Select(r => r.Name));
    public static TheoryData<string> TokenRoutes => new(new[] { PasswordResetComplete, ConfirmEmail, Invitation, InvitationSignup }.Select(r => r.Name));

    private static Route ByName(string name) => All.Single(r => r.Name == name);

    private static async Task<int> Send(
        Harness h, Route route, string email, string ip,
        string token = "tok-1", string username = "dev", string password = "correct horse")
    {
        h.NewRequest(ip);
        return StatusOf(await route.Invoke(h.Controller, email, token, username, password));
    }

    private static async Task AssertRateLimited(
        Harness h, Route route, string email, string ip,
        string token = "tok-1", string username = "dev", string password = "correct horse")
    {
        h.NewRequest(ip);
        var result = await route.Invoke(h.Controller, email, token, username, password);
        var problem = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status429TooManyRequests, problem.StatusCode);
        Assert.Equal(AccountErrorCode.RateLimited, Assert.IsAssignableFrom<ProblemDetails>(problem.Value).Extensions["error"]);
    }

    private static bool IsSuccess(int status) => status is >= 200 and < 300;

    // ---- row 211: reachable without a session, no identity to skein-api ------

    [Theory]
    [MemberData(nameof(AllRoutes))]
    public async Task Route_WithoutSession_ReachesApi_WithoutIdentityHeaders(string name)
    {
        var h = Build();

        var status = await Send(h, ByName(name), "dev@client.io", "203.0.113.7");

        Assert.True(IsSuccess(status), $"{name} answered {status} without a session");
        var sent = Assert.Single(h.Api.Requests);
        Assert.Equal(Secret, sent.Headers.GetValues(SkeinHeaders.InternalSecret).Single());
        Assert.DoesNotContain(sent.Headers, x =>
            x.Key.StartsWith("X-Skein-User", StringComparison.OrdinalIgnoreCase) ||
            x.Key.Equals(SkeinHeaders.Username, StringComparison.OrdinalIgnoreCase) ||
            x.Key.Equals(SkeinHeaders.SessionEpoch, StringComparison.OrdinalIgnoreCase));
    }

    // ---- row 213: X-Skein-Client-Ip only from a trusted proxy ----------------

    [Theory]
    [MemberData(nameof(AllRoutes))]
    public async Task ClientIp_TrustedProxy_IsTheResolvedAddress_NotTheClientsHeader(string name)
    {
        var h = Build(clientIpTrusted: true);
        h.NewRequest("203.0.113.7", forgedClientIp: "6.6.6.6");

        await ByName(name).Invoke(h.Controller, "dev@client.io", "tok-1", "dev", "correct horse");

        var sent = Assert.Single(h.Api.Requests);
        Assert.Equal("203.0.113.7", sent.Headers.GetValues(SkeinHeaders.ClientIp).Single());
    }

    [Theory]
    [MemberData(nameof(AllRoutes))]
    public async Task ClientIp_NoTrustedProxy_IsNotSent_EvenWhenTheClientSendsOne(string name)
    {
        var h = Build(clientIpTrusted: false);
        h.NewRequest("203.0.113.7", forgedClientIp: "6.6.6.6");

        await ByName(name).Invoke(h.Controller, "dev@client.io", "tok-1", "dev", "correct horse");

        var sent = Assert.Single(h.Api.Requests);
        Assert.False(sent.Headers.Contains(SkeinHeaders.ClientIp));
    }

    // ---- row 212: rate-limit keys ------------------------------------------------

    [Theory]
    [MemberData(nameof(AllRoutes))]
    public async Task EveryRoute_NPass_NextIsRateLimited_PassesAgainAfterTheWindow(string name)
    {
        var route = ByName(name);
        var n = route.Policy.EmailLimit ?? route.Policy.IpLimit;
        Assert.True(n >= 1, $"{name}: a zero threshold would refuse every request");
        var h = Build();

        for (var i = 0; i < n; i++)
        {
            Assert.True(IsSuccess(await Send(h, route, "dev@client.io", "203.0.113.7")), $"{name}: request {i + 1} of {n} refused");
        }
        await AssertRateLimited(h, route, "dev@client.io", "203.0.113.7");
        var apiCalls = h.Api.Requests.Count;

        h.Time.Advance(route.Policy.Window + TimeSpan.FromSeconds(1));

        Assert.True(IsSuccess(await Send(h, route, "dev@client.io", "203.0.113.7")));
        Assert.Equal(n, apiCalls); // the refused request never reached skein-api
    }

    [Theory]
    [MemberData(nameof(EmailRoutes))]
    public async Task EmailRoute_Series1_OnlyTheActionChanges_OtherActionPasses(string name)
    {
        var route = ByName(name);
        var other = route == Signup ? PasswordReset : Signup;
        var h = Build();
        for (var i = 0; i < route.Policy.EmailLimit!.Value; i++)
        {
            await Send(h, route, "dev@client.io", "203.0.113.7");
        }
        await AssertRateLimited(h, route, "dev@client.io", "203.0.113.7");

        Assert.True(IsSuccess(await Send(h, other, "dev@client.io", "203.0.113.7")));
    }

    [Theory]
    [MemberData(nameof(EmailRoutes))]
    public async Task EmailRoute_Series2_OnlyTheIpChanges_EmailBucketRefuses_ThenAnotherEmailPasses(string name)
    {
        var route = ByName(name);
        var n = route.Policy.EmailLimit!.Value;
        var h = Build();
        for (var i = 0; i < n; i++)
        {
            Assert.True(IsSuccess(await Send(h, route, "dev@client.io", $"198.51.100.{i + 1}")));
        }
        var lastIp = $"198.51.100.{n + 1}";

        // (2) the email bucket is exhausted although every IP is fresh.
        await AssertRateLimited(h, route, "dev@client.io", lastIp);
        // (2b) same last IP, only the email changes: that IP is far from its limit.
        Assert.True(IsSuccess(await Send(h, route, "other@client.io", lastIp)));
    }

    [Theory]
    [MemberData(nameof(EmailRoutes))]
    public async Task EmailRoute_Series3_OnlyTheEmailChanges_IpBucketRefuses_ThenAnotherIpPasses(string name)
    {
        var route = ByName(name);
        var n = route.Policy.IpLimit;
        var h = Build();
        for (var i = 0; i < n; i++)
        {
            Assert.True(IsSuccess(await Send(h, route, $"u{i}@client.io", "203.0.113.7")));
        }
        var lastEmail = $"u{n}@client.io";

        // (3) the IP bucket is exhausted although every email is fresh.
        await AssertRateLimited(h, route, lastEmail, "203.0.113.7");
        // (3b) same last email, only the IP changes.
        Assert.True(IsSuccess(await Send(h, route, lastEmail, "203.0.113.99")));
    }

    [Theory]
    [MemberData(nameof(EmailRoutes))]
    public async Task EmailRoute_Series4_FieldsOutsideTheKey_DoNotLiftTheLimit(string name)
    {
        var route = ByName(name);
        var h = Build();
        for (var i = 0; i < route.Policy.EmailLimit!.Value; i++)
        {
            await Send(h, route, "dev@client.io", "203.0.113.7");
        }

        // One axis at a time: only the username, only the password (where the
        // input has them), only the case of the email.
        await AssertRateLimited(h, route, "dev@client.io", "203.0.113.7", username: "someone-else");
        await AssertRateLimited(h, route, "dev@client.io", "203.0.113.7", password: "another password");
        await AssertRateLimited(h, route, "DEV@Client.IO", "203.0.113.7");
    }

    [Theory]
    [MemberData(nameof(TokenRoutes))]
    public async Task TokenRoute_SeriesA_OnlyTheActionChanges_OtherActionPasses(string name)
    {
        var route = ByName(name);
        var other = route == ConfirmEmail ? PasswordResetComplete : ConfirmEmail;
        var h = Build();
        for (var i = 0; i < route.Policy.IpLimit; i++)
        {
            await Send(h, route, "dev@client.io", "203.0.113.7");
        }
        await AssertRateLimited(h, route, "dev@client.io", "203.0.113.7");

        Assert.True(IsSuccess(await Send(h, other, "dev@client.io", "203.0.113.7")));
    }

    [Theory]
    [MemberData(nameof(TokenRoutes))]
    public async Task TokenRoute_SeriesB_OnlyTheIpChanges_NewIpPasses(string name)
    {
        var route = ByName(name);
        var h = Build();
        for (var i = 0; i < route.Policy.IpLimit; i++)
        {
            await Send(h, route, "dev@client.io", "203.0.113.7");
        }
        await AssertRateLimited(h, route, "dev@client.io", "203.0.113.7");

        Assert.True(IsSuccess(await Send(h, route, "dev@client.io", "203.0.113.99")));
    }

    [Theory]
    [MemberData(nameof(TokenRoutes))]
    public async Task TokenRoute_SeriesC_TokenAndBodyAreOutsideTheKey(string name)
    {
        var route = ByName(name);
        var h = Build();
        for (var i = 0; i < route.Policy.IpLimit; i++)
        {
            await Send(h, route, "dev@client.io", "203.0.113.7", token: $"tok-{i}");
        }

        // One axis at a time: only the path token; only the username, only the
        // password (where the input has them).
        await AssertRateLimited(h, route, "dev@client.io", "203.0.113.7", token: "tok-never-seen");
        await AssertRateLimited(h, route, "dev@client.io", "203.0.113.7", username: "someone-else");
        await AssertRateLimited(h, route, "dev@client.io", "203.0.113.7", password: "another password");
    }

    [Theory]
    [MemberData(nameof(TokenRoutes))]
    public async Task NoTrustedProxy_TokenRoute_HasNoIpBucket(string name)
    {
        var route = ByName(name);
        var h = Build(clientIpTrusted: false);

        for (var i = 0; i <= route.Policy.IpLimit; i++)
        {
            Assert.True(IsSuccess(await Send(h, route, "dev@client.io", "203.0.113.7", token: $"tok-{i}")));
        }
    }

    [Theory]
    [MemberData(nameof(EmailRoutes))]
    public async Task NoTrustedProxy_EmailRoute_IsLimitedPerEmailOnly(string name)
    {
        var route = ByName(name);
        var h = Build(clientIpTrusted: false);

        // Many emails from one address: no IP bucket to exhaust.
        for (var i = 0; i <= route.Policy.IpLimit; i++)
        {
            Assert.True(IsSuccess(await Send(h, route, $"u{i}@client.io", "203.0.113.7")));
        }
        // The email bucket still applies.
        for (var i = 0; i < route.Policy.EmailLimit!.Value - 1; i++)
        {
            await Send(h, route, "u0@client.io", "203.0.113.7");
        }
        await AssertRateLimited(h, route, "u0@client.io", "203.0.113.7");
    }

    // ---- row 217: reset re-issues only the same user's session ---------------

    [Fact]
    public async Task ResetComplete_SameUsersSession_IsReissuedWithTheEpochOfTheAnswer()
    {
        var h = Build();
        h.NewRequest("203.0.113.7", user: SignedIn(U1));

        var result = await h.Controller.PasswordResetComplete(
            "tok-1", new PasswordResetCompleteRequest("new"), CancellationToken.None);

        Assert.Equal(StatusCodes.Status204NoContent, StatusOf(result));
        var reissued = Assert.Single(h.SignIns);
        Assert.Equal(U1, reissued.FindFirstValue(ClaimTypes.NameIdentifier));
        Assert.Equal("4", reissued.FindFirstValue(SessionPrincipal.SessionEpochClaim));
    }

    [Fact]
    public async Task ResetComplete_AnotherUsersSession_IsNotReissued_NorTurnedIntoTheOwners()
    {
        var h = Build();
        h.NewRequest("203.0.113.7", user: SignedIn(U2));

        var result = await h.Controller.PasswordResetComplete(
            "tok-1", new PasswordResetCompleteRequest("new"), CancellationToken.None);

        Assert.Equal(StatusCodes.Status204NoContent, StatusOf(result));
        Assert.Empty(h.SignIns);
    }

    [Fact]
    public async Task ResetComplete_WithoutSession_IssuesNoSession()
    {
        var h = Build();
        h.NewRequest("203.0.113.7");

        var result = await h.Controller.PasswordResetComplete(
            "tok-1", new PasswordResetCompleteRequest("new"), CancellationToken.None);

        Assert.Equal(StatusCodes.Status204NoContent, StatusOf(result));
        Assert.Empty(h.SignIns);
    }

    // ---- INV-26: the reset ends the user's other sessions ----

    private const string KeyOfThisTab = "skein:session:this-tab";

    private static ClaimsPrincipal SignedInWithKey(string userId, string key)
    {
        var principal = SignedIn(userId);
        ((ClaimsIdentity)principal.Identity!).AddClaim(new Claim(SessionPrincipal.SessionKeyClaim, key));
        return principal;
    }

    /// <summary>Hub connections: U1 in this tab and in another session, U2 elsewhere. Returns the closed log.</summary>
    private static List<string> Connections(Harness h)
    {
        var closed = new List<string>();
        void Add(string id, string user, string key) =>
            h.Hub.Add(new ConnectionState(id, Guid.Parse(user), false, false, key, () => closed.Add(id)));
        Add("u1-this-tab", U1, KeyOfThisTab);
        Add("u1-other", U1, "skein:session:u1-other");
        Add("u2", U2, "skein:session:u2");
        return closed;
    }

    public static TheoryData<string> ResetRequesters => new() { "same-user-session", "no-session", "other-user-session" };

    [Theory]
    [MemberData(nameof(ResetRequesters))]
    public async Task ResetComplete_EndsTheOwnersOtherSessions_KeepsOnlyTheReissuedOne(string requester)
    {
        var h = Build();
        var closed = Connections(h);
        h.NewRequest("203.0.113.7", user: requester switch
        {
            "same-user-session" => SignedInWithKey(U1, KeyOfThisTab),
            "other-user-session" => SignedInWithKey(U2, "skein:session:u2"),
            _ => null,
        });
        // Only the re-issued session of the token's owner is kept.
        string? kept = requester == "same-user-session" ? KeyOfThisTab : null;
        string[] expectedClosed = requester == "same-user-session" ? ["u1-other"] : ["u1-this-tab", "u1-other"];

        var result = await h.Controller.PasswordResetComplete(
            "tok-1", new PasswordResetCompleteRequest("new"), CancellationToken.None);

        Assert.Equal(StatusCodes.Status204NoContent, StatusOf(result));
        h.Sessions.Verify(r => r.RemoveSessionsAsync(Guid.Parse(U1), kept, It.IsAny<CancellationToken>()), Times.Once);
        h.Sessions.Verify(r => r.RemoveSessionsAsync(Guid.Parse(U2), It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Never);
        Assert.Equal(expectedClosed.Order(), closed.Order());
    }

    [Fact]
    public async Task ResetComplete_RemovalIncomplete_StillAnswers204_AndLogsAnError()
    {
        // The password is already set — the failure is reported, not hidden.
        var h = Build();
        h.Sessions.Setup(r => r.RemoveSessionsAsync(It.IsAny<Guid>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SessionRemovalResult(Removed: 1, Failed: 1, IndexRead: true));
        h.NewRequest("203.0.113.7", user: SignedInWithKey(U1, KeyOfThisTab));

        var result = await h.Controller.PasswordResetComplete(
            "tok-1", new PasswordResetCompleteRequest("new"), CancellationToken.None);

        Assert.Equal(StatusCodes.Status204NoContent, StatusOf(result));
        Assert.Contains(h.Logs.Entries, e => e.Level == LogLevel.Error);
    }

    // ---- a 2xx outside the contract is not a success ----------

    public static TheoryData<string, string> NonContractSuccess()
    {
        var data = new TheoryData<string, string>();
        foreach (var route in All)
        {
            data.Add(route.Name, "html-200");   // a gateway page where JSON or 204 is due
            if (route != PasswordReset && route != ConfirmEmail)
            {
                data.Add(route.Name, "empty-204"); // no body where a 200 body is due (204 IS the contract of those two)
            }
            data.Add(route.Name, "empty-object-200");
            data.Add(route.Name, "created-201");
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(NonContractSuccess))]
    public async Task NonContract2xx_Is502_AndIssuesNoSession(string name, string answer)
    {
        var route = ByName(name);
        var h = Build();
        h.Api.Override = answer switch
        {
            "html-200" => () => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("<html>gateway</html>", Encoding.UTF8, "text/html"),
            },
            "empty-204" => () => new HttpResponseMessage(HttpStatusCode.NoContent),
            "empty-object-200" => () => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json"),
            },
            _ => () => new HttpResponseMessage(HttpStatusCode.Created)
            {
                Content = new StringContent(AuthResponseU1, Encoding.UTF8, "application/json"),
            },
        };
        // A same-user session, so a reset that took the answer for success
        // would re-issue it.
        h.NewRequest("203.0.113.7", user: SignedIn(U1));

        var result = await route.Invoke(h.Controller, "dev@client.io", "tok-1", "dev", "correct horse");

        var problem = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status502BadGateway, problem.StatusCode);
        Assert.Equal("upstream_unavailable", Assert.IsAssignableFrom<ProblemDetails>(problem.Value).Extensions["error"]);
        Assert.Empty(h.SignIns);
    }
}
