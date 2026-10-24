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
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using SkeinWeb.Auth;
using SkeinWeb.Controllers;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Controllers;

/// <summary>
/// INV-26, K-16: a session skein-api revoked is refused on
/// the BFF's own <c>GET /api/auth/me</c>, not only on the <c>/api/v1</c>
/// proxy — <c>session_revoked</c> ends the session (cookie scheme signed out)
/// and answers 401; any other answer leaves it alone. The skein-api call goes
/// through the real <see cref="InternalApiHandler"/>, so the session's epoch is
/// what skein-api is asked about.
/// </summary>
public class AuthControllerMeTest
{
    private const string U1 = "0199a1b2-0000-7000-8000-000000000001";

    private sealed class Api(HttpStatusCode status, string body) : HttpMessageHandler
    {
        public HttpRequestMessage? Sent { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Sent = request;
            return Task.FromResult(new HttpResponseMessage(status)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            });
        }
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

    private sealed record Run(ActionResult<UserDto> Result, Api Api, List<string?> SignOuts);

    private static async Task<Run> Me(HttpStatusCode status, string body)
    {
        var signOuts = new List<string?>();
        var auth = new Mock<IAuthenticationService>();
        auth.Setup(a => a.SignOutAsync(It.IsAny<HttpContext>(), It.IsAny<string?>(), It.IsAny<AuthenticationProperties?>()))
            .Callback((HttpContext _, string? scheme, AuthenticationProperties? _) => signOuts.Add(scheme))
            .Returns(Task.CompletedTask);
        var services = new ServiceCollection();
        services.AddSingleton(auth.Object);
        services.AddSingleton<ProblemDetailsFactory, PlainProblemDetailsFactory>();
        var ctx = new DefaultHttpContext
        {
            RequestServices = services.BuildServiceProvider(),
            User = new ClaimsPrincipal(new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.NameIdentifier, U1),
                    new Claim(ClaimTypes.Email, "dev@client.io"),
                    new Claim("username", "dev"),
                    new Claim(ClaimTypes.Name, "dev"),
                    new Claim(ClaimTypes.Role, "user"),
                    new Claim("is_external", "false"),
                    new Claim(SessionPrincipal.SessionEpochClaim, "3"),
                ],
                CookieAuthenticationDefaults.AuthenticationScheme)),
        };

        var api = new Api(status, body);
        var options = Options.Create(new SkeinApiOptions { Url = "http://skein-api.test", InternalSecret = "s" });
        var pipeline = new InternalApiHandler(new HttpContextAccessor { HttpContext = ctx }, options) { InnerHandler = api };
        var mux = new Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(new Mock<IDatabase>().Object);
        var controller = new AuthController(
            new SkeinApiClient(new HttpClient(pipeline) { BaseAddress = new Uri("http://skein-api.test/") },
                NullLogger<SkeinApiClient>.Instance),
            new LoginRateLimiter(mux.Object),
            WebAuthMode.FromApi("local", null),
            Options.Create(new SsoOptions()),
            options,
            NullLogger<AuthController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = ctx },
        };

        var result = await controller.Me(CancellationToken.None);
        return new Run(result, api, signOuts);
    }

    [Fact]
    public async Task SessionRevokedByApi_EndsTheSession_AndAnswers401()
    {
        var run = await Me(HttpStatusCode.Unauthorized, """{"error":"session_revoked"}""");

        var problem = Assert.IsType<ObjectResult>(run.Result.Result);
        Assert.Equal(StatusCodes.Status401Unauthorized, problem.StatusCode);
        Assert.Equal("session_revoked", Assert.IsAssignableFrom<ProblemDetails>(problem.Value).Extensions["error"]);
        Assert.Equal([CookieAuthenticationDefaults.AuthenticationScheme], run.SignOuts);
    }

    [Fact]
    public async Task LiveSession_ReturnsTheApiUser_AskingWithTheSessionsEpoch()
    {
        var run = await Me(HttpStatusCode.OK,
            "{\"id\":\"" + U1 + "\",\"email\":\"dev@client.io\",\"username\":\"dev\",\"name\":\"Dev Renamed\"," +
            "\"role\":\"user\",\"isExternal\":false,\"createdAt\":\"2026-10-12T18:13:03Z\",\"lastLoginAt\":null,\"sessionEpoch\":3}");

        var ok = Assert.IsType<OkObjectResult>(run.Result.Result);
        Assert.Equal("Dev Renamed", Assert.IsType<UserDto>(ok.Value).Name);
        Assert.Equal("3", run.Api.Sent!.Headers.GetValues(SkeinHeaders.SessionEpoch).Single());
        Assert.Empty(run.SignOuts);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, """{"error":"invalid internal secret"}""")]
    [InlineData(HttpStatusCode.InternalServerError, """{"error":"internal_error"}""")]
    public async Task OtherAnswer_Is502_AndLeavesTheSessionAlone(HttpStatusCode status, string body)
    {
        var run = await Me(status, body);

        var problem = Assert.IsType<ObjectResult>(run.Result.Result);
        Assert.Equal(StatusCodes.Status502BadGateway, problem.StatusCode);
        Assert.Empty(run.SignOuts);
    }
}
