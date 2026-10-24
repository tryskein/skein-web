using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using SkeinWeb.Auth;
using SkeinWeb.Middleware;

namespace SkeinWeb.Tests.Middleware;

/// <summary>
/// INV-26, K-16: skein-api's 401
/// <c>{"error":"session_revoked"}</c> makes <see cref="ApiProxyMiddleware"/>
/// end the session — sign-out of the cookie scheme, which deletes the cookie
/// and the Redis ticket — and still answer 401 with skein-api's body. Any
/// other 401 leaves the session alone.
/// </summary>
public class ApiProxyMiddlewareSessionRevokedTest
{
    private const string UpstreamBase = "http://skein-api.test";

    private sealed class FixedAnswer(HttpStatusCode status, string? body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var response = new HttpResponseMessage(status);
            if (body is not null)
            {
                response.Content = new StringContent(body, Encoding.UTF8, "application/json");
            }
            return Task.FromResult(response);
        }
    }

    private sealed class StubHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(handler, disposeHandler: false) { BaseAddress = new Uri(UpstreamBase) };
    }

    private sealed record Run(DefaultHttpContext Ctx, List<string?> SignOuts)
    {
        public string Body => Encoding.UTF8.GetString(((MemoryStream)Ctx.Response.Body).ToArray());
    }

    private static async Task<Run> Proxy(HttpStatusCode upstreamStatus, string? upstreamBody)
    {
        var signOuts = new List<string?>();
        var auth = new Mock<IAuthenticationService>();
        auth.Setup(a => a.SignOutAsync(It.IsAny<HttpContext>(), It.IsAny<string?>(), It.IsAny<AuthenticationProperties?>()))
            .Callback((HttpContext _, string? scheme, AuthenticationProperties? _) => signOuts.Add(scheme))
            .Returns(Task.CompletedTask);
        var services = new ServiceCollection();
        services.AddSingleton(auth.Object);

        var ctx = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
        ctx.Request.Method = HttpMethods.Get;
        ctx.Request.Path = "/api/v1/projects";
        ctx.Response.Body = new MemoryStream();
        ctx.User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "0199a1b2-0000-7000-8000-000000000001"),
                new Claim(SessionPrincipal.SessionEpochClaim, "1"),
            ],
            CookieAuthenticationDefaults.AuthenticationScheme));

        var middleware = new ApiProxyMiddleware(
            new StubHttpClientFactory(new FixedAnswer(upstreamStatus, upstreamBody)),
            Options.Create(new SkeinApiOptions { Url = UpstreamBase, InternalSecret = "s" }),
            NullLogger<ApiProxyMiddleware>.Instance);

        await middleware.InvokeAsync(ctx, _ => Task.CompletedTask);
        return new Run(ctx, signOuts);
    }

    [Fact]
    public async Task SessionRevoked_SignsOutOfTheCookieScheme_AndAnswers401()
    {
        // auth/headers.go#CodeSessionRevoked literal.
        var run = await Proxy(HttpStatusCode.Unauthorized, """{"error":"session_revoked"}""");

        Assert.Equal(StatusCodes.Status401Unauthorized, run.Ctx.Response.StatusCode);
        Assert.Equal([CookieAuthenticationDefaults.AuthenticationScheme], run.SignOuts);
        Assert.Contains("session_revoked", run.Body);
    }

    public static TheoryData<HttpStatusCode, string?> NotARevocation => new()
    {
        { HttpStatusCode.Unauthorized, """{"error":"invalid internal secret"}""" },
        { HttpStatusCode.Unauthorized, "not json" },
        { HttpStatusCode.Unauthorized, null },
        { HttpStatusCode.Forbidden, """{"error":"session_revoked"}""" },
        { HttpStatusCode.OK, """{"error":"session_revoked"}""" },
    };

    [Theory]
    [MemberData(nameof(NotARevocation))]
    public async Task AnyOtherAnswer_LeavesTheSessionAlone(HttpStatusCode status, string? body)
    {
        var run = await Proxy(status, body);

        Assert.Equal((int)status, run.Ctx.Response.StatusCode);
        Assert.Empty(run.SignOuts);
    }
}
