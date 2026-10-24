using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SkeinWeb.Auth;
using SkeinWeb.Middleware;

namespace SkeinWeb.Tests.Middleware;

/// <summary>
/// sk-163 S9 — pins the removal of the unauthenticated <c>POST
/// /api/v1/auth/login</c> allowlist from <see cref="ApiProxyMiddleware"/>. The
/// browser must no longer be able to reach skein-api's login endpoint directly
/// (which would bypass the BFF's per-email + per-IP throttle): an uncookied
/// request is now 401 and is NEVER forwarded upstream. External login must go
/// through the rate-limited BFF route <c>POST /api/auth/login</c> instead.
/// </summary>
public class ApiProxyMiddlewareLoginGateTest
{
    private const string UpstreamBase = "http://skein-api.test";

    private sealed class CapturingHandler : HttpMessageHandler
    {
        public bool Called { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Called = true;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    private sealed class StubHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;
        public StubHttpClientFactory(HttpMessageHandler handler) => _handler = handler;
        public HttpClient CreateClient(string name) =>
            new(_handler, disposeHandler: false) { BaseAddress = new Uri(UpstreamBase) };
    }

    private static (ApiProxyMiddleware mw, CapturingHandler handler) Build()
    {
        var handler = new CapturingHandler();
        var opts = Options.Create(new SkeinApiOptions { Url = UpstreamBase, InternalSecret = "s" });
        var mw = new ApiProxyMiddleware(new StubHttpClientFactory(handler), opts,
            NullLogger<ApiProxyMiddleware>.Instance);
        return (mw, handler);
    }

    private static DefaultHttpContext Context(bool authenticated)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = HttpMethods.Post;
        ctx.Request.Path = "/api/v1/auth/login";
        ctx.Request.Body = new MemoryStream("{\"email\":\"e\",\"password\":\"p\"}"u8.ToArray());
        ctx.Request.ContentType = "application/json";
        ctx.Response.Body = new MemoryStream();
        ctx.User = authenticated
            ? new ClaimsPrincipal(new ClaimsIdentity(
                new[] { new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()) }, "Cookies"))
            : new ClaimsPrincipal(new ClaimsIdentity()); // unauthenticated
        return ctx;
    }

    [Fact]
    public async Task Uncookied_Login_Is401_AndNotForwarded()
    {
        var (mw, handler) = Build();
        var ctx = Context(authenticated: false);

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        Assert.False(handler.Called); // the direct /api/v1/auth/login passthrough is gone
    }

    [Fact]
    public async Task Cookied_Login_StillProxies()
    {
        // Regression guard: an authenticated caller still reaches upstream
        // (the gate is purely about the unauthenticated passthrough removal).
        var (mw, handler) = Build();
        var ctx = Context(authenticated: true);

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.True(handler.Called);
        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
    }
}
