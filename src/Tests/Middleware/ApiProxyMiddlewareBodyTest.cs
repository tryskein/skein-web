using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SkeinWeb.Auth;
using SkeinWeb.Middleware;

namespace SkeinWeb.Tests.Middleware;

/// <summary>
/// Pins request-body forwarding through <see cref="ApiProxyMiddleware"/>.
///
/// The load-bearing case is the Web Push unsubscribe contract: skein-api's
/// <c>DELETE /api/v1/push/subscriptions</c> reads a JSON body
/// <c>{ "endpoint": "..." }</c>. A verb-only body gate (POST/PUT/PATCH) would
/// silently drop a DELETE body and the upstream would answer
/// <c>400 invalid_json</c>. These tests drive the middleware against a stub
/// upstream that captures whatever body it receives and assert:
///   - DELETE WITH a body forwards that body verbatim;
///   - bodyless GET/DELETE forward no entity body;
///   - POST still forwards its body (regression guard on the existing path).
/// </summary>
public class ApiProxyMiddlewareBodyTest
{
    private const string UpstreamBase = "http://skein-api.test";

    /// <summary>Captures the body the proxy forwards upstream.</summary>
    private sealed class CapturingHandler : HttpMessageHandler
    {
        public string? CapturedBody { get; private set; }
        public HttpMethod? CapturedMethod { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CapturedMethod = request.Method;
            CapturedBody = request.Content is null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.NoContent);
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
        var factory = new StubHttpClientFactory(handler);
        var opts = Options.Create(new SkeinApiOptions { Url = UpstreamBase, InternalSecret = "s" });
        var mw = new ApiProxyMiddleware(factory, opts, NullLogger<ApiProxyMiddleware>.Instance);
        return (mw, handler);
    }

    private static DefaultHttpContext AuthedContext(string method, string path, string? body)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = method;
        ctx.Request.Path = path;
        ctx.User = new ClaimsPrincipal(new ClaimsIdentity(
            new[] { new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()) },
            authenticationType: "Cookies"));
        if (body is not null)
        {
            var bytes = Encoding.UTF8.GetBytes(body);
            ctx.Request.Body = new MemoryStream(bytes);
            ctx.Request.ContentLength = bytes.Length;
            ctx.Request.ContentType = "application/json";
        }
        ctx.Response.Body = new MemoryStream();
        return ctx;
    }

    [Fact]
    public async Task Delete_WithBody_ForwardsBodyToUpstream()
    {
        var (mw, handler) = Build();
        const string body = "{\"endpoint\":\"https://push.example.com/abc\"}";
        var ctx = AuthedContext(HttpMethods.Delete, "/api/v1/push/subscriptions", body);

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(HttpMethod.Delete, handler.CapturedMethod);
        Assert.Equal(body, handler.CapturedBody);
        Assert.Equal(StatusCodes.Status204NoContent, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task Delete_WithoutBody_ForwardsNoBody()
    {
        var (mw, handler) = Build();
        var ctx = AuthedContext(HttpMethods.Delete, "/api/v1/issues/sk-1/watch", body: null);

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(HttpMethod.Delete, handler.CapturedMethod);
        Assert.Null(handler.CapturedBody);
    }

    [Fact]
    public async Task Get_ForwardsNoBody()
    {
        var (mw, handler) = Build();
        var ctx = AuthedContext(HttpMethods.Get, "/api/v1/push/config", body: null);

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(HttpMethod.Get, handler.CapturedMethod);
        Assert.Null(handler.CapturedBody);
    }

    [Fact]
    public async Task Post_StillForwardsBody()
    {
        // Regression guard: the existing POST body path must keep working.
        var (mw, handler) = Build();
        const string body = "{\"endpoint\":\"https://push.example.com/abc\",\"keys\":{}}";
        var ctx = AuthedContext(HttpMethods.Post, "/api/v1/push/subscriptions", body);

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(HttpMethod.Post, handler.CapturedMethod);
        Assert.Equal(body, handler.CapturedBody);
    }

    [Fact]
    public async Task Put_ForwardsBody()
    {
        // /me/push-prefs (and /me/theme) ride PUT with a JSON body.
        var (mw, handler) = Build();
        const string body = "{\"enabled\":true}";
        var ctx = AuthedContext(HttpMethods.Put, "/api/v1/me/push-prefs", body);

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(HttpMethod.Put, handler.CapturedMethod);
        Assert.Equal(body, handler.CapturedBody);
    }
}
