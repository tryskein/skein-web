using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SkeinWeb.Auth;
using SkeinWeb.Middleware;

namespace SkeinWeb.Tests.Middleware;

/// <summary>
/// Pins which browser request headers <see cref="ApiProxyMiddleware"/> carries
/// to skein-api. skein-api identifies the caller only by the X-Skein-* headers
/// the BFF mints, so the session cookie, <c>Authorization</c> and the
/// client-controlled address headers (<c>X-Forwarded-*</c>, <c>X-Real-IP</c>)
/// stay at the BFF, while ordinary request headers still pass through.
/// </summary>
public class ApiProxyMiddlewareHeaderForwardingTest
{
    private const string UpstreamBase = "http://skein-api.test";

    private sealed class CapturingHandler : HttpMessageHandler
    {
        public HttpRequestMessage? Captured { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Captured = request;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    private sealed class StubHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(handler, disposeHandler: false) { BaseAddress = new Uri(UpstreamBase) };
    }

    private static async Task<HttpRequestMessage> ProxyAsync(string headerName, string headerValue)
    {
        var handler = new CapturingHandler();
        var options = Options.Create(new SkeinApiOptions { Url = UpstreamBase, InternalSecret = "s" });
        var middleware = new ApiProxyMiddleware(
            new StubHttpClientFactory(handler), options, NullLogger<ApiProxyMiddleware>.Instance);

        var ctx = new DefaultHttpContext();
        ctx.Request.Method = "GET";
        ctx.Request.Path = "/api/v1/projects";
        ctx.Request.Headers[headerName] = headerValue;
        ctx.User = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString())],
            authenticationType: "Cookies"));
        ctx.Response.Body = new MemoryStream();

        await middleware.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.NotNull(handler.Captured);
        return handler.Captured;
    }

    [Theory]
    [InlineData("Cookie", "skein.sid=CfDJ8session")]
    [InlineData("cookie", "skein.sid=CfDJ8session")]
    [InlineData("Authorization", "Bearer ska_browser")]
    [InlineData("X-Forwarded-For", "203.0.113.7")]
    [InlineData("X-Forwarded-Host", "evil.example")]
    [InlineData("X-Forwarded-Proto", "https")]
    [InlineData("x-forwarded-port", "443")]
    [InlineData("X-Real-IP", "203.0.113.7")]
    public async Task Browser_only_header_is_not_forwarded(string name, string value)
    {
        var upstream = await ProxyAsync(name, value);

        Assert.False(upstream.Headers.Contains(name), $"{name} reached skein-api");
    }

    [Theory]
    [InlineData("Accept-Language", "ru")]
    [InlineData("If-None-Match", "\"v1\"")]
    [InlineData("X-Request-Id", "req-1")]
    public async Task Ordinary_header_is_forwarded(string name, string value)
    {
        var upstream = await ProxyAsync(name, value);

        Assert.True(upstream.Headers.TryGetValues(name, out var values), $"{name} was dropped");
        Assert.Equal([value], values);
    }
}
