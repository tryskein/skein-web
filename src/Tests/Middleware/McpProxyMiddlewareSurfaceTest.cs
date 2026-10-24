using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SkeinWeb.Auth;
using SkeinWeb.Middleware;

namespace SkeinWeb.Tests.Middleware;

/// <summary>
/// Pins the surface marker stamped by <see cref="McpProxyMiddleware"/> on
/// every <c>/mcp</c> request — <c>X-Skein-Surface: internal</c> — which is
/// what skein-api's api-key gate consults: present ⇒ internal-owner keys are
/// allowed; absent ⇒ public, internal-owner keys get 403.
///
/// sk-303.8 — this used to be a Host-based fail-closed allowlist (sk-163
/// S7a, SKEIN_INTERNAL_HOSTS): stamp only when Request.Host matched a
/// configured internal host. That allowlist was removed — it derived a
/// privilege decision from a header the CLIENT controls, and it never
/// actually divided anything in this deployment (both routes to skein-web go
/// through the internal gateway; no public route exists). See
/// McpProxyMiddleware for the fuller rationale. The marker is now stamped
/// unconditionally — the empty-allowlist behaviour this class always ran
/// under in production, made permanent. What is still worth pinning:
///   - the marker is stamped on EVERY request, regardless of Host;
///   - a CLIENT-supplied <c>X-Skein-Surface</c> is stripped and never
///     forwarded — the client can't forge or override the marker.
/// </summary>
public class McpProxyMiddlewareSurfaceTest
{
    private const string UpstreamBase = "http://skein-api.test";

    /// <summary>Captures the headers the proxy forwards upstream.</summary>
    private sealed class CapturingHandler : HttpMessageHandler
    {
        public HttpRequestMessage? Captured { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Captured = request;
            // Minimal upstream response so the proxy's copy-back path runs.
            var resp = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{}"),
            };
            return Task.FromResult(resp);
        }

        public string? SurfaceValue =>
            Captured is not null &&
            Captured.Headers.TryGetValues(SkeinHeaders.Surface, out var v)
                ? string.Join(",", v)
                : null;
    }

    private sealed class StubHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;
        public StubHttpClientFactory(HttpMessageHandler handler) => _handler = handler;
        public HttpClient CreateClient(string name) =>
            new(_handler, disposeHandler: false) { BaseAddress = new Uri(UpstreamBase) };
    }

    private static (McpProxyMiddleware mw, CapturingHandler handler) Build()
    {
        var handler = new CapturingHandler();
        var factory = new StubHttpClientFactory(handler);
        var opts = Options.Create(new SkeinApiOptions
        {
            Url = UpstreamBase,
            InternalSecret = "s",
        });
        var mw = new McpProxyMiddleware(factory, opts, TimeProvider.System, NullLogger<McpProxyMiddleware>.Instance);
        return (mw, handler);
    }

    private static DefaultHttpContext McpContext(string? host, string? clientSuppliedSurface = null)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = HttpMethods.Post;
        ctx.Request.Path = "/mcp";
        if (host is not null)
        {
            ctx.Request.Host = new HostString(host);
        }
        // host == null ⇒ leave Host unset (HostString.HasValue == false).
        ctx.Request.Headers[SkeinHeaders.ApiKey] = "ska_dummy";
        if (clientSuppliedSurface is not null)
        {
            // A malicious client tries to assert the trusted marker itself.
            ctx.Request.Headers[SkeinHeaders.Surface] = clientSuppliedSurface;
        }
        ctx.Request.Body = new MemoryStream();
        ctx.Request.ContentLength = 0;
        ctx.Response.Body = new MemoryStream();
        return ctx;
    }

    [Theory]
    [InlineData("anything.example")]
    [InlineData("evil.attacker.com")]
    [InlineData(null)]
    public async Task StampsMarker_RegardlessOfHost(string? host)
    {
        // No Host-based classification any more: the marker is stamped on
        // every request, including an unrecognised or entirely missing Host.
        var (mw, handler) = Build();
        var ctx = McpContext(host);

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(SkeinHeaders.SurfaceInternal, handler.SurfaceValue);
    }

    [Fact]
    public async Task ClientSuppliedMarker_IsStripped_AndReplacedByOurs()
    {
        // A client tries to forge X-Skein-Surface: internal (or any other
        // value) itself. It must be stripped and never forwarded verbatim —
        // the forwarded value is always our own canonical "internal".
        var (mw, handler) = Build();
        var ctx = McpContext("anything.example", clientSuppliedSurface: "evil");

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(SkeinHeaders.SurfaceInternal, handler.SurfaceValue);
    }
}
