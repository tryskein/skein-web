using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SkeinWeb.Auth;
using SkeinWeb.Middleware;

namespace SkeinWeb.Tests.Middleware;

/// <summary>
/// sk-304 — the BFF must not be where OAuth discovery dies.
///
/// An MCP client reaching skein-mcp.example.com talks to skein-web, which
/// reverse-proxies to skein-api. Two things have to survive that hop or the
/// client cannot connect with a static credential at all:
///
/// <list type="number">
///   <item><description>
///     <c>GET /.well-known/oauth-protected-resource</c> and
///     <c>GET /.well-known/oauth-protected-resource/mcp</c> must be forwarded
///     upstream — unauthenticated. This image serves no SPA and has no
///     catch-all, so an unmatched path is a 404 and the client never sees the
///     metadata document.
///   </description></item>
///   <item><description>
///     The <c>WWW-Authenticate</c> header skein-api puts on a 401 from
///     <c>/mcp</c> (RFC 9728 §5.1) must be copied back verbatim. It is the
///     client's primary discovery route per the MCP authorization spec.
///   </description></item>
/// </list>
/// </summary>
public class McpProxyMiddlewareMetadataTest
{
    private const string UpstreamBase = "http://skein-api.test";

    private sealed class ScriptedHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        private readonly string? _wwwAuthenticate;

        public ScriptedHandler(HttpStatusCode status, string? wwwAuthenticate = null)
        {
            _status = status;
            _wwwAuthenticate = wwwAuthenticate;
        }

        public HttpRequestMessage? Captured { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Captured = request;
            var resp = new HttpResponseMessage(_status)
            {
                Content = new StringContent(
                    "{\"resource\":\"https://skein-mcp.test/mcp\"}"),
            };
            resp.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            if (_wwwAuthenticate is not null)
            {
                resp.Headers.TryAddWithoutValidation("WWW-Authenticate", _wwwAuthenticate);
            }
            return Task.FromResult(resp);
        }
    }

    private sealed class StubHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;
        public StubHttpClientFactory(HttpMessageHandler handler) => _handler = handler;
        public HttpClient CreateClient(string name) =>
            new(_handler, disposeHandler: false) { BaseAddress = new Uri(UpstreamBase) };
    }

    private static (McpProxyMiddleware mw, ScriptedHandler handler) Build(
        HttpStatusCode status = HttpStatusCode.OK, string? wwwAuthenticate = null)
    {
        var handler = new ScriptedHandler(status, wwwAuthenticate);
        var mw = new McpProxyMiddleware(
            new StubHttpClientFactory(handler),
            Options.Create(new SkeinApiOptions
            {
                Url = UpstreamBase,
                InternalSecret = "s",
            }),
            TimeProvider.System,
            NullLogger<McpProxyMiddleware>.Instance);
        return (mw, handler);
    }

    private static DefaultHttpContext Request(string method, string path)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = method;
        ctx.Request.Path = path;
        ctx.Request.Host = new HostString("skein-mcp.test");
        ctx.Request.Body = new MemoryStream();
        ctx.Request.ContentLength = 0;
        ctx.Response.Body = new MemoryStream();
        return ctx;
    }

    [Theory]
    [InlineData("/.well-known/oauth-protected-resource")]
    [InlineData("/.well-known/oauth-protected-resource/mcp")]
    public async Task MetadataPaths_AreProxiedUpstream_WithoutCredentials(string path)
    {
        var (mw, handler) = Build();
        var ctx = Request(HttpMethods.Get, path);
        var nextCalled = false;

        await mw.InvokeAsync(ctx, _ => { nextCalled = true; return Task.CompletedTask; });

        Assert.False(nextCalled); // terminated here, not passed down to a 404
        Assert.NotNull(handler.Captured);
        Assert.Equal(UpstreamBase + path, handler.Captured!.RequestUri!.ToString());
        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
        Assert.Equal("application/json", ctx.Response.Headers["Content-Type"].ToString());

        // The "WithoutCredentials" half of the name (sk-304 review F7). The
        // first cut asserted nothing about credentials at all, so the name was
        // a claim the test did not back. A discovery document is fetched by a
        // client that cannot authenticate; forwarding a browser's session
        // cookie with it would make an unauthenticated public probe carry a
        // logged-in user's credential upstream.
        AssertNoCredentialsForwarded(handler.Captured!);
    }

    /// <summary>
    /// <c>Authorization</c> and <c>Cookie</c> must never reach skein-api
    /// through this middleware (McpProxyMiddleware, the two Header.Equals
    /// guards in the request-forwarding loop) — sk-304 review F7.
    ///
    /// There was no test on this at all, on either proxied path. That is a
    /// hole aimed squarely at tomorrow: sk-304 stage 2 (accepting a static
    /// <c>ska_</c> key in <c>Authorization</c>) edits exactly this header
    /// loop, and without a red test the leak it could introduce — a browser
    /// session cookie, or an OAuth bearer token minted for somebody else,
    /// forwarded to a service that trusts what the BFF hands it — would ship
    /// green.
    ///
    /// Asserted for both metadata paths and <c>/mcp</c> itself, because the
    /// strip happens once for all of them and a future path-conditional strip
    /// must be caught here.
    /// </summary>
    [Theory]
    [InlineData("/.well-known/oauth-protected-resource")]
    [InlineData("/.well-known/oauth-protected-resource/mcp")]
    [InlineData("/mcp")]
    public async Task ProxiedPaths_StripAuthorizationAndCookie(string path)
    {
        var (mw, handler) = Build();
        var ctx = Request(path == "/mcp" ? HttpMethods.Post : HttpMethods.Get, path);
        ctx.Request.Headers["Authorization"] = "Bearer a-token-that-must-not-travel";
        ctx.Request.Headers["Cookie"] = ".AspNetCore.Cookies=a-session-that-must-not-travel";
        // A header that MUST survive, so the assertion below cannot pass
        // trivially by the forwarding loop dropping everything.
        ctx.Request.Headers["X-Skein-Api-Key"] = "ska_live_key";

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.NotNull(handler.Captured);
        AssertNoCredentialsForwarded(handler.Captured!);
        Assert.True(
            handler.Captured!.Headers.TryGetValues("X-Skein-Api-Key", out var apiKey),
            "X-Skein-Api-Key must be forwarded verbatim — it is the MCP credential");
        Assert.Equal("ska_live_key", string.Join(",", apiKey!));
    }

    private static void AssertNoCredentialsForwarded(HttpRequestMessage upstream)
    {
        Assert.False(
            upstream.Headers.TryGetValues("Authorization", out var auth),
            $"Authorization was forwarded upstream: {string.Join(",", auth ?? Array.Empty<string>())}. "
            + "Agents authenticate with X-Skein-Api-Key only; accepting a bearer token is "
            + "sk-304 stage 2 and needs skein-api to understand it first.");
        Assert.False(
            upstream.Headers.TryGetValues("Cookie", out var cookie),
            $"Cookie was forwarded upstream: {string.Join(",", cookie ?? Array.Empty<string>())}. "
            + "Cookies belong to the browser flow on /api/v1/*; they have no consumer here "
            + "and leaking them across channels is pure attack surface.");
    }

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/oauth-protected-resource/other")]
    [InlineData("/.well-known/oauth-authorization-server")]
    [InlineData("/api/v1/issues")]
    public async Task OtherPaths_AreNotClaimed(string path)
    {
        // The opt-in is two exact paths — not a /.well-known prefix. A prefix
        // match would silently hand unrelated discovery documents to skein-api.
        var (mw, handler) = Build();
        var ctx = Request(HttpMethods.Get, path);
        var nextCalled = false;

        await mw.InvokeAsync(ctx, _ => { nextCalled = true; return Task.CompletedTask; });

        Assert.True(nextCalled);
        Assert.Null(handler.Captured);
    }

    [Fact]
    public async Task WwwAuthenticateHeader_SurvivesTheProxyHop()
    {
        const string challenge =
            "Bearer resource_metadata=\"https://skein-mcp.test/.well-known/oauth-protected-resource/mcp\"";
        var (mw, _) = Build(HttpStatusCode.Unauthorized, challenge);
        var ctx = Request(HttpMethods.Post, "/mcp");

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
        Assert.Equal(challenge, ctx.Response.Headers["WWW-Authenticate"].ToString());
    }
}
