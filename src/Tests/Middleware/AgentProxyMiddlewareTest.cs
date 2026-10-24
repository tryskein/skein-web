using System.Net;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SkeinWeb.Auth;
using SkeinWeb.Middleware;

namespace SkeinWeb.Tests.Middleware;

/// <summary>
/// Pins the behaviour of <see cref="AgentProxyMiddleware"/> — the BFF
/// passthrough for the agent data-plane <c>/agent/v1/*</c> (sk-142).
///
/// The load-bearing decisions under test:
/// <list type="bullet">
///   <item><description>
///     <b>Segment-boundary matching.</b> <c>/agent/v1</c> and anything under
///     it are proxied; the sibling paths <c>/agent</c>, <c>/agentx</c>,
///     <c>/agent/v10</c>, <c>/agent/v2</c> and the cookie-gated
///     <c>/api/v1/*</c> are NOT — they fall through to <c>next</c>. This is the
///     exact reason the middleware cannot reuse McpProxy's exact-match
///     <c>IsMcpPath</c>.
///   </description></item>
///   <item><description>
///     <b>Header policy.</b> <c>X-Skein-Api-Key</c> is forwarded verbatim;
///     inbound <c>Cookie</c>/<c>Authorization</c> and spoofable
///     <c>X-Skein-User-*</c> are stripped; <c>X-Skein-Internal-Secret</c> is
///     added by the BFF.
///   </description></item>
///   <item><description>
///     <b>No cookie required.</b> The proxy forwards even when no
///     authenticated principal is attached to the context.
///   </description></item>
/// </list>
/// </summary>
public class AgentProxyMiddlewareTest
{
    private const string UpstreamBase = "http://skein-api.test";
    private const string InternalSecret = "channel-secret";

    /// <summary>Captures the request the proxy forwards upstream.</summary>
    private sealed class CapturingHandler : HttpMessageHandler
    {
        public HttpRequestMessage? Captured { get; private set; }
        public string? CapturedBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Captured = request;
            CapturedBody = request.Content is null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"ok\":true}", Encoding.UTF8, "application/json"),
            };
        }
    }

    private sealed class StubHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;
        public StubHttpClientFactory(HttpMessageHandler handler) => _handler = handler;
        public HttpClient CreateClient(string name) =>
            new(_handler, disposeHandler: false) { BaseAddress = new Uri(UpstreamBase) };
    }

    private static (AgentProxyMiddleware mw, CapturingHandler handler) Build()
    {
        var handler = new CapturingHandler();
        var factory = new StubHttpClientFactory(handler);
        var opts = Options.Create(new SkeinApiOptions { Url = UpstreamBase, InternalSecret = InternalSecret });
        var mw = new AgentProxyMiddleware(factory, opts, NullLogger<AgentProxyMiddleware>.Instance);
        return (mw, handler);
    }

    /// <summary>
    /// A context with NO authenticated principal (agents do not carry a cookie)
    /// and a response body sink. Headers/body are configured by the caller.
    /// </summary>
    private static DefaultHttpContext AgentContext(string method, string path, string? query = null)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = method;
        ctx.Request.Path = path;
        if (query is not null)
        {
            ctx.Request.QueryString = new QueryString(query);
        }
        ctx.Response.Body = new MemoryStream();
        return ctx;
    }

    // ---- Positive: /agent/v1[/...] is proxied without a cookie --------------

    [Theory]
    [InlineData("/agent/v1")]
    [InlineData("/agent/v1/notifications/poll")]
    [InlineData("/agent/v1/monitor-script")]
    public async Task AgentV1Paths_AreProxiedUpstream_WithoutCookie(string path)
    {
        var (mw, handler) = Build();
        var ctx = AgentContext(HttpMethods.Get, path);
        var nextCalled = false;

        await mw.InvokeAsync(ctx, _ => { nextCalled = true; return Task.CompletedTask; });

        Assert.False(nextCalled);                       // middleware handled it
        Assert.NotNull(handler.Captured);               // it was forwarded
        Assert.Equal(UpstreamBase + path, handler.Captured!.RequestUri!.ToString());
        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task Poll_PreservesQueryString()
    {
        var (mw, handler) = Build();
        var ctx = AgentContext(HttpMethods.Get, "/agent/v1/notifications/poll", "?since_ts=10&since_id=abc");

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.NotNull(handler.Captured);
        Assert.Equal(
            UpstreamBase + "/agent/v1/notifications/poll?since_ts=10&since_id=abc",
            handler.Captured!.RequestUri!.ToString());
    }

    // ---- Negative: sibling paths fall through to next ----------------------

    [Theory]
    [InlineData("/agent")]
    [InlineData("/agentx")]
    [InlineData("/agent/v10")]
    [InlineData("/agent/v2")]
    [InlineData("/agent/v1x")]
    [InlineData("/api/v1/issues/sk-1")]
    [InlineData("/mcp")]
    [InlineData("/")]
    public async Task NonAgentV1Paths_FallThroughToNext(string path)
    {
        var (mw, handler) = Build();
        var ctx = AgentContext(HttpMethods.Get, path);
        var nextCalled = false;

        await mw.InvokeAsync(ctx, _ => { nextCalled = true; return Task.CompletedTask; });

        Assert.True(nextCalled);          // passed down the pipeline
        Assert.Null(handler.Captured);    // NOT forwarded upstream by this middleware
    }

    // ---- Security: dot-segment traversal is rejected fail-closed -----------

    /// <summary>
    /// A path that matches the <c>/agent/v1</c> prefix but contains a relative
    /// dot-segment (<c>.</c> / <c>..</c>) must be rejected with 400 and never
    /// forwarded upstream — otherwise <see cref="Uri"/> would normalize the
    /// traversal out of the <c>/agent/v1</c> subtree (e.g. to <c>/api/v1/*</c>)
    /// while still attaching the BFF internal secret, a privilege bypass.
    /// It must also NOT fall through to <c>next</c> (the cookie-gated pipeline).
    /// </summary>
    [Theory]
    [InlineData("/agent/v1/../../api/v1/issues")]
    [InlineData("/agent/v1/../api/v1/issues")]
    [InlineData("/agent/v1/.")]
    [InlineData("/agent/v1/foo/../bar")]
    public async Task DotSegmentPaths_Are400_AndNeverForwarded(string path)
    {
        var (mw, handler) = Build();
        var ctx = AgentContext(HttpMethods.Get, path);
        ctx.Request.Headers[SkeinHeaders.ApiKey] = "skm_token";
        var nextCalled = false;

        await mw.InvokeAsync(ctx, _ => { nextCalled = true; return Task.CompletedTask; });

        Assert.Equal(StatusCodes.Status400BadRequest, ctx.Response.StatusCode);
        Assert.Null(handler.Captured);   // never built/sent upstream -> internal secret never attached
        Assert.False(nextCalled);        // never falls into the cookie-gated /api/v1 pipeline

        ctx.Response.Body.Position = 0;
        var body = await new StreamReader(ctx.Response.Body).ReadToEndAsync();
        Assert.Contains("invalid_path", body);
    }

    /// <summary>
    /// The percent-encoded traversal <c>/agent/v1/%2e%2e/api/v1/issues</c> is
    /// rejected too. The real ASP.NET pipeline percent-decodes the path before
    /// middleware runs, so <c>%2e%2e</c> reaches <c>Request.Path</c> as a
    /// literal <c>..</c> segment; <see cref="DefaultHttpContext"/> bypasses that
    /// URL-decoder, so we set the post-decode form ASP.NET would produce.
    /// </summary>
    [Fact]
    public async Task EncodedDotSegmentPath_Is400_AndNeverForwarded()
    {
        var (mw, handler) = Build();
        var decoded = "/agent/v1/" + Uri.UnescapeDataString("%2e%2e") + "/api/v1/issues";
        Assert.Equal("/agent/v1/../api/v1/issues", decoded); // confirms %2e%2e -> ..
        var ctx = AgentContext(HttpMethods.Get, decoded);
        var nextCalled = false;

        await mw.InvokeAsync(ctx, _ => { nextCalled = true; return Task.CompletedTask; });

        Assert.Equal(StatusCodes.Status400BadRequest, ctx.Response.StatusCode);
        Assert.Null(handler.Captured);
        Assert.False(nextCalled);
    }

    // ---- Header policy -----------------------------------------------------

    [Fact]
    public async Task ApiKey_IsForwarded_InternalSecret_IsAdded_CookieAndAuth_AreStripped()
    {
        var (mw, handler) = Build();
        var ctx = AgentContext(HttpMethods.Get, "/agent/v1/notifications/poll");
        ctx.Request.Headers[SkeinHeaders.ApiKey] = "skm_test-monitor-token";
        ctx.Request.Headers["Cookie"] = "skein.sid=secret";
        ctx.Request.Headers["Authorization"] = "Bearer leak-me";

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.NotNull(handler.Captured);
        var fwd = handler.Captured!;

        Assert.True(fwd.Headers.TryGetValues(SkeinHeaders.ApiKey, out var apiKey));
        Assert.Equal("skm_test-monitor-token", Assert.Single(apiKey!));

        Assert.True(fwd.Headers.TryGetValues(SkeinHeaders.InternalSecret, out var secret));
        Assert.Equal(InternalSecret, Assert.Single(secret!));

        Assert.False(fwd.Headers.Contains("Cookie"));
        Assert.False(fwd.Headers.Contains("Authorization"));
    }

    [Fact]
    public async Task InboundUserHeaders_AreStrippedBeforeForwarding()
    {
        var (mw, handler) = Build();
        var ctx = AgentContext(HttpMethods.Get, "/agent/v1/notifications/poll");
        ctx.Request.Headers[SkeinHeaders.ApiKey] = "skm_token";
        ctx.Request.Headers[SkeinHeaders.UserId] = Guid.NewGuid().ToString();
        ctx.Request.Headers[SkeinHeaders.UserEmail] = "attacker@example.com";
        ctx.Request.Headers[SkeinHeaders.Username] = "attacker";
        ctx.Request.Headers[SkeinHeaders.UserRole] = "admin";

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        // Stripped from the inbound request itself (defence-in-depth)...
        Assert.False(ctx.Request.Headers.ContainsKey(SkeinHeaders.UserId));
        Assert.False(ctx.Request.Headers.ContainsKey(SkeinHeaders.UserEmail));
        Assert.False(ctx.Request.Headers.ContainsKey(SkeinHeaders.Username));
        Assert.False(ctx.Request.Headers.ContainsKey(SkeinHeaders.UserRole));

        // ...and therefore never reach the upstream.
        var fwd = handler.Captured!;
        Assert.False(fwd.Headers.Contains(SkeinHeaders.UserId));
        Assert.False(fwd.Headers.Contains(SkeinHeaders.UserEmail));
        Assert.False(fwd.Headers.Contains(SkeinHeaders.Username));
        Assert.False(fwd.Headers.Contains(SkeinHeaders.UserRole));

        // The api-key is NOT stripped — it is the agent's credential.
        Assert.True(ctx.Request.Headers.ContainsKey(SkeinHeaders.ApiKey));
        Assert.True(fwd.Headers.Contains(SkeinHeaders.ApiKey));
    }

    // ---- Method + body passthrough ----------------------------------------

    [Fact]
    public async Task UpstreamMethod_IsPreserved()
    {
        var (mw, handler) = Build();
        var ctx = AgentContext(HttpMethods.Get, "/agent/v1/monitor-script");

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(HttpMethod.Get, handler.Captured!.Method);
    }

    // ---- Upstream RESPONSE passthrough (G4) --------------------------------
    //
    // The CapturingHandler above always returns 200 + a tiny body, so it proves
    // request forwarding but NOT that the middleware copies the upstream
    // response back verbatim. These tests stub a controllable upstream response
    // (status + headers + body) via a delegating handler — the SAME injection
    // path the existing tests use (HttpMessageHandler -> StubHttpClientFactory),
    // no real HTTP server — and assert status, headers, and body reach the
    // client response.

    /// <summary>
    /// A delegating handler that returns a caller-supplied response, so a test
    /// can drive the exact status/headers/body the proxy must copy back. Same
    /// stub seam as <see cref="CapturingHandler"/>, just with a controllable
    /// response.
    /// </summary>
    private sealed class RespondingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;
        public HttpRequestMessage? Captured { get; private set; }

        public RespondingHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) =>
            _responder = responder;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Captured = request;
            return Task.FromResult(_responder(request));
        }
    }

    /// <summary>
    /// HttpContent that emits its payload across multiple flushed writes, so the
    /// upstream body genuinely arrives in several chunks and the proxy's chunked
    /// <c>CopyToAsync</c> loop is exercised end-to-end.
    /// </summary>
    private sealed class MultiWriteContent : HttpContent
    {
        private readonly byte[][] _chunks;
        public MultiWriteContent(params string[] chunks) =>
            _chunks = chunks.Select(c => Encoding.UTF8.GetBytes(c)).ToArray();

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            foreach (var chunk in _chunks)
            {
                await stream.WriteAsync(chunk);
                await stream.FlushAsync();
            }
        }

        protected override bool TryComputeLength(out long length)
        {
            length = _chunks.Sum(c => (long)c.Length);
            return true;
        }
    }

    private static (AgentProxyMiddleware mw, RespondingHandler handler) BuildWith(
        Func<HttpRequestMessage, HttpResponseMessage> responder)
    {
        var handler = new RespondingHandler(responder);
        var factory = new StubHttpClientFactory(handler);
        var opts = Options.Create(new SkeinApiOptions { Url = UpstreamBase, InternalSecret = InternalSecret });
        var mw = new AgentProxyMiddleware(factory, opts, NullLogger<AgentProxyMiddleware>.Instance);
        return (mw, handler);
    }

    /// <summary>
    /// A real upstream non-200 status is propagated verbatim — NOT rewritten to
    /// 200 and NOT collapsed into the proxy's own 502 (which is reserved for an
    /// unreachable upstream / <see cref="HttpRequestException"/>). 429 matters
    /// most: the runner's backoff keys off it.
    /// </summary>
    [Theory]
    [InlineData(401)]
    [InlineData(429)]
    [InlineData(500)]
    public async Task UpstreamStatus_IsPropagatedVerbatim_NotRewritten(int status)
    {
        var (mw, _) = BuildWith(_ => new HttpResponseMessage((HttpStatusCode)status)
        {
            Content = new StringContent("{\"upstream\":true}", Encoding.UTF8, "application/json"),
        });
        var ctx = AgentContext(HttpMethods.Get, "/agent/v1/notifications/poll");

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(status, ctx.Response.StatusCode);
        // Distinguish a real upstream status from the proxy's own 502/504.
        Assert.NotEqual(StatusCodes.Status502BadGateway, ctx.Response.StatusCode);
        Assert.NotEqual(StatusCodes.Status504GatewayTimeout, ctx.Response.StatusCode);
    }

    /// <summary>
    /// Upstream response headers reach the client. <c>Retry-After</c> is a
    /// response-level header; <c>Content-Type</c> is a content-level header —
    /// the proxy copies BOTH header collections, so this pins both branches.
    /// </summary>
    [Fact]
    public async Task UpstreamResponseHeaders_ArePropagated()
    {
        var (mw, _) = BuildWith(_ =>
        {
            var resp = new HttpResponseMessage(HttpStatusCode.TooManyRequests)
            {
                Content = new StringContent("rate limited", Encoding.UTF8, "application/json"),
            };
            // Response-level header (HttpResponseMessage.Headers).
            resp.Headers.TryAddWithoutValidation("Retry-After", "5");
            return resp;
        });
        var ctx = AgentContext(HttpMethods.Get, "/agent/v1/notifications/poll");

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(StatusCodes.Status429TooManyRequests, ctx.Response.StatusCode);
        Assert.Equal("5", ctx.Response.Headers["Retry-After"].ToString());
        // Content-level header crossed over too (charset is appended by StringContent).
        Assert.Contains("application/json", ctx.Response.Headers["Content-Type"].ToString());
    }

    /// <summary>
    /// An SSE-style <c>text/event-stream</c> content-type survives the copy —
    /// the poll endpoint can degrade to a streamed long-poll, so this media type
    /// must not be rewritten.
    /// </summary>
    [Fact]
    public async Task UpstreamEventStreamContentType_IsPropagated()
    {
        var (mw, _) = BuildWith(_ =>
        {
            var content = new StringContent("data: hello\n\n", Encoding.UTF8);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("text/event-stream");
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
        });
        var ctx = AgentContext(HttpMethods.Get, "/agent/v1/notifications/poll");

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
        Assert.Contains("text/event-stream", ctx.Response.Headers["Content-Type"].ToString());
    }

    /// <summary>
    /// A non-trivial body larger than the proxy's 4 KiB chunk buffer is copied
    /// byte-for-byte — forces several <c>CopyToAsync</c> buffer iterations.
    /// </summary>
    [Fact]
    public async Task UpstreamResponseBody_IsCopiedVerbatim()
    {
        // 22000 bytes > ChunkBufferBytes (4096) -> multiple copy iterations.
        var payload = string.Concat(Enumerable.Repeat("chunk-data-0123456789;", 1000));
        var (mw, _) = BuildWith(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(payload, Encoding.UTF8, "application/json"),
        });
        var ctx = AgentContext(HttpMethods.Get, "/agent/v1/notifications/poll");

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        ctx.Response.Body.Position = 0;
        var body = await new StreamReader(ctx.Response.Body).ReadToEndAsync();
        Assert.Equal(payload, body);
    }

    /// <summary>
    /// A multi-segment upstream body is delivered intact and IN ORDER —
    /// exercises the chunked copy loop's ordering/concatenation. NOTE: this
    /// does not prove true live chunk-boundary streaming (the custom
    /// HttpContent may be materialized before the proxy copies); it pins the
    /// ordered multi-segment passthrough, not real-time flush semantics.
    /// </summary>
    [Fact]
    public async Task UpstreamMultiSegmentBody_IsCopiedInOrder()
    {
        var (mw, _) = BuildWith(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new MultiWriteContent("event-1\n", "event-2\n", "event-3\n"),
        });
        var ctx = AgentContext(HttpMethods.Get, "/agent/v1/notifications/poll");

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        ctx.Response.Body.Position = 0;
        var body = await new StreamReader(ctx.Response.Body).ReadToEndAsync();
        Assert.Equal("event-1\nevent-2\nevent-3\n", body);
    }
}
