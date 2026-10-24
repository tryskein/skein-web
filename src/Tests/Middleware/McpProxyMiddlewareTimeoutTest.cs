using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using SkeinWeb.Auth;
using SkeinWeb.Middleware;

namespace SkeinWeb.Tests.Middleware;

/// <summary>
/// sk-608 regression: the <c>/mcp</c> upstream headers timeout comes from
/// <see cref="SkeinApiOptions.McpUpstreamHeadersTimeout"/> (not a literal), and
/// when it fires on a state-changing request the 504 keeps the existing
/// <c>error: "upstream_timeout"</c> code (502: <c>upstream_unavailable</c>) while adding
/// <c>outcome: "unknown"</c> — skein-api may already have committed the write,
/// so the caller must check before retrying. Production 2026-10-07: retried
/// epic_create calls answered 504 produced duplicate epics.
/// </summary>
public class McpProxyMiddlewareTimeoutTest
{
    private const string UpstreamBase = "http://skein-api.test";

    /// <summary>An upstream that never sends headers until it is cancelled.</summary>
    private sealed class HangingHandler : HttpMessageHandler
    {
        private readonly TaskCompletionSource<CancellationToken> _entered =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        /// <summary>Completes with the request's token once the proxy has sent it.</summary>
        public Task<CancellationToken> Entered => _entered.Task;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            _entered.TrySetResult(cancellationToken);
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("unreachable: the delay only ends by cancellation");
        }
    }

    private sealed class StubHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;
        public StubHttpClientFactory(HttpMessageHandler handler) => _handler = handler;
        public HttpClient CreateClient(string name) =>
            new(_handler, disposeHandler: false) { BaseAddress = new Uri(UpstreamBase) };
    }

    private static DefaultHttpContext Request(string method)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = method;
        ctx.Request.Path = "/mcp";
        ctx.Request.Headers[SkeinHeaders.ApiKey] = "ska_dummy";
        ctx.Request.Headers[SkeinHeaders.McpSessionId] = "sess-1";
        ctx.Request.Body = new MemoryStream();
        ctx.Request.ContentLength = 0;
        ctx.Response.Body = new MemoryStream();
        return ctx;
    }

    private static JsonElement ReadBody(HttpContext ctx)
    {
        ctx.Response.Body.Position = 0;
        using var doc = JsonDocument.Parse(ctx.Response.Body);
        return doc.RootElement.Clone();
    }

    /// <summary>
    /// Runs one request against a hanging upstream with a non-default
    /// configured timeout, and pins that the deadline is that value: one
    /// second short of it the upstream call is still live (the former 30 s
    /// literal would already have cut it), at it the call is cancelled (the
    /// 120 s default would not have) and the proxy answers 504.
    /// </summary>
    private static async Task<HttpContext> RunUntilTimeout(string method)
    {
        var configured = TimeSpan.FromSeconds(45);
        var clock = new FakeTimeProvider();
        var handler = new HangingHandler();
        var mw = new McpProxyMiddleware(
            new StubHttpClientFactory(handler),
            Options.Create(new SkeinApiOptions
            {
                Url = UpstreamBase,
                InternalSecret = "s",
                McpUpstreamHeadersTimeout = configured,
            }),
            clock,
            NullLogger<McpProxyMiddleware>.Instance);
        var ctx = Request(method);

        var run = mw.InvokeAsync(ctx, _ => Task.CompletedTask);
        // Guard against a hung test, not a measurement of the proxy.
        var upstreamToken = await handler.Entered.WaitAsync(TimeSpan.FromSeconds(10));

        clock.Advance(configured - TimeSpan.FromSeconds(1));
        Assert.False(upstreamToken.IsCancellationRequested,
            "the upstream call was cut before the configured timeout elapsed");

        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.True(upstreamToken.IsCancellationRequested,
            "the upstream call was not cut when the configured timeout elapsed");

        await run.WaitAsync(TimeSpan.FromSeconds(10));
        return ctx;
    }

    [Theory]
    [InlineData("POST")]
    [InlineData("DELETE")]
    public async Task StateChangingRequest_TimesOutAtConfiguredValue_With504OutcomeUnknown(string method)
    {
        var ctx = await RunUntilTimeout(method);

        Assert.Equal(StatusCodes.Status504GatewayTimeout, ctx.Response.StatusCode);
        var body = ReadBody(ctx);
        // The code clients already know is kept; the outcome is added beside it.
        Assert.Equal("upstream_timeout", body.GetProperty("error").GetString());
        Assert.Equal("unknown", body.GetProperty("outcome").GetString());
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("HEAD")]
    [InlineData("OPTIONS")]
    public async Task SafeRequest_TimesOut_With504WithoutOutcome(string method)
    {
        // A safe method changes nothing upstream: there is no write whose
        // fate could be unknown, so no outcome is claimed.
        var ctx = await RunUntilTimeout(method);

        Assert.Equal(StatusCodes.Status504GatewayTimeout, ctx.Response.StatusCode);
        var body = ReadBody(ctx);
        Assert.Equal("upstream_timeout", body.GetProperty("error").GetString());
        Assert.False(body.TryGetProperty("outcome", out _));
    }

    [Theory]
    [InlineData("30", 30)]
    [InlineData("120", 120)]
    [InlineData(" 3600 ", 3600)]
    public void ParseTimeout_AcceptsWholeSecondsInRange(string raw, int expectedSeconds)
    {
        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds),
            SkeinApiOptions.ParseMcpUpstreamHeadersTimeout(raw));
    }

    [Fact]
    public void ParseTimeout_UnsetMeans120Seconds()
    {
        Assert.Equal(TimeSpan.FromSeconds(120), SkeinApiOptions.ParseMcpUpstreamHeadersTimeout(null));
    }

    /// <summary>An upstream whose connection breaks: the request may or may
    /// not have reached skein-api before it did.</summary>
    private sealed class FailingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("connection reset by peer");
    }

    private static async Task<HttpContext> RunAgainstBrokenUpstream(string method)
    {
        var mw = new McpProxyMiddleware(
            new StubHttpClientFactory(new FailingHandler()),
            Options.Create(new SkeinApiOptions { Url = UpstreamBase, InternalSecret = "s" }),
            TimeProvider.System,
            NullLogger<McpProxyMiddleware>.Instance);
        var ctx = Request(method);
        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);
        return ctx;
    }

    [Theory]
    [InlineData("POST")]
    [InlineData("DELETE")]
    public async Task StateChangingRequest_UpstreamUnavailable_502OutcomeUnknown(string method)
    {
        var ctx = await RunAgainstBrokenUpstream(method);

        Assert.Equal(StatusCodes.Status502BadGateway, ctx.Response.StatusCode);
        var body = ReadBody(ctx);
        Assert.Equal("upstream_unavailable", body.GetProperty("error").GetString());
        Assert.Equal("unknown", body.GetProperty("outcome").GetString());
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("HEAD")]
    [InlineData("OPTIONS")]
    public async Task SafeRequest_UpstreamUnavailable_502WithoutOutcome(string method)
    {
        var ctx = await RunAgainstBrokenUpstream(method);

        Assert.Equal(StatusCodes.Status502BadGateway, ctx.Response.StatusCode);
        var body = ReadBody(ctx);
        Assert.Equal("upstream_unavailable", body.GetProperty("error").GetString());
        Assert.False(body.TryGetProperty("outcome", out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData("abc")]
    [InlineData("1.5")]
    [InlineData("-40")]
    [InlineData("29")]
    [InlineData("3601")]
    public void ParseTimeout_RejectsInvalidValue(string raw)
    {
        Assert.Throws<InvalidOperationException>(
            () => SkeinApiOptions.ParseMcpUpstreamHeadersTimeout(raw));
    }
}
