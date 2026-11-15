using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SkeinWeb.Auth;
using SkeinWeb.Middleware;

namespace SkeinWeb.Tests.Middleware;

/// <summary>
/// Regression: when skein-api is unreachable the proxies log the failure, and
/// that log line must not carry a link token from the path or anything from
/// the query string. Every value the line holds is checked — the rendered
/// message, its structured fields and the fields of the active scopes.
/// </summary>
public class ProxyFailureLogTest
{
    private const string UpstreamBase = "http://skein-api.test";
    private const string LinkToken = "linktokenfixturelinktokenfixturelinktokenfi";
    private const string QuerySecret = "querysecretvalue";

    private sealed class UnreachableHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("Connection refused");
    }

    private sealed class StubHttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(new UnreachableHandler()) { BaseAddress = new Uri(UpstreamBase) };
    }

    /// <summary>Everything a log call put on the record, as text.</summary>
    private sealed class RecordingLogger<T> : ILogger<T>
    {
        private readonly Stack<object> _scopes = new();
        public List<(LogLevel Level, List<string> Values)> Records { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
        {
            _scopes.Push(state);
            return new Pop(_scopes);
        }

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var values = new List<string> { formatter(state, exception) };
            foreach (var item in _scopes.Prepend((object)state!))
            {
                if (item is IEnumerable<KeyValuePair<string, object?>> pairs)
                {
                    values.AddRange(pairs.Select(p => $"{p.Key}={p.Value}"));
                }
            }
            Records.Add((logLevel, values));
        }

        private sealed class Pop(Stack<object> scopes) : IDisposable
        {
            public void Dispose() => scopes.Pop();
        }
    }

    private static IOptions<SkeinApiOptions> Options() =>
        Microsoft.Extensions.Options.Options.Create(new SkeinApiOptions { Url = UpstreamBase, InternalSecret = "s" });

    private static DefaultHttpContext Request(string path)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = "GET";
        ctx.Request.Path = path;
        ctx.Request.QueryString = new QueryString("?code=" + QuerySecret);
        ctx.Response.Body = new MemoryStream();
        return ctx;
    }

    private static void AssertFailureLoggedWithoutSecrets<T>(RecordingLogger<T> logger, string expectedPath)
    {
        var record = Assert.Single(logger.Records, r => r.Level == LogLevel.Error);
        Assert.All(record.Values, v =>
        {
            Assert.DoesNotContain(LinkToken, v);
            Assert.DoesNotContain(QuerySecret, v);
        });
        Assert.Contains(record.Values, v => v.Contains(expectedPath, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Api_proxy_logs_the_masked_upstream_path()
    {
        var logger = new RecordingLogger<ApiProxyMiddleware>();
        var middleware = new ApiProxyMiddleware(new StubHttpClientFactory(), Options(), logger);
        var ctx = Request("/api/v1/invitations/" + LinkToken);
        ctx.User = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString())], authenticationType: "Cookies"));

        await middleware.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(StatusCodes.Status502BadGateway, ctx.Response.StatusCode);
        AssertFailureLoggedWithoutSecrets(logger, "/ui/v1/invitations/{redacted}");
    }

    [Fact]
    public async Task Agent_proxy_logs_the_masked_path()
    {
        var logger = new RecordingLogger<AgentProxyMiddleware>();
        var middleware = new AgentProxyMiddleware(new StubHttpClientFactory(), Options(), logger);
        var ctx = Request("/agent/v1/" + LinkToken);

        await middleware.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(StatusCodes.Status502BadGateway, ctx.Response.StatusCode);
        AssertFailureLoggedWithoutSecrets(logger, "/agent/v1/{redacted}");
    }

    [Fact]
    public async Task Mcp_proxy_logs_the_path_without_the_query()
    {
        var logger = new RecordingLogger<McpProxyMiddleware>();
        var middleware = new McpProxyMiddleware(new StubHttpClientFactory(), Options(), TimeProvider.System, logger);
        var ctx = Request("/mcp");
        ctx.Request.Method = "POST";
        ctx.Request.Body = new MemoryStream();
        ctx.Request.ContentLength = 0;

        await middleware.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(StatusCodes.Status502BadGateway, ctx.Response.StatusCode);
        AssertFailureLoggedWithoutSecrets(logger, "upstreamPath=/mcp");
    }
}
