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
/// Pins the prefix swap of <see cref="ApiProxyMiddleware"/>: the browser keeps
/// calling <c>/api/v1/*</c> on the BFF, while skein-api serves the frontend's
/// internal API under <c>/ui/v1/*</c> (<c>/api/v1</c> on skein-api is the public,
/// key-authenticated API). The upstream request must therefore go to
/// <c>/ui/v1/&lt;rest&gt;</c> for every method, with and without a body; only the
/// leading <c>/api/v1</c> is replaced, the query string is kept, and a path
/// outside <c>/api/v1</c> is not proxied at all.
/// </summary>
public class ApiProxyMiddlewarePrefixTest
{
    private const string UpstreamBase = "http://skein-api.test";

    /// <summary>Captures the upstream request URI and body.</summary>
    private sealed class CapturingHandler : HttpMessageHandler
    {
        public Uri? CapturedUri { get; private set; }
        public HttpMethod? CapturedMethod { get; private set; }
        public string? CapturedBody { get; private set; }
        public int Calls { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            CapturedUri = request.RequestUri;
            CapturedMethod = request.Method;
            CapturedBody = request.Content is null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

    private sealed class StubHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(handler, disposeHandler: false) { BaseAddress = new Uri(UpstreamBase) };
    }

    private static (ApiProxyMiddleware Middleware, CapturingHandler Handler) Build()
    {
        var handler = new CapturingHandler();
        var options = Options.Create(new SkeinApiOptions { Url = UpstreamBase, InternalSecret = "s" });
        var middleware = new ApiProxyMiddleware(
            new StubHttpClientFactory(handler), options, NullLogger<ApiProxyMiddleware>.Instance);
        return (middleware, handler);
    }

    private static DefaultHttpContext AuthedContext(string method, string path, string query, string? body)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = method;
        ctx.Request.Path = path;
        ctx.Request.QueryString = new QueryString(query);
        ctx.User = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString())],
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

    public static TheoryData<string, string?> MethodsWithAndWithoutBody => new()
    {
        { "GET", null },
        { "POST", "{\"title\":\"t\"}" },
        { "POST", null },
        { "PUT", "{\"enabled\":true}" },
        { "PATCH", "{\"priority\":1}" },
        { "PATCH", null },
        { "DELETE", "{\"endpoint\":\"https://push.example.com/abc\"}" },
        { "DELETE", null },
    };

    [Theory]
    [MemberData(nameof(MethodsWithAndWithoutBody))]
    public async Task EveryMethod_IsForwardedUnderUiV1(string method, string? body)
    {
        var (middleware, handler) = Build();
        var ctx = AuthedContext(method, "/api/v1/issues/sk-1", "", body);
        var nextCalled = false;

        await middleware.InvokeAsync(ctx, _ => { nextCalled = true; return Task.CompletedTask; });

        Assert.False(nextCalled);
        Assert.Equal(method, handler.CapturedMethod!.Method);
        Assert.Equal("http://skein-api.test/ui/v1/issues/sk-1", handler.CapturedUri!.OriginalString);
        Assert.Equal(body ?? string.Empty, handler.CapturedBody ?? string.Empty);
    }

    [Theory]
    [InlineData("/api/v1/x/api/v1", "", "http://skein-api.test/ui/v1/x/api/v1")]
    [InlineData("/api/v1/projects", "?q=api%2Fv1&limit=5", "http://skein-api.test/ui/v1/projects?q=api%2Fv1&limit=5")]
    [InlineData("/api/v1", "", "http://skein-api.test/ui/v1")]
    [InlineData("/api/v1/", "?a=1", "http://skein-api.test/ui/v1/?a=1")]
    public async Task OnlyTheLeadingPrefixIsSwapped_AndTheQueryIsKept(string path, string query, string expectedUpstream)
    {
        var (middleware, handler) = Build();
        var ctx = AuthedContext(HttpMethods.Get, path, query, body: null);

        await middleware.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(expectedUpstream, handler.CapturedUri!.OriginalString);
    }

    [Theory]
    [InlineData("/api/v10/issues")]
    [InlineData("/api/auth/me")]
    [InlineData("/ui/v1/issues")]
    [InlineData("/mcp")]
    [InlineData("/agent/v1/issues/sk-1/events")]
    public async Task PathOutsideApiV1_GoesToNext_AndIsNotProxied(string path)
    {
        var (middleware, handler) = Build();
        var ctx = AuthedContext(HttpMethods.Get, path, "", body: null);
        var nextCalled = false;

        await middleware.InvokeAsync(ctx, _ => { nextCalled = true; return Task.CompletedTask; });

        Assert.True(nextCalled);
        Assert.Equal(0, handler.Calls);
    }
}
