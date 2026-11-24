using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SkeinWeb.Auth;
using SkeinWeb.Middleware;

namespace SkeinWeb.Tests.Middleware;

/// <summary>
/// The service path class of the browser proxy: skein-api routes only the BFF
/// itself calls (everything under <c>auth/</c> except <c>GET auth/me</c>, and
/// everything under <c>hub/</c> and <c>internal/</c>) answer 404 through
/// <see cref="ApiProxyMiddleware"/> in every equivalent path form, for every
/// method, with and without a session cookie, and never reach skein-api. A path
/// that leaves <c>/ui/v1</c> after its dot segments are resolved is refused the
/// same way. User paths, including <c>GET auth/me</c> and segments that only
/// start with a class name, are still proxied, and still need the cookie.
/// </summary>
/// <remarks>
/// <c>Request.Path</c> is given in the form the server hands to middleware:
/// already percent-decoded, except an encoded <c>/</c> (<c>%2F</c>), which stays
/// encoded. A literal <c>%2e%2e</c> in it stands for a doubly-encoded dot segment.
/// </remarks>
public class ApiProxyMiddlewareServiceClassTest
{
    private const string UpstreamBase = "http://skein-api.test";

    /// <summary>Counts upstream calls and keeps the last request URI.</summary>
    private sealed class CountingHandler : HttpMessageHandler
    {
        public int Calls { get; private set; }
        public Uri? LastUri { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            LastUri = request.RequestUri;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    private sealed class StubHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(handler, disposeHandler: false) { BaseAddress = new Uri(UpstreamBase) };
    }

    private static (ApiProxyMiddleware Middleware, CountingHandler Handler) Build()
    {
        var handler = new CountingHandler();
        var options = Options.Create(new SkeinApiOptions { Url = UpstreamBase, InternalSecret = "s" });
        var middleware = new ApiProxyMiddleware(
            new StubHttpClientFactory(handler), options, NullLogger<ApiProxyMiddleware>.Instance);
        return (middleware, handler);
    }

    private static DefaultHttpContext Context(string method, string path, string query, bool cookie)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = method;
        ctx.Request.Path = path;
        ctx.Request.QueryString = new QueryString(query);
        ctx.User = cookie
            ? new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString())],
                authenticationType: "Cookies"))
            : new ClaimsPrincipal(new ClaimsIdentity());
        ctx.Response.Body = new MemoryStream();
        return ctx;
    }

    private static async Task<(int Status, int Calls, Uri? Upstream)> Send(
        string method, string path, string query, bool cookie)
    {
        var (middleware, handler) = Build();
        var ctx = Context(method, path, query, cookie);
        await middleware.InvokeAsync(ctx, _ => Task.CompletedTask);
        return (ctx.Response.StatusCode, handler.Calls, handler.LastUri);
    }

    /// <summary>The service routes of skein-api's internal API, after <c>/ui/v1/</c>.</summary>
    private static readonly string[] ServiceRoutes =
    [
        "auth/oidc/provision",
        "hub/project-access",
        "internal/instance-config",
        "auth/signup",
        "auth/username-suggestions",
        "auth/password-reset",
        "auth/password-reset/tok3n",
        "auth/confirm-email/tok3n",
        "auth/invitations/tok3n",
        "auth/invitations/tok3n/signup",
        "auth/login",
        "auth/logout",
    ];

    /// <summary>Equivalent forms of a route: browser path and query string.</summary>
    private static IEnumerable<(string Form, string Path, string Query)> Forms(string route) =>
    [
        ("canonical", "/api/v1/" + route, ""),
        ("upper case", "/API/V1/" + route.ToUpperInvariant(), ""),
        ("repeated slashes", "/api/v1//" + route.Replace("/", "//"), ""),
        ("dot segment", "/api/v1/./" + route.Replace("/", "/./"), ""),
        ("dot-dot segment", "/api/v1/x/../" + route, ""),
        ("encoded dot-dot", "/api/v1/x/%2e%2e/" + route, ""),
        ("encoded dot-dot upper hex", "/api/v1/x/%2E%2E/" + route, ""),
        ("encoded separator", "/api/v1/" + route.Replace("/", "%2F"), ""),
        ("encoded backslash separator", "/api/v1/" + route.Replace("/", "%5C"), ""),
        ("encoded backslash separator lower hex", "/api/v1/" + route.Replace("/", "%5c"), ""),
        ("encoded dot segment", "/api/v1/%2e/" + route.Replace("/", "/%2e/"), ""),
        ("encoded dot segment upper hex", "/api/v1/%2E/" + route.Replace("/", "/%2E/"), ""),
        ("backslash at start", "/api/v1/\\" + route, ""),
        ("backslash in middle", "/api/v1/" + route.Replace("/", "\\"), ""),
        ("backslash at end", "/api/v1/" + route + "\\", ""),
        ("trailing slash", "/api/v1/" + route + "/", ""),
        ("query", "/api/v1/" + route, "?next=%2Fprojects&a=1"),
    ];

    private static readonly string[] Methods =
    [
        HttpMethods.Get, HttpMethods.Post, HttpMethods.Put,
        HttpMethods.Delete, HttpMethods.Head, HttpMethods.Options,
    ];

    public static TheoryData<string, string, string, bool> ServiceRouteForms()
    {
        var data = new TheoryData<string, string, string, bool>();
        foreach (var route in ServiceRoutes)
        foreach (var (_, path, query) in Forms(route))
        foreach (var method in Methods)
        {
            data.Add(method, path, query, true);
            data.Add(method, path, query, false);
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(ServiceRouteForms))]
    public async Task ServiceRoute_InAnyForm_Is404_AndNeverProxied(
        string method, string path, string query, bool cookie)
    {
        var (status, calls, _) = await Send(method, path, query, cookie);

        Assert.Equal(StatusCodes.Status404NotFound, status);
        Assert.Equal(0, calls);
    }

    /// <summary>
    /// The refusal itself is the JSON error the rest of the API answers with:
    /// a JSON Content-Type and the machine code <c>not_found</c>, the same with
    /// and without a session cookie, for a service route and for a path that
    /// leaves the internal-API prefix.
    /// </summary>
    [Theory]
    [InlineData("POST", "/api/v1/auth/login", true)]
    [InlineData("POST", "/api/v1/auth/login", false)]
    [InlineData("GET", "/api/v1/../../api/v1/projects", true)]
    [InlineData("GET", "/api/v1/../../api/v1/projects", false)]
    public async Task Refusal_IsAJsonNotFoundError(string method, string path, bool cookie)
    {
        var (middleware, handler) = Build();
        var ctx = Context(method, path, "", cookie);
        await middleware.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(StatusCodes.Status404NotFound, ctx.Response.StatusCode);
        Assert.Equal(0, handler.Calls);
        Assert.Equal("application/json", ctx.Response.ContentType);
        ctx.Response.Body.Position = 0;
        using var body = await System.Text.Json.JsonDocument.ParseAsync(ctx.Response.Body, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("not_found", body.RootElement.GetProperty("error").GetString());
    }

    [Theory]
    // Dot segments that climb above /ui/v1: the result would address skein-api
    // outside the internal-API prefix (the transitional /api/v1 serves the same
    // service routes), whether the target is a service or a user route.
    [InlineData("/api/v1/../../api/v1/auth/login", true)]
    [InlineData("/api/v1/../../api/v1/auth/login", false)]
    [InlineData("/api/v1/x/..%2F..%2Fauth/login", true)]
    [InlineData("/api/v1/x/..%2F..%2Fauth/login", false)]
    [InlineData("/api/v1/../../api/v1/projects", true)]
    [InlineData("/api/v1/../../api/v1/projects", false)]
    [InlineData("/api/v1/x/..%2F..%2Fprojects", true)]
    [InlineData("/api/v1/x/..%2F..%2Fprojects", false)]
    public async Task PathLeavingTheInternalApiPrefix_Is404_AndNeverProxied(string path, bool cookie)
    {
        var (status, calls, _) = await Send(HttpMethods.Get, path, "", cookie);

        Assert.Equal(StatusCodes.Status404NotFound, status);
        Assert.Equal(0, calls);
    }

    [Theory]
    // A class, not a list: routes skein-api does not have today are refused too.
    [InlineData("GET", "/api/v1/auth/new-route", true)]
    [InlineData("GET", "/api/v1/auth/new-route", false)]
    [InlineData("POST", "/api/v1/hub/x", true)]
    [InlineData("POST", "/api/v1/hub/x", false)]
    [InlineData("GET", "/api/v1/internal/y", true)]
    [InlineData("GET", "/api/v1/internal/y", false)]
    // auth/me is a user route only for GET.
    [InlineData("POST", "/api/v1/auth/me", true)]
    [InlineData("POST", "/api/v1/auth/me", false)]
    [InlineData("HEAD", "/api/v1/auth/me", true)]
    [InlineData("HEAD", "/api/v1/auth/me", false)]
    [InlineData("OPTIONS", "/api/v1/auth/me", true)]
    [InlineData("OPTIONS", "/api/v1/auth/me", false)]
    [InlineData("GET", "/api/v1/auth/me/../login", true)]
    [InlineData("GET", "/api/v1/auth/me/../login", false)]
    // The GET exception is auth/me only: "me" under hub/ or internal/ is in the class.
    [InlineData("GET", "/api/v1/hub/me", true)]
    [InlineData("GET", "/api/v1/hub/me", false)]
    [InlineData("GET", "/api/v1/internal/me", true)]
    [InlineData("GET", "/api/v1/internal/me", false)]
    public async Task OtherPathInTheClass_Is404_AndNeverProxied(string method, string path, bool cookie)
    {
        var (status, calls, _) = await Send(method, path, "", cookie);

        Assert.Equal(StatusCodes.Status404NotFound, status);
        Assert.Equal(0, calls);
    }

    [Theory]
    [InlineData("/api/v1/auth/me", "http://skein-api.test/ui/v1/auth/me")]
    [InlineData("/api/v1/authors", "http://skein-api.test/ui/v1/authors")]
    [InlineData("/api/v1/hubs", "http://skein-api.test/ui/v1/hubs")]
    [InlineData("/api/v1/internals", "http://skein-api.test/ui/v1/internals")]
    [InlineData("/api/v1/projects/p/auth/login", "http://skein-api.test/ui/v1/projects/p/auth/login")]
    public async Task UserPath_WithCookie_IsProxiedOnce(string path, string expectedUpstream)
    {
        var (status, calls, upstream) = await Send(HttpMethods.Get, path, "", cookie: true);

        Assert.Equal(StatusCodes.Status200OK, status);
        Assert.Equal(1, calls);
        Assert.Equal(expectedUpstream, upstream!.OriginalString);
    }

    [Theory]
    [InlineData("/api/v1/auth/me")]
    [InlineData("/api/v1/authors")]
    [InlineData("/api/v1/hubs")]
    [InlineData("/api/v1/internals")]
    [InlineData("/api/v1/projects/p/auth/login")]
    public async Task UserPath_WithoutCookie_Is401_AndNeverProxied(string path)
    {
        var (status, calls, _) = await Send(HttpMethods.Get, path, "", cookie: false);

        Assert.Equal(StatusCodes.Status401Unauthorized, status);
        Assert.Equal(0, calls);
    }
}
