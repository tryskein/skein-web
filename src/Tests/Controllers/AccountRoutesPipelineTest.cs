using System.Net;
using System.Net.Http.Json;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using SkeinWeb.Auth;
using SkeinWeb.Controllers;
using SkeinWeb.Hubs;
using SkeinWeb.Middleware;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Controllers;

/// <summary>
/// The public account routes through the ASP.NET pipeline: routing,
/// model binding, authentication and the proxy run for real, in process — a
/// Kestrel host on a loopback port 0 with the BFF's own registrations
/// (<see cref="AuthenticationRegistration.AddSkeinAuthentication"/>,
/// <see cref="SkeinAccountsApiClient.Register"/>,
/// <see cref="ApiProxyMiddleware.AddProxyHttpClient"/>) and the middleware
/// order of <c>Program.cs</c>; only skein-api (a recorder behind the clients'
/// transport) and Redis (in-memory session cache, mocked multiplexer) are
/// stand-ins. No package beyond the shared framework.
/// </summary>
/// <remarks>
/// Each of the seven public paths answers without a session; with a real
/// session cookie (minted by the signup route) the calls still reach skein-api
/// without identity headers, while a proxied <c>/api/v1</c> call with the same
/// cookie does carry the identity — the cookie is a working session. Without
/// a cookie <c>/api/v1</c> stays 401 and is not forwarded.
/// </remarks>
public sealed class AccountRoutesPipelineTest : IAsyncLifetime
{
    private const string AuthResponseU1 = """
        {"id":"0199a1b2-0000-7000-8000-000000000001","email":"dev@client.io",
         "username":"dev","name":"dev","role":"user","isExternal":false,
         "createdAt":"2026-10-12T18:13:03Z","lastLoginAt":null,"sessionEpoch":4}
        """;

    private const string InvitationSignupLiteral = """
        {"id":"0199a1b2-0000-7000-8000-000000000001","email":"dev@client.io",
         "username":"dev","name":"dev","role":"user","isExternal":false,
         "createdAt":"2026-10-12T18:13:03Z","lastLoginAt":null,"sessionEpoch":4,
         "space":{"id":"k3x9p2qa","slug":"acme","name":"Acme"}}
        """;

    /// <summary>skein-api stand-in: the T012 success answer per route, every request recorded.</summary>
    private sealed class RecordingApi : HttpMessageHandler
    {
        private readonly object _gate = new();
        private readonly List<HttpRequestMessage> _requests = [];

        public HttpRequestMessage[] Requests
        {
            get { lock (_gate) { return [.. _requests]; } }
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            lock (_gate) { _requests.Add(request); }
            var path = request.RequestUri!.AbsolutePath;
            var post = request.Method == HttpMethod.Post;
            return Task.FromResult(path switch
            {
                "/api/v1/auth/signup" when post => Json(AuthResponseU1),
                "/api/v1/auth/username-suggestions" => Json("""{"suggestions":["dev","dev2"]}"""),
                "/api/v1/auth/password-reset" when post => new HttpResponseMessage(HttpStatusCode.NoContent),
                _ when post && path.StartsWith("/api/v1/auth/password-reset/") => Json(AuthResponseU1),
                _ when post && path.StartsWith("/api/v1/auth/confirm-email/") => new HttpResponseMessage(HttpStatusCode.NoContent),
                _ when post && path.EndsWith("/signup") => Json(InvitationSignupLiteral),
                _ when path.StartsWith("/api/v1/auth/invitations/") => Json(
                    """{"status":"invalid","space":null,"inviterUsername":null,"email":null,"hasAccount":null}"""),
                _ => Json("""{"ok":true}"""),
            });
        }

        private static HttpResponseMessage Json(string body) => new(HttpStatusCode.OK)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
    }

    private readonly RecordingApi _api = new();
    private WebApplication _app = null!;
    private Uri _base = null!;

    public async Task InitializeAsync()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var services = builder.Services;

        var mux = new Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(new Mock<IDatabase>().Object);
        services.AddSingleton(mux.Object);
        services.AddDistributedMemoryCache();
        services.AddSingleton<RedisTicketStore>();
        services.AddSingleton<IUserSessionRevoker>(sp => sp.GetRequiredService<RedisTicketStore>());
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<ConnectionRegistry>();

        services.AddSkeinAuthentication(WebAuthMode.FromApi("local", null), new SsoOptions());
        services.AddAuthorization();
        services.AddHttpContextAccessor();
        services.Configure<SkeinApiOptions>(o =>
        {
            o.Url = "http://skein-api.test";
            o.InternalSecret = "svc-secret";
        });
        services.AddTransient<InternalApiHandler>();
        SkeinAccountsApiClient.Register(services, "http://skein-api.test/").ConfigurePrimaryHttpMessageHandler(() => _api);
        ApiProxyMiddleware.AddProxyHttpClient(services, "http://skein-api.test/").ConfigurePrimaryHttpMessageHandler(() => _api);
        services.AddSingleton<ActionRateLimiter>();
        services.AddTransient<ApiProxyMiddleware>();
        services.AddControllers().AddApplicationPart(typeof(AccountController).Assembly);
        services.AddProblemDetails();

        _app = builder.Build();
        // Program.cs order: routing → authentication → authorization →
        // controllers → /api/v1 proxy.
        _app.UseRouting();
        _app.UseAuthentication();
        _app.UseAuthorization();
        _app.MapControllers();
        _app.UseMiddleware<ApiProxyMiddleware>();

        await _app.StartAsync();
        var address = _app.Services.GetRequiredService<Microsoft.AspNetCore.Hosting.Server.IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
        _base = new Uri(address);
    }

    public async Task DisposeAsync() => await _app.DisposeAsync();

    private HttpClient Browser(CookieContainer? cookies = null) =>
        new(new HttpClientHandler { CookieContainer = cookies ?? new CookieContainer(), UseCookies = true })
        {
            BaseAddress = _base,
        };

    /// <summary>The seven public paths of the contract, with request bodies of the declared shape.</summary>
    private static readonly (string Method, string Path, object? Body)[] PublicRoutes =
    [
        ("POST", "/api/auth/signup", new { email = "dev@client.io", username = "dev", password = "correct horse", termsAccepted = true, language = "en" }),
        ("GET", "/api/auth/username-suggestions?email=dev%40client.io", null),
        ("POST", "/api/auth/password-reset", new { email = "dev@client.io", language = "ru" }),
        ("POST", "/api/auth/password-reset/tok-1", new { password = "new password" }),
        ("POST", "/api/auth/confirm-email/tok-1", null),
        ("GET", "/api/auth/invitations/tok-1", null),
        ("POST", "/api/auth/invitations/tok-1/signup", new { username = "dev", password = "correct horse", termsAccepted = true }),
    ];

    private static Task<HttpResponseMessage> Send(HttpClient browser, string method, string path, object? body) =>
        method == "GET"
            ? browser.GetAsync(path)
            : browser.PostAsync(path, body is null ? null : JsonContent.Create(body));

    private static bool CarriesIdentity(HttpRequestMessage sent) =>
        sent.Headers.Any(h =>
            h.Key.StartsWith("X-Skein-User", StringComparison.OrdinalIgnoreCase) ||
            h.Key.Equals(SkeinHeaders.Username, StringComparison.OrdinalIgnoreCase) ||
            h.Key.Equals(SkeinHeaders.SessionEpoch, StringComparison.OrdinalIgnoreCase));

    [Fact]
    public async Task EveryPublicPath_AnswersWithoutSession_AndReachesApiWithoutIdentity()
    {
        using var browser = Browser();

        foreach (var (method, path, body) in PublicRoutes)
        {
            var before = _api.Requests.Length;
            using var response = await Send(browser, method, path, body);

            Assert.True(response.IsSuccessStatusCode, $"{method} {path} answered {(int)response.StatusCode} without a session");
            var sent = Assert.Single(_api.Requests[before..]);
            Assert.False(CarriesIdentity(sent), $"{method} {path} reached skein-api with identity headers");
        }
    }

    [Fact]
    public async Task WithASessionCookie_PublicPathsStillCarryNoIdentity_WhileTheProxyDoes()
    {
        var cookies = new CookieContainer();
        using var browser = Browser(cookies);
        using (var signup = await Send(browser, PublicRoutes[0].Method, PublicRoutes[0].Path, PublicRoutes[0].Body))
        {
            Assert.True(signup.IsSuccessStatusCode);
        }
        Assert.NotEmpty(cookies.GetCookies(_base));

        foreach (var (method, path, body) in PublicRoutes)
        {
            var before = _api.Requests.Length;
            using var response = await Send(browser, method, path, body);

            Assert.True(response.IsSuccessStatusCode, $"{method} {path} answered {(int)response.StatusCode}");
            Assert.False(CarriesIdentity(Assert.Single(_api.Requests[before..])), $"{method} {path} forwarded the session's identity");
        }

        // The same cookie is a working session: the proxy forwards its identity.
        var mark = _api.Requests.Length;
        using var proxied = await browser.GetAsync("/api/v1/projects");
        Assert.Equal(HttpStatusCode.OK, proxied.StatusCode);
        Assert.True(CarriesIdentity(Assert.Single(_api.Requests[mark..])));
    }

    [Fact]
    public async Task ApiV1_WithoutSession_Is401_AndNotForwarded()
    {
        using var browser = Browser();

        using var response = await browser.GetAsync("/api/v1/projects");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(_api.Requests);
    }
}
