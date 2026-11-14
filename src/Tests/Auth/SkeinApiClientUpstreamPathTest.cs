using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SkeinWeb.Auth;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// The BFF's own service calls go to skein-api's internal API under
/// <c>/ui/v1/*</c> (on skein-api <c>/api/v1</c> is the public, key-authenticated
/// API): login, the session's user, OIDC provisioning, the hub's project-access
/// check and the installation settings — both from the per-request client and
/// from <see cref="InstanceConfigBootstrap"/> before the host is built. The
/// expected paths are literals of the internal API contract, not the constants
/// of the code under test. The stand-in answers only the expected route, so a
/// call to any other path fails instead of passing on a generic 200.
/// </summary>
public class SkeinApiClientUpstreamPathTest
{
    private const string BaseUrl = "http://skein-api.test/";

    private static readonly Guid U1 = Guid.Parse("0199a1b2-0000-7000-8000-000000000001");

    private const string AuthResponse = """
        {"id":"0199a1b2-0000-7000-8000-000000000001","email":"dev@client.io",
         "username":"dev","name":"dev","role":"user","isExternal":false,
         "createdAt":"2026-10-12T18:13:03Z","lastLoginAt":null,"sessionEpoch":4}
        """;

    private const string ProjectAccessResponse = """
        {"users":[{"userId":"0199a1b2-0000-7000-8000-000000000001","active":true,
          "internalAdmin":false,"external":false,"allowed":[],"denied":[]}]}
        """;

    // T012 godoc literal of InstanceConfig (internal/accounts/contract.go).
    private const string InstanceConfigResponse = """
        {"authMode":"local","signupEnabled":true,"emailEnabled":true,
         "turnstileSiteKey":"0x4AAAAAAA","projectPrefixMinLength":3,
         "termsUrl":"https://skein.example.com/terms","privacyUrl":null,
         "instanceAdminEnabled":false}
        """;

    /// <summary>
    /// skein-api stand-in that answers 200 with <paramref name="body"/> only on
    /// <paramref name="method"/> <paramref name="path"/>, 404 anywhere else, and
    /// records every path it was asked for.
    /// </summary>
    private sealed class SingleRouteApi(HttpMethod method, string path, string body) : HttpMessageHandler
    {
        public List<string> Paths { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Paths.Add(request.RequestUri!.AbsolutePath);
            var matches = request.Method == method && request.RequestUri.AbsolutePath == path;
            return Task.FromResult(matches
                ? new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(body, Encoding.UTF8, "application/json"),
                }
                : new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    private static HttpClient Http(HttpMessageHandler handler) => new(handler) { BaseAddress = new Uri(BaseUrl) };

    private static SkeinApiClient ApiClient(HttpMessageHandler handler) =>
        new(Http(handler), NullLogger<SkeinApiClient>.Instance);

    private static SkeinServiceApiClient ServiceClient(HttpMessageHandler handler) =>
        new(Http(handler),
            Options.Create(new SkeinApiOptions { Url = BaseUrl, InternalSecret = "s" }),
            TimeProvider.System,
            NullLogger<SkeinServiceApiClient>.Instance);

    [Fact]
    public async Task Login_PostsToUiV1AuthLogin()
    {
        var api = new SingleRouteApi(HttpMethod.Post, "/ui/v1/auth/login", AuthResponse);

        var result = await ApiClient(api).LoginAsync("dev@client.io", "pw", CancellationToken.None);

        Assert.Equal(LoginOutcome.Success, result.Outcome);
        Assert.Equal(["/ui/v1/auth/login"], api.Paths);
    }

    [Fact]
    public async Task Me_GetsUiV1AuthMe()
    {
        var api = new SingleRouteApi(HttpMethod.Get, "/ui/v1/auth/me", AuthResponse);

        var result = await ApiClient(api).MeAsync(CancellationToken.None);

        Assert.False(result.Revoked);
        Assert.Equal(["/ui/v1/auth/me"], api.Paths);
    }

    [Fact]
    public async Task OidcProvision_PostsToUiV1AuthOidcProvision()
    {
        var api = new SingleRouteApi(HttpMethod.Post, "/ui/v1/auth/oidc/provision", AuthResponse);

        var result = await ApiClient(api).OidcProvisionAsync("dev@client.io", "dev", "", CancellationToken.None);

        Assert.Equal(U1.ToString(), result.User.Id);
        Assert.Equal(["/ui/v1/auth/oidc/provision"], api.Paths);
    }

    [Fact]
    public async Task ProjectAccess_PostsToUiV1HubProjectAccess()
    {
        var api = new SingleRouteApi(HttpMethod.Post, "/ui/v1/hub/project-access", ProjectAccessResponse);

        var results = await ServiceClient(api).CheckProjectAccessAsync(
            [new ProjectAccessQuery(U1, ProjectIds: [])], CancellationToken.None);

        Assert.True(Assert.Single(results).Active);
        Assert.Equal(["/ui/v1/hub/project-access"], api.Paths);
    }

    [Fact]
    public async Task InstanceConfig_PerRequest_GetsUiV1InternalInstanceConfig()
    {
        var api = new SingleRouteApi(HttpMethod.Get, "/ui/v1/internal/instance-config", InstanceConfigResponse);

        var config = await ServiceClient(api).GetInstanceConfigAsync(CancellationToken.None);

        Assert.True(config.HasKnownAuthMode);
        Assert.Equal(["/ui/v1/internal/instance-config"], api.Paths);
    }

    [Fact]
    public async Task InstanceConfig_AtStartup_GetsUiV1InternalInstanceConfig()
    {
        var api = new SingleRouteApi(HttpMethod.Get, "/ui/v1/internal/instance-config", InstanceConfigResponse);

        var config = await InstanceConfigBootstrap.LoadAsync(
            Http(api), TimeSpan.FromSeconds(5), TimeProvider.System, NullLogger.Instance, CancellationToken.None);

        Assert.True(config.HasKnownAuthMode);
        Assert.Equal(["/ui/v1/internal/instance-config"], api.Paths);
    }
}
