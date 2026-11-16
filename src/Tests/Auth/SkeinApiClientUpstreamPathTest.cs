using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SkeinWeb.Auth;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// The BFF's own calls go to skein-api's internal API under <c>/ui/v1/*</c>
/// (on skein-api <c>/api/v1</c> is the public, key-authenticated API): the
/// service calls — login, OIDC provisioning, the hub's project-access check and
/// the installation settings, both from the per-request client and from
/// <see cref="InstanceConfigBootstrap"/> before the host is built — and the
/// user route <c>GET auth/me</c> (the session's user). Login and provisioning
/// carry the service-call marker <c>X-Skein-Service-Call: 1</c>;
/// <c>GET auth/me</c> does not. The
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

    /// <summary>
    /// skein-api stand-in for the typed <see cref="SkeinApiClient"/>: answers
    /// the auth literal on every route and records, per request, the path and
    /// the values of the service-call marker header (empty when absent).
    /// </summary>
    private sealed class MarkerRecordingApi : HttpMessageHandler
    {
        public List<(string Path, string[] Marker)> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var marker = request.Headers.TryGetValues("X-Skein-Service-Call", out var values) ? values.ToArray() : [];
            Requests.Add((request.RequestUri!.AbsolutePath, marker));
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(AuthResponse, Encoding.UTF8, "application/json"),
            });
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

    // Row 10 (SC-004, US-3): login and provision — on creation, on the TTL
    // refresh and in native OIDC alike, one method — are service calls and
    // carry exactly one X-Skein-Service-Call: 1.
    [Theory]
    [InlineData("login", "/ui/v1/auth/login")]
    [InlineData("provision", "/ui/v1/auth/oidc/provision")]
    public async Task ServiceCall_CarriesExactlyOneMarker(string call, string expectedPath)
    {
        var api = new MarkerRecordingApi();
        var client = ApiClient(api);

        if (call == "login")
        {
            await client.LoginAsync("dev@client.io", "pw", CancellationToken.None);
        }
        else
        {
            await client.OidcProvisionAsync("dev@client.io", "dev", "", CancellationToken.None);
        }

        var (path, marker) = Assert.Single(api.Requests);
        Assert.Equal(expectedPath, path);
        Assert.Equal(["1"], marker);
    }

    // Row 10: GET auth/me is a user route — the same client, right after its
    // service calls, sends it without the marker.
    [Fact]
    public async Task Me_OnTheSameClientAfterServiceCalls_CarriesNoMarker()
    {
        var api = new MarkerRecordingApi();
        var client = ApiClient(api);
        await client.LoginAsync("dev@client.io", "pw", CancellationToken.None);
        await client.OidcProvisionAsync("dev@client.io", "dev", "", CancellationToken.None);

        await client.MeAsync(CancellationToken.None);

        Assert.Equal(3, api.Requests.Count);
        var (path, marker) = api.Requests[2];
        Assert.Equal("/ui/v1/auth/me", path);
        Assert.Empty(marker);
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
