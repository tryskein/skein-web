using System.Net;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SkeinWeb.Auth;
using SkeinWeb.Controllers;

namespace SkeinWeb.Tests.Controllers;

/// <summary>
/// sk-163 S4b — pins the AuthConfig contract surfaced to the SPA:
/// <c>{ authMode: local|keycloak|hybrid }</c>.
///
/// sk-303.8 — this used to also pin <c>isExternalHost</c>, a per-request
/// Host classification removed along with the S7a SKEIN_INTERNAL_HOSTS
/// allowlist it read (see AuthConfigController remarks for the rationale).
///
/// sk-303.42 — the contract grew two deployment ADDRESSES the SPA used to
/// compile in or derive from its own hostname: <c>logoutRedirectUrl</c> (the
/// client's redirect allow-list) and <c>mcpUrl</c>. Both must reach the client
/// verbatim when configured and as <c>null</c> when not — "unset" and "set to
/// an empty string" have to stay one and the same on the wire, because the SPA
/// branches on presence.
///
/// sk-674.18 — D-7 (the mode comes from skein-api, there
/// is no <c>Authentication:Mode</c>) and K-14 (the behaviour flags are
/// read from skein-api on every request; skein-api down → 503).
/// </summary>
public class AuthConfigControllerTest
{
    private const string Authority = "https://keycloak.example.com/realms/skein";

    // T012 godoc literal of InstanceConfig (internal/accounts/contract.go).
    private const string InstanceConfigLiteral = """
        {"authMode":"local","signupEnabled":true,"emailEnabled":true,
         "turnstileSiteKey":"0x4AAAAAAA","projectPrefixMinLength":3,
         "termsUrl":"https://skein.example.com/terms","privacyUrl":null,
         "instanceAdminEnabled":false}
        """;

    private static string ConfigWithSignup(bool signupEnabled) =>
        InstanceConfigLiteral.Replace("\"signupEnabled\":true", $"\"signupEnabled\":{(signupEnabled ? "true" : "false")}");

    /// <summary>
    /// Stands in for skein-api: answers with whatever <see cref="Answer"/>
    /// holds at the moment of the call (a body, or a status with no body), and
    /// counts the calls — so a test can change skein-api's state between two
    /// requests the way a restart of skein-api with a new value does.
    /// </summary>
    private sealed class InstanceConfigApi : HttpMessageHandler
    {
        public Func<HttpResponseMessage> Answer { get; set; } = () => Ok(InstanceConfigLiteral);

        public int Calls { get; private set; }

        public static HttpResponseMessage Ok(string body) => new(HttpStatusCode.OK)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Calls++;
            Assert.Equal(InstanceConfigBootstrap.Path, request.RequestUri!.AbsolutePath);
            return Task.FromResult(Answer());
        }
    }

    private static AuthConfigController Controller(
        WebAuthMode mode,
        InstanceConfigApi api,
        string logoutRedirectUrl = "",
        string mcpUrl = "")
    {
        var controller = new AuthConfigController(
            mode,
            Options.Create(new SsoOptions { LogoutRedirectUrl = logoutRedirectUrl }),
            Options.Create(new ClientRuntimeOptions { McpUrl = mcpUrl }),
            new SkeinServiceApiClient(
                new HttpClient(api) { BaseAddress = new Uri("http://skein-api.test/") },
                Options.Create(new SkeinApiOptions { Url = "http://skein-api.test", InternalSecret = "s" }),
                TimeProvider.System,
                NullLogger<SkeinServiceApiClient>.Instance),
            NullLogger<AuthConfigController>.Instance);
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };
        return controller;
    }

    private static async Task<AuthConfigResponse> OkBody(AuthConfigController controller)
    {
        var action = await controller.Get(CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(action.Result);
        return Assert.IsType<AuthConfigResponse>(ok.Value);
    }

    /// <summary>
    /// The SPA config for a process whose mode was taken from skein-api
    /// (<paramref name="apiAuthMode"/> + the configured OIDC authority,
    /// plan K-13) — D-7: there is no web-side mode setting any more.
    /// </summary>
    private static Task<AuthConfigResponse> Get(
        string apiAuthMode,
        string? authority = null,
        string logoutRedirectUrl = "",
        string mcpUrl = "") =>
        OkBody(Controller(WebAuthMode.FromApi(apiAuthMode, authority), new InstanceConfigApi(), logoutRedirectUrl, mcpUrl));

    // ---- row 224 (D-7): authMode token from the mode taken from skein-api ----

    [Fact]
    public async Task Local_ReturnsLocal()
    {
        var r = await Get("local");
        Assert.Equal("local", r.AuthMode);
    }

    [Fact]
    public async Task Keycloak_ReturnsKeycloak()
    {
        // keycloak without an OIDC authority → legacy trust-headers scheme.
        var r = await Get("keycloak");
        Assert.Equal("keycloak", r.AuthMode);
    }

    [Fact]
    public async Task KeycloakOidc_ReturnsKeycloak()
    {
        // keycloak with an OIDC authority → native OIDC scheme, same SPA token.
        var r = await Get("keycloak", Authority);
        Assert.Equal("keycloak", r.AuthMode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(Authority)]
    public async Task Hybrid_ReturnsHybrid_NotKeycloak(string? authority)
    {
        // A hybrid deployment is ALSO an SSO mode — must report 'hybrid', not collapse.
        var r = await Get("hybrid", authority);
        Assert.Equal("hybrid", r.AuthMode);
    }

    [Fact]
    public async Task Local_WithOidcAuthorityConfigured_StaysLocal()
    {
        // An OIDC client left configured in web does not turn a local
        // installation into SSO — the mode is skein-api's.
        var r = await Get("local", Authority);
        Assert.Equal("local", r.AuthMode);
    }

    // ---- row 210 (US-18, K-14): behaviour flags read from skein-api per request ----

    [Fact]
    public async Task BehaviourFlags_AreReadFromApiOnEveryRequest_NoCache()
    {
        var api = new InstanceConfigApi { Answer = () => InstanceConfigApi.Ok(ConfigWithSignup(false)) };
        var controller = Controller(WebAuthMode.FromApi("local", null), api);

        var first = await OkBody(controller);
        // skein-api restarted with a new value; the same controller instance answers again.
        api.Answer = () => InstanceConfigApi.Ok(ConfigWithSignup(true));
        var second = await OkBody(controller);

        Assert.False(first.SignupEnabled);
        Assert.True(second.SignupEnabled);
        Assert.Equal(2, api.Calls);
    }

    [Fact]
    public async Task BehaviourFlags_AreCopiedFromTheApiAnswer()
    {
        var r = await Get("local");

        // Values of the T012 literal above.
        Assert.True(r.SignupEnabled);
        Assert.True(r.EmailEnabled);
        Assert.Equal("0x4AAAAAAA", r.TurnstileSiteKey);
        Assert.Equal(3, r.ProjectPrefixMinLength);
        Assert.Equal("https://skein.example.com/terms", r.TermsUrl);
        Assert.Null(r.PrivacyUrl);
    }

    public static TheoryData<string> Unavailable => new() { "503", "refused", "not-the-contract" };

    [Theory]
    [MemberData(nameof(Unavailable))]
    public async Task ApiUnavailable_Answers503_NeverAStaleOrDefaultValue(string kind)
    {
        var api = new InstanceConfigApi
        {
            Answer = kind switch
            {
                "503" => () => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable),
                "refused" => () => throw new HttpRequestException("Connection refused"),
                _ => () => InstanceConfigApi.Ok("{\"authMode\":\"local\"}"),
            },
        };
        var controller = Controller(WebAuthMode.FromApi("local", null), api);

        var action = await controller.Get(CancellationToken.None);

        var problem = Assert.IsType<ObjectResult>(action.Result);
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, problem.StatusCode);
        var details = Assert.IsAssignableFrom<ProblemDetails>(problem.Value);
        Assert.Equal("upstream_unavailable", details.Extensions["error"]);
    }

    // ---- sk-303.42: deployment addresses ------------------------------------

    [Fact]
    public async Task LogoutRedirectUrl_IsPublishedVerbatim()
    {
        var r = await Get("keycloak",
            logoutRedirectUrl: "https://sso.example.org/oauth2/sign_out");
        Assert.Equal("https://sso.example.org/oauth2/sign_out", r.LogoutRedirectUrl);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task LogoutRedirectUrl_UnsetIsNull_NotEmptyString(string configured)
    {
        var r = await Get("keycloak", logoutRedirectUrl: configured);
        Assert.Null(r.LogoutRedirectUrl);
    }

    [Fact]
    public async Task McpUrl_IsPublishedVerbatim()
    {
        var r = await Get("local", mcpUrl: "https://skein-mcp.example.com/mcp");
        Assert.Equal("https://skein-mcp.example.com/mcp", r.McpUrl);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task McpUrl_UnsetIsNull_NotEmptyString(string configured)
    {
        // null is the SPA's signal to fall back to same-origin /mcp.
        var r = await Get("local", mcpUrl: configured);
        Assert.Null(r.McpUrl);
    }

    [Fact]
    public async Task AddressesAreIndependentOfAuthMode()
    {
        // MCP lives on its own ingress regardless of how humans log in; the
        // two settings must not be coupled to the mode collapse above.
        var r = await Get("local",
            logoutRedirectUrl: "https://sso.example.org/oauth2/sign_out",
            mcpUrl: "https://skein-mcp.example.com/mcp");
        Assert.Equal("local", r.AuthMode);
        Assert.Equal("https://sso.example.org/oauth2/sign_out", r.LogoutRedirectUrl);
        Assert.Equal("https://skein-mcp.example.com/mcp", r.McpUrl);
    }
}
