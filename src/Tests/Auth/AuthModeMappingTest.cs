using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using SkeinWeb.Auth;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// K-13: skein-api's <c>authMode</c> ×
/// "is <c>Authentication:Oidc:Authority</c> set" → the web scheme
/// <c>Local</c> / <c>Keycloak</c> / <c>KeycloakOidc</c> (+ <c>Hybrid</c>).
/// Checked twice: on the mapper itself, and on its application to the
/// scheme registration — <see cref="AuthenticationRegistration.AddSkeinAuthentication"/>,
/// the method <c>Program.cs</c> calls, run on a real
/// <see cref="ServiceCollection"/> (the residual R-209 that T045 closed by
/// moving the registration out of the top-level composition).
/// </summary>
public class AuthModeMappingTest
{
    private const string Authority = "https://keycloak.example.com/realms/skein";

    // The K-13 table, written out: api mode, authority, expected kind, expected hybrid.
    public static TheoryData<string, string?, WebAuthKind, bool> Table => new()
    {
        { "local", null, WebAuthKind.Local, false },
        { "local", Authority, WebAuthKind.Local, false },
        { "keycloak", null, WebAuthKind.Keycloak, false },
        { "keycloak", "   ", WebAuthKind.Keycloak, false },
        { "keycloak", Authority, WebAuthKind.KeycloakOidc, false },
        { "hybrid", null, WebAuthKind.Keycloak, true },
        { "hybrid", Authority, WebAuthKind.KeycloakOidc, true },
    };

    [Theory]
    [MemberData(nameof(Table))]
    public void Mapper_FollowsTheK13Table(string apiMode, string? authority, WebAuthKind kind, bool hybrid)
    {
        var mode = WebAuthMode.FromApi(apiMode, authority);

        Assert.Equal(kind, mode.Kind);
        Assert.Equal(hybrid, mode.IsHybridMode);
    }

    [Theory]
    [InlineData("corporate")]
    [InlineData("Local")]   // contract values are lower-case and compared exactly
    [InlineData("")]
    [InlineData(null)]
    public void Mapper_UnknownApiMode_HasNoDefault(string? apiMode) =>
        Assert.Throws<InvalidOperationException>(() => WebAuthMode.FromApi(apiMode, Authority));

    // Same table, with the scheme set each row must register written out.
    public static TheoryData<string, string?, string[], WebAuthKind, bool> RegistrationTable => new()
    {
        { "local", null, ["Cookies"], WebAuthKind.Local, false },
        { "local", Authority, ["Cookies"], WebAuthKind.Local, false },
        { "keycloak", null, ["Cookies"], WebAuthKind.Keycloak, false },
        { "keycloak", Authority, ["Cookies", "OpenIdConnect"], WebAuthKind.KeycloakOidc, false },
        { "hybrid", null, ["Cookies"], WebAuthKind.Keycloak, true },
        { "hybrid", Authority, ["Cookies", "OpenIdConnect"], WebAuthKind.KeycloakOidc, true },
    };

    [Theory]
    [MemberData(nameof(RegistrationTable))]
    public async Task Registration_RegistersTheSchemesOfTheMappedMode(
        string apiMode, string? authority, string[] expectedSchemes, WebAuthKind kind, bool hybrid)
    {
        var sso = new SsoOptions();
        if (!string.IsNullOrWhiteSpace(authority))
        {
            // A complete OIDC client, so the KeycloakOidc validation passes.
            sso.Oidc.Authority = authority;
            sso.Oidc.ClientId = "skein";
            sso.Oidc.ClientSecret = "secret";
        }
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddSkeinAuthentication(WebAuthMode.FromApi(apiMode, authority), sso);

        await using var provider = services.BuildServiceProvider();
        var schemes = (await provider.GetRequiredService<IAuthenticationSchemeProvider>().GetAllSchemesAsync())
            .Select(s => s.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(expectedSchemes, schemes);

        // The mode-dependent surfaces read this singleton.
        var registered = provider.GetRequiredService<WebAuthMode>();
        Assert.Equal(kind, registered.Kind);
        Assert.Equal(hybrid, registered.IsHybridMode);
    }
}
