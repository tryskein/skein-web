using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Moq;
using SkeinWeb.Auth;
using SkeinWeb.Hubs;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Auth;

/// <summary>RP logout must identify its client after the local session has been deleted.</summary>
public sealed class OidcLogoutTest
{
    [Theory]
    [InlineData("keycloak", "skein")]
    [InlineData("hybrid", "another-client")]
    public async Task SignedOutBrowser_RealmRedirectContainsConfiguredClientAndCallback(string authMode, string clientId)
    {
        const string realm = "https://identity.example.com/realms/test";
        var sso = new SsoOptions();
        sso.Oidc.Authority = realm;
        sso.Oidc.ClientId = clientId;
        sso.Oidc.ClientSecret = "test-client-secret";
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection().UseEphemeralDataProtectionProvider();
        services.AddDistributedMemoryCache();
        services.AddSingleton(Mock.Of<IConnectionMultiplexer>());
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<ConnectionRegistry>();
        services.AddSingleton<RedisTicketStore>();
        services.AddSkeinAuthentication(WebAuthMode.FromApi(authMode, realm), sso);
        services.PostConfigure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
            options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(new()
            {
                Issuer = realm,
                EndSessionEndpoint = realm + "/protocol/openid-connect/logout",
            }));
        await using var provider = services.BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = provider };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("app.example.com");
        context.Request.Path = "/api/auth/oidc-signout";

        // POST /logout has already deleted the local cookie and its ticket.
        // Drive the actual OIDC handler with no session or saved tokens.
        await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme,
            new AuthenticationProperties { RedirectUri = "/login" });

        Assert.Equal(StatusCodes.Status302Found, context.Response.StatusCode);
        var redirect = new Uri(context.Response.Headers.Location.ToString());
        Assert.Equal("identity.example.com", redirect.Host);
        Assert.Equal("/realms/test/protocol/openid-connect/logout", redirect.AbsolutePath);
        var query = QueryHelpers.ParseQuery(redirect.Query);
        Assert.Equal(clientId, query["client_id"].ToString());
        Assert.Equal("https://app.example.com/api/auth/oidc-signout-callback", query["post_logout_redirect_uri"].ToString());
        Assert.False(query.ContainsKey("id_token_hint"));
        Assert.False(string.IsNullOrEmpty(query["state"]));
    }
}
