using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SkeinWeb.Auth;

namespace SkeinWeb.Tests.Auth;

public class OidcProvisioningRejectionTest
{
    private sealed class RejectedProvisioningApi(HttpStatusCode status, string errorCode) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(status)
            {
                Content = new StringContent(
                    JsonSerializer.Serialize(new { error = errorCode, message = "Upstream provisioning was denied." }),
                    Encoding.UTF8, "application/json"),
            });
    }

    [Theory]
    [InlineData("keycloak", 403, "user_not_provisioned", 403, "user_not_provisioned")]
    [InlineData("hybrid", 403, "user_not_provisioned", 403, "user_not_provisioned")]
    [InlineData("keycloak", 403, "unknown_error", 502, "sso_provisioning_failed")]
    [InlineData("hybrid", 403, "unknown_error", 502, "sso_provisioning_failed")]
    [InlineData("keycloak", 422, "missing_claims", 502, "sso_provisioning_failed")]
    [InlineData("hybrid", 422, "missing_claims", 502, "sso_provisioning_failed")]
    [InlineData("keycloak", 409, "username_conflict", 502, "sso_provisioning_failed")]
    [InlineData("hybrid", 409, "username_conflict", 502, "sso_provisioning_failed")]
    public async Task ProvisioningRejection_ReturnsExpectedStatusWithoutSession(
        string authMode, int upstreamStatus, string upstreamCode, int expectedStatus, string expectedCode)
    {
        var sso = new SsoOptions();
        sso.Oidc.Authority = "https://identity.example.com/realms/skein";
        sso.Oidc.ClientId = "skein";
        sso.Oidc.ClientSecret = "test-client-secret";
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSkeinAuthentication(WebAuthMode.FromApi(authMode, sso.Oidc.Authority), sso);
        using var http = new HttpClient(new RejectedProvisioningApi((HttpStatusCode)upstreamStatus, upstreamCode))
        {
            BaseAddress = new Uri("http://skein-api.test/"),
        };
        services.AddSingleton(new SkeinApiClient(http, NullLogger<SkeinApiClient>.Instance));
        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);
        var context = new DefaultHttpContext { RequestServices = provider };
        context.Response.Body = new MemoryStream();
        var idToken = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("groups", "/skein-users"),
                new Claim("email", "unprovisioned@example.com"),
                new Claim("preferred_username", "unprovisioned"),
            ], "oidc"));
        var validated = new TokenValidatedContext(
            context,
            new AuthenticationScheme(OpenIdConnectDefaults.AuthenticationScheme, null, typeof(OpenIdConnectHandler)),
            options, idToken, new AuthenticationProperties());

        await options.Events.OnTokenValidated(validated);

        Assert.Equal(expectedStatus, context.Response.StatusCode);
        Assert.True(validated.Result?.Handled);
        Assert.Null(validated.Principal?.FindFirst(ClaimTypes.NameIdentifier));
        Assert.Null(validated.Principal?.FindFirst(SessionPrincipal.SessionEpochClaim));
        Assert.False(context.Response.Headers.ContainsKey("Set-Cookie"));
        context.Response.Body.Position = 0;
        using var body = await JsonDocument.ParseAsync(context.Response.Body);
        Assert.Equal(expectedCode, body.RootElement.GetProperty("error").GetString());
    }
}
