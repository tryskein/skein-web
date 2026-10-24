using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using SkeinWeb.Auth;
using SkeinWeb.Controllers;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Controllers;

/// <summary>
/// sk-303.42 — pins where the post-logout redirect comes from.
///
/// It used to be a string literal naming one organisation's oauth2-proxy
/// host, which sent every OTHER deployment's users to a proxy that is not
/// theirs. The address is now a deployment setting
/// (<c>Authentication:LogoutRedirectUrl</c>), and — the part worth pinning —
/// leaving it unset DEGRADES rather than fails: no absolute redirect is
/// handed out, so nobody is navigated anywhere unexpected.
/// </summary>
public class AuthControllerLogoutTest
{
    private static AuthController Build(string mode, string logoutRedirectUrl)
    {
        var http = new HttpClient(new NoopHandler())
        {
            BaseAddress = new Uri("http://skein-api.test/"),
        };
        var apiClient = new SkeinApiClient(http, NullLogger<SkeinApiClient>.Instance);

        var sso = Options.Create(new SsoOptions
        {
            LogoutRedirectUrl = logoutRedirectUrl,
        });
        var apiOpts = Options.Create(new SkeinApiOptions
        {
            Url = "http://skein-api.test",
            InternalSecret = "s",
        });

        var controller = new AuthController(
            apiClient,
            RateLimiter(),
            new WebAuthMode(Enum.Parse<WebAuthKind>(mode), Hybrid: false),
            sso,
            apiOpts,
            NullLogger<AuthController>.Instance);

        // Logout only needs SignOutAsync on the cookie scheme to succeed.
        var authService = new Mock<IAuthenticationService>();
        authService
            .Setup(a => a.SignOutAsync(
                It.IsAny<HttpContext>(), It.IsAny<string>(),
                It.IsAny<AuthenticationProperties>()))
            .Returns(Task.CompletedTask);

        var services = new ServiceCollection();
        services.AddSingleton(authService.Object);

        var ctx = new DefaultHttpContext
        {
            RequestServices = services.BuildServiceProvider(),
            User = new ClaimsPrincipal(new ClaimsIdentity(
                new[] { new Claim(ClaimTypes.NameIdentifier, "u-1") }, "test")),
        };

        controller.ControllerContext = new ControllerContext { HttpContext = ctx };
        return controller;
    }

    private sealed class NoopHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("logout must not call skein-api");
    }

    private static LoginRateLimiter RateLimiter()
    {
        var db = new Mock<IDatabase>();
        var mux = new Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(db.Object);
        return new LoginRateLimiter(mux.Object);
    }

    private static async Task<LogoutResponse> Logout(string mode, string logoutRedirectUrl)
    {
        var action = await Build(mode, logoutRedirectUrl).Logout(CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(action.Result);
        return Assert.IsType<LogoutResponse>(ok.Value);
    }

    [Fact]
    public async Task Keycloak_WithConfiguredUrl_ReturnsExactlyThatUrl()
    {
        var r = await Logout("Keycloak", "https://sso.example.org/oauth2/sign_out");
        Assert.Equal("https://sso.example.org/oauth2/sign_out", r.RedirectTo);
    }

    [Fact]
    public async Task Keycloak_WithoutConfiguredUrl_ReturnsNoAbsoluteRedirect()
    {
        // The degraded path: the local cookie is cleared, but we do NOT invent
        // an upstream address. Program.cs has already warned at startup that
        // the external session survives this logout.
        var r = await Logout("Keycloak", "");
        Assert.Null(r.RedirectTo);
    }

    [Fact]
    public async Task Keycloak_WithWhitespaceUrl_ReturnsNoAbsoluteRedirect()
    {
        // "   " is what an env var set to nothing meaningful looks like after
        // binding; it must read as unset, not as a redirect target.
        var r = await Logout("Keycloak", "   ");
        Assert.Null(r.RedirectTo);
    }

    [Fact]
    public async Task Local_ReturnsNull_EvenWhenUrlConfigured()
    {
        // No external session in local mode — the setting is inert there.
        var r = await Logout("Local", "https://sso.example.org/oauth2/sign_out");
        Assert.Null(r.RedirectTo);
    }

    [Fact]
    public async Task KeycloakOidc_ReturnsSameOriginSignoutPath_Unchanged()
    {
        // Native OIDC drives RP-logout itself; the proxy setting must not
        // divert it.
        var r = await Logout("KeycloakOidc", "https://sso.example.org/oauth2/sign_out");
        Assert.Equal("/api/auth/oidc-signout", r.RedirectTo);
    }

    [Theory]
    [InlineData("Keycloak")]
    [InlineData("KeycloakOidc")]
    [InlineData("Local")]
    public async Task NoDeploymentAddressIsBakedIn(string mode)
    {
        // Whatever comes back must be traceable to configuration or to a
        // same-origin path — never to a host compiled into this code.
        var r = await Logout(mode, "");
        Assert.True(r.RedirectTo is null || r.RedirectTo.StartsWith('/'),
            $"mode {mode} produced an absolute redirect with no configuration: {r.RedirectTo}");
    }
}
