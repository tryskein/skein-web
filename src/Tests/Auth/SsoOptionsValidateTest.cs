using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.DependencyInjection;
using SkeinWeb.Auth;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// sk-303.42 — <see cref="SsoOptions.Validate"/>. The logout redirect is
/// handed to the browser as a top-level navigation target AND published to
/// the SPA as its redirect allow-list, so a value that is not an absolute
/// http(s) URL has no meaningful reading on either side. Fail at startup
/// where an operator sees it, not on somebody's logout.
/// </summary>
public class SsoOptionsValidateTest
{
    private static void Validate(string url) =>
        new SsoOptions { LogoutRedirectUrl = url }.Validate();

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Unset_IsAccepted(string url)
    {
        // Absence is the documented degraded mode, not a misconfiguration.
        Validate(url);
    }

    [Theory]
    [InlineData("https://sso.example.org/oauth2/sign_out")]
    [InlineData("http://localhost:4180/oauth2/sign_out")]
    [InlineData("https://example.com")]
    public void AbsoluteHttpUrl_IsAccepted(string url) => Validate(url);

    [Theory]
    [InlineData("/oauth2/sign_out")]          // relative
    [InlineData("//sso.example.org/oauth2/")] // protocol-relative
    [InlineData("sso.example.org")]           // bare host
    [InlineData("javascript:alert(1)")]       // non-http scheme
    [InlineData("ftp://example.org/x")]       // non-http scheme
    [InlineData("not a url")]
    public void NonAbsoluteHttpUrl_Throws(string url)
    {
        var ex = Assert.Throws<ValidationException>(() => Validate(url));
        Assert.Contains("Authentication:LogoutRedirectUrl", ex.Message);
    }

    // sk-674.18 (D-7): the mode is no longer a property of
    // the options — it is skein-api's, mapped at startup — so "regardless of
    // mode" is observed where the mode now lives: the scheme registration
    // validates the shape in every mode skein-api can report.
    [Theory]
    [InlineData("local")]
    [InlineData("keycloak")]
    [InlineData("hybrid")]
    public void ValidationRunsRegardlessOfMode(string apiAuthMode)
    {
        // A typo left behind by a mode switch is still a typo — catching it
        // only in the mode that reads it would let it sit unnoticed until the
        // deployment flips to the trust-headers mode.
        var services = new ServiceCollection();

        Assert.Throws<ValidationException>(() => services.AddSkeinAuthentication(
            WebAuthMode.FromApi(apiAuthMode, oidcAuthority: null),
            new SsoOptions { LogoutRedirectUrl = "nonsense" }));
    }
}
