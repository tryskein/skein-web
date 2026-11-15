using SkeinWeb.Auth;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// Regression for the <c>/oauth2/start</c> return target: only a local path
/// may come out, so the sign-in flow cannot redirect a user off-site after
/// the identity provider; and a local path must survive (the relative form
/// was once shadowed by the absolute parse, which on Unix takes <c>/path</c>
/// for a <c>file://</c> URI, so every relative <c>rd</c> collapsed to <c>/</c>).
/// </summary>
public class OidcReturnPathTest
{
    private const string Scheme = "https";
    private const string Host = "skein.example";

    [Theory]
    [InlineData("/", "/")]
    [InlineData("/issues", "/issues")]
    [InlineData("/projects/p-1/issues?status=open", "/projects/p-1/issues?status=open")]
    [InlineData("https://skein.example/issues?x=1", "/issues?x=1")]
    [InlineData("HTTPS://SKEIN.EXAMPLE/issues", "/issues")]
    [InlineData("https://skein.example", "/")]
    public void Local_target_is_kept(string rd, string expected)
    {
        Assert.Equal(expected, OidcReturnPath.Resolve(rd, Scheme, Host));
    }

    [Theory]
    // Network-path references in the relative form.
    [InlineData("//evil.example")]
    [InlineData("//evil.example/path")]
    [InlineData("/\\evil.example")]
    [InlineData("/\t/evil.example")]
    [InlineData("/\n/evil.example")]
    // The same, smuggled through a same-origin absolute URL.
    [InlineData("https://skein.example//evil.example")]
    [InlineData("https://skein.example/\\evil.example")]
    // Another host, scheme or port.
    [InlineData("https://evil.example/issues")]
    [InlineData("http://skein.example/issues")]
    [InlineData("https://skein.example:8443/issues")]
    [InlineData("https://skein.example.evil.example/issues")]
    // Not an http(s) URL or not a path at all.
    [InlineData("javascript:alert(1)")]
    [InlineData("file:///etc/passwd")]
    [InlineData("issues")]
    [InlineData("")]
    [InlineData(null)]
    public void Anything_else_becomes_root(string? rd)
    {
        Assert.Equal("/", OidcReturnPath.Resolve(rd, Scheme, Host));
    }
}
