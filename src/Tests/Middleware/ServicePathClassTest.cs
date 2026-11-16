using SkeinWeb.Middleware;

namespace SkeinWeb.Tests.Middleware;

/// <summary>
/// The service path class decided directly on an upstream URI: everything under
/// <c>auth/</c> except <c>GET auth/me</c>, and everything under <c>hub/</c> and
/// <c>internal/</c>, is refused, matched per segment and ignoring case; a path
/// that leaves the internal-API root is refused too; other paths are not.
/// The same decisions through the proxy are in
/// <see cref="ApiProxyMiddlewareServiceClassTest"/>.
/// </summary>
/// <remarks>
/// The path is given as <see cref="Uri"/> hands it to the classifier: an encoded
/// <c>/</c> (<c>%2F</c>) stays encoded in <c>AbsolutePath</c>, and the
/// classifier decodes it once, so <c>%2F.%2F</c> is a dot segment it has to drop.
/// </remarks>
public class ServicePathClassTest
{
    private const string Root = "/ui/v1";

    private static bool Refuses(string method, string path, string root = Root) =>
        ServicePathClass.Refuses(method, new Uri("http://skein-api.test" + path), root);

    [Theory]
    [InlineData("POST", "/ui/v1/auth/login", true)]
    [InlineData("GET", "/ui/v1/auth/login", true)]
    [InlineData("GET", "/ui/v1/auth", true)]
    [InlineData("GET", "/ui/v1/hub/me", true)]
    [InlineData("GET", "/ui/v1/internal/instance-config", true)]
    [InlineData("DELETE", "/ui/v1/INTERNAL/x", true)]
    [InlineData("GET", "/ui/v1/Hub", true)]
    // GET auth/me is the one user route of the class, in any letter case.
    [InlineData("GET", "/ui/v1/auth/me", false)]
    [InlineData("GET", "/ui/v1/AUTH/Me", false)]
    [InlineData("POST", "/ui/v1/auth/me", true)]
    [InlineData("GET", "/ui/v1/auth/me/sessions", true)]
    [InlineData("GET", "/ui/v1/auth/other", true)]
    // Segments that only start with a class name are ordinary paths.
    [InlineData("GET", "/ui/v1/authors", false)]
    [InlineData("GET", "/ui/v1/hubs/1", false)]
    [InlineData("GET", "/ui/v1/internals", false)]
    [InlineData("GET", "/ui/v1/projects", false)]
    [InlineData("POST", "/ui/v1/projects/p1/issues", false)]
    // The root itself is not in the class.
    [InlineData("GET", "/ui/v1", false)]
    [InlineData("GET", "/ui/v1/", false)]
    public void Path_InsideTheRoot_IsRefusedExactlyWhenItIsInTheClass(string method, string path, bool refused)
    {
        Assert.Equal(refused, Refuses(method, path));
    }

    // A dot segment hidden behind an encoded slash is dropped, so it neither
    // hides a class segment nor turns GET auth/me into another path.
    [Theory]
    [InlineData("POST", "/ui/v1/%2F.%2Fauth/login", true)]
    [InlineData("GET", "/ui/v1/%2F.%2Fhub/x", true)]
    [InlineData("GET", "/ui/v1/auth/%2F.%2Fme", false)]
    [InlineData("POST", "/ui/v1/auth/%2F.%2Fme", true)]
    [InlineData("GET", "/ui/v1/%2F.%2Fprojects", false)]
    public void DotSegment_BehindAnEncodedSlash_IsDropped(string method, string path, bool refused)
    {
        Assert.Equal(refused, Refuses(method, path));
    }

    // A ".." that has nothing above it stays at the root instead of failing.
    [Fact]
    public void ParentSegment_AtTheRoot_StaysAtTheRoot()
    {
        Assert.False(Refuses("GET", "/..%2F..%2Fui/v1/projects"));
        Assert.True(Refuses("GET", "/..%2F..%2Fui/v1/hub/x"));
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/ui")]
    [InlineData("/ui/")]
    public void Path_ShorterThanTheRoot_IsRefused(string path)
    {
        Assert.True(Refuses("GET", path));
    }

    [Theory]
    [InlineData("/api/v1/projects")]
    [InlineData("/ui/v2/projects")]
    [InlineData("/ui/v1/../hub/x")]
    [InlineData("/other/ui/v1/projects")]
    public void Path_OutsideTheRoot_IsRefused(string path)
    {
        Assert.True(Refuses("GET", path));
    }

    [Theory]
    [InlineData("/base/ui/v1/projects", false)]
    [InlineData("/base/ui/v1/hub/x", true)]
    [InlineData("/ui/v1/projects", true)]
    public void RootWithABasePath_IsMatchedSegmentBySegment(string path, bool refused)
    {
        Assert.Equal(refused, Refuses("GET", path, root: "/base/ui/v1"));
    }

    [Fact]
    public void RelativeUpstream_IsAnArgumentError_NamingTheParameter()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            ServicePathClass.Refuses("GET", new Uri("/ui/v1/projects", UriKind.Relative), Root));

        Assert.Equal("upstream", ex.ParamName);
    }
}
