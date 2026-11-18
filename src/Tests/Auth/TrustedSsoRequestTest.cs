using System.Net;
using Microsoft.AspNetCore.Http;
using SkeinWeb.Auth;
using SkeinWeb.Middleware;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// The trust boundary of the legacy trust-headers mode (US-8): a request is a
/// "trusted SSO request" only in that mode, off the service paths, from a transport
/// peer listed in <c>SKEIN_TRUSTED_PROXIES</c>, with both identity headers non-blank.
/// The expectations come from that rule, not from the predicate's implementation.
/// </summary>
public class TrustedSsoRequestTest
{
    private const string TrustedPeer = "10.0.0.1";
    private const string UntrustedPeer = "10.9.9.9";

    private static readonly TrustedProxyConfig TrustedProxies = TrustedProxyConfig.FromEntries([TrustedPeer]);

    private static readonly WebAuthMode TrustHeadersMode = WebAuthMode.FromApi("keycloak", null);

    private static DefaultHttpContext Request(string path, string? peer, string? email, string? username)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Path = path;
        if (peer is not null)
        {
            ctx.Features.Set(new EdgeSnapshot(IPAddress.Parse(peer), AmbiguousForwardedHost: false));
        }
        if (email is not null)
        {
            ctx.Request.Headers[TrustedSsoRequest.EmailHeader] = email;
        }
        if (username is not null)
        {
            ctx.Request.Headers[TrustedSsoRequest.UserHeader] = username;
        }
        return ctx;
    }

    // Row order: path, peer (null = no edge snapshot), email header (null = absent),
    // user header (null = absent), expected. Every row but the first differs from it
    // in exactly one condition of the rule.
    [Theory]
    [InlineData("/api/auth/me", TrustedPeer, "a@example.com", "alice", true)]
    [InlineData("/api/auth/me", UntrustedPeer, "a@example.com", "alice", false)]
    [InlineData("/api/auth/me", null, "a@example.com", "alice", false)]
    [InlineData("/api/auth/me", TrustedPeer, "", "alice", false)]
    [InlineData("/api/auth/me", TrustedPeer, "   ", "alice", false)]
    [InlineData("/api/auth/me", TrustedPeer, null, "alice", false)]
    [InlineData("/api/auth/me", TrustedPeer, "a@example.com", "", false)]
    [InlineData("/api/auth/me", TrustedPeer, "a@example.com", "   ", false)]
    [InlineData("/api/auth/me", TrustedPeer, "a@example.com", null, false)]
    [InlineData("/api/auth/me", TrustedPeer, null, null, false)]
    [InlineData("/healthz", TrustedPeer, "a@example.com", "alice", false)]
    [InlineData("/ready", TrustedPeer, "a@example.com", "alice", false)]
    [InlineData("/metrics", TrustedPeer, "a@example.com", "alice", false)]
    [InlineData("/api/auth/config", TrustedPeer, "a@example.com", "alice", false)]
    [InlineData("/mcp", TrustedPeer, "a@example.com", "alice", false)]
    [InlineData("/mcp/session", TrustedPeer, "a@example.com", "alice", false)]
    public void TrustHeadersMode_IsTrustedSsoOnlyWhenEveryConditionHolds(
        string path, string? peer, string? email, string? username, bool expected)
    {
        var ctx = Request(path, peer, email, username);

        Assert.Equal(expected, TrustedSsoRequest.Matches(ctx, TrustHeadersMode, TrustedProxies));
    }

    [Theory]
    [InlineData("local", null)]
    [InlineData("keycloak", "https://idp.example.com/realms/skein")]
    [InlineData("hybrid", "https://idp.example.com/realms/skein")]
    public void OtherModes_AreNeverTrustedSso(string apiAuthMode, string? authority)
    {
        var ctx = Request("/api/auth/me", TrustedPeer, "a@example.com", "alice");

        Assert.False(TrustedSsoRequest.Matches(ctx, WebAuthMode.FromApi(apiAuthMode, authority), TrustedProxies));
    }

    [Fact]
    public void EmptyTrustedList_TrustsNoPeer()
    {
        var ctx = Request("/api/auth/me", TrustedPeer, "a@example.com", "alice");

        Assert.False(TrustedSsoRequest.Matches(ctx, TrustHeadersMode, TrustedProxyConfig.FromEntries([])));
    }
}
