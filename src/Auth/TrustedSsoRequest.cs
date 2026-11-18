using SkeinWeb.Middleware;

namespace SkeinWeb.Auth;

/// <summary>
/// The one definition of "a trusted SSO request": a request in the legacy
/// trust-headers mode that the authenticating proxy at the edge vouches for.
/// <see cref="SsoSessionMiddleware"/> and the early session-store failure
/// boundary read this type, so they cannot disagree about which requests carry
/// an SSO identity.
/// </summary>
/// <remarks>
/// A request is a trusted SSO request only when ALL of these hold:
/// <list type="number">
///   <item><description>the auth mode is the legacy trust-headers mode
///   (<see cref="WebAuthMode.IsKeycloakMode"/>);</description></item>
///   <item><description>the path is not one of <see cref="BypassPaths"/> (infrastructure
///   and static endpoints the SSO middleware never touches);</description></item>
///   <item><description>the transport peer recorded by <see cref="EdgeSnapshotMiddleware"/> is in
///   <c>SKEIN_TRUSTED_PROXIES</c> (no snapshot, or an empty list, trusts nobody);</description></item>
///   <item><description>both <see cref="EmailHeader"/> and <see cref="UserHeader"/> carry a value
///   that is not empty or whitespace.</description></item>
/// </list>
/// Nothing a client controls other than the two headers takes part in the decision.
/// </remarks>
public static class TrustedSsoRequest
{
    /// <summary>oauth2-proxy header carrying the user name (<c>preferred_username</c>).</summary>
    public const string UserHeader = "X-Auth-Request-User";

    /// <summary>oauth2-proxy header carrying the e-mail address.</summary>
    public const string EmailHeader = "X-Auth-Request-Email";

    /// <summary>
    /// Paths that never take part in SSO, even in the trust-headers mode: they
    /// either do not traverse the proxy or must work without a session.
    /// </summary>
    public static readonly IReadOnlyList<string> BypassPaths = new[]
    {
        "/healthz",
        "/ready",
        "/metrics",
        "/mcp",
        "/api/auth/config",
    };

    /// <summary>Whether <paramref name="path"/> is, or lies under, one of <see cref="BypassPaths"/>.</summary>
    public static bool IsBypassPath(PathString path)
    {
        foreach (var prefix in BypassPaths)
        {
            if (path.StartsWithSegments(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>Whether the request carries either trust header, whatever its value.</summary>
    public static bool HasTrustHeaders(HttpRequest request) =>
        request.Headers.ContainsKey(EmailHeader) || request.Headers.ContainsKey(UserHeader);

    /// <summary>
    /// Whether the transport peer of this request is in <paramref name="trustedProxies"/>.
    /// A request without an <see cref="EdgeSnapshot"/> has no known peer and is not trusted.
    /// </summary>
    public static bool IsFromTrustedPeer(HttpContext context, TrustedProxyConfig trustedProxies) =>
        trustedProxies.Contains(context.Features.Get<EdgeSnapshot>()?.TransportPeer);

    /// <summary>
    /// Reads the identity the proxy forwarded. Returns false unless both headers
    /// carry a value that is not empty or whitespace.
    /// </summary>
    public static bool TryReadIdentity(HttpRequest request, out string email, out string username)
    {
        var rawEmail = request.Headers[EmailHeader].FirstOrDefault();
        var rawUsername = request.Headers[UserHeader].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(rawEmail) || string.IsNullOrWhiteSpace(rawUsername))
        {
            email = string.Empty;
            username = string.Empty;
            return false;
        }

        email = rawEmail;
        username = rawUsername;
        return true;
    }

    /// <summary>
    /// The predicate: true only in the trust-headers mode, off the bypass paths, from a
    /// trusted transport peer, with both identity headers non-empty.
    /// </summary>
    public static bool Matches(HttpContext context, WebAuthMode mode, TrustedProxyConfig trustedProxies) =>
        mode.IsKeycloakMode
        && !IsBypassPath(context.Request.Path)
        && IsFromTrustedPeer(context, trustedProxies)
        && TryReadIdentity(context.Request, out _, out _);
}
