using System.Net;
using SkeinWeb.Auth;

namespace SkeinWeb.Middleware;

/// <summary>
/// What the edge of the pipeline saw before <c>X-Forwarded-*</c> processing
/// rewrote the request: the transport peer and whether a trusted peer sent an
/// ambiguous <c>X-Forwarded-Host</c>. Stored as a typed feature in
/// <see cref="HttpContext.Features"/> by <see cref="EdgeSnapshotMiddleware"/>.
/// </summary>
/// <param name="TransportPeer">Address of the TCP connection that reached
/// skein-web, taken from <c>Connection.RemoteIpAddress</c> before forwarded
/// headers are applied; never from a header. <c>null</c> when the server did not
/// report one.</param>
/// <param name="AmbiguousForwardedHost">Whether a trusted peer sent
/// <c>X-Forwarded-Host</c> with more than one value (comma-separated or on
/// repeated lines) or with an empty value. Decided on the header as it arrived;
/// always <c>false</c> for a peer that is not trusted, whose header is ignored.</param>
public sealed record EdgeSnapshot(IPAddress? TransportPeer, bool AmbiguousForwardedHost);

/// <summary>
/// First link of <see cref="SkeinEdgePipeline.UseSkeinEdge"/>: records an
/// <see cref="EdgeSnapshot"/> before <c>UseForwardedHeaders</c> replaces the
/// client address with the visitor from <c>X-Forwarded-For</c> and reduces
/// <c>X-Forwarded-Host</c> to one name.
/// </summary>
/// <remarks>
/// The snapshot is kept apart from the request: <c>Connection.RemoteIpAddress</c>
/// is not touched and, after forwarded headers are applied, stays the visitor
/// address the rate limiters and <c>X-Skein-Client-Ip</c> rely on. Trust
/// decisions read the transport peer from the snapshot instead.
/// </remarks>
public sealed class EdgeSnapshotMiddleware(RequestDelegate next, TrustedProxyConfig trustedProxies)
{
    /// <summary>Name of the header whose arriving shape is recorded.</summary>
    private const string ForwardedHostHeader = "X-Forwarded-Host";

    /// <summary>Records the snapshot and calls the next middleware.</summary>
    /// <param name="context">The request.</param>
    public Task InvokeAsync(HttpContext context)
    {
        var peer = context.Connection.RemoteIpAddress;
        var ambiguous = trustedProxies.Contains(peer) && IsAmbiguous(context.Request.Headers);
        context.Features.Set(new EdgeSnapshot(peer, ambiguous));
        return next(context);
    }

    /// <summary>
    /// Whether <c>X-Forwarded-Host</c> is present with more than one value: on
    /// repeated lines, or comma-separated in one line, or with an empty value.
    /// Such a header means a hop passed on what the visitor sent, and the one
    /// name forwarded-header processing would pick from it is not a checked name.
    /// </summary>
    private static bool IsAmbiguous(IHeaderDictionary headers)
    {
        if (!headers.TryGetValue(ForwardedHostHeader, out var values))
        {
            return false;
        }
        if (values.Count != 1)
        {
            return true;
        }
        var value = values[0];
        return string.IsNullOrWhiteSpace(value) || value.Contains(',');
    }
}
