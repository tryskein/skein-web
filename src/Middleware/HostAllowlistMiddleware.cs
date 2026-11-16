using SkeinWeb.Auth;

namespace SkeinWeb.Middleware;

/// <summary>
/// Last link of <see cref="SkeinEdgePipeline.UseSkeinEdge"/>: with a non-empty
/// <c>SKEIN_ALLOWED_HOSTS</c>, a request whose actual host is not in the list
/// answers 400 <c>{"error":"invalid_host",…}</c> before any other processing.
/// </summary>
/// <remarks>
/// <para>It runs after forwarded headers are applied, so the host compared is
/// the actual host: <c>X-Forwarded-Host</c> of a trusted peer, otherwise the
/// literal <c>Host</c>. A trusted peer's <c>X-Forwarded-Host</c> with several
/// values or an empty one (<see cref="EdgeSnapshot.AmbiguousForwardedHost"/>,
/// decided before forwarded headers reduce it to one name) is refused too: the
/// one name picked from it is not a checked name. A request that reaches this
/// check without a host (HTTP/1.0) is refused; an HTTP/1.1 request without
/// <c>Host</c> is refused by the server before the application.</para>
/// <para><c>/healthz</c>, <c>/ready</c> and <c>/metrics</c> skip the check,
/// matched per segment: probes reach the pod by its address. With an empty list
/// nothing is checked. Not the framework's host filtering, whose
/// <c>AllowedHosts</c> stays <c>*</c>.</para>
/// </remarks>
public sealed class HostAllowlistMiddleware(RequestDelegate next, AllowedHostsConfig allowedHosts)
{
    /// <summary>Probe and metrics paths that never go through the check.</summary>
    private static readonly string[] ProbePaths = ["/healthz", "/ready", "/metrics"];

    /// <summary>Checks the host and calls the next middleware, or answers 400.</summary>
    /// <param name="context">The request.</param>
    public async Task InvokeAsync(HttpContext context)
    {
        if (allowedHosts.IsEmpty || IsProbePath(context.Request.Path))
        {
            await next(context);
            return;
        }

        var ambiguous = context.Features.Get<EdgeSnapshot>()?.AmbiguousForwardedHost ?? false;
        var host = context.Request.Host;
        if (ambiguous || !host.HasValue || !allowedHosts.Allows(host.Host))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                "{\"error\":\"invalid_host\",\"message\":\"the request host is not served here\"}",
                context.RequestAborted);
            return;
        }

        await next(context);
    }

    private static bool IsProbePath(PathString path) =>
        ProbePaths.Any(p => path.StartsWithSegments(p, StringComparison.OrdinalIgnoreCase));
}
