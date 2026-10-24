using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;
using SkeinWeb.Auth;

namespace SkeinWeb.Middleware;

/// <summary>
/// Reverse-proxy middleware for the agent data-plane <c>/agent/v1/*</c>
/// (sk-142, agent task-monitor). It is the BFF half of the "second door"
/// auth model: external API-key agents reach skein-api's <c>/agent/v1</c>
/// routes carrying a short-lived monitor token (<c>skm_</c>) on
/// <c>X-Skein-Api-Key</c>, WITHOUT ever touching the cookie-auth flow that
/// gates <c>/api/v1/*</c>.
///
/// This is a deliberate sibling of <see cref="McpProxyMiddleware"/> — not an
/// edit of it — because the two differ in exactly one load-bearing way: the
/// path matcher. <c>/mcp</c> is a single-endpoint transport matched EXACTLY
/// (see <c>McpProxyMiddleware.IsMcpPath</c>); <c>/agent/v1</c> has sub-paths
/// (<c>/agent/v1/notifications/poll</c>, <c>/agent/v1/monitor-script</c>) and
/// must therefore match by SEGMENT boundary. Everything else — header
/// forwarding policy, identity-header stripping, internal-secret injection,
/// streaming response copy — is identical to the MCP proxy and intentionally
/// duplicated rather than abstracted, so the MCP-specific SSE comments do not
/// mislead a reader of this file.
/// </summary>
/// <remarks>
/// <list type="bullet">
///   <item><description>
///     <b>No cookie auth.</b> Agents are not browsers; they authenticate with
///     <c>X-Skein-Api-Key</c> (a <c>skm_</c> monitor token) directly to
///     skein-api, validated there by <c>RequireMonitorToken</c>. We do NOT
///     short-circuit on missing cookies and do NOT add <c>X-Skein-User-*</c>
///     identity headers. The middleware is registered ABOVE
///     <c>UseAuthentication</c> in the pipeline for this reason.
///   </description></item>
///   <item><description>
///     <b>Streaming, no buffering.</b> The poll endpoint can degrade to a
///     long-poll (spec §9); buffering would make a slow upstream stick in our
///     response buffer. We disable response buffering and use
///     <see cref="HttpCompletionOption.ResponseHeadersRead"/> so headers come
///     back the moment skein-api sends them.
///   </description></item>
///   <item><description>
///     <b>API-key passthrough + identity-header strip.</b> The
///     <c>X-Skein-Api-Key</c> header is the agent's own credential and IS
///     forwarded verbatim. Inbound <c>Cookie</c>/<c>Authorization</c> and any
///     <c>X-Skein-User-*</c> headers are stripped (defence-in-depth — an agent
///     must not be able to spoof user identity). The internal-secret header is
///     added by us (channel auth, distinct from the per-user token).
///   </description></item>
/// </list>
/// </remarks>
public sealed class AgentProxyMiddleware : IMiddleware
{
    /// <summary>
    /// The segment-prefix Skein exposes for the agent data-plane. Matched by
    /// <see cref="PathString.StartsWithSegments(PathString, out PathString)"/>
    /// so <c>/agent/v1</c> and anything under it (e.g.
    /// <c>/agent/v1/notifications/poll</c>) are proxied, while sibling paths
    /// (<c>/agent</c>, <c>/agentx</c>, <c>/agent/v10</c>, <c>/agent/v2</c>) are
    /// NOT — StartsWithSegments compares whole path segments, so it never
    /// matches on a partial-segment prefix.
    /// </summary>
    private const string AgentV1Path = "/agent/v1";

    // Small buffer so each chunk is forwarded promptly (long-poll friendly).
    private const int ChunkBufferBytes = 4096;

    /// <summary>
    /// Maximum time the upstream may take to flush response headers. The
    /// stream body has no timeout (a long-poll may legitimately stay open);
    /// this bound applies only to the connect/headers phase via a linked
    /// CancellationTokenSource. See <see cref="ProxyAsync"/>.
    /// </summary>
    private static readonly TimeSpan UpstreamHeadersTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Hop-by-hop headers (RFC 7230 §6.1). Same list as
    /// <see cref="McpProxyMiddleware"/>; duplicated deliberately (see class
    /// remarks) rather than shared.
    /// </summary>
    private static readonly HashSet<string> HopByHopHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        "Host",
    };

    private readonly IHttpClientFactory _httpFactory;
    private readonly ILogger<AgentProxyMiddleware> _logger;
    private readonly SkeinApiOptions _options;

    public AgentProxyMiddleware(
        IHttpClientFactory httpFactory,
        IOptions<SkeinApiOptions> options,
        ILogger<AgentProxyMiddleware> logger)
    {
        _httpFactory = httpFactory;
        _options = options.Value;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        if (!IsAgentPath(context.Request.Path))
        {
            await next(context);
            return;
        }

        // SECURITY (sk-142.3): reject any dot-segment ("." / "..") in the path
        // BEFORE building/forwarding the upstream URL. This middleware runs
        // ABOVE UseAuthentication and attaches the BFF->API internal secret, so
        // a traversal sequence like /agent/v1/../../api/v1/issues would
        // otherwise be normalized by System.Uri when ProxyAsync concatenates
        // the path into an absolute upstream URL — escaping the /agent/v1
        // subtree and reaching arbitrary upstream routes with the internal
        // secret attached (a cookie-auth / privilege bypass). A malformed agent
        // request is rejected outright (400); we deliberately do NOT call
        // next() — that is the cookie-gated /api/v1 pipeline and this is not a
        // valid request for it.
        if (HasDotSegment(context.Request.Path))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                "{\"error\":\"invalid_path\"}",
                context.RequestAborted);
            return;
        }

        // Strip identity-spoofable headers before forwarding. On /agent/v1 the
        // upstream reads identity from the monitor token via
        // RequireMonitorToken; browser/agent-supplied X-Skein-User-* values
        // are never trusted and must not pollute audit logs.
        StripSpoofableUserHeaders(context.Request);

        await ProxyAsync(context);
    }

    /// <summary>
    /// Whether the requested path is under the agent data-plane. Uses
    /// <see cref="PathString.StartsWithSegments(PathString, StringComparison, out PathString)"/>
    /// which is segment-aware: <c>/agent/v1</c> and <c>/agent/v1/...</c> match,
    /// but <c>/agent</c>, <c>/agentx</c>, <c>/agent/v10</c> and <c>/agent/v2</c>
    /// do NOT (no partial-segment matches). The <c>remaining</c> out value is
    /// discarded — we forward the full original path verbatim below, which
    /// preserves the matched prefix and the rest of the path identically.
    /// </summary>
    private static bool IsAgentPath(PathString path) =>
        path.StartsWithSegments(AgentV1Path, StringComparison.OrdinalIgnoreCase, out _);

    /// <summary>
    /// Whether the path contains a relative dot-segment (<c>.</c> or <c>..</c>)
    /// as a whole path segment. Used to fail-closed on traversal attempts
    /// before the path is concatenated into an absolute upstream URL — where
    /// <see cref="Uri"/> would normalize the dot segments away and let the
    /// request escape the <c>/agent/v1</c> subtree (see
    /// <see cref="InvokeAsync"/>). The scan runs on the already-percent-decoded
    /// <see cref="HttpRequest.Path"/>, so an encoded <c>%2e%2e</c> arrives here
    /// as a literal <c>..</c> segment and is caught by the same check as a raw
    /// <c>..</c>.
    /// </summary>
    private static bool HasDotSegment(PathString path)
    {
        var value = path.Value;
        if (string.IsNullOrEmpty(value)) return false;
        foreach (var segment in value.Split('/'))
        {
            if (segment == "." || segment == "..") return true;
        }
        return false;
    }

    /// <summary>
    /// Drop X-Skein-User-Id / -Email / -Username / -Role (any X-Skein-* except
    /// the api-key) from the inbound request. We deliberately do NOT strip
    /// <see cref="SkeinHeaders.ApiKey"/>: it is the agent's own credential and
    /// the entire reason this path exists.
    /// </summary>
    private static void StripSpoofableUserHeaders(HttpRequest request)
    {
        var toRemove = request.Headers.Keys
            .Where(k =>
                k.StartsWith(SkeinHeaders.Prefix, StringComparison.OrdinalIgnoreCase) &&
                !k.Equals(SkeinHeaders.ApiKey, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        foreach (var key in toRemove)
        {
            request.Headers.Remove(key);
        }
    }

    private async Task ProxyAsync(HttpContext context)
    {
        var ct = context.RequestAborted;

        // Disable response buffering up-front so long-poll responses are not
        // queued in our buffer.
        var bodyFeature = context.Features.Get<IHttpResponseBodyFeature>();
        bodyFeature?.DisableBuffering();

        // Dedicated client (no InternalApiHandler — that would inject
        // X-Skein-User-* from a cookie principal we explicitly do not have
        // here; no Polly — a streaming/long-poll body must not be retried).
        // We add the internal-secret header by hand below.
        var client = _httpFactory.CreateClient("skein-api-agent");

        // Forward the full original path (already begins with /agent/v1) plus
        // the query string verbatim.
        var upstreamUrl = _options.Url.TrimEnd('/')
                         + context.Request.Path.ToString()
                         + context.Request.QueryString.ToString();

        using var upstream = new HttpRequestMessage(
            new HttpMethod(context.Request.Method),
            upstreamUrl);

        if (HasRequestBody(context.Request.Method))
        {
            upstream.Content = new StreamContent(context.Request.Body);
            if (context.Request.ContentType is { } ctype)
            {
                upstream.Content.Headers.TryAddWithoutValidation("Content-Type", ctype);
            }
            if (context.Request.ContentLength is { } clen)
            {
                upstream.Content.Headers.ContentLength = clen;
            }
        }

        // Forward headers, dropping hop-by-hop and Content-*. Keep
        // X-Skein-Api-Key verbatim (the monitor credential). Strip Cookie and
        // Authorization defensively: agents authenticate via X-Skein-Api-Key
        // only; cookies belong to the /api/v1/* cookie-auth flow and have no
        // upstream consumer here, so leaking them across channels is pure
        // attack surface.
        foreach (var (name, values) in context.Request.Headers)
        {
            if (HopByHopHeaders.Contains(name)) continue;
            if (name.StartsWith("Content-", StringComparison.OrdinalIgnoreCase)) continue;
            if (name.Equals("Cookie", StringComparison.OrdinalIgnoreCase)) continue;
            if (name.Equals("Authorization", StringComparison.OrdinalIgnoreCase)) continue;
            upstream.Headers.TryAddWithoutValidation(name, values.ToArray());
        }

        // Channel auth (BFF -> API). Defence-in-depth: skein-api also applies
        // RequireInternalSecret on /agent/v1.
        upstream.Headers.Remove(SkeinHeaders.InternalSecret);
        upstream.Headers.TryAddWithoutValidation(SkeinHeaders.InternalSecret, _options.InternalSecret);

        // Per-attempt headers timeout. The named client uses
        // Timeout.InfiniteTimeSpan because HttpClient.Timeout would also bound
        // the (possibly long-poll) body — we only want to bound the
        // connect/headers phase. A linked CTS cancels on either client
        // disconnect (ct) or after UpstreamHeadersTimeout, distinguishable in
        // the catch block via ct.IsCancellationRequested.
        using var headersCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        headersCts.CancelAfter(UpstreamHeadersTimeout);

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(upstream, HttpCompletionOption.ResponseHeadersRead, headersCts.Token);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Client disconnected before we got headers — nothing to send back.
            return;
        }
        catch (OperationCanceledException ex)
        {
            // headersCts fired: upstream took longer than UpstreamHeadersTimeout
            // to flush response headers. Distinct from a client-cancelled
            // request and from an unreachable upstream.
            using (_logger.BeginScope(new Dictionary<string, object?>
            {
                ["method"]      = context.Request.Method,
                ["upstreamUrl"] = upstreamUrl,
            }))
            {
                _logger.LogWarning(ex, "agent proxy: upstream headers timeout at {Url}", upstreamUrl);
            }
            if (!context.Response.HasStarted)
            {
                context.Response.StatusCode = StatusCodes.Status504GatewayTimeout;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(
                    "{\"error\":\"upstream_timeout\",\"message\":\"skein-api did not respond in time\"}",
                    ct);
            }
            return;
        }
        catch (HttpRequestException ex)
        {
            using (_logger.BeginScope(new Dictionary<string, object?>
            {
                ["method"]      = context.Request.Method,
                ["upstreamUrl"] = upstreamUrl,
            }))
            {
                _logger.LogError(ex, "agent proxy: failed to reach skein-api");
            }
            context.Response.StatusCode = StatusCodes.Status502BadGateway;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                "{\"error\":\"upstream_unavailable\",\"message\":\"skein-api is unreachable\"}",
                ct);
            return;
        }

        using (response)
        {
            context.Response.StatusCode = (int)response.StatusCode;

            foreach (var (name, values) in response.Headers)
            {
                if (HopByHopHeaders.Contains(name)) continue;
                context.Response.Headers[name] = values.ToArray();
            }
            foreach (var (name, values) in response.Content.Headers)
            {
                if (HopByHopHeaders.Contains(name)) continue;
                context.Response.Headers[name] = values.ToArray();
            }
            // Kestrel chooses Transfer-Encoding/Content-Length itself.
            context.Response.Headers.Remove("Transfer-Encoding");

            await using var upstreamStream = await response.Content.ReadAsStreamAsync(ct);
            try
            {
                await upstreamStream.CopyToAsync(context.Response.Body, bufferSize: ChunkBufferBytes, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                // Client disconnected mid-stream — nothing more to do.
            }
            catch (OperationCanceledException ex)
            {
                // Upstream cancelled mid-stream. Headers already flushed, so we
                // cannot rewrite to a 5xx — log for diagnosis and tear down.
                using (_logger.BeginScope(new Dictionary<string, object?>
                {
                    ["method"]      = context.Request.Method,
                    ["upstreamUrl"] = upstreamUrl,
                }))
                {
                    _logger.LogWarning(ex, "agent proxy: upstream stream cancelled at {Url}", upstreamUrl);
                }
            }
        }
    }

    private static bool HasRequestBody(string method) =>
        HttpMethods.IsPost(method) ||
        HttpMethods.IsPut(method) ||
        HttpMethods.IsPatch(method);
}
