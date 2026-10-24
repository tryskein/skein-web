using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Options;
using SkeinWeb.Auth;

namespace SkeinWeb.Middleware;

/// <summary>
/// Reverse-proxy middleware for everything under <c>/api/v1/*</c>: streams
/// the browser's request to skein-api (adding internal-secret + identity
/// forward headers) and streams the response back. Other paths are passed
/// through to the next middleware (controllers, static files, SPA fallback).
/// </summary>
/// <remarks>
/// Why hand-rolled instead of YARP? YARP would do everything we need and
/// more, but for one upstream and a fixed identity-forwarding shape the
/// extra dependency and config surface is overkill. ~120 lines of code
/// keeps the trust boundary explicit: the input X-Skein-* headers are
/// stripped, then InternalApiHandler (on the named HttpClient) re-adds
/// them from the cookie principal — the entire identity-spoofing surface
/// is visible in two files.
///
/// No unauthenticated allowlist (sk-163 S9): every /api/v1/* request requires
/// an authenticated cookie. The old POST /api/v1/auth/login passthrough was
/// removed so external login can only go through the BFF's rate-limited
/// POST /api/auth/login route, never directly to skein-api's login endpoint.
/// </remarks>
public sealed class ApiProxyMiddleware : IMiddleware
{
    /// <summary>Path segment under which everything proxies to skein-api.</summary>
    private const string ProxyPrefix = "/api/v1";

    /// <summary>Name of the <see cref="IHttpClientFactory"/> client this middleware proxies through.</summary>
    public const string ProxyClientName = "skein-api";

    /// <summary>
    /// Registers the proxy's named client: skein-api base address, 30 s,
    /// <see cref="InternalApiHandler"/> (secret + identity of the session), no
    /// Polly (a streamed body cannot be replayed), and NO request logging of
    /// <see cref="IHttpClientFactory"/>: its default handlers write the full
    /// request URI at Information, and proxied paths carry secrets such as
    /// <c>/api/v1/invitations/{token}</c> (CLAUDE_DEV "What NOT to log").
    /// </summary>
    /// <param name="services">Service collection.</param>
    /// <param name="skeinApiUrl"><c>SKEIN_API_URL</c>.</param>
    public static IHttpClientBuilder AddProxyHttpClient(IServiceCollection services, string skeinApiUrl) =>
        services.AddHttpClient(ProxyClientName, client =>
            {
                client.BaseAddress = new Uri(skeinApiUrl);
                client.Timeout = TimeSpan.FromSeconds(30);
            })
            .RemoveAllLoggers()
            .AddHttpMessageHandler<InternalApiHandler>();

    /// <summary>
    /// Hop-by-hop headers (RFC 7230 §6.1) that must NOT be forwarded
    /// across the proxy. Comparing case-insensitively because HTTP/1.1
    /// header names are case-insensitive.
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
        // Host gets set by HttpClient on send; forwarding it risks SNI weirdness.
        "Host",
    };

    private readonly IHttpClientFactory _httpFactory;
    private readonly ILogger<ApiProxyMiddleware> _logger;
    private readonly SkeinApiOptions _options;

    public ApiProxyMiddleware(
        IHttpClientFactory httpFactory,
        IOptions<SkeinApiOptions> options,
        ILogger<ApiProxyMiddleware> logger)
    {
        _httpFactory = httpFactory;
        _options = options.Value;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var path = context.Request.Path;
        if (!path.StartsWithSegments(ProxyPrefix, StringComparison.OrdinalIgnoreCase))
        {
            await next(context);
            return;
        }

        // Trust boundary: strip ANY inbound X-Skein-* header. The browser
        // must not be able to forge identity headers; the only legitimate
        // source for these is InternalApiHandler, which adds them from the
        // cookie principal AFTER we've stripped the inbound copies.
        StripSpoofableHeaders(context.Request);

        // sk-163 S9 — NO unauthenticated allowlist. EVERY /api/v1/* request
        // (including /api/v1/auth/login) requires an authenticated cookie. The
        // former direct-login passthrough was removed: it let the browser reach
        // skein-api's POST /api/v1/auth/login WITHOUT a cookie, bypassing the
        // BFF's LoginRateLimiter entirely. External password login now goes ONLY
        // through the BFF route POST /api/auth/login (AuthController), which is
        // throttled per-email AND per-IP. A browser hitting /api/v1/auth/login
        // here is therefore unauthenticated → 401.
        if (context.User.Identity is not { IsAuthenticated: true })
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                "{\"error\":\"unauthenticated\",\"message\":\"sign in to call /api/v1/*\"}",
                context.RequestAborted);
            return;
        }

        await ProxyToApiAsync(context);
    }

    /// <summary>
    /// Remove every header whose name starts with <c>X-Skein-</c> or
    /// <c>X-Auth-Request-</c>. The BFF is the single source of truth
    /// for both header families:
    /// <list type="bullet">
    ///   <item><c>X-Skein-*</c> — minted by <c>InternalApiHandler</c>
    ///     from the cookie principal; allowing the browser to set them
    ///     would let any logged-in user impersonate anyone else on the
    ///     upstream (which trusts the channel-auth secret).</item>
    ///   <item><c>X-Auth-Request-*</c> — set by oauth2-proxy at the
    ///     cluster edge for the BFF's own consumption (see
    ///     <see cref="SkeinWeb.Middleware.SsoSessionMiddleware"/>). They
    ///     should never reach skein-api: defence in depth in case a
    ///     future change starts trusting them on the API side.</item>
    /// </list>
    /// </summary>
    private static void StripSpoofableHeaders(HttpRequest request)
    {
        var toRemove = request.Headers.Keys
            .Where(k =>
                k.StartsWith(SkeinHeaders.Prefix, StringComparison.OrdinalIgnoreCase) ||
                k.StartsWith("X-Auth-Request-", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        foreach (var key in toRemove)
        {
            request.Headers.Remove(key);
        }
    }

    private async Task ProxyToApiAsync(HttpContext context)
    {
        var ct = context.RequestAborted;
        var client = _httpFactory.CreateClient(ProxyClientName);

        // Build the absolute upstream URL: <api-base>/<path><query>
        // QueryString already includes the leading '?' when present.
        var upstreamUrl = _options.Url.TrimEnd('/')
                         + context.Request.Path.ToString()
                         + context.Request.QueryString.ToString();

        using var upstream = new HttpRequestMessage(
            new HttpMethod(context.Request.Method),
            upstreamUrl);

        // Body: stream straight through. Pre-buffering would defeat the
        // point of streaming uploads; HttpClient handles chunked transfer
        // when the inbound request is chunked.
        if (HasRequestBody(context.Request))
        {
            upstream.Content = new StreamContent(context.Request.Body);
            // Mirror Content-Type / Content-Length onto the StreamContent,
            // since they belong to the entity not the message.
            if (context.Request.ContentType is { } ctype)
            {
                upstream.Content.Headers.TryAddWithoutValidation("Content-Type", ctype);
            }
            if (context.Request.ContentLength is { } clen)
            {
                upstream.Content.Headers.ContentLength = clen;
            }
        }

        // Forward request headers, dropping hop-by-hop and X-Skein-* (the
        // latter are re-added by InternalApiHandler from the cookie principal).
        foreach (var (name, values) in context.Request.Headers)
        {
            if (HopByHopHeaders.Contains(name)) continue;
            if (name.StartsWith(SkeinHeaders.Prefix, StringComparison.OrdinalIgnoreCase)) continue;
            // Content-* headers belong to upstream.Content, not upstream.Headers.
            // We've already mapped Content-Type / Content-Length above; skip them
            // here so HttpClient doesn't refuse to add them on the wrong bag.
            if (name.StartsWith("Content-", StringComparison.OrdinalIgnoreCase)) continue;

            upstream.Headers.TryAddWithoutValidation(name, values.ToArray());
        }

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(upstream, HttpCompletionOption.ResponseHeadersRead, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Client disconnected — nothing to send.
            return;
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "proxy: failed to reach skein-api at {Url}", upstreamUrl);
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

            // Copy response headers, dropping hop-by-hop. HttpResponseMessage
            // splits headers into .Headers (general/response) and .Content.Headers
            // (entity); both must be forwarded.
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
            // Kestrel manages Transfer-Encoding/Content-Length itself; stripping
            // upstream's value avoids double-headers when chunking is decided
            // afresh on the outbound side.
            context.Response.Headers.Remove("Transfer-Encoding");

            // sk-674.18 K-16 — a 401 is read whole (skein-api's error bodies are
            // a few bytes) to tell session_revoked from any other 401. On
            // session_revoked the session ends HERE: cookie deleted, Redis
            // ticket removed — never a retry. The browser still gets skein-api's
            // own 401 body, so the SPA routes to /login. Any other 401 leaves
            // the session alone. Sign-out runs after the upstream headers are
            // copied so its Set-Cookie is not overwritten by them.
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                var body = await response.Content.ReadAsByteArrayAsync(ct);
                if (SessionRevocation.IsRevokedBody(body))
                {
                    _logger.LogInformation(
                        "proxy: skein-api revoked the session of {UserId}; signing out",
                        context.User.FindFirstValue(ClaimTypes.NameIdentifier));
                    await SessionRevocation.EndSessionAsync(context);
                }
                await context.Response.Body.WriteAsync(body, ct);
                return;
            }

            await using var upstreamStream = await response.Content.ReadAsStreamAsync(ct);
            try
            {
                await upstreamStream.CopyToAsync(context.Response.Body, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                // Client disconnected mid-stream; nothing more to do.
            }
        }
    }

    /// <summary>
    /// Whether to forward a body to upstream. POST/PUT/PATCH always
    /// semantically carry one. DELETE usually does not — but skein-api's
    /// Web Push contract (<c>DELETE /api/v1/push/subscriptions</c>) takes a
    /// JSON body <c>{ "endpoint": "..." }</c>, so a verb-only gate would
    /// silently strip it and the upstream would answer 400 invalid_json.
    /// We therefore forward a body for any request that actually carries
    /// one — a positive Content-Length, or a chunked request with no
    /// declared length (ContentLength == null but a non-empty body stream
    /// signalled by Transfer-Encoding). For bodyless GET/HEAD/DELETE the
    /// inbound Content-Length is 0 (or absent with no chunking), so nothing
    /// is attached and we don't force chunked encoding on a zero-byte body.
    /// </summary>
    private static bool HasRequestBody(HttpRequest request)
    {
        // Verbs that always carry a body — forward unconditionally so an
        // empty-but-present POST/PUT/PATCH body still reaches upstream.
        if (HttpMethods.IsPost(request.Method) ||
            HttpMethods.IsPut(request.Method) ||
            HttpMethods.IsPatch(request.Method))
        {
            return true;
        }

        // Other verbs (notably DELETE): forward only when a body is
        // actually present. Declared length > 0, or chunked (no
        // Content-Length but a Transfer-Encoding header).
        if (request.ContentLength is { } len)
        {
            return len > 0;
        }
        return request.Headers.ContainsKey("Transfer-Encoding");
    }
}
