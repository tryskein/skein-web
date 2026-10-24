using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;
using SkeinWeb.Auth;

namespace SkeinWeb.Middleware;

/// <summary>
/// Reverse-proxy middleware for the MCP endpoint <c>/mcp</c> (R2.1).
///
/// Differs from <see cref="ApiProxyMiddleware"/> in three load-bearing ways:
/// <list type="bullet">
///   <item><description>
///     <b>No cookie auth.</b> MCP clients are not browsers; they
///     authenticate with <c>X-Skein-Api-Key</c> directly to skein-api. We
///     do NOT short-circuit on missing cookies, do NOT call <c>UseAuthentication</c>
///     for this path, do NOT add identity headers (<c>X-Skein-User-*</c>).
///   </description></item>
///   <item><description>
///     <b>Streaming, no buffering.</b> Streamable-HTTP MCP responses can
///     be plain JSON-RPC OR a long-lived SSE stream. Buffering would make
///     the SSE notifications stick in our response buffer and block. We
///     disable response buffering on the
///     <see cref="IHttpResponseBodyFeature"/> and use
///     <see cref="HttpCompletionOption.ResponseHeadersRead"/> so headers
///     come back the moment skein-api sends them.
///   </description></item>
///   <item><description>
///     <b>API-key passthrough + identity-header strip.</b> The browser
///     could forge <c>X-Skein-User-*</c> headers; even though /mcp is
///     not gated on them, stripping is defence-in-depth. The
///     <c>X-Skein-Api-Key</c> header is the user's own credential and
///     IS forwarded verbatim. The internal-secret header is added by us
///     (channel auth, distinct from the per-user api key).
///   </description></item>
///   <item><description>
///     <b>Bearer compatibility mode (sk-304 stage 2).</b> An MCP client
///     configured with a static credential sends it the standard way —
///     <c>Authorization: Bearer</c> — so a Skein key presented that way is
///     translated into <c>X-Skein-Api-Key</c> here, on the public boundary.
///     A bearer value that is not a Skein key is NOT translated (that is the
///     future OAuth branch) and <c>Authorization</c> is never forwarded
///     upstream in either case. Contradictory credentials are refused with a
///     400, never silently resolved. See
///     <see cref="McpBearerCompatibility"/>.
///   </description></item>
///   <item><description>
///     <b>Access logging.</b> One structured line per request — method, path,
///     which credential headers were present (fact, never value), credential
///     transport, outcome. Inbound <c>/mcp</c> traffic used to be logged
///     nowhere; see <see cref="LogAccess"/>.
///   </description></item>
/// </list>
/// </summary>
/// <remarks>
/// Path matching: <c>/mcp</c> (and <c>/mcp/</c> for safety) plus the two
/// OAuth 2.0 Protected Resource Metadata URIs that describe it —
/// <c>/.well-known/oauth-protected-resource</c> and
/// <c>/.well-known/oauth-protected-resource/mcp</c> (sk-304, RFC 9728 §3
/// and §3.1). Anything else is passed to the next middleware in the
/// pipeline. We register this middleware ABOVE <see cref="ApiProxyMiddleware"/>
/// in the pipeline because /mcp does not start with /api/v1; ordering
/// matters only because each middleware short-circuits on path mismatch.
/// </remarks>
public sealed class McpProxyMiddleware : IMiddleware
{
    /// <summary>The path Skein exposes for MCP (Streamable HTTP transport).</summary>
    private const string McpPath = "/mcp";

    /// <summary>
    /// Root OAuth 2.0 Protected Resource Metadata URI (RFC 9728 §3), sk-304.
    /// </summary>
    private const string ResourceMetadataPath = "/.well-known/oauth-protected-resource";

    /// <summary>
    /// Path-aware Protected Resource Metadata URI for the <c>/mcp</c> resource
    /// (RFC 9728 §3.1 — the well-known suffix goes BETWEEN host and path).
    /// This is the URL skein-api names in the <c>WWW-Authenticate</c> challenge
    /// on a 401 from <c>/mcp</c>, so it is the one an MCP client fetches first.
    /// </summary>
    private const string ResourceMetadataMcpPath = "/.well-known/oauth-protected-resource/mcp";

    // Small buffer so each SSE event is forwarded promptly.
    private const int SseChunkBufferBytes = 4096;

    /// <summary>
    /// Machine-readable outcome on a 504 <c>upstream_timeout</c> / 502
    /// <c>upstream_unavailable</c> for a request that may have changed state
    /// upstream (sk-608): skein-api may already have committed the write. See
    /// <see cref="WriteUpstreamFailureAsync"/>.
    /// </summary>
    private const string OutcomeUnknown = "unknown";

    /// <summary>
    /// Hop-by-hop headers (RFC 7230 §6.1). Same list as
    /// <see cref="ApiProxyMiddleware"/> — keeping the two duplicated
    /// rather than shared because their request-stripping policies
    /// differ enough that a unified abstraction would obscure rather
    /// than clarify.
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
    private readonly ILogger<McpProxyMiddleware> _logger;
    private readonly SkeinApiOptions _options;
    private readonly TimeProvider _timeProvider;

    /// <param name="httpFactory">Source of the <c>skein-api-mcp</c> client.</param>
    /// <param name="options">Upstream address, channel secret and
    /// <see cref="SkeinApiOptions.McpUpstreamHeadersTimeout"/>.</param>
    /// <param name="timeProvider">Clock the headers timeout is scheduled on.</param>
    /// <param name="logger">Access and failure log.</param>
    public McpProxyMiddleware(
        IHttpClientFactory httpFactory,
        IOptions<SkeinApiOptions> options,
        TimeProvider timeProvider,
        ILogger<McpProxyMiddleware> logger)
    {
        _httpFactory = httpFactory;
        _options = options.Value;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var path = context.Request.Path;
        if (!IsProxiedPath(path))
        {
            await next(context);
            return;
        }

        // Strip identity-spoofable headers. The browser CANNOT plant
        // X-Skein-User-* on a request to /mcp and expect the upstream
        // to honour it (the api-key middleware overwrites whatever's
        // there) but we strip anyway so audit logs are not polluted by
        // attacker-supplied values.
        StripSpoofableUserHeaders(context.Request);

        // sk-304 stage 2. Classify the inbound credentials for the access log
        // on every proxied path; ENFORCE (translate / refuse) only on /mcp.
        // The metadata documents are public and credential-free — refusing one
        // over a credential conflict would break discovery for no gain, which
        // is the very failure sk-304 is about.
        var credentials = McpBearerCompatibility.Classify(context.Request);
        if (IsMcpPath(path))
        {
            if (credentials.Rejected)
            {
                LogAccess(context, credentials, StatusCodes.Status400BadRequest);
                await WriteCredentialConflictAsync(context, credentials.RejectionReason!);
                return;
            }
            if (credentials.TranslatedApiKey is { } translated)
            {
                // Compatibility mode: the key becomes the internal header. The
                // Authorization header itself is still NOT forwarded — the
                // strip in the forwarding loop below is unconditional.
                context.Request.Headers[SkeinHeaders.ApiKey] = translated;
            }
        }

        await ProxyAsync(context, credentials);
    }

    /// <summary>
    /// Refuse a request that presented two contradictory credentials
    /// (sk-304 stage 2).
    ///
    /// 400 with <c>invalid_request</c> is not a local invention: RFC 6750 §2
    /// says "Clients MUST NOT use more than one method to transmit the token in
    /// each request", and §3.1 defines <c>invalid_request</c> as covering a
    /// request that "uses more than one method for including an access token",
    /// adding "The resource server SHOULD respond with the HTTP 400 (Bad
    /// Request) status code". The MCP authorization spec's error table agrees:
    /// 400 = "Malformed authorization request". The alternative — silently
    /// picking one header — would stamp a possibly-wrong identity on every
    /// audit row the request writes, with no way to tell afterwards which
    /// credential won.
    ///
    /// The reason text is generated here, never echoed from the request, and
    /// never contains the credential — so it is safe both as JSON and inside
    /// the RFC 6750 <c>error_description</c> quoted-string.
    /// </summary>
    private static async Task WriteCredentialConflictAsync(HttpContext context, string reason)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        context.Response.Headers["WWW-Authenticate"] =
            $"Bearer error=\"invalid_request\", error_description=\"{reason}\"";
        await context.Response.WriteAsJsonAsync(
            new { error = "invalid_request", message = reason },
            context.RequestAborted);
    }

    /// <summary>
    /// One structured line per request that reaches this middleware: method,
    /// path, which of the two credential headers were present (the FACT only —
    /// never a value, so nothing here can leak a key past the slog/logger
    /// sanitiser), how the credential arrived, and the outcome status.
    ///
    /// <para><b>Why this exists.</b> Inbound <c>/mcp</c> requests were logged
    /// nowhere, in either service. That blindness is what stopped sk-304 (and
    /// sk-274.1 before it) from being settled from the journals: nobody could
    /// establish whether the client presented its key on the first request or
    /// probed unauthenticated first.</para>
    ///
    /// <para><b>Level.</b> A busy agent drives many POSTs per session, so the
    /// steady state is <c>Debug</c> (off in production, per the logging
    /// standard's "Debug = HTTP requests"). It is raised to
    /// <c>Information</c> exactly where a line is worth keeping: the request
    /// that opens a session (no <c>Mcp-Session-Id</c> yet — the first request
    /// of a conversation, and every metadata fetch), a request that carried no
    /// credential at all, a foreign bearer we dropped, and any 401/403.
    /// A refused conflict is a <c>Warning</c>. Net effect: one line per MCP
    /// session plus anomalies, not one line per tool call.</para>
    /// </summary>
    private void LogAccess(HttpContext context, in McpCredentialDecision credentials, int status)
    {
        var hasSession = !string.IsNullOrEmpty(
            context.Request.Headers[SkeinHeaders.McpSessionId].ToString());
        var level = SelectAccessLogLevel(credentials, status, hasSession);
        if (!_logger.IsEnabled(level))
        {
            return;
        }

        _logger.Log(
            level,
            // sk-304: the field NAMES are chosen to
            // avoid the secret-sanitiser denylist, which would
            // match field names case-insensitively on
            // password|token|secret|key|credential|authorization|apikey|api_key.
            // The earlier names (credentialTransport / apiKeyHeader /
            // authorizationHeader) each hit it. Nothing here CAN leak a key — every
            // argument is a bool or an enum — so the sanitiser would not be
            // protecting anything; it would blank the presence facts and leave a
            // line of "***" exactly where this log is supposed to answer "did the
            // client present its key at all". A log that a correct sanitiser
            // silently empties is worse than no log: it reads as evidence.
            "mcp proxy request method={Method} path={Path} authRoute={Transport} "
            + "nativeHdr={HasNativeHdr} authzHdr={HasAuthzHdr} "
            + "sessionHdr={HasSessionHdr} status={Status}",
            context.Request.Method,
            context.Request.Path.Value,
            credentials.Transport,
            credentials.HasApiKeyHeader,
            credentials.HasAuthorizationHeader,
            hasSession,
            status);
    }

    private static LogLevel SelectAccessLogLevel(
        in McpCredentialDecision credentials, int status, bool hasSession)
    {
        if (credentials.Transport == McpCredentialTransport.Conflict)
        {
            return LogLevel.Warning;
        }
        if (status is StatusCodes.Status401Unauthorized or StatusCodes.Status403Forbidden)
        {
            return LogLevel.Information;
        }
        if (credentials.Transport is McpCredentialTransport.None
            or McpCredentialTransport.ForeignBearerIgnored)
        {
            return LogLevel.Information;
        }
        // No session id yet ⇒ this is the request that opens the conversation
        // (or a metadata fetch, which never carries one). One keepable line per
        // session; the chatty remainder stays at Debug.
        return hasSession ? LogLevel.Debug : LogLevel.Information;
    }

    /// <summary>
    /// Whether the requested path is the MCP endpoint. We match <c>/mcp</c>
    /// exactly (with optional trailing slash) and nothing else. Streamable
    /// HTTP MCP is a single-endpoint transport — any future sub-path
    /// (e.g. <c>/mcp/admin</c>) must opt in deliberately rather than ride
    /// on a permissive prefix match that would silently bypass the cookie
    /// auth gate enforced under <c>/api/v1/*</c>.
    /// </summary>
    private static bool IsMcpPath(PathString path) =>
        path.Equals(McpPath, StringComparison.OrdinalIgnoreCase) ||
        path.Equals(new PathString("/mcp/"), StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Whether the requested path is one of the two OAuth 2.0 Protected
    /// Resource Metadata URIs of the MCP door (sk-304).
    ///
    /// This is the "deliberate opt-in" the remark above demands, and it is
    /// narrow on purpose: two exact paths, no prefix match. They belong to
    /// this middleware rather than <see cref="ApiProxyMiddleware"/> because
    /// they describe <c>/mcp</c> and must NOT be cookie-gated — a client reads
    /// them precisely because it cannot yet authenticate. Sitting here also
    /// puts them ahead of <c>UseAuthentication</c> in the pipeline, so an
    /// unauthenticated GET is proxied instead of being turned into a login
    /// challenge.
    ///
    /// Without this passthrough the request dies in skein-web with a 404
    /// (this image serves no SPA and no catch-all), the MCP client cannot
    /// discover where the metadata lives, and it falls back to interactive
    /// authorization it cannot perform in a headless session — the sk-304
    /// symptom.
    /// </summary>
    private static bool IsResourceMetadataPath(PathString path) =>
        path.Equals(ResourceMetadataPath, StringComparison.OrdinalIgnoreCase) ||
        path.Equals(ResourceMetadataMcpPath, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The full set of paths this middleware terminates: the MCP endpoint and
    /// its protected-resource metadata documents.
    /// </summary>
    private static bool IsProxiedPath(PathString path) =>
        IsMcpPath(path) || IsResourceMetadataPath(path);

    /// <summary>
    /// Drop X-Skein-User-Id / -Email / -Username / -Role from the inbound
    /// request. These headers are an artefact of the cookie-auth path; on
    /// /mcp the upstream reads identity from the api-key middleware and
    /// forwarding browser-supplied values would either be ignored
    /// (defence in depth) or — worse — confuse downstream audit logs.
    ///
    /// We deliberately do NOT strip <see cref="SkeinHeaders.ApiKey"/>:
    /// it is the user's own credential and the entire reason this path
    /// exists.
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

    private async Task ProxyAsync(HttpContext context, McpCredentialDecision credentials)
    {
        var ct = context.RequestAborted;

        // Disable response buffering up-front. Without this, IIS / Kestrel
        // may queue chunks and SSE notifications would arrive batched —
        // breaking MCP's expected push-style notification flow.
        var bodyFeature = context.Features.Get<IHttpResponseBodyFeature>();
        bodyFeature?.DisableBuffering();

        // Use a fresh HttpClient (not the named "skein-api" one) — that
        // client wires InternalApiHandler which tries to add X-Skein-User-*
        // from the cookie principal, which we explicitly do not want here.
        // We pull the unconfigured client and add the internal-secret
        // header by hand below.
        var client = _httpFactory.CreateClient("skein-api-mcp");

        var upstreamUrl = _options.Url.TrimEnd('/')
                         + context.Request.Path.ToString()
                         + context.Request.QueryString.ToString();

        using var upstream = new HttpRequestMessage(
            new HttpMethod(context.Request.Method),
            upstreamUrl);

        // Body: stream straight through. JSON-RPC bodies are small but
        // pre-buffering would also defeat any future MCP variant that
        // streams a request body.
        if (HasRequestBody(context.Request.Method))
        {
            // Disposed via the using-statement on `upstream`; ASP.NET tolerates
            // the wrapped Body being closed for terminating middleware.
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

        // Forward headers, dropping hop-by-hop. Keep X-Skein-Api-Key and
        // Mcp-Session-Id verbatim — they are part of the MCP contract.
        // We strip Cookie and Authorization defensively:
        // agents authenticate via X-Skein-Api-Key only; cookies belong to
        // the cookie-auth flow on /api/v1/* and have no upstream consumer
        // here, so leaking them across channels is pure attack surface.
        //
        // The Authorization strip is UNCONDITIONAL and stays that way after
        // sk-304 stage 2: compatibility mode copies an ska_ key INTO
        // X-Skein-Api-Key on the way in, it does not relax this line. skein-api
        // never learns to read an OAuth header for our opaque key, so a real
        // access token (once R5.1 mints them) cannot reach a service with no
        // validator for it — the token-passthrough the MCP security guidance
        // forbids. Pinned by McpProxyMiddlewareMetadataTest and
        // McpProxyMiddlewareBearerCompatTest.
        foreach (var (name, values) in context.Request.Headers)
        {
            if (HopByHopHeaders.Contains(name)) continue;
            // Content-* belongs on the entity, not the message.
            if (name.StartsWith("Content-", StringComparison.OrdinalIgnoreCase)) continue;
            if (name.Equals("Cookie", StringComparison.OrdinalIgnoreCase)) continue;
            if (name.Equals("Authorization", StringComparison.OrdinalIgnoreCase)) continue;
            upstream.Headers.TryAddWithoutValidation(name, values.ToArray());
        }

        // Channel auth (BFF → API). Defence-in-depth: skein-api also
        // applies RequireInternalSecret on /mcp.
        upstream.Headers.Remove(SkeinHeaders.InternalSecret);
        upstream.Headers.TryAddWithoutValidation(SkeinHeaders.InternalSecret, _options.InternalSecret);

        // Internal-surface marker. We are the ONLY party that may set it:
        // StripSpoofableUserHeaders already removed any inbound X-Skein-Surface
        // (it is in the X-Skein-* family), and we Remove again here
        // belt-and-braces before deciding. skein-api trusts this marker only
        // because /mcp also requires the internal secret above — a credential
        // no internet client holds — so the value provably originates here.
        //
        // sk-303.8 — this used to be conditional on Request.Host matching a
        // configured allowlist (sk-163 S7a, SKEIN_INTERNAL_HOSTS): stamp only
        // on a recognised internal host, leave it absent otherwise so
        // skein-api's gate would reject internal-owner api-keys on the public
        // surface. That mechanism was removed, not hardened, because it never
        // divided anything in the shape it was written for: every route that
        // reached skein-web came in through the internal gateway and no public
        // route existed, so the allowlist matched every request it ever saw —
        // and it derived a privilege decision from Request.Host, a header the
        // CLIENT controls (with no trusted proxy configured, a supported
        // deployment shape, Host is taken verbatim). A boundary an
        // attacker can draw for you is worse than no boundary — it gives false
        // confidence instead of none. So the marker is now stamped
        // unconditionally, matching the empty-allowlist default this class
        // always ran under in production.
        //
        // If a public surface ever ships (R5.1 hybrid/Keycloak), rebuild this
        // gate on a signal the SERVER controls, not one the client sends — e.g.
        // the listener port/endpoint this request arrived on
        // (HttpContext.Connection.LocalPort, or a separate Kestrel endpoint
        // bound only on the internal interface), which a client cannot choose.
        // Do not resurrect a Host-string allowlist.
        upstream.Headers.Remove(SkeinHeaders.Surface);
        upstream.Headers.TryAddWithoutValidation(SkeinHeaders.Surface, SkeinHeaders.SurfaceInternal);

        // Per-attempt headers timeout. The named client uses
        // Timeout.InfiniteTimeSpan because HttpClient.Timeout would also
        // bound the streaming body — we only want to bound the connect /
        // headers phase. A linked CTS gives us exactly that: cancels on
        // either client disconnect (ct) or after the configured
        // McpUpstreamHeadersTimeout (sk-608: SKEIN_MCP_UPSTREAM_HEADERS_TIMEOUT_SECONDS),
        // and the two sources are distinguishable in the catch block via
        // ct.IsCancellationRequested. The timer runs on the injected
        // TimeProvider so the deadline is a configured value, not a literal.
        using var timeoutCts = new CancellationTokenSource(_options.McpUpstreamHeadersTimeout, _timeProvider);
        using var headersCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(upstream, HttpCompletionOption.ResponseHeadersRead, headersCts.Token);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Client disconnected before we got headers — nothing to send back,
            // and no outcome status exists to log. Deliberately not an access
            // line: an aborted connection is a transport event, not a
            // credential event, and inventing a status code for it would put a
            // number in the journal that never went on the wire.
            return;
        }
        catch (OperationCanceledException ex)
        {
            // headersCts fired: upstream took longer than
            // McpUpstreamHeadersTimeout to flush response headers. Distinct
            // from a client-cancelled request and distinct from an unreachable
            // upstream — the request was sent, skein-api is too slow.
            using (_logger.BeginScope(new Dictionary<string, object?>
            {
                ["mcpSessionId"] = context.Request.Headers[SkeinHeaders.McpSessionId].ToString(),
                ["method"]       = context.Request.Method,
                ["upstreamUrl"]  = upstreamUrl,
                ["timeoutSeconds"] = _options.McpUpstreamHeadersTimeout.TotalSeconds,
            }))
            {
                _logger.LogWarning(ex, "mcp proxy: upstream headers timeout at {Url}", upstreamUrl);
            }
            LogAccess(context, credentials, StatusCodes.Status504GatewayTimeout);
            if (!context.Response.HasStarted)
            {
                await WriteUpstreamFailureAsync(
                    context, StatusCodes.Status504GatewayTimeout,
                    "upstream_timeout", "skein-api did not respond in time", ct);
            }
            return;
        }
        catch (HttpRequestException ex)
        {
            using (_logger.BeginScope(new Dictionary<string, object?>
            {
                ["mcpSessionId"] = context.Request.Headers[SkeinHeaders.McpSessionId].ToString(),
                ["method"]       = context.Request.Method,
                ["upstreamUrl"]  = upstreamUrl,
            }))
            {
                _logger.LogError(ex, "mcp proxy: failed to reach skein-api");
            }
            LogAccess(context, credentials, StatusCodes.Status502BadGateway);
            await WriteUpstreamFailureAsync(
                context, StatusCodes.Status502BadGateway,
                "upstream_unavailable", "skein-api is unreachable", ct);
            return;
        }

        using (response)
        {
            context.Response.StatusCode = (int)response.StatusCode;

            // Log here rather than after the body: a Streamable-HTTP response
            // may be an SSE stream that stays open for hours, and an access
            // line that only lands when the stream ends is useless for the
            // "what did the client send on its first request" question this
            // logging exists to answer. The status is already final.
            LogAccess(context, credentials, context.Response.StatusCode);

            // Response headers are copied wholesale minus hop-by-hop. That
            // includes WWW-Authenticate, which skein-api puts on a 401 from
            // /mcp to point the client at the protected-resource metadata
            // (sk-304, RFC 9728 §5.1). Dropping it here would leave the client
            // guessing where the document lives — the exact failure this
            // header exists to prevent — so it must never be added to a
            // strip-list. Pinned by McpProxyMiddlewareMetadataTest.
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
                // Use a small buffer so each chunk is forwarded promptly —
                // matters for SSE-style streaming responses that emit one
                // event at a time.
                await upstreamStream.CopyToAsync(context.Response.Body, bufferSize: SseChunkBufferBytes, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                // Client disconnected mid-stream — nothing more to do.
            }
            catch (OperationCanceledException ex)
            {
                // Upstream cancelled mid-stream (e.g. skein-api closed the
                // connection). Headers have already been flushed (status
                // 200), so we cannot rewrite to a 5xx — log for diagnosis
                // and let the connection tear down.
                using (_logger.BeginScope(new Dictionary<string, object?>
                {
                    ["mcpSessionId"] = context.Request.Headers[SkeinHeaders.McpSessionId].ToString(),
                        ["method"]       = context.Request.Method,
                    ["upstreamUrl"]  = upstreamUrl,
                }))
                {
                    _logger.LogWarning(ex, "mcp proxy: upstream stream cancelled at {Url}", upstreamUrl);
                }
            }
        }
    }

    /// <summary>
    /// The body of a 504 <c>upstream_timeout</c> or 502
    /// <c>upstream_unavailable</c> — the two answers this proxy invents itself
    /// when skein-api gives it no response.
    ///
    /// <para><c>error</c> keeps the code this proxy has always sent. For a
    /// request that can change state upstream (anything but GET/HEAD/OPTIONS —
    /// on <c>/mcp</c> that is every JSON-RPC POST, and the session-ending
    /// DELETE) the body adds <c>outcome: "unknown"</c> and says so in
    /// <c>message</c>, because neither status means the call failed. On a
    /// timeout skein-api has the request and may already have committed it
    /// when we stopped waiting; on a 502 the connection can break after the
    /// request was sent, and from here that is indistinguishable from a refused
    /// connect. A caller that reads the old body as "nothing happened" and
    /// repeats a create writes the same thing twice — observed in production
    /// (sk-608: epic_create calls answered 504 had been written,
    /// were retried, and left duplicate epics). The added field is what lets an
    /// agent tell "check before retrying" from "safe to retry" without parsing
    /// prose. A safe method changes nothing, so it keeps the plain body.</para>
    /// </summary>
    /// <param name="context">The request being answered.</param>
    /// <param name="status">504 or 502.</param>
    /// <param name="error">Machine code: <c>upstream_timeout</c> or <c>upstream_unavailable</c>.</param>
    /// <param name="reason">What went wrong, without the outcome caveat.</param>
    /// <param name="ct">Client-disconnect token.</param>
    private static Task WriteUpstreamFailureAsync(
        HttpContext context, int status, string error, string reason, CancellationToken ct)
    {
        context.Response.StatusCode = status;
        if (HttpMethods.IsGet(context.Request.Method)
            || HttpMethods.IsHead(context.Request.Method)
            || HttpMethods.IsOptions(context.Request.Method))
        {
            return context.Response.WriteAsJsonAsync(new { error, message = reason }, ct);
        }
        return context.Response.WriteAsJsonAsync(
            new
            {
                error,
                outcome = OutcomeUnknown,
                message = reason + "; the outcome is unknown — the request may have been applied. "
                    + "Check the current state before retrying.",
            },
            ct);
    }

    private static bool HasRequestBody(string method) =>
        HttpMethods.IsPost(method) ||
        HttpMethods.IsPut(method) ||
        HttpMethods.IsPatch(method);
}
