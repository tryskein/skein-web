namespace SkeinWeb.Auth;

/// <summary>
/// Header names that flow between skein-web (BFF) and skein-api on every
/// request to /api/v1/*. Centralising them here mirrors the equivalent
/// constants in skein-api (internal/auth/headers.go) so the two services
/// can never disagree on capitalisation or punctuation.
/// </summary>
/// <remarks>
/// HeaderInternalSecret authenticates the channel (BFF -> API), not the
/// end user. HeaderUserId/Email/Username/Role identify the human on whose
/// behalf the BFF is calling. The BFF must strip any inbound X-Skein-*
/// headers from the browser before adding its own — otherwise a malicious
/// client could spoof identity.
/// </remarks>
public static class SkeinHeaders
{
    public const string InternalSecret = "X-Skein-Internal-Secret";
    public const string UserId = "X-Skein-User-Id";
    public const string UserEmail = "X-Skein-User-Email";
    public const string Username = "X-Skein-Username";
    public const string UserRole = "X-Skein-User-Role";

    /// <summary>
    /// External-collaborator flag (sk-163). Carries the literal
    /// <c>"true"</c> / <c>"false"</c>; absent header is read as
    /// <c>false</c> (internal) on the skein-api side. Must match the
    /// constant <c>HeaderUserIsExternal</c> in skein-api
    /// (internal/auth/headers.go).
    /// </summary>
    public const string UserIsExternal = "X-Skein-User-Is-External";

    /// <summary>
    /// MCP API-key authentication (R2.1). Carried verbatim from the MCP
    /// client (Claude Code, Codex, etc.) through the BFF to skein-api.
    /// The BFF does NOT trust this header for cookie-authenticated traffic
    /// — it is read only by the /mcp proxy path.
    /// </summary>
    public const string ApiKey = "X-Skein-Api-Key";

    /// <summary>
    /// MCP standard session header (server-issued on initialize, echoed by
    /// the client thereafter). Forwarded as-is on /mcp; the proxy does not
    /// inspect or rewrite the value.
    /// </summary>
    public const string McpSessionId = "Mcp-Session-Id";

    /// <summary>
    /// Internal-surface marker for <c>/mcp</c>. The BFF stamps the value
    /// <see cref="SurfaceInternal"/> on every request (sk-303.8 — this used
    /// to be conditional on a Host-based allowlist, sk-163 S7a; see
    /// <see cref="Middleware.McpProxyMiddleware"/> for why that was removed
    /// rather than hardened). skein-api treats absence as PUBLIC and rejects
    /// internal-owner api-keys there — the header still matters, only the
    /// condition on stamping it is gone. Because this header is part of the
    /// <see cref="Prefix"/> family it is stripped from inbound client
    /// requests before the BFF sets its own value — a client can never forge
    /// it. Must match the constant <c>HeaderSurface</c> in skein-api
    /// (internal/auth/headers.go).
    /// </summary>
    public const string Surface = "X-Skein-Surface";

    /// <summary>
    /// The only <see cref="Surface"/> value that asserts the trusted internal
    /// surface. Must match <c>SurfaceInternal</c> in skein-api
    /// (internal/auth/headers.go) byte-for-byte.
    /// </summary>
    public const string SurfaceInternal = "internal";

    /// <summary>
    /// Trusted client IP forwarded to skein-api on internal calls (sk-163 S9).
    /// The BFF stamps the value from <c>HttpContext.Connection.RemoteIpAddress</c>
    /// — i.e. the address resolved by the ForwardedHeaders middleware from the
    /// trusted proxy chain, NOT a raw inbound X-Forwarded-For. skein-api uses it
    /// as the per-IP key for its defense-in-depth login limiter so the throttle
    /// keys on the real client, not on the single BFF egress IP. Trusted only
    /// because it rides the internal-secret channel; like the rest of the
    /// <see cref="Prefix"/> family it is stripped from inbound client requests
    /// before the BFF sets its own value. Must match the constant
    /// <c>HeaderClientIP</c> in skein-api (internal/auth/headers.go).
    /// </summary>
    public const string ClientIp = "X-Skein-Client-Ip";

    /// <summary>
    /// Session epoch of the browser session on whose behalf the BFF calls
    /// (sk-674.18 K-16, INV-26) — part of the <c>X-Skein-User-*</c> identity
    /// family: <see cref="InternalApiHandler"/> stamps it from the
    /// <see cref="SessionPrincipal.SessionEpochClaim"/> claim on every call
    /// that carries a user. skein-api answers 401 <c>session_revoked</c> when
    /// it differs from the user's current epoch (or the user is deactivated
    /// or deleted); <c>ApiProxyMiddleware</c> ends the session on that code.
    /// Must match <c>HeaderSessionEpoch</c> in skein-api
    /// (internal/auth/headers.go).
    /// </summary>
    public const string SessionEpoch = "X-Skein-Session-Epoch";

    /// <summary>
    /// <c>error</c> of skein-api's 401 for a revoked session (skein-api
    /// <c>CodeSessionRevoked</c>, internal/auth/headers.go).
    /// </summary>
    public const string SessionRevokedCode = "session_revoked";

    /// <summary>
    /// Common prefix used by <see cref="System.String.StartsWith(string)"/>
    /// when the BFF strips spoofable inbound headers before proxying.
    /// </summary>
    public const string Prefix = "X-Skein-";
}
