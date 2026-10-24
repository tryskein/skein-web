using Microsoft.Extensions.Primitives;
using SkeinWeb.Auth;

namespace SkeinWeb.Middleware;

/// <summary>
/// How the caller's Skein credential arrived on a request to the MCP surface
/// (sk-304 stage 2). Recorded in the access log so an audit can tell the
/// native header apart from the compatibility mode WITHOUT the log ever
/// carrying the credential itself.
/// </summary>
public enum McpCredentialTransport
{
    /// <summary>Neither <c>X-Skein-Api-Key</c> nor <c>Authorization</c> was sent.</summary>
    /// <remarks>
    /// This is the unauthenticated probe an MCP client makes to trigger the
    /// 401 + <c>WWW-Authenticate</c> discovery hop (MCP authorization spec,
    /// "Authorization Server Location"). Seeing it in the log is the whole
    /// point of logging this surface: sk-304 could not be diagnosed because
    /// nobody could tell whether the client probed first or presented its key.
    /// </remarks>
    None,

    /// <summary>Native transport: <c>X-Skein-Api-Key</c> only.</summary>
    ApiKeyHeader,

    /// <summary>
    /// Compatibility mode: the Skein api key was presented as
    /// <c>Authorization: Bearer ska_…</c> and no <c>X-Skein-Api-Key</c> was
    /// sent. On <c>/mcp</c> the value is translated into the internal header;
    /// on the (credential-free) metadata documents nothing is translated.
    /// </summary>
    BearerCompatibility,

    /// <summary>
    /// Both headers present carrying the SAME value. Nothing is translated —
    /// the native header already says everything. This is the shape of the
    /// client-side workaround sk-304 documented (a second <c>Authorization</c>
    /// line pasted into <c>~/.grok/config.toml</c>), and it must keep working.
    /// </summary>
    BothHeadersMatching,

    /// <summary>
    /// An <c>Authorization</c> header was present but is NOT a Skein api key
    /// (e.g. a Keycloak JWT). It is neither translated nor forwarded upstream.
    /// Logged rather than dropped in silence — see the remarks on
    /// <see cref="McpBearerCompatibility"/>.
    /// </summary>
    ForeignBearerIgnored,

    /// <summary>
    /// Two credentials that cannot both be true were presented at once. The
    /// request is refused on <c>/mcp</c>; see
    /// <see cref="McpCredentialDecision.RejectionReason"/>.
    /// </summary>
    Conflict,
}

/// <summary>
/// The read-only verdict of <see cref="McpBearerCompatibility.Classify"/> —
/// what the client presented, and whether it is self-contradictory.
/// </summary>
/// <param name="Transport">Which credential transport the client used.</param>
/// <param name="HasApiKeyHeader">Whether <c>X-Skein-Api-Key</c> was present at all (fact only — never the value).</param>
/// <param name="HasAuthorizationHeader">Whether <c>Authorization</c> was present at all (fact only — never the value).</param>
/// <param name="TranslatedApiKey">
/// The api-key value to install into <c>X-Skein-Api-Key</c>, or <c>null</c>
/// when nothing needs translating. Non-null only for
/// <see cref="McpCredentialTransport.BearerCompatibility"/>.
/// </param>
/// <param name="RejectionReason">
/// Human-readable reason the request must be refused, or <c>null</c> when it
/// may proceed. Deliberately free of the credential and of any quote/backslash
/// so it is safe both as JSON and inside an RFC 6750 <c>error_description</c>
/// quoted-string.
/// </param>
public readonly record struct McpCredentialDecision(
    McpCredentialTransport Transport,
    bool HasApiKeyHeader,
    bool HasAuthorizationHeader,
    string? TranslatedApiKey,
    string? RejectionReason)
{
    /// <summary>Whether the request must be refused instead of proxied.</summary>
    public bool Rejected => RejectionReason is not null;
}

/// <summary>
/// sk-304 stage 2 — the named compatibility mode that lets an MCP client
/// present its Skein api key the standard way, <c>Authorization: Bearer</c>,
/// and have it work.
///
/// <para><b>Why this lives on the public boundary and not in skein-api.</b>
/// skein-api must not learn to read an OAuth header for the sake of our opaque
/// key. The invariant "only <c>X-Skein-Api-Key</c> travels inward" is kept and
/// the boundary translates. When R5.1 lands, a real Keycloak access token gets
/// its own validation path (issuer, signature, expiry, and the audience binding
/// the MCP authorization spec requires) and can never be swallowed by the
/// api-key validator by accident — because a non-<c>ska_</c> bearer is not
/// translated here in the first place.</para>
///
/// <para><b>Why a foreign bearer is dropped rather than passed on.</b> Today
/// skein-api has no token validator; forwarding a token to a service that
/// cannot check its audience is exactly the token-passthrough the MCP security
/// guidance forbids. So it is dropped — but it is dropped LOUDLY (logged, see
/// <see cref="McpCredentialTransport.ForeignBearerIgnored"/>), because a
/// silently swallowed token is how a future OAuth rollout would appear to work
/// while authenticating nobody. The place that must change when R5.1 arrives is
/// <see cref="Classify"/>: that branch grows a second validation path.</para>
///
/// <para><b>Standards this follows.</b> RFC 9110 §11.6.2: <c>credentials =
/// auth-scheme [ 1*SP ( token68 / #auth-param ) ]</c> and "the auth-scheme
/// token is case-insensitive" — hence the ordinal-ignore-case scheme match and
/// the explicit space requirement. RFC 6750 §2.1 gives the same grammar for
/// Bearer (<c>credentials = "Bearer" 1*SP b64token</c>); an <c>ska_…</c> key is
/// a syntactically valid b64token because <c>_</c> is in that charset. RFC 6750
/// §2 states "Clients MUST NOT use more than one method to transmit the token
/// in each request", and §3.1 maps that to <c>invalid_request</c> with "The
/// resource server SHOULD respond with the HTTP 400 (Bad Request) status code"
/// — which is why a contradictory pair is a 400 and never a silent pick.</para>
/// </summary>
public static class McpBearerCompatibility
{
    /// <summary>
    /// The Skein api-key tag. Mirrors <c>APIKeyTag</c> in skein-api
    /// (internal/auth/apikey.go) byte-for-byte; a format bump there is a
    /// coordinated change here.
    /// </summary>
    public const string ApiKeyTag = "ska_";

    /// <summary>
    /// Shortest string this boundary will accept as a Skein key. Mirrors
    /// <c>IsAPIKeyShape</c> in skein-api (<c>len(tag)+8</c>). Like its Go twin
    /// this is a routing hint, NOT a security check — skein-api remains the
    /// only party that decides whether a key is real.
    /// </summary>
    private const int MinApiKeyLength = 12;

    private const string BearerScheme = "Bearer";

    /// <summary>
    /// Whether <paramref name="value"/> has the shape of a Skein api key.
    /// Case-SENSITIVE on purpose: the tag is a lowercase literal and the rest
    /// is base64url, where case is meaningful. Only the scheme name is
    /// case-insensitive, not the credential.
    /// </summary>
    public static bool LooksLikeSkeinApiKey(string? value) =>
        value is not null &&
        value.Length >= MinApiKeyLength &&
        value.StartsWith(ApiKeyTag, StringComparison.Ordinal);

    /// <summary>
    /// Classify the credentials on an inbound request. Pure — it reads headers
    /// and returns a verdict, it does not mutate anything. The caller decides
    /// whether to act on it (we act on <c>/mcp</c> only; the protected-resource
    /// metadata documents are public and take no credentials, so refusing one
    /// over a credential conflict would break discovery for no gain).
    /// </summary>
    public static McpCredentialDecision Classify(HttpRequest request)
    {
        StringValues authorization = request.Headers["Authorization"];
        StringValues apiKey = request.Headers[SkeinHeaders.ApiKey];

        bool hasAuthorization = authorization.Count > 0;
        bool hasApiKey = apiKey.Count > 0;

        if (!hasAuthorization)
        {
            return new McpCredentialDecision(
                hasApiKey ? McpCredentialTransport.ApiKeyHeader : McpCredentialTransport.None,
                hasApiKey, false, null, null);
        }

        var compatTokens = new List<string>();
        foreach (var raw in authorization)
        {
            if (TryReadBearerToken(raw, out var token) && LooksLikeSkeinApiKey(token))
            {
                compatTokens.Add(token);
            }
        }

        if (compatTokens.Count == 0)
        {
            // Some other scheme, or a bearer token that is not ours (a JWT).
            // Untouched: stripped by the forwarding loop exactly as before this
            // change, and logged so it is not swallowed in silence.
            return new McpCredentialDecision(
                McpCredentialTransport.ForeignBearerIgnored, hasApiKey, true, null, null);
        }

        if (authorization.Count > 1)
        {
            // Authorization is a singleton field (RFC 9110 §5.5); a repeated one
            // has no defined meaning and we will not guess which line the caller
            // meant. Note the gate: we only refuse when at least one repeat IS a
            // Skein key, so traffic that never enters compatibility mode gains
            // no new failure mode from this change.
            return new McpCredentialDecision(
                McpCredentialTransport.Conflict, hasApiKey, true, null,
                "Authorization was sent more than once");
        }

        var bearer = compatTokens[0];

        bool sawApiKeyValue = false;
        foreach (var raw in apiKey)
        {
            var candidate = raw?.Trim() ?? string.Empty;
            if (candidate.Length == 0)
            {
                continue; // present-but-empty is not a credential
            }
            if (!string.Equals(candidate, bearer, StringComparison.Ordinal))
            {
                // Two different credentials at once. Picking one silently would
                // put the wrong identity in every audit row the request writes,
                // and which one got picked would be invisible afterwards.
                return new McpCredentialDecision(
                    McpCredentialTransport.Conflict, hasApiKey, true, null,
                    "X-Skein-Api-Key and Authorization carry different credentials");
            }
            sawApiKeyValue = true;
        }

        return sawApiKeyValue
            ? new McpCredentialDecision(
                McpCredentialTransport.BothHeadersMatching, true, true, null, null)
            : new McpCredentialDecision(
                McpCredentialTransport.BearerCompatibility, hasApiKey, true, bearer, null);
    }

    /// <summary>
    /// Parse one <c>Authorization</c> field value as Bearer credentials.
    /// Returns false for any other scheme.
    /// </summary>
    /// <remarks>
    /// The scheme comparison is <see cref="StringComparison.OrdinalIgnoreCase"/>
    /// because RFC 9110 §11.1 makes auth-scheme names case-insensitive —
    /// <c>bearer</c>, <c>Bearer</c> and <c>BEARER</c> are the same scheme, and a
    /// client that spells it lowercase must not be quietly unauthenticated.
    /// The character right after the scheme must be a space (RFC 9110 §11.6.2:
    /// <c>auth-scheme [ 1*SP … ]</c>) — without that check a different scheme
    /// whose name merely starts with "Bearer" would be misread as this one.
    /// </remarks>
    private static bool TryReadBearerToken(string? headerValue, out string token)
    {
        token = string.Empty;
        if (string.IsNullOrEmpty(headerValue))
        {
            return false;
        }

        var value = headerValue.Trim();
        if (value.Length <= BearerScheme.Length)
        {
            return false;
        }
        if (!value.StartsWith(BearerScheme, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var rest = value[BearerScheme.Length..];
        if (rest[0] != ' ')
        {
            return false;
        }

        token = rest.TrimStart(' ');
        return token.Length > 0;
    }
}
