using System.ComponentModel.DataAnnotations;

namespace SkeinWeb.Auth;

/// <summary>
/// Deployment-specific addresses the BFF publishes to the SPA at boot
/// (<c>GET /api/auth/config</c>). Values here are NOT secrets and NOT
/// per-request state — they are facts about the topology this instance is
/// deployed into that the browser cannot work out on its own.
/// </summary>
/// <remarks>
/// <para>
/// The class exists because the alternative was for the client to GUESS.
/// The MCP endpoint used to be derived in the SPA from
/// <c>window.location.host</c> by rewriting a known host prefix into a
/// sibling one — correct for exactly one deployment (the one whose naming
/// scheme was compiled in) and silently wrong for every other install that
/// happened to use the same prefix. Topology is the server's knowledge;
/// it is configured here and handed to the client.
/// </para>
/// <para>
/// Bound from environment variables directly (<c>SKEIN_MCP_URL</c>),
/// matching the <c>SKEIN_API_URL</c> / <c>SKEIN_TRUSTED_PROXIES</c>
/// convention already used for the other infrastructure addresses in
/// <c>Program.cs</c>.
/// </para>
/// </remarks>
public sealed class ClientRuntimeOptions
{
    /// <summary>
    /// Absolute URL of the MCP endpoint agents should connect to, shown in
    /// the <c>.mcp.json</c> snippet on the Api Keys settings page. Set it
    /// only when MCP is served from a different origin than the web UI —
    /// e.g. a dedicated ingress that bypasses the authenticating proxy so
    /// agents can present a static <c>ska_…</c> key.
    ///
    /// Empty by default, which is the correct value for every deployment
    /// where the same origin serves both the UI and <c>/mcp</c> (the local
    /// docker-compose shape, and any single-host install): the SPA then
    /// renders a same-origin <c>/mcp</c> URL built from the page's own
    /// origin.
    ///
    /// Env: <c>SKEIN_MCP_URL</c>.
    /// </summary>
    public string McpUrl { get; set; } = string.Empty;

    /// <summary>
    /// Throw if a supplied value is malformed. Called once at startup so a
    /// typo surfaces as a clear configuration failure instead of an
    /// unusable copy-paste snippet an agent operator has to debug.
    /// </summary>
    /// <exception cref="ValidationException">
    /// <see cref="McpUrl"/> is set but is not an absolute http(s) URL.
    /// </exception>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(McpUrl))
        {
            return;
        }

        if (!Uri.TryCreate(McpUrl, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new ValidationException(
                "SKEIN_MCP_URL must be an ABSOLUTE http(s) URL " +
                $"(got '{McpUrl}'), e.g. https://skein-mcp.example.com/mcp. " +
                "Leave it empty when MCP is served from the same origin as the " +
                "web UI — the SPA then uses same-origin /mcp.");
        }
    }
}
