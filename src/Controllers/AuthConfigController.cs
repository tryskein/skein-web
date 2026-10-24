using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SkeinWeb.Auth;
using Swashbuckle.AspNetCore.Annotations;

namespace SkeinWeb.Controllers;

/// <summary>
/// Runtime client configuration endpoint (R5.1 Stage 3, sk-674.18 K-14).
/// Fetched by the SPA at app boot to decide which login affordances and
/// self-service screens to render.
/// </summary>
/// <remarks>
/// Exposed as a separate controller from <see cref="AuthController"/>
/// so the route can be marked <c>[AllowAnonymous]</c> without
/// loosening the gates on /api/auth/login or /api/auth/me.
/// </remarks>
[ApiController]
[Route("api/auth")]
[SwaggerTag("Runtime client configuration for SPA boot: auth mode, deployment addresses, installation behaviour flags")]
public sealed class AuthConfigController : ControllerBase
{
    private readonly WebAuthMode _mode;
    private readonly SsoOptions _sso;
    private readonly ClientRuntimeOptions _clientRuntime;
    private readonly SkeinServiceApiClient _api;
    private readonly ILogger<AuthConfigController> _logger;

    public AuthConfigController(
        WebAuthMode mode,
        IOptions<SsoOptions> sso,
        IOptions<ClientRuntimeOptions> clientRuntime,
        SkeinServiceApiClient api,
        ILogger<AuthConfigController> logger)
    {
        _mode = mode;
        _sso = sso.Value;
        _clientRuntime = clientRuntime.Value;
        _api = api;
        _logger = logger;
    }

    /// <summary>
    /// Return the auth mode, the deployment addresses and skein-api's current
    /// behaviour flags.
    /// </summary>
    /// <remarks>
    /// Algorithm:
    /// <list type="number">
    ///   <item>Read skein-api's installation settings
    ///         (<c>GET /api/v1/internal/instance-config</c>, service secret only,
    ///         <see cref="SkeinServiceApiClient.GetInstanceConfigAsync"/>) — on
    ///         EVERY call, no cache (plan K-14): a restart of skein-api alone
    ///         with a new value changes the next response without a restart of
    ///         skein-web. Unreachable, non-200 after retries, past the call
    ///         budget, or a body breaking the contract → 503 ProblemDetails with
    ///         <c>error = "upstream_unavailable"</c>; never a stale or default
    ///         value.</item>
    ///   <item>Copy <c>signupEnabled</c>, <c>emailEnabled</c>,
    ///         <c>turnstileSiteKey</c>, <c>projectPrefixMinLength</c>,
    ///         <c>termsUrl</c>, <c>privacyUrl</c> from that answer unchanged.</item>
    ///   <item>Report <c>authMode</c> from the process's <see cref="WebAuthMode"/>
    ///         — the mode skein-web took from skein-api at startup (plan K-12;
    ///         changing it needs a restart of both services), not the
    ///         per-request value — collapsed to one of three SPA tokens:</item>
    /// </list>
    /// <list type="bullet">
    ///   <item><c>hybrid</c> — an SSO mode is active AND the password channel
    ///         is open (sk-163 S4b). Reported first because a hybrid
    ///         deployment is also an SSO mode and must NOT collapse to plain
    ///         <c>keycloak</c>.</item>
    ///   <item><c>keycloak</c> — SSO active, password channel closed. Both
    ///         legacy trust-headers (<c>Keycloak</c>) and native OIDC
    ///         (<c>KeycloakOidc</c>) report this single token; the SPA renders
    ///         one SSO button regardless of which backend flow redirects.</item>
    ///   <item><c>local</c> — password form only.</item>
    /// </list>
    /// <para>
    /// sk-303.8 — this endpoint used to also report <c>isExternalHost</c>, a
    /// per-request classification of <c>Request.Host</c> against the S7a
    /// <c>SKEIN_INTERNAL_HOSTS</c> allowlist. That allowlist was removed: it
    /// derived a privilege signal from a header the client controls, and in
    /// this deployment (both routes to skein-web go through the internal
    /// gateway; no public route exists) it never actually divided anything.
    /// The SPA now always renders the hybrid-mode "both SSO and password"
    /// affordance — see <c>LoginPage</c> — which is what
    /// <c>isExternalHost</c> always evaluated to under the allowlist's
    /// empty-by-default production value anyway, so this is a no-op for the
    /// only shape this service has ever run in.
    /// </para>
    /// <para>
    /// sk-303.42 — the payload also carries two deployment ADDRESSES the
    /// client used to compile in or guess:
    /// <list type="bullet">
    ///   <item><c>logoutRedirectUrl</c> — the single absolute URL the SPA may
    ///         navigate to on logout (<see cref="SsoOptions.LogoutRedirectUrl"/>).
    ///         The client builds its redirect allow-list from this value, so a
    ///         deployment's own sign-out endpoint is accepted instead of being
    ///         silently dropped.</item>
    ///   <item><c>mcpUrl</c> — where agents reach MCP
    ///         (<see cref="ClientRuntimeOptions.McpUrl"/>), when that is not
    ///         this origin.</item>
    /// </list>
    /// Both are <c>null</c> when unset, which the SPA reads as "no external
    /// logout target" and "MCP is same-origin" respectively. Neither is a
    /// secret: both are public endpoints a browser is about to be pointed at.
    /// </para>
    /// </remarks>
    /// <param name="ct">Request abort.</param>
    /// <response code="200">Auth mode, addresses and behaviour flags.</response>
    /// <response code="503">skein-api did not hand out its settings; ProblemDetails, <c>error = "upstream_unavailable"</c>.</response>
    [HttpGet("config")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(AuthConfigResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status503ServiceUnavailable)]
    [SwaggerOperation(
        Summary = "Get runtime client configuration",
        Description =
            "Returns { authMode: 'local'|'keycloak'|'hybrid', logoutRedirectUrl, " +
            "mcpUrl, signupEnabled, emailEnabled, turnstileSiteKey, " +
            "projectPrefixMinLength, termsUrl, privacyUrl } so the SPA can branch its " +
            "Login page, self-service screens and admin UI and learn the " +
            "deployment-specific addresses it must not compile in. The six behaviour " +
            "fields are skein-api's values read on every call (no cache in skein-web); " +
            "skein-api unavailable → 503 ProblemDetails with error " +
            "'upstream_unavailable'. Both legacy " +
            "trust-headers and native OIDC modes report 'keycloak'; a hybrid " +
            "deployment reports 'hybrid' so the SPA can render both the password " +
            "form and the SSO button. logoutRedirectUrl is the only absolute URL " +
            "the client will follow after logout (null when this deployment has no " +
            "external session to end); mcpUrl is where agents reach MCP (null when " +
            "that is this same origin). Safe to fetch unauthenticated — every value " +
            "is a public endpoint address.",
        OperationId = "GetAuthConfig")]
    public async Task<ActionResult<AuthConfigResponse>> Get(CancellationToken ct)
    {
        InstanceConfig settings;
        try
        {
            settings = await _api.GetInstanceConfigAsync(ct);
        }
        catch (Exception ex) when (ex is HttpRequestException or TimeoutException)
        {
            _logger.LogWarning(
                "auth config: skein-api installation settings unavailable ({Reason}); answering 503",
                ex.Message);
            return Problem(
                statusCode: StatusCodes.Status503ServiceUnavailable,
                title: "skein-api is unavailable",
                detail: "The installation settings could not be read from skein-api; retry later.",
                extensions: new Dictionary<string, object?> { ["error"] = "upstream_unavailable" });
        }

        var mode = _mode.IsHybridMode ? "hybrid"
                 : _mode.IsSsoMode ? "keycloak"
                 : "local";
        return Ok(new AuthConfigResponse(
            AuthMode: mode,
            LogoutRedirectUrl: NullIfBlank(_sso.LogoutRedirectUrl),
            McpUrl: NullIfBlank(_clientRuntime.McpUrl),
            SignupEnabled: settings.SignupEnabled,
            EmailEnabled: settings.EmailEnabled,
            TurnstileSiteKey: settings.TurnstileSiteKey,
            ProjectPrefixMinLength: settings.ProjectPrefixMinLength,
            TermsUrl: settings.TermsUrl,
            PrivacyUrl: settings.PrivacyUrl));
    }

    /// <summary>
    /// Collapse an unset configuration value to <c>null</c> on the wire.
    /// Configuration binding yields <c>""</c> for "not provided", but the SPA
    /// branches on presence — an empty string would read as "an address was
    /// configured, and it is empty".
    /// </summary>
    private static string? NullIfBlank(string value) =>
        string.IsNullOrWhiteSpace(value) ? null : value;
}
