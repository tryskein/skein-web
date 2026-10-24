using System.ComponentModel.DataAnnotations;

namespace SkeinWeb.Auth;

/// <summary>
/// OIDC-client configuration root. Bound from the <c>Authentication</c>
/// section of <c>appsettings.json</c> / environment variables
/// (<c>Authentication__Oidc__*</c>, <c>Authentication__LogoutRedirectUrl</c>).
/// </summary>
/// <remarks>
/// <para>
/// The authentication MODE is not configured here (D-7, plan K-12): skein-web
/// takes it from skein-api's <c>GET /api/v1/internal/instance-config</c> at
/// startup (<see cref="InstanceConfigBootstrap"/>) and maps it onto a web
/// scheme with <see cref="WebAuthMode.FromApi"/>. What stays in this section
/// is what only the BFF can know — the settings of its own OIDC client and the
/// sign-out address of the proxy in front of it.
/// </para>
/// </remarks>
public sealed class SsoOptions
{
    /// <summary>Configuration section name used by <c>IConfiguration.GetSection</c>.</summary>
    public const string SectionName = "Authentication";

    /// <summary>
    /// OIDC settings. <see cref="OidcOptions.Authority"/> also selects the SSO
    /// flavour (<see cref="WebAuthMode.FromApi"/>): set — native OIDC
    /// (<see cref="WebAuthKind.KeycloakOidc"/>), empty — legacy trust-headers
    /// (<see cref="WebAuthKind.Keycloak"/>). Bound from <c>Authentication:Oidc:*</c>.
    /// </summary>
    public OidcOptions Oidc { get; set; } = new();

    /// <summary>
    /// Absolute URL the SPA navigates to after <c>POST /api/auth/logout</c>
    /// so the EXTERNAL session is terminated too — the sign-out endpoint of
    /// whatever authenticating proxy sits in front of this deployment (for an
    /// oauth2-proxy edge, its <c>/oauth2/sign_out</c>). Only consulted in
    /// <see cref="WebAuthKind.Keycloak"/> (legacy trust-headers): in
    /// <c>KeycloakOidc</c> mode the BFF drives RP-initiated logout itself and
    /// in <c>Local</c> mode there is no external session at all.
    ///
    /// Bound from <c>Authentication:LogoutRedirectUrl</c> (env
    /// <c>Authentication__LogoutRedirectUrl</c>). Empty by default — the
    /// address is deployment-specific and there is no value that is right for
    /// anyone but the deployment that set it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Unset in <c>Keycloak</c> mode the BFF DEGRADES rather than fails: the
    /// logout response carries <c>redirectTo: null</c>, the local cookie is
    /// still cleared, and a warning is written at startup saying the external
    /// session will survive logout. Making it required would kill every local
    /// / proxy-less run of this mode over a value that only a proxied
    /// deployment can supply — the same trade-off taken for
    /// <c>SKEIN_TRUSTED_PROXIES</c> in sk-194.6.52.
    /// </para>
    /// <para>
    /// The value is also published to the SPA on <c>GET /api/auth/config</c>:
    /// the client accepts an absolute logout redirect ONLY when it equals this
    /// URL, so the allow-list follows the deployment instead of a compiled-in
    /// constant. That is why <see cref="Validate"/> insists on an absolute
    /// http(s) URL — a relative or opaque value would widen the client's
    /// allow-list to something it cannot compare meaningfully.
    /// </para>
    /// </remarks>
    public string LogoutRedirectUrl { get; set; } = string.Empty;

    /// <summary>
    /// Throw if a supplied value is malformed. Called once at startup, in
    /// every mode — the checks here are about the SHAPE of the values, so
    /// they must run regardless of which mode consumes them (a typo in
    /// <see cref="LogoutRedirectUrl"/> that only surfaces when someone
    /// logs out is exactly the failure this prevents).
    /// </summary>
    /// <remarks>
    /// Missing values are NOT an error here: every setting on this class is
    /// optional and has a documented degraded behaviour. Contrast
    /// <see cref="OidcOptions.Validate"/>, which is called only in
    /// <c>KeycloakOidc</c> mode and does demand its fields — native OIDC
    /// cannot degrade, it either has an issuer and a client or it does not
    /// work at all.
    /// </remarks>
    /// <exception cref="ValidationException">
    /// <see cref="LogoutRedirectUrl"/> is set but is not an absolute
    /// http(s) URL.
    /// </exception>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(LogoutRedirectUrl))
        {
            return;
        }

        if (!Uri.TryCreate(LogoutRedirectUrl, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new ValidationException(
                "Authentication:LogoutRedirectUrl must be an ABSOLUTE http(s) URL " +
                $"(got '{LogoutRedirectUrl}'). It is the sign-out endpoint of the " +
                "authenticating proxy in front of this deployment, e.g. " +
                "https://proxy.example.com/oauth2/sign_out. Leave it empty if there " +
                "is no external session to terminate.");
        }
    }
}

/// <summary>
/// Native-OIDC settings (sk-9). Only consulted in
/// <see cref="WebAuthKind.KeycloakOidc"/>. Bound from
/// <c>Authentication:Oidc:*</c>.
/// </summary>
/// <remarks>
/// In native OIDC mode the BFF acts as the OIDC Relying Party against
/// Keycloak. The Authorization Code + PKCE handshake happens between
/// the user's browser, Keycloak, and the BFF itself — no oauth2-proxy
/// in the chain. The standard ASP.NET Core OpenIdConnect handler
/// (registered by <see cref="AuthenticationRegistration"/> only in <see cref="WebAuthKind.KeycloakOidc"/>)
/// reads the values below at startup; changing them at runtime has no
/// effect without a pod restart.
/// </remarks>
public sealed class OidcOptions
{
    /// <summary>
    /// OIDC issuer URL — the realm's discovery root. The handler
    /// fetches <c>{Authority}/.well-known/openid-configuration</c> at
    /// startup to learn endpoint URLs and JWKS location. Shaped like
    /// <c>https://keycloak.example.com/realms/skein</c>.
    /// </summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>
    /// Keycloak client id. Point this at an existing client if you want
    /// users already signed in to a sibling service on the same realm to
    /// reach Skein without a second prompt; otherwise register a client
    /// of its own. Either way the client's "Valid Redirect URIs" must
    /// include <c>{your-skein-host}/api/auth/oidc-callback</c>, matching
    /// <see cref="CallbackPath"/>.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Keycloak client secret. Inject it from a secret store as the
    /// <c>Authentication__Oidc__ClientSecret</c> environment variable at
    /// startup. Never commit a literal value to appsettings or version
    /// control.
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// Group claim value that gates entry. Authenticated users whose
    /// <c>groups</c> claim does NOT contain this string get a 403 from
    /// the OnTokenValidated callback — no Skein cookie minted, the SPA
    /// renders an access-denied message. Default <c>skein-users</c>
    /// matches the existing realm group that controls Skein access
    /// across the trust-headers mode as well.
    /// </summary>
    public string AllowedGroup { get; set; } = "skein-users";

    /// <summary>
    /// Path the browser redirects to after Keycloak finishes the
    /// Authorization Code handshake. Default <c>/api/auth/oidc-callback</c>
    /// — chosen so the path falls under the existing <c>/api/</c>
    /// HTTPRoute backend (skein-web) without needing a separate
    /// route entry for the well-known OIDC default <c>/signin-oidc</c>.
    /// Whatever value you set MUST be added to the Keycloak client's
    /// "Valid Redirect URIs" list.
    /// </summary>
    public string CallbackPath { get; set; } = "/api/auth/oidc-callback";

    /// <summary>
    /// Path Keycloak redirects to after the front-channel logout
    /// completes. Default <c>/api/auth/oidc-signout-callback</c> —
    /// again under <c>/api/</c> for the same HTTPRoute reason. Must be
    /// registered on the Keycloak client as a "Valid Post Logout
    /// Redirect URI".
    /// </summary>
    public string SignedOutCallbackPath { get; set; } = "/api/auth/oidc-signout-callback";

    /// <summary>
    /// Where to send the browser after the entire logout chain (BFF
    /// cookie cleared + Keycloak end_session complete). Relative to the
    /// app origin; default <c>/login</c> renders the SPA login page,
    /// which in an SSO mode (<see cref="WebAuthMode.IsSsoMode"/>) shows the
    /// "Sign in via Keycloak" button again.
    /// </summary>
    public string SignedOutRedirectUri { get; set; } = "/login";

    /// <summary>
    /// Throw if any required field is missing. Called once at startup
    /// in <see cref="WebAuthKind.KeycloakOidc"/> — surfaces
    /// misconfiguration as a clear startup failure rather than a
    /// confusing runtime 500 the first time someone hits
    /// <c>/oauth2/start</c>.
    /// </summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Authority))
        {
            throw new ValidationException(
                "Authentication:Oidc:Authority is required in KeycloakOidc mode " +
                "(expected the Keycloak realm URL, e.g. https://keycloak.example.com/realms/skein).");
        }
        if (string.IsNullOrWhiteSpace(ClientId))
        {
            throw new ValidationException(
                "Authentication:Oidc:ClientId is required in KeycloakOidc mode.");
        }
        if (string.IsNullOrWhiteSpace(ClientSecret))
        {
            throw new ValidationException(
                "Authentication:Oidc:ClientSecret is required in KeycloakOidc mode " +
                "(inject it from your secret store via the " +
                "Authentication__Oidc__ClientSecret env var; never commit it).");
        }
        if (string.IsNullOrWhiteSpace(AllowedGroup))
        {
            throw new ValidationException(
                "Authentication:Oidc:AllowedGroup is required in KeycloakOidc mode " +
                "(usually 'skein-users').");
        }
        if (!CallbackPath.StartsWith('/') || CallbackPath.Contains("//"))
        {
            throw new ValidationException(
                "Authentication:Oidc:CallbackPath must be a same-origin path " +
                "starting with a single '/'.");
        }
        if (!SignedOutCallbackPath.StartsWith('/') || SignedOutCallbackPath.Contains("//"))
        {
            throw new ValidationException(
                "Authentication:Oidc:SignedOutCallbackPath must be a same-origin path " +
                "starting with a single '/'.");
        }
    }
}

/// <summary>
/// Authentication scheme family this BFF runs (plan K-13).
/// </summary>
public enum WebAuthKind
{
    /// <summary>Password form; the BFF forwards credentials to skein-api.</summary>
    Local,

    /// <summary>Legacy trust-headers (R5.1): oauth2-proxy at the edge negotiates
    /// OIDC and forwards <c>X-Auth-Request-User</c> / <c>X-Auth-Request-Email</c>,
    /// which <c>SsoSessionMiddleware</c> trusts inside the cluster boundary.</summary>
    Keycloak,

    /// <summary>Native OIDC (sk-9): the BFF is the relying party itself
    /// (Authorization Code + PKCE), no oauth2-proxy in the chain.</summary>
    KeycloakOidc,
}

/// <summary>
/// The authentication mode this process runs, fixed for its lifetime: the
/// result of mapping skein-api's <c>authMode</c> onto a web scheme
/// (<see cref="FromApi"/>, plan K-13). Registered as a singleton by
/// <see cref="AuthenticationRegistration.AddSkeinAuthentication"/>; every
/// mode-dependent surface (login, logout, <c>GET /api/auth/config</c>, the
/// trust-headers bootstrapper, <c>/oauth2/start</c>) reads it from DI.
/// </summary>
/// <param name="Kind">Scheme family.</param>
/// <param name="Hybrid">skein-api runs <c>hybrid</c>: in an SSO mode the
/// password channel stays open next to SSO (external collaborators and the
/// break-glass admin); which accounts it authenticates is skein-api's gate.
/// Never true with <see cref="WebAuthKind.Local"/> — <see cref="FromApi"/>
/// does not produce that pair.</param>
public sealed record WebAuthMode(WebAuthKind Kind, bool Hybrid)
{
    /// <summary>skein-api <c>authMode</c>: password accounts only.</summary>
    public const string ApiLocal = "local";

    /// <summary>skein-api <c>authMode</c>: SSO only.</summary>
    public const string ApiKeycloak = "keycloak";

    /// <summary>skein-api <c>authMode</c>: SSO plus password for external and
    /// break-glass accounts.</summary>
    public const string ApiHybrid = "hybrid";

    /// <summary>Legacy trust-headers mode (<see cref="WebAuthKind.Keycloak"/>).</summary>
    public bool IsKeycloakMode => Kind == WebAuthKind.Keycloak;

    /// <summary>Native OIDC mode (<see cref="WebAuthKind.KeycloakOidc"/>):
    /// the OpenIdConnect handler is registered and <c>/oauth2/start</c> is served.</summary>
    public bool IsKeycloakOidcMode => Kind == WebAuthKind.KeycloakOidc;

    /// <summary>An external IdP is in front, in either flavour.</summary>
    public bool IsSsoMode => Kind != WebAuthKind.Local;

    /// <summary>Hybrid: an SSO mode with the password channel kept open.</summary>
    public bool IsHybridMode => Hybrid && IsSsoMode;

    /// <summary>
    /// Maps skein-api's <c>authMode</c> onto the web scheme (plan K-13):
    /// <list type="table">
    ///   <listheader><term>api <c>authMode</c></term><description>web scheme</description></listheader>
    ///   <item><term><c>local</c></term><description><see cref="WebAuthKind.Local"/></description></item>
    ///   <item><term><c>keycloak</c></term><description><see cref="WebAuthKind.KeycloakOidc"/> when
    ///         <c>Authentication:Oidc:Authority</c> is set, otherwise <see cref="WebAuthKind.Keycloak"/></description></item>
    ///   <item><term><c>hybrid</c></term><description>the same SSO choice, with <see cref="Hybrid"/> = true</description></item>
    /// </list>
    /// The SSO flavour is a property of the OIDC client, which stays in web
    /// configuration (plan 2.3); the mode itself has no web-side default.
    /// </summary>
    /// <param name="apiAuthMode">The <c>authMode</c> value from skein-api, compared exactly.</param>
    /// <param name="oidcAuthority">The configured <c>Authentication:Oidc:Authority</c>.</param>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="apiAuthMode"/> is not one of the three contract values —
    /// a version skew or a broken api, never something to read as <c>local</c>.
    /// </exception>
    public static WebAuthMode FromApi(string? apiAuthMode, string? oidcAuthority)
    {
        var sso = string.IsNullOrWhiteSpace(oidcAuthority) ? WebAuthKind.Keycloak : WebAuthKind.KeycloakOidc;
        return apiAuthMode switch
        {
            ApiLocal => new WebAuthMode(WebAuthKind.Local, Hybrid: false),
            ApiKeycloak => new WebAuthMode(sso, Hybrid: false),
            ApiHybrid => new WebAuthMode(sso, Hybrid: true),
            _ => throw new InvalidOperationException(
                $"skein-api reported authMode '{apiAuthMode}', expected one of " +
                $"'{ApiLocal}', '{ApiKeycloak}', '{ApiHybrid}' (GET /api/v1/internal/instance-config). " +
                "skein-web does not guess a mode."),
        };
    }
}
