using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace SkeinWeb.Auth;

/// <summary>
/// Registers the BFF's authentication schemes for the mode this process runs
/// (plan K-12, K-13). Called once from <c>Program.cs</c>, after the mode was
/// read from skein-api (<see cref="InstanceConfigBootstrap"/>) and mapped by
/// <see cref="WebAuthMode.FromApi"/>, and before <c>builder.Build()</c> —
/// <c>AddAuthentication</c> must see every scheme up front.
/// </summary>
/// <remarks>
/// Lives outside <c>Program.cs</c> so that the application of the mapped mode
/// to the scheme set runs on a real <see cref="IServiceCollection"/> in a unit
/// test; the top-level composition cannot be executed there.
/// </remarks>
public static class AuthenticationRegistration
{
    /// <summary>
    /// Validates the OIDC-client settings for <paramref name="mode"/>, registers
    /// <paramref name="mode"/> as a singleton, and adds the authentication schemes:
    /// <list type="bullet">
    ///   <item>always — the cookie scheme (<c>skein.sid</c>, server-side
    ///         tickets in <see cref="RedisTicketStore"/>, 401/403 instead of
    ///         redirects), the only scheme a session is signed into;</item>
    ///   <item><see cref="WebAuthKind.KeycloakOidc"/> only — the OpenIdConnect
    ///         scheme (Authorization Code + PKCE, group gate, provisioning via
    ///         skein-api, cookie principal of the password-login shape).</item>
    /// </list>
    /// <see cref="WebAuthKind.Local"/> and <see cref="WebAuthKind.Keycloak"/>
    /// register the cookie scheme alone: the trust-headers bootstrapper
    /// (<c>SsoSessionMiddleware</c>) signs into the cookie scheme itself.
    /// </summary>
    /// <param name="services">The application's service collection.</param>
    /// <param name="mode">Mode mapped from skein-api's <c>authMode</c>.</param>
    /// <param name="sso">The bound <c>Authentication</c> section.</param>
    /// <returns>The authentication builder, for further schemes.</returns>
    /// <exception cref="System.ComponentModel.DataAnnotations.ValidationException">
    /// <see cref="SsoOptions.LogoutRedirectUrl"/> is malformed (any mode), or a
    /// required OIDC setting is missing in <see cref="WebAuthKind.KeycloakOidc"/>.
    /// </exception>
    public static AuthenticationBuilder AddSkeinAuthentication(
        this IServiceCollection services,
        WebAuthMode mode,
        SsoOptions sso)
    {
        // Mode-independent shape checks first (sk-303.42: Authentication:LogoutRedirectUrl
        // must be an absolute http(s) URL if supplied at all) — a malformed address is an
        // operator typo with no safe reading, and catching it here beats discovering it
        // the first time somebody logs out.
        sso.Validate();
        if (mode.IsKeycloakOidcMode)
        {
            sso.Oidc.Validate();
        }

        services.AddSingleton(mode);

        var authBuilder = services
            .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
            {
                options.Cookie.Name = "skein.sid";
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                options.ExpireTimeSpan = TimeSpan.FromHours(24);
                options.SlidingExpiration = true;

                // SessionStore is set via a closure on the built service provider
                // because options-configuration runs before DI is final. Resolving
                // RedisTicketStore lazily here mirrors what AddCookie examples do
                // when wiring server-side ticket storage.
                options.Events.OnSigningIn = ctx =>
                {
                    // No-op hook reserved for audit logging in R5+. Required to be
                    // declared so the events object is not null.
                    return Task.CompletedTask;
                };

                // Return 401/403 instead of redirecting to /login — we are an API,
                // not a server-rendered app. The React client interprets a 401 as
                // "show the login screen".
                options.Events.OnRedirectToLogin = ctx =>
                {
                    ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return Task.CompletedTask;
                };
                options.Events.OnRedirectToAccessDenied = ctx =>
                {
                    ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                    return Task.CompletedTask;
                };
            });

        // sk-9 — Native OIDC handler. Only registered in KeycloakOidc mode;
        // the legacy trust-headers Keycloak mode keeps its existing flow
        // (no JWT validation in this pod). Authorization Code + PKCE against
        // the realm; on the callback we (1) validate group membership against
        // AllowedGroup, (2) provision a local user via skein-api, (3) replace
        // the OIDC principal with the canonical Skein cookie principal so
        // downstream code sees the same shape as the password-login flow.
        if (mode.IsKeycloakOidcMode)
        {
            var oidc = sso.Oidc;
            authBuilder.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
            {
                options.Authority = oidc.Authority;
                options.ClientId = oidc.ClientId;
                options.ClientSecret = oidc.ClientSecret;
                options.ResponseType = OpenIdConnectResponseType.Code;
                options.UsePkce = true;
                options.RequireHttpsMetadata = true;

                // .NET 10 defaults to PushedAuthorizationBehavior.UseIfAvailable —
                // if the realm's discovery document advertises
                // `pushed_authorization_request_endpoint` (Keycloak 25+ does),
                // the handler tries PAR first. PAR adds two extra realm-side
                // configuration knobs (allowed auth methods on the PAR endpoint,
                // client-level enable flag) that are NOT set on the shared
                // oauth2-proxy client today; the realm rejects the PAR push
                // with `invalid_request` and the user gets a 500 before
                // Keycloak's login form ever renders. Disable PAR explicitly
                // and fall back to the classic Authorization Code flow over
                // a 302 — works against any compliant OIDC IdP with no extra
                // realm-side config.
                options.PushedAuthorizationBehavior = PushedAuthorizationBehavior.Disable;

                // The cookie scheme below is what we ultimately sign into; OIDC
                // exists only to drive the realm handshake. SaveTokens=false
                // keeps the cookie small — we never replay access/refresh tokens
                // back at Keycloak; skein-api derives identity from the cookie
                // principal, not from upstream tokens.
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.SaveTokens = false;

                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("email");
                // 'groups' is the Keycloak scope that surfaces realm-group
                // membership in the id_token; the realm-side mapper on the
                // oauth2-proxy client must include this claim in the id_token
                // (not only in the access_token) for the gate below to work.
                options.Scope.Add("groups");

                options.CallbackPath = new PathString(oidc.CallbackPath);
                options.SignedOutCallbackPath = new PathString(oidc.SignedOutCallbackPath);
                options.SignedOutRedirectUri = oidc.SignedOutRedirectUri;

                // Map the canonical Keycloak username claim onto ClaimsIdentity.Name
                // so the rest of ASP.NET treats it consistently.
                options.TokenValidationParameters.NameClaimType = "preferred_username";
                options.TokenValidationParameters.RoleClaimType = "groups";

                options.Events = new OpenIdConnectEvents
                {
                    // After the id_token is validated by the OIDC handler:
                    // 1) enforce group membership — non-members get 403, no cookie
                    // 2) provision (or look up) the local Skein user via skein-api
                    // 3) replace the OIDC principal with the canonical cookie
                    //    principal so the cookie ticket carries exactly the same
                    //    claims as a local-password login.
                    OnTokenValidated = async ctx =>
                    {
                        var allowedGroup = oidc.AllowedGroup;
                        var groups = ctx.Principal?
                            .FindAll("groups")
                            .Select(c => NormaliseGroupClaim(c.Value))
                            .ToList()
                            ?? new List<string>();

                        if (!groups.Any(g => string.Equals(g, allowedGroup, StringComparison.Ordinal)))
                        {
                            var logger = ctx.HttpContext.RequestServices
                                .GetRequiredService<ILoggerFactory>()
                                .CreateLogger("Oidc");
                            logger.LogWarning(
                                "oidc: group gate denied — user not in '{AllowedGroup}' (groups={GroupCount})",
                                allowedGroup, groups.Count);
                            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                            ctx.Response.ContentType = "application/json";
                            await ctx.Response.WriteAsync(
                                "{\"error\":\"user_not_provisioned\"," +
                                "\"message\":\"Your SSO identity is authenticated but not authorized for Skein. " +
                                "Contact your administrator to request access.\"}",
                                ctx.HttpContext.RequestAborted);
                            ctx.HandleResponse();
                            return;
                        }

                        var email = ctx.Principal?.FindFirstValue("email")
                                    ?? ctx.Principal?.FindFirstValue(ClaimTypes.Email);
                        var username = ctx.Principal?.FindFirstValue("preferred_username")
                                       ?? ctx.Principal?.FindFirstValue(ClaimTypes.Name);
                        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(username))
                        {
                            ctx.Response.StatusCode = StatusCodes.Status422UnprocessableEntity;
                            ctx.Response.ContentType = "application/json";
                            await ctx.Response.WriteAsync(
                                "{\"error\":\"missing_claims\"," +
                                "\"message\":\"id_token from Keycloak is missing required claims " +
                                "(email or preferred_username). Contact your administrator.\"}",
                                ctx.HttpContext.RequestAborted);
                            ctx.HandleResponse();
                            return;
                        }

                        // Display name from the OIDC profile scope; empty string
                        // falls back to skein-api's first-login-wins behaviour
                        // (the row's existing name on UPDATE, or the username on
                        // INSERT) so we never overwrite a user-edited display
                        // name with an absent claim.
                        var name = ctx.Principal?.FindFirstValue("name") ?? string.Empty;

                        var api = ctx.HttpContext.RequestServices.GetRequiredService<SkeinApiClient>();
                        AuthenticatedUser provisioned;
                        try
                        {
                            provisioned = await api.OidcProvisionAsync(
                                email, username, name, ctx.HttpContext.RequestAborted);
                        }
                        catch (SsoProvisioningException ex)
                        {
                            var logger = ctx.HttpContext.RequestServices
                                .GetRequiredService<ILoggerFactory>()
                                .CreateLogger("Oidc");
                            logger.LogError(
                                "oidc: provisioning failed ({StatusCode} {Code}): {Message}",
                                ex.StatusCode, ex.ErrorCode, ex.Message);
                            ctx.Response.StatusCode = StatusCodes.Status502BadGateway;
                            ctx.Response.ContentType = "application/json";
                            await ctx.Response.WriteAsync(
                                "{\"error\":\"sso_provisioning_failed\"," +
                                "\"message\":\"Failed to establish a Skein session. Try again.\"}",
                                ctx.HttpContext.RequestAborted);
                            ctx.HandleResponse();
                            return;
                        }

                        // sk-674.18 K-16: the session carries the epoch of THIS
                        // answer; without it no session is issued (no default,
                        // no older value).
                        if (provisioned.SessionEpoch is not { } sessionEpoch)
                        {
                            var logger = ctx.HttpContext.RequestServices
                                .GetRequiredService<ILoggerFactory>()
                                .CreateLogger("Oidc");
                            logger.LogError(
                                "oidc: provisioning response for {UserId} has no sessionEpoch; no session issued",
                                provisioned.User.Id);
                            ctx.Response.StatusCode = StatusCodes.Status502BadGateway;
                            ctx.Response.ContentType = "application/json";
                            await ctx.Response.WriteAsync(
                                "{\"error\":\"sso_provisioning_failed\"," +
                                "\"message\":\"Failed to establish a Skein session. Try again.\"}",
                                ctx.HttpContext.RequestAborted);
                            ctx.HandleResponse();
                            return;
                        }

                        // Same principal shape as the password login
                        // (SessionPrincipal), plus the refresh timestamp so the
                        // trust-headers TTL-refresh path (if ever toggled back
                        // on) starts its timer at sign-in.
                        var nowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                            .ToString(CultureInfo.InvariantCulture);
                        ctx.Principal = SessionPrincipal.Create(
                            provisioned.User,
                            sessionEpoch,
                            new Claim("urn:skein:refreshed-at", nowUnix));
                    },

                    // OIDC challenge is browser-navigation, not XHR. Surfacing
                    // the upstream error to the browser as a plain 502 keeps the
                    // user from looping silently when Keycloak rejects the
                    // redirect URI or the realm is misconfigured.
                    OnRemoteFailure = ctx =>
                    {
                        var logger = ctx.HttpContext.RequestServices
                            .GetRequiredService<ILoggerFactory>()
                            .CreateLogger("Oidc");
                        logger.LogError(ctx.Failure, "oidc: remote auth failure");
                        ctx.Response.StatusCode = StatusCodes.Status502BadGateway;
                        ctx.Response.ContentType = "text/plain";
                        ctx.HandleResponse();
                        return ctx.Response.WriteAsync(
                            "OIDC sign-in failed. Contact your administrator.",
                            ctx.HttpContext.RequestAborted);
                    },
                };
            });
        }

        // Wire SessionStore after the service provider is fully built. This is
        // the standard recipe for ITicketStore: configure-options resolves the
        // store from DI, but only on first use.
        services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
            .Configure<RedisTicketStore>((opts, store) => opts.SessionStore = store);

        return authBuilder;
    }

    // Strip the leading slash Keycloak prepends to realm-group path claims
    // ("/skein-users") so OnTokenValidated can compare against the configured
    // AllowedGroup value without forcing operators to remember the slash. If
    // the claim already lacks a slash (some mappers emit bare names) we pass
    // it through unchanged. Also normalises a single trailing slash for the
    // same reason.
    private static string NormaliseGroupClaim(string raw)
    {
        if (string.IsNullOrEmpty(raw))
        {
            return raw;
        }
        var trimmed = raw.AsSpan().Trim('/').ToString();
        return trimmed;
    }
}
