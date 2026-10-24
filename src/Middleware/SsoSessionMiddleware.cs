using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using SkeinWeb.Auth;

namespace SkeinWeb.Middleware;

/// <summary>
/// R5.1 — auto-create a skein cookie session from the trust headers
/// (<c>X-Auth-Request-User</c> + <c>X-Auth-Request-Email</c>) injected
/// by oauth2-proxy when the user is authenticated upstream but does not
/// yet have a skein.sid cookie. R5.x adds a TTL refresh fallback that
/// periodically re-syncs cookie claims from skein-api.
/// </summary>
/// <remarks>
/// <para>
/// Trust-headers org pattern — the shape an organisation gets when one
/// shared oauth2-proxy fronts many services at once, Skein among them:
/// authentication happens at the ingress edge — nginx only forwards
/// headers listed in <c>auth-response-headers</c>, and the ingress
/// already 403s anyone outside the group that gates Skein before they
/// reach this pod. The BFF identifies the user from the trusted headers
/// and does NOT validate any JWT.
/// </para>
/// <para>Flow on a request without a cookie:
/// <list type="number">
///   <item>Skip unless <see cref="WebAuthMode.IsKeycloakMode"/> (legacy trust-headers).</item>
///   <item>Skip bypass paths (health checks, metrics, MCP, auth/config).</item>
///   <item>Skip if the request already carries an authenticated cookie principal —
///         except that on every authenticated request we ALSO run the TTL
///         refresh below.</item>
///   <item>Skip if neither <c>X-Auth-Request-Email</c> nor
///         <c>X-Auth-Request-User</c> are present — the request never
///         traversed oauth2-proxy. Subsequent middleware will enforce
///         auth (e.g. ApiProxyMiddleware returns 401).</item>
///   <item>Otherwise: call <c>POST /api/v1/auth/oidc/provision</c> on
///         skein-api with {email, username, name} and
///         <c>HttpContext.SignInAsync</c> to mint the same cookie + Redis
///         ticket as the local-password login flow.</item>
/// </list></para>
/// <para>Flow on an authenticated request (TTL refresh fallback —
/// belt-and-braces for the event-driven invalidation path in
/// <see cref="SkeinWeb.Auth.UserChangedSubscriber"/>):
/// <list type="number">
///   <item>Read the <see cref="RefreshedAtClaim"/> claim. If missing OR
///         older than <see cref="SessionRefreshTtl"/>, re-fetch claims
///         from skein-api via <c>OidcProvisionAsync</c>.</item>
///   <item>Diff against the current cookie claims (role / username /
///         name / email). If anything changed → <c>SignInAsync</c> with
///         the fresh tuple, which rotates the Valkey ticket and rolls
///         the cookie. If nothing changed → still <c>SignInAsync</c>
///         with the same claims to refresh the timestamp (cheaper than
///         a custom claims-only update, and keeps the renewal logic in
///         one place).</item>
///   <item>Skip silently if the trust headers are absent on this
///         request — the cookie is still valid; the next request from
///         oauth2-proxy will carry headers and the refresh will fire
///         then.</item>
/// </list></para>
/// </remarks>
public sealed class SsoSessionMiddleware : IMiddleware
{
    /// <summary>
    /// Bypass list — paths the middleware must never touch even in
    /// keycloak mode. Infrastructure / static endpoints that either
    /// don't carry oauth2-proxy headers or must work without a cookie.
    /// </summary>
    private static readonly string[] BypassPaths = new[]
    {
        "/healthz",
        "/ready",
        "/metrics",
        "/mcp",
        "/api/auth/config",
    };

    // oauth2-proxy trust headers (oauth2-proxy option set_xauthrequest = true):
    //   X-Auth-Request-User   — the Keycloak `preferred_username` claim
    //   X-Auth-Request-Email  — the Keycloak `email` claim
    // X-Auth-Request-Access-Token is NOT forwarded (pass_access_token=false
    // in a typical oauth2-proxy deployment), which is why the previous
    // JWT-validation design silently no-op'd in such deployments.
    private const string UserHeader = "X-Auth-Request-User";
    private const string EmailHeader = "X-Auth-Request-Email";

    /// <summary>
    /// Custom claim that records when the cookie principal was last
    /// re-synced against skein-api. Value is a Unix-seconds string. Used
    /// purely by this middleware — no other code reads it.
    /// </summary>
    private const string RefreshedAtClaim = "urn:skein:refreshed-at";

    /// <summary>
    /// How stale the cookie claims may be before the middleware re-fetches
    /// them from skein-api on the next request. 5 minutes is short enough
    /// that an admin promotion takes effect quickly even if the NATS
    /// event-driven invalidation path is down, and long enough that the
    /// refresh adds at most one extra hop per user per 5min of activity.
    /// </summary>
    private static readonly TimeSpan SessionRefreshTtl = TimeSpan.FromMinutes(5);

    private readonly WebAuthMode _mode;
    private readonly IServiceProvider _services;
    private readonly ILogger<SsoSessionMiddleware> _logger;

    public SsoSessionMiddleware(
        WebAuthMode mode,
        IServiceProvider services,
        ILogger<SsoSessionMiddleware> logger)
    {
        _mode = mode;
        _services = services;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        // 1) Local mode → middleware is inert.
        if (!_mode.IsKeycloakMode)
        {
            await next(context);
            return;
        }

        // 2) Bypass paths.
        var path = context.Request.Path;
        foreach (var prefix in BypassPaths)
        {
            if (path.StartsWithSegments(prefix, StringComparison.OrdinalIgnoreCase))
            {
                await next(context);
                return;
            }
        }

        // 3) Already authenticated via the cookie? Run the TTL refresh
        //    fallback path — re-fetch claims from skein-api when the
        //    last sync is older than SessionRefreshTtl. Defends against
        //    missed NATS events (lag, pod restart, queue-group drop).
        if (context.User.Identity is { IsAuthenticated: true })
        {
            await TryRefreshClaimsAsync(context);
            await next(context);
            return;
        }

        // 4) Read trust headers. Both must be present — username alone
        //    can't drive provisioning (skein-api needs the email key)
        //    and email alone can't populate the canonical handle.
        var email = context.Request.Headers[EmailHeader].FirstOrDefault();
        var username = context.Request.Headers[UserHeader].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(username))
        {
            await next(context);
            return;
        }

        // Display name is intentionally empty here. oauth2-proxy does
        // NOT forward a `name` claim unless it is explicitly added to
        // the forwarded-header set, so on a stock edge config we have
        // no upstream value to write. skein-api COALESCEs an
        // empty `name` to either `username` (on INSERT) or the row's
        // existing `name` (on UPDATE) — first-login-wins. A future
        // profile-edit UI is the canonical place for the user to
        // override their display name without it being re-synced from
        // an absent claim on every page load.
        var name = string.Empty;

        // 5) Provision via skein-api.
        AuthenticatedUser provisioned;
        try
        {
            var api = _services.GetRequiredService<SkeinApiClient>();
            provisioned = await api.OidcProvisionAsync(email, username, name, context.RequestAborted);
        }
        catch (SsoProvisioningException ex)
        {
            // Map skein-api error codes to their proper HTTP statuses
            // instead of demoting everything to 502. The codes here
            // mirror handler/auth.go OIDCProvision.
            switch (ex.ErrorCode)
            {
                case "user_not_provisioned":
                    _logger.LogWarning(
                        "sso: provisioning denied — user probably not in the group that gates Skein access ({StatusCode} {Code})",
                        ex.StatusCode, ex.ErrorCode);
                    await WriteUserNotProvisionedAsync(context);
                    return;

                case "missing_claims":
                    // skein-api rejected the body — most likely
                    // oauth2-proxy is not forwarding X-Auth-Request-Email
                    // or -User. Operator-facing problem.
                    _logger.LogError(
                        "sso: provisioning rejected, missing claims — check oauth2-proxy auth-response-headers config ({Message})",
                        ex.Message);
                    await WriteJsonStatusAsync(context, StatusCodes.Status422UnprocessableEntity, new
                    {
                        error = "missing_claims",
                        message = "Authentication headers from the SSO proxy are incomplete. Contact your administrator.",
                    });
                    return;

                case "username_conflict":
                    _logger.LogError(
                        "sso: provisioning hit username-suffix exhaustion ({Message})", ex.Message);
                    await WriteJsonStatusAsync(context, StatusCodes.Status409Conflict, new
                    {
                        error = "username_conflict",
                        message = "Could not derive a unique username from your SSO identity. Contact your administrator.",
                    });
                    return;

                default:
                    // Genuine upstream failure — 502 is honest.
                    _logger.LogError(
                        "sso: provisioning failed ({StatusCode} {Code}): {Message}",
                        ex.StatusCode, ex.ErrorCode, ex.Message);
                    await WriteJsonStatusAsync(context, StatusCodes.Status502BadGateway, new
                    {
                        error = "sso_provisioning_failed",
                        message = "Failed to establish a Skein session from your SSO identity. Try again.",
                    });
                    return;
            }
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "sso: unexpected error during provisioning");
            await WriteJsonStatusAsync(context, StatusCodes.Status502BadGateway, new
            {
                error = "sso_unavailable",
                message = "Authentication service is temporarily unavailable.",
            });
            return;
        }

        // 6) sk-674.18 K-16: the session carries the epoch of THIS answer;
        //    without it no session is issued (no default, no older value).
        if (provisioned.SessionEpoch is not { } sessionEpoch)
        {
            _logger.LogError(
                "sso: provisioning response for {UserId} has no sessionEpoch; no session issued",
                provisioned.User.Id);
            await WriteJsonStatusAsync(context, StatusCodes.Status502BadGateway, new
            {
                error = "sso_provisioning_failed",
                message = "Failed to establish a Skein session from your SSO identity. Try again.",
            });
            return;
        }

        // 7) Mint the cookie + Redis ticket. Mirror AuthController.Login
        //    so /api/auth/me and the proxy handler treat both flows
        //    identically.
        await SignInWithUserAsync(context, provisioned.User, sessionEpoch);
        _logger.LogInformation("sso: signed in user {UserId}", provisioned.User.Id);

        await next(context);
    }

    /// <summary>
    /// TTL refresh fallback. Called on every authenticated request; only
    /// hits skein-api when the cookie's <see cref="RefreshedAtClaim"/>
    /// is missing or older than <see cref="SessionRefreshTtl"/>. Silent
    /// no-op if the trust headers are absent (the cookie is still valid,
    /// the next request from oauth2-proxy will carry headers).
    /// </summary>
    private async Task TryRefreshClaimsAsync(HttpContext context)
    {
        // Without trust headers we cannot reliably re-provision: the
        // current request didn't traverse oauth2-proxy (e.g. an internal
        // health probe leaked into the auth pipeline, or the SPA is
        // talking to /api/* directly during a frontend dev session).
        // Leave the cookie alone — the user is still authenticated, the
        // event-driven NATS path covers role flips, and the next request
        // that DOES come through oauth2-proxy will refresh as expected.
        var email = context.Request.Headers[EmailHeader].FirstOrDefault();
        var username = context.Request.Headers[UserHeader].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(username))
        {
            return;
        }

        // Read the refresh timestamp claim. Missing / unparseable / too
        // old → refresh; otherwise short-circuit.
        if (!IsRefreshDue(context.User))
        {
            return;
        }

        AuthenticatedUser refreshed;
        try
        {
            var api = _services.GetRequiredService<SkeinApiClient>();
            refreshed = await api.OidcProvisionAsync(email, username, string.Empty, context.RequestAborted);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex)
        {
            // Refresh failure is non-fatal — the existing cookie keeps
            // working; the next request retries. We log at warning
            // because chronic failures here defeat the fallback and
            // operators should notice.
            _logger.LogWarning(ex,
                "sso: TTL refresh failed; existing cookie kept (userId={UserId})",
                context.User.FindFirstValue(ClaimTypes.NameIdentifier));
            return;
        }

        // sk-674.18 K-16: a provisioning answer without sessionEpoch cannot
        // re-issue the session — keep the existing cookie (as on any other
        // refresh failure) and say so loudly: chronic, it means skein-api
        // broke the authentication-response contract.
        if (refreshed.SessionEpoch is not { } sessionEpoch)
        {
            _logger.LogError(
                "sso: TTL refresh response for {UserId} has no sessionEpoch; existing cookie kept",
                refreshed.User.Id);
            return;
        }
        var fresh = refreshed.User;

        // sk-674.18 K-16: a refresh never raises the session's
        // epoch. If skein-api's current epoch differs from the one this
        // session was issued with, the session was revoked (password reset,
        // deactivation…) — end it instead of re-signing it with the new epoch,
        // which would quietly heal a revoked session. The request goes on
        // unauthenticated; the browser's next request through the proxy
        // signs in afresh (the bootstrap path below — a new login).
        var sessionEpochNow = sessionEpoch.ToString(CultureInfo.InvariantCulture);
        if (!string.Equals(context.User.FindFirstValue(SessionPrincipal.SessionEpochClaim), sessionEpochNow, StringComparison.Ordinal))
        {
            _logger.LogInformation(
                "sso: TTL refresh found the session of {UserId} revoked (epoch changed); session ended",
                fresh.Id);
            await SessionRevocation.EndSessionAsync(context);
            context.User = new ClaimsPrincipal(new ClaimsIdentity());
            return;
        }

        // Diff the claim fields that ride in the cookie principal.
        // SignInAsync ALWAYS runs (even on no-change) so the timestamp
        // resets and we don't immediately re-fetch on the next request.
        var changed = HasClaimsChanged(context.User, fresh);
        await SignInWithUserAsync(context, fresh, sessionEpoch);

        if (changed)
        {
            _logger.LogInformation(
                "sso: TTL refresh detected claim drift for {UserId}; cookie rotated",
                fresh.Id);
        }
        else
        {
            _logger.LogDebug(
                "sso: TTL refresh confirmed claims unchanged for {UserId}; timestamp reset",
                fresh.Id);
        }
    }

    /// <summary>
    /// Compare the current cookie principal against the fresh DB tuple.
    /// Returns true when any of role / username / name / email differs.
    /// Email is included even though it is the lookup key — a future
    /// admin tool may rewrite it on the DB row and the cookie must
    /// follow.
    /// </summary>
    private static bool HasClaimsChanged(ClaimsPrincipal current, UserDto fresh)
    {
        var currentExternal = string.Equals(
            current.FindFirstValue("is_external"), "true", StringComparison.OrdinalIgnoreCase);
        return !string.Equals(current.FindFirstValue(ClaimTypes.Role), fresh.Role, StringComparison.Ordinal)
            || !string.Equals(current.FindFirstValue("username"), fresh.Username, StringComparison.Ordinal)
            || !string.Equals(current.FindFirstValue(ClaimTypes.Name), fresh.Name, StringComparison.Ordinal)
            || !string.Equals(current.FindFirstValue(ClaimTypes.Email), fresh.Email, StringComparison.OrdinalIgnoreCase)
            || currentExternal != fresh.IsExternal;
    }

    /// <summary>
    /// Build a fresh ClaimsPrincipal from <paramref name="user"/>, stamp
    /// the refresh timestamp, and call <c>SignInAsync</c>. Shared between
    /// the bootstrap path (first sign-in via trust headers) and the TTL
    /// refresh path so both go through one place.
    /// </summary>
    private static async Task SignInWithUserAsync(HttpContext context, UserDto user, long sessionEpoch)
    {
        var nowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            .ToString(CultureInfo.InvariantCulture);

        // Same principal shape as the login and OIDC paths (SessionPrincipal),
        // plus the refresh timestamp this middleware keys its TTL on.
        var principal = SessionPrincipal.Create(user, sessionEpoch, new Claim(RefreshedAtClaim, nowUnix));

        await context.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            new AuthenticationProperties
            {
                IsPersistent = true,
                AllowRefresh = true,
            });

        // Replace the in-memory principal so downstream middleware /
        // [Authorize] gates see the fresh claims on THIS request rather
        // than waiting for the next one to round-trip through the cookie.
        context.User = principal;
    }

    /// <summary>
    /// True when the cookie's <see cref="RefreshedAtClaim"/> is missing,
    /// unparseable, or older than <see cref="SessionRefreshTtl"/>. The
    /// missing / unparseable branches are intentionally pessimistic —
    /// any cookie that predates this middleware version will refresh on
    /// its next request, which is exactly what we want.
    /// </summary>
    private static bool IsRefreshDue(ClaimsPrincipal principal)
    {
        var raw = principal.FindFirstValue(RefreshedAtClaim);
        if (string.IsNullOrEmpty(raw))
        {
            return true;
        }
        if (!long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var unix))
        {
            return true;
        }
        var refreshedAt = DateTimeOffset.FromUnixTimeSeconds(unix);
        return DateTimeOffset.UtcNow - refreshedAt > SessionRefreshTtl;
    }

    private static async Task WriteUserNotProvisionedAsync(HttpContext context)
    {
        await WriteJsonStatusAsync(context, StatusCodes.Status403Forbidden, new
        {
            error = "user_not_provisioned",
            message = "Your SSO identity is authenticated but not authorized for Skein. " +
                      "Contact your administrator to request access.",
        });
    }

    private static readonly JsonSerializerOptions ErrorJsonOpts = new(JsonSerializerDefaults.Web);

    private static async Task WriteJsonStatusAsync(HttpContext context, int statusCode, object body)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json";
        await JsonSerializer.SerializeAsync(
            context.Response.Body,
            body,
            options: ErrorJsonOpts,
            cancellationToken: context.RequestAborted);
    }
}
