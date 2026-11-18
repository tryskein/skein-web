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
/// yet have a session cookie. R5.x adds a TTL refresh fallback that
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
/// <para>Flow (trust-headers mode, a trusted transport peer, both headers non-empty, an endpoint that
/// is not an explicit sign-in operation and not a bypass path):
/// <list type="number">
///   <item>No session: confirm the subject at skein-api and issue a new session through
///         <see cref="SessionIssuer"/>, remembering the header pair in the ticket.</item>
///   <item>A live session whose remembered pair equals the request's pair: nothing is asked of
///         skein-api (the sliding renewal of the cookie handler applies), except the periodic
///         refresh every <see cref="SessionRefreshTtl"/>.</item>
///   <item>A different or unknown pair, or a due refresh: confirm the subject. Another user id → a
///         new session, the old key revoked. The same id with another epoch → the session ends and
///         nothing is issued. The same id and epoch → an explicit renewal of the same key with the
///         confirmed claims and the new pair; an absent row → a new session.</item>
///   <item>An unconfirmed subject is neither executed as the old user nor given a session.</item>
/// </list></para>
/// </remarks>
public sealed class SsoSessionMiddleware : IMiddleware
{
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
    private readonly TrustedProxyConfig _trustedProxies;
    private readonly IServiceProvider _services;
    private readonly ILogger<SsoSessionMiddleware> _logger;

    public SsoSessionMiddleware(
        WebAuthMode mode,
        TrustedProxyConfig trustedProxies,
        IServiceProvider services,
        ILogger<SsoSessionMiddleware> logger)
    {
        _mode = mode;
        _trustedProxies = trustedProxies;
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
        if (TrustedSsoRequest.IsBypassPath(context.Request.Path))
        {
            await next(context);
            return;
        }

        // 3) An explicit sign-in operation (login, signup, invitation signup, password reset) owns
        //    its identity and its outcome: no comparison, no confirmation, no sign-in by headers.
        if (context.GetEndpoint()?.Metadata.GetMetadata<ExplicitSignInAttribute>() is not null)
        {
            await next(context);
            return;
        }

        // 4) Trust headers count only from a trusted TRANSPORT peer — the
        //    connection address EdgeSnapshotMiddleware recorded before
        //    ForwardedHeaders rewrote RemoteIpAddress to the visitor. No
        //    header (X-Forwarded-For, X-Original-For, …) takes part in this
        //    decision. A foreign identity never creates, refreshes, rotates or ends a session.
        if (TrustedSsoRequest.HasTrustHeaders(context.Request) &&
            !TrustedSsoRequest.IsFromTrustedPeer(context, _trustedProxies))
        {
            _logger.LogWarning(
                "sso: trust headers from a transport peer outside {Setting} ignored; " +
                "no session is created, refreshed or ended by this request",
                TrustedProxyConfig.SettingName);
            await next(context);
            return;
        }

        // 5) Both identity headers must be present: username alone cannot drive provisioning
        //    (skein-api needs the email key) and email alone cannot populate the handle. Incomplete
        //    headers neither create, rotate nor end a session.
        if (!TrustedSsoRequest.TryReadIdentity(context.Request, out var email, out var username))
        {
            await next(context);
            return;
        }

        var issuer = context.RequestServices.GetRequiredService<SessionIssuer>();
        var authenticated = context.User.Identity is { IsAuthenticated: true };

        if (authenticated)
        {
            // 6) The pair of THIS request against the remembered one: local, no call to skein-api.
            var current = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            var pairMatches = PairMatches(current.Properties, email, username);
            if (pairMatches && !IsRefreshDue(context.User))
            {
                await next(context);
                return;
            }

            // Same login with a due periodic refresh: a failed refresh is not fatal, the session stays.
            // A different or unknown pair needs the subject confirmed first, and an unconfirmed
            // subject is not executed as the old one, nor given a session.
            var confirmed = await ConfirmAsync(context, email, username, failureIsFatal: !pairMatches);
            if (confirmed is null)
            {
                // A fatal failure has written its answer; a failed periodic refresh of an unchanged
                // pair leaves the session as it is.
                if (pairMatches)
                {
                    await next(context);
                }
                return;
            }

            if (!await ApplyToLiveSessionAsync(context, issuer, confirmed, email, username))
            {
                return;
            }
            await next(context);
            return;
        }

        // 7) No session: the bootstrap, a new authentication from the headers.
        var bootstrap = await ConfirmAsync(context, email, username, failureIsFatal: true);
        if (bootstrap is null)
        {
            return;
        }
        if (!await RotateToAsync(context, issuer, bootstrap, email, username))
        {
            return;
        }
        await next(context);
    }

    /// <summary>The remembered pair of the session equals the pair of the request: both non-empty, ordinal.</summary>
    private static bool PairMatches(AuthenticationProperties? properties, string email, string username) =>
        properties is not null
        && properties.Items.TryGetValue(RedisTicketStore.SsoEmailItem, out var rememberedEmail)
        && properties.Items.TryGetValue(RedisTicketStore.SsoUserItem, out var rememberedUser)
        && !string.IsNullOrEmpty(rememberedEmail)
        && !string.IsNullOrEmpty(rememberedUser)
        && string.Equals(rememberedEmail, email, StringComparison.Ordinal)
        && string.Equals(rememberedUser, username, StringComparison.Ordinal);

    private sealed record Confirmed(UserDto User, long Epoch);

    /// <summary>
    /// Ask skein-api who the headers name. Null when there is no usable answer: with
    /// <paramref name="failureIsFatal"/> the response is already written (the request is not executed);
    /// without it (the periodic refresh of an unchanged pair) the failure is logged and the session stays.
    /// </summary>
    private async Task<Confirmed?> ConfirmAsync(HttpContext context, string email, string username, bool failureIsFatal)
    {
        AuthenticatedUser answer;
        try
        {
            var api = _services.GetRequiredService<SkeinApiClient>();
            // Display name is intentionally empty: oauth2-proxy does not forward a name claim on a
            // stock edge config; skein-api keeps the existing name or falls back to the username.
            answer = await api.OidcProvisionAsync(email, username, string.Empty, context.RequestAborted);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            return null;
        }
        catch (SsoProvisioningException ex) when (failureIsFatal)
        {
            await WriteProvisioningFailureAsync(context, ex);
            return null;
        }
        catch (Exception ex) when (!failureIsFatal)
        {
            _logger.LogWarning(ex,
                "sso: TTL refresh failed; existing cookie kept (userId={UserId})",
                context.User.FindFirstValue(ClaimTypes.NameIdentifier));
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "sso: unexpected error during provisioning");
            await WriteJsonStatusAsync(context, StatusCodes.Status502BadGateway, new
            {
                error = "sso_unavailable",
                message = "Authentication service is temporarily unavailable.",
            });
            return null;
        }

        // The session carries the epoch of THIS answer; without it no session is issued or renewed.
        if (answer.SessionEpoch is not { } epoch)
        {
            _logger.LogError(
                "sso: provisioning response for {UserId} has no sessionEpoch; no session issued",
                answer.User.Id);
            if (failureIsFatal)
            {
                await WriteJsonStatusAsync(context, StatusCodes.Status502BadGateway, new
                {
                    error = "sso_provisioning_failed",
                    message = "Failed to establish a Skein session from your SSO identity. Try again.",
                });
            }
            return null;
        }
        return new Confirmed(answer.User, epoch);
    }

    /// <summary>
    /// The confirmed subject against the live session: another id → a new authentication (the old key
    /// is revoked); the same id and another epoch → the session ends and nothing is issued; the same id
    /// and epoch → an explicit renewal of the same key. False when the response is already written.
    /// </summary>
    private async Task<bool> ApplyToLiveSessionAsync(
        HttpContext context, SessionIssuer issuer, Confirmed confirmed, string email, string username)
    {
        var ticketUserId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!string.Equals(ticketUserId, confirmed.User.Id, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogInformation("sso: the confirmed subject differs from the session's; a new session is issued");
            return await RotateToAsync(context, issuer, confirmed, email, username);
        }

        var ticketEpoch = context.User.FindFirstValue(SessionPrincipal.SessionEpochClaim);
        var confirmedEpoch = confirmed.Epoch.ToString(CultureInfo.InvariantCulture);
        if (!string.Equals(ticketEpoch, confirmedEpoch, StringComparison.Ordinal))
        {
            // The session was revoked (password reset, deactivation…): end it instead of healing it with
            // the new epoch. The request goes on anonymous; the next one signs in afresh.
            _logger.LogInformation(
                "sso: the session of {UserId} is revoked (epoch changed); session ended", confirmed.User.Id);
            try
            {
                await issuer.EndCurrentAsync(context);
            }
            catch (SessionIssueException)
            {
                await WriteJsonStatusAsync(context, StatusCodes.Status502BadGateway, new
                {
                    error = "sso_unavailable",
                    message = "Authentication service is temporarily unavailable.",
                });
                return false;
            }
            return true;
        }

        return await RenewSameKeyAsync(context, issuer, confirmed, email, username);
    }

    private async Task<bool> RenewSameKeyAsync(
        HttpContext context, SessionIssuer issuer, Confirmed confirmed, string email, string username)
    {
        var key = SessionPrincipal.SessionKeyOf(context.User);
        var principal = NewPrincipal(confirmed);
        var state = SessionRequestState.Of(context);
        state.ExplicitRenewal = true;
        try
        {
            await context.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                principal,
                NewProperties(email, username, pairWrite: true));
        }
        finally
        {
            // Only this step is explicit: a later sliding renewal of the handler in the same request
            // carries a clone of the earlier read and must not write it over the confirmed claims.
            state.ExplicitRenewal = false;
        }

        switch (state.RenewOutcome)
        {
            case RenewOutcome.Written when key is not null:
                context.User = SessionPrincipal.WithSessionKey(
                    new AuthenticationTicket(principal, new AuthenticationProperties(), CookieAuthenticationDefaults.AuthenticationScheme),
                    key).Principal;
                return true;

            case RenewOutcome.KeyAbsent:
                // The row is gone (revoked in parallel): a new authentication from the answer already in hand.
                return await RotateToAsync(context, issuer, confirmed, email, username);

            case RenewOutcome.CasExhausted:
            case RenewOutcome.OwnerMismatch:
                // A live key that kept changing, or that belongs to another user now: not revoked, not
                // rotated; the request goes on with the session it carried.
                return true;

            default:
                _logger.LogError("sso: the renewal of the session ended without a usable outcome");
                throw new SessionStoreUnavailableException();
        }
    }

    private async Task<bool> RotateToAsync(
        HttpContext context, SessionIssuer issuer, Confirmed confirmed, string email, string username)
    {
        try
        {
            await issuer.RotateAsync(
                context, NewPrincipal(confirmed), NewProperties(email, username, pairWrite: false), "Sso");
        }
        catch (SessionIssueException)
        {
            await WriteJsonStatusAsync(context, StatusCodes.Status502BadGateway, new
            {
                error = "sso_provisioning_failed",
                message = "Failed to establish a Skein session from your SSO identity. Try again.",
            });
            return false;
        }
        _logger.LogInformation("sso: signed in user {UserId}", confirmed.User.Id);
        return true;
    }

    private static ClaimsPrincipal NewPrincipal(Confirmed confirmed)
    {
        var nowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        // Same principal shape as the login and OIDC paths, plus the refresh timestamp this middleware keys its TTL on.
        return SessionPrincipal.Create(confirmed.User, confirmed.Epoch, new Claim(RefreshedAtClaim, nowUnix));
    }

    private static AuthenticationProperties NewProperties(string email, string username, bool pairWrite)
    {
        var properties = new AuthenticationProperties { IsPersistent = true, AllowRefresh = true };
        properties.Items[RedisTicketStore.SsoEmailItem] = email;
        properties.Items[RedisTicketStore.SsoUserItem] = username;
        if (pairWrite)
        {
            properties.Items[RedisTicketStore.SsoPairWriteMarker] = "1";
        }
        return properties;
    }

    private async Task WriteProvisioningFailureAsync(HttpContext context, SsoProvisioningException ex)
    {
        // Map skein-api error codes to their proper HTTP statuses instead of demoting everything to 502.
        // The codes here mirror handler/auth.go OIDCProvision.
        switch (ex.ErrorCode)
        {
            case "user_not_provisioned":
                _logger.LogWarning(
                    "sso: provisioning denied — user probably not in the group that gates Skein access ({StatusCode} {Code})",
                    ex.StatusCode, ex.ErrorCode);
                await WriteUserNotProvisionedAsync(context);
                return;

            case "missing_claims":
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
                _logger.LogError("sso: provisioning hit username-suffix exhaustion ({Message})", ex.Message);
                await WriteJsonStatusAsync(context, StatusCodes.Status409Conflict, new
                {
                    error = "username_conflict",
                    message = "Could not derive a unique username from your SSO identity. Contact your administrator.",
                });
                return;

            default:
                _logger.LogError(
                    "sso: provisioning failed ({StatusCode} {Code}): {Message}", ex.StatusCode, ex.ErrorCode, ex.Message);
                await WriteJsonStatusAsync(context, StatusCodes.Status502BadGateway, new
                {
                    error = "sso_provisioning_failed",
                    message = "Failed to establish a Skein session from your SSO identity. Try again.",
                });
                return;
        }
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
