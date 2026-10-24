using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace SkeinWeb.Auth;

/// <summary>
/// Builds the cookie-session principal from a user skein-api has just
/// authenticated. One shape for every way a browser session starts after an
/// answer of skein-api — password login (<c>AuthController#Login</c>), signup
/// and signup by invitation (<c>AccountController</c>), OIDC sign-in
/// (<see cref="AuthenticationRegistration"/>) and the trust-headers bootstrap
/// (<c>SsoSessionMiddleware</c>) — so the
/// <c>X-Skein-User-*</c> headers <see cref="InternalApiHandler"/> derives from
/// it are the same whichever door the user came through.
/// </summary>
public static class SessionPrincipal
{
    /// <summary>
    /// Claim carrying the session epoch the session was issued with
    /// (sk-674.18 K-16): the decimal <c>sessionEpoch</c> of skein-api's
    /// authentication response. Sent back on every call as
    /// <see cref="SkeinHeaders.SessionEpoch"/>.
    /// </summary>
    public const string SessionEpochClaim = "session_epoch";

    /// <summary>
    /// Claim carrying the key of the session's server-side ticket (sk-674.18
    /// INV-26). Stamped by <see cref="RedisTicketStore"/> into every ticket it
    /// stores or renews, so a request — and a hub connection opened by it —
    /// knows which ticket it lives on: when the ticket is gone, the session
    /// has ended. Never sent to skein-api or to the browser.
    /// </summary>
    public const string SessionKeyClaim = "session_key";

    /// <summary>The <see cref="SessionKeyClaim"/> of <paramref name="principal"/>, or null.</summary>
    public static string? SessionKeyOf(ClaimsPrincipal? principal)
    {
        var key = principal?.FindFirstValue(SessionKeyClaim);
        return string.IsNullOrEmpty(key) ? null : key;
    }

    /// <summary>
    /// Claims: <see cref="ClaimTypes.NameIdentifier"/> (user id),
    /// <see cref="ClaimTypes.Email"/>, <c>username</c> (the @-handle — not
    /// <see cref="ClaimTypes.Name"/>, which carries the display name),
    /// <see cref="ClaimTypes.Name"/>, <see cref="ClaimTypes.Role"/> and
    /// <c>is_external</c> as the literal <c>true</c> / <c>false</c> (sk-163 S1),
    /// <see cref="SessionEpochClaim"/>, then <paramref name="extra"/>.
    /// </summary>
    /// <param name="user">The user from skein-api's 200 answer.</param>
    /// <param name="sessionEpoch">The <c>sessionEpoch</c> of that answer. Not
    /// nullable on purpose: a response without it must not reach here (K-16).</param>
    /// <param name="extra">Additional claims of a particular door (the SSO
    /// refresh timestamp).</param>
    /// <returns>A principal of the cookie scheme.</returns>
    public static ClaimsPrincipal Create(UserDto user, long sessionEpoch, params Claim[] extra)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id),
            new(ClaimTypes.Email, user.Email),
            new("username", user.Username),
            new(ClaimTypes.Name, user.Name),
            new(ClaimTypes.Role, user.Role),
            new("is_external", user.IsExternal ? "true" : "false"),
            new(SessionEpochClaim, sessionEpoch.ToString(CultureInfo.InvariantCulture)),
        };
        claims.AddRange(extra);
        return new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));
    }
}
