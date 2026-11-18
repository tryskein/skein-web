using Microsoft.AspNetCore.Authentication.Cookies;

namespace SkeinWeb.Auth;

/// <summary>Names of the two cookie schemes that carry the session.</summary>
public static class SessionSchemes
{
    /// <summary>
    /// The scheme that reads, renews and ends the session (the default scheme; every sign-out path
    /// uses it). Its name is the framework's cookie scheme name and does not change.
    /// </summary>
    public const string Main = CookieAuthenticationDefaults.AuthenticationScheme;

    /// <summary>
    /// The scheme every new authentication is signed into. Same options, store and ticket format as
    /// <see cref="Main"/>, but its cookie manager never reads the incoming cookie, so the handler
    /// stores the ticket under a new key instead of reusing the one the browser sent.
    /// </summary>
    public const string Issue = "Skein.Issue";
}
