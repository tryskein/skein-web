using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;

namespace SkeinWeb.Auth;

/// <summary>
/// Cookie manager of <see cref="SessionSchemes.Main"/>. Reads the cookie the scheme's options name
/// (the name of the current mode, nothing else), and decides on every write whether Main may add a
/// Set-Cookie. Main writes a ticket only on an explicit SSO renewal of the same key (there is no
/// sliding renewal): the write may not add a Set-Cookie when the request suppressed Main's write
/// or when the renewal ended in anything but <see cref="RenewOutcome.Written"/>. A write with no
/// renewal outcome (an issue through Main, which does not set one) goes through as usual, and a
/// deletion always does.
/// </summary>
public sealed class SessionCookieManager(ICookieManager inner) : ICookieManager
{
    /// <inheritdoc />
    public string? GetRequestCookie(HttpContext context, string key) => inner.GetRequestCookie(context, key);

    /// <inheritdoc />
    public void AppendResponseCookie(HttpContext context, string key, string? value, CookieOptions options)
    {
        var state = SessionRequestState.Of(context);
        if (state.SuppressMainWrite || (state.RenewOutcome is { } outcome && outcome != RenewOutcome.Written))
        {
            return;
        }
        inner.AppendResponseCookie(context, key, value, options);
    }

    /// <inheritdoc />
    public void DeleteCookie(HttpContext context, string key, CookieOptions options) =>
        inner.DeleteCookie(context, key, options);

    /// <summary>
    /// Adds the header that deletes the session cookie, built from the options of
    /// <see cref="SessionSchemes.Main"/>. Does not touch the session store: ending the session in
    /// the store is a separate step.
    /// </summary>
    public static void DeleteSessionCookie(HttpContext context)
    {
        var main = context.RequestServices
            .GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(SessionSchemes.Main);
        main.CookieManager!.DeleteCookie(context, main.Cookie.Name!, main.Cookie.Build(context));
    }
}

/// <summary>
/// Cookie manager of <see cref="SessionSchemes.Issue"/>: never reads the incoming cookie, which
/// makes the cookie handler treat every sign-in as a first one and store the ticket under a new key.
/// Writes and deletions go through unchanged.
/// </summary>
public sealed class IssueCookieManager(ICookieManager inner) : ICookieManager
{
    /// <inheritdoc />
    public string? GetRequestCookie(HttpContext context, string key) => null;

    /// <inheritdoc />
    public void AppendResponseCookie(HttpContext context, string key, string? value, CookieOptions options) =>
        inner.AppendResponseCookie(context, key, value, options);

    /// <inheritdoc />
    public void DeleteCookie(HttpContext context, string key, CookieOptions options) =>
        inner.DeleteCookie(context, key, options);
}
