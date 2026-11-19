using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using SkeinWeb.Hubs;

namespace SkeinWeb.Auth;

/// <summary>A session issued by <see cref="SessionIssuer"/>.</summary>
/// <param name="Key">The key of the new session (never logged, never sent to skein-api).</param>
/// <param name="HadPreviousKey">The request carried a session cookie of the current mode with a
/// readable key, which was revoked before the new key was issued.</param>
public sealed record IssuedSession(string Key, bool HadPreviousKey);

/// <summary>
/// The only way to start a new authentication and to end a session in a controlled way: the key the
/// browser sent is revoked first, then the session is issued under a new random key through the
/// <see cref="SessionSchemes.Issue"/> scheme, so a key that came with the request never carries
/// somebody else's — or a new — authentication.
/// </summary>
/// <remarks>
/// <para>
/// Every issue starts a new window (<see cref="SessionWindow.ForSignIn"/>): the issue time is now and
/// the expiry is now plus the absolute limit, whatever issue or expiry time the caller's properties
/// or the identity provider's carried; the window of a revoked key is never passed on.
/// <see cref="AuthenticationProperties.IsPersistent"/> is kept as the caller set it, so a persistent
/// cookie expires at the end of the new window and an OIDC session keeps a browser-session cookie.
/// </para>
/// <para>
/// Any failure is a <see cref="SessionIssueException"/> without the text of its source and writes no
/// Set-Cookie of a new session. A failed revocation leaves the previous key alive for its previous
/// owner (an accepted state): it is never reused and never handed to the new identity.
/// </para>
/// <para>
/// One issue per request: the handler would reuse the key of the first issue for a second one and
/// write two cookies of the same name, so a second <see cref="RotateAsync"/> or
/// <see cref="IssueAsync(HttpContext, ClaimsPrincipal, AuthenticationProperties, string)"/> on a request is refused before it revokes anything.
/// </para>
/// <para>
/// The log carries the user, the surface and whether a previous key existed — no e-mail, session
/// key or cookie value.
/// </para>
/// </remarks>
public sealed class SessionIssuer(
    RedisTicketStore store,
    ConnectionRegistry hubConnections,
    SessionCookiePolicy policy,
    TicketDataFormat ticketFormat,
    TimeProvider timeProvider,
    SessionTimeouts timeouts,
    ILogger<SessionIssuer> logger)
{
    // The claim the stock cookie handler puts into a cookie when a server-side store is used. It
    // is internal to the handler; the issuer reads it to learn which key a cookie carries.
    private const string HandlerSessionIdClaim = "Microsoft.AspNetCore.Authentication.Cookies-SessionId";

    private const string IssuedItemsKey = "skein.session.issued";

    private static readonly TimeSpan InsecureSchemeWarningInterval = TimeSpan.FromMinutes(1);

    private readonly ChunkingCookieManager _cookies = new();
    private long _lastInsecureSchemeWarningTicks = long.MinValue;

    /// <summary>
    /// Start a new authentication: revoke the key the request carried, then issue the session of
    /// <paramref name="principal"/> under a new key. The principal of the request becomes the new one.
    /// </summary>
    /// <param name="context">The request.</param>
    /// <param name="principal">The identity to sign in.</param>
    /// <param name="properties">Properties of the ticket (the remembered SSO pair among them). They
    /// are copied; their issue and expiry times are replaced by the new window.</param>
    /// <param name="surface">Short stable label of the sign-in path for the log (a surface name, or
    /// the label of the SSO or OIDC path).</param>
    /// <exception cref="SessionIssueException">A second issue on this request, a failed
    /// revocation, or a failed issue; no new Set-Cookie was written.</exception>
    public async Task<IssuedSession> RotateAsync(
        HttpContext context, ClaimsPrincipal principal, AuthenticationProperties properties, string surface)
    {
        EnsureNotIssuedYet(context);
        MarkSessionWriteSuppressed(context);
        var hadPreviousKey = await RevokeIncomingAsync(context);
        return await IssueAsync(context, principal, properties, surface, hadPreviousKey);
    }

    /// <summary>
    /// End the current authentication without issuing a new one: revoke the key the request
    /// carried (the one required store operation), delete the session cookie through the Main
    /// manager without touching the store, and make the principal of the request anonymous. After a
    /// confirmed revocation the end completes whatever the state of the store.
    /// </summary>
    /// <exception cref="SessionIssueException">The revocation failed; no Set-Cookie was written and
    /// the previous key stays with its previous owner.</exception>
    public async Task EndCurrentAsync(HttpContext context)
    {
        MarkSessionWriteSuppressed(context);
        await RevokeIncomingAsync(context);
        SessionCookieManager.DeleteSessionCookie(context);
        context.User = new ClaimsPrincipal(new ClaimsIdentity());
    }

    /// <summary>
    /// Forbid any later ticket write of Main on this request. Called before the first revocation of
    /// any sequence that revokes or issues a session, including a sequence whose first step fails.
    /// </summary>
    public void MarkSessionWriteSuppressed(HttpContext context) =>
        SessionRequestState.Of(context).SuppressMainWrite = true;

    /// <summary>
    /// Mark the request as past its point of no return (the confirmed password reset): store
    /// operations of this request, including the issue of the new key the handler performs, ignore
    /// the cancellation of the request and run to completion.
    /// </summary>
    public void MarkPointOfNoReturn(HttpContext context) =>
        SessionRequestState.Of(context).NoCancellation = true;

    /// <summary>
    /// The key of the session cookie the request carries: the cookie of the current mode's name,
    /// opened with the session ticket format. Null when there is no such cookie, it cannot be
    /// opened, or it holds no key. Never the key of the authenticated principal, so it works when
    /// the early read failed and on a callback whose <c>HttpContext.User</c> is empty.
    /// </summary>
    public string? IncomingSessionKey(HttpContext context)
    {
        var value = _cookies.GetRequestCookie(context, policy.CookieName);
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }
        try
        {
            var key = ticketFormat.Unprotect(value)?.Principal.FindFirstValue(HandlerSessionIdClaim);
            return string.IsNullOrEmpty(key) ? null : key;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return null;
        }
    }

    /// <summary>
    /// Revoke the session key the request carried (<see cref="IncomingSessionKey"/>) and close this
    /// replica's hub connections opened with it; other replicas close theirs at the first successful
    /// access re-check of each connection after the key is gone (a re-check that fails closes nothing).
    /// Called on its own only by the password-reset sequence.
    /// </summary>
    /// <returns>True when the request carried a readable key.</returns>
    /// <exception cref="SessionIssueException">The revocation failed.</exception>
    public async Task<bool> RevokeIncomingAsync(HttpContext context)
    {
        var key = IncomingSessionKey(context);
        if (key is null)
        {
            return false;
        }

        try
        {
            await store.RevokeAsync(key, context, context.RequestAborted);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning("session revocation failed exceptionType={ExceptionType}", ex.GetType().Name);
            throw new SessionIssueException("The previous session could not be revoked.");
        }

        SessionRequestState.Of(context).PreviousKeyRevoked = true;
        hubConnections.AbortSession(key);
        return true;
    }

    /// <summary>
    /// Issue the session of <paramref name="principal"/> through <see cref="SessionSchemes.Issue"/>.
    /// Called on its own only by the password-reset sequence, after <see cref="RevokeIncomingAsync"/>.
    /// </summary>
    /// <exception cref="SessionIssueException">A second issue on this request, or the issue failed.</exception>
    public Task<IssuedSession> IssueAsync(
        HttpContext context, ClaimsPrincipal principal, AuthenticationProperties properties, string surface)
    {
        EnsureNotIssuedYet(context);
        return IssueAsync(context, principal, properties, surface, SessionRequestState.Of(context).PreviousKeyRevoked);
    }

    private async Task<IssuedSession> IssueAsync(
        HttpContext context, ClaimsPrincipal principal, AuthenticationProperties properties, string surface,
        bool hadPreviousKey)
    {
        context.Items[IssuedItemsKey] = true;
        // A copy, so the caller's object is not changed; the window is always the new one.
        var issued = properties.Clone();
        var window = SessionWindow.ForSignIn(timeouts, timeProvider.GetUtcNow());
        issued.IssuedUtc = window.IssuedUtc;
        issued.ExpiresUtc = window.ExpiresUtc;
        try
        {
            await context.SignInAsync(SessionSchemes.Issue, principal, issued);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning("session issue failed exceptionType={ExceptionType}", ex.GetType().Name);
            throw new SessionIssueException("The session could not be issued.");
        }

        var state = SessionRequestState.Of(context);
        var key = state.IssuedKey ?? throw new SessionIssueException("The session store returned no key.");

        // The principal of the rest of this request is the new session's, so a later
        // revocation of "the current session" reaches the new key, not the old one.
        context.User = SessionPrincipal.WithSessionKey(
            new AuthenticationTicket(principal, issued, SessionSchemes.Issue), key).Principal;

        logger.LogInformation(
            // The placeholder name avoids words the console formatter masks (key, token, secret…).
            "session issued userId={UserId} surface={Surface} previousSession={PreviousSession}",
            principal.FindFirstValue(ClaimTypes.NameIdentifier), surface, hadPreviousKey);
        WarnIfSchemeLooksInsecure(context);
        return new IssuedSession(key, hadPreviousKey);
    }

    private static void EnsureNotIssuedYet(HttpContext context)
    {
        if (context.Items.ContainsKey(IssuedItemsKey))
        {
            throw new SessionIssueException("A session was already issued on this request.");
        }
    }

    // In the normal mode the cookie is Secure, which a browser does not send back over http: a
    // deployment whose edge does not tell the BFF about https would sign users in and then lose
    // the session at once. At most one warning a minute. The scheme comes from forwarded headers
    // and does not prove the scheme of the browser's own connection, so the text says "seen as".
    private void WarnIfSchemeLooksInsecure(HttpContext context)
    {
        if (policy.AllowInsecureHttp || !string.Equals(context.Request.Scheme, "http", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var now = timeProvider.GetUtcNow().UtcTicks;
        var last = Interlocked.Read(ref _lastInsecureSchemeWarningTicks);
        if (last != long.MinValue && now - last < InsecureSchemeWarningInterval.Ticks)
        {
            return;
        }
        if (Interlocked.CompareExchange(ref _lastInsecureSchemeWarningTicks, now, last) != last)
        {
            return;
        }

        logger.LogWarning(
            "a session was issued on a request seen as http while {Setting} is off: its cookie is Secure and a browser " +
            "does not send it back over http. The scheme seen here comes from forwarded headers and does not prove the " +
            "scheme of the browser's connection; check that the edge terminates https and forwards the scheme",
            SessionCookiePolicy.SettingName);
    }
}
