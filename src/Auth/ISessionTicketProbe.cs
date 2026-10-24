namespace SkeinWeb.Auth;

/// <summary>
/// Tells whether a server-side cookie session is still the session of a given
/// user (sk-674.18 INV-26). Implemented by <see cref="RedisTicketStore"/>;
/// consumed by the hub's access re-check, which closes connections whose
/// session ticket is gone — signed out, revoked by skein-api
/// (<c>session_revoked</c>), removed by a password reset or a deactivation,
/// expired — or now belongs to ANOTHER user (a login or signup in a tab that
/// was logged in renews the same ticket key for the new user).
/// </summary>
public interface ISessionTicketProbe
{
    /// <summary>Whether the ticket <paramref name="key"/> is still stored AND belongs to <paramref name="userId"/>.</summary>
    /// <param name="key">Ticket key (<see cref="SessionPrincipal.SessionKeyClaim"/>).</param>
    /// <param name="userId">The user the session must belong to — the owner of the hub connection.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="Exception">The store is unreachable; the caller decides.</exception>
    Task<bool> IsSessionOfAsync(string key, Guid userId, CancellationToken ct);
}
