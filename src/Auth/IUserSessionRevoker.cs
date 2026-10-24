namespace SkeinWeb.Auth;

/// <summary>
/// Ends every server-side cookie session of a user. Implemented by
/// <see cref="RedisTicketStore"/>; consumed by the hub's access control
/// (sk-622.21 K10: deactivation removes the user's tickets on every replica,
/// idempotently).
/// </summary>
public interface IUserSessionRevoker
{
    /// <summary>Removes every session ticket of <paramref name="userId"/>.</summary>
    /// <param name="userId">The user.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>How many ticket keys of the user's index had their session
    /// row deleted — an upper bound of the sessions ended, since a key may
    /// have expired already; 0 when the index could not be read.</returns>
    Task<int> RemoveByUserIdAsync(Guid userId, CancellationToken ct);

    /// <summary>
    /// Removes every session ticket of <paramref name="userId"/> except
    /// <paramref name="keepKey"/> (null — all of them), reporting what could
    /// not be removed (sk-674.18 INV-26: a password reset ends every session but
    /// the one it re-issued, and must not pass off a failed removal as done).
    /// </summary>
    /// <param name="userId">The user.</param>
    /// <param name="keepKey">Ticket key to keep (<see cref="SessionPrincipal.SessionKeyClaim"/>); null — keep none.</param>
    /// <param name="ct">Cancellation token.</param>
    Task<SessionRemovalResult> RemoveSessionsAsync(Guid userId, string? keepKey, CancellationToken ct);
}

/// <summary>Outcome of <see cref="IUserSessionRevoker.RemoveSessionsAsync"/>.</summary>
/// <param name="Removed">Tickets deleted.</param>
/// <param name="Failed">Tickets of the user that could not be deleted after the retries; they stay in the user's index.</param>
/// <param name="IndexRead">False when the user's index could not be read after the retries — nothing was removed and how many sessions remain is unknown.</param>
public sealed record SessionRemovalResult(int Removed, int Failed, bool IndexRead)
{
    /// <summary>Every other session of the user is gone.</summary>
    public bool Complete => IndexRead && Failed == 0;
}
