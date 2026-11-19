using Microsoft.AspNetCore.Authentication;

namespace SkeinWeb.Auth;

/// <summary>
/// The window of a session: its sign-in time and sign-in plus the absolute limit
/// in effect at that sign-in, stored in the ticket as
/// <see cref="AuthenticationProperties.IssuedUtc"/> and
/// <see cref="AuthenticationProperties.ExpiresUtc"/>. Only a sign-in sets it;
/// nothing rewrites it afterwards.
/// <para>This type is the single definition of the window, of its validity, of
/// the end of a session and of the lifetime a write gives the session row in
/// Redis. Every other path refers to it rather than restating these rules.</para>
/// </summary>
/// <param name="IssuedUtc">Sign-in time.</param>
/// <param name="ExpiresUtc">Sign-in time plus the absolute limit in effect at sign-in.</param>
public readonly record struct SessionWindow(DateTimeOffset IssuedUtc, DateTimeOffset ExpiresUtc)
{
    /// <summary>
    /// The window a sign-in at <paramref name="now"/> starts:
    /// [<paramref name="now"/>, <paramref name="now"/> + absolute limit].
    /// </summary>
    /// <param name="timeouts">The limits in effect.</param>
    /// <param name="now">The moment of the sign-in.</param>
    /// <returns>The new window.</returns>
    public static SessionWindow ForSignIn(SessionTimeouts timeouts, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(timeouts);
        return new SessionWindow(now, now + timeouts.Absolute);
    }

    /// <summary>
    /// Reads the window of a ticket. It is valid when the ticket carries both a
    /// parsable issue time and a parsable expiry time and the issue time is
    /// earlier than the expiry time. A ticket without a valid window does not
    /// authenticate.
    /// </summary>
    /// <param name="properties">The ticket's properties.</param>
    /// <param name="window">The window, when valid.</param>
    /// <returns><c>true</c> when the window is valid.</returns>
    public static bool TryRead(AuthenticationProperties properties, out SessionWindow window)
    {
        ArgumentNullException.ThrowIfNull(properties);
        if (properties.IssuedUtc is { } issued
            && properties.ExpiresUtc is { } expires
            && issued < expires)
        {
            window = new SessionWindow(issued, expires);
            return true;
        }
        window = default;
        return false;
    }

    /// <summary>
    /// The end of the session: the earlier of sign-in plus the absolute limit in
    /// effect now and the expiry written at sign-in. Lowering the limit brings it
    /// earlier for sessions already issued; raising it never moves it past the
    /// written window.
    /// </summary>
    /// <param name="timeouts">The limits in effect at the moment of the request.</param>
    /// <returns>The moment from which the session no longer authenticates.</returns>
    public DateTimeOffset SessionEnd(SessionTimeouts timeouts)
    {
        ArgumentNullException.ThrowIfNull(timeouts);
        // Compared through the written span rather than by adding the limit first:
        // IssuedUtc + limit may lie past DateTimeOffset.MaxValue while the written
        // expiry is representable, and when the limit is shorter than that span the
        // sum is earlier than ExpiresUtc and so representable too.
        return timeouts.Absolute < ExpiresUtc - IssuedUtc
            ? IssuedUtc + timeouts.Absolute
            : ExpiresUtc;
    }

    /// <summary>
    /// Whether the session has ended at <paramref name="now"/>: at its end and
    /// later it does not authenticate.
    /// <para>During the last millisecond before the end (a time left greater than
    /// 0 and shorter than 1 ms) the session has not ended yet, while
    /// <see cref="TryGetRowLifetime"/> already reports «ended», because it counts
    /// the time left in whole milliseconds rounded down.</para>
    /// </summary>
    /// <param name="timeouts">The limits in effect at the moment of the request.</param>
    /// <param name="now">The moment of the check.</param>
    /// <returns><c>true</c> when <paramref name="now"/> is at or past <see cref="SessionEnd"/>.</returns>
    public bool HasEnded(SessionTimeouts timeouts, DateTimeOffset now) => now >= SessionEnd(timeouts);

    /// <summary>
    /// The lifetime a write at <paramref name="now"/> gives the session row:
    /// min(idle limit, time left until <see cref="SessionEnd"/>). The time left is
    /// counted in whole milliseconds, rounded down, so the row never outlives the
    /// session. The result is either a positive whole number of milliseconds
    /// (at least 1, valid for <c>PX</c> and <c>PEXPIRE</c>) or «ended»: a time left
    /// of 0 ms or less, including a positive remainder shorter than 1 ms, means the
    /// session has ended and no lifetime is written.
    /// </summary>
    /// <param name="timeouts">The limits in effect at the moment of the write.</param>
    /// <param name="now">The moment of the write.</param>
    /// <param name="lifetime">The row lifetime, in whole milliseconds, when the session is alive.</param>
    /// <returns><c>false</c> when the session has ended.</returns>
    public bool TryGetRowLifetime(SessionTimeouts timeouts, DateTimeOffset now, out TimeSpan lifetime)
    {
        ArgumentNullException.ThrowIfNull(timeouts);
        var remaining = SessionEnd(timeouts) - now;
        // Integer division truncates toward zero: for a positive remainder that is
        // rounding down; a negative one ends up at 0 or below, «ended» either way.
        var remainingMs = remaining.Ticks / TimeSpan.TicksPerMillisecond;
        if (remainingMs < 1)
        {
            lifetime = default;
            return false;
        }
        var idleMs = timeouts.Idle.Ticks / TimeSpan.TicksPerMillisecond;
        lifetime = TimeSpan.FromMilliseconds(Math.Min(idleMs, remainingMs));
        return true;
    }
}
