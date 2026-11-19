namespace SkeinWeb.Auth;

/// <summary>How the explicit SSO renewal of a session row ended; set only when a renewal was attempted.</summary>
public enum RenewOutcome
{
    /// <summary>The row was written (extended, claims and the remembered SSO pair merged).</summary>
    Written,

    /// <summary>The key is confirmed absent from the store, or its value is unusable. Nothing was written.</summary>
    KeyAbsent,

    /// <summary>The row kept changing under the renewal: three compare-and-set attempts lost on a live key.</summary>
    CasExhausted,

    /// <summary>The row belongs to another user than the ticket being renewed. Nothing was written.</summary>
    OwnerMismatch,

    /// <summary>The request decided that Main must not write anymore (<see cref="SessionRequestState.SuppressMainWrite"/>).</summary>
    Suppressed,

    /// <summary>The store could not be reached. Nothing is known to be written.</summary>
    TechnicalFailure,
}

/// <summary>
/// The decision of one request about its session, shared by the two cookie schemes and the
/// ticket store. It lives in <see cref="HttpContext.Items"/> and is created on first use.
/// </summary>
public sealed class SessionRequestState
{
    private const string ItemsKey = "skein.session.request-state";

    /// <summary>The state of <paramref name="context"/>, created if the request has none yet.</summary>
    public static SessionRequestState Of(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.Items[ItemsKey] is not SessionRequestState state)
        {
            state = new SessionRequestState();
            context.Items[ItemsKey] = state;
        }
        return state;
    }

    /// <summary>
    /// The request revoked or issued a session, so a later ticket write of Main (an explicit SSO
    /// renewal) must neither touch the store nor add a Set-Cookie. Set before the first store call
    /// of such a sequence.
    /// </summary>
    public bool SuppressMainWrite { get; set; }

    /// <summary>
    /// Outcome of the renewal of this request; null while no renewal was attempted (an issue does
    /// not set it). Main adds no Set-Cookie when it is set and is not <see cref="RenewOutcome.Written"/>.
    /// </summary>
    public RenewOutcome? RenewOutcome { get; set; }

    /// <summary>
    /// The renewal under way is the explicit step of the request (the SSO renewal). The store does
    /// not depend on it: every renewal is that step, and a technical store failure of a renewal is
    /// thrown to the caller.
    /// </summary>
    public bool ExplicitRenewal { get; set; }

    /// <summary>The request carried a session key that was revoked by the issuer (for the issue event of the log).</summary>
    public bool PreviousKeyRevoked { get; set; }

    /// <summary>Key of the session this request issued, or null.</summary>
    public string? IssuedKey { get; set; }

    /// <summary>
    /// Keys whose deletion in this request is confirmed. A repeated removal of such a key by the
    /// cookie handler does nothing and does not call the store.
    /// </summary>
    public HashSet<string> RemovedKeys { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// The request is past the point of no return: store operations ignore the cancellation of the
    /// request and run to completion.
    /// </summary>
    public bool NoCancellation { get; set; }

    /// <summary>The token store operations of this request observe.</summary>
    public CancellationToken Effective(CancellationToken requestAborted) =>
        NoCancellation ? CancellationToken.None : requestAborted;
}
