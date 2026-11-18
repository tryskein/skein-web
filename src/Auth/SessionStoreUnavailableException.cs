namespace SkeinWeb.Auth;

/// <summary>
/// The session store failed technically (Redis unreachable, timed out, answered with an error):
/// the state of the session is unknown, which is not the same as "no session".
/// </summary>
/// <remarks>
/// Carries neither the text of the source failure nor an inner exception: both can hold a
/// session key. The type and code of the failure are logged by the store.
/// </remarks>
public sealed class SessionStoreUnavailableException()
    : Exception("The session store is unavailable.")
{
}
