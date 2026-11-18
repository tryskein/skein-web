namespace SkeinWeb.Auth;

/// <summary>
/// A session could not be revoked or issued. The message is one of this service's own short
/// reasons; neither the text of the source failure nor an inner exception is carried, because
/// both can hold a session key. No Set-Cookie of a new session was written.
/// </summary>
/// <param name="reason">A short own reason, never a source exception message.</param>
public sealed class SessionIssueException(string reason) : Exception(reason)
{
}
