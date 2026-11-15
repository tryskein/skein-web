namespace SkeinWeb.Logging;

/// <summary>
/// A request path that is safe to write to the log. Proxied paths carry link
/// tokens (<c>/ui/v1/invitations/{token}</c>, password-reset and email
/// confirmation links), and query strings may carry anything, so a raw URL is
/// never logged. Every path segment that could be a secret — 20 or more
/// characters of the base64url alphabet that are not a GUID (a link token is
/// 43) — is replaced by <see cref="Redacted"/>, and the query string is never
/// part of the result. Ids, prefixes and words keep the path readable. The rule
/// matches the one skein-api applies to its own request log.
/// </summary>
public static class LoggablePath
{
    /// <summary>Replacement for a segment that may be a secret.</summary>
    public const string Redacted = "{redacted}";

    /// <summary>Shortest segment treated as a possible secret.</summary>
    private const int MinSecretLength = 20;

    /// <summary>Returns <paramref name="path"/> with possible secrets masked.</summary>
    /// <param name="path">A request path without the query string.</param>
    public static string From(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return string.Empty;
        }
        var segments = path.Split('/');
        for (var i = 0; i < segments.Length; i++)
        {
            if (MayBeSecret(segments[i]))
            {
                segments[i] = Redacted;
            }
        }
        return string.Join('/', segments);
    }

    private static bool MayBeSecret(string segment) =>
        segment.Length >= MinSecretLength &&
        segment.All(IsTokenChar) &&
        !Guid.TryParse(segment, out _);

    private static bool IsTokenChar(char c) =>
        c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '_';
}
