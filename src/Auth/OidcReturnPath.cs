namespace SkeinWeb.Auth;

/// <summary>
/// Turns the <c>rd</c> parameter of <c>/oauth2/start</c> into the local path
/// the browser returns to after the identity provider. Only a path on this
/// site is ever returned; anything else becomes <c>/</c>, so the sign-in flow
/// cannot be used to send a user to another host right after login.
/// </summary>
public static class OidcReturnPath
{
    /// <summary>Returned for an empty, foreign or malformed <c>rd</c>.</summary>
    public const string Root = "/";

    /// <summary>Resolves <paramref name="rd"/> to a local return path.</summary>
    /// <param name="rd">The requested return target: a local path
    /// (<c>/issues?x=1</c>) or an absolute http(s) URL of this site.</param>
    /// <param name="requestScheme">Scheme of the current request.</param>
    /// <param name="requestHost">Host (with port, if any) of the current request.</param>
    /// <returns>A path that starts with a single <c>/</c> and contains no
    /// control characters, or <see cref="Root"/>.</returns>
    /// <remarks>
    /// The relative form is checked first: on Unix <see cref="Uri.TryCreate(string, UriKind, out Uri)"/>
    /// with <see cref="UriKind.Absolute"/> also accepts <c>/path</c> as a
    /// <c>file://</c> URI. An absolute URL counts only with an http or https
    /// scheme and the request's own scheme and authority, and its path and
    /// query then pass the same local-path check — <c>https://host//evil</c>
    /// has the path <c>//evil</c>, which a browser reads as another host.
    /// The request's host is client-supplied, but it only decides whether the
    /// path of an absolute <c>rd</c> is kept: the result is always a local path,
    /// never a host taken from the request.
    /// </remarks>
    public static string Resolve(string? rd, string requestScheme, string requestHost)
    {
        if (string.IsNullOrEmpty(rd))
        {
            return Root;
        }

        string candidate;
        if (rd.StartsWith('/'))
        {
            candidate = rd;
        }
        else if (Uri.TryCreate(rd, UriKind.Absolute, out var absolute) &&
                 (absolute.Scheme == Uri.UriSchemeHttp || absolute.Scheme == Uri.UriSchemeHttps) &&
                 string.Equals(
                     absolute.GetLeftPart(UriPartial.Authority),
                     $"{requestScheme}://{requestHost}",
                     StringComparison.OrdinalIgnoreCase))
        {
            candidate = absolute.PathAndQuery;
        }
        else
        {
            return Root;
        }

        return IsLocalPath(candidate) ? candidate : Root;
    }

    /// <summary>
    /// A path a browser resolves on this site: one leading <c>/</c> not followed
    /// by <c>/</c> or <c>\</c> (both start a network-path reference), and no
    /// control character anywhere (browsers drop tab and newline, which turns
    /// <c>/&#9;/evil</c> into <c>//evil</c>).
    /// </summary>
    private static bool IsLocalPath(string path)
    {
        if (path.Length == 0 || path[0] != '/')
        {
            return false;
        }
        if (path.Length > 1 && (path[1] == '/' || path[1] == '\\'))
        {
            return false;
        }
        foreach (var c in path)
        {
            if (char.IsControl(c))
            {
                return false;
            }
        }
        return true;
    }
}
