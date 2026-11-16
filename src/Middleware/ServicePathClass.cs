namespace SkeinWeb.Middleware;

/// <summary>
/// The single definition of the browser proxy's service path class: the
/// skein-api internal-API paths that only the BFF itself may call, never a
/// browser through <see cref="ApiProxyMiddleware"/>.
/// </summary>
/// <remarks>
/// <para>The class, relative to the internal-API prefix (<c>/ui/v1</c>):</para>
/// <list type="bullet">
///   <item>everything under <c>auth/</c>, except <c>GET auth/me</c>;</item>
///   <item>everything under <c>hub/</c>;</item>
///   <item>everything under <c>internal/</c>.</item>
/// </list>
/// <para>Every service route of skein-api's internal API lies inside this class.
/// It is a class, not a list: a new route under these segments is refused without
/// any change here. The match is per segment, so <c>authors</c>, <c>hubs</c> and
/// <c>internals</c> are ordinary paths.</para>
/// <para>The input is the upstream URI the proxy is about to send, not the
/// browser's path: an equivalent form of a service path (other letter case,
/// repeated or trailing slashes, dot segments plain or percent-encoded, an
/// encoded <c>/</c>, a backslash) must not reach skein-api, and only the URI
/// after every transformation of building it says where the request would go.
/// The path is normalised the way a server could still read it: decoded once,
/// split on <c>/</c> and <c>\</c> with empty segments dropped, <c>.</c> and
/// <c>..</c> resolved again, class segments compared ignoring case.</para>
/// <para>A path that leaves the internal-API prefix after normalisation is
/// refused too: it would address skein-api outside <c>/ui/v1</c>, where the
/// transitional <c>/api/v1</c> prefix serves the same service routes.</para>
/// <para>The work is a fixed scan of the path, no I/O.</para>
/// </remarks>
public static class ServicePathClass
{
    /// <summary>Top-level internal-API segments whose whole subtree is the service class.</summary>
    private static readonly string[] ServiceSegments = ["auth", "hub", "internal"];

    /// <summary>
    /// Whether the browser proxy must refuse to send a request with
    /// <paramref name="method"/> to <paramref name="upstream"/>: the normalised
    /// path is in the service class or lies outside
    /// <paramref name="upstreamRootPath"/>.
    /// </summary>
    /// <param name="method">HTTP method of the browser's request.</param>
    /// <param name="upstream">Absolute upstream URI the proxy built for the request.</param>
    /// <param name="upstreamRootPath">Absolute path of the internal-API root on
    /// skein-api, including any base path of the configured skein-api URL, e.g.
    /// <c>/ui/v1</c>. Compared exactly, segment by segment, after the same
    /// normalisation.</param>
    /// <returns><c>true</c> when the request must not reach skein-api.</returns>
    public static bool Refuses(string method, Uri upstream, string upstreamRootPath)
    {
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(upstream);
        ArgumentNullException.ThrowIfNull(upstreamRootPath);
        if (!upstream.IsAbsoluteUri)
        {
            throw new ArgumentException("The upstream URI must be absolute.", nameof(upstream));
        }

        var root = Normalise(upstreamRootPath);
        var path = Normalise(upstream.AbsolutePath);

        if (path.Count < root.Count)
        {
            return true;
        }
        for (var i = 0; i < root.Count; i++)
        {
            if (!string.Equals(path[i], root[i], StringComparison.Ordinal))
            {
                return true;
            }
        }

        if (path.Count == root.Count)
        {
            return false;
        }

        var head = path[root.Count];
        if (!ServiceSegments.Any(s => string.Equals(s, head, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        var isMe = path.Count == root.Count + 2 &&
                   string.Equals(head, "auth", StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(path[root.Count + 1], "me", StringComparison.OrdinalIgnoreCase);
        return !(isMe && HttpMethods.IsGet(method));
    }

    /// <summary>
    /// Segments of <paramref name="absolutePath"/> after one percent-decoding,
    /// splitting on <c>/</c> and <c>\</c>, dropping empty segments and
    /// resolving <c>.</c> and <c>..</c> (a <c>..</c> at the root stays at the root).
    /// </summary>
    private static List<string> Normalise(string absolutePath)
    {
        var decoded = Uri.UnescapeDataString(absolutePath);
        var segments = new List<string>();
        foreach (var segment in decoded.Split(['/', '\\'], StringSplitOptions.RemoveEmptyEntries))
        {
            if (segment == ".")
            {
                continue;
            }
            if (segment == "..")
            {
                if (segments.Count > 0)
                {
                    segments.RemoveAt(segments.Count - 1);
                }
                continue;
            }
            segments.Add(segment);
        }
        return segments;
    }
}
