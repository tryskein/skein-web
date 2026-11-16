using System.Net;
using System.Net.Sockets;

namespace SkeinWeb.Auth;

/// <summary>
/// The parsed <c>SKEIN_ALLOWED_HOSTS</c> list: the host names skein-web answers
/// to. Parsed once at startup (a malformed value stops the start) and
/// registered as a singleton; <c>HostAllowlistMiddleware</c> compares the
/// actual request host with it.
/// </summary>
/// <remarks>
/// <para>Grammar: a comma-separated list; spaces around entries are dropped and
/// empty entries between commas are ignored. An entry is a host name — a DNS
/// name or an IP literal, IPv6 in square brackets. An entry with a scheme, a
/// port, a path, <c>*</c> or another wildcard, or any other character outside a
/// host name is a startup error, and so is a non-empty value left without a
/// single entry (<c>,,</c>): it never turns silently into the empty list.
/// Unset or empty is the empty list — any host, as before.</para>
/// <para>Comparison ignores letter case and a trailing dot; IP literals are
/// compared as addresses, so <c>[2001:db8::1]</c> in the list and the same
/// address in a request are one name.</para>
/// <para>This is not the framework's <c>AllowedHosts</c> setting, which stays
/// <c>*</c>.</para>
/// </remarks>
public sealed class AllowedHostsConfig
{
    /// <summary>Name of the setting this list is read from.</summary>
    public const string SettingName = "SKEIN_ALLOWED_HOSTS";

    /// <summary>Longest DNS name, without the trailing dot (RFC 1035).</summary>
    private const int MaxNameLength = 253;

    /// <summary>Longest DNS label (RFC 1035).</summary>
    private const int MaxLabelLength = 63;

    private readonly HashSet<string> _names;
    private readonly List<IPAddress> _addresses;

    private AllowedHostsConfig(HashSet<string> names, List<IPAddress> addresses)
    {
        _names = names;
        _addresses = addresses;
    }

    /// <summary>
    /// Parse the raw <c>SKEIN_ALLOWED_HOSTS</c> value.
    /// </summary>
    /// <param name="raw">The setting's value, or <c>null</c> when unset.</param>
    /// <returns>The parsed list; empty for an unset or empty value.</returns>
    /// <exception cref="InvalidOperationException">
    /// An entry is not a host name, or a non-empty value has no entry. The
    /// message names the setting and the offending entry or value.
    /// </exception>
    public static AllowedHostsConfig Parse(string? raw)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        var addresses = new List<IPAddress>();
        if (string.IsNullOrEmpty(raw))
        {
            return new AllowedHostsConfig(names, addresses);
        }

        var entries = raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (entries.Length == 0)
        {
            throw new InvalidOperationException(
                $"{SettingName} is set but holds no host name: '{raw}'. Leave it empty to allow any host.");
        }

        foreach (var entry in entries)
        {
            if (!TryNormalise(entry, out var address, out var name))
            {
                throw new InvalidOperationException(
                    $"{SettingName} entry is not a host name: '{entry}'. Expected a DNS name or an IP " +
                    "literal (IPv6 in square brackets), without a scheme, port, path or wildcard.");
            }
            if (address is not null)
            {
                addresses.Add(address);
            }
            else
            {
                names.Add(name!);
            }
        }

        return new AllowedHostsConfig(names, addresses);
    }

    /// <summary>Whether the list is empty, i.e. any host is allowed.</summary>
    public bool IsEmpty => _names.Count == 0 && _addresses.Count == 0;

    /// <summary>
    /// Whether <paramref name="host"/> — a request host without its port, as in
    /// <c>HttpRequest.Host.Host</c> (IPv6 in brackets) — is in the list. An empty
    /// list allows every host; an empty or malformed host is never in a
    /// non-empty list.
    /// </summary>
    /// <param name="host">The host name of the request.</param>
    public bool Allows(string? host)
    {
        if (IsEmpty)
        {
            return true;
        }
        if (string.IsNullOrEmpty(host) || !TryNormalise(host, out var address, out var name))
        {
            return false;
        }
        return address is not null
            ? _addresses.Any(a => a.Equals(address))
            : _names.Contains(name!);
    }

    /// <summary>
    /// Startup Warning when the list is empty: any host is then accepted. Written
    /// in every authentication mode; nothing is written for a non-empty list.
    /// </summary>
    /// <param name="logger">Where the Warning goes.</param>
    public void WarnIfEmpty(ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);

        if (!IsEmpty)
        {
            return;
        }

        logger.LogWarning(
            "{Setting} is empty — skein-web answers requests for ANY host name. Set {Setting} to the " +
            "host name(s) this deployment is reached by.",
            SettingName, SettingName);
    }

    /// <summary>
    /// Reads <paramref name="value"/> as a host name: an IPv6 literal in square
    /// brackets, a dotted IPv4 literal, or a DNS name (letters, digits and
    /// hyphens in labels of 1–63 characters, at most one trailing dot). IP
    /// literals come back as an address (IPv4-mapped IPv6 as IPv4), names in
    /// lower case without the trailing dot.
    /// </summary>
    private static bool TryNormalise(string value, out IPAddress? address, out string? name)
    {
        address = null;
        name = null;

        if (value.StartsWith('['))
        {
            if (!value.EndsWith(']') ||
                !IPAddress.TryParse(value.AsSpan(1, value.Length - 2), out var v6) ||
                v6.AddressFamily != AddressFamily.InterNetworkV6 ||
                v6.ScopeId != 0)
            {
                return false;
            }
            address = v6.IsIPv4MappedToIPv6 ? v6.MapToIPv4() : v6;
            return true;
        }

        var trimmed = value.EndsWith('.') ? value[..^1] : value;
        if (trimmed.Length is 0 or > MaxNameLength)
        {
            return false;
        }

        var labels = trimmed.Split('.');
        if (labels.Length == 4 && labels.All(l => l.Length is > 0 and <= 3 && l.All(char.IsAsciiDigit)))
        {
            if (!IPAddress.TryParse(trimmed, out var v4) || v4.AddressFamily != AddressFamily.InterNetwork)
            {
                return false;
            }
            address = v4;
            return true;
        }

        foreach (var label in labels)
        {
            if (label.Length is 0 or > MaxLabelLength ||
                label[0] == '-' || label[^1] == '-' ||
                !label.All(c => char.IsAsciiLetterOrDigit(c) || c == '-'))
            {
                return false;
            }
        }

        name = trimmed.ToLowerInvariant();
        return true;
    }
}
