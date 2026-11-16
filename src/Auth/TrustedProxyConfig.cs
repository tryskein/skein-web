using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;

namespace SkeinWeb.Auth;

/// <summary>
/// Trusted-proxy / client-IP policy for the BFF (sk-163 S9): the parsed
/// <c>SKEIN_TRUSTED_PROXIES</c> list. Parsed once at startup and registered as a
/// singleton, it is the single definition of a trusted peer: Program.cs and the
/// tests configure the ForwardedHeaders middleware from it identically
/// (<see cref="Apply"/>), the "is the per-IP throttle safe to enable?" decision
/// lives here, and the trust-header session bootstrap asks it whether the
/// transport peer of a request is trusted (<see cref="Contains"/>).
/// </summary>
/// <remarks>
/// The per-IP login throttle keys on <c>Connection.RemoteIpAddress</c>. Behind
/// an ingress that address is the ingress/peer IP for EVERY user unless a
/// trusted proxy is configured to honour X-Forwarded-For. With no trusted proxy
/// the per-IP bucket would collapse all logins into ONE key — an attacker could
/// lock out the whole org with a trickle of garbage POSTs. So the per-IP bucket
/// is OPT-IN: enabled only when at least one trusted proxy is configured. The
/// per-email throttle is always on (keyed on email, unaffected).
/// </remarks>
public sealed class TrustedProxyConfig
{
    /// <summary>Name of the setting this list is read from.</summary>
    public const string SettingName = "SKEIN_TRUSTED_PROXIES";

    private readonly IReadOnlyList<IPAddress> _proxies;
    private readonly IReadOnlyList<System.Net.IPNetwork> _networks;

    private TrustedProxyConfig(IReadOnlyList<IPAddress> proxies, IReadOnlyList<System.Net.IPNetwork> networks)
    {
        _proxies = proxies;
        _networks = networks;
    }

    /// <summary>
    /// Parse the raw <c>SKEIN_TRUSTED_PROXIES</c> value: a comma-separated list
    /// of proxy IPs and/or CIDR networks; spaces around entries and empty entries
    /// are ignored. Unset or empty is the empty list.
    /// </summary>
    /// <param name="raw">The setting's value, or <c>null</c> when unset.</param>
    /// <exception cref="InvalidOperationException">
    /// An entry is neither a bare IP nor a CIDR network.
    /// </exception>
    public static TrustedProxyConfig Parse(string? raw) =>
        FromEntries((raw ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

    /// <summary>
    /// Parse already-split <c>SKEIN_TRUSTED_PROXIES</c> entries.
    /// </summary>
    /// <remarks>
    /// A malformed entry throws instead of failing closed: an unparsable
    /// allowlist is an unambiguous operator mistake with no safe reading, and
    /// silently downgrading it to "no trusted proxy" would quietly disable the
    /// per-IP throttle and the host gate on a deployment that asked for both.
    /// The whole list is validated here, before any
    /// <see cref="ForwardedHeadersOptions"/> is touched by <see cref="Apply"/>,
    /// so a throw can never leave a half-applied (half-trusted) configuration
    /// behind.
    /// </remarks>
    /// <param name="entries">One IP or CIDR network per entry.</param>
    /// <exception cref="InvalidOperationException">
    /// An entry is neither a bare IP nor a CIDR network.
    /// </exception>
    public static TrustedProxyConfig FromEntries(IReadOnlyList<string> entries)
    {
        var proxies = new List<IPAddress>();
        var networks = new List<System.Net.IPNetwork>();

        foreach (var entry in entries)
        {
            if (IPAddress.TryParse(entry, out var ip))
            {
                proxies.Add(ip);
            }
            else if (System.Net.IPNetwork.TryParse(entry, out var network))
            {
                networks.Add(network);
            }
            else
            {
                throw new InvalidOperationException(
                    $"{SettingName} entry is neither an IP nor a CIDR network: '{entry}'");
            }
        }

        return new TrustedProxyConfig(proxies, networks);
    }

    /// <summary>Whether the list has no entry at all.</summary>
    public bool IsEmpty => _proxies.Count == 0 && _networks.Count == 0;

    /// <summary>
    /// True when a trusted proxy chain is configured, i.e. it is safe to derive
    /// a real client IP from X-Forwarded-For and therefore to engage the per-IP
    /// login throttle + forward <c>X-Skein-Client-Ip</c> to skein-api.
    /// </summary>
    public bool PerIpThrottleEnabled => !IsEmpty;

    /// <summary>
    /// True when <c>X-Forwarded-Host</c> is honoured, i.e. a trusted proxy chain
    /// is configured and the framework can therefore gate the header on the
    /// known-proxy check. With no trusted proxy the header is NOT honoured and
    /// <c>Request.Host</c> is the literal <c>Host</c> header (sk-194.6.52).
    /// </summary>
    public bool ForwardedHostHonoured => !IsEmpty;

    /// <summary>
    /// Whether <paramref name="peer"/> is a trusted proxy: equal to a listed IP or
    /// inside a listed network. The answer does not depend on the address form:
    /// an IPv4-mapped IPv6 address (<c>::ffff:10.0.0.1</c>) is the same peer as
    /// its IPv4 address (<c>10.0.0.1</c>), whichever form the list or the
    /// connection uses. An empty list trusts no one.
    /// </summary>
    /// <param name="peer">Transport peer address of a connection; <c>null</c> is never trusted.</param>
    public bool Contains(IPAddress? peer)
    {
        if (peer is null || IsEmpty)
        {
            return false;
        }

        var forms = peer.IsIPv4MappedToIPv6 ? new[] { peer, peer.MapToIPv4() } : new[] { peer };
        foreach (var form in forms)
        {
            foreach (var proxy in _proxies)
            {
                var listed = proxy.IsIPv4MappedToIPv6 ? proxy.MapToIPv4() : proxy;
                if (listed.Equals(form))
                {
                    return true;
                }
            }
            foreach (var network in _networks)
            {
                if (network.Contains(form))
                {
                    return true;
                }
            }
        }
        return false;
    }

    /// <summary>
    /// Startup Warning for the legacy trust-headers mode (SSO without an OIDC
    /// authority, skein-api <c>keycloak</c> or <c>hybrid</c>) with an empty list:
    /// trust headers are then accepted from no peer, so no trust-header session
    /// can be created or refreshed. Written as its own entry, apart from the
    /// Warning about <c>X-Forwarded-*</c>. Nothing is written in the other modes,
    /// which do not read trust headers, or with a non-empty list.
    /// </summary>
    /// <param name="mode">The mode this process runs.</param>
    /// <param name="logger">Where the Warning goes.</param>
    public void WarnIfTrustHeadersRefused(WebAuthMode mode, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(mode);
        ArgumentNullException.ThrowIfNull(logger);

        if (!mode.IsKeycloakMode || !IsEmpty)
        {
            return;
        }

        logger.LogWarning(
            "{Setting} is empty in the legacy trust-headers mode (skein-api SKEIN_AUTH_MODE=keycloak|hybrid, " +
            "no Authentication__Oidc__Authority) — X-Auth-Request-User/X-Auth-Request-Email are accepted " +
            "from NO peer, so no SSO session is created or refreshed and users cannot sign in through the " +
            "authenticating proxy. Set {Setting} to the address(es) of the proxy that sets these headers.",
            SettingName, SettingName);
    }

    /// <summary>
    /// Fill the <see cref="ForwardedHeadersOptions"/> of the BFF's one
    /// forwarded-headers pass, the one <c>SkeinEdgePipeline.UseSkeinEdge</c> runs
    /// after the transport peer is recorded. That pass uses its own options
    /// object, filled here from this list; the DI options, read only by a pass
    /// the host may add itself, are set to apply nothing in
    /// <c>SkeinEdgePipeline.AddSkeinEdge</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>With at least one trusted proxy</b> (the required shape for any host a
    /// public client can reach): X-Forwarded-Proto, X-Forwarded-Host and
    /// X-Forwarded-For are all honoured, each gated on the known-proxy check and
    /// peeled for exactly one hop — so OIDC builds an https redirect_uri, the
    /// OIDC same-origin return-URL whitelist (<c>AuthController</c>'s <c>rd</c>
    /// handling) sees the real host, and the per-IP throttle keys on the real
    /// client IP, none of which an arbitrary client can forge.
    /// </para>
    /// <para>
    /// <b>With an empty list</b>: only X-Forwarded-Proto is honoured.
    /// X-Forwarded-Host and X-Forwarded-For are NOT applied — <c>Request.Host</c>
    /// stays the literal <c>Host</c> header and <c>RemoteIpAddress</c> stays the
    /// immediate peer. This is the fail-closed default (sk-194.6.52), and it is
    /// load-bearing rather than cosmetic: ASP.NET Core skips the known-proxy
    /// check entirely when both <see cref="ForwardedHeadersOptions.KnownProxies"/>
    /// and <see cref="ForwardedHeadersOptions.KnownIPNetworks"/> are empty —
    /// documented by Microsoft as the supported way to restore the pre-8.0.17
    /// "trust any proxy" behaviour. Enabling XForwardedHost there therefore meant
    /// "accept X-Forwarded-Host from ANYONE": a public client could set
    /// <c>Request.Host</c> to whatever it liked, which feeds every consumer of
    /// that property downstream — today that is the OIDC same-origin return-URL
    /// whitelist (<c>AuthController</c>'s <c>rd</c> handling) — with an
    /// attacker-controlled value. (sk-303.8 removed the Host-based internal/
    /// public surface classifier that used to sit here too; that gate is gone,
    /// but keeping X-Forwarded-Host fail-closed by default is still the right
    /// call for the remaining consumers of <c>Request.Host</c>.)
    /// </para>
    /// <para>
    /// X-Forwarded-Proto stays on in the empty case deliberately. It is the
    /// sk-163.17 regression fix — the BFF sits behind a TLS-terminating gateway
    /// that forwards plain HTTP upstream, and dropping it degrades the OIDC
    /// callback to http, which Keycloak rejects (this is what broke internal SSO
    /// once already). Unlike the host, the scheme feeds NO authorisation
    /// decision: it only shapes URLs the requester builds for their own session.
    /// The residual exposure — a client that forges its own scheme — is accepted;
    /// a deployment that cares (any deployment with a public surface) declares
    /// SKEIN_TRUSTED_PROXIES and gets the header gated like the other two.
    /// </para>
    /// </remarks>
    /// <param name="o">The options object of the edge's forwarded-headers pass.</param>
    public void Apply(ForwardedHeadersOptions o)
    {
        // Drop the framework's loopback defaults: the allowlist below is the
        // complete statement of who may forward headers to this BFF.
        o.KnownProxies.Clear();
        o.KnownIPNetworks.Clear();

        if (IsEmpty)
        {
            // Fail-closed: with an empty allowlist the middleware has no proxy to
            // check against, so anything we enable here is trusted from ANY peer.
            // Scheme only (sk-163.17 SSO), never host or client IP (sk-194.6.52).
            o.ForwardedHeaders = ForwardedHeaders.XForwardedProto;
            return;
        }

        o.ForwardedHeaders =
            ForwardedHeaders.XForwardedProto |
            ForwardedHeaders.XForwardedHost |
            ForwardedHeaders.XForwardedFor;

        // Peel a single hop only — a multi-hop chain must enumerate each proxy
        // in the allowlist rather than blanket-trusting an arbitrarily long XFF.
        o.ForwardLimit = 1;

        foreach (var ip in _proxies)
        {
            o.KnownProxies.Add(ip);
        }

        foreach (var network in _networks)
        {
            o.KnownIPNetworks.Add(network);
        }
    }
}
