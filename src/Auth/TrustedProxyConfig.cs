using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;

namespace SkeinWeb.Auth;

/// <summary>
/// Trusted-proxy / client-IP policy for the BFF (sk-163 S9). Centralises the
/// SKEIN_TRUSTED_PROXIES parsing so Program.cs and the tests configure the
/// ForwardedHeaders middleware identically, and so the "is the per-IP throttle
/// safe to enable?" decision lives in one place.
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
public static class TrustedProxyConfig
{
    /// <summary>
    /// True when a trusted proxy chain is configured, i.e. it is safe to derive
    /// a real client IP from X-Forwarded-For and therefore to engage the per-IP
    /// login throttle + forward <c>X-Skein-Client-Ip</c> to skein-api.
    /// </summary>
    public static bool PerIpThrottleEnabled(IReadOnlyList<string> trustedProxies) =>
        trustedProxies.Count > 0;

    /// <summary>
    /// True when <c>X-Forwarded-Host</c> is honoured, i.e. a trusted proxy chain
    /// is configured and the framework can therefore gate the header on the
    /// known-proxy check. With no trusted proxy the header is NOT honoured and
    /// <c>Request.Host</c> is the literal <c>Host</c> header (sk-194.6.52).
    /// </summary>
    public static bool ForwardedHostHonoured(IReadOnlyList<string> trustedProxies) =>
        trustedProxies.Count > 0;

    /// <summary>
    /// Configure <see cref="ForwardedHeadersOptions"/> as the BFF's SINGLE source
    /// of truth for forwarded-header handling (replacing the framework's
    /// ASPNETCORE_FORWARDEDHEADERS_ENABLED path — two configs on the same DI
    /// options would fight and double-register the middleware).
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
    /// <para>
    /// A malformed entry throws instead of failing closed: an unparsable
    /// allowlist is an unambiguous operator mistake with no safe reading, and
    /// silently downgrading it to "no trusted proxy" would quietly disable the
    /// per-IP throttle and the host gate on a deployment that asked for both.
    /// The whole list is validated BEFORE the options are touched, so a throw
    /// can never leave a half-applied (half-trusted) configuration behind.
    /// </para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// An entry is neither a bare IP nor a CIDR network.
    /// </exception>
    public static void Apply(ForwardedHeadersOptions o, IReadOnlyList<string> trustedProxies)
    {
        // Parse and validate the ENTIRE list first — nothing on `o` is mutated
        // until every entry is known-good (see the atomicity note above).
        var knownProxies = new List<IPAddress>();
        var knownNetworks = new List<System.Net.IPNetwork>();

        foreach (var entry in trustedProxies)
        {
            if (IPAddress.TryParse(entry, out var ip))
            {
                knownProxies.Add(ip);
            }
            else if (System.Net.IPNetwork.TryParse(entry, out var network))
            {
                knownNetworks.Add(network);
            }
            else
            {
                throw new InvalidOperationException(
                    $"SKEIN_TRUSTED_PROXIES entry is neither an IP nor a CIDR network: '{entry}'");
            }
        }

        // Drop the framework's loopback defaults: the allowlist below is the
        // complete statement of who may forward headers to this BFF.
        o.KnownProxies.Clear();
        o.KnownIPNetworks.Clear();

        if (knownProxies.Count == 0 && knownNetworks.Count == 0)
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

        foreach (var ip in knownProxies)
        {
            o.KnownProxies.Add(ip);
        }

        foreach (var network in knownNetworks)
        {
            o.KnownIPNetworks.Add(network);
        }
    }
}
