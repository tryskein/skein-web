using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SkeinWeb.Auth;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// sk-163 S9 / sk-194.6.52 — proves the trusted-proxy forwarded-header policy:
/// X-Forwarded-For AND X-Forwarded-Host are honoured ONLY from a configured
/// trusted proxy, so neither the per-IP throttle key nor Request.Host itself
/// can be spoofed by an arbitrary client. Drives the real
/// <see cref="ForwardedHeadersMiddleware"/> against options produced by
/// <see cref="TrustedProxyConfig.Apply"/>, exactly as Program.cs wires it.
/// </summary>
public class TrustedProxyConfigTest
{
    /// <summary>
    /// Run ForwardedHeaders over a request whose immediate peer is
    /// <paramref name="peer"/> and which carries <paramref name="xff"/>, with
    /// <paramref name="trustedProxies"/> configured; return the resolved
    /// RemoteIpAddress the rest of the pipeline (and the throttle) would see.
    /// </summary>
    private static async Task<string?> ResolveAsync(
        string[] trustedProxies, string peer, string? xff)
    {
        var opts = new ForwardedHeadersOptions();
        TrustedProxyConfig.Apply(opts, trustedProxies);

        var mw = new ForwardedHeadersMiddleware(
            next: _ => Task.CompletedTask,
            loggerFactory: NullLoggerFactory.Instance,
            options: Options.Create(opts));

        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = IPAddress.Parse(peer);
        if (xff is not null)
        {
            ctx.Request.Headers["X-Forwarded-For"] = xff;
        }

        await mw.Invoke(ctx);
        return ctx.Connection.RemoteIpAddress?.ToString();
    }

    [Fact]
    public void EmptyConfig_PerIpThrottleDisabled()
    {
        Assert.False(TrustedProxyConfig.PerIpThrottleEnabled([]));
        Assert.True(TrustedProxyConfig.PerIpThrottleEnabled(["10.0.0.1"]));
    }

    [Fact]
    public void EmptyConfig_ForwardedHostNotHonoured()
    {
        // sk-194.6.52 — the predicate Program.cs reports at startup: no trusted
        // proxy ⇒ X-Forwarded-Host is not honoured (Request.Host is the literal
        // Host header). One trusted proxy ⇒ honoured, gated on that proxy.
        Assert.False(TrustedProxyConfig.ForwardedHostHonoured([]));
        Assert.True(TrustedProxyConfig.ForwardedHostHonoured(["10.0.0.1"]));
    }

    [Fact]
    public async Task EmptyConfig_SpoofedXff_Ignored()
    {
        // No trusted proxy: a client-supplied X-Forwarded-For is NOT applied —
        // RemoteIpAddress stays the immediate peer (the would-be spoof fails).
        var resolved = await ResolveAsync(
            trustedProxies: [], peer: "10.1.2.3", xff: "1.2.3.4");

        Assert.Equal("10.1.2.3", resolved);
    }

    [Fact]
    public async Task TrustedPeer_Xff_Honoured()
    {
        // The peer IS the configured trusted proxy → its single XFF hop is
        // honoured, so RemoteIpAddress becomes the real client.
        var resolved = await ResolveAsync(
            trustedProxies: ["10.1.2.3"], peer: "10.1.2.3", xff: "203.0.113.9");

        Assert.Equal("203.0.113.9", resolved);
    }

    [Fact]
    public async Task UntrustedPeer_Xff_Ignored()
    {
        // The peer is NOT in the trusted list (a different proxy is configured)
        // → the XFF is ignored and RemoteIpAddress stays the peer. A client that
        // is not behind the trusted proxy cannot inject a forged key.
        var resolved = await ResolveAsync(
            trustedProxies: ["192.0.2.1"], peer: "10.9.9.9", xff: "203.0.113.9");

        Assert.Equal("10.9.9.9", resolved);
    }

    [Fact]
    public async Task TrustedCidr_Xff_Honoured()
    {
        // CIDR form: peer within the trusted network → XFF honoured.
        var resolved = await ResolveAsync(
            trustedProxies: ["10.0.0.0/8"], peer: "10.4.5.6", xff: "198.51.100.7");

        Assert.Equal("198.51.100.7", resolved);
    }

    /// <summary>
    /// Run ForwardedHeaders with the full set of forwarded headers and return
    /// the scheme/host/ip the rest of the pipeline (OIDC, cookies, throttle)
    /// would see. <paramref name="requestHost"/> is the literal <c>Host</c>
    /// header the edge delivered — what a client trying to forge Request.Host
    /// actually connects to.
    /// </summary>
    private static async Task<(string? ip, string scheme, string? host)> RunAsync(
        string[] trustedProxies, string peer, string? xff, string? proto, string? host,
        string requestHost = "skein.example.com")
    {
        var opts = new ForwardedHeadersOptions();
        TrustedProxyConfig.Apply(opts, trustedProxies);

        var mw = new ForwardedHeadersMiddleware(
            next: _ => Task.CompletedTask,
            loggerFactory: NullLoggerFactory.Instance,
            options: Options.Create(opts));

        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = IPAddress.Parse(peer);
        ctx.Request.Host = new HostString(requestHost);
        if (xff is not null) ctx.Request.Headers["X-Forwarded-For"] = xff;
        if (proto is not null) ctx.Request.Headers["X-Forwarded-Proto"] = proto;
        if (host is not null) ctx.Request.Headers["X-Forwarded-Host"] = host;

        await mw.Invoke(ctx);
        return (ctx.Connection.RemoteIpAddress?.ToString(), ctx.Request.Scheme, ctx.Request.Host.Value);
    }

    [Fact]
    public void EmptyConfig_EnablesProtoOnly_NeverHostOrFor()
    {
        // sk-194.6.52 — the flag-level statement of the fix. With no trusted
        // proxy the middleware has no allowlist to gate a forwarded header
        // against (ASP.NET Core skips the known-proxy check outright when both
        // KnownProxies and KnownIPNetworks are empty — Microsoft documents that
        // as the way to restore "trust any proxy"), so anything enabled here is
        // accepted from ANY client. Only Proto may be, and it carries no
        // authority; Host and For (the throttle key) must not.
        var opts = new ForwardedHeadersOptions();
        TrustedProxyConfig.Apply(opts, []);

        Assert.Equal(ForwardedHeaders.XForwardedProto, opts.ForwardedHeaders);
        Assert.Empty(opts.KnownProxies);
        Assert.Empty(opts.KnownIPNetworks);
    }

    [Fact]
    public async Task EmptyConfig_ForwardedProtoHonoured_SpoofedHostAndXffIgnored()
    {
        // sk-194.6.52 — the vulnerability, as a test. A public client sends
        // X-Forwarded-Host naming a different host it wants Request.Host to
        // become. With no trusted proxy the header must be dropped:
        // Request.Host stays the host the edge actually delivered.
        // X-Forwarded-Proto is still applied (sk-163.17: OIDC needs the https
        // scheme or Keycloak rejects the callback), X-Forwarded-For still is not.
        var (ip, scheme, host) = await RunAsync(
            trustedProxies: [], peer: "203.0.113.5",
            xff: "1.2.3.4", proto: "https", host: "internal.example.com",
            requestHost: "skein.example.com");

        Assert.Equal("https", scheme);             // Proto honoured → OIDC https
        Assert.Equal("skein.example.com", host);   // Host spoof REJECTED
        Assert.Equal("203.0.113.5", ip);           // XFF ignored (fail-closed IP)
    }

    [Fact]
    public async Task UntrustedPeer_SpoofedHost_Ignored()
    {
        // With an allowlist configured, a peer that is NOT the trusted proxy gets
        // nothing applied — not its forged Host, not its forged XFF. (The scheme
        // rides the same known-proxy check here, which is exactly why declaring
        // the proxy is the required shape for a public surface.)
        var (ip, _, host) = await RunAsync(
            trustedProxies: ["10.244.0.0/16"], peer: "203.0.113.5",
            xff: "1.2.3.4", proto: "https", host: "internal.example.com",
            requestHost: "skein.example.com");

        Assert.Equal("skein.example.com", host);
        Assert.Equal("203.0.113.5", ip);
    }

    [Fact]
    public async Task TrustedPeer_ForwardedProtoHostAndXff_Honoured()
    {
        // sk-163.17 — with a trusted proxy the deployment gets all three: real
        // client IP (per-IP throttle) AND https scheme + forwarded host, each
        // gated on the trusted-proxy check so a non-proxy peer could not have
        // set them. This is the prod shape (SKEIN_TRUSTED_PROXIES = pod CIDR).
        var (ip, scheme, host) = await RunAsync(
            trustedProxies: ["10.1.2.3"], peer: "10.1.2.3",
            xff: "203.0.113.9", proto: "https", host: "skein.example.com",
            requestHost: "skein-web.svc.local");

        Assert.Equal("https", scheme);
        Assert.Equal("skein.example.com", host);
        Assert.Equal("203.0.113.9", ip);
    }

    [Fact]
    public async Task TrustedCidr_ForwardedHost_Honoured()
    {
        // The Kubernetes form: the ingress pod's CIDR rather than a bare IP.
        var (_, _, host) = await RunAsync(
            trustedProxies: ["10.244.0.0/16"], peer: "10.244.7.9",
            xff: null, proto: "https", host: "skein.example.com",
            requestHost: "skein-web.svc.local");

        Assert.Equal("skein.example.com", host);
    }

    [Fact]
    public void InvalidEntry_Throws()
    {
        // A malformed allowlist is an unambiguous operator error with no safe
        // reading — it fails loudly at startup rather than degrading silently
        // into "no trusted proxy" (which would quietly disable the per-IP
        // throttle and the host gate on a deployment that asked for both).
        var opts = new ForwardedHeadersOptions();

        var ex = Assert.Throws<InvalidOperationException>(
            () => TrustedProxyConfig.Apply(opts, ["10.244.0.0/16", "not-an-ip"]));

        Assert.Contains("not-an-ip", ex.Message);
        Assert.Contains("SKEIN_TRUSTED_PROXIES", ex.Message);
    }

    [Fact]
    public void InvalidEntry_LeavesOptionsUntouched()
    {
        // Atomicity: the whole list is validated BEFORE the options are mutated,
        // so a throw can never leave a half-applied configuration behind — in
        // particular it can never leave XForwardedHost enabled with a partly
        // populated (or emptied) allowlist, which is the fail-OPEN shape.
        var opts = new ForwardedHeadersOptions { ForwardedHeaders = ForwardedHeaders.None };
        var sentinel = IPAddress.Parse("198.51.100.1");
        opts.KnownProxies.Clear();
        opts.KnownIPNetworks.Clear();
        opts.KnownProxies.Add(sentinel);

        Assert.Throws<InvalidOperationException>(
            () => TrustedProxyConfig.Apply(opts, ["10.0.0.1", "garbage/99"]));

        Assert.Equal(ForwardedHeaders.None, opts.ForwardedHeaders);
        Assert.Equal([sentinel], opts.KnownProxies);
        Assert.Empty(opts.KnownIPNetworks);
    }
}
