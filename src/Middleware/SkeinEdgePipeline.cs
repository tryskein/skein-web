using Microsoft.AspNetCore.HttpOverrides;
using SkeinWeb.Auth;

namespace SkeinWeb.Middleware;

/// <summary>
/// The edge of the request pipeline — the single ordered composition shared by
/// <c>Program.cs</c> and the tests of the assembled pipeline, so both run the
/// links in the same order.
/// </summary>
public static class SkeinEdgePipeline
{
    /// <summary>
    /// Registers what the edge reads: the parsed trusted proxy list and the
    /// parsed allowed host list as singletons, and neutral forwarded-headers
    /// options for any forwarded-headers pass outside the edge.
    /// </summary>
    /// <remarks>
    /// <para>Forwarded headers are processed exactly once, inside
    /// <see cref="UseSkeinEdge"/>, after the transport peer is recorded, with
    /// options of its own built from the trusted proxy list. The options in DI
    /// are reached only by a pass the host adds on its own: with
    /// <c>ASPNETCORE_FORWARDEDHEADERS_ENABLED=true</c> the default web host puts
    /// <c>UseForwardedHeaders()</c> in front of the whole application pipeline,
    /// before the snapshot, where it would replace the transport peer with the
    /// visitor and reduce <c>X-Forwarded-Host</c> to one name. Those DI options are
    /// therefore set, in <c>PostConfigure</c> (after every <c>Configure</c>
    /// callback, the host's own included), to process no header and trust no
    /// proxy: such a pass changes nothing, whatever the flag says.</para>
    /// </remarks>
    /// <param name="services">Service collection.</param>
    /// <param name="trustedProxies">The parsed <c>SKEIN_TRUSTED_PROXIES</c>.</param>
    /// <param name="allowedHosts">The parsed <c>SKEIN_ALLOWED_HOSTS</c>.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddSkeinEdge(
        this IServiceCollection services,
        TrustedProxyConfig trustedProxies,
        AllowedHostsConfig allowedHosts)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(trustedProxies);
        ArgumentNullException.ThrowIfNull(allowedHosts);

        services.AddSingleton(trustedProxies);
        services.AddSingleton(allowedHosts);
        services.PostConfigure<ForwardedHeadersOptions>(o =>
        {
            o.ForwardedHeaders = ForwardedHeaders.None;
            o.KnownProxies.Clear();
            o.KnownIPNetworks.Clear();
        });
        return services;
    }

    /// <summary>
    /// Adds the edge links in order: the <see cref="EdgeSnapshotMiddleware"/>
    /// (transport peer and the arriving shape of <c>X-Forwarded-Host</c>), then
    /// <c>UseForwardedHeaders</c> with options built from the trusted proxy list
    /// (scheme, host and visitor address from a trusted peer) — the one pass of
    /// forwarded headers, see <see cref="AddSkeinEdge"/> — then the <see cref="HostAllowlistMiddleware"/> (the actual
    /// host against <c>SKEIN_ALLOWED_HOSTS</c>, before any processing of the
    /// application).
    /// </summary>
    /// <param name="app">Application builder whose services were registered with
    /// <see cref="AddSkeinEdge"/>.</param>
    /// <returns>The application builder.</returns>
    public static IApplicationBuilder UseSkeinEdge(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        var forwardedHeaders = new ForwardedHeadersOptions();
        app.ApplicationServices.GetRequiredService<TrustedProxyConfig>().Apply(forwardedHeaders);

        app.UseMiddleware<EdgeSnapshotMiddleware>();
        app.UseForwardedHeaders(forwardedHeaders);
        app.UseMiddleware<HostAllowlistMiddleware>();
        return app;
    }
}
