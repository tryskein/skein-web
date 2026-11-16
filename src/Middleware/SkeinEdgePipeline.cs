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
    /// parsed allowed host list as singletons, and the forwarded-headers options
    /// taken from the trusted proxy list.
    /// </summary>
    /// <remarks>
    /// The options are set in <c>PostConfigure</c>, which runs after every
    /// <c>Configure</c> callback, including the one the
    /// <c>ASPNETCORE_FORWARDEDHEADERS_ENABLED</c> hosting startup registers:
    /// <see cref="TrustedProxyConfig.Apply"/> is the final word on them whether
    /// that flag is set or not (sk-163.17).
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
        services.PostConfigure<ForwardedHeadersOptions>(trustedProxies.Apply);
        return services;
    }

    /// <summary>
    /// Adds the edge links in order: the <see cref="EdgeSnapshotMiddleware"/>
    /// (transport peer and the arriving shape of <c>X-Forwarded-Host</c>), then
    /// <c>UseForwardedHeaders</c> (scheme, host and visitor address from a
    /// trusted peer), then the <see cref="HostAllowlistMiddleware"/> (the actual
    /// host against <c>SKEIN_ALLOWED_HOSTS</c>, before any processing of the
    /// application).
    /// </summary>
    /// <param name="app">Application builder whose services were registered with
    /// <see cref="AddSkeinEdge"/>.</param>
    /// <returns>The application builder.</returns>
    public static IApplicationBuilder UseSkeinEdge(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        app.UseMiddleware<EdgeSnapshotMiddleware>();
        app.UseForwardedHeaders();
        app.UseMiddleware<HostAllowlistMiddleware>();
        return app;
    }
}
