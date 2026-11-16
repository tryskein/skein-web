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
    /// Registers what the edge reads: the parsed trusted proxy list as a
    /// singleton, and the forwarded-headers options taken from it.
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
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddSkeinEdge(this IServiceCollection services, TrustedProxyConfig trustedProxies)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(trustedProxies);

        services.AddSingleton(trustedProxies);
        services.PostConfigure<ForwardedHeadersOptions>(trustedProxies.Apply);
        return services;
    }

    /// <summary>
    /// Adds the edge links in order: the <see cref="EdgeSnapshotMiddleware"/>
    /// (transport peer and the arriving shape of <c>X-Forwarded-Host</c>), then
    /// <c>UseForwardedHeaders</c> (scheme, host and visitor address from a
    /// trusted peer).
    /// </summary>
    /// <param name="app">Application builder whose services were registered with
    /// <see cref="AddSkeinEdge"/>.</param>
    /// <returns>The application builder.</returns>
    public static IApplicationBuilder UseSkeinEdge(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        app.UseMiddleware<EdgeSnapshotMiddleware>();
        app.UseForwardedHeaders();
        return app;
    }
}
