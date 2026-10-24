using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.SignalR.StackExchangeRedis;
using NATS.Client.Core;
using StackExchange.Redis;

namespace SkeinWeb.Hubs;

/// <summary>
/// DI registration of hub delivery (sk-622.21 US-9, US-10, US-11, K10, K11) —
/// the single composition shared by <c>Program.cs</c> and the test that
/// resolves it.
/// </summary>
public static class HubDeliveryRegistration
{
    /// <summary>
    /// Registers the NATS connection, the SignalR hub with its Redis
    /// backplane, and the hub-delivery services: connection registry, access
    /// re-check, declaration limiter, personal-signal coalescing, the NATS
    /// bridge, the control-event subscriber and the transport-health monitor.
    /// </summary>
    /// <remarks>
    /// <para>The backplane's <see cref="RedisOptions.ConnectionFactory"/>
    /// depends only on <see cref="BackplaneConnectionSlot"/>, which has no
    /// dependencies: the factory stores the multiplexer there and
    /// <see cref="TransportHealthMonitor"/> subscribes to it on start. The
    /// options must not depend on anything that takes
    /// <see cref="IHubContext{THub}"/> — that context needs the Redis hub
    /// lifetime manager, which needs these options, and the host would never
    /// start.</para>
    /// <para>Expects registered elsewhere: logging, <see cref="TimeProvider"/>,
    /// <see cref="Auth.SkeinServiceApiClient"/> and
    /// <see cref="Auth.IUserSessionRevoker"/>. Neither the NATS connection nor
    /// the backplane connects here: both connect when first used.</para>
    /// </remarks>
    /// <param name="services">Service collection.</param>
    /// <param name="natsUrl">NATS server URL.</param>
    /// <param name="natsName">Connection name reported to NATS.</param>
    /// <param name="redisConfig">Redis configuration of the backplane; its
    /// channel prefix is set to <c>skein:signalr</c>.</param>
    /// <param name="maxProjectsPerConnection">Raw <c>HUB_MAX_PROJECTS_PER_CONNECTION</c>
    /// (see <see cref="HubDeliveryOptions.ParseMaxProjectsPerConnection"/>).</param>
    /// <param name="signalWindowMs">Raw <c>COUNTS_SIGNAL_WINDOW_MS</c>
    /// (see <see cref="PersonalSignalOptions.ParseWindow"/>).</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddSkeinHubDelivery(
        this IServiceCollection services,
        string natsUrl,
        string natsName,
        ConfigurationOptions redisConfig,
        string? maxProjectsPerConnection,
        string? signalWindowMs)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrEmpty(natsUrl);
        ArgumentException.ThrowIfNullOrEmpty(natsName);
        ArgumentNullException.ThrowIfNull(redisConfig);

        // Single NATS connection per pod, shared between the events firehose
        // and the user-namespace subscriptions in NatsBridge. NATS.Net
        // handles reconnects internally.
        services.AddSingleton<INatsConnection>(_ =>
            new NatsConnection(new NatsOpts
            {
                Url = natsUrl,
                Name = natsName,
            }));

        // US-9 — addressed delivery: per-replica connection registry,
        // per-connection declaration rate limit, HUB_MAX_PROJECTS_PER_CONNECTION.
        services.AddSingleton(new HubDeliveryOptions
        {
            MaxProjectsPerConnection = HubDeliveryOptions.ParseMaxProjectsPerConnection(maxProjectsPerConnection),
        });
        services.AddSingleton<ConnectionRegistry>();
        // K10 — access re-check every 30 s, after NATS reconnect, fail-closed
        // at 60 s; the bridge waits on it (IProjectDeliveryGate) after a reconnect.
        services.AddSingleton<AccessRecheckService>();
        services.AddSingleton<IProjectDeliveryGate>(sp => sp.GetRequiredService<AccessRecheckService>());
        services.AddHostedService(sp => sp.GetRequiredService<AccessRecheckService>());
        services.AddSingleton<DeclarationLimiter>();

        // US-11 — personal signals: every replica subscribes
        // skein.user.*.signal WITHOUT a queue group and coalesces per
        // connection over COUNTS_SIGNAL_WINDOW_MS.
        services.AddSingleton(new PersonalSignalOptions
        {
            Window = PersonalSignalOptions.ParseWindow(signalWindowMs),
        });
        services.AddSingleton<PersonalSignalCoalescer>();
        services.AddSingleton<IUserIdProvider, SkeinUserIdProvider>();

        // SignalR + Redis backplane: a hub message published on pod A reaches
        // a client whose WebSocket lives on pod B. The channel prefix isolates
        // skein hub traffic from anything else on the same Redis instance.
        services
            .AddSignalR()
            .AddStackExchangeRedis(options =>
            {
                options.Configuration = redisConfig;
                options.Configuration.ChannelPrefix = RedisChannel.Literal("skein:signalr");
            });
        services.AddHostedService<NatsBridge>();
        services.AddHostedService<PersonalSignalSubscriber>();
        services.AddHostedService<AccessControlSubscriber>();

        // K11 — transport breaks: NATS reconnect → resync to this replica's
        // connections; backplane restore → resync to them and to the
        // addressees of sends that failed meanwhile. The bridge records failed
        // sends on the monitor; the monitor learns the backplane's multiplexer
        // from the slot, never from these options (see remarks).
        services.AddSingleton<BackplaneConnectionSlot>();
        services.AddSingleton<TransportHealthMonitor>();
        services.AddSingleton<IDeliveryFailureRecorder>(sp => sp.GetRequiredService<TransportHealthMonitor>());
        services.AddHostedService(sp => sp.GetRequiredService<TransportHealthMonitor>());
        services
            .AddOptions<RedisOptions>()
            .Configure<BackplaneConnectionSlot>((options, slot) =>
                options.ConnectionFactory = async writer =>
                {
                    var multiplexer = await ConnectionMultiplexer.ConnectAsync(options.Configuration, writer);
                    slot.Publish(multiplexer);
                    return multiplexer;
                });

        return services;
    }
}
