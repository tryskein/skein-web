using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.SignalR.StackExchangeRedis;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Moq;
using SkeinWeb.Auth;
using SkeinWeb.Hubs;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Hubs;

/// <summary>
/// The hub-delivery composition <see cref="HubDeliveryRegistration.AddSkeinHubDelivery"/>
/// — the same function <c>Program.cs</c> calls — resolves: the backplane's
/// options, the hub context and every hosted service the host starts
/// (sk-622.21 K11, review of wave skein-web/2: the options depended on a
/// service that needs the hub context, and the host never started).
/// </summary>
/// <remarks>
/// Redis points at an address nothing listens on: neither the options nor the
/// hub context connect while they are built. The bounded wait is a deadlock
/// detector, not a performance budget — a resolution cycle through a factory
/// lambda never returns, so without the bound the test would hang instead of
/// failing.
/// </remarks>
public class HubDeliveryRegistrationTests
{
    private static readonly TimeSpan DeadlockBound = TimeSpan.FromSeconds(30);

    private static IHost BuildHost()
    {
        // A host as Program.cs gets one (lifetime, logging, DI validation of
        // the Development environment), without starting it.
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            EnvironmentName = Environments.Development,
        });
        var services = builder.Services;
        // Registered by Program.cs outside the hub-delivery composition.
        services.AddSingleton(TimeProvider.System);
        services.Configure<SkeinApiOptions>(o =>
        {
            o.Url = "http://skein-api.test/";
            o.InternalSecret = "test-secret";
        });
        services.AddSkeinServiceApiClient("http://skein-api.test/");
        services.AddSingleton(new Mock<IUserSessionRevoker>().Object);
        services.AddSingleton(new Mock<ISessionTicketProbe>().Object);

        services.AddSkeinHubDelivery(
            "nats://127.0.0.1:1",
            "skein-web-test",
            new ConfigurationOptions
            {
                EndPoints = { { "127.0.0.1", 1 } },
                AbortOnConnectFail = false,
                ConnectTimeout = 200,
            },
            maxProjectsPerConnection: null,
            signalWindowMs: null);
        return builder.Build();
    }

    [Fact]
    public async Task Composition_ResolvesBackplaneOptionsHubContextAndHostedServices()
    {
        using var host = BuildHost();
        var provider = host.Services;

        var resolve = Task.Run(() =>
        {
            var options = provider.GetRequiredService<IOptions<RedisOptions>>().Value;
            var hub = provider.GetRequiredService<IHubContext<SkeinHub>>();
            var hosted = provider.GetServices<IHostedService>().ToArray();
            return (options, hub, hosted);
        });
        var (options, hub, hosted) = await resolve.WaitAsync(DeadlockBound);

        Assert.NotNull(options.ConnectionFactory);
        Assert.NotNull(hub.Clients);
        Assert.Contains(hosted, s => s is TransportHealthMonitor);
        Assert.Contains(hosted, s => s is AccessRecheckService);
        Assert.Contains(hosted, s => s is NatsBridge);
    }

    [Fact]
    public async Task BackplaneFactory_PublishesItsMultiplexerToTheSlot()
    {
        using var host = BuildHost();
        var provider = host.Services;
        var slot = provider.GetRequiredService<BackplaneConnectionSlot>();
        var published = new List<IConnectionMultiplexer>();
        slot.Subscribe(published.Add);

        var options = provider.GetRequiredService<IOptions<RedisOptions>>().Value;
        await using var multiplexer = await options.ConnectionFactory!(TextWriter.Null);

        Assert.Same(multiplexer, Assert.Single(published));
    }
}
