using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Caching.StackExchangeRedis;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using NATS.Client.Core;
using SkeinWeb.Auth;
using SkeinWeb.Hubs;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Auth;

/// <summary>Session revocation through live subscriptions while the browser bridge is running.</summary>
[Trait("Category", "Integration")]
public sealed class UserChangedSubscriberIntegrationTests
{
    [InfrastructureTheory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task ClaimChanges_RevokeEveryAffectedTicket_WithConcurrentBrowserBridges(int replicas)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var ct = deadline.Token;
        var natsUrl = Required("TEST_NATS_URL");
        var redisUrl = Required("TEST_REDIS_URL");
        using var monitor = new HttpClient { BaseAddress = new Uri(Required("TEST_NATS_MONITOR_URL")) };
        await using var redis = await ConnectionMultiplexer.ConnectAsync(redisUrl);
        var options = Options.Create(new RedisCacheOptions { Configuration = redisUrl });
        using var cache = new RedisCache(options);
        var store = new RedisTicketStore(cache, redis, new ConnectionRegistry(TimeProvider.System),
            options, NullLogger<RedisTicketStore>.Instance);
        var connections = new List<NatsConnection>();
        var bridges = new List<NatsBridge>();
        var subscribers = new List<UserChangedSubscriber>();
        var keys = new List<string>();
        try
        {
            for (var replica = 0; replica < replicas; replica++)
            {
                var conn = new NatsConnection(new NatsOpts { Url = natsUrl });
                connections.Add(conn);
                var bridge = new NatsBridge(conn, Mock.Of<IHubContext<SkeinHub>>(), NullLogger<NatsBridge>.Instance);
                var subscriber = new UserChangedSubscriber(conn, store, NullLogger<UserChangedSubscriber>.Instance);
                bridges.Add(bridge);
                subscribers.Add(subscriber);
                await bridge.StartAsync(ct);
                await subscriber.StartAsync(ct);
            }

            // Wait for all three real subscriptions per replica. StartAsync starts
            // background tasks; publishing immediately would race their registration.
            await UntilAsync(async () =>
            {
                var state = await monitor.GetFromJsonAsync<SubscriptionState>("subsz", ct);
                return state?.NumSubscriptions >= replicas * 3;
            }, ct);

            await using var publisher = new NatsConnection(new NatsOpts { Url = natsUrl });
            var events = new List<(Guid User, string Field, string Key)>();
            foreach (var field in new[] { "role", "deactivated-at", "name", "username" })
            {
                for (var sample = 0; sample < 8; sample++)
                {
                    var user = Guid.NewGuid();
                    var key = await store.StoreAsync(Ticket(user));
                    keys.Add(key);
                    events.Add((user, field, key));
                    Assert.NotNull(await store.RetrieveAsync(key));
                }
            }
            var unaffectedUser = Guid.NewGuid();
            var unaffectedKey = await store.StoreAsync(Ticket(unaffectedUser));
            keys.Add(unaffectedKey);

            foreach (var change in events)
            {
                await publisher.PublishAsync($"skein.user.{change.User}.field.{change.Field}",
                    JsonSerializer.SerializeToUtf8Bytes(new
                    {
                        eventType = "user.field_changed", entityType = "user", entityId = change.User.ToString(),
                    }),
                    cancellationToken: ct);
            }
            await publisher.PingAsync(ct);

            // Observe the product's effect in the shared ticket store, rather than
            // asserting queue names or calling the handler directly. Every event
            // must revoke its user's ticket; unrelated tickets must survive.
            await UntilAsync(async () =>
            {
                foreach (var change in events)
                {
                    if (await store.RetrieveAsync(change.Key) is not null)
                    {
                        return false;
                    }
                }
                return true;
            }, ct);
            Assert.NotNull(await store.RetrieveAsync(unaffectedKey));
        }
        finally
        {
            using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            foreach (var subscriber in subscribers)
            {
                await subscriber.StopAsync(shutdown.Token);
            }
            foreach (var bridge in bridges)
            {
                await bridge.StopAsync(shutdown.Token);
            }
            foreach (var conn in connections)
            {
                await conn.DisposeAsync();
            }
            foreach (var key in keys)
            {
                await store.RemoveAsync(key);
            }
        }
    }

    private static AuthenticationTicket Ticket(Guid user) => new(
        new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, user.ToString())], "Cookies")),
        new AuthenticationProperties(), CookieAuthenticationDefaults.AuthenticationScheme);

    private static string Required(string name) => Environment.GetEnvironmentVariable(name)
        ?? throw new InvalidOperationException($"{name} is required");

    private static async Task UntilAsync(Func<Task<bool>> condition, CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(25));
        while (!await condition())
        {
            await timer.WaitForNextTickAsync(ct);
        }
    }

    private sealed record SubscriptionState(
        [property: System.Text.Json.Serialization.JsonPropertyName("num_subscriptions")] int NumSubscriptions);

    private sealed class InfrastructureTheoryAttribute : TheoryAttribute
    {
        public InfrastructureTheoryAttribute()
        {
            if (new[] { "TEST_NATS_URL", "TEST_REDIS_URL", "TEST_NATS_MONITOR_URL" }
                .Any(name => string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(name))))
            {
                Skip = "Requires the NATS and Redis integration harness.";
            }
        }
    }
}
