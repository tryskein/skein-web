using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using SkeinWeb.Auth;
using SkeinWeb.Hubs;
using SkeinWeb.Tests.Auth;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Hubs;

/// <summary>
/// SC-006 / INV-10: after a revocation the connections of the old key close at once on the replica
/// that revoked and on the first 30 s round of another replica, while the store answers; they stay
/// while it does not; a control session of the same user is untouched. Two replicas share a real Redis
/// (database 10); each runs the real <see cref="AccessRecheckService"/> on a fake clock with the real
/// store as its probe.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SessionRevocationAcrossReplicasIntegrationTest
{
    private const int Database = 10;
    private static readonly Guid User = Guid.Parse("0199a1b2-0000-7000-8000-00000000000a");

    private static async Task<bool> UntilAsync(Func<bool> condition)
    {
        for (var i = 0; i < 250; i++)
        {
            if (condition())
            {
                return true;
            }
            await Task.Delay(20);
        }
        return condition();
    }

    [RedisFact]
    public async Task ARevokedKey_ClosesAtOnceOnTheRevokingReplica_AndOnTheFirstRoundOfTheOther_WhileTheControlLives()
    {
        using var mux = TestRedis.Connect(Database);
        mux.GetServers().First(s => !s.IsReplica).FlushDatabase(Database);
        try
        {
            var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
            var world = new HubTestWorld();
            world.AccessApi.SetUser(User);
            using var first = new HubTestReplica(world, clock);
            using var second = new HubTestReplica(world, clock);
            var store1 = TestRedis.Store(mux);
            var secondDb = DbProxy.Create(mux.GetDatabase(Database), out var secondFaults);
            var store2 = TestRedis.Store(TestRedis.Over(mux, secondDb));

            async Task<string> NewKeyAsync() =>
                await store1.StoreAsync(TestRedis.Ticket(User), new DefaultHttpContext(), CancellationToken.None);
            var old = await NewKeyAsync();
            var control = await NewKeyAsync();
            var oldOn1 = await first.ConnectAsync(User, sessionKey: old);
            var controlOn1 = await first.ConnectAsync(User, sessionKey: control);
            var oldOn2 = await second.ConnectAsync(User, sessionKey: old);
            var controlOn2 = await second.ConnectAsync(User, sessionKey: control);

            using var service1 = new AccessRecheckService(first.Registry, first.Access, first.HubContext, first.Nats, clock,
                NullLogger<AccessRecheckService>.Instance, store1);
            using var service2 = new AccessRecheckService(second.Registry, second.Access, second.HubContext, second.Nats, clock,
                NullLogger<AccessRecheckService>.Instance, store2);
            await service1.StartAsync(CancellationToken.None);
            await service2.StartAsync(CancellationToken.None);

            // The rotation on the first replica: the row goes, its own connections close at once.
            await store1.RevokeAsync(old, new DefaultHttpContext(), CancellationToken.None);
            first.Registry.AbortSession(old);

            Assert.Contains(oldOn1, first.Aborted);
            Assert.DoesNotContain(oldOn2, second.Aborted);

            // While the store of the second replica does not answer, its connection stays.
            secondFaults.Before = (name, _) => name is nameof(IDatabase.SetContainsAsync) or nameof(IDatabase.KeyExistsAsync)
                ? new InvalidOperationException("injected") : null;
            clock.Advance(AccessRecheckService.Interval);
            await Task.Delay(300);
            Assert.DoesNotContain(oldOn2, second.Aborted);

            // The store answers again: the next round closes it.
            secondFaults.Before = null;
            clock.Advance(AccessRecheckService.Interval);
            Assert.True(await UntilAsync(() => second.Aborted.Contains(oldOn2)), "the other replica did not close the old key");

            Assert.DoesNotContain(controlOn1, first.Aborted);
            Assert.DoesNotContain(controlOn2, second.Aborted);
            Assert.True(await mux.GetDatabase(Database).KeyExistsAsync(control));
        }
        finally
        {
            mux.GetServers().First(s => !s.IsReplica).FlushDatabase(Database);
        }
    }
}
