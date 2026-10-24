using Microsoft.Extensions.Time.Testing;
using SkeinWeb.Hubs;

namespace SkeinWeb.Tests.Hubs;

/// <summary>
/// Per-user index of <see cref="ConnectionRegistry"/> (sk-622.21 US-11, K10):
/// a connection registered while the same user's last connection is being
/// removed stays findable by user — the personal signal reaches it. Review of
/// wave skein-web/2: the removal dropped the user's bucket after a concurrent
/// registration had put the new connection into it.
/// </summary>
/// <remarks>
/// The two calls are released together by a <see cref="Barrier"/> — the test's
/// synchronisation point — once per round, over many rounds: the window lies
/// inside <see cref="ConnectionRegistry.Remove"/>, which offers no hook, so the
/// interleaving is reached by repetition rather than forced. A round passes
/// only if, whichever order the calls took, the new connection is the user's
/// one connection.
/// </remarks>
public class ConnectionRegistryTests
{
    private const int Rounds = 2000;

    [Fact]
    public async Task LastDisconnectRacingNewConnect_TheNewConnectionStaysTheUsersAndGetsPersonalSignals()
    {
        var world = new HubTestWorld();
        var clock = new FakeTimeProvider(DateTimeOffset.Parse("2026-10-09T10:00:00Z"));
        using var replica = new HubTestReplica(world, clock);
        var users = new Guid[Rounds];

        for (var i = 0; i < Rounds; i++)
        {
            var user = users[i] = Guid.NewGuid();
            var old = $"old-{i}";
            var fresh = $"new-{i}";
            world.AddConnection(old, user);
            world.AddConnection(fresh, user);
            replica.Registry.Add(new ConnectionState(old, user, isExternal: false, isInternalAdmin: false));

            using var start = new Barrier(2);
            var disconnect = Task.Run(() =>
            {
                start.SignalAndWait();
                replica.Registry.Remove(old);
            });
            var connect = Task.Run(() =>
            {
                start.SignalAndWait();
                replica.Registry.Add(new ConnectionState(fresh, user, isExternal: false, isInternalAdmin: false));
            });
            await Task.WhenAll(disconnect, connect);
            world.RemoveConnection(old);

            var conns = replica.Registry.ConnectionsOf(user);
            Assert.True(conns.Count == 1 && conns[0].ConnectionId == fresh,
                $"round {i}: ConnectionsOf lost the new connection (has {conns.Count})");
        }

        foreach (var user in users)
        {
            replica.Coalescer.SignalUser(user, [PersonalSignalArea.Inbox]);
        }
        clock.Advance(replica.SignalOptions.Window);

        for (var i = 0; i < Rounds; i++)
        {
            Assert.Single(world.DeliveriesTo($"new-{i}", BrowserClientMethods.Signal));
        }
    }
}
