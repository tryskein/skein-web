using System.Net;
using Microsoft.Extensions.Time.Testing;
using Moq;
using SkeinWeb.Hubs;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Hubs;

/// <summary>
/// The <c>resync</c> frame of <see cref="TransportHealthMonitor"/> (sk-622.21
/// tests No. 64; SC-016, INV-10, US-10 guarantee boundary): after a NATS break the
/// replica's own connections; after a backplane break its own connections and
/// the groups/users whose sends failed meanwhile; no break — no frame. The
/// dropped-sends metric grows by the number of failed sends.
/// </summary>
/// <remarks>
/// Transport events are raised on a fake NATS connection and a mocked
/// backplane multiplexer — the boundaries; the monitor, bridge, registry and
/// access re-check are the production types. A failing backplane is
/// <see cref="HubTestWorld.FailSends"/>.
/// </remarks>
public class TransportHealthMonitorTests
{
    private static readonly Guid Alice = Guid.Parse("0199a1b2-0000-7000-8000-000000000001");
    private static readonly Guid Bob = Guid.Parse("0199a1b2-0000-7000-8000-000000000002");
    private static readonly Guid Carol = Guid.Parse("0199a1b2-0000-7000-8000-000000000003");
    private static readonly Guid P = Guid.Parse("0199a1b2-0000-7000-8000-0000000000a1");

    private static async Task<(HubTestWorld World, HubTestReplica R1, HubTestReplica R2)> TwoReplicas()
    {
        var world = new HubTestWorld();
        world.AccessApi.SetUser(Alice, memberOf: P);
        world.AccessApi.SetUser(Bob, memberOf: P);
        world.AccessApi.SetUser(Carol);
        var clock = new FakeTimeProvider(DateTimeOffset.Parse("2026-10-09T10:00:00Z"));
        var r1 = new HubTestReplica(world, clock);
        var r2 = new HubTestReplica(world, clock);
        await r1.StartAsync(0, r1.Recheck, r1.Monitor);
        await r2.StartAsync(0, r2.Recheck, r2.Monitor);
        return (world, r1, r2);
    }

    private static async Task Eventually(Func<bool> condition, string what)
    {
        for (var i = 0; i < 2000; i++)
        {
            if (condition())
            {
                return;
            }
            await Task.Delay(5);
        }
        Assert.Fail("not reached: " + what);
    }

    private static int Resyncs(HubTestWorld world, string conn) =>
        world.DeliveriesTo(conn, BrowserClientMethods.Resync).Count;

    private static Mock<IConnectionMultiplexer> AttachBackplane(HubTestReplica replica)
    {
        var multiplexer = new Mock<IConnectionMultiplexer>();
        replica.Backplane.Publish(multiplexer.Object);
        return multiplexer;
    }

    private static void BackplaneFailed(Mock<IConnectionMultiplexer> multiplexer) =>
        multiplexer.Raise(m => m.ConnectionFailed += null, multiplexer.Object, new ConnectionFailedEventArgs(
            multiplexer.Object, new DnsEndPoint("redis", 6379), ConnectionType.Subscription,
            ConnectionFailureType.SocketFailure, new IOException("reset"), "redis:6379"));

    private static void BackplaneRestored(Mock<IConnectionMultiplexer> multiplexer) =>
        multiplexer.Raise(m => m.ConnectionRestored += null, multiplexer.Object, new ConnectionFailedEventArgs(
            multiplexer.Object, new DnsEndPoint("redis", 6379), ConnectionType.Subscription,
            ConnectionFailureType.None, null!, "redis:6379"));

    [Fact]
    public async Task NatsBreakAndRestore_ResyncToEveryConnectionOfThisReplica_OnlyThisReplica()
    {
        var (world, r1, r2) = await TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;
        var a = await r1.ConnectAsync(Alice);
        var c = await r1.ConnectAsync(Carol); // declared nothing — still gets it
        var b = await r2.ConnectAsync(Bob);

        FakeNats.RaiseDisconnected(r1.Nats);
        FakeNats.RaiseOpened(r1.Nats);

        await Eventually(() => Resyncs(world, a) == 1 && Resyncs(world, c) == 1, "resync on replica 1");
        await Task.Delay(50);
        Assert.Equal(1, Resyncs(world, a));
        Assert.Equal(0, Resyncs(world, b));
    }

    [Fact]
    public async Task BackplaneBreakAndRestore_ResyncToOwnConnectionsAndFailedAddressees()
    {
        var (world, r1, r2) = await TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;
        var multiplexer = AttachBackplane(r1);
        var onR1 = await r1.ConnectAsync(Carol);
        var bobOnR2 = await r2.ConnectAsync(Bob);
        await r2.DeclareAsync(bobOnR2, P);
        var aliceOnR2 = await r2.ConnectAsync(Alice);
        var before = HubMetrics.BridgeSendsFailed.Value;

        BackplaneFailed(multiplexer);
        world.FailSends = true;
        await r1.DispatchAsync($"skein.events.project.{P}.issue.created.sk-1", new
        {
            id = 1, occurredAt = "2026-10-09T10:00:00Z", eventType = "issue.created",
            entityType = "issue", entityId = "sk-1", projectId = P,
        });
        await r1.DispatchAsync($"skein.user.{Alice}.reminder", new
        {
            reminderId = "0199a1b2-0000-7000-8000-0000000000f1", issueId = "sk-1", projectId = P,
            kind = "rang", remindAt = "2026-10-09T10:00:00Z",
            firingId = "0199a1b2-0000-7000-8000-0000000000f1@2026-10-09T10:00:00Z",
        });
        Assert.Equal(2, HubMetrics.BridgeSendsFailed.Value - before);

        world.FailSends = false;
        BackplaneRestored(multiplexer);

        await Eventually(
            () => Resyncs(world, onR1) == 1 && Resyncs(world, bobOnR2) == 1 && Resyncs(world, aliceOnR2) == 1,
            "resync to own connection, failed group and failed user");
    }

    [Theory]
    [InlineData("notification")]
    [InlineData("theme.preview")]
    [InlineData("theme.updated")]
    public async Task BackplaneBreak_FailedNotificationOrThemeSend_AddresseeOnOtherReplicaGetsResync(string kind)
    {
        var (world, r1, r2) = await TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;
        var multiplexer = AttachBackplane(r1);
        var bobOnR2 = await r2.ConnectAsync(Bob);
        var aliceOnR2 = await r2.ConnectAsync(Alice); // not an addressee of any of these sends

        BackplaneFailed(multiplexer);
        world.FailSends = true;
        switch (kind)
        {
            case "notification":
                await r1.DispatchAsync($"skein.user.{Bob}.notification", new
                {
                    notificationId = 42, userId = Bob, eventId = 100, eventType = "comment.created",
                    projectId = P, createdAt = "2026-10-09T10:00:00Z",
                });
                break;
            case "theme.preview":
                await r1.DispatchAsync($"skein.user.{Bob}.theme.preview", new { userId = Bob, variables = new { } });
                break;
            default:
                // Row 230b (K-31): the author's personal subject, not a broadcast.
                await r1.DispatchAsync($"skein.user.{Bob}.theme.updated",
                    new { themeId = "0199a1b2-0000-7000-8000-0000000000e1", variables = new { } });
                break;
        }
        world.FailSends = false;
        BackplaneRestored(multiplexer);

        await Eventually(() => Resyncs(world, bobOnR2) == 1, "resync to the addressee of the failed " + kind);
        // The restore sends the failed groups' resyncs before the failed users'
        // in one pass: once Bob's is there, a resync to a broadcast group would be too.
        Assert.Equal(0, Resyncs(world, aliceOnR2));
    }

    [Fact]
    public async Task FailedSendWithoutConnectionFailed_AddresseeGetsResyncOnRestore()
    {
        // The multiplexer may fail a publish without raising ConnectionFailed;
        // the failed addressee must not wait for a break that is never reported.
        var (world, r1, r2) = await TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;
        var multiplexer = AttachBackplane(r1);
        var bobOnR2 = await r2.ConnectAsync(Bob);

        world.FailSends = true;
        await r1.DispatchAsync($"skein.user.{Bob}.theme.preview", new { userId = Bob, variables = new { } });
        world.FailSends = false;
        BackplaneRestored(multiplexer);

        await Eventually(() => Resyncs(world, bobOnR2) == 1, "resync to the addressee of the failed send");
    }

    [Fact]
    public async Task NoBreak_NoResync_OnlyTheRealBreakResyncs()
    {
        // Positive form: the events without a break come first, then one real
        // break. Once the real break's resync has arrived, the connection holds
        // exactly one — none came from the events without a break.
        var (world, r1, _) = await TwoReplicas();
        using var _1 = r1;
        var multiplexer = AttachBackplane(r1);
        var a = await r1.ConnectAsync(Alice);

        FakeNats.RaiseOpened(r1.Nats);         // first connect, no prior break
        BackplaneRestored(multiplexer);        // restore without a failure
        FakeNats.RaiseDisconnected(r1.Nats);   // the one real break
        FakeNats.RaiseOpened(r1.Nats);

        await Eventually(() => Resyncs(world, a) >= 1, "resync after the real break");
        Assert.Equal(1, Resyncs(world, a));
    }
}
