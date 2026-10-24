using System.Net;
using Microsoft.Extensions.Time.Testing;
using SkeinWeb.Auth;
using SkeinWeb.Hubs;

namespace SkeinWeb.Tests.Hubs;

/// <summary>
/// Periodic re-check of <see cref="AccessRecheckService"/> (sk-622.21 tests
/// No. 63, re-check part; INV-9, SC-014, edge 10): a lost <c>member_removed</c>
/// is applied by the 30 s re-check; with skein-api failing, access
/// unconfirmed for 60 s takes the connection out of every project group and
/// the first successful check puts it back; after a NATS reconnect project
/// events wait for the re-check; batches respect the T028 budget of 4,000
/// entries per call.
/// </summary>
/// <remarks>
/// The service runs on a <see cref="FakeTimeProvider"/> (its timer and the
/// access client's call budget). Its runs are asynchronous, so outcomes are
/// awaited with <see cref="Eventually"/> — a synchronisation wait on observable
/// state, not a timing assertion. The access client's retry pauses (Polly) run
/// on real time; a failing check therefore takes about 1.4 s of wall time.
/// </remarks>
public class AccessRecheckServiceTests
{
    private static readonly Guid Alice = Guid.Parse("0199a1b2-0000-7000-8000-000000000001");
    private static readonly Guid P = Guid.Parse("0199a1b2-0000-7000-8000-0000000000a1");
    private static readonly TimeSpan Period = TimeSpan.FromSeconds(30);

    private static async Task<(HubTestWorld World, FakeTimeProvider Clock, HubTestReplica Replica, string Conn)> AliceDeclaredP()
    {
        var world = new HubTestWorld();
        world.AccessApi.SetUser(Alice, memberOf: P);
        var clock = new FakeTimeProvider(DateTimeOffset.Parse("2026-10-09T10:00:00Z"));
        var replica = new HubTestReplica(world, clock);
        await replica.StartAsync(0, replica.Recheck);
        var conn = await replica.ConnectAsync(Alice);
        await replica.DeclareAsync(conn, P);
        Assert.Contains($"project:{P}", world.GroupsOf(conn));
        return (world, clock, replica, conn);
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

    [Fact]
    public async Task LostMemberRemoved_PeriodicRecheckRevokesWithin30Seconds()
    {
        var (world, clock, replica, conn) = await AliceDeclaredP();
        using var _r = replica;
        var callsBefore = world.AccessApi.Calls;

        world.AccessApi.RemoveMembership(Alice, P); // the control event is lost
        clock.Advance(Period - TimeSpan.FromSeconds(1));
        Assert.Equal(callsBefore, world.AccessApi.Calls);
        Assert.Contains($"project:{P}", world.GroupsOf(conn));

        clock.Advance(TimeSpan.FromSeconds(1));

        await Eventually(() => !world.GroupsOf(conn).Contains($"project:{P}"), "connection out of project:P");
    }

    [Fact]
    public async Task SkeinApiFailing_60sUnconfirmed_OutOfAllProjectGroups_FirstSuccessRestores()
    {
        var (world, clock, replica, conn) = await AliceDeclaredP();
        using var _r = replica;
        world.AccessApi.FailWith = HttpStatusCode.InternalServerError;

        // t = 30 s: the check fails (1 + 3 retries); 30 s unconfirmed is still tolerated.
        var calls = world.AccessApi.Calls;
        clock.Advance(Period);
        await Eventually(() => world.AccessApi.Calls == calls + 4, "first failing check");
        await Task.Delay(50);
        Assert.Contains($"project:{P}", world.GroupsOf(conn));

        // t = 60 s: unconfirmed for 60 s → fail-closed.
        calls = world.AccessApi.Calls;
        clock.Advance(Period);
        await Eventually(() => world.GroupsOf(conn).Count(g => g.StartsWith("project", StringComparison.Ordinal)) == 0,
            "connection out of every project group");
        await Eventually(() => world.AccessApi.Calls == calls + 4, "second failing check finished");

        // t = 90 s: skein-api answers again → back into the declared, still allowed group.
        world.AccessApi.FailWith = null;
        clock.Advance(Period);
        await Eventually(() => world.GroupsOf(conn).Contains($"project:{P}"), "connection back in project:P");
    }

    [Fact]
    public async Task SkeinApiHanging_OutOfProjectGroupsAtTheDeadline_WhileTheCheckStillHangs()
    {
        // INV-9, SC-014: not later than 60 s after the last confirmation, even
        // while the re-check call is still waiting on skein-api. Confirmation at
        // t = 10 s puts the deadline (t = 70 s) inside the call started at
        // t = 60 s, which hangs until its 15 s budget (t = 75 s).
        var world = new HubTestWorld();
        world.AccessApi.SetUser(Alice, memberOf: P);
        var clock = new FakeTimeProvider(DateTimeOffset.Parse("2026-10-09T10:00:00Z"));
        using var replica = new HubTestReplica(world, clock);
        await replica.StartAsync(0, replica.Recheck);
        var conn = await replica.ConnectAsync(Alice);
        clock.Advance(TimeSpan.FromSeconds(10));
        await replica.DeclareAsync(conn, P);
        world.AccessApi.HoldCalls = true;

        clock.Advance(TimeSpan.FromSeconds(20));                            // t = 30: check hangs
        await Eventually(() => world.AccessApi.Held == 1, "check at t=30 waiting on skein-api");
        clock.Advance(SkeinServiceApiClient.CallBudget);                    // t = 45: budget ends it
        await Eventually(() => world.AccessApi.Held == 0, "check at t=30 timed out");
        Assert.Contains($"project:{P}", world.GroupsOf(conn));               // 35 s unconfirmed
        clock.Advance(TimeSpan.FromSeconds(15));                            // t = 60: next check hangs
        await Eventually(() => world.AccessApi.Held == 1, "check at t=60 waiting on skein-api");
        Assert.Contains($"project:{P}", world.GroupsOf(conn));               // 50 s unconfirmed

        clock.Advance(TimeSpan.FromSeconds(10));                            // t = 70: deadline

        await Eventually(() => !world.GroupsOf(conn).Any(g => g.StartsWith("project", StringComparison.Ordinal)),
            "connection out of every project group at the deadline");
        Assert.Equal(1, world.AccessApi.Held);
    }

    [Fact]
    public async Task SkeinApiHanging_ConnectionsOfEveryBatchOutOfProjectGroupsAtTheDeadline()
    {
        // 4,001 connections → two batches (T028 budget). Both calls hang until
        // their budget; the second batch starts only after the first ended.
        // Every connection, of either batch, is out of its groups at t = 60 s.
        var world = new HubTestWorld();
        world.AccessApi.SetUser(Alice, memberOf: P);
        var clock = new FakeTimeProvider(DateTimeOffset.Parse("2026-10-09T10:00:00Z"));
        using var replica = new HubTestReplica(world, clock);
        await replica.StartAsync(0, replica.Recheck);
        var conns = new List<string>();
        for (var i = 0; i < SkeinServiceApiClient.MaxQueriesPerCall + 1; i++)
        {
            var conn = await replica.ConnectAsync(Alice);
            await replica.DeclareAsync(conn, P);
            conns.Add(conn);
        }
        world.AccessApi.HoldCalls = true;

        clock.Advance(Period);                                              // t = 30: batch 1 hangs
        await Eventually(() => world.AccessApi.Held == 1, "batch 1 waiting on skein-api");
        var calls = world.AccessApi.Calls;
        clock.Advance(SkeinServiceApiClient.CallBudget);                    // t = 45: batch 2 hangs
        await Eventually(() => world.AccessApi.Calls == calls + 1 && world.AccessApi.Held == 1,
            "batch 2 waiting on skein-api");

        clock.Advance(TimeSpan.FromSeconds(15));                            // t = 60: deadline

        await Eventually(() => conns.All(c => !world.GroupsOf(c).Contains($"project:{P}")),
            "every connection out of project:P at the deadline");
    }

    [Fact]
    public async Task GateHeldByOneConnection_DoesNotDelayAnotherConnectionsDeadline()
    {
        // INV-9, SC-014: A's gate is held the
        // way the hub holds it during A's own declaration (R20 accepts the delay
        // for A only). B, confirmed 10 s later, must still leave its project
        // groups at its own deadline (t = 70 s), not when A's gate is released.
        // Red if the next deadline is armed only after waiting on A's gate.
        var world = new HubTestWorld();
        world.AccessApi.SetUser(Alice, memberOf: P);
        var clock = new FakeTimeProvider(DateTimeOffset.Parse("2026-10-09T10:00:00Z"));
        using var replica = new HubTestReplica(world, clock);
        await replica.StartAsync(0, replica.Recheck);
        var connA = await replica.ConnectAsync(Alice);
        await replica.DeclareAsync(connA, P);                               // A confirmed at t = 0
        clock.Advance(TimeSpan.FromSeconds(10));
        var connB = await replica.ConnectAsync(Alice);
        await replica.DeclareAsync(connB, P);                               // B confirmed at t = 10
        world.AccessApi.HoldCalls = true;                                    // no re-check confirms anyone
        var gateA = replica.Registry.Get(connA)!.Gate;
        await gateA.WaitAsync();
        try
        {
            clock.Advance(TimeSpan.FromSeconds(50));                        // t = 60: A expired, its gate held
            Assert.Contains($"project:{P}", world.GroupsOf(connA));
            Assert.Contains($"project:{P}", world.GroupsOf(connB));          // B: 50 s unconfirmed

            clock.Advance(TimeSpan.FromSeconds(10));                        // t = 70: B's deadline

            await Eventually(() => !world.GroupsOf(connB).Contains($"project:{P}"),
                "B out of project:P at its own deadline while A's gate is still held");
        }
        finally
        {
            gateA.Release();
        }
        await Eventually(() => !world.GroupsOf(connA).Contains($"project:{P}"),
            "A out of project:P once its gate is released");
    }

    [Fact]
    public async Task AfterNatsReconnect_ProjectEventsWaitForTheRecheck()
    {
        var (world, _, replica, conn) = await AliceDeclaredP();
        using var _r = replica;

        FakeNats.RaiseDisconnected(replica.Nats);
        world.AccessApi.RemoveMembership(Alice, P); // lost while the bus was down
        var dispatch = replica.DispatchAsync($"skein.events.project.{P}.issue.created.sk-5", new
        {
            id = 5, occurredAt = "2026-10-09T10:00:00Z", eventType = "issue.created",
            entityType = "issue", entityId = "sk-5", projectId = P,
        });
        await Task.Delay(50);
        Assert.False(dispatch.IsCompleted, "a project event must wait for the post-reconnect re-check");

        FakeNats.RaiseOpened(replica.Nats);
        await dispatch.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.DoesNotContain($"project:{P}", world.GroupsOf(conn));
        Assert.Empty(world.DeliveriesTo(conn, BrowserClientMethods.Event));
    }

    [Fact]
    public async Task FullRecheck_SplitsIntoBatchesOfAtMost4000()
    {
        var world = new HubTestWorld();
        world.AccessApi.SetUser(Alice, memberOf: P);
        using var replica = new HubTestReplica(world, new FakeTimeProvider());
        for (var i = 0; i < 4001; i++)
        {
            await replica.ConnectAsync(Alice);
        }

        await replica.Recheck.RecheckAllAsync("recheck");

        Assert.Equal(new[] { 4000, 1 }, world.AccessApi.BatchSizes);
    }

    [Fact]
    public async Task Client_RefusesABatchOverTheBudget_BeforeSending()
    {
        var world = new HubTestWorld();
        using var replica = new HubTestReplica(world, new FakeTimeProvider());
        var queries = Enumerable.Range(0, 4001).Select(_ => new ProjectAccessQuery(Alice)).ToArray();

        await Assert.ThrowsAsync<ArgumentException>(() => replica.Access.CheckProjectAccessAsync(queries, CancellationToken.None));
        Assert.Equal(0, world.AccessApi.Calls);
    }
}
