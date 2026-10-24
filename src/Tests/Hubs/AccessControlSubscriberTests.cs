using Microsoft.Extensions.Time.Testing;
using Moq;
using SkeinWeb.Hubs;

namespace SkeinWeb.Tests.Hubs;

/// <summary>
/// Control events of <see cref="AccessControlSubscriber"/> (sk-622.21 tests
/// No. 63, control part; INV-9, US-9 revocation, US-10 membership on every
/// replica): subscriptions without a queue group, applied by every replica to
/// its own connections — membership, role demotion, deactivation (groups and
/// session tickets) and project lifecycle. Hub v2 (sk-674.18 K-15, D-10,
/// SC-015): <c>access_changed</c> takes the lost projects' groups away at once
/// on every replica and re-checks for the gained ones; project lifecycle
/// re-checks internal admins instead of signalling <c>projects</c> to all of them.
/// </summary>
/// <remarks>
/// Messages enter through the fake NATS server the replicas' subscribers
/// were started on; skein-api's access answers come from
/// <see cref="FakeAccessApi"/>, whose state the test changes as the real
/// database would change before the event is published.
/// </remarks>
public class AccessControlSubscriberTests
{
    private static readonly Guid Alice = Guid.Parse("0199a1b2-0000-7000-8000-000000000001");
    private static readonly Guid Bob = Guid.Parse("0199a1b2-0000-7000-8000-000000000002");
    private static readonly Guid Admin = Guid.Parse("0199a1b2-0000-7000-8000-000000000003");
    private static readonly Guid P = Guid.Parse("0199a1b2-0000-7000-8000-0000000000a1");
    private static readonly Guid Q = Guid.Parse("0199a1b2-0000-7000-8000-0000000000a2");
    private static readonly Guid NewProject = Guid.Parse("0199a1b2-0000-7000-8000-0000000000a3");
    private static readonly Guid AlicePersonal = Guid.Parse("0199a1b2-0000-7000-8000-0000000000b1");

    private static async Task<(HubTestWorld World, FakeTimeProvider Clock, HubTestReplica R1, HubTestReplica R2)> TwoReplicas()
    {
        var world = new HubTestWorld();
        world.AccessApi.SetUser(Alice, memberOf: [P, Q]);
        world.AccessApi.SetUser(Bob);
        world.AccessApi.SetUser(Admin, internalAdmin: true);
        var clock = new FakeTimeProvider(DateTimeOffset.Parse("2026-10-09T10:00:00Z"));
        var r1 = new HubTestReplica(world, clock);
        var r2 = new HubTestReplica(world, clock);
        await r1.StartAsync(5, r1.Control);
        await r2.StartAsync(5, r2.Control);
        return (world, clock, r1, r2);
    }

    private static object MemberEvent(string type, Guid user) => new
    {
        id = 1,
        occurredAt = "2026-10-09T10:00:00Z",
        eventType = $"project.{type}",
        entityType = "project",
        entityId = P.ToString(),
        projectId = P,
        newData = type == "member_removed" ? null : new { userId = user, role = "member" },
        oldData = type == "member_removed" ? new { userId = user, role = "member" } : null,
    };

    private static async Task Publish(HubTestWorld world, string subject, object body)
    {
        world.Nats.Publish(subject, body);
        await world.Nats.DrainAsync();
    }

    [Fact]
    public async Task ControlSubscriptions_HaveNoQueueGroup()
    {
        var (world, _, r1, r2) = await TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;

        Assert.Equal(10, world.Nats.Subscriptions.Count);
        Assert.All(world.Nats.Subscriptions, s => Assert.Null(s.QueueGroup));
        Assert.Equal(
            new[]
            {
                "skein.events.project.*.project.>", "skein.user.*.access_changed", "skein.user.*.deactivated",
                "skein.user.*.field.role", "skein.user.*.reactivated",
            },
            world.Nats.Subscriptions.Select(s => s.Subject).Distinct().OrderBy(x => x, StringComparer.Ordinal));
    }

    [Fact]
    public async Task MemberRemoved_TakesTheUsersConnectionsOutOfTheProject_OnBothReplicas()
    {
        var (world, _, r1, r2) = await TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;
        var onR1 = await r1.ConnectAsync(Alice);
        var onR2 = await r2.ConnectAsync(Alice);
        await r1.DeclareAsync(onR1, P);
        await r2.DeclareAsync(onR2, P);

        world.AccessApi.RemoveMembership(Alice, P);
        await Publish(world, $"skein.events.project.{P}.project.member_removed.{P}", MemberEvent("member_removed", Alice));

        Assert.DoesNotContain($"project:{P}", world.GroupsOf(onR1));
        Assert.DoesNotContain($"project:{P}", world.GroupsOf(onR2));
        await r1.DispatchAsync($"skein.events.project.{P}.issue.created.sk-9", new
        {
            id = 9, occurredAt = "2026-10-09T10:00:00Z", eventType = "issue.created",
            entityType = "issue", entityId = "sk-9", projectId = P,
        });
        Assert.Empty(world.DeliveriesTo(onR1, BrowserClientMethods.Event));
        Assert.Empty(world.DeliveriesTo(onR2, BrowserClientMethods.Event));
    }

    [Fact]
    public async Task MemberAdded_AdmitsTheDeclaredProject()
    {
        var (world, _, r1, r2) = await TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;
        var bob = await r2.ConnectAsync(Bob);
        var denied = await r2.DeclareAsync(bob, P);
        Assert.Equal("no_access", Assert.Single(denied.Rejected).Reason);

        world.AccessApi.SetUser(Bob, memberOf: P);
        await Publish(world, $"skein.events.project.{P}.project.member_added.{P}", MemberEvent("member_added", Bob));

        Assert.Contains($"project:{P}", world.GroupsOf(bob));
    }

    private static object AccessChanged(Guid[] lost, Guid[] gained) => new
    {
        lostProjectIds = lost,
        gainedProjectIds = gained,
        lostSpaceIds = Array.Empty<string>(),
        sentAt = "2026-10-12T10:15:03Z",
    };

    [Fact]
    public async Task AccessChangedLost_LeavesOnlyTheLostProjectGroup_OnBothReplicas_WithoutAnyAccessAnswer()
    {
        // Row 219 (SC-015, D-10): skein-api is held — no re-check can answer, the
        // re-check clock never moves; the event alone must take P away.
        var (world, _, r1, r2) = await TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;
        var onR1 = await r1.ConnectAsync(Alice);
        var onR2 = await r2.ConnectAsync(Alice);
        await r1.DeclareAsync(onR1, P, Q);
        await r2.DeclareAsync(onR2, P, Q);
        world.AccessApi.RemoveMembership(Alice, P);
        world.AccessApi.HoldCalls = true;

        // Not drained: the handler goes on to the re-check, which is held.
        world.Nats.Publish($"skein.user.{Alice}.access_changed", AccessChanged(lost: [P], gained: []));
        try
        {
            await Task.WhenAll(
                WaitLeft(world, onR1, $"project:{P}"),
                WaitLeft(world, onR2, $"project:{P}"));

            Assert.Contains($"project:{Q}", world.GroupsOf(onR1));
            Assert.Contains($"project:{Q}", world.GroupsOf(onR2));
        }
        finally
        {
            world.AccessApi.ReleaseHeld();
            await world.Nats.DrainAsync();
        }
    }

    [Fact]
    public async Task AccessChangedOfAnotherUser_IsAppliedAtOnce_WhileTheFirstUsersRecheckIsHeld()
    {
        // Review W-3 C1 (SC-015, US-19): the re-check queued by the first event
        // hangs on skein-api; the second event — another user — must still take
        // its lost project away on both replicas before skein-api answers.
        var (world, _, r1, r2) = await TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;
        world.AccessApi.SetUser(Bob, memberOf: [P, Q]);
        var alice = await r1.ConnectAsync(Alice);
        var bobOnR1 = await r1.ConnectAsync(Bob);
        var bobOnR2 = await r2.ConnectAsync(Bob);
        await r1.DeclareAsync(alice, P, Q);
        await r1.DeclareAsync(bobOnR1, P, Q);
        await r2.DeclareAsync(bobOnR2, P, Q);
        world.AccessApi.HoldCalls = true;

        world.AccessApi.RemoveMembership(Alice, P);
        world.Nats.Publish($"skein.user.{Alice}.access_changed", AccessChanged(lost: [P], gained: []));
        await Eventually(() => world.AccessApi.Held >= 1, "Alice's re-check held on skein-api");
        world.AccessApi.RemoveMembership(Bob, Q);
        world.Nats.Publish($"skein.user.{Bob}.access_changed", AccessChanged(lost: [Q], gained: []));
        try
        {
            await Task.WhenAll(
                WaitLeft(world, bobOnR1, $"project:{Q}"),
                WaitLeft(world, bobOnR2, $"project:{Q}"));
            Assert.Contains($"project:{P}", world.GroupsOf(bobOnR1));
        }
        finally
        {
            world.AccessApi.ReleaseHeld();
            await world.Nats.DrainAsync();
        }
    }

    private static async Task Eventually(Func<bool> condition, string what)
    {
        for (var i = 0; i < 2000 && !condition(); i++)
        {
            await Task.Delay(5);
        }
        Assert.True(condition(), "not reached: " + what);
    }

    private static async Task WaitLeft(HubTestWorld world, string connectionId, string group)
    {
        for (var i = 0; i < 2000 && world.GroupsOf(connectionId).Contains(group); i++)
        {
            await Task.Delay(5);
        }
        Assert.DoesNotContain(group, world.GroupsOf(connectionId));
    }

    [Fact]
    public async Task AccessChangedGained_RechecksAndAdmitsTheDeclaredProject()
    {
        // Row 219: gained → the user is re-checked against skein-api.
        var (world, _, r1, r2) = await TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;
        var bob = await r2.ConnectAsync(Bob);
        Assert.Equal("no_access", Assert.Single((await r2.DeclareAsync(bob, P)).Rejected).Reason);
        var calls = world.AccessApi.Calls;

        world.AccessApi.SetUser(Bob, memberOf: P);
        await Publish(world, $"skein.user.{Bob}.access_changed", AccessChanged(lost: [], gained: [P]));

        // The re-check runs on the subscriber's worker, after the event loop.
        await Eventually(() => world.GroupsOf(bob).Contains($"project:{P}"), "Bob admitted to P");
        Assert.True(world.AccessApi.Calls > calls, "no re-check after gained");
    }

    [Fact]
    public async Task RoleDemotion_DropsTheAdminsVisibleSetAndAdminsInternal()
    {
        var (world, _, r1, r2) = await TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;
        var admin = await r1.ConnectAsync(Admin, role: "admin");
        await r1.DeclareAllVisibleAsync(admin, true);
        // As an admin it sees P (not personal) without being a member.
        Assert.Contains($"project:{P}", world.GroupsOf(admin));
        Assert.Contains("admins:internal", world.GroupsOf(admin));

        world.AccessApi.SetInternalAdmin(Admin, false);
        await Publish(world, $"skein.user.{Admin}.field.role", new
        {
            id = 2, occurredAt = "2026-10-09T10:00:00Z", eventType = "user.field_changed",
            entityType = "user", entityId = Admin.ToString(),
        });

        Assert.DoesNotContain($"project:{P}", world.GroupsOf(admin));
        Assert.DoesNotContain("admins:internal", world.GroupsOf(admin));
    }

    [Fact]
    public async Task Deactivated_DropsEveryGroupAndTheTickets_OnEveryReplicaWithoutError()
    {
        var (world, _, r1, r2) = await TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;
        var admin = await r1.ConnectAsync(Admin, role: "admin");
        await r1.DeclareAsync(admin, P);
        Assert.NotEmpty(world.GroupsOf(admin));

        world.AccessApi.Deactivate(Admin);
        await Publish(world, $"skein.user.{Admin}.deactivated", new
        {
            id = 3, occurredAt = "2026-10-09T10:00:00Z", eventType = "user.deactivated",
            entityType = "user", entityId = Admin.ToString(),
        });

        Assert.Empty(world.GroupsOf(admin));
        // Both replicas received the event; each removed the tickets — idempotent.
        r1.Sessions.Verify(s => s.RemoveByUserIdAsync(Admin, It.IsAny<CancellationToken>()), Times.Once);
        r2.Sessions.Verify(s => s.RemoveByUserIdAsync(Admin, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ProjectCreated_RechecksInternalAdmins_InsteadOfAProjectsSignal()
    {
        // Row 229 (K-15): the admin in "all visible" joins a new non-personal
        // project through the re-check; nobody gets a projects signal; a new
        // project of another user's personal space stays out.
        var (world, clock, r1, r2) = await TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;
        var admin = await r1.ConnectAsync(Admin, role: "admin");
        await r1.DeclareAllVisibleAsync(admin, true);
        var alice = await r2.ConnectAsync(Alice);
        world.AccessApi.SetProject(NewProject);
        world.AccessApi.SetProject(AlicePersonal, personalOwner: Alice);

        foreach (var created in new[] { NewProject, AlicePersonal })
        {
            await Publish(world, $"skein.events.project.{created}.project.created.{created}", new
            {
                id = 4, occurredAt = "2026-10-09T10:00:00Z", eventType = "project.created",
                entityType = "project", entityId = created.ToString(), projectId = created,
            });
        }
        clock.Advance(PersonalSignalOptions.DefaultWindow);

        Assert.Contains($"project:{NewProject}", world.GroupsOf(admin));
        Assert.DoesNotContain($"project:{AlicePersonal}", world.GroupsOf(admin));
        Assert.Empty(world.DeliveriesTo(admin, BrowserClientMethods.Signal));
        Assert.Empty(world.DeliveriesTo(alice, BrowserClientMethods.Signal));
    }
}
