using Microsoft.Extensions.Time.Testing;
using SkeinWeb.Hubs;

namespace SkeinWeb.Tests.Hubs;

/// <summary>
/// Addressed delivery of <see cref="NatsBridge"/> (sk-622.21 tests No. 61;
/// SC-005, US-9, US-10, INV-10): project events go to the groups of the
/// project and "all visible" only; with two replicas over one fake backplane
/// an event taken by either replica reaches connections on both; user events,
/// deactivation, reminder frames and theme messages reach their addressees;
/// the queue-group loop leaves personal signals alone. Hub v2 (sk-674.18
/// K-15, K-31, SC-005): no group of all projects; the admins' channel carries
/// user-entity events only; an event of another user's personal space reaches
/// the admin on no channel; a theme change goes to its author only.
/// </summary>
/// <remarks>
/// Two "replicas" are two <see cref="HubTestReplica"/> — each with its own
/// connection registry, hub instances and bridge — over one
/// <see cref="HubTestWorld"/> that resolves groups and users across both at
/// send time, as the Redis backplane does (tests-rationale No. 61). A bridge
/// that picked recipients from its own replica's state would miss the
/// connections of the other.
/// </remarks>
public class NatsBridgeProjectDeliveryTests
{
    private static readonly Guid Alice = Guid.Parse("0199a1b2-0000-7000-8000-000000000001");
    private static readonly Guid Bob = Guid.Parse("0199a1b2-0000-7000-8000-000000000002");
    private static readonly Guid Admin = Guid.Parse("0199a1b2-0000-7000-8000-000000000003");
    private static readonly Guid ExternalAdmin = Guid.Parse("0199a1b2-0000-7000-8000-000000000004");
    private static readonly Guid P = Guid.Parse("0199a1b2-0000-7000-8000-0000000000a1");
    private static readonly Guid Q = Guid.Parse("0199a1b2-0000-7000-8000-0000000000a2");
    private static readonly Guid AlicePersonal = Guid.Parse("0199a1b2-0000-7000-8000-0000000000b1");

    private static (HubTestWorld World, HubTestReplica R1, HubTestReplica R2) TwoReplicas()
    {
        var world = new HubTestWorld();
        world.AccessApi.SetUser(Alice, memberOf: [P, Q]);
        world.AccessApi.SetUser(Bob, memberOf: [P, Q]);
        world.AccessApi.SetUser(Admin, internalAdmin: true);
        world.AccessApi.SetUser(ExternalAdmin, internalAdmin: true, external: true);
        var clock = new FakeTimeProvider(DateTimeOffset.Parse("2026-10-09T10:00:00Z"));
        return (world, new HubTestReplica(world, clock), new HubTestReplica(world, clock));
    }

    private static object IssueEvent(long id, Guid project) => new
    {
        id,
        occurredAt = "2026-10-09T10:00:00Z",
        eventType = "issue.updated",
        entityType = "issue",
        entityId = "sk-1",
        projectId = project,
        payload = new { changes = new[] { new { field = "status" } } },
    };

    [Fact]
    public async Task ProjectEvent_GoesOnlyToItsProjectGroup_DeclaredOrAllVisible_NeverToEveryoneOrAdminsAsSuch()
    {
        var (world, r1, r2) = TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;
        var declaredP = await r1.ConnectAsync(Alice);
        var declaredQ = await r1.ConnectAsync(Bob);
        var adminIdle = await r1.ConnectAsync(Admin, role: "admin");
        var adminAll = await r2.ConnectAsync(Admin, role: "admin");
        await r1.DeclareAsync(declaredP, P);
        await r1.DeclareAsync(declaredQ, Q);
        await r2.DeclareAllVisibleAsync(adminAll, true);

        await r1.DispatchAsync($"skein.events.project.{P}.issue.updated.sk-1", IssueEvent(1, P));

        Assert.Single(world.DeliveriesTo(declaredP, BrowserClientMethods.Event));
        Assert.Single(world.DeliveriesTo(adminAll, BrowserClientMethods.Event));
        Assert.Empty(world.DeliveriesTo(declaredQ));
        Assert.Empty(world.DeliveriesTo(adminIdle));
    }

    [Fact]
    public async Task EventTakenByReplicaOne_ReachesConnectionsOnBothReplicas()
    {
        var (world, r1, r2) = TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;
        var onR1 = await r1.ConnectAsync(Alice);
        var onR2 = await r2.ConnectAsync(Bob);
        await r1.DeclareAsync(onR1, P);
        await r2.DeclareAsync(onR2, P);

        await r1.DispatchAsync($"skein.events.project.{P}.issue.updated.sk-1", IssueEvent(2, P));

        Assert.Single(world.DeliveriesTo(onR1, BrowserClientMethods.Event));
        Assert.Single(world.DeliveriesTo(onR2, BrowserClientMethods.Event));
    }

    [Fact]
    public async Task ReplicaWithoutNats_DoesNotPreventDelivery_TheOtherTakesTheEvent()
    {
        // Replica 1 lost NATS: it dispatches nothing. Replica 2 took the event.
        var (world, r1, r2) = TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;
        var onR1 = await r1.ConnectAsync(Alice);
        var onR2 = await r2.ConnectAsync(Bob);
        await r1.DeclareAsync(onR1, P);
        await r2.DeclareAsync(onR2, P);

        await r2.DispatchAsync($"skein.events.project.{P}.issue.updated.sk-1", IssueEvent(3, P));

        Assert.Single(world.DeliveriesTo(onR1, BrowserClientMethods.Event));
        Assert.Single(world.DeliveriesTo(onR2, BrowserClientMethods.Event));
    }

    [Fact]
    public async Task UserEvent_ToTheUserAndInternalAdmins_NotToAnExternalAdmin()
    {
        var (world, r1, r2) = TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;
        var alice = await r1.ConnectAsync(Alice);
        var bob = await r1.ConnectAsync(Bob);
        var admin = await r2.ConnectAsync(Admin, role: "admin");
        var external = await r2.ConnectAsync(ExternalAdmin, role: "admin", isExternal: true);

        await r1.DispatchAsync($"skein.user.{Alice}.updated", new
        {
            id = 4, occurredAt = "2026-10-09T10:00:00Z", eventType = "user.updated",
            entityType = "user", entityId = Alice.ToString(),
        });

        Assert.Single(world.DeliveriesTo(alice, BrowserClientMethods.Event));
        Assert.Single(world.DeliveriesTo(admin, BrowserClientMethods.Event));
        Assert.Empty(world.DeliveriesTo(bob));
        Assert.Empty(world.DeliveriesTo(external));
    }

    [Fact]
    public async Task Deactivated_EnvelopeReachesEveryConnectionOfTheUser()
    {
        var (world, r1, r2) = TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;
        var tab1 = await r1.ConnectAsync(Alice);
        var tab2 = await r2.ConnectAsync(Alice);

        await r1.DispatchAsync($"skein.user.{Alice}.deactivated", new
        {
            id = 5, occurredAt = "2026-10-09T10:00:00Z", eventType = "user.deactivated",
            entityType = "user", entityId = Alice.ToString(),
        });

        foreach (var tab in new[] { tab1, tab2 })
        {
            var env = Assert.IsType<BrowserEnvelope>(Assert.Single(world.DeliveriesTo(tab, BrowserClientMethods.Event)).Payload);
            Assert.Equal("user.deactivated", env.EventType);
            Assert.Equal(Alice.ToString(), env.EntityId);
        }
    }

    [Fact]
    public async Task ReminderFrame_ToEveryConnectionOfTheOwner_RegardlessOfDeclarations()
    {
        var (world, r1, r2) = TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;
        var undeclared = await r1.ConnectAsync(Alice);
        var otherProject = await r2.ConnectAsync(Alice);
        await r2.DeclareAsync(otherProject, Q);
        var bob = await r1.ConnectAsync(Bob);
        await r1.DeclareAsync(bob, P);

        await r1.DispatchAsync($"skein.user.{Alice}.reminder", new
        {
            reminderId = "0199a1b2-0000-7000-8000-0000000000f1",
            issueId = "sk-1",
            projectId = P,
            kind = "rang",
            remindAt = "2026-10-09T10:00:00Z",
            firingId = "0199a1b2-0000-7000-8000-0000000000f1@2026-10-09T10:00:00Z",
        });

        foreach (var tab in new[] { undeclared, otherProject })
        {
            var frame = Assert.IsType<ReminderFrame>(Assert.Single(world.DeliveriesTo(tab, BrowserClientMethods.Reminder)).Payload);
            Assert.Equal("rang", frame.Kind);
            Assert.Equal("0199a1b2-0000-7000-8000-0000000000f1@2026-10-09T10:00:00Z", frame.FiringId);
        }
        Assert.Empty(world.DeliveriesTo(bob));
    }

    [Fact]
    public async Task ThemeMessages_KeepTheirMethods_AndGoToTheirOneUserOnly()
    {
        // Row 230a (K-31, US-21): a theme change goes to its author only, on
        // the personal subject; the former org-wide subject reaches nobody.
        var (world, r1, _) = TwoReplicas();
        using var _1 = r1;
        var alice = await r1.ConnectAsync(Alice);
        var bob = await r1.ConnectAsync(Bob);
        var admin = await r1.ConnectAsync(Admin, role: "admin");

        await r1.DispatchAsync($"skein.user.{Alice}.theme.preview", new { userId = Alice, variables = new { } });
        await r1.DispatchAsync($"skein.user.{Alice}.theme.user-pref.updated", new { });
        await r1.DispatchAsync($"skein.user.{Alice}.theme.updated",
            new { themeId = "0199a1b2-0000-7000-8000-0000000000e1", variables = new { } });
        await r1.DispatchAsync("skein.events.theme.updated.0199a1b2-0000-7000-8000-0000000000e1",
            new { themeId = "0199a1b2-0000-7000-8000-0000000000e1", variables = new { } });

        Assert.Single(world.DeliveriesTo(alice, "theme.preview"));
        Assert.Single(world.DeliveriesTo(alice, "theme.user-pref.updated"));
        Assert.Single(world.DeliveriesTo(alice, "theme.updated"));
        Assert.Empty(world.DeliveriesTo(bob));
        Assert.Empty(world.DeliveriesTo(admin));
    }

    [Fact]
    public async Task AdminsChannel_CarriesUserEntityEventsOnly_NeverProjectData()
    {
        // Row 220 (K-15): admins:internal gets the events of the entity "user";
        // an event on a user subject that names a project goes to that user
        // only; a project event never reaches an admin as such.
        var (world, r1, r2) = TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;
        var alice = await r1.ConnectAsync(Alice);
        var admin = await r2.ConnectAsync(Admin, role: "admin");

        await r1.DispatchAsync($"skein.user.{Alice}.updated", new
        {
            id = 10, occurredAt = "2026-10-09T10:00:00Z", eventType = "user.updated",
            entityType = "user", entityId = Alice.ToString(),
        });
        await r1.DispatchAsync($"skein.user.{Alice}.updated", new
        {
            id = 11, occurredAt = "2026-10-09T10:00:00Z", eventType = "user.updated",
            entityType = "user", entityId = Alice.ToString(), projectId = P, projectIdPrefix = "sk",
        });
        await r1.DispatchAsync($"skein.events.project.{P}.issue.updated.sk-1", IssueEvent(12, P));

        var toAdmin = world.DeliveriesTo(admin, BrowserClientMethods.Event)
            .Select(d => Assert.IsType<BrowserEnvelope>(d.Payload)).ToArray();
        Assert.Equal(new long[] { 10 }, toAdmin.Select(e => e.Id));
        Assert.Equal(2, world.DeliveriesTo(alice, BrowserClientMethods.Event).Count);
    }

    [Fact]
    public async Task AnotherUsersPersonalProjectEvent_ReachesTheAdminOnNoChannel()
    {
        // Row 221 (SC-005, US-19, INV-23), api answering v2: the admin in "all
        // visible", the admin that tried to declare the project, and the idle
        // admin get no frame of Alice's personal project — neither the project
        // event nor a user-subject event carrying it. Positive controls: Alice
        // receives both; the admin in "all visible" receives a non-personal
        // project's event.
        var (world, r1, r2) = TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;
        world.AccessApi.SetUser(Alice, memberOf: [P, Q, AlicePersonal]);
        world.AccessApi.SetProject(AlicePersonal, personalOwner: Alice);
        var alice = await r1.ConnectAsync(Alice);
        await r1.DeclareAsync(alice, AlicePersonal);
        var adminAll = await r2.ConnectAsync(Admin, role: "admin");
        await r2.DeclareAllVisibleAsync(adminAll, true);
        var adminDeclared = await r2.ConnectAsync(Admin, role: "admin");
        Assert.Equal("no_access", Assert.Single((await r2.DeclareAsync(adminDeclared, AlicePersonal)).Rejected).Reason);
        var adminIdle = await r1.ConnectAsync(Admin, role: "admin");

        await r1.DispatchAsync($"skein.events.project.{AlicePersonal}.issue.updated.sk-1", IssueEvent(20, AlicePersonal));
        await r2.DispatchAsync($"skein.user.{Alice}.updated", new
        {
            id = 21, occurredAt = "2026-10-09T10:00:00Z", eventType = "user.updated",
            entityType = "user", entityId = Alice.ToString(), projectId = AlicePersonal, projectIdPrefix = "me",
        });
        await r2.DispatchAsync($"skein.events.project.{P}.issue.updated.sk-2", IssueEvent(22, P));

        Assert.Equal(2, world.DeliveriesTo(alice, BrowserClientMethods.Event).Count);
        var toAdminAll = Assert.Single(world.DeliveriesTo(adminAll));
        Assert.Equal(22, Assert.IsType<BrowserEnvelope>(toAdminAll.Payload).Id);
        Assert.Empty(world.DeliveriesTo(adminDeclared));
        Assert.Empty(world.DeliveriesTo(adminIdle));
    }

    [Fact]
    public async Task PersonalSignal_IsNotHandledByTheQueueGroupLoop()
    {
        var (world, r1, _) = TwoReplicas();
        using var _1 = r1;
        var alice = await r1.ConnectAsync(Alice);

        await r1.DispatchAsync($"skein.user.{Alice}.signal", new { areas = new[] { "inbox" }, sentAt = "2026-10-09T10:00:00Z" });

        Assert.Empty(world.DeliveriesTo(alice));
    }
}
