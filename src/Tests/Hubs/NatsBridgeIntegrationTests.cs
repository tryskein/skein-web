using Microsoft.Extensions.Time.Testing;
using SkeinWeb.Hubs;

namespace SkeinWeb.Tests.Hubs;

/// <summary>
/// Dispatch tests for <see cref="NatsBridge"/> over the real hub declaration
/// path (sk-622.21 tests No. 65): who receives a project event is decided by
/// what each connection declared through <see cref="SkeinHub.DeclareProjects"/>
/// and by skein-api's access answer — not by a membership cache and not by
/// the admin role. Messages enter through the internal <c>Dispatch</c> with
/// synthesised NATS payloads; SignalR delivery is the shared
/// <see cref="HubTestWorld"/> fabric.
/// </summary>
/// <remarks>
/// Rewritten from the membership-cache era: the scenarios «members and
/// admins», «not a member», «external / internal admin» are kept, now through
/// declarations. The cache-delta scenarios are gone with the cache (their
/// property — revocation on membership change — is No. 63's).
/// </remarks>
public class NatsBridgeIntegrationTests
{
    private static readonly Guid AdminUser = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private static readonly Guid MemberUser = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
    private static readonly Guid OutsiderUser = Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc");
    private static readonly Guid ExternalAdmin = Guid.Parse("dddddddd-dddd-dddd-dddd-dddddddddddd");
    private static readonly Guid ProjectId = Guid.Parse("11111111-2222-3333-4444-555555555555");
    private static readonly Guid OtherProjectId = Guid.Parse("22222222-3333-4444-5555-666666666666");

    private static HubTestReplica NewReplica(out HubTestWorld world)
    {
        world = new HubTestWorld();
        world.AccessApi.SetUser(AdminUser, internalAdmin: true);
        world.AccessApi.SetUser(MemberUser, memberOf: ProjectId);
        world.AccessApi.SetUser(OutsiderUser, memberOf: OtherProjectId);
        world.AccessApi.SetUser(ExternalAdmin, internalAdmin: true, external: true);
        return new HubTestReplica(world, new FakeTimeProvider(DateTimeOffset.Parse("2026-10-09T10:00:00Z")));
    }

    private static object IssueCreated(long id, Guid project, string issue) => new
    {
        id,
        occurredAt = "2026-10-09T10:00:00Z",
        eventType = "issue.created",
        entityType = "issue",
        entityId = issue,
        projectId = project,
        newData = new { title = "T", description = "secret description" },
    };

    [Fact]
    public async Task ProjectEvent_ReachesConnectionsThatDeclaredIt_MembersAndAdminsAlike()
    {
        using var replica = NewReplica(out var world);
        var admin = await replica.ConnectAsync(AdminUser, role: "admin");
        var member = await replica.ConnectAsync(MemberUser);
        var outsider = await replica.ConnectAsync(OutsiderUser);
        await replica.DeclareAsync(admin, ProjectId);
        await replica.DeclareAsync(member, ProjectId);
        await replica.DeclareAsync(outsider, OtherProjectId);

        await replica.DispatchAsync($"skein.events.project.{ProjectId}.issue.created.demo-1",
            IssueCreated(1, ProjectId, "demo-1"));

        Assert.Single(world.DeliveriesTo(admin, BrowserClientMethods.Event));
        Assert.Single(world.DeliveriesTo(member, BrowserClientMethods.Event));
        Assert.Empty(world.DeliveriesTo(outsider));
        var env = Assert.IsType<BrowserEnvelope>(world.DeliveriesTo(member)[0].Payload);
        Assert.Equal(1, env.Id);
        Assert.Equal("demo-1", env.EntityId);
    }

    [Fact]
    public async Task ProjectEvent_NotDeclared_ReachesNobody_AdminIncluded()
    {
        using var replica = NewReplica(out var world);
        var admin = await replica.ConnectAsync(AdminUser, role: "admin");
        var member = await replica.ConnectAsync(MemberUser);

        await replica.DispatchAsync($"skein.events.project.{ProjectId}.issue.created.demo-2",
            IssueCreated(2, ProjectId, "demo-2"));

        Assert.Empty(world.DeliveriesTo(admin));
        Assert.Empty(world.DeliveriesTo(member));
    }

    [Fact]
    public async Task NotAMember_DeclarationRejected_EventNotDelivered()
    {
        using var replica = NewReplica(out var world);
        var outsider = await replica.ConnectAsync(OutsiderUser);

        var result = await replica.DeclareAsync(outsider, ProjectId);

        var rejection = Assert.Single(result.Rejected);
        Assert.Equal("no_access", rejection.Reason);
        await replica.DispatchAsync($"skein.events.project.{ProjectId}.issue.created.demo-3",
            IssueCreated(3, ProjectId, "demo-3"));
        Assert.Empty(world.DeliveriesTo(outsider));
    }

    [Fact]
    public async Task ExternalAdmin_ForeignProjectDeclarationRejected_ReceivesNoFrame()
    {
        using var replica = NewReplica(out var world);
        var external = await replica.ConnectAsync(ExternalAdmin, role: "admin", isExternal: true);

        var result = await replica.DeclareAsync(external, ProjectId);
        var all = await replica.DeclareAllVisibleAsync(external, true);

        Assert.Equal("no_access", Assert.Single(result.Rejected).Reason);
        Assert.Empty(all.Rejected); // the mode is on, but only over memberships (none)
        await replica.DispatchAsync($"skein.events.project.{ProjectId}.issue.created.zz-1",
            IssueCreated(42, ProjectId, "zz-1"));
        Assert.Empty(world.DeliveriesTo(external));
    }

    [Fact]
    public async Task InternalAdmin_DeclaresForeignProject_ReceivesItsFrame()
    {
        using var replica = NewReplica(out var world);
        var admin = await replica.ConnectAsync(AdminUser, role: "admin");

        var result = await replica.DeclareAsync(admin, OtherProjectId);

        Assert.Empty(result.Rejected);
        await replica.DispatchAsync($"skein.events.project.{OtherProjectId}.issue.created.zz-2",
            IssueCreated(43, OtherProjectId, "zz-2"));
        Assert.Single(world.DeliveriesTo(admin, BrowserClientMethods.Event));
    }

    [Fact]
    public async Task NotificationSubject_DoesNotEnterEventEnvelopePath()
    {
        using var replica = NewReplica(out var world);
        var member = await replica.ConnectAsync(MemberUser);

        // Empty body — the notification forwarder logs and returns.
        await replica.Bridge.Dispatch($"skein.user.{MemberUser}.notification", [], CancellationToken.None);

        Assert.Empty(world.DeliveriesTo(member));
    }

    [Fact]
    public async Task UserEvent_ReachesTheUserAndInternalAdmins_NotOthers()
    {
        using var replica = NewReplica(out var world);
        var admin = await replica.ConnectAsync(AdminUser, role: "admin");
        var member = await replica.ConnectAsync(MemberUser);
        var outsider = await replica.ConnectAsync(OutsiderUser);
        var external = await replica.ConnectAsync(ExternalAdmin, role: "admin", isExternal: true);

        await replica.DispatchAsync($"skein.user.{MemberUser}.updated", new
        {
            id = 7,
            occurredAt = "2026-10-09T10:00:00Z",
            eventType = "user.updated",
            entityType = "user",
            entityId = MemberUser.ToString(),
        });

        Assert.Single(world.DeliveriesTo(admin, BrowserClientMethods.Event));
        Assert.Single(world.DeliveriesTo(member, BrowserClientMethods.Event));
        Assert.Empty(world.DeliveriesTo(outsider));
        Assert.Empty(world.DeliveriesTo(external));
    }

    [Fact]
    public async Task MalformedSubject_DroppedSilently()
    {
        using var replica = NewReplica(out var world);
        var admin = await replica.ConnectAsync(AdminUser, role: "admin");

        await replica.DispatchAsync("not.a.real.subject", new { id = 8, eventType = "weird" });

        Assert.Empty(world.DeliveriesTo(admin));
    }
}
