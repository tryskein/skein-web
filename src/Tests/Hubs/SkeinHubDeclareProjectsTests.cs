using System.Net;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using SkeinWeb.Hubs;

namespace SkeinWeb.Tests.Hubs;

/// <summary>
/// Project declarations of <see cref="SkeinHub"/> (sk-622.21 tests No. 59; US-9,
/// edge 11, INV-9): acceptance and group membership, <c>no_access</c>, the
/// per-connection project limit from configuration, the per-connection rate
/// limit on <see cref="FakeTimeProvider"/>, one access call per change of the
/// set, "all visible" by kind of user, and the connect-time admin group.
/// Hub v2 (sk-674.18 K-15, ADR-3, D-10): "all visible" joins the groups of the
/// projects skein-api lists as visible for every actor, the admin included —
/// there is no group of all projects, and another user's personal space stays
/// out of the admin's delivery.
/// </summary>
/// <remarks>
/// Expected values come from spec US-9 and plan T030/T032: limit 50 by
/// default, 10 changes per 10 s, reasons <c>no_access</c> / <c>limit</c> /
/// <c>rate</c>, group names <c>project:{pid}</c>, <c>admins:internal</c>
/// (sk-674.18 ADR-3 removes <c>projects:all</c>). The hub, registry, limiter and access client are
/// the production types; skein-api and the SignalR transport are faked
/// (<see cref="HubTestWorld"/>).
/// </remarks>
public class SkeinHubDeclareProjectsTests
{
    private static readonly Guid Alice = Guid.Parse("0199a1b2-0000-7000-8000-000000000001");
    private static readonly Guid Bob = Guid.Parse("0199a1b2-0000-7000-8000-000000000002");
    private static readonly Guid Admin = Guid.Parse("0199a1b2-0000-7000-8000-000000000003");
    private static readonly Guid ExternalAdmin = Guid.Parse("0199a1b2-0000-7000-8000-000000000004");

    private static readonly Guid P1 = Guid.Parse("0199a1b2-0000-7000-8000-0000000000a1");
    private static readonly Guid P2 = Guid.Parse("0199a1b2-0000-7000-8000-0000000000a2");
    private static readonly Guid Hidden = Guid.Parse("0199a1b2-0000-7000-8000-0000000000ff");
    private static readonly Guid AlicePersonal = Guid.Parse("0199a1b2-0000-7000-8000-0000000000b1");
    private static readonly Guid AdminPersonal = Guid.Parse("0199a1b2-0000-7000-8000-0000000000b2");

    private static readonly Guid[] Many = Enumerable.Range(1, 60)
        .Select(i => Guid.Parse($"0199a1b2-0000-7000-8000-{i:D12}"))
        .ToArray();

    private static (HubTestReplica Replica, HubTestWorld World, FakeTimeProvider Clock) Build(
        HubDeliveryOptions? options = null)
    {
        var world = new HubTestWorld();
        world.AccessApi.SetUser(Alice, memberOf: [P1, P2, .. Many]);
        world.AccessApi.SetUser(Bob, memberOf: [P1, P2, .. Many]);
        world.AccessApi.SetUser(Admin, internalAdmin: true);
        world.AccessApi.SetUser(ExternalAdmin, internalAdmin: true, external: true, memberOf: P2);
        var clock = new FakeTimeProvider(DateTimeOffset.Parse("2026-10-09T10:00:00Z"));
        return (new HubTestReplica(world, clock, options), world, clock);
    }

    [Fact]
    public async Task AcceptedProject_PutsTheConnectionIntoItsGroup()
    {
        var (replica, world, _) = Build();
        using var _r = replica;
        var conn = await replica.ConnectAsync(Alice);

        var result = await replica.DeclareAsync(conn, P1.ToString());

        Assert.Equal(new[] { P1.ToString() }, result.Accepted);
        Assert.Empty(result.Rejected);
        Assert.Contains($"project:{P1}", world.GroupsOf(conn));
    }

    [Fact]
    public async Task InaccessibleProject_RejectedNoAccess_OthersAccepted_WarnNamesUserAndProject()
    {
        var (replica, world, _) = Build();
        using var _r = replica;
        var conn = await replica.ConnectAsync(Alice);

        var result = await replica.DeclareAsync(conn, P1, Hidden, P2);

        Assert.Equal(new[] { P1.ToString(), P2.ToString() }, result.Accepted);
        var rejection = Assert.Single(result.Rejected);
        Assert.Equal(Hidden.ToString(), rejection.ProjectId);
        Assert.Equal("no_access", rejection.Reason);
        Assert.DoesNotContain($"project:{Hidden}", world.GroupsOf(conn));
        Assert.Contains(replica.Logs.Entries, e =>
            e.Level == LogLevel.Warning
            && e.Line.Contains($"UserId={Alice}", StringComparison.Ordinal)
            && e.Line.Contains($"ProjectId={Hidden}", StringComparison.Ordinal));
    }

    [Fact]
    public async Task LimitFromConfiguration_ThreeMeansTheFourthIsRejected()
    {
        var options = new HubDeliveryOptions
        {
            MaxProjectsPerConnection = HubDeliveryOptions.ParseMaxProjectsPerConnection("3"),
        };
        var (replica, world, _) = Build(options);
        using var _r = replica;
        var conn = await replica.ConnectAsync(Alice);

        var result = await replica.DeclareAsync(conn, Many[0], Many[1], Many[2], Many[3]);

        Assert.Equal(Many.Take(3).Select(p => p.ToString()), result.Accepted);
        var rejection = Assert.Single(result.Rejected);
        Assert.Equal(Many[3].ToString(), rejection.ProjectId);
        Assert.Equal("limit", rejection.Reason);
        Assert.DoesNotContain($"project:{Many[3]}", world.GroupsOf(conn));
    }

    [Fact]
    public async Task UnsetLimit_IsFifty_FiftiethAccepted_FiftyFirstRejected()
    {
        var options = new HubDeliveryOptions
        {
            MaxProjectsPerConnection = HubDeliveryOptions.ParseMaxProjectsPerConnection(null),
        };
        var (replica, _, _) = Build(options);
        using var _r = replica;
        var conn = await replica.ConnectAsync(Alice);

        var result = await replica.DeclareAsync(conn, Many.Take(51).ToArray());

        Assert.Equal(50, result.Accepted.Count);
        Assert.Equal(Many[49].ToString(), result.Accepted[^1]);
        var rejection = Assert.Single(result.Rejected);
        Assert.Equal(Many[50].ToString(), rejection.ProjectId);
        Assert.Equal("limit", rejection.Reason);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-1")]
    [InlineData("")]
    [InlineData("fifty")]
    public void LimitParse_NonPositiveOrGarbage_RefusesStart(string raw)
    {
        Assert.Throws<InvalidOperationException>(() => HubDeliveryOptions.ParseMaxProjectsPerConnection(raw));
    }

    [Fact]
    public async Task EleventhChangeWithinTenSeconds_IsRate_BudgetReturnsAfterTenSeconds()
    {
        var (replica, world, clock) = Build();
        using var _r = replica;
        var conn = await replica.ConnectAsync(Alice);

        for (var i = 0; i < 10; i++)
        {
            var ok = await replica.DeclareAsync(conn, Many[i]);
            Assert.Empty(ok.Rejected);
        }
        var refused = await replica.DeclareAsync(conn, Many[10]);

        Assert.Empty(refused.Accepted);
        Assert.Equal("rate", Assert.Single(refused.Rejected).Reason);
        Assert.Contains($"project:{Many[9]}", world.GroupsOf(conn)); // previous set in force
        Assert.DoesNotContain($"project:{Many[10]}", world.GroupsOf(conn));

        clock.Advance(TimeSpan.FromSeconds(10));
        var again = await replica.DeclareAsync(conn, Many[10]);

        Assert.Equal(new[] { Many[10].ToString() }, again.Accepted);
        Assert.Contains($"project:{Many[10]}", world.GroupsOf(conn));
    }

    [Fact]
    public async Task LimitsAreKeyedByConnection_NotByUser()
    {
        var options = new HubDeliveryOptions { MaxProjectsPerConnection = 3 };
        var (replica, _, _) = Build(options);
        using var _r = replica;
        var tab1 = await replica.ConnectAsync(Alice);
        var tab2 = await replica.ConnectAsync(Alice);
        var bobTab = await replica.ConnectAsync(Bob);

        // Tab 1 fills its project set and exhausts its rate budget.
        await replica.DeclareAsync(tab1, Many[0], Many[1], Many[2]);
        for (var i = 3; i < 12; i++)
        {
            await replica.DeclareAsync(tab1, Many[i]);
        }
        Assert.Equal("rate", Assert.Single((await replica.DeclareAsync(tab1, Many[20])).Rejected).Reason);

        // The second tab of the same user has its own full budgets.
        var second = await replica.DeclareAsync(tab2, Many[30], Many[31], Many[32]);
        Assert.Equal(3, second.Accepted.Count);
        for (var i = 0; i < 9; i++)
        {
            Assert.Empty((await replica.DeclareAsync(tab2, Many[40 + i])).Rejected);
        }

        // Another user's tab too.
        var bob = await replica.DeclareAsync(bobTab, Many[50], Many[51], Many[52]);
        Assert.Equal(3, bob.Accepted.Count);
    }

    [Fact]
    public async Task OneAccessCallPerChange_SameSetAgainCallsNothing()
    {
        var (replica, world, _) = Build();
        using var _r = replica;
        var conn = await replica.ConnectAsync(Alice);

        await replica.DeclareAsync(conn, P1, P2);
        Assert.Equal(1, world.AccessApi.Calls);

        var repeat = await replica.DeclareAsync(conn, P2, P1);
        Assert.Equal(1, world.AccessApi.Calls);
        Assert.Equal(2, repeat.Accepted.Count);

        await replica.DeclareAsync(conn, P1);
        Assert.Equal(2, world.AccessApi.Calls);
        Assert.DoesNotContain($"project:{P2}", world.GroupsOf(conn));
    }

    [Fact]
    public async Task AdminWithoutDeclaration_IsInNoProjectGroup()
    {
        var (replica, world, _) = Build();
        using var _r = replica;
        var conn = await replica.ConnectAsync(Admin, role: "admin");

        // No project delivery of any kind (ADR-3: no group of all projects either).
        Assert.DoesNotContain(world.GroupsOf(conn), g => g.StartsWith("project", StringComparison.Ordinal));
    }

    /// <summary>
    /// World of row 218: non-personal projects P1, P2 and 60 more (<see cref="Many"/>);
    /// Alice's personal space holds <see cref="AlicePersonal"/>, the admin's
    /// holds <see cref="AdminPersonal"/>. Alice is a member of everything
    /// non-personal; the admin of nothing.
    /// </summary>
    private static (HubTestReplica Replica, HubTestWorld World) SpacesWorld()
    {
        var world = new HubTestWorld();
        world.AccessApi.SetUser(Alice, memberOf: [P1, P2, .. Many, AlicePersonal]);
        world.AccessApi.SetUser(Admin, internalAdmin: true, memberOf: AdminPersonal);
        world.AccessApi.SetProject(AlicePersonal, personalOwner: Alice);
        world.AccessApi.SetProject(AdminPersonal, personalOwner: Admin);
        return (new HubTestReplica(world, new FakeTimeProvider()), world);
    }

    public static TheoryData<string> AllVisibleActors => new() { "admin", "member" };

    [Theory]
    [MemberData(nameof(AllVisibleActors))]
    public async Task AllVisible_AnyActor_JoinsExactlyTheVisibleSet_MoreThanFiftyWhole_NoGroupOfAllProjects(string actor)
    {
        // Row 218 (K-15, ADR-3, SC-005): the visible set for every actor, the
        // admin included — exactly it, so another user's personal project is
        // out and the role widens nothing; 63 projects — over the limit of 50,
        // which bounds DeclareProjects only — all accepted.
        var (replica, world) = SpacesWorld();
        using var _r = replica;
        var conn = actor == "admin"
            ? await replica.ConnectAsync(Admin, role: "admin")
            : await replica.ConnectAsync(Alice);
        Guid[] visible = actor == "admin"
            ? [P1, P2, .. Many, AdminPersonal]   // every non-personal project + its own personal
            : [P1, P2, .. Many, AlicePersonal];  // its memberships

        var result = await replica.DeclareAllVisibleAsync(conn, true);

        Assert.Empty(result.Accepted);
        Assert.Empty(result.Rejected);
        var projectGroups = world.GroupsOf(conn).Where(g => g.StartsWith("project", StringComparison.Ordinal)).ToHashSet();
        Assert.Equal(visible.Select(p => $"project:{p}").ToHashSet(), projectGroups);

        await replica.DeclareAllVisibleAsync(conn, false);
        Assert.DoesNotContain(world.GroupsOf(conn), g => g.StartsWith("project", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AllVisible_MemberJoinsItsProjectGroups_NotAGroupOfAllProjects()
    {
        var world = new HubTestWorld();
        world.AccessApi.SetUser(Alice, memberOf: [P1, P2]);
        using var replica = new HubTestReplica(world, new FakeTimeProvider());
        var conn = await replica.ConnectAsync(Alice);

        await replica.DeclareAllVisibleAsync(conn, true);

        var groups = world.GroupsOf(conn);
        Assert.Contains($"project:{P1}", groups);
        Assert.Contains($"project:{P2}", groups);
        Assert.DoesNotContain("projects:all", groups);
    }

    [Fact]
    public async Task AllVisible_ExternalAdminGetsOnlyMembership()
    {
        var (replica, world, _) = Build();
        using var _r = replica;
        var conn = await replica.ConnectAsync(ExternalAdmin, role: "admin", isExternal: true);

        await replica.DeclareAllVisibleAsync(conn, true);

        var groups = world.GroupsOf(conn);
        Assert.Contains($"project:{P2}", groups);
        Assert.DoesNotContain("projects:all", groups);
        Assert.DoesNotContain($"project:{P1}", groups);
    }

    [Theory]
    [InlineData("admin", false, true)]
    [InlineData("admin", true, false)]
    [InlineData("user", false, false)]
    public async Task Connect_PutsOnlyInternalAdminsIntoAdminsInternal(string role, bool external, bool expected)
    {
        var (replica, world, _) = Build();
        using var _r = replica;
        var conn = await replica.ConnectAsync(Guid.NewGuid(), role: role, isExternal: external);

        Assert.Equal(expected, world.GroupsOf(conn).Contains("admins:internal"));
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
    public async Task AfterFailClosed_SuccessfulDeclaration_PutsTheConnectionBackAtOnce()
    {
        // K10: a connection out of its groups by fail-closed stays out "until
        // the next successful check" — a successful declaration is one.
        var (replica, world, clock) = Build();
        using var _r = replica;
        await replica.StartAsync(0, replica.Recheck);
        var conn = await replica.ConnectAsync(Alice);
        await replica.DeclareAsync(conn, P1);
        world.AccessApi.FailWith = HttpStatusCode.InternalServerError;
        var calls = world.AccessApi.Calls;
        clock.Advance(AccessRecheckService.Interval);                       // t = 30: check fails
        await Eventually(() => world.AccessApi.Calls == calls + 4, "first failing check");
        calls = world.AccessApi.Calls;
        clock.Advance(AccessRecheckService.Interval);                       // t = 60: fail-closed
        await Eventually(() => world.AccessApi.Calls == calls + 4, "second failing check finished");
        Assert.DoesNotContain($"project:{P1}", world.GroupsOf(conn));
        world.AccessApi.FailWith = null;

        var result = await replica.DeclareAsync(conn, P1, P2);

        Assert.Equal(new[] { P1.ToString(), P2.ToString() }, result.Accepted);
        var groups = world.GroupsOf(conn);
        Assert.Contains($"project:{P1}", groups);
        Assert.Contains($"project:{P2}", groups);
    }

    [Fact]
    public async Task SkeinApiUnavailable_DeclarationFails_PreviousSetInForce_RateSlotNotSpent()
    {
        var (replica, world, _) = Build();
        using var _r = replica;
        var conn = await replica.ConnectAsync(Alice);
        for (var i = 0; i < 9; i++)                                         // 9 of 10 changes in the window
        {
            await replica.DeclareAsync(conn, i % 2 == 0 ? P1 : P2);
        }
        world.AccessApi.FailWith = HttpStatusCode.InternalServerError;
        var calls = world.AccessApi.Calls;

        await Assert.ThrowsAsync<HubException>(() => replica.DeclareAsync(conn, P2));

        Assert.Equal(calls + 4, world.AccessApi.Calls);                     // 1 attempt + 3 retries
        Assert.Contains($"project:{P1}", world.GroupsOf(conn));
        Assert.DoesNotContain($"project:{P2}", world.GroupsOf(conn));
        world.AccessApi.FailWith = null;
        var result = await replica.DeclareAsync(conn, P2);                  // the 10th change still fits
        Assert.Equal(new[] { P2.ToString() }, result.Accepted);
        Assert.Contains($"project:{P2}", world.GroupsOf(conn));
    }
}
