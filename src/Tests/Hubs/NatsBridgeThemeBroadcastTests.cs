using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using SkeinWeb.Hubs;

namespace SkeinWeb.Tests.Hubs;

/// <summary>
/// Theme events of <see cref="NatsBridge"/> (sk-674.18 K-31, US-21): themes
/// are personal — a theme change, published on the author's subject
/// <c>skein.user.{author}.theme.updated</c>, reaches every connection of the
/// author and nobody else; the former org-wide broadcast
/// <c>skein.events.theme.updated.{themeId}</c> (sk-163 S7b, group
/// <see cref="SkeinHub.OrgBroadcastGroup"/>) is no longer delivered at all.
/// </summary>
/// <remarks>
/// Real bridge, hub and registry over the <see cref="HubTestWorld"/> fakes of
/// the SignalR transport, so every possible addressee — a user, a group, all
/// connections — is observed by what connections receive.
/// </remarks>
public class NatsBridgeThemeBroadcastTests
{
    private static readonly Guid Author = Guid.Parse("0199a1b2-0000-7000-8000-000000000001");
    private static readonly Guid Other = Guid.Parse("0199a1b2-0000-7000-8000-000000000002");
    private static readonly Guid Admin = Guid.Parse("0199a1b2-0000-7000-8000-000000000003");
    private const string ThemeId = "0199a1b2-0000-7000-8000-0000000000e1";

    private static (HubTestWorld World, HubTestReplica R1, HubTestReplica R2) TwoReplicas()
    {
        var world = new HubTestWorld();
        var clock = new FakeTimeProvider(DateTimeOffset.Parse("2026-10-12T10:00:00Z"));
        return (world, new HubTestReplica(world, clock), new HubTestReplica(world, clock));
    }

    [Fact]
    public async Task ThemeUpdated_ReachesEveryConnectionOfTheAuthor_AndNoOtherConnection()
    {
        // Row 223 (K-31, US-21).
        var (world, r1, r2) = TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;
        var authorTab1 = await r1.ConnectAsync(Author);
        var authorTab2 = await r2.ConnectAsync(Author);
        var other = await r1.ConnectAsync(Other);
        var admin = await r2.ConnectAsync(Admin, role: "admin");

        await r1.DispatchAsync($"skein.user.{Author}.theme.updated",
            new { themeId = ThemeId, variables = new { color = "#fff" } });

        foreach (var tab in new[] { authorTab1, authorTab2 })
        {
            var payload = Assert.IsType<JsonElement>(Assert.Single(world.DeliveriesTo(tab, "theme.updated")).Payload);
            Assert.Equal(ThemeId, payload.GetProperty("themeId").GetString());
        }
        Assert.Empty(world.DeliveriesTo(other));
        Assert.Empty(world.DeliveriesTo(admin));
    }

    [Fact]
    public async Task FormerOrgWideThemeSubject_IsNotDeliveredToAnyone()
    {
        // Row 231 (K-31): no longer to the org-broadcast group — to no one.
        var (world, r1, r2) = TwoReplicas();
        using var _1 = r1;
        using var _2 = r2;
        await r1.ConnectAsync(Author);
        var other = await r1.ConnectAsync(Other);
        // Precondition: a send to the old group would be observed.
        Assert.Contains(SkeinHub.OrgBroadcastGroup, world.GroupsOf(other));

        await r1.DispatchAsync($"skein.events.theme.updated.{ThemeId}",
            new { themeId = ThemeId, variables = new { color = "#fff" } });

        Assert.Empty(world.Deliveries);
    }
}
