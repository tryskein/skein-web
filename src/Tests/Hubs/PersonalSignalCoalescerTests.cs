using Microsoft.Extensions.Time.Testing;
using SkeinWeb.Hubs;

namespace SkeinWeb.Tests.Hubs;

/// <summary>
/// Per-connection coalescing of personal signals (sk-622.21 tests No. 62, No. 62a;
/// SC-004, US-11, edge 14, edge 17). Input enters where the process takes it:
/// the real <see cref="PersonalSignalSubscriber"/> (and, for No. 62a, the real
/// <see cref="NatsBridge"/>) started with <c>StartAsync</c> on a fake NATS
/// connection; output is what connections receive. Time is a
/// <see cref="FakeTimeProvider"/>.
/// </summary>
/// <remarks>
/// Expected values: window 2000 ms by default (spec US-11), one frame per
/// connection per window with the union of areas, reminder frames never
/// coalesced; area names are the T005 literals. Area <c>spaces</c>
/// (sk-674.18 K-18, US-19): the frame carries the union of the window's
/// <c>spaces</c> entries, an entry equal in all three fields once, at its LAST
/// occurrence (merge rule of the T044 contract, <see cref="PersonalSignal"/>).
/// </remarks>
public class PersonalSignalCoalescerTests
{
    private static readonly Guid Alice = Guid.Parse("0199a1b2-0000-7000-8000-000000000001");
    private static readonly Guid Bob = Guid.Parse("0199a1b2-0000-7000-8000-000000000002");
    private static readonly TimeSpan W = TimeSpan.FromMilliseconds(2000);

    private static FakeTimeProvider NewClock() => new(DateTimeOffset.Parse("2026-10-09T10:00:00Z"));

    private static async Task<HubTestReplica> StartedReplica(
        HubTestWorld world, FakeTimeProvider clock, PersonalSignalOptions? options = null)
    {
        var replica = new HubTestReplica(world, clock, signalOptions: options);
        await replica.StartAsync(1, replica.SignalSubscriber);
        return replica;
    }

    private static async Task Signal(HubTestWorld world, Guid user, params string[] areas)
    {
        world.Nats.Publish($"skein.user.{user}.signal", new { areas, sentAt = "2026-10-09T10:00:00Z" });
        await world.Nats.DrainAsync();
    }

    private static PersonalSignal[] Frames(HubTestWorld world, string connectionId) =>
        world.DeliveriesTo(connectionId, BrowserClientMethods.Signal)
            .Select(d => Assert.IsType<PersonalSignal>(d.Payload))
            .ToArray();

    [Fact]
    public async Task Subscription_HasNoQueueGroup()
    {
        var world = new HubTestWorld();
        using var replica = await StartedReplica(world, NewClock());

        var sub = Assert.Single(world.Nats.Subscriptions);
        Assert.Equal("skein.user.*.signal", sub.Subject);
        Assert.Null(sub.QueueGroup);
    }

    [Fact]
    public async Task FiftySignalsFromTwoPublishersInOneWindow_OneFramePerConnection_UnionOfAreas()
    {
        var world = new HubTestWorld();
        var clock = NewClock();
        using var replica = await StartedReplica(world, clock);
        var tab1 = await replica.ConnectAsync(Alice);
        var tab2 = await replica.ConnectAsync(Alice);

        for (var i = 0; i < 50; i++)
        {
            // Two skein-api replicas publish alternately: their messages interleave on NATS.
            await Signal(world, Alice, i % 2 == 0 ? "inbox" : "watching");
        }
        await Signal(world, Alice, "lens");
        clock.Advance(W - TimeSpan.FromMilliseconds(1));
        Assert.Empty(Frames(world, tab1));
        Assert.Empty(Frames(world, tab2));

        clock.Advance(TimeSpan.FromMilliseconds(1));

        foreach (var tab in new[] { tab1, tab2 })
        {
            var frame = Assert.Single(Frames(world, tab));
            Assert.Equal(new[] { "inbox", "lens", "watching" }, frame.Areas.OrderBy(a => a, StringComparer.Ordinal));
        }
    }

    [Fact]
    public async Task TwoTabsOnTwoWebReplicas_EachGetsExactlyOneFrame()
    {
        var world = new HubTestWorld();
        var clock = NewClock();
        using var r1 = await StartedReplica(world, clock);
        using var r2 = await StartedReplica(world, clock);
        var onR1 = await r1.ConnectAsync(Alice);
        var onR2 = await r2.ConnectAsync(Alice);

        await Signal(world, Alice, "inbox");
        await Signal(world, Alice, "mentions");
        clock.Advance(W);

        Assert.Single(Frames(world, onR1));
        Assert.Single(Frames(world, onR2));
    }

    [Fact]
    public async Task WindowIsKeyedByConnection_LateTabDoesNotJoinAnOpenWindow()
    {
        var world = new HubTestWorld();
        var clock = NewClock();
        using var replica = await StartedReplica(world, clock);
        var c1 = await replica.ConnectAsync(Alice);
        await Signal(world, Alice, "inbox");

        clock.Advance(W / 2);
        var c2 = await replica.ConnectAsync(Alice);
        await Signal(world, Alice, "watching");

        clock.Advance(W / 2); // t0 + W
        var c1Frame = Assert.Single(Frames(world, c1));
        Assert.Equal(new[] { "inbox", "watching" }, c1Frame.Areas.OrderBy(a => a, StringComparer.Ordinal));
        Assert.Empty(Frames(world, c2));

        clock.Advance(W / 2); // t0 + 3W/2
        Assert.Equal(new[] { "watching" }, Assert.Single(Frames(world, c2)).Areas);
        Assert.Single(Frames(world, c1));
    }

    [Fact]
    public async Task SignalAfterTheWindow_OpensTheNextFrame()
    {
        var world = new HubTestWorld();
        var clock = NewClock();
        using var replica = await StartedReplica(world, clock);
        var tab = await replica.ConnectAsync(Alice);

        await Signal(world, Alice, "inbox");
        clock.Advance(W);
        await Signal(world, Alice, "tasks");
        clock.Advance(W);

        var frames = Frames(world, tab);
        Assert.Equal(2, frames.Length);
        Assert.Equal(new[] { "inbox" }, frames[0].Areas);
        Assert.Equal(new[] { "tasks" }, frames[1].Areas);
    }

    [Fact]
    public async Task ConnectionClosedWithinTheWindow_GetsNoFrame_StrangerGetsNothing()
    {
        var world = new HubTestWorld();
        var clock = NewClock();
        using var replica = await StartedReplica(world, clock);
        var closing = await replica.ConnectAsync(Alice);
        var stranger = await replica.ConnectAsync(Bob);

        await Signal(world, Alice, "inbox");
        await replica.DisconnectAsync(closing);
        clock.Advance(W);

        Assert.Empty(world.DeliveriesTo(closing));
        Assert.Empty(world.DeliveriesTo(stranger));
    }

    [Fact]
    public async Task WindowFromConfiguration_500ms()
    {
        var world = new HubTestWorld();
        var clock = NewClock();
        var options = new PersonalSignalOptions { Window = PersonalSignalOptions.ParseWindow("500") };
        using var replica = await StartedReplica(world, clock, options);
        var tab = await replica.ConnectAsync(Alice);

        await Signal(world, Alice, "inbox");
        clock.Advance(TimeSpan.FromMilliseconds(500));

        Assert.Single(Frames(world, tab));
    }

    [Fact]
    public async Task UnsetWindow_Is2000ms_NoFrameAt1999()
    {
        var world = new HubTestWorld();
        var clock = NewClock();
        var options = new PersonalSignalOptions { Window = PersonalSignalOptions.ParseWindow(null) };
        using var replica = await StartedReplica(world, clock, options);
        var tab = await replica.ConnectAsync(Alice);

        await Signal(world, Alice, "inbox");
        clock.Advance(TimeSpan.FromMilliseconds(1999));
        Assert.Empty(Frames(world, tab));
        clock.Advance(TimeSpan.FromMilliseconds(1));
        Assert.Single(Frames(world, tab));
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-5")]
    [InlineData("")]
    [InlineData("2s")]
    public void WindowParse_NonPositiveOrGarbage_RefusesStart(string raw)
    {
        Assert.Throws<InvalidOperationException>(() => PersonalSignalOptions.ParseWindow(raw));
    }

    private static async Task SpacesSignal(HubTestWorld world, Guid user, string[] areas, params object[] spaces)
    {
        world.Nats.Publish($"skein.user.{user}.signal", new { areas, spaces, sentAt = "2026-10-12T10:00:00Z" });
        await world.Nats.DrainAsync();
    }

    [Fact]
    public async Task SpacesReasons_FromSeveralSignalsOfOneWindow_AllArrive_EachDistinctEntryOnceAtItsLastOccurrence()
    {
        // Row 222 (K-18): no reason is lost, a repeated entry is not doubled.
        var world = new HubTestWorld();
        var clock = NewClock();
        using var replica = await StartedReplica(world, clock);
        var tab = await replica.ConnectAsync(Alice);

        await SpacesSignal(world, Alice, ["spaces"], new { reason = "invited", spaceId = "k3x9p2qa", spaceName = "Acme" });
        await Signal(world, Alice, "inbox");
        await SpacesSignal(world, Alice, ["spaces", "projects"],
            new { reason = "added", spaceId = "b7m2c4zz", spaceName = "Beta" },
            new { reason = "renamed", spaceId = "k3x9p2qa", spaceName = "Acme Ltd" });
        await SpacesSignal(world, Alice, ["spaces"], new { reason = "renamed", spaceId = "k3x9p2qa", spaceName = "Acme" });
        await SpacesSignal(world, Alice, ["spaces"], new { reason = "invited", spaceId = "k3x9p2qa", spaceName = "Acme" });
        clock.Advance(W);

        var frame = Assert.Single(Frames(world, tab));
        Assert.Equal(new[] { "inbox", "projects", "spaces" }, frame.Areas.OrderBy(a => a, StringComparer.Ordinal));
        Assert.Equal(
            new[]
            {
                new PersonalSignalSpace("added", "b7m2c4zz", "Beta"),
                new PersonalSignalSpace("renamed", "k3x9p2qa", "Acme Ltd"),
                new PersonalSignalSpace("renamed", "k3x9p2qa", "Acme"),
                new PersonalSignalSpace("invited", "k3x9p2qa", "Acme"),
            },
            frame.Spaces);
    }

    [Fact]
    public async Task WindowWithoutTheSpacesArea_CarriesNoSpacesField()
    {
        // Row 222: the other areas as before — no payload.
        var world = new HubTestWorld();
        var clock = NewClock();
        using var replica = await StartedReplica(world, clock);
        var tab = await replica.ConnectAsync(Alice);

        await Signal(world, Alice, "inbox");
        await Signal(world, Alice, "projects");
        clock.Advance(W);

        var frame = Assert.Single(Frames(world, tab));
        Assert.Null(frame.Spaces);
    }

    [Fact]
    public async Task ProjectsAreaFromControlPath_JoinsTheSameWindow()
    {
        var world = new HubTestWorld();
        var clock = NewClock();
        using var replica = await StartedReplica(world, clock);
        var tab = await replica.ConnectAsync(Alice);

        await Signal(world, Alice, "inbox");
        replica.Coalescer.SignalConnection(tab, ["projects"]);
        clock.Advance(W);

        var frame = Assert.Single(Frames(world, tab));
        Assert.Equal(new[] { "inbox", "projects" }, frame.Areas.OrderBy(a => a, StringComparer.Ordinal));
    }

    [Fact]
    public async Task ReminderFramesAreNotCoalesced_SignalStillIs()
    {
        // No. 62a: bridge and subscriber of one replica started on one NATS connection.
        var world = new HubTestWorld();
        var clock = NewClock();
        using var replica = new HubTestReplica(world, clock);
        await replica.StartAsync(3, replica.Bridge, replica.SignalSubscriber);
        var tab = await replica.ConnectAsync(Alice);

        object Reminder(string firing) => new
        {
            reminderId = "0199a1b2-0000-7000-8000-0000000000f1",
            issueId = "sk-1",
            projectId = "0199a1b2-0000-7000-8000-0000000000a1",
            kind = "rang",
            remindAt = "2026-10-09T10:00:00Z",
            firingId = firing,
        };
        world.Nats.Publish($"skein.user.{Alice}.reminder", Reminder("0199a1b2-0000-7000-8000-0000000000f1@2026-10-09T10:00:00Z"));
        world.Nats.Publish($"skein.user.{Alice}.signal", new { areas = new[] { "inbox" }, sentAt = "2026-10-09T10:00:00Z" });
        world.Nats.Publish($"skein.user.{Alice}.reminder", Reminder("0199a1b2-0000-7000-8000-0000000000f1@2026-10-09T10:00:01Z"));
        await world.Nats.DrainAsync();

        // Before any clock movement: both reminder frames are there, no signal yet.
        var reminders = world.DeliveriesTo(tab, BrowserClientMethods.Reminder)
            .Select(d => Assert.IsType<ReminderFrame>(d.Payload).FiringId)
            .ToArray();
        Assert.Equal(
            new[]
            {
                "0199a1b2-0000-7000-8000-0000000000f1@2026-10-09T10:00:00Z",
                "0199a1b2-0000-7000-8000-0000000000f1@2026-10-09T10:00:01Z",
            },
            reminders);
        Assert.Empty(Frames(world, tab));

        clock.Advance(W);
        Assert.Equal(new[] { "inbox" }, Assert.Single(Frames(world, tab)).Areas);
    }
}
