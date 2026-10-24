using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Moq;
using SkeinWeb.Auth;
using SkeinWeb.Hubs;

namespace SkeinWeb.Tests.Hubs;

/// <summary>
/// INV-26 on the hub (sk-674.18 T049): a session that has ended stops receiving hub frames. The replica
/// that ends it — skein-api's <c>session_revoked</c> answered to a request of
/// that session (<see cref="SessionRevocation.EndSessionAsync"/>) — closes its
/// connections of that session at once; any other replica closes its own on
/// the access re-check once the session ticket is gone from the shared store.
/// Connections of another session of the same user keep receiving.
/// </summary>
/// <remarks>
/// The replicas, the hub, the bridge, the registry and the re-check are the
/// product's; the SignalR transport, skein-api, NATS and Redis are the shared
/// fakes of <see cref="HubTestWorld"/>. A server-side abort is played as
/// SignalR plays it — the connection is forgotten and leaves its groups.
/// </remarks>
public class HubSessionRevocationTests
{
    private static readonly Guid Alice = Guid.Parse("0199a1b2-0000-7000-8000-000000000001");
    private static readonly Guid P = Guid.Parse("0199a1b2-0000-7000-8000-0000000000a1");
    private const string RevokedKey = "skein:session:revoked";
    private const string LiveKey = "skein:session:live";
    private static readonly TimeSpan Period = TimeSpan.FromSeconds(30);

    private static object IssueEvent(long id) => new
    {
        id,
        occurredAt = "2026-10-12T10:00:00Z",
        eventType = "issue.updated",
        entityType = "issue",
        entityId = "sk-1",
        projectId = P,
        payload = new { changes = new[] { new { field = "status" } } },
    };

    private static Task SendEventAsync(HubTestReplica replica, long id) =>
        replica.DispatchAsync($"skein.events.project.{P}.issue.updated.sk-1", IssueEvent(id));

    /// <summary>A request of the session <paramref name="sessionKey"/> on <paramref name="replica"/>.</summary>
    private static DefaultHttpContext RequestOf(HubTestReplica replica, string sessionKey)
    {
        var auth = new Mock<IAuthenticationService>();
        auth.Setup(a => a.SignOutAsync(It.IsAny<HttpContext>(), It.IsAny<string?>(), It.IsAny<AuthenticationProperties?>()))
            .Returns(Task.CompletedTask);
        var services = new ServiceCollection();
        services.AddSingleton(auth.Object);
        services.AddSingleton(replica.Registry);
        return new DefaultHttpContext
        {
            RequestServices = services.BuildServiceProvider(),
            User = new ClaimsPrincipal(new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.NameIdentifier, Alice.ToString()),
                    new Claim(SessionPrincipal.SessionKeyClaim, sessionKey),
                ],
                CookieAuthenticationDefaults.AuthenticationScheme)),
        };
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
    public async Task SessionEndedOnThisReplica_ItsConnectionGetsNoMoreFrames_AtOnce()
    {
        var world = new HubTestWorld();
        world.AccessApi.SetUser(Alice, memberOf: P);
        using var replica = new HubTestReplica(world, new FakeTimeProvider(DateTimeOffset.Parse("2026-10-12T10:00:00Z")));
        var revoked = await replica.ConnectAsync(Alice, sessionKey: RevokedKey);
        var live = await replica.ConnectAsync(Alice, sessionKey: LiveKey);
        await replica.DeclareAsync(revoked, P);
        await replica.DeclareAsync(live, P);
        await SendEventAsync(replica, 1);
        // Positive control: both connections are in the project's delivery.
        Assert.Single(world.DeliveriesTo(revoked, BrowserClientMethods.Event));
        Assert.Single(world.DeliveriesTo(live, BrowserClientMethods.Event));

        // skein-api answered session_revoked to a request of the revoked session.
        await SessionRevocation.EndSessionAsync(RequestOf(replica, RevokedKey));
        await SendEventAsync(replica, 2);

        Assert.Equal([revoked], replica.Aborted);
        Assert.Single(world.DeliveriesTo(revoked, BrowserClientMethods.Event));
        Assert.Equal(2, world.DeliveriesTo(live, BrowserClientMethods.Event).Count);
    }

    [Fact]
    public async Task TicketKeyHandedToAnotherUser_PreviousOwnersConnectionOnAnotherReplica_IsClosedByTheRecheck()
    {
        // Bob logged in in Alice's tab — the key is Bob's now.
        // Alice's connection opened with it must stop receiving Alice's frames;
        // Bob's new connection with the same key stays.
        var world = new HubTestWorld();
        world.AccessApi.SetUser(Alice, memberOf: P);
        var bob = Guid.Parse("0199a1b2-0000-7000-8000-000000000002");
        world.AccessApi.SetUser(bob);
        var clock = new FakeTimeProvider(DateTimeOffset.Parse("2026-10-12T10:00:00Z"));
        using var other = new HubTestReplica(world, clock);
        await other.StartAsync(0, other.Recheck);
        var aliceConn = await other.ConnectAsync(Alice, sessionKey: RevokedKey);
        await other.DeclareAsync(aliceConn, P);

        world.Tickets.SetOwner(RevokedKey, bob);
        var bobConn = await other.ConnectAsync(bob, sessionKey: RevokedKey);
        clock.Advance(Period);
        await Eventually(() => other.Aborted.Contains(aliceConn), "previous owner's connection closed");
        await SendEventAsync(other, 1);

        Assert.Equal([aliceConn], other.Aborted);
        Assert.Empty(world.DeliveriesTo(aliceConn));
        Assert.NotNull(other.Registry.Get(bobConn));
    }

    [Fact]
    public async Task TicketGone_ConnectionIsClosedAtTheFirstTick_EvenWhileTheAccessRecheckHangs()
    {
        // the ticket sweep has its own 30 s period; an access
        // re-check hanging on skein-api does not hold it back.
        var world = new HubTestWorld();
        world.AccessApi.SetUser(Alice, memberOf: P);
        var clock = new FakeTimeProvider(DateTimeOffset.Parse("2026-10-12T10:00:00Z"));
        using var other = new HubTestReplica(world, clock);
        await other.StartAsync(0, other.Recheck);
        var revoked = await other.ConnectAsync(Alice, sessionKey: RevokedKey);
        await other.DeclareAsync(revoked, P);
        world.AccessApi.HoldCalls = true;
        world.Tickets.Remove(RevokedKey);
        try
        {
            clock.Advance(Period);
            await Eventually(() => world.AccessApi.Held >= 1, "the access re-check hangs on skein-api");
            await Eventually(() => other.Aborted.Contains(revoked), "closed at the first tick");
            Assert.Equal(1, world.AccessApi.Held); // still hanging when the connection was closed
        }
        finally
        {
            world.AccessApi.ReleaseHeld();
        }
    }

    [Fact]
    public async Task TicketGone_ConnectionOnAnotherReplica_IsClosedByTheRecheck()
    {
        var world = new HubTestWorld();
        world.AccessApi.SetUser(Alice, memberOf: P);
        var clock = new FakeTimeProvider(DateTimeOffset.Parse("2026-10-12T10:00:00Z"));
        using var other = new HubTestReplica(world, clock);
        await other.StartAsync(0, other.Recheck);
        var revoked = await other.ConnectAsync(Alice, sessionKey: RevokedKey);
        var live = await other.ConnectAsync(Alice, sessionKey: LiveKey);
        await other.DeclareAsync(revoked, P);
        await other.DeclareAsync(live, P);

        // A sweep with both tickets alive closes nothing (positive control):
        // both connections probed, then neither closed.
        var probes = world.Tickets.Probes;
        clock.Advance(Period);
        await Eventually(() => world.Tickets.Probes >= probes + 2, "first sweep probed both connections");
        Assert.Empty(other.Aborted);

        // The session ended on another replica: its ticket is gone from the shared store.
        // The control's sweep may still be finishing when the clock moves (a tick
        // during a running sweep is skipped), so the next periods are given too;
        // closing at the very first tick is the subject of
        // TicketGone_ConnectionIsClosedAtTheFirstTick_EvenWhileTheAccessRecheckHangs.
        world.Tickets.Remove(RevokedKey);
        for (var period = 0; period < 3 && !other.Aborted.Contains(revoked); period++)
        {
            clock.Advance(Period);
            for (var i = 0; i < 200 && !other.Aborted.Contains(revoked); i++)
            {
                await Task.Delay(5);
            }
        }
        Assert.Contains(revoked, other.Aborted);
        await SendEventAsync(other, 1);

        Assert.Equal([revoked], other.Aborted);
        Assert.Empty(world.DeliveriesTo(revoked, BrowserClientMethods.Event));
        Assert.Single(world.DeliveriesTo(live, BrowserClientMethods.Event));
    }
}
