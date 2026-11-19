using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging.Abstractions;
using SkeinWeb.Hubs;
using SkeinWeb.Tests.Auth;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Hubs;

/// <summary>
/// SC-006, US-4: whatever ends a session — a rotation through the real issuer, or the row expiring in
/// Redis by either limit — its connections close at once on the replica that rotated, and on another
/// replica at the first successful probe of that connection after the row is gone. The period of the
/// re-check is nominal, not an upper bound: a probe that fails technically closes nothing, and the next
/// one that succeeds does. Losing the index member (R-1) may close a connection earlier; a reconnect
/// that reads the ticket restores the member. A control session of the same user is untouched. The
/// first replica is the pipeline stand (real rotation, real hub endpoint); the sweeps are the real
/// <see cref="AccessRecheckService"/> on the stand's fake clock, with the real store as their probe,
/// over the registry of another replica or of the stand's own.
/// </summary>
/// <remarks>
/// A round is observed, never waited for by a pause: the clock moves one period on until the probe of
/// the key is seen (a tick that lands while the previous sweep still runs is skipped by the service, so
/// one tick is not enough). Sweeps never overlap, so the start of the next sweep proves the previous one
/// has handled its answers: "nothing closed" is read at the next sweep's probe of the same key
/// (<see cref="Sweeper.FenceAsync"/>).
/// </remarks>
[Trait("Category", "Integration")]
[Collection("session-pipeline")]
public sealed class SessionRevocationAcrossReplicasIntegrationTest
{
    private static readonly Guid User = Guid.Parse("0199a1b2-0000-7000-8000-00000000000a");

    private static async Task<bool> UntilAsync(Func<bool> condition)
    {
        for (var i = 0; i < 250; i++)
        {
            if (condition())
            {
                return true;
            }
            await Task.Delay(20);
        }
        return condition();
    }

    private static string Connection(SessionPipelineHost.Reply reply) =>
        JsonDocument.Parse(reply.Body).RootElement.GetProperty("connection").GetString()!;

    /// <summary>Whether the replica closed <paramref name="connection"/>, read under the lock its closes take.</summary>
    private static bool Closed(HubTestReplica replica, string connection)
    {
        lock (replica.Aborted)
        {
            return replica.Aborted.Contains(connection);
        }
    }

    private static string IndexKey => "skein:user-tickets:" + User;

    private static bool IsProbeOf(string name, object?[] args, string? key) =>
        name == nameof(IDatabase.SetContainsAsync)
        && (key is null || (args[1] is RedisValue member && (string?)member == key));

    /// <summary>The real re-check service over the registry of <paramref name="replica"/>, probing through its own proxied store.</summary>
    private sealed class Sweeper : IAsyncDisposable
    {
        private readonly SessionPipelineHost _host;
        private readonly AccessRecheckService _service;

        private Sweeper(SessionPipelineHost host, HubTestReplica replica, DbProxy faults, AccessRecheckService service)
        {
            _host = host;
            Replica = replica;
            Faults = faults;
            _service = service;
        }

        public HubTestReplica Replica { get; }
        public DbProxy Faults { get; }

        public static async Task<Sweeper> StartAsync(SessionPipelineHost host, HubTestReplica replica)
        {
            var db = DbProxy.Create(host.Db, out var faults);
            var service = new AccessRecheckService(replica.Registry, replica.Access, replica.HubContext, replica.Nats, host.Time,
                NullLogger<AccessRecheckService>.Instance, TestRedis.Store(TestRedis.Over(host.Mux, db)));
            await service.StartAsync(CancellationToken.None);
            return new Sweeper(host, replica, faults, service);
        }

        /// <summary>Moves the clock one period on at a time until <paramref name="seen"/> completes; false after 10 s.</summary>
        private async Task<bool> TickUntilAsync(Task seen)
        {
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (!seen.IsCompleted && DateTime.UtcNow < deadline)
            {
                _host.Time.Advance(AccessRecheckService.Interval);
                await Task.WhenAny(seen, Task.Delay(100));
            }
            return seen.IsCompleted;
        }

        /// <summary>
        /// A round in which the probe of <paramref name="key"/> is sent; with <paramref name="failing"/> it fails
        /// technically. Returns once the probe has been sent (its answer may still be handled).
        /// </summary>
        public async Task RoundAsync(string key, bool failing = false)
        {
            var probed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            Faults.Before = (name, args) =>
            {
                if (!IsProbeOf(name, args, key))
                {
                    return null;
                }
                probed.TrySetResult();
                return failing ? new InvalidOperationException("injected") : null;
            };
            var ran = await TickUntilAsync(probed.Task);
            Faults.Before = null;
            Assert.True(ran, "precondition: no round probed the key within 10 s");
        }

        /// <summary>
        /// Starts the next sweep and reads, at its probe of <paramref name="key"/> (every probe of it fails, so it
        /// closes nothing), whether <paramref name="connection"/> was closed: a sweep probes each connection
        /// once and <paramref name="connection"/> is the only one of that key, so this probe belongs to a later
        /// sweep, and by then every earlier sweep has handled its answers. A closed connection is not probed
        /// any more; then no such probe comes and the close is read at the end of the wait.
        /// </summary>
        public async Task<bool> FenceAsync(string connection, string key)
        {
            var started = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            Faults.Before = (name, args) =>
            {
                if (IsProbeOf(name, args, key))
                {
                    started.TrySetResult(Closed(Replica, connection));
                }
                return IsProbeOf(name, args, key: null) ? new InvalidOperationException("fence") : null;
            };
            var ran = await TickUntilAsync(started.Task);
            Faults.Before = null;
            if (!ran)
            {
                // No sweep probed the key: only possible when its connection is closed.
                Assert.True(Closed(Replica, connection), "precondition: no sweep probed the key within 10 s");
                return true;
            }
            return await started.Task;
        }

        public async ValueTask DisposeAsync()
        {
            Faults.Before = null;
            await _service.StopAsync(CancellationToken.None);
            _service.Dispose();
        }
    }

    [RedisFact]
    public async Task ARotation_ClosesAtOnceOnTheRotatingReplica_AndOnTheFirstRoundOfTheOther_WhileTheControlLives()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        host.Replica.World.AccessApi.SetUser(User);
        using var second = new HubTestReplica(host.Replica.World, host.Time);
        await using var sweeper = await Sweeper.StartAsync(host, second);

        var (oldCookie, oldKey, _) = await host.SignInAsync(User);
        var (controlCookie, controlKey, _) = await host.SignInAsync(User);
        var oldOn1 = Connection(await host.SendAsync("/test/hub", oldCookie));
        var controlOn1 = Connection(await host.SendAsync("/test/hub", controlCookie));
        var oldOn2 = await second.ConnectAsync(User, sessionKey: oldKey);
        var controlOn2 = await second.ConnectAsync(User, sessionKey: controlKey);

        // The real rotation on the first replica.
        var rotated = await host.SendAsync($"/test/issue?user={User}", oldCookie);
        Assert.Single(rotated.Sessions(host.CookieName));
        Assert.True(Closed(host.Replica, oldOn1));
        Assert.False(Closed(second, oldOn2));

        // While the store of the second replica does not answer for that key, the connection stays.
        await sweeper.RoundAsync(oldKey, failing: true);
        Assert.False(await sweeper.FenceAsync(oldOn2, oldKey));

        // The store answers again: the next round closes it.
        await sweeper.RoundAsync(oldKey);
        Assert.True(await UntilAsync(() => Closed(second, oldOn2)), "the other replica did not close the old key");

        Assert.False(Closed(host.Replica, controlOn1));
        Assert.False(Closed(second, controlOn2));
        Assert.True(await host.Db.KeyExistsAsync(controlKey));
    }

    // SC-006, US-4, E-4: the row of a session expires in Redis — (a) at the end of the session: its window
    // ends about 2 s after the read of a request, which sets the row's lifetime to the time left; (b) idle:
    // the test sets the lifetime to 2 s. A round while the row lives closes nothing and does not move the
    // lifetime; after the row is gone a probe that fails technically closes nothing; the next successful
    // round closes the connection; the control session of the same user lives.
    [RedisTheory]
    [InlineData("absolute")]
    [InlineData("idle")]
    public async Task ARowExpiredInRedis_IsClosedByTheFirstSuccessfulRoundAfterItIsGone_WhileTheControlLives(string ending)
    {
        await using var host = await SessionPipelineHost.StartAsync();
        host.Replica.World.AccessApi.SetUser(User);
        using var second = new HubTestReplica(host.Replica.World, host.Time);
        await using var sweeper = await Sweeper.StartAsync(host, second);
        var (cookie, key, _) = await host.SignInAsync(User);
        var (_, controlKey, _) = await host.SignInAsync(User);
        var connection = await second.ConnectAsync(User, sessionKey: key);
        var control = await second.ConnectAsync(User, sessionKey: controlKey);

        if (ending == "absolute")
        {
            // A window ending at a whole second (the precision of a stored ticket) 2–3 s ahead, read on a
            // replica clock set to real time: the read sets the lifetime of the row to the time left.
            var end = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3);
            var ticket = TicketSerializer.Default.Deserialize((byte[])(await host.Db.StringGetAsync(key))!)!;
            ticket.Properties.IssuedUtc = end.AddHours(-1);
            ticket.Properties.ExpiresUtc = end;
            await host.Db.StringSetAsync(key, TicketSerializer.Default.Serialize(ticket), TimeSpan.FromMinutes(1));
            host.Time.SetUtcNow(DateTimeOffset.UtcNow);
            var left = end - host.Time.GetUtcNow();
            Assert.Equal(HttpStatusCode.OK, (await host.SendAsync("/test/me", cookie)).Status);
            var lifetime = await host.Db.KeyTimeToLiveAsync(key);
            Assert.True(lifetime is { } l && l > TimeSpan.Zero && l <= left,
                $"the read did not set the lifetime to the time left ({lifetime}, {left} left)");
        }
        else
        {
            Assert.True(await host.Db.KeyExpireAsync(key, TimeSpan.FromSeconds(2)));
        }
        var lifetimeBefore = await host.Db.KeyTimeToLiveAsync(key);

        await sweeper.RoundAsync(key);
        var closedWhileAlive = await sweeper.FenceAsync(connection, key);

        var lifetimeAfter = await host.Db.KeyTimeToLiveAsync(key);
        Assert.True(lifetimeAfter is not null, "precondition: the row expired before the round was handled");
        Assert.False(closedWhileAlive); // the row lives: nothing closes
        Assert.True(lifetimeAfter <= lifetimeBefore, "the probe moved the lifetime of the row");

        Assert.True(await UntilAsync(() => !host.Db.KeyExists(key)), "precondition: the row did not expire in Redis");

        await sweeper.RoundAsync(key, failing: true);
        Assert.False(await sweeper.FenceAsync(connection, key)); // a failed probe is not an expiry

        await sweeper.RoundAsync(key);
        Assert.True(await UntilAsync(() => Closed(second, connection)),
            "the first successful round after the row is gone did not close the connection");

        Assert.False(Closed(second, control));
        Assert.True(await host.Db.KeyExistsAsync(controlKey));
    }

    // US-4, R-1, INV-5, on the connections the hub handshake opens: the index member of a live row removed by
    // the test → the next round closes the connection before the row expires. A reconnect while the index is
    // spoiled (another type) is admitted and does not restore the member; the probe through the spoiled index
    // fails technically, so the round closes nothing; with the spoiled key deleted the round closes the
    // connection without a member. Once the index is repaired a reconnect restores the member (and, reading
    // the ticket, moves the row's lifetime) and the next round closes nothing; once the row is gone a
    // reconnect is refused and creates nothing.
    [RedisFact]
    public async Task ALostIndexMember_ClosesEarly_AReconnectRestoresIt_AndWithoutTheRowNothingIsRestored()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        host.Replica.World.AccessApi.SetUser(User);
        await using var sweeper = await Sweeper.StartAsync(host, host.Replica);
        var (cookie, key, _) = await host.SignInAsync(User);
        var first = Connection(await host.SendAsync("/test/hub", cookie));

        // The member of a live row is lost: the round closes the connection early.
        Assert.True(await host.Db.SetRemoveAsync(IndexKey, key));
        await sweeper.RoundAsync(key);
        Assert.True(await UntilAsync(() => Closed(host.Replica, first)), "a connection without its member stayed");
        Assert.True(await host.Db.KeyExistsAsync(key)); // earlier than the expiry of the row

        // A reconnect while the index is of another type: admitted, the member is not restored.
        await host.Db.KeyDeleteAsync(IndexKey);
        await host.Db.StringSetAsync(IndexKey, "not-a-set");
        var spoiled = await host.SendAsync("/test/hub", cookie);
        Assert.Equal(HttpStatusCode.OK, spoiled.Status);
        var second = Connection(spoiled);
        Assert.Equal(RedisType.String, await host.Db.KeyTypeAsync(IndexKey));

        // The probe through the spoiled index fails technically: the round closes nothing.
        await sweeper.RoundAsync(key);
        Assert.False(await sweeper.FenceAsync(second, key));

        // The spoiled key deleted: the index is readable and has no member, the round closes the connection.
        await host.Db.KeyDeleteAsync(IndexKey);
        await sweeper.RoundAsync(key);
        Assert.True(await UntilAsync(() => Closed(host.Replica, second)), "the round did not close the connection without a member");

        // The index repaired: a reconnect reads the ticket, restores the member and moves the row's lifetime.
        Assert.True(await host.Db.KeyExpireAsync(key, TimeSpan.FromSeconds(60)));
        var restored = Connection(await host.SendAsync("/test/hub", cookie));
        Assert.True(await host.Db.SetContainsAsync(IndexKey, key));
        Assert.True(await host.Db.KeyTimeToLiveAsync(key) > TimeSpan.FromHours(1));
        await sweeper.RoundAsync(key);
        Assert.False(await sweeper.FenceAsync(restored, key));

        // The row gone: the reconnect is refused, registers no connection and creates no row.
        Assert.True(await host.Db.KeyExpireAsync(key, TimeSpan.FromMilliseconds(100)));
        Assert.True(await UntilAsync(() => !host.Db.KeyExists(key)), "precondition: the row did not expire in Redis");
        var registered = host.Replica.Registry.All().Count;
        var reply = await host.SendAsync("/test/hub", cookie);
        Assert.Equal(HttpStatusCode.Unauthorized, reply.Status);
        Assert.Equal(registered, host.Replica.Registry.All().Count);
        Assert.False(await host.Db.KeyExistsAsync(key));
        Assert.Empty(reply.Sessions(host.CookieName));
    }
}
