using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging.Abstractions;
using SkeinWeb.Auth;
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
/// first replica is the pipeline stand (real rotation, real hub endpoint); the second is another
/// registry on the same Redis with the real <see cref="AccessRecheckService"/> on the stand's fake
/// clock and the real store as its probe.
/// </summary>
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

    private static string IndexKey => "skein:user-tickets:" + User;

    /// <summary>The second replica with the real re-check service over its own proxied store, on the stand's clock.</summary>
    private sealed class SecondReplica : IAsyncDisposable
    {
        private SecondReplica(HubTestReplica replica, DbProxy faults, AccessRecheckService service)
        {
            Replica = replica;
            Faults = faults;
            Service = service;
        }

        public HubTestReplica Replica { get; }
        public DbProxy Faults { get; }
        private AccessRecheckService Service { get; }

        public static async Task<SecondReplica> StartAsync(SessionPipelineHost host)
        {
            var replica = new HubTestReplica(host.Replica.World, host.Time);
            var db = DbProxy.Create(host.Db, out var faults);
            var service = new AccessRecheckService(replica.Registry, replica.Access, replica.HubContext, replica.Nats, host.Time,
                NullLogger<AccessRecheckService>.Instance, TestRedis.Store(TestRedis.Over(host.Mux, db)));
            await service.StartAsync(CancellationToken.None);
            return new SecondReplica(replica, faults, service);
        }

        /// <summary>
        /// One round of the session sweep: the clock moves one period on and the probe of <paramref name="key"/>
        /// is awaited (its ownership lookup completed), then the handling of its answer.
        /// </summary>
        public async Task RoundAsync(SessionPipelineHost host, string key)
        {
            var probed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            Faults.After = (name, args) =>
            {
                if (name == nameof(IDatabase.SetContainsAsync) && args[1] is RedisValue member && (string?)member == key)
                {
                    probed.TrySetResult();
                }
                return Task.CompletedTask;
            };
            host.Time.Advance(AccessRecheckService.Interval);
            await probed.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Task.Delay(50); // the answer of the probe is handled right after
            Faults.After = null;
        }

        /// <summary>A round whose probe of <paramref name="key"/> fails technically.</summary>
        public async Task FailedRoundAsync(SessionPipelineHost host, string key)
        {
            var probed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            Faults.Before = (name, args) =>
            {
                if (name == nameof(IDatabase.SetContainsAsync) && args[1] is RedisValue member && (string?)member == key)
                {
                    probed.TrySetResult();
                    return new InvalidOperationException("injected");
                }
                return null;
            };
            host.Time.Advance(AccessRecheckService.Interval);
            await probed.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Task.Delay(50); // the failed probe is handled right after; nothing may close
            Faults.Before = null;
        }

        public async ValueTask DisposeAsync()
        {
            await Service.StopAsync(CancellationToken.None);
            Service.Dispose();
            Replica.Dispose();
        }
    }

    [RedisFact]
    public async Task ARotation_ClosesAtOnceOnTheRotatingReplica_AndOnTheFirstRoundOfTheOther_WhileTheControlLives()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var world = host.Replica.World;
        world.AccessApi.SetUser(User);
        using var second = new HubTestReplica(world, host.Time);
        var secondDb = DbProxy.Create(host.Db, out var secondFaults);
        var secondStore = TestRedis.Store(TestRedis.Over(host.Mux, secondDb));

        var (oldCookie, oldKey, _) = await host.SignInAsync(User);
        var (controlCookie, controlKey, _) = await host.SignInAsync(User);
        var oldOn1 = Connection(await host.SendAsync("/test/hub", oldCookie));
        var controlOn1 = Connection(await host.SendAsync("/test/hub", controlCookie));
        var oldOn2 = await second.ConnectAsync(User, sessionKey: oldKey);
        var controlOn2 = await second.ConnectAsync(User, sessionKey: controlKey);

        using var service2 = new AccessRecheckService(second.Registry, second.Access, second.HubContext, second.Nats, host.Time,
            NullLogger<AccessRecheckService>.Instance, secondStore);
        await service2.StartAsync(CancellationToken.None);

        // The real rotation on the first replica.
        var rotated = await host.SendAsync($"/test/issue?user={User}", oldCookie);
        Assert.Single(rotated.Sessions(host.CookieName));
        Assert.Contains(oldOn1, host.Replica.Aborted);
        Assert.DoesNotContain(oldOn2, second.Aborted);

        // While the store of the second replica does not answer for that key, the connection stays:
        // wait for the probe of exactly that key to have run, not for a pause.
        var probed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        secondFaults.Before = (name, args) =>
        {
            if (name == nameof(IDatabase.SetContainsAsync) && args[1] is RedisValue member && (string?)member == oldKey)
            {
                probed.TrySetResult();
                return new InvalidOperationException("injected");
            }
            return null;
        };
        host.Time.Advance(AccessRecheckService.Interval);
        await probed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        await Task.Delay(50); // the failed probe is handled right after; nothing may close
        Assert.DoesNotContain(oldOn2, second.Aborted);

        // The store answers again: the next round closes it.
        secondFaults.Before = null;
        host.Time.Advance(AccessRecheckService.Interval);
        Assert.True(await UntilAsync(() => second.Aborted.Contains(oldOn2)), "the other replica did not close the old key");

        Assert.DoesNotContain(controlOn1, host.Replica.Aborted);
        Assert.DoesNotContain(controlOn2, second.Aborted);
        Assert.True(await host.Db.KeyExistsAsync(controlKey));
    }

    // SC-006, US-4, E-4: the row of a session expires in Redis — (a) at the end of the session: its window
    // ends about 300 ms after the read of a request, which sets the row's lifetime to the time left; (b) idle:
    // the test sets the lifetime to 300 ms. A round while the row lives closes nothing and does not move the
    // lifetime; after the row is gone a probe that fails technically closes nothing; the next successful
    // round closes the connection; the control session of the same user lives.
    [RedisTheory]
    [InlineData("absolute")]
    [InlineData("idle")]
    public async Task ARowExpiredInRedis_IsClosedByTheFirstSuccessfulRoundAfterItIsGone_WhileTheControlLives(string ending)
    {
        await using var host = await SessionPipelineHost.StartAsync();
        host.Replica.World.AccessApi.SetUser(User);
        await using var second = await SecondReplica.StartAsync(host);
        var (cookie, key, _) = await host.SignInAsync(User);
        var (_, controlKey, _) = await host.SignInAsync(User);
        var connection = await second.Replica.ConnectAsync(User, sessionKey: key);
        var control = await second.Replica.ConnectAsync(User, sessionKey: controlKey);

        if (ending == "absolute")
        {
            // A window ending at a whole second (the precision of a stored ticket), read about 300 ms before
            // that end on a replica clock set to real time.
            var end = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 2);
            var ticket = TicketSerializer.Default.Deserialize((byte[])(await host.Db.StringGetAsync(key))!)!;
            ticket.Properties.IssuedUtc = end.AddHours(-1);
            ticket.Properties.ExpiresUtc = end;
            await host.Db.StringSetAsync(key, TicketSerializer.Default.Serialize(ticket), TimeSpan.FromMinutes(1));
            await Task.Delay(end.AddMilliseconds(-300) - DateTimeOffset.UtcNow);
            host.Time.SetUtcNow(DateTimeOffset.UtcNow);
            Assert.Equal(HttpStatusCode.OK, (await host.SendAsync("/test/me", cookie)).Status);
            var left = await host.Db.KeyTimeToLiveAsync(key);
            Assert.True(left is { } l && l <= TimeSpan.FromMilliseconds(350),
                $"precondition: the read did not set the lifetime to the time left ({left})");
        }
        else
        {
            Assert.True(await host.Db.KeyExpireAsync(key, TimeSpan.FromMilliseconds(300)));
        }
        var lifetimeBefore = await host.Db.KeyTimeToLiveAsync(key);

        await second.RoundAsync(host, key);

        var lifetimeAfter = await host.Db.KeyTimeToLiveAsync(key);
        Assert.True(lifetimeAfter is not null, "precondition: the row expired before the round");
        Assert.DoesNotContain(connection, second.Replica.Aborted); // the row lives: nothing closes
        Assert.True(lifetimeAfter <= lifetimeBefore, "the probe moved the lifetime of the row");

        Assert.True(await UntilAsync(() => !host.Db.KeyExists(key)), "precondition: the row did not expire in Redis");

        await second.FailedRoundAsync(host, key);
        Assert.DoesNotContain(connection, second.Replica.Aborted); // a failed probe is not an expiry

        host.Time.Advance(AccessRecheckService.Interval);
        Assert.True(await UntilAsync(() => second.Replica.Aborted.Contains(connection)),
            "the first successful round after the row is gone did not close the connection");

        Assert.DoesNotContain(control, second.Replica.Aborted);
        Assert.True(await host.Db.KeyExistsAsync(controlKey));
    }

    // US-4, R-1, INV-5: the index member of a live row removed by the test → the next round closes the
    // connection before the row expires. A reconnect while the index is spoiled (another type) is admitted but
    // does not restore the member, so the next round closes the new connection again; once the index is
    // repaired a reconnect restores the member (and, reading the ticket, moves the row's lifetime) and the
    // next round closes nothing; once the row is gone a reconnect is refused and creates nothing.
    [RedisFact]
    public async Task ALostIndexMember_ClosesEarly_AReconnectRestoresIt_AndWithoutTheRowNothingIsRestored()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        host.Replica.World.AccessApi.SetUser(User);
        await using var second = await SecondReplica.StartAsync(host);
        var (cookie, key, _) = await host.SignInAsync(User);
        var first = await second.Replica.ConnectAsync(User, sessionKey: key);

        // The member of a live row is lost: the round closes the connection early.
        Assert.True(await host.Db.SetRemoveAsync(IndexKey, key));
        await second.RoundAsync(host, key);
        Assert.True(await UntilAsync(() => second.Replica.Aborted.Contains(first)), "a connection without its member stayed");
        Assert.True(await host.Db.KeyExistsAsync(key)); // earlier than the expiry of the row

        // A reconnect while the index is of another type: admitted, the member is not restored.
        await host.Db.KeyDeleteAsync(IndexKey);
        await host.Db.StringSetAsync(IndexKey, "not-a-set");
        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync("/test/hub", cookie)).Status);
        Assert.Equal(RedisType.String, await host.Db.KeyTypeAsync(IndexKey));
        var spoiled = await second.Replica.ConnectAsync(User, sessionKey: key);
        await host.Db.KeyDeleteAsync(IndexKey); // readable again, without the member
        await second.RoundAsync(host, key);
        Assert.True(await UntilAsync(() => second.Replica.Aborted.Contains(spoiled)), "the round did not close the new connection");

        // The index repaired: a reconnect reads the ticket, restores the member and moves the row's lifetime.
        Assert.True(await host.Db.KeyExpireAsync(key, TimeSpan.FromSeconds(60)));
        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync("/test/hub", cookie)).Status);
        Assert.True(await host.Db.SetContainsAsync(IndexKey, key));
        Assert.True(await host.Db.KeyTimeToLiveAsync(key) > TimeSpan.FromHours(1));
        var restored = await second.Replica.ConnectAsync(User, sessionKey: key);
        await second.RoundAsync(host, key);
        Assert.DoesNotContain(restored, second.Replica.Aborted);

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
