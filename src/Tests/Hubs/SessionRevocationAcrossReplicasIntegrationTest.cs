using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SkeinWeb.Auth;
using SkeinWeb.Hubs;
using SkeinWeb.Tests.Auth;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Hubs;

/// <summary>
/// SC-006 / INV-10: a rotation through the real issuer closes the connections of the old key at once
/// on the replica that rotated and on the first 30 s round of another replica, while the store
/// answers; they stay while it does not; a control session of the same user is untouched. The first
/// replica is the pipeline stand (real rotation, real hub endpoint); the second is another registry
/// on the same Redis with the real <see cref="AccessRecheckService"/> on the stand's fake clock and
/// the real store as its probe.
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
}
