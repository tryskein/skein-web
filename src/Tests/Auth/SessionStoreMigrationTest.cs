using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using SkeinWeb.Auth;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// The startup cleanup of session rows of the former format against a real Redis, in database 7 so
/// a flush cannot touch other tests: what is deleted and what is not, the lock and its loss, a
/// cleanup interrupted and finished by the next start, and a re-rollout after a rollback.
/// </summary>
[Trait("Category", "Integration")]
[Collection("session-store-migration")]
public sealed class SessionStoreMigrationTest : IDisposable
{
    private const int Database = 7;
    private readonly ConnectionMultiplexer _mux = TestRedis.Connect(Database);
    private readonly List<string> _otherDbKeys = [];

    public SessionStoreMigrationTest()
    {
        if (!string.IsNullOrWhiteSpace(TestRedis.Url))
        {
            Flush();
        }
    }

    public void Dispose()
    {
        if (!string.IsNullOrWhiteSpace(TestRedis.Url))
        {
            Flush();
            foreach (var key in _otherDbKeys)
            {
                _mux.GetDatabase(0).KeyDelete(key);
            }
        }
        _mux.Dispose();
    }

    private void Flush() => _mux.GetServers().First(s => !s.IsReplica).FlushDatabase(Database);

    private IDatabase Db => _mux.GetDatabase(Database);

    private static string Legacy() => "skein:session:legacy-" + Guid.NewGuid().ToString("N");

    private Task LegacyHashAsync(string key) =>
        Db.HashSetAsync(key, [new HashEntry("absexp", -1), new HashEntry("sldexp", 86400), new HashEntry("data", new byte[] { 1, 2, 3 })]);

    private SessionStoreMigration Migration(IConnectionMultiplexer? mux = null) =>
        new(mux ?? _mux, TimeProvider.System, NullLogger<SessionStoreMigration>.Instance);

    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(10);

    private async Task<string> IssueV3Async(Guid user) =>
        await TestRedis.Store(_mux).StoreAsync(TestRedis.Ticket(user), new DefaultHttpContext(), CancellationToken.None);

    // ---- R29 ----------------------------------------------------------------------------------

    [RedisFact]
    public async Task Cleanup_RemovesTheFormerHashes_AndNothingElse()
    {
        var legacy = new[] { Legacy(), Legacy(), Legacy() };
        foreach (var key in legacy)
        {
            await LegacyHashAsync(key);
        }
        var user = Guid.NewGuid();
        var v3 = await IssueV3Async(user);
        byte[] v3Bytes = (await Db.StringGetAsync(v3))!;
        await Db.StringSetAsync("skein:dataprotection:keys", "ring");
        await Db.StringSetAsync("skein:login:fail:someone", "3");
        await Db.StringSetAsync("skein:signalr:other", "x");

        await Migration().RunAsync(Wait, CancellationToken.None);

        foreach (var key in legacy)
        {
            Assert.False(await Db.KeyExistsAsync(key));
        }
        Assert.Equal(v3Bytes, (byte[])(await Db.StringGetAsync(v3))!);
        Assert.True(await Db.SetContainsAsync("skein:user-tickets:" + user, v3));
        Assert.Equal("ring", await Db.StringGetAsync("skein:dataprotection:keys"));
        Assert.Equal("3", await Db.StringGetAsync("skein:login:fail:someone"));
        Assert.Equal("x", await Db.StringGetAsync("skein:signalr:other"));
        Assert.Equal(SessionStoreMigration.MarkerValue, await Db.StringGetAsync(SessionStoreMigration.MarkerKey));
        Assert.False(await Db.KeyExistsAsync(SessionStoreMigration.LockKey));
    }

    [RedisFact]
    public async Task Cleanup_WhenTheMarkerIsAlreadySet_DeletesNothing()
    {
        var legacy = Legacy();
        await LegacyHashAsync(legacy);
        await Db.StringSetAsync(SessionStoreMigration.MarkerKey, SessionStoreMigration.MarkerValue);

        await Migration().RunAsync(Wait, CancellationToken.None);

        Assert.True(await Db.KeyExistsAsync(legacy));
    }

    [RedisFact]
    public async Task Cleanup_WhenTheMarkerAppearsAfterTheLockWasTaken_DeletesNothing()
    {
        var legacy = Legacy();
        await LegacyHashAsync(legacy);
        var db = DbProxy.Create(Db, out var proxy);
        proxy.After = async (name, args) =>
        {
            if (name == nameof(IDatabase.StringSetAsync) && (RedisKey)args[0]! == SessionStoreMigration.LockKey)
            {
                await Db.StringSetAsync(SessionStoreMigration.MarkerKey, SessionStoreMigration.MarkerValue);
            }
        };

        await Migration(TestRedis.Over(_mux, db)).RunAsync(Wait, CancellationToken.None);

        Assert.True(await Db.KeyExistsAsync(legacy));
    }

    [RedisFact]
    public async Task Restart_WithALiveNewSession_KeepsIt()
    {
        var v3 = await IssueV3Async(Guid.NewGuid());
        await Migration().RunAsync(Wait, CancellationToken.None);

        await Migration().RunAsync(Wait, CancellationToken.None);

        Assert.NotNull(await TestRedis.Store(_mux).RetrieveAsync(v3, new DefaultHttpContext(), CancellationToken.None));
    }

    // ---- R30 ----------------------------------------------------------------------------------

    [RedisFact]
    public async Task AnotherReplica_WaitsForTheMarker_AndFailsOnTimeoutWithoutIt()
    {
        await Db.StringSetAsync(SessionStoreMigration.LockKey, "somebody-else", TimeSpan.FromMinutes(1));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Migration().RunAsync(TimeSpan.FromSeconds(1), CancellationToken.None));

        Assert.DoesNotContain("skein:", ex.Message);
        Assert.Equal("somebody-else", await Db.StringGetAsync(SessionStoreMigration.LockKey));
    }

    [RedisFact]
    public async Task AnotherReplica_ReturnsAsSoonAsTheMarkerAppears_AndDeletesNothing()
    {
        var legacy = Legacy();
        await LegacyHashAsync(legacy);
        await Db.StringSetAsync(SessionStoreMigration.LockKey, "somebody-else", TimeSpan.FromMinutes(1));
        var waiting = Migration().RunAsync(Wait, CancellationToken.None);
        await Task.Delay(500);
        await Db.StringSetAsync(SessionStoreMigration.MarkerKey, SessionStoreMigration.MarkerValue);

        await waiting;

        Assert.True(await Db.KeyExistsAsync(legacy));
    }

    [RedisFact]
    public async Task AnOwnerThatLostItsLock_DeletesNothing_ReleasesNothingOfTheNewOwner_AndTheNextStartFinishes()
    {
        var legacy = Legacy();
        await LegacyHashAsync(legacy);
        var db = DbProxy.Create(Db, out var proxy);
        proxy.Before = (name, _) =>
        {
            if (name == nameof(IDatabase.ScriptEvaluateAsync) && proxy.Before is not null)
            {
                // The first script of the cleanup is the lock extension: the lock is taken over first.
                proxy.Before = null;
                Db.StringSet(SessionStoreMigration.LockKey, "thief", TimeSpan.FromMinutes(1));
            }
            return null;
        };

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Migration(TestRedis.Over(_mux, db)).RunAsync(Wait, CancellationToken.None));

        Assert.True(await Db.KeyExistsAsync(legacy));
        Assert.False(await Db.KeyExistsAsync(SessionStoreMigration.MarkerKey));
        Assert.Equal("thief", await Db.StringGetAsync(SessionStoreMigration.LockKey));

        await Db.KeyDeleteAsync(SessionStoreMigration.LockKey);
        await Migration().RunAsync(Wait, CancellationToken.None);

        Assert.False(await Db.KeyExistsAsync(legacy));
        Assert.Equal(SessionStoreMigration.MarkerValue, await Db.StringGetAsync(SessionStoreMigration.MarkerKey));
    }

    [RedisFact]
    public async Task Scan_RunsInTheDatabaseOfTheProcess()
    {
        var legacy = Legacy();
        await LegacyHashAsync(legacy);
        var elsewhere = Legacy();
        _otherDbKeys.Add(elsewhere);
        await _mux.GetDatabase(0).HashSetAsync(elsewhere, [new HashEntry("data", 1)]);

        await Migration().RunAsync(Wait, CancellationToken.None);

        Assert.False(await Db.KeyExistsAsync(legacy));
        Assert.True(await _mux.GetDatabase(0).KeyExistsAsync(elsewhere));
    }

    // ---- R31 ----------------------------------------------------------------------------------

    [RedisFact]
    public async Task RolloutAfterARollback_WithTheMarkerKept_SkipsTheCleanup_AndStillRejectsTheFormerHash()
    {
        await Migration().RunAsync(Wait, CancellationToken.None);
        var v3 = await IssueV3Async(Guid.NewGuid());
        var rolledBack = Legacy();
        await LegacyHashAsync(rolledBack); // written by the former version during the rollback

        await Migration().RunAsync(Wait, CancellationToken.None);

        var store = TestRedis.Store(_mux);
        Assert.True(await Db.KeyExistsAsync(rolledBack));
        Assert.Null(await store.RetrieveAsync(rolledBack, new DefaultHttpContext(), CancellationToken.None));
        Assert.NotNull(await store.RetrieveAsync(v3, new DefaultHttpContext(), CancellationToken.None));
    }

    [RedisFact]
    public async Task RolloutAfterARollback_WithTheMarkerDeleted_RemovesTheFormerHashes()
    {
        await Migration().RunAsync(Wait, CancellationToken.None);
        var rolledBack = Legacy();
        await LegacyHashAsync(rolledBack);
        await Db.KeyDeleteAsync(SessionStoreMigration.MarkerKey);

        await Migration().RunAsync(Wait, CancellationToken.None);

        Assert.False(await Db.KeyExistsAsync(rolledBack));
        Assert.Equal(SessionStoreMigration.MarkerValue, await Db.StringGetAsync(SessionStoreMigration.MarkerKey));
    }
}
