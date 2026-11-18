using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Moq;
using Microsoft.Extensions.DependencyInjection;
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

    private static bool IsScript(string name, object?[] args, string fragment) =>
        name == nameof(IDatabase.ScriptEvaluateAsync) && args[0] is string text && text.Contains(fragment, StringComparison.Ordinal);

    // The lock is taken over right before one chosen script of the cleanup runs.
    private async Task<(DbProxy Proxy, IDatabase Db)> StealBeforeAsync(string scriptFragment)
    {
        var db = DbProxy.Create(Db, out var proxy);
        proxy.Before = (name, args) =>
        {
            if (IsScript(name, args, scriptFragment))
            {
                proxy.Before = null;
                Db.StringSet(SessionStoreMigration.LockKey, "thief", TimeSpan.FromMinutes(1));
            }
            return null;
        };
        await Task.CompletedTask;
        return (proxy, db);
    }

    [RedisFact]
    public async Task LockLostBeforeTheExtension_StopsTheCleanup_AndTheNextStartFinishesIt()
    {
        var legacy = Legacy();
        await LegacyHashAsync(legacy);
        var (_, db) = await StealBeforeAsync("PEXPIRE");

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Migration(TestRedis.Over(_mux, db)).RunAsync(Wait, CancellationToken.None));

        Assert.True(await Db.KeyExistsAsync(legacy));
        Assert.False(await Db.KeyExistsAsync(SessionStoreMigration.MarkerKey));
        Assert.Equal("thief", await Db.StringGetAsync(SessionStoreMigration.LockKey)); // not released by the loser

        await Db.KeyDeleteAsync(SessionStoreMigration.LockKey);
        await Migration().RunAsync(Wait, CancellationToken.None);

        Assert.False(await Db.KeyExistsAsync(legacy));
        Assert.Equal(SessionStoreMigration.MarkerValue, await Db.StringGetAsync(SessionStoreMigration.MarkerKey));
    }

    [RedisFact]
    public async Task LockLostAfterTheExtension_TheDeleteScriptItselfChecksTheToken_AndDeletesNothing()
    {
        var legacy = Legacy();
        await LegacyHashAsync(legacy);
        var (_, db) = await StealBeforeAsync("TYPE"); // the delete batch: the extension before it already succeeded

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Migration(TestRedis.Over(_mux, db)).RunAsync(Wait, CancellationToken.None));

        Assert.True(await Db.KeyExistsAsync(legacy));
        Assert.False(await Db.KeyExistsAsync(SessionStoreMigration.MarkerKey));
    }

    [RedisFact]
    public async Task LockLostBeforeTheMarkerScript_WritesNoMarker()
    {
        var legacy = Legacy();
        await LegacyHashAsync(legacy);
        var (_, db) = await StealBeforeAsync("KEYS[2]");

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Migration(TestRedis.Over(_mux, db)).RunAsync(Wait, CancellationToken.None));

        Assert.False(await Db.KeyExistsAsync(legacy)); // the deletion was legitimate: the lock was ours then
        Assert.False(await Db.KeyExistsAsync(SessionStoreMigration.MarkerKey));
        Assert.Equal("thief", await Db.StringGetAsync(SessionStoreMigration.LockKey));
    }

    [RedisFact]
    public async Task TheLockIsExtendedByTheScan()
    {
        var legacy = Legacy();
        await LegacyHashAsync(legacy);
        var db = DbProxy.Create(Db, out var proxy);
        TimeSpan? afterExtension = null;
        proxy.Before = (name, args) =>
        {
            if (IsScript(name, args, "PEXPIRE"))
            {
                Db.KeyExpire(SessionStoreMigration.LockKey, TimeSpan.FromSeconds(2)); // as if the scan had run long
            }
            return null;
        };
        proxy.After = (name, args) =>
        {
            if (IsScript(name, args, "PEXPIRE"))
            {
                afterExtension = Db.KeyTimeToLive(SessionStoreMigration.LockKey);
            }
            return Task.CompletedTask;
        };

        await Migration(TestRedis.Over(_mux, db)).RunAsync(Wait, CancellationToken.None);

        Assert.True(afterExtension > TimeSpan.FromSeconds(20), "the extension did not renew the lock");
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


    [RedisTheory]
    [InlineData(false)] // no primary known
    [InlineData(true)]  // a known primary that is not connected
    public async Task Cleanup_WithoutEveryPrimaryReachable_FailsTheStart_AndWritesNoMarker(bool knownButDisconnected)
    {
        var legacy = Legacy();
        await LegacyHashAsync(legacy);
        var servers = new List<IServer>();
        if (knownButDisconnected)
        {
            var server = new Moq.Mock<IServer>();
            server.SetupGet(x => x.IsConnected).Returns(false);
            server.SetupGet(x => x.IsReplica).Returns(false);
            servers.Add(server.Object);
        }
        var mux = new Moq.Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(Db);
        mux.Setup(m => m.GetServers()).Returns(servers.ToArray());

        await Assert.ThrowsAsync<InvalidOperationException>(() => Migration(mux.Object).RunAsync(Wait, CancellationToken.None));

        Assert.True(await Db.KeyExistsAsync(legacy));
        Assert.False(await Db.KeyExistsAsync(SessionStoreMigration.MarkerKey));
        Assert.False(await Db.KeyExistsAsync(SessionStoreMigration.LockKey)); // the lock was released
    }

    [RedisFact]
    public async Task ATimeoutOfTheClient_IsTheSameStartupFailure_NotTheRawException()
    {
        var db = new Moq.Mock<IDatabase>();
        db.Setup(d => d.StringGetAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
            .ThrowsAsync(new RedisTimeoutException("timed out", CommandStatus.Unknown));
        var mux = new Moq.Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(db.Object);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new SessionStoreMigration(mux.Object, TimeProvider.System, NullLogger<SessionStoreMigration>.Instance)
                .RunAsync(TimeSpan.FromSeconds(1), CancellationToken.None));

        Assert.Null(ex.InnerException);
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

/// <summary>
/// A value of the former purpose is rejected at the format boundary, under both names and in both
/// modes, while a value of the current purpose on the same keyring and row is accepted (US-6, SC-011, SC-013).
/// </summary>
[Trait("Category", "Integration")]
[Collection("session-pipeline")]
public sealed class SessionFormatRejectionTest
{
    private static readonly Guid Alice = Guid.Parse("0199a1b2-0000-7000-8000-00000000000a");

    private static AuthenticationTicket Ticket(string key) => new(
        new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(
            [new System.Security.Claims.Claim("Microsoft.AspNetCore.Authentication.Cookies-SessionId", key)], "Cookies")),
        "Cookies");

    [RedisTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AValueOfTheFormerPurpose_IsRejectedUnderBothNames_AndTheCurrentOneIsAccepted(bool insecureHttp)
    {
        await using var host = await SessionPipelineHost.StartAsync(insecureHttp);
        var (_, key, _) = await host.SignInAsync(Alice); // a LIVE row under this key
        var former = new TicketDataFormat(host.Services.GetRequiredService<IDataProtectionProvider>().CreateProtector(
            "Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware", "Cookies", "v2"));
        var current = host.Services.GetRequiredService<TicketDataFormat>();

        foreach (var name in new[] { "skein.sid", "__Host-skein.sid" })
        {
            var old = await host.SendAsync("/test/me", $"{name}={Uri.EscapeDataString(former.Protect(Ticket(key)))}");
            Assert.Equal(HttpStatusCode.Unauthorized, old.Status);
        }
        var fresh = await host.SendAsync("/test/me", $"{host.CookieName}={Uri.EscapeDataString(current.Protect(Ticket(key)))}");
        Assert.Equal(HttpStatusCode.OK, fresh.Status); // control, and (insecure mode) the new skein.sid works
    }

    [RedisFact]
    public async Task AFormerHashWithALongTtl_AndAFormerCookie_AreRejected()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var key = "skein:session:legacy-" + Guid.NewGuid().ToString("N");
        await host.Db.HashSetAsync(key, [new HashEntry("absexp", -1), new HashEntry("sldexp", 86400), new HashEntry("data", new byte[] { 1 })]);
        await host.Db.KeyExpireAsync(key, TimeSpan.FromDays(30));
        var former = new TicketDataFormat(host.Services.GetRequiredService<IDataProtectionProvider>().CreateProtector(
            "Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware", "Cookies", "v2"));

        var reply = await host.SendAsync("/test/me", $"{host.CookieName}={Uri.EscapeDataString(former.Protect(Ticket(key)))}");

        Assert.Equal(HttpStatusCode.Unauthorized, reply.Status);
    }

    [RedisFact]
    public async Task AfterTheCleanup_AReaderOfTheFormerVersionAcceptsNothingOfThisOne()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, key, set) = await host.SignInAsync(Alice);
        var preUpdate = "skein:session:legacy-" + Guid.NewGuid().ToString("N");
        await host.Db.HashSetAsync(preUpdate, [new HashEntry("absexp", -1), new HashEntry("sldexp", 86400), new HashEntry("data", new byte[] { 1 })]);
        await host.Db.KeyDeleteAsync(SessionStoreMigration.MarkerKey);

        await new SessionStoreMigration(host.Mux, TimeProvider.System, Microsoft.Extensions.Logging.Abstractions.NullLogger<SessionStoreMigration>.Instance)
            .RunAsync(TimeSpan.FromSeconds(10), CancellationToken.None);

        // The reader of the former version: its cookie purpose and HGETALL of the row.
        var former = new TicketDataFormat(host.Services.GetRequiredService<IDataProtectionProvider>().CreateProtector(
            "Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware", "Cookies", "v2"));
        Assert.Null(former.Unprotect(Uri.UnescapeDataString(set.Value))); // the cookie of this version
        await Assert.ThrowsAsync<RedisServerException>(() => host.Db.HashGetAllAsync(key)); // WRONGTYPE: a string row
        Assert.Empty(await host.Db.HashGetAllAsync(preUpdate)); // the row issued before the update is gone
        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync("/test/me", cookie)).Status); // this version still works
    }
}
