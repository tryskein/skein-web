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

/// <summary>A step of the startup session cleanup, as seen on the Redis boundary.</summary>
internal enum CleanupStep
{
    None,
    Status,
    Confirm,
    Begin,
    Extend,
    Delete,
    Finish,
    Release,
}

/// <summary>
/// Tells the scripts of the startup session cleanup apart by their <c>KEYS</c>, in a call of
/// <c>ScriptEvaluateAsync</c> (<see cref="DbProxy"/>) and in a command on the wire
/// (<see cref="RedisProxy"/>, where an <c>EVALSHA</c> carries a SHA instead of the text).
/// </summary>
internal static class CleanupCalls
{
    public const string SessionPattern = "skein:session:*";

    /// <summary>
    /// The step of a script with <paramref name="keys"/> and <paramref name="arguments"/> values of
    /// <c>ARGV</c>: the confirmation of readiness has the keys of the status and carries the observed count.
    /// </summary>
    public static CleanupStep Of(IReadOnlyList<string> keys, int arguments) =>
        Of(keys) == CleanupStep.Status && arguments > 0 ? CleanupStep.Confirm : Of(keys);

    public static CleanupStep Of(IReadOnlyList<string> keys) => keys switch
    {
        [SessionStoreMigration.MarkerKey, SessionStoreMigration.LockKey, SessionStoreMigration.GenerationKey] => CleanupStep.Status,
        [SessionStoreMigration.LockKey, SessionStoreMigration.GenerationKey, SessionStoreMigration.MarkerKey, SessionStoreMigration.IssuedDuringKey] => CleanupStep.Begin,
        [SessionStoreMigration.LockKey, SessionStoreMigration.IssuedDuringKey] => CleanupStep.Extend,
        [SessionStoreMigration.LockKey, SessionStoreMigration.MarkerKey, SessionStoreMigration.GenerationKey, SessionStoreMigration.IssuedDuringKey] => CleanupStep.Finish,
        [SessionStoreMigration.LockKey, SessionStoreMigration.IssuedDuringKey, ..] => CleanupStep.Delete,
        [SessionStoreMigration.LockKey] => CleanupStep.Release,
        _ => CleanupStep.None,
    };

    public static CleanupStep Of(string method, object?[] args) =>
        DbProxy.ScriptOf(method, args) is null
            ? CleanupStep.None
            : Of(DbProxy.KeysOf(method, args).Select(k => (string)k!).ToArray(), args.Length > 2 && args[2] is RedisValue[] values ? values.Length : 0);

    /// <summary>The <c>KEYS</c> of an <c>EVAL</c> or <c>EVALSHA</c> command; empty for any other command.</summary>
    public static string[] KeysOf(RedisCommand command) =>
        command.Name is "EVAL" or "EVALSHA" && command.Args.Length > 1 && int.TryParse(command.Args[1], out var n)
            ? command.Args.Skip(2).Take(n).ToArray()
            : [];

    public static CleanupStep Of(RedisCommand command)
    {
        var keys = KeysOf(command);
        return keys.Length == 0 ? CleanupStep.None : Of(keys, command.Args.Length - 2 - keys.Length);
    }
}

/// <summary>
/// The startup session cleanup against a real Redis, in database 7 so a flush cannot touch other
/// tests: when a pass runs and what it ends (US-5), the protocol of the pass (the count of finished
/// passes, the answers of its begin, the lock with a lifetime from the moment it is taken), the marks
/// of a pass, the loss of the lock at every step, the wait of another replica, two replicas at once,
/// and the failures of the start.
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

    private Task MarkAsync() => Db.StringSetAsync(SessionStoreMigration.MarkerKey, SessionStoreMigration.MarkerValue);

    private async Task<long> GenerationAsync() => (long?)await Db.StringGetAsync(SessionStoreMigration.GenerationKey) ?? 0;

    /// <summary>
    /// A multiplexer whose database records every step of the cleanup; <paramref name="onStep"/> sees
    /// the step and its occurrence (1 for the first) before it reaches Redis, and may fail it.
    /// </summary>
    private (IConnectionMultiplexer Mux, List<CleanupStep> Steps) Watched(Func<CleanupStep, int, Exception?>? onStep = null)
    {
        var db = DbProxy.Create(Db, out var proxy);
        var steps = new List<CleanupStep>();
        proxy.Before = (name, args) =>
        {
            var step = CleanupCalls.Of(name, args);
            if (step == CleanupStep.None)
            {
                return null;
            }
            int occurrence;
            lock (steps)
            {
                steps.Add(step);
                occurrence = steps.Count(s => s == step);
            }
            return onStep?.Invoke(step, occurrence);
        };
        return (TestRedis.Over(_mux, db), steps);
    }

    private static int CountOf(List<CleanupStep> steps, CleanupStep step)
    {
        lock (steps)
        {
            return steps.Count(s => s == step);
        }
    }

    /// <summary>The state a finished pass leaves: the marker, the count, no lock, no marks.</summary>
    private async Task AssertFinishedAsync(long generation)
    {
        Assert.Equal(SessionStoreMigration.MarkerValue, await Db.StringGetAsync(SessionStoreMigration.MarkerKey));
        Assert.Equal(generation, await GenerationAsync());
        Assert.False(await Db.KeyExistsAsync(SessionStoreMigration.LockKey));
        Assert.False(await Db.KeyExistsAsync(SessionStoreMigration.IssuedDuringKey));
    }

    private static async Task UntilAsync(Func<bool> condition, string what)
    {
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                Assert.Fail($"precondition not met within 15 s: {what}");
            }
            await Task.Delay(20);
        }
    }

    // ---- when a pass runs and what it ends (US-5) ----------------------------------------------

    [RedisFact]
    public async Task Cleanup_RemovesTheFormerHashes_AndTheRowsOfThisVersion_AndNothingElse()
    {
        // A re-rollout after a rollback: the marker of the earlier deployment is kept, the former version left hashes.
        await MarkAsync();
        var legacy = new[] { Legacy(), Legacy(), Legacy() };
        foreach (var key in legacy)
        {
            await LegacyHashAsync(key);
        }
        var user = Guid.NewGuid();
        var v3 = await IssueV3Async(user);
        await Db.StringSetAsync("skein:dataprotection:keys", "ring");
        await Db.StringSetAsync("skein:login:fail:someone", "3");
        await Db.StringSetAsync("skein:signalr:other", "x");
        await Db.StringSetAsync("skein:session-other", "y");

        await Migration().RunAsync(Wait, CancellationToken.None);

        foreach (var key in legacy)
        {
            Assert.False(await Db.KeyExistsAsync(key));
        }
        Assert.False(await Db.KeyExistsAsync(v3));
        Assert.True(await Db.SetContainsAsync("skein:user-tickets:" + user, v3)); // the index is not the cleanup's
        Assert.Equal("ring", await Db.StringGetAsync("skein:dataprotection:keys"));
        Assert.Equal("3", await Db.StringGetAsync("skein:login:fail:someone"));
        Assert.Equal("x", await Db.StringGetAsync("skein:signalr:other"));
        Assert.Equal("y", await Db.StringGetAsync("skein:session-other"));
        await AssertFinishedAsync(1);
    }

    [RedisFact]
    public async Task Cleanup_WhenTheMarkerIsSetAndNoFormerHashIsLeft_DeletesNothing_AndBeginsNoPass()
    {
        await MarkAsync();
        await Db.StringSetAsync(SessionStoreMigration.GenerationKey, 4);
        var v3 = await IssueV3Async(Guid.NewGuid());
        var (mux, steps) = Watched();

        await Migration(mux).RunAsync(Wait, CancellationToken.None);

        Assert.True(await Db.KeyExistsAsync(v3));
        Assert.Equal(0, CountOf(steps, CleanupStep.Begin));
        Assert.Equal(1, CountOf(steps, CleanupStep.Confirm));
        await AssertFinishedAsync(5); // the confirmation of readiness counted once
    }

    [RedisFact]
    public async Task Restart_WithALiveNewSession_KeepsIt()
    {
        await Migration().RunAsync(Wait, CancellationToken.None); // the first deployment: no marker yet
        var v3 = await IssueV3Async(Guid.NewGuid());
        var (mux, steps) = Watched();

        await Migration(mux).RunAsync(Wait, CancellationToken.None);

        Assert.NotNull(await TestRedis.Store(_mux).RetrieveAsync(v3, new DefaultHttpContext(), CancellationToken.None));
        Assert.Equal(0, CountOf(steps, CleanupStep.Begin));
        Assert.Equal(1, CountOf(steps, CleanupStep.Confirm));
        await AssertFinishedAsync(2); // the pass of the first deployment, then the confirmation
    }

    [RedisFact]
    public async Task Start_WithoutTheMarker_AndWithoutAFormerHash_EndsEverySessionRow()
    {
        var first = await IssueV3Async(Guid.NewGuid());
        var second = await IssueV3Async(Guid.NewGuid());

        await Migration().RunAsync(Wait, CancellationToken.None);

        Assert.False(await Db.KeyExistsAsync(first));
        Assert.False(await Db.KeyExistsAsync(second));
        await AssertFinishedAsync(1);
    }

    [RedisFact]
    public async Task RolloutAfterARollback_WithTheMarkerKept_EndsEverySession_IncludingTheRowsThatSurvivedTheRollback()
    {
        await Migration().RunAsync(Wait, CancellationToken.None);
        var v3 = await IssueV3Async(Guid.NewGuid()); // survives the rollback
        var rolledBack = Legacy();
        await LegacyHashAsync(rolledBack); // written by the former version during the rollback

        await Migration().RunAsync(Wait, CancellationToken.None);

        var store = TestRedis.Store(_mux);
        Assert.False(await Db.KeyExistsAsync(rolledBack));
        Assert.False(await Db.KeyExistsAsync(v3));
        Assert.Null(await store.RetrieveAsync(v3, new DefaultHttpContext(), CancellationToken.None));
        await AssertFinishedAsync(2);
    }

    [RedisFact]
    public async Task RolloutAfterARollback_WithTheMarkerDeleted_EndsEverySession()
    {
        await Migration().RunAsync(Wait, CancellationToken.None);
        var v3 = await IssueV3Async(Guid.NewGuid());
        var rolledBack = Legacy();
        await LegacyHashAsync(rolledBack);
        await Db.KeyDeleteAsync(SessionStoreMigration.MarkerKey);

        await Migration().RunAsync(Wait, CancellationToken.None);

        Assert.False(await Db.KeyExistsAsync(rolledBack));
        Assert.False(await Db.KeyExistsAsync(v3));
        await AssertFinishedAsync(2);
    }

    [RedisFact]
    public async Task TheLastFormerHashExpiringBeforeTheBegin_DoesNotCancelThePass()
    {
        await MarkAsync();
        var legacy = Legacy();
        await LegacyHashAsync(legacy);
        var v3 = await IssueV3Async(Guid.NewGuid());
        var (mux, steps) = Watched((step, n) =>
        {
            if (step == CleanupStep.Begin && n == 1)
            {
                Db.KeyDelete(legacy); // its own lifetime ran out between the observation and the begin
            }
            return null;
        });

        await Migration(mux).RunAsync(Wait, CancellationToken.None);

        Assert.False(await Db.KeyExistsAsync(v3));
        Assert.Equal(1, CountOf(steps, CleanupStep.Begin));
        await AssertFinishedAsync(1);
    }

    // ---- the protocol of the pass (ОСТ-3-1) ------------------------------------------------------

    [RedisFact]
    public async Task ABeginWithAStaleCount_FindsThePassFinishedAfterTheObservation_DeletesNothing_AndTheNextStartIsOrdinary()
    {
        var legacy = Legacy();
        await LegacyHashAsync(legacy);
        var issuedDuringTheOtherPass = await IssueV3Async(Guid.NewGuid());
        var lockAfterTheBegin = new List<bool>();
        var db = DbProxy.Create(Db, out var proxy);
        var steps = new List<CleanupStep>();
        proxy.Before = (name, args) =>
        {
            var step = CleanupCalls.Of(name, args);
            steps.Add(step);
            if (step == CleanupStep.Begin)
            {
                // Another replica ran its whole pass between this replica's observation and its begin;
                // the row issued during that pass was kept by it.
                Db.KeyDelete(legacy);
                Db.StringSet(SessionStoreMigration.MarkerKey, SessionStoreMigration.MarkerValue);
                Db.StringIncrement(SessionStoreMigration.GenerationKey);
            }
            else if (step == CleanupStep.Status && steps.Contains(CleanupStep.Begin))
            {
                // The late claimant is interrupted right after the answer of its begin.
                return new RedisException("interrupted");
            }
            return null;
        };
        proxy.After = (name, args) =>
        {
            if (CleanupCalls.Of(name, args) == CleanupStep.Begin)
            {
                lockAfterTheBegin.Add(Db.KeyExists(SessionStoreMigration.LockKey));
            }
            return Task.CompletedTask;
        };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Migration(TestRedis.Over(_mux, db)).RunAsync(Wait, CancellationToken.None));

        // The begin answered "a pass finished after the observation": no lock was taken, nothing deleted.
        Assert.DoesNotContain("skein:", ex.Message);
        Assert.Equal(new[] { false }, lockAfterTheBegin);
        Assert.DoesNotContain(CleanupStep.Delete, steps);
        Assert.True(await Db.KeyExistsAsync(issuedDuringTheOtherPass));
        await AssertFinishedAsync(1);

        // The next start is ordinary: it begins no pass and deletes nothing.
        var (mux, next) = Watched();
        await Migration(mux).RunAsync(Wait, CancellationToken.None);

        Assert.Equal(0, CountOf(next, CleanupStep.Begin));
        Assert.True(await Db.KeyExistsAsync(issuedDuringTheOtherPass));
        await AssertFinishedAsync(2); // the other pass, then this start's confirmation
    }

    [RedisFact]
    public async Task TheLock_HasAFiniteLifetime_FromTheMomentItIsTaken()
    {
        await LegacyHashAsync(Legacy());
        var db = DbProxy.Create(Db, out var proxy);
        TimeSpan? lifetime = null;
        var extendedBefore = false;
        proxy.Before = (name, args) =>
        {
            extendedBefore |= CleanupCalls.Of(name, args) == CleanupStep.Extend;
            return null;
        };
        proxy.After = (name, args) =>
        {
            if (CleanupCalls.Of(name, args) == CleanupStep.Begin)
            {
                Assert.False(extendedBefore); // before the first page of the scan
                lifetime = Db.KeyTimeToLive(SessionStoreMigration.LockKey);
            }
            return Task.CompletedTask;
        };

        await Migration(TestRedis.Over(_mux, db)).RunAsync(Wait, CancellationToken.None);

        Assert.NotNull(lifetime);
        Assert.InRange(lifetime.Value, TimeSpan.FromMilliseconds(1), SessionStoreMigration.LockLifetime);
    }

    // ---- the marks of a pass (ОСТ-3-2, R30) --------------------------------------------------------

    [RedisFact]
    public async Task ANewPass_DropsTheMarksOfAnInterruptedOne_AtItsBegin()
    {
        var v3 = await IssueV3Async(Guid.NewGuid());
        // An interrupted pass marked that row; its lock is gone, its marks are not.
        await Db.SetAddAsync(SessionStoreMigration.IssuedDuringKey, "interrupted:" + v3);
        bool? marksAfterTheBegin = null;
        var db = DbProxy.Create(Db, out var proxy);
        proxy.After = (name, args) =>
        {
            if (CleanupCalls.Of(name, args) == CleanupStep.Begin)
            {
                marksAfterTheBegin = Db.KeyExists(SessionStoreMigration.IssuedDuringKey);
            }
            return Task.CompletedTask;
        };

        await Migration(TestRedis.Over(_mux, db)).RunAsync(Wait, CancellationToken.None);

        Assert.False(marksAfterTheBegin);
        Assert.False(await Db.KeyExistsAsync(v3));
        await AssertFinishedAsync(1);
    }

    [RedisFact]
    public async Task AMarkOfAnotherToken_ProtectsNoRow_WhileAMarkOfThisPassDoes()
    {
        await LegacyHashAsync(Legacy());
        var foreign = await IssueV3Async(Guid.NewGuid());
        var own = await IssueV3Async(Guid.NewGuid());
        var db = DbProxy.Create(Db, out var proxy);
        proxy.After = (name, args) =>
        {
            if (CleanupCalls.Of(name, args) == CleanupStep.Begin)
            {
                var token = (string)Db.StringGet(SessionStoreMigration.LockKey)!;
                Db.SetAdd(SessionStoreMigration.IssuedDuringKey, ["another-token:" + foreign, token + ":" + own]);
            }
            return Task.CompletedTask;
        };

        await Migration(TestRedis.Over(_mux, db)).RunAsync(Wait, CancellationToken.None);

        Assert.False(await Db.KeyExistsAsync(foreign));
        Assert.True(await Db.KeyExistsAsync(own));
        await AssertFinishedAsync(1);
    }

    // ---- the loss of the lock (R30) ---------------------------------------------------------------

    /// <summary>The lifetime the other pass gave its marks: below the lifetime a page of the loser would give them.</summary>
    private static readonly TimeSpan TheirMarksLifetime = TimeSpan.FromSeconds(20);

    [RedisTheory]
    [InlineData("Extend")] // before the first page: the extension of that page finds the lock taken
    [InlineData("Delete")] // after a page was extended: the delete script itself checks the token
    [InlineData("Finish")] // before the finish: the rows were deleted while the lock was the owner's
    public async Task AnOwnerThatLostItsLock_DeletesNoMore_WritesNoMarker_AndTouchesNoMarkOfTheOtherPass_AndAFullPassFollows(string step)
    {
        var at = Enum.Parse<CleanupStep>(step);
        var legacy = Legacy();
        await LegacyHashAsync(legacy);
        var thiefMark = "thief:skein:session:issued-by-the-other-pass";
        var (mux, _) = Watched((step, n) =>
        {
            if (step == at && n == 1)
            {
                Db.StringSet(SessionStoreMigration.LockKey, "thief", TimeSpan.FromMinutes(1));
                Db.SetAdd(SessionStoreMigration.IssuedDuringKey, thiefMark);
                Db.KeyExpire(SessionStoreMigration.IssuedDuringKey, TheirMarksLifetime);
            }
            return null;
        });

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => Migration(mux).RunAsync(Wait, CancellationToken.None));

        Assert.DoesNotContain("skein:", ex.Message);
        Assert.Equal(at != CleanupStep.Finish, await Db.KeyExistsAsync(legacy));
        Assert.False(await Db.KeyExistsAsync(SessionStoreMigration.MarkerKey));
        Assert.Equal(0, await GenerationAsync());
        Assert.Equal("thief", await Db.StringGetAsync(SessionStoreMigration.LockKey)); // not released by the loser
        Assert.True(await Db.SetContainsAsync(SessionStoreMigration.IssuedDuringKey, thiefMark));
        // The loser did not extend the marks of the other pass either.
        var theirs = await Db.KeyTimeToLiveAsync(SessionStoreMigration.IssuedDuringKey);
        Assert.NotNull(theirs);
        Assert.True(theirs <= TheirMarksLifetime, $"the marks of the other pass were extended to {theirs}");

        // The lock of the interrupted pass runs out by itself; the next start runs a full pass.
        await Db.KeyExpireAsync(SessionStoreMigration.LockKey, TimeSpan.FromMilliseconds(200));
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (await Db.KeyExistsAsync(SessionStoreMigration.LockKey))
        {
            Assert.True(DateTime.UtcNow < deadline, "the lock did not run out");
            await Task.Delay(20);
        }
        var survivor = await IssueV3Async(Guid.NewGuid()); // issued between the interrupted pass and the next one

        await Migration().RunAsync(Wait, CancellationToken.None);

        Assert.False(await Db.KeyExistsAsync(legacy));
        Assert.False(await Db.KeyExistsAsync(survivor));
        await AssertFinishedAsync(1);
    }

    // ---- a cancelled pass -------------------------------------------------------------------------

    [RedisTheory]
    [InlineData("AfterBegin")]      // before the first extension: no extension is sent
    [InlineData("AfterExtend")]     // while the extension of a page is answered: no delete of that page
    [InlineData("AfterLastDelete")] // after the last page: no finish
    public async Task ACancelledPass_WritesNothingMore_ReleasesItsLock_AndLeavesNoMarker(string point)
    {
        var legacy = Legacy();
        await LegacyHashAsync(legacy); // one page of the scan
        using var cancellation = new CancellationTokenSource();
        var cancelAfter = point switch
        {
            "AfterBegin" => CleanupStep.Begin,
            "AfterExtend" => CleanupStep.Extend,
            _ => CleanupStep.Delete,
        };
        var db = DbProxy.Create(Db, out var proxy);
        var steps = new List<CleanupStep>();
        proxy.Before = (name, args) =>
        {
            var step = CleanupCalls.Of(name, args);
            if (step != CleanupStep.None)
            {
                lock (steps)
                {
                    steps.Add(step);
                }
            }
            return null;
        };
        proxy.After = (name, args) =>
        {
            if (CleanupCalls.Of(name, args) == cancelAfter)
            {
                cancellation.Cancel();
            }
            return Task.CompletedTask;
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Migration(TestRedis.Over(_mux, db)).RunAsync(Wait, cancellation.Token));

        Assert.Equal(point == "AfterBegin" ? 0 : 1, CountOf(steps, CleanupStep.Extend));
        Assert.Equal(point == "AfterLastDelete" ? 1 : 0, CountOf(steps, CleanupStep.Delete));
        Assert.Equal(0, CountOf(steps, CleanupStep.Finish));
        Assert.Equal(point != "AfterLastDelete", await Db.KeyExistsAsync(legacy));
        Assert.False(await Db.KeyExistsAsync(SessionStoreMigration.MarkerKey));
        Assert.Equal(0, await GenerationAsync());
        // The way out of a failed pass releases the lock of its owner.
        Assert.Equal(1, CountOf(steps, CleanupStep.Release));
        Assert.False(await Db.KeyExistsAsync(SessionStoreMigration.LockKey));
    }

    // ---- another replica waits for the pass (US-5, the condition of the start) ----------------------

    [RedisFact]
    public async Task AnotherReplica_WaitsForThePass_AndFailsOnTimeoutWithoutIt()
    {
        var legacy = Legacy();
        await LegacyHashAsync(legacy);
        await Db.StringSetAsync(SessionStoreMigration.LockKey, "somebody-else", TimeSpan.FromMinutes(1));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Migration().RunAsync(TimeSpan.FromSeconds(1), CancellationToken.None));

        Assert.DoesNotContain("skein:", ex.Message);
        Assert.Equal("somebody-else", await Db.StringGetAsync(SessionStoreMigration.LockKey));
        Assert.True(await Db.KeyExistsAsync(legacy));
    }

    [RedisFact]
    public async Task AnotherReplica_LeavesTheWaitWhenTheLockIsGone_NotOnTheMarkerAlone_AndDeletesNothingAfterAFinishedPass()
    {
        var legacy = Legacy();
        await LegacyHashAsync(legacy);
        await Db.StringSetAsync(SessionStoreMigration.LockKey, "somebody-else", TimeSpan.FromMinutes(1));
        var (mux, steps) = Watched();
        var waiting = Migration(mux).RunAsync(TimeSpan.FromSeconds(30), CancellationToken.None);
        await UntilAsync(() => CountOf(steps, CleanupStep.Status) >= 3, "the replica polls the state");

        // The marker alone, with the lock alive: the wait goes on through several more polls.
        await MarkAsync();
        var polls = CountOf(steps, CleanupStep.Status);
        await UntilAsync(() => CountOf(steps, CleanupStep.Status) >= polls + 3, "the replica keeps polling");
        Assert.False(waiting.IsCompleted);

        // The other pass finishes: its rows are gone, its count grows, its lock goes; a row issued
        // during it was kept.
        var issuedDuringIt = await IssueV3Async(Guid.NewGuid());
        await Db.KeyDeleteAsync(legacy);
        await Db.StringIncrementAsync(SessionStoreMigration.GenerationKey);
        await Db.KeyDeleteAsync([SessionStoreMigration.IssuedDuringKey, SessionStoreMigration.LockKey]); // its finish drops its marks too

        await waiting.WaitAsync(TimeSpan.FromSeconds(15));

        Assert.Equal(0, CountOf(steps, CleanupStep.Begin));
        Assert.True(await Db.KeyExistsAsync(issuedDuringIt));
        await AssertFinishedAsync(2); // the other pass, then this replica's confirmation
    }

    [RedisFact]
    public async Task AnotherReplica_WhoseOwnerStopped_RunsItsOwnPassWhenTheLockIsGone_NotATimeout()
    {
        // The owner began its pass (the marker is deleted) and stopped; its lock is still there.
        var legacy = Legacy();
        await LegacyHashAsync(legacy);
        await Db.StringSetAsync(SessionStoreMigration.LockKey, "stopped-owner", TimeSpan.FromMinutes(1));
        var (mux, steps) = Watched();
        var waiting = Migration(mux).RunAsync(TimeSpan.FromSeconds(60), CancellationToken.None);
        await UntilAsync(() => CountOf(steps, CleanupStep.Status) >= 3, "the replica waits for the lock");
        Assert.False(waiting.IsCompleted);

        await Db.KeyDeleteAsync(SessionStoreMigration.LockKey); // the lock runs out; the count did not grow

        await waiting.WaitAsync(TimeSpan.FromSeconds(15)); // well before the startup timeout

        Assert.Equal(1, CountOf(steps, CleanupStep.Begin));
        Assert.Equal(1, CountOf(steps, CleanupStep.Finish));
        Assert.False(await Db.KeyExistsAsync(legacy));
        await AssertFinishedAsync(1);
    }

    // ---- the confirmation of readiness against a late claimant (row 101) ---------------------------

    [RedisFact]
    public async Task AConfirmedStart_TurnsTheBeginOfALateClaimantIntoAFinishedPass_AndNoPassRuns()
    {
        // Replica A observes the last former hash; the hash runs out before replica B scans.
        await MarkAsync();
        var legacy = Legacy();
        await LegacyHashAsync(legacy);
        var live = await IssueV3Async(Guid.NewGuid());
        var dbA = DbProxy.Create(Db, out var proxyA);
        var stepsA = new List<CleanupStep>();
        proxyA.Before = (name, args) =>
        {
            lock (stepsA)
            {
                stepsA.Add(CleanupCalls.Of(name, args));
            }
            return null;
        };
        var beginA = proxyA.Hold((name, args) => CleanupCalls.Of(name, args) == CleanupStep.Begin);
        var a = Migration(TestRedis.Over(_mux, dbA)).RunAsync(Wait, CancellationToken.None);
        await beginA.Reached.WaitAsync(TimeSpan.FromSeconds(15));
        await Db.KeyDeleteAsync(legacy);

        // B finds no hash and confirms its readiness: it serves, and the count grows.
        var (muxB, stepsB) = Watched();
        await Migration(muxB).RunAsync(Wait, CancellationToken.None);
        Assert.Equal(1, CountOf(stepsB, CleanupStep.Confirm));
        Assert.Equal(1, await GenerationAsync());

        // A's begin with its old count finds a pass finished after its observation; A observes anew
        // and starts without a pass, so nothing runs while B serves.
        beginA.Release();
        await a.WaitAsync(TimeSpan.FromSeconds(15));

        Assert.Equal(1, CountOf(stepsA, CleanupStep.Begin));
        Assert.DoesNotContain(CleanupStep.Extend, stepsA);
        Assert.DoesNotContain(CleanupStep.Finish, stepsA);
        Assert.True(await Db.KeyExistsAsync(live));
        await AssertFinishedAsync(2);
    }

    [RedisFact]
    public async Task ABeginBeforeTheConfirmation_RefusesTheConfirmation_AndTheOtherReplicaWaitsForThePass()
    {
        await MarkAsync();
        var legacy = Legacy();
        await LegacyHashAsync(legacy);
        var live = await IssueV3Async(Guid.NewGuid());
        // A observes the hash and is held at its begin, and later inside its pass.
        var dbA = DbProxy.Create(Db, out var proxyA);
        var beginA = proxyA.Hold((name, args) => CleanupCalls.Of(name, args) == CleanupStep.Begin);
        var pageA = proxyA.Hold((name, args) => CleanupCalls.Of(name, args) == CleanupStep.Extend);
        var a = Migration(TestRedis.Over(_mux, dbA)).RunAsync(Wait, CancellationToken.None);
        await beginA.Reached.WaitAsync(TimeSpan.FromSeconds(15));
        await Db.KeyDeleteAsync(legacy);

        // B observes the clean state and is held at its confirmation.
        var dbB = DbProxy.Create(Db, out var proxyB);
        var stepsB = new List<CleanupStep>();
        proxyB.Before = (name, args) =>
        {
            lock (stepsB)
            {
                stepsB.Add(CleanupCalls.Of(name, args));
            }
            return null;
        };
        var confirmB = proxyB.Hold((name, args) => CleanupCalls.Of(name, args) == CleanupStep.Confirm);
        var b = Migration(TestRedis.Over(_mux, dbB)).RunAsync(Wait, CancellationToken.None);
        await confirmB.Reached.WaitAsync(TimeSpan.FromSeconds(15));

        // A begins first and holds its pass; then B's confirmation runs and is refused.
        beginA.Release();
        await pageA.Reached.WaitAsync(TimeSpan.FromSeconds(15));
        Assert.True(await Db.KeyExistsAsync(SessionStoreMigration.LockKey));
        var polls = CountOf(stepsB, CleanupStep.Status);
        confirmB.Release();
        await UntilAsync(() => CountOf(stepsB, CleanupStep.Status) >= polls + 4, "the second replica observes the pass");
        Assert.False(b.IsCompleted); // B does not serve during A's pass
        Assert.Equal(0, await GenerationAsync());

        pageA.Release();
        await Task.WhenAll(a, b).WaitAsync(TimeSpan.FromSeconds(15));

        Assert.Equal(0, CountOf(stepsB, CleanupStep.Begin));
        Assert.False(await Db.KeyExistsAsync(live)); // A's pass ended the rows of its start
        await AssertFinishedAsync(2); // A's pass, then B's confirmation
    }

    [RedisFact]
    public async Task TwoReplicasStartingTogether_RunOnePass_AndBothReturn()
    {
        await MarkAsync();
        var legacy = Legacy();
        await LegacyHashAsync(legacy);
        var v3 = await IssueV3Async(Guid.NewGuid());
        var dbA = DbProxy.Create(Db, out var proxyA);
        var heldA = proxyA.Hold((name, args) => CleanupCalls.Of(name, args) == CleanupStep.Extend);
        var a = Migration(TestRedis.Over(_mux, dbA)).RunAsync(Wait, CancellationToken.None);
        await heldA.Reached.WaitAsync(TimeSpan.FromSeconds(15));

        var (muxB, stepsB) = Watched();
        var b = Migration(muxB).RunAsync(Wait, CancellationToken.None);
        await UntilAsync(() => CountOf(stepsB, CleanupStep.Status) >= 3, "the second replica waits for the pass of the first");
        heldA.Release();

        await Task.WhenAll(a, b).WaitAsync(TimeSpan.FromSeconds(15));

        Assert.Equal(0, CountOf(stepsB, CleanupStep.Begin));
        Assert.False(await Db.KeyExistsAsync(legacy));
        Assert.False(await Db.KeyExistsAsync(v3));
        await AssertFinishedAsync(2); // A's pass, then B's confirmation
    }

    // ---- the failures of the start ------------------------------------------------------------------

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
    [InlineData(false, false)] // no primary known, a rollback to clean up after
    [InlineData(true, false)]  // a known primary that is not connected, a rollback to clean up after
    [InlineData(false, true)]  // no primary known, a plain restart
    [InlineData(true, true)]   // a known primary that is not connected, a plain restart
    public async Task Start_WithoutEveryPrimaryReachable_Fails_EvenOnAPlainRestart_AndWritesNothing(bool knownButDisconnected, bool plainRestart)
    {
        var row = Legacy();
        if (plainRestart)
        {
            await MarkAsync();
            row = await IssueV3Async(Guid.NewGuid());
        }
        else
        {
            await LegacyHashAsync(row);
        }
        var servers = new List<IServer>();
        if (knownButDisconnected)
        {
            var server = new Mock<IServer>();
            server.SetupGet(x => x.IsConnected).Returns(false);
            server.SetupGet(x => x.IsReplica).Returns(false);
            servers.Add(server.Object);
        }
        var mux = new Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(Db);
        mux.Setup(m => m.GetServers()).Returns(servers.ToArray());

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => Migration(mux.Object).RunAsync(Wait, CancellationToken.None));

        Assert.DoesNotContain("skein:", ex.Message);
        Assert.True(await Db.KeyExistsAsync(row));
        Assert.Equal(plainRestart, await Db.KeyExistsAsync(SessionStoreMigration.MarkerKey));
        Assert.False(await Db.KeyExistsAsync(SessionStoreMigration.LockKey));
        Assert.Equal(0, await GenerationAsync());
    }

    [RedisFact]
    public async Task ATimeoutOfTheClient_IsTheSameStartupFailure_NotTheRawException()
    {
        var db = new Mock<IDatabase>();
        db.Setup(d => d.ScriptEvaluateAsync(It.IsAny<string>(), It.IsAny<RedisKey[]>(), It.IsAny<RedisValue[]>(), It.IsAny<CommandFlags>()))
            .ThrowsAsync(new RedisTimeoutException("timed out on skein:session-format", CommandStatus.Unknown));
        var mux = new Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(db.Object);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new SessionStoreMigration(mux.Object, TimeProvider.System, NullLogger<SessionStoreMigration>.Instance)
                .RunAsync(TimeSpan.FromSeconds(1), CancellationToken.None));

        Assert.Null(ex.InnerException);
        Assert.DoesNotContain("skein:", ex.Message);
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
        var (before, beforeKey, _) = await host.SignInAsync(Alice);
        var preUpdate = "skein:session:legacy-" + Guid.NewGuid().ToString("N");
        await host.Db.HashSetAsync(preUpdate, [new HashEntry("absexp", -1), new HashEntry("sldexp", 86400), new HashEntry("data", new byte[] { 1 })]);
        await host.Db.KeyDeleteAsync(SessionStoreMigration.MarkerKey);

        await new SessionStoreMigration(host.Mux, TimeProvider.System, Microsoft.Extensions.Logging.Abstractions.NullLogger<SessionStoreMigration>.Instance)
            .RunAsync(TimeSpan.FromSeconds(10), CancellationToken.None);

        // (а) The session issued before the cleanup has ended with it (US-5), as has the row of the former version.
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.SendAsync("/test/me", before)).Status);
        Assert.False(await host.Db.KeyExistsAsync(beforeKey));
        Assert.False(await host.Db.KeyExistsAsync(preUpdate));

        // (б) A session issued after the cleanup lives, and the reader of the former version accepts
        // neither its cookie (the purpose differs) nor its row (HGETALL of a string: WRONGTYPE).
        var (after, afterKey, set) = await host.SignInAsync(Alice);
        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync("/test/me", after)).Status);
        var former = new TicketDataFormat(host.Services.GetRequiredService<IDataProtectionProvider>().CreateProtector(
            "Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware", "Cookies", "v2"));
        Assert.Null(former.Unprotect(Uri.UnescapeDataString(set.Value)));
        var wrongType = await Assert.ThrowsAsync<RedisServerException>(() => host.Db.HashGetAllAsync(afterKey));
        Assert.StartsWith("WRONGTYPE", wrongType.Message, StringComparison.Ordinal);
    }
}
