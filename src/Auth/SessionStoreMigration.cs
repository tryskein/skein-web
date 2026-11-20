using StackExchange.Redis;

namespace SkeinWeb.Auth;

/// <summary>
/// Startup cleanup of the session store: before the first request is served, every session row
/// under <c>skein:session:*</c> that existed when the cleanup began ends, when the store shows that
/// the former version ran on it. A plain restart ends no session.
/// </summary>
/// <remarks>
/// <para>
/// WHEN: the sessions of this version are Redis strings, the former ones (version 1.0.1) were
/// hashes under the same keys. Every start scans for such hashes (<c>SCAN … TYPE hash</c>). The
/// cleanup runs when a hash is found — the former version ran after a rollback, and the rows this
/// version left behind are ended with its own — or when the marker <c>skein:session-format</c> =
/// <c>3</c> is missing (deleted by the rollback procedure, or never written). With the marker in
/// place and no hash, nothing is deleted. Deleting the marker stays a required step of a rollback
/// that leaves no session of the former version behind: without it such a rollback is not seen.
/// </para>
/// <para>
/// PASS: the state is four keys — the marker, the lock <c>skein:session-format:lock</c> (the
/// random token of its owner, with a finite lifetime from the moment it is taken), the count
/// <c>skein:session-format:generation</c> (no key = 0) of finished passes and confirmed starts,
/// and the set of marks <c>skein:session-format:issued-during</c>. A replica observes the state
/// (marker, lock, count), scans for hashes and observes again. It serves only when both
/// observations show the marker <c>3</c>, no lock and the same count, the scan found nothing, and
/// <see cref="ConfirmReadyScript"/> confirms that state against the count of the first observation
/// in one step and counts the confirmation; else it observes again. When the scan found a hash or
/// the marker is missing, it enters a pass only through <see cref="BeginPassScript"/> with the
/// count of its first observation: when the lock is taken it waits until the lock is gone and
/// observes again; when the count differs (a pass finished, or a replica confirmed its start,
/// after the observation) it observes again; else the script takes the lock and deletes the marker
/// and the marks of an earlier pass in one step.
/// </para>
/// <para>
/// The owner scans <c>skein:session:*</c> page by page. Every page first extends the lock and the
/// set of marks by its token, then deletes the hashes and strings of the page except the rows
/// marked "own token:key": a session issued during the pass by a replica that is serving is marked
/// by the issue script before its row is written, and survives. The end
/// (<see cref="FinishPassScript"/>) counts the pass, writes the marker, drops the marks and the
/// lock in one step. Every step checks the token: an owner that lost its lock deletes nothing,
/// writes no marker and touches no mark of another pass. An owner whose pass fails releases its
/// lock; the lock of a process that stopped runs out by its lifetime. A replica waiting for
/// another pass leaves the wait when the lock is gone — the marker alone does not end it — and
/// observes again: a pass that did not finish is then run by that replica. A lock that is not gone
/// within the startup timeout fails the start.
/// </para>
/// <para>
/// Keys of the data-protection key ring, the login throttle, the SignalR backplane and the
/// <c>skein:user-tickets:*</c> index are not touched. Every key of a script is passed in
/// <c>KEYS</c>. Redis exceptions are logged by type, never with a key.
/// </para>
/// </remarks>
public sealed class SessionStoreMigration(
    IConnectionMultiplexer redis,
    TimeProvider timeProvider,
    ILogger<SessionStoreMigration> logger)
{
    /// <summary>The key that records the session format of the store; written at the end of a pass.</summary>
    public const string MarkerKey = "skein:session-format";

    /// <summary>The value of <see cref="MarkerKey"/> of the session format of this version.</summary>
    public const string MarkerValue = "3";

    /// <summary>The key of the lock of a pass; its value is the token of the owner.</summary>
    public const string LockKey = "skein:session-format:lock";

    /// <summary>
    /// The key of the count of finished passes and confirmed starts; no key means 0. A change of it
    /// after an observation tells the replica that the observation is stale.
    /// </summary>
    public const string GenerationKey = "skein:session-format:generation";

    /// <summary>The set of the marks of a pass; a member is "token of the pass:key of the row".</summary>
    public const string IssuedDuringKey = "skein:session-format:issued-during";

    /// <summary>The lifetime the lock and the set of marks get when the pass begins and on every page of its scan.</summary>
    public static readonly TimeSpan LockLifetime = TimeSpan.FromSeconds(30);

    private const string SessionKeyPattern = "skein:session:*";
    private const int PageSize = 500;
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(250);

    // The state in one call (KEYS: marker, lock, count): the marker or false, 1 when the lock
    // exists, the count of finished passes and confirmed starts.
    private const string PassStatusScript =
        "return {redis.call('GET', KEYS[1]), redis.call('EXISTS', KEYS[2]), " +
        "tonumber(redis.call('GET', KEYS[3]) or '0')}";

    // Enter a pass (KEYS: lock, count, marker, marks; ARGV: expected count, token, lifetime ms):
    // 1 = the lock is taken, 2 = the count is not the expected one (a pass finished, or a start was
    // confirmed, after the observation), 3 = begun: the lock is taken with its lifetime, the marker and the marks of an
    // earlier pass are deleted.
    private const string BeginPassScript =
        "if redis.call('EXISTS', KEYS[1]) == 1 then return 1 end " +
        "if tonumber(redis.call('GET', KEYS[2]) or '0') ~= tonumber(ARGV[1]) then return 2 end " +
        "redis.call('SET', KEYS[1], ARGV[2], 'PX', ARGV[3]) " +
        "redis.call('DEL', KEYS[3], KEYS[4]) " +
        "return 3";

    // A page of the scan (KEYS: lock, marks; ARGV: token, lifetime ms): extend both if the lock is
    // still ours; 0 = it is not.
    private const string ExtendPassScript =
        "if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end " +
        "redis.call('PEXPIRE', KEYS[1], ARGV[2]) " +
        "redis.call('PEXPIRE', KEYS[2], ARGV[2]) " +
        "return 1";

    // Delete the rows of a page (KEYS: lock, marks, rows...; ARGV: token): hashes and strings,
    // except a row marked "token:key" with the token of this pass. -1 = the lock is not ours.
    private const string DeletePageScript =
        "if redis.call('GET', KEYS[1]) ~= ARGV[1] then return -1 end " +
        "local n = 0 " +
        "for i = 3, #KEYS do " +
        "local t = redis.call('TYPE', KEYS[i]).ok " +
        "if (t == 'hash' or t == 'string') and " +
        "redis.call('SISMEMBER', KEYS[2], ARGV[1] .. ':' .. KEYS[i]) == 0 then " +
        "redis.call('DEL', KEYS[i]) n = n + 1 end " +
        "end return n";

    // End a pass (KEYS: lock, marker, count, marks; ARGV: token, marker value): if the lock is ours,
    // count the pass, write the marker, drop the marks and the lock. 0 = it is not ours. The count
    // goes first: a script stops at a failed command and keeps what it already wrote, so a failure
    // of INCR leaves no marker behind with the old count.
    private const string FinishPassScript =
        "if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end " +
        "redis.call('INCR', KEYS[3]) " +
        "redis.call('SET', KEYS[2], ARGV[2]) " +
        "redis.call('DEL', KEYS[4], KEYS[1]) " +
        "return 1";

    // Confirm the readiness of a replica (KEYS: marker, lock, count; ARGV: the count of its first
    // observation, marker value): when the marker is in place, there is no lock and the count is
    // still the observed one, count the confirmation and answer 1; else 0. A replica that observed
    // the same state before and begins a pass with the old count then finds "a pass finished after
    // the observation", so no replica serves while another one runs a pass.
    private const string ConfirmReadyScript =
        "if redis.call('GET', KEYS[1]) ~= ARGV[2] then return 0 end " +
        "if redis.call('EXISTS', KEYS[2]) == 1 then return 0 end " +
        "if tonumber(redis.call('GET', KEYS[3]) or '0') ~= tonumber(ARGV[1]) then return 0 end " +
        "redis.call('INCR', KEYS[3]) " +
        "return 1";

    // Release the lock of a pass that failed, if it is still ours; the marks expire or are
    // deleted by the next pass.
    private const string ReleaseLockScript =
        "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end return 0";

    private const long Busy = 1;
    private const long FinishedAfterObservation = 2;
    private const long Begun = 3;

    private readonly record struct PassStatus(bool Marked, bool Locked, long Generation);

    /// <summary>
    /// Make sure the store holds no session that predates a rollback: observe the state and confirm
    /// the readiness, run the pass when it is needed, or wait until the lock of another pass is gone
    /// and observe again.
    /// </summary>
    /// <param name="timeout">The window of the start: how long the lock of another pass may stay
    /// and the observation may keep changing.</param>
    /// <param name="cancellationToken">Cancellation token; a cancelled pass writes nothing more and
    /// releases its lock.</param>
    /// <exception cref="InvalidOperationException">The pass failed, lost its lock, a Redis primary
    /// was not reachable, the lock of another pass was not gone, or no settled state was observed,
    /// within <paramref name="timeout"/>. The message names no key.</exception>
    public async Task RunAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        var deadline = timeProvider.GetUtcNow() + timeout;
        var db = redis.GetDatabase();

        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var first = await ReadStatusAsync(db);
                var formerFound = await AnyFormerRowAsync(db, cancellationToken);
                var second = await ReadStatusAsync(db);

                if (first.Locked || second.Locked)
                {
                    await WaitForLockGoneAsync(db, deadline, cancellationToken);
                    continue;
                }
                if (first.Generation != second.Generation)
                {
                    ThrowPastDeadline(deadline); // a pass finished, or a start was confirmed, between the observations
                    continue;
                }
                if (first.Marked && second.Marked && !formerFound)
                {
                    var confirmed = (long)await db.ScriptEvaluateAsync(
                        ConfirmReadyScript,
                        [(RedisKey)MarkerKey, (RedisKey)LockKey, (RedisKey)GenerationKey],
                        [(RedisValue)first.Generation, (RedisValue)MarkerValue]);
                    if (confirmed == 1)
                    {
                        return;
                    }
                    ThrowPastDeadline(deadline); // the state changed after the observation
                    continue;
                }

                var token = Guid.NewGuid().ToString("N");
                var begun = (long)await db.ScriptEvaluateAsync(
                    BeginPassScript,
                    [(RedisKey)LockKey, (RedisKey)GenerationKey, (RedisKey)MarkerKey, (RedisKey)IssuedDuringKey],
                    [(RedisValue)first.Generation, (RedisValue)token, (RedisValue)(long)LockLifetime.TotalMilliseconds]);
                if (begun == Busy)
                {
                    await WaitForLockGoneAsync(db, deadline, cancellationToken);
                    continue;
                }
                if (begun == FinishedAfterObservation)
                {
                    ThrowPastDeadline(deadline);
                    continue;
                }
                if (begun != Begun)
                {
                    throw new InvalidOperationException("The session store cleanup got an unknown answer when it began.");
                }

                await RunPassAsync(db, token, cancellationToken);
                return;
            }
        }
        catch (Exception ex) when (ex is RedisException or RedisTimeoutException)
        {
            logger.LogError(
                "session store migration failed exceptionType={ExceptionType}", ex.GetType().Name);
            throw new InvalidOperationException("The session store cleanup failed on a Redis error.");
        }
    }

    /// <summary>
    /// Wait until the lock of another pass is gone: the pass finished, or its owner stopped and the
    /// lock ran out or was released. The marker alone does not end the wait. The caller then
    /// observes anew and runs its own pass when the other one did not finish.
    /// </summary>
    /// <summary>The start observes anew only within its window: past the deadline it fails, as the wait does.</summary>
    private void ThrowPastDeadline(DateTimeOffset deadline)
    {
        if (timeProvider.GetUtcNow() >= deadline)
        {
            throw new InvalidOperationException(
                "The session store cleanup could not observe a settled state within the startup timeout.");
        }
    }

    private async Task WaitForLockGoneAsync(IDatabase db, DateTimeOffset deadline, CancellationToken ct)
    {
        while (true)
        {
            var status = await ReadStatusAsync(db);
            if (!status.Locked)
            {
                return;
            }
            if (timeProvider.GetUtcNow() >= deadline)
            {
                throw new InvalidOperationException(
                    "The session store cleanup of another replica did not finish within the startup timeout.");
            }
            await Task.Delay(PollInterval, timeProvider, ct);
        }
    }

    private async Task RunPassAsync(IDatabase db, string token, CancellationToken ct)
    {
        try
        {
            var removed = 0L;
            foreach (var server in Primaries())
            {
                await ScanAsync(server, db.Database, type: null, async page =>
                {
                    ct.ThrowIfCancellationRequested(); // no write of the page after a cancellation
                    var extended = (long)await db.ScriptEvaluateAsync(
                        ExtendPassScript,
                        [(RedisKey)LockKey, (RedisKey)IssuedDuringKey],
                        [(RedisValue)token, (RedisValue)(long)LockLifetime.TotalMilliseconds]);
                    if (extended != 1)
                    {
                        throw new InvalidOperationException("The session store cleanup lost its lock.");
                    }
                    ct.ThrowIfCancellationRequested(); // a cancellation while the extension was answered
                    if (page.Length == 0)
                    {
                        return true;
                    }

                    var keys = new RedisKey[page.Length + 2];
                    keys[0] = LockKey;
                    keys[1] = IssuedDuringKey;
                    page.CopyTo(keys, 2);
                    var deleted = (long)await db.ScriptEvaluateAsync(DeletePageScript, keys, [(RedisValue)token]);
                    if (deleted < 0)
                    {
                        throw new InvalidOperationException("The session store cleanup lost its lock.");
                    }
                    removed += deleted;
                    return true;
                }, ct);
            }

            ct.ThrowIfCancellationRequested();
            var finished = (long)await db.ScriptEvaluateAsync(
                FinishPassScript,
                [(RedisKey)LockKey, (RedisKey)MarkerKey, (RedisKey)GenerationKey, (RedisKey)IssuedDuringKey],
                [(RedisValue)token, (RedisValue)MarkerValue]);
            if (finished != 1)
            {
                throw new InvalidOperationException("The session store cleanup lost its lock before it was recorded.");
            }

            logger.LogInformation("session store cleanup done: removed {Removed} sessions", removed);
        }
        catch
        {
            try
            {
                await db.ScriptEvaluateAsync(ReleaseLockScript, [(RedisKey)LockKey], [(RedisValue)token]);
            }
            catch (Exception ex) when (ex is RedisException or RedisTimeoutException)
            {
                // The lock expires by itself.
                logger.LogWarning("session store cleanup: lock not released exceptionType={ExceptionType}", ex.GetType().Name);
            }
            throw;
        }
    }

    private async Task<bool> AnyFormerRowAsync(IDatabase db, CancellationToken ct)
    {
        var found = false;
        foreach (var server in Primaries())
        {
            await ScanAsync(server, db.Database, type: "hash", page =>
            {
                found = page.Length > 0;
                return Task.FromResult(!found);
            }, ct);
            if (found)
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Every primary that is known must be scanned: a scan that missed one would hide its rows. No
    /// primary, or one not connected, stops the start.
    /// </summary>
    private List<IServer> Primaries()
    {
        var primaries = redis.GetServers().Where(s => !s.IsReplica).ToList();
        if (primaries.Count == 0 || primaries.Any(s => !s.IsConnected))
        {
            throw new InvalidOperationException("The session store cleanup could not reach every Redis primary.");
        }
        return primaries;
    }

    /// <summary>
    /// Walk <c>skein:session:*</c> of the database of this process with <c>SCAN</c>, one call of
    /// <paramref name="onPage"/> per page (an empty page included); it returns false to stop.
    /// </summary>
    private static async Task ScanAsync(
        IServer server, int database, string? type, Func<RedisKey[], Task<bool>> onPage, CancellationToken ct)
    {
        var cursor = "0";
        do
        {
            ct.ThrowIfCancellationRequested();
            List<object> args = [cursor, "MATCH", SessionKeyPattern, "COUNT", PageSize];
            if (type is not null)
            {
                args.Add("TYPE");
                args.Add(type);
            }
            var reply = (RedisResult[])(await server.ExecuteAsync(database, "SCAN", args))!;
            cursor = (string)reply[0]!;
            var page = ((RedisResult[])reply[1]!).Select(k => (RedisKey)(string)k!).ToArray();
            if (!await onPage(page))
            {
                return;
            }
        }
        while (cursor != "0");
    }

    private static async Task<PassStatus> ReadStatusAsync(IDatabase db)
    {
        var reply = (RedisResult[])(await db.ScriptEvaluateAsync(
            PassStatusScript, [(RedisKey)MarkerKey, (RedisKey)LockKey, (RedisKey)GenerationKey]))!;
        return new PassStatus(
            Marked: !reply[0].IsNull && (string?)reply[0] == MarkerValue,
            Locked: (long)reply[1] == 1,
            Generation: (long)reply[2]);
    }
}
