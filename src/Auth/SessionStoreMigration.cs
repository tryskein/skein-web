using StackExchange.Redis;

namespace SkeinWeb.Auth;

/// <summary>
/// One-time cleanup at startup of the session rows of the former format: the sessions of this
/// version are Redis strings, the former ones were hashes under the same <c>skein:session:*</c>
/// keys. No value of the former format is read or converted; the hashes are deleted so no session
/// issued before the update is accepted (a user signs in once), and nothing else is touched.
/// </summary>
/// <remarks>
/// <para>
/// The work is done once per deployment under a lock whose owner is a random token, and
/// recorded by the marker <c>skein:session-format</c> = <c>3</c>. When the marker is already
/// <c>3</c>, before or after the lock is taken, no key is deleted. A replica that does not get the
/// lock waits for the marker and fails with a startup timeout if it does not appear.
/// </para>
/// <para>
/// The lock lives <see cref="LockLifetime"/> and is extended on every batch of the scan; every
/// delete runs in a script that first checks the lock still belongs to this process, and deletes
/// only keys of type hash, so a paused owner that lost its lock deletes nothing and a string row of
/// the new model is never removed. The marker is written by a script under the same check, and only
/// then is the lock released.
/// </para>
/// <para>
/// Operator contract: after a rollback to the former version, delete <c>skein:session-format</c>
/// before rolling forward again. Without that the cleanup is skipped and hashes of the former
/// format are rejected anyway (<c>WRONGTYPE</c> is read as no session, and the cookie purpose
/// differs). Rows of this version that survived a rollback stay valid.
/// </para>
/// <para>
/// Keys of the data-protection key ring, the login throttle, the SignalR backplane and the
/// <c>skein:user-tickets:*</c> index are not touched. Redis exceptions are logged by type and
/// code, never with a key.
/// </para>
/// </remarks>
public sealed class SessionStoreMigration(
    IConnectionMultiplexer redis,
    TimeProvider timeProvider,
    ILogger<SessionStoreMigration> logger)
{
    /// <summary>The key that records that the cleanup was done.</summary>
    public const string MarkerKey = "skein:session-format";

    /// <summary>The value of <see cref="MarkerKey"/> of the session format of this version.</summary>
    public const string MarkerValue = "3";

    /// <summary>The key of the lock that serialises the cleanup.</summary>
    public const string LockKey = "skein:session-format:lock";

    private const string SessionKeyPattern = "skein:session:*";
    private const int BatchSize = 500;
    private static readonly TimeSpan LockLifetime = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan LockPollInterval = TimeSpan.FromMilliseconds(250);

    // Extend the lock if it is still ours.
    private const string ExtendLockScript =
        "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('PEXPIRE', KEYS[1], ARGV[2]) end return 0";

    // Delete the hash keys of a batch if the lock is still ours; -1 = the lock is not ours.
    private const string DeleteBatchScript =
        "if redis.call('GET', KEYS[1]) ~= ARGV[1] then return -1 end " +
        "local n = 0 " +
        "for i = 2, #KEYS do " +
        "if redis.call('TYPE', KEYS[i]).ok == 'hash' then redis.call('DEL', KEYS[i]) n = n + 1 end " +
        "end return n";

    // Write the marker if the lock is still ours.
    private const string WriteMarkerScript =
        "if redis.call('GET', KEYS[1]) == ARGV[1] then redis.call('SET', KEYS[2], ARGV[2]) return 1 end return 0";

    // Release the lock if it is still ours.
    private const string ReleaseLockScript =
        "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end return 0";

    /// <summary>
    /// Make sure the cleanup is done: do it under the lock, or wait for the replica that holds the
    /// lock to record the marker.
    /// </summary>
    /// <param name="timeout">How long to wait for the marker when another replica does the cleanup.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="InvalidOperationException">The cleanup failed, lost its lock, or did not
    /// finish within <paramref name="timeout"/>. The message names no key.</exception>
    public async Task RunAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        var deadline = timeProvider.GetUtcNow() + timeout;
        var db = redis.GetDatabase();
        var token = Guid.NewGuid().ToString("N");

        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (await IsMarkedAsync(db))
                {
                    return;
                }

                if (await db.StringSetAsync(LockKey, token, LockLifetime, When.NotExists))
                {
                    await CleanUnderLockAsync(db, token, cancellationToken);
                    return;
                }

                if (timeProvider.GetUtcNow() >= deadline)
                {
                    throw new InvalidOperationException(
                        "The session store cleanup of another replica did not finish within the startup timeout.");
                }
                await Task.Delay(LockPollInterval, timeProvider, cancellationToken);
            }
        }
        catch (Exception ex) when (ex is RedisException or RedisTimeoutException)
        {
            logger.LogError(
                "session store migration failed exceptionType={ExceptionType}", ex.GetType().Name);
            throw new InvalidOperationException("The session store cleanup failed on a Redis error.");
        }
    }

    private async Task CleanUnderLockAsync(IDatabase db, string token, CancellationToken ct)
    {
        try
        {
            // The marker may have been written between the check and the lock.
            if (await IsMarkedAsync(db))
            {
                return;
            }

            var removed = 0;
            var batch = new List<RedisKey>(BatchSize);
            // Every primary that is known must be scanned: a marker written after a partial scan would
            // hide the rows of the one that was not reached. No primary, or one not connected, stops the start.
            var primaries = redis.GetServers().Where(s => !s.IsReplica).ToList();
            if (primaries.Count == 0 || primaries.Any(s => !s.IsConnected))
            {
                throw new InvalidOperationException("The session store cleanup could not reach every Redis primary.");
            }
            foreach (var server in primaries)
            {
                await foreach (var key in server.KeysAsync(db.Database, SessionKeyPattern, BatchSize).WithCancellation(ct))
                {
                    batch.Add(key);
                    if (batch.Count >= BatchSize)
                    {
                        removed += await DeleteBatchAsync(db, token, batch);
                    }
                }
            }
            removed += await DeleteBatchAsync(db, token, batch);

            var written = (long)await db.ScriptEvaluateAsync(
                WriteMarkerScript, [(RedisKey)LockKey, (RedisKey)MarkerKey], [(RedisValue)token, (RedisValue)MarkerValue]);
            if (written != 1)
            {
                throw new InvalidOperationException("The session store cleanup lost its lock before it was recorded.");
            }

            logger.LogInformation("session store migration done: removed {Removed} sessions of the former format", removed);
        }
        finally
        {
            try
            {
                await db.ScriptEvaluateAsync(ReleaseLockScript, [(RedisKey)LockKey], [(RedisValue)token]);
            }
            catch (Exception ex) when (ex is RedisException or RedisTimeoutException)
            {
                // The lock expires by itself; nothing waits on it once the marker is written.
                logger.LogWarning("session store migration: lock not released exceptionType={ExceptionType}", ex.GetType().Name);
            }
        }
    }

    private async Task<int> DeleteBatchAsync(IDatabase db, string token, List<RedisKey> batch)
    {
        if (batch.Count == 0)
        {
            return 0;
        }

        var extended = (long)await db.ScriptEvaluateAsync(
            ExtendLockScript, [(RedisKey)LockKey], [(RedisValue)token, (RedisValue)(long)LockLifetime.TotalMilliseconds]);
        if (extended != 1)
        {
            throw new InvalidOperationException("The session store cleanup lost its lock.");
        }

        var keys = new RedisKey[batch.Count + 1];
        keys[0] = LockKey;
        batch.CopyTo(keys, 1);
        batch.Clear();

        var removed = (long)await db.ScriptEvaluateAsync(DeleteBatchScript, keys, [(RedisValue)token]);
        if (removed < 0)
        {
            throw new InvalidOperationException("The session store cleanup lost its lock.");
        }
        return (int)removed;
    }

    private static async Task<bool> IsMarkedAsync(IDatabase db) =>
        (string?)await db.StringGetAsync(MarkerKey) == MarkerValue;
}
