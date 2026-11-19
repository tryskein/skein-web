using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using StackExchange.Redis;

namespace SkeinWeb.Auth;

/// <summary>
/// Server-side session store for the cookie auth scheme. The browser cookie carries only an
/// opaque session key (32 random bytes, base64url, generated here); the
/// <see cref="AuthenticationTicket"/> — claims, window, properties — is a Redis string under
/// <c>skein:session:{key}</c>. The row lives for the idle lifetime of <see cref="SessionWindow"/>
/// from its last lifetime write and never past the end of its session.
/// </summary>
/// <remarks>
/// <para>
/// Rows are written straight to Redis, not through <c>IDistributedCache</c>, because the
/// session rules need atomic decisions: an issue is <c>SET NX</c> (a key is never overwritten),
/// a renewal is a compare-and-set against the bytes it read (it never creates an absent key, never
/// changes the owner of a live one and never changes the window written at sign-in), a revocation
/// reads and deletes in one step. The only renewal is the explicit one of the SSO confirmation;
/// the cookie handler does not renew on its own.
/// </para>
/// <para>
/// WRITE: an issue and a renewal give the row min(idle limit, time left until the end of the
/// session) in the same script that writes it, together with the reverse index. A renewal whose
/// session has ended by the time the script runs — by the clock of Redis — deletes the row and
/// writes nothing.
/// </para>
/// <para>
/// READ: every read checks the window of the ticket (<see cref="SessionWindow.TryRead"/>) and the
/// end of the session under the limits of this process. A row without a valid window, or whose
/// session has ended, is deleted and the read finds no session; otherwise one script moves the
/// row's lifetime (<c>PEXPIRE</c>) and maintains the reverse index. A row that disappeared before
/// that script ran is no session either.
/// </para>
/// <para>
/// REVERSE INDEX: next to each row the store keeps <c>skein:user-tickets:{userId}</c>, a Set of
/// the user's session keys, walked by <see cref="RemoveUserSessionsAsync"/>. It drives
/// event-driven invalidation and the hub's ownership probe. The script that writes a row's
/// lifetime also adds the key to the index and lifts the index lifetime to the row's actual one
/// (<see cref="IndexMaintain"/>), so the index never expires before a live row of its user; a
/// failed index part is repaired by the next lifetime write of that session. Members whose rows
/// are gone are removed when the user signs in next (<see cref="IndexPruneScript"/>).
/// </para>
/// <para>
/// The request-level decisions (suppressed write, renewal outcome, issued key, removed
/// keys, no-cancellation) are read from and written to <see cref="SessionRequestState"/> by the
/// overloads that take an <see cref="HttpContext"/>; the cookie handler calls those.
/// </para>
/// <para>
/// DIAGNOSTICS: an exception raised by an operation on a session key can carry the key in its
/// text, so such exceptions are never logged or passed on as an inner exception. The store logs
/// the operation, the exception type and a short code, and throws
/// <see cref="SessionStoreUnavailableException"/>.
/// </para>
/// </remarks>
public sealed class RedisTicketStore : ITicketStore, IUserSessionRevoker, ISessionTicketProbe
{
    /// <summary>Remembered SSO e-mail of a session, kept in <see cref="AuthenticationProperties.Items"/>.</summary>
    public const string SsoEmailItem = "skein.sso.email";

    /// <summary>Remembered SSO user name of a session, kept in <see cref="AuthenticationProperties.Items"/>.</summary>
    public const string SsoUserItem = "skein.sso.user";

    /// <summary>
    /// Marker an explicit SSO confirmation puts into the properties of a renewal: the pair of
    /// that ticket replaces the stored one. The store strips it; it is never persisted.
    /// </summary>
    public const string SsoPairWriteMarker = "skein.sso.pair-write";

    /// <summary>Redis key prefix; combined with the random key to form the row's Redis key.</summary>
    private const string KeyPrefix = "skein:session:";

    /// <summary>Reverse-index key prefix; combined with the user UUID to form a Set of session keys.</summary>
    private const string UserIndexPrefix = "skein:user-tickets:";

    /// <summary>Compare-and-set attempts of a renewal on a live key before it reports <see cref="RenewOutcome.CasExhausted"/>.</summary>
    private const int CasAttempts = 3;

    /// <summary>Attempts to find an unused key at issue (a collision of 256-bit keys does not happen; the bound is a guard).</summary>
    private const int IssueAttempts = 3;

    /// <summary>Attempts of one Redis step of a mass removal (index read, one ticket delete) before it counts as failed.</summary>
    private const int RemovalAttempts = 3;

    /// <summary>Pause before the second attempt of a removal step; doubled before the third.</summary>
    private static readonly TimeSpan RemovalRetryDelay = TimeSpan.FromMilliseconds(100);

    // Delete the row and hand back what it held: nil = there was no row, integer 1 = a row of
    // a kind this store cannot read (a hash of the former format) was deleted, otherwise the bytes.
    private const string GetAndDeleteScript =
        "local v = redis.pcall('GET', KEYS[1]) " +
        "if type(v) == 'table' then redis.call('DEL', KEYS[1]) return 1 end " +
        "if v then redis.call('DEL', KEYS[1]) return v end return false";

    /// <summary>
    /// Maintenance of the reverse index inside a script that has just written the lifetime of the
    /// row <c>KEYS[1]</c> (the row exists at this point): adds the member — the last argument,
    /// <c>ARGV[#ARGV]</c>, the session key — to the
    /// index <c>KEYS[2]</c> and gives the index the actual <c>PTTL</c> of the row when the index
    /// has no lifetime or a shorter one. Runs under <c>redis.pcall</c>: a failure returns
    /// <see cref="RowWriteIndexFailed"/> and leaves the written row as it is. Without
    /// <c>KEYS[2]</c> (a ticket without a user) there is no index to maintain.
    /// </summary>
    private const string IndexMaintain =
        "if #KEYS < 2 then return 1 end " +
        "local added = redis.pcall('SADD', KEYS[2], ARGV[#ARGV]) " +
        "if type(added) == 'table' and added.err then return 2 end " +
        "local row = redis.call('PTTL', KEYS[1]) " +
        "local index = redis.pcall('PTTL', KEYS[2]) " +
        "if type(index) == 'table' and index.err then return 2 end " +
        "if row > 0 and (index == -1 or row > index) then " +
        "local set = redis.pcall('PEXPIRE', KEYS[2], row) " +
        "if type(set) == 'table' and set.err then return 2 end end " +
        "return 1";

    // The lifetime write of a read: PEXPIRE of the row (ARGV[1] milliseconds), then the index.
    // A row that is gone is not recreated and gets no index member.
    private const string ReadLifetimeScript =
        "if redis.call('PEXPIRE', KEYS[1], ARGV[1]) == 0 then return 0 end " + IndexMaintain;

    // The issue: SET NX PX (ARGV[1] the ticket, ARGV[2] milliseconds), then the index. An existing
    // row (a collision) is left as it is and gets no index member.
    private const string IssueScript =
        "if not redis.call('SET', KEYS[1], ARGV[1], 'NX', 'PX', ARGV[2]) then return 0 end " + IndexMaintain;

    // The renewal: replace the row only if it still holds the bytes the renewal read (ARGV[1]); a row
    // that is gone is reported as such, apart from a row that holds other bytes.
    // The moment of the write is the clock of Redis: when the end of the session (ARGV[3], Unix
    // milliseconds) leaves less than 1 ms — the time left rounded down, as in SessionWindow —
    // the row is deleted and nothing is written; otherwise it gets the new bytes (ARGV[2]) for
    // min(idle limit ARGV[4] in milliseconds, time left), then the index.
    private const string CompareAndSetScript =
        "local current = redis.call('GET', KEYS[1]) " +
        "if not current then return 5 end " +
        "if current ~= ARGV[1] then return 3 end " +
        "local t = redis.call('TIME') " +
        "local now = tonumber(t[1]) * 1000 + math.floor((tonumber(t[2]) + 999) / 1000) " +
        "local left = tonumber(ARGV[3]) - now " +
        "if left < 1 then redis.call('DEL', KEYS[1]) return 4 end " +
        "redis.call('SET', KEYS[1], ARGV[2], 'PX', math.min(tonumber(ARGV[4]), left)) " + IndexMaintain;

    // Dead members of a reverse index (KEYS[1]): every member whose row no longer exists is
    // removed; members with a live row stay. Returns the number removed.
    private const string IndexPruneScript =
        "local dead = {} " +
        "for _, member in ipairs(redis.call('SMEMBERS', KEYS[1])) do " +
        "if redis.call('EXISTS', member) == 0 then dead[#dead + 1] = member end end " +
        "for i = 1, #dead, 1000 do " +
        "redis.call('SREM', KEYS[1], unpack(dead, i, math.min(i + 999, #dead))) end " +
        "return #dead";

    /// <summary>Outcome of the renewal script: the row no longer holds the bytes the renewal read; nothing was written.</summary>
    private const long RenewLost = 3;

    /// <summary>Outcome of the renewal script: the session had ended at the moment of the write; the row was deleted.</summary>
    private const long RenewEnded = 4;

    /// <summary>Outcome of the renewal script: the row is gone; nothing was written.</summary>
    private const long RenewAbsent = 5;

    /// <summary>Outcome of a lifetime-writing script: the row is not there; nothing was written.</summary>
    private const long RowWriteAbsent = 0;

    /// <summary>Outcome of a lifetime-writing script: the row is written and the index maintained.</summary>
    private const long RowWriteIndexed = 1;

    /// <summary>Outcome of a lifetime-writing script: the row is written; the index part failed.</summary>
    private const long RowWriteIndexFailed = 2;

    private readonly IConnectionMultiplexer _redis;
    private readonly SessionTimeouts _timeouts;
    private readonly TimeProvider _time;
    private readonly ILogger<RedisTicketStore> _logger;

    /// <summary>Creates the store.</summary>
    /// <param name="redis">Rows and reverse index.</param>
    /// <param name="timeouts">The session limits of this process: the end of a session and the row lifetime.</param>
    /// <param name="time">Clock of the end-of-session check and of the row lifetime.</param>
    /// <param name="logger">Logger.</param>
    public RedisTicketStore(IConnectionMultiplexer redis, SessionTimeouts timeouts, TimeProvider time, ILogger<RedisTicketStore> logger)
    {
        _redis = redis;
        _timeouts = timeouts;
        _time = time;
        _logger = logger;
    }

    // ---- ITicketStore: overloads without a request (no request decision exists) -------------

    /// <inheritdoc />
    public Task<string> StoreAsync(AuthenticationTicket ticket) =>
        StoreCoreAsync(ticket, new SessionRequestState(), CancellationToken.None);

    /// <inheritdoc />
    public Task RenewAsync(string key, AuthenticationTicket ticket) =>
        RenewCoreAsync(key, ticket, new SessionRequestState(), CancellationToken.None);

    /// <inheritdoc />
    public Task<AuthenticationTicket?> RetrieveAsync(string key) =>
        RetrieveCoreAsync(key, CancellationToken.None);

    /// <inheritdoc />
    public Task RemoveAsync(string key) =>
        RevokeCoreAsync(key, new SessionRequestState(), CancellationToken.None);

    // ---- ITicketStore: overloads the cookie handler calls ----------------------------------

    /// <summary>
    /// Persist a freshly issued ticket under a new random key and return the key (the cookie
    /// value). <c>SET NX</c> with the row lifetime of <see cref="SessionWindow.TryGetRowLifetime"/>:
    /// an existing row is never overwritten. The key is recorded in
    /// <see cref="SessionRequestState.IssuedKey"/>; <see cref="SessionRequestState.RenewOutcome"/>
    /// is not set.
    /// </summary>
    /// <exception cref="InvalidOperationException">The ticket has no valid window (<see cref="SessionWindow.TryRead"/>):
    /// a defect of the caller; nothing is written.</exception>
    /// <exception cref="SessionStoreUnavailableException">The store failed technically, or the session of
    /// the ticket has already ended; nothing is written.</exception>
    public Task<string> StoreAsync(AuthenticationTicket ticket, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var state = SessionRequestState.Of(httpContext);
        return StoreCoreAsync(ticket, state, state.Effective(cancellationToken));
    }

    /// <summary>
    /// Renew the row of <paramref name="key"/> (the explicit SSO renewal). Never creates an absent
    /// key, never changes the owner of a live one and keeps the window of the stored row whatever
    /// the incoming ticket carries; the result is in <see cref="SessionRequestState.RenewOutcome"/>.
    /// A session that has ended — before the attempt by the clock of this process, or at the
    /// moment of the write by the clock of Redis — has its row deleted and is
    /// <see cref="RenewOutcome.KeyAbsent"/>.
    /// </summary>
    /// <exception cref="SessionStoreUnavailableException">The store failed technically.</exception>
    public Task RenewAsync(string key, AuthenticationTicket ticket, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var state = SessionRequestState.Of(httpContext);
        return RenewCoreAsync(key, ticket, state, state.Effective(cancellationToken));
    }

    /// <summary>
    /// Look up a ticket by its key and write the row's lifetime anew (min(idle limit, time left
    /// until the end of the session), <see cref="SessionWindow.TryGetRowLifetime"/>). Null when the
    /// key is unknown or expired in Redis, of a kind this store cannot read (a hash of the former
    /// format), without a valid window (unreadable bytes included), when its session has ended under
    /// the limits of this process, or when the row disappeared before its lifetime was written. A row
    /// without a valid window or of an ended session is deleted.
    /// </summary>
    /// <exception cref="SessionStoreUnavailableException">The store failed technically.</exception>
    public Task<AuthenticationTicket?> RetrieveAsync(string key, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var state = SessionRequestState.Of(httpContext);
        return RetrieveCoreAsync(key, state.Effective(cancellationToken));
    }

    /// <summary>
    /// Remove the row of <paramref name="key"/>. A key already removed in this request
    /// (<see cref="SessionRequestState.RemovedKeys"/>) is a no-op that does not call the store.
    /// </summary>
    /// <exception cref="SessionStoreUnavailableException">The store failed technically.</exception>
    public Task RemoveAsync(string key, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var state = SessionRequestState.Of(httpContext);
        return RevokeCoreAsync(key, state, state.Effective(cancellationToken));
    }

    /// <summary>
    /// Revoke the session of <paramref name="key"/>: <c>DEL</c> that reports whether a row was
    /// there. "No such key" is a success (<c>false</c>), and the key is recorded in
    /// <see cref="SessionRequestState.RemovedKeys"/> either way; the owner's index entry is removed
    /// best-effort.
    /// </summary>
    /// <returns>True when a row existed and was deleted.</returns>
    /// <exception cref="SessionStoreUnavailableException">The store failed technically.</exception>
    public Task<bool> RevokeAsync(string key, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var state = SessionRequestState.Of(httpContext);
        return RevokeCoreAsync(key, state, state.Effective(cancellationToken));
    }

    // ---- Issue ---------------------------------------------------------------------------------

    private async Task<string> StoreCoreAsync(AuthenticationTicket ticket, SessionRequestState state, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var stored = StripPairMarker(ticket);
        if (!SessionWindow.TryRead(stored.Properties, out var window))
        {
            throw new InvalidOperationException("A session ticket is issued without a valid window.");
        }
        if (!window.TryGetRowLifetime(_timeouts, _time.GetUtcNow(), out var lifetime))
        {
            // Unreachable with an absolute limit of at least 1 h; refused like a failed issue.
            _logger.LogWarning("session issue refused: the session of the ticket has already ended");
            throw new SessionStoreUnavailableException();
        }

        var db = _redis.GetDatabase();
        await TryPruneIndexAsync(db, stored, ct);
        try
        {
            for (var attempt = 1; attempt <= IssueAttempts; attempt++)
            {
                var key = KeyPrefix + NewSessionId();
                var bytes = TicketSerializer.Default.Serialize(SessionPrincipal.WithSessionKey(stored, key));
                var outcome = (long)await db.ScriptEvaluateAsync(
                    IssueScript,
                    LifetimeKeys(key, stored),
                    [(RedisValue)bytes, (RedisValue)(long)lifetime.TotalMilliseconds, (RedisValue)key]).WaitAsync(ct);
                if (outcome == RowWriteAbsent)
                {
                    continue; // the key is taken
                }
                state.IssuedKey = key;
                if (outcome == RowWriteIndexFailed)
                {
                    LogIndexFailure("store");
                }
                return key;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogFailure("store", ex);
        }
        throw new SessionStoreUnavailableException();
    }

    // ---- Renewal -------------------------------------------------------------------------------

    private async Task RenewCoreAsync(string key, AuthenticationTicket ticket, SessionRequestState state, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (state.SuppressMainWrite)
        {
            state.RenewOutcome = RenewOutcome.Suppressed;
            return;
        }

        try
        {
            state.RenewOutcome = await TryRenewAsync(key, ticket, ct);
        }
        catch (RedisServerException ex) when (IsWrongType(ex))
        {
            // A row of the former format (a hash) is not a session of this store.
            state.RenewOutcome = RenewOutcome.KeyAbsent;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogFailure("renew", ex);
            throw new SessionStoreUnavailableException();
        }
    }

    private async Task<RenewOutcome> TryRenewAsync(string key, AuthenticationTicket ticket, CancellationToken ct)
    {
        var db = _redis.GetDatabase();
        var newOwner = TryReadUserId(ticket.Principal);

        for (var attempt = 1; attempt <= CasAttempts; attempt++)
        {
            byte[]? current = await db.StringGetAsync(key).WaitAsync(ct);
            if (current is null)
            {
                return RenewOutcome.KeyAbsent;
            }

            var stored = TryDeserialize(current);
            if (stored is null)
            {
                return RenewOutcome.KeyAbsent;
            }
            if (TryReadUserId(stored.Principal) != newOwner)
            {
                return RenewOutcome.OwnerMismatch;
            }

            // The window is the one written at sign-in; a session without a valid one, or one that has
            // ended by the clock of this process, is gone. The script decides again at the moment of the write.
            if (!SessionWindow.TryRead(stored.Properties, out var window)
                || !window.TryGetRowLifetime(_timeouts, _time.GetUtcNow(), out _))
            {
                await db.KeyDeleteAsync(key).WaitAsync(ct);
                return RenewOutcome.KeyAbsent;
            }

            var merged = SessionPrincipal.WithSessionKey(MergePair(ticket, stored, window), key);
            var bytes = TicketSerializer.Default.Serialize(merged);
            var outcome = (long)await db.ScriptEvaluateAsync(
                CompareAndSetScript,
                LifetimeKeys(key, stored),
                [
                    (RedisValue)current,
                    (RedisValue)bytes,
                    (RedisValue)window.SessionEnd(_timeouts).ToUnixTimeMilliseconds(),
                    (RedisValue)(_timeouts.Idle.Ticks / TimeSpan.TicksPerMillisecond),
                    (RedisValue)key,
                ]).WaitAsync(ct);
            switch (outcome)
            {
                case RowWriteIndexed:
                    return RenewOutcome.Written;
                case RowWriteIndexFailed:
                    LogIndexFailure("renew");
                    return RenewOutcome.Written;
                case RenewEnded:
                case RenewAbsent:
                    return RenewOutcome.KeyAbsent;
            }
        }

        return RenewOutcome.CasExhausted;
    }

    /// <summary>
    /// The ticket to write on a renewal: the incoming principal and properties, with the window of
    /// the stored row (<paramref name="window"/>, never the incoming one). With
    /// <see cref="SsoPairWriteMarker"/> the pair of <paramref name="incoming"/> is an explicit
    /// confirmation and replaces the stored one; without it the pair is the one already stored. The
    /// marker is never kept.
    /// </summary>
    private static AuthenticationTicket MergePair(AuthenticationTicket incoming, AuthenticationTicket stored, SessionWindow window)
    {
        var properties = incoming.Properties.Clone();
        properties.IssuedUtc = window.IssuedUtc;
        properties.ExpiresUtc = window.ExpiresUtc;
        var confirmed = properties.Items.Remove(SsoPairWriteMarker);
        if (!confirmed)
        {
            properties.Items.Remove(SsoEmailItem);
            properties.Items.Remove(SsoUserItem);
            foreach (var item in new[] { SsoEmailItem, SsoUserItem })
            {
                if (stored.Properties.Items.TryGetValue(item, out var value))
                {
                    properties.Items[item] = value;
                }
            }
        }
        return new AuthenticationTicket(incoming.Principal, properties, incoming.AuthenticationScheme);
    }

    private static AuthenticationTicket StripPairMarker(AuthenticationTicket ticket)
    {
        if (!ticket.Properties.Items.ContainsKey(SsoPairWriteMarker))
        {
            return ticket;
        }
        var properties = ticket.Properties.Clone();
        properties.Items.Remove(SsoPairWriteMarker);
        return new AuthenticationTicket(ticket.Principal, properties, ticket.AuthenticationScheme);
    }

    // ---- Read ----------------------------------------------------------------------------------

    private async Task<AuthenticationTicket?> RetrieveCoreAsync(string key, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var db = _redis.GetDatabase();
        byte[]? bytes;
        try
        {
            bytes = await db.StringGetAsync(key).WaitAsync(ct);
        }
        catch (RedisServerException ex) when (IsWrongType(ex))
        {
            // A row of the former format (a hash): not a session of this store.
            return null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogFailure("retrieve", ex);
            throw new SessionStoreUnavailableException();
        }
        if (bytes is null || bytes.Length == 0)
        {
            return null;
        }

        var ticket = TryDeserializeQuietly(bytes);
        if (ticket is null || !SessionWindow.TryRead(ticket.Properties, out var window))
        {
            await DeleteRowAsync(db, key, "retrieve-invalid", ct);
            _logger.LogWarning(
                "session row without a valid window deleted; treated as no session reason={Reason}",
                ticket is null ? "unreadable" : "window");
            return null;
        }

        if (!window.TryGetRowLifetime(_timeouts, _time.GetUtcNow(), out var lifetime))
        {
            // The session has ended: a regular end, not logged.
            await DeleteRowAsync(db, key, "retrieve-ended", ct);
            return null;
        }

        long outcome;
        try
        {
            var result = await db.ScriptEvaluateAsync(
                ReadLifetimeScript,
                LifetimeKeys(key, ticket),
                [(RedisValue)(long)lifetime.TotalMilliseconds, (RedisValue)key]).WaitAsync(ct);
            outcome = (long)result;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogFailure("retrieve-lifetime", ex);
            throw new SessionStoreUnavailableException();
        }

        if (outcome == RowWriteAbsent)
        {
            // The row disappeared between the read and the lifetime write: it does not authenticate.
            return null;
        }
        if (outcome == RowWriteIndexFailed)
        {
            LogIndexFailure("retrieve");
        }
        return ticket;
    }

    /// <summary>
    /// <c>KEYS</c> of a lifetime-writing script: the row and, when the ticket names its user, the
    /// user's reverse index (<see cref="IndexMaintain"/>).
    /// </summary>
    private static RedisKey[] LifetimeKeys(string key, AuthenticationTicket ticket) =>
        TryReadUserId(ticket.Principal) is { } userId
            ? [(RedisKey)key, (RedisKey)(UserIndexPrefix + userId)]
            : [(RedisKey)key];

    /// <summary>Delete a row the read found unusable; a technical failure is a store failure.</summary>
    private async Task DeleteRowAsync(IDatabase db, string key, string operation, CancellationToken ct)
    {
        try
        {
            await db.KeyDeleteAsync(key).WaitAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogFailure(operation, ex);
            throw new SessionStoreUnavailableException();
        }
    }

    private static AuthenticationTicket? TryDeserializeQuietly(byte[] bytes)
    {
        try
        {
            return TicketSerializer.Default.Deserialize(bytes);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return null;
        }
    }

    private AuthenticationTicket? TryDeserialize(byte[] bytes)
    {
        try
        {
            return TicketSerializer.Default.Deserialize(bytes);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning("session ticket cannot be read; treated as no session exceptionType={ExceptionType}", ex.GetType().Name);
            return null;
        }
    }

    // ---- Revocation ----------------------------------------------------------------------------

    private async Task<bool> RevokeCoreAsync(string key, SessionRequestState state, CancellationToken ct)
    {
        if (state.RemovedKeys.Contains(key))
        {
            return false;
        }
        ct.ThrowIfCancellationRequested();

        bool existed;
        Guid? owner = null;
        try
        {
            var result = await _redis.GetDatabase().ScriptEvaluateAsync(GetAndDeleteScript, [(RedisKey)key]).WaitAsync(ct);
            existed = !result.IsNull;
            if (existed && result.Resp3Type != ResultType.Integer && (byte[]?)result is { } bytes)
            {
                owner = TryDeserialize(bytes) is { } ticket ? TryReadUserId(ticket.Principal) : null;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogFailure("revoke", ex);
            throw new SessionStoreUnavailableException();
        }

        state.RemovedKeys.Add(key);
        if (owner is { } userId)
        {
            await TryUnindexAsync(userId, key);
        }
        return existed;
    }

    /// <summary>
    /// Hard-revoke EVERY active session of <paramref name="userId"/> and return how many session
    /// keys were enumerated. Used by <see cref="UserChangedSubscriber"/> when the claims baked into
    /// a cookie principal change.
    /// </summary>
    /// <param name="userId">UUID of the user whose sessions to invalidate.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task<int> RemoveByUserIdAsync(Guid userId, CancellationToken ct) =>
        (await RemoveUserSessionsAsync(userId, keepKey: null, ct)).Removed;

    /// <inheritdoc />
    /// <remarks>
    /// Each Redis step — the index read, every ticket delete — is tried
    /// <see cref="RemovalAttempts"/> times. After the walk only the members that were processed
    /// leave the index (<c>SREM</c>); the kept key, every key whose delete failed and every member
    /// added meanwhile stay, so a later revocation still finds them.
    /// </remarks>
    public Task<SessionRemovalResult> RemoveSessionsAsync(Guid userId, string? keepKey, CancellationToken ct) =>
        RemoveUserSessionsAsync(userId, keepKey, ct);

    private async Task<SessionRemovalResult> RemoveUserSessionsAsync(Guid userId, string? keepKey, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var db = _redis.GetDatabase();
        var indexKey = UserIndexPrefix + userId;

        RedisValue[]? members = null;
        for (var attempt = 1; members is null; attempt++)
        {
            try
            {
                members = await db.SetMembersAsync(indexKey).WaitAsync(ct);
            }
            catch (Exception ex) when (attempt < RemovalAttempts && ex is not OperationCanceledException)
            {
                LogFailure("index-read-retry", ex);
                await Task.Delay(RemovalRetryDelay * attempt, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                LogFailure("index-read", ex);
                return new SessionRemovalResult(0, 0, IndexRead: false);
            }
        }

        var processed = new List<RedisValue>();
        var failed = 0;
        foreach (var member in members)
        {
            ct.ThrowIfCancellationRequested();
            var key = (string?)member;
            if (string.IsNullOrEmpty(key) || string.Equals(key, keepKey, StringComparison.Ordinal))
            {
                continue;
            }
            if (await TryDeleteRowAsync(key, ct))
            {
                processed.Add(member);
            }
            else
            {
                failed++;
            }
        }

        if (processed.Count > 0)
        {
            try
            {
                await db.SetRemoveAsync(indexKey, processed.ToArray()).WaitAsync(ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                LogFailure("index-prune", ex);
            }
        }

        return new SessionRemovalResult(processed.Count, failed, IndexRead: true);
    }

    private async Task<bool> TryDeleteRowAsync(string key, CancellationToken ct)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                await _redis.GetDatabase().KeyDeleteAsync(key).WaitAsync(ct);
                return true;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                if (attempt >= RemovalAttempts)
                {
                    LogFailure("delete", ex);
                    return false;
                }
                await Task.Delay(RemovalRetryDelay * attempt, ct);
            }
        }
    }

    // ---- Probes ---------------------------------------------------------------------------------

    /// <summary>
    /// Whether the row <paramref name="key"/> is still stored — false once the session was signed
    /// out, revoked or removed, or has expired. Uses <c>EXISTS</c>, not a read, so it does not
    /// write the row's lifetime: a session with an open hub connection must still expire.
    /// </summary>
    /// <exception cref="SessionStoreUnavailableException">The store is unreachable; the caller decides.</exception>
    public async Task<bool> ExistsAsync(string key, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            return await _redis.GetDatabase().KeyExistsAsync(key).WaitAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogFailure("exists", ex);
            throw new SessionStoreUnavailableException();
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// Ownership is read from the reverse index: the key is in <c>skein:user-tickets:{userId}</c>.
    /// A revocation of the user's sessions drops the member.
    /// </remarks>
    /// <exception cref="SessionStoreUnavailableException">The store failed technically.</exception>
    public async Task<bool> IsSessionOfAsync(string key, Guid userId, CancellationToken ct)
    {
        try
        {
            if (!await _redis.GetDatabase().SetContainsAsync(UserIndexPrefix + userId, key).WaitAsync(ct))
            {
                return false;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogFailure("is-session-of", ex);
            throw new SessionStoreUnavailableException();
        }
        return await ExistsAsync(key, ct);
    }

    // ---- Index ----------------------------------------------------------------------------------

    /// <summary>
    /// Remove from the reverse index of the ticket's user the members whose rows are gone, before an
    /// issue (<see cref="IndexPruneScript"/>), so dead members do not outlive the user's next
    /// sign-in. Live members stay. Best-effort: a failure leaves the index as it was and does not
    /// affect the issue.
    /// </summary>
    private async Task TryPruneIndexAsync(IDatabase db, AuthenticationTicket ticket, CancellationToken ct)
    {
        if (TryReadUserId(ticket.Principal) is not { } userId)
        {
            return;
        }
        try
        {
            await db.ScriptEvaluateAsync(IndexPruneScript, [(RedisKey)(UserIndexPrefix + userId)]).WaitAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogFailure("index-prune-dead", ex);
        }
    }

    private async Task TryUnindexAsync(Guid userId, string key)
    {
        try
        {
            await _redis.GetDatabase().SetRemoveAsync(UserIndexPrefix + userId, key);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogFailure("index-prune", ex);
        }
    }

    // ---- Helpers --------------------------------------------------------------------------------

    private static Guid? TryReadUserId(ClaimsPrincipal principal)
    {
        var raw = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(raw))
        {
            return null;
        }
        return Guid.TryParse(raw, out var uid) ? uid : null;
    }

    private static bool IsWrongType(RedisServerException ex) =>
        ex.Message.StartsWith("WRONGTYPE", StringComparison.Ordinal);

    /// <summary>
    /// Log a failed operation by operation name, exception type and code only. The exception
    /// itself is never passed on: its text can contain the session key.
    /// </summary>
    private void LogFailure(string operation, Exception ex) =>
        _logger.LogWarning(
            "session store operation failed operation={Operation} exceptionType={ExceptionType} code={Code}",
            operation, ex.GetType().Name, CodeOf(ex));

    /// <summary>The index part of a lifetime write failed; logged without the key, the request is not affected.</summary>
    private void LogIndexFailure(string operation) =>
        _logger.LogWarning("session index maintenance failed operation={Operation}", operation);

    private static string CodeOf(Exception ex) => ex switch
    {
        RedisServerException server => ServerErrorCode(server.Message),
        RedisConnectionException connection => connection.FailureType.ToString(),
        RedisTimeoutException => "TIMEOUT",
        _ => "-",
    };

    // The code of a Redis error reply is its first word in capitals (WRONGTYPE, LOADING, NOSCRIPT…).
    private static string ServerErrorCode(string message)
    {
        var end = 0;
        while (end < message.Length && message[end] is >= 'A' and <= 'Z')
        {
            end++;
        }
        return end == 0 ? "-" : message[..end];
    }

    /// <summary>
    /// Generate a 32-byte (256-bit) cryptographically random session id and
    /// encode it base64url (no padding) for cookie-safe transport.
    /// </summary>
    private static string NewSessionId()
    {
        Span<byte> raw = stackalloc byte[32];
        RandomNumberGenerator.Fill(raw);
        var b64 = Convert.ToBase64String(raw);
        // RFC 4648 §5 (base64url): + → -, / → _, drop trailing =
        return b64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
