using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using StackExchange.Redis;

namespace SkeinWeb.Auth;

/// <summary>
/// Server-side session store for the cookie auth scheme. The browser cookie carries only an
/// opaque session key (32 random bytes, base64url, generated here); the
/// <see cref="AuthenticationTicket"/> — claims, expiry, properties — is a Redis string under
/// <c>skein:session:{key}</c> with a sliding 24 h lifetime.
/// </summary>
/// <remarks>
/// <para>
/// Rows are written straight to Redis, not through <c>IDistributedCache</c>, because the
/// session rules need atomic decisions: an issue is <c>SET NX</c> (a key is never overwritten),
/// a renewal is a compare-and-set against the bytes it read (it never creates an absent key and
/// never changes the owner of a live one), a revocation reads and deletes in one step.
/// </para>
/// <para>
/// REVERSE INDEX: next to each row the store keeps <c>skein:user-tickets:{userId}</c>, a Set of
/// the user's session keys, written on every issue and successful renewal (best-effort) and
/// walked by <see cref="RemoveUserSessionsAsync"/>. It drives event-driven invalidation and the
/// hub's ownership probe.
/// </para>
/// <para>
/// The request-level decisions (suppressed late write, renewal outcome, issued key, removed
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

    /// <summary>Sliding session lifetime. 24h matches the cookie ExpireTimeSpan.</summary>
    private static readonly TimeSpan SessionLifetime = TimeSpan.FromHours(24);

    /// <summary>Compare-and-set attempts of a renewal on a live key before it reports <see cref="RenewOutcome.CasExhausted"/>.</summary>
    private const int CasAttempts = 3;

    /// <summary>Attempts to find an unused key at issue (a collision of 256-bit keys does not happen; the bound is a guard).</summary>
    private const int IssueAttempts = 3;

    /// <summary>Attempts of one Redis step of a mass removal (index read, one ticket delete) before it counts as failed.</summary>
    private const int RemovalAttempts = 3;

    /// <summary>Pause before the second attempt of a removal step; doubled before the third.</summary>
    private static readonly TimeSpan RemovalRetryDelay = TimeSpan.FromMilliseconds(100);

    // Replace the row only if it still holds the bytes the renewal read.
    private const string CompareAndSetScript =
        "if redis.call('GET', KEYS[1]) == ARGV[1] then " +
        "redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3]) return 1 end return 0";

    // Delete the row and hand back what it held: nil = there was no row, integer 1 = a row of
    // a kind this store cannot read (a hash of the former format) was deleted, otherwise the bytes.
    private const string GetAndDeleteScript =
        "local v = redis.pcall('GET', KEYS[1]) " +
        "if type(v) == 'table' then redis.call('DEL', KEYS[1]) return 1 end " +
        "if v then redis.call('DEL', KEYS[1]) return v end return false";

    private readonly IConnectionMultiplexer _redis;
    private readonly ILogger<RedisTicketStore> _logger;

    /// <summary>Creates the store.</summary>
    /// <param name="redis">Rows and reverse index.</param>
    /// <param name="logger">Logger.</param>
    public RedisTicketStore(IConnectionMultiplexer redis, ILogger<RedisTicketStore> logger)
    {
        _redis = redis;
        _logger = logger;
    }

    // ---- ITicketStore: overloads without a request (no request decision exists) -------------

    /// <inheritdoc />
    public Task<string> StoreAsync(AuthenticationTicket ticket) =>
        StoreCoreAsync(ticket, new SessionRequestState(), CancellationToken.None);

    /// <inheritdoc />
    public Task RenewAsync(string key, AuthenticationTicket ticket) =>
        RenewCoreAsync(key, ticket, new SessionRequestState { ExplicitRenewal = true }, CancellationToken.None);

    /// <inheritdoc />
    public Task<AuthenticationTicket?> RetrieveAsync(string key) =>
        RetrieveCoreAsync(key, CancellationToken.None);

    /// <inheritdoc />
    public Task RemoveAsync(string key) =>
        RevokeCoreAsync(key, new SessionRequestState(), CancellationToken.None);

    // ---- ITicketStore: overloads the cookie handler calls ----------------------------------

    /// <summary>
    /// Persist a freshly issued ticket under a new random key and return the key (the cookie
    /// value). <c>SET NX</c> with the session lifetime: an existing row is never overwritten. The
    /// key is recorded in <see cref="SessionRequestState.IssuedKey"/>;
    /// <see cref="SessionRequestState.RenewOutcome"/> is not set.
    /// </summary>
    public Task<string> StoreAsync(AuthenticationTicket ticket, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var state = SessionRequestState.Of(httpContext);
        return StoreCoreAsync(ticket, state, state.Effective(cancellationToken));
    }

    /// <summary>
    /// Renew the row of <paramref name="key"/> as the request decided. Never creates an absent
    /// key and never changes the owner of a live one; the result is in
    /// <see cref="SessionRequestState.RenewOutcome"/>. A technical failure is absorbed as
    /// <see cref="RenewOutcome.TechnicalFailure"/> unless <see cref="SessionRequestState.ExplicitRenewal"/>
    /// is set, in which case it is thrown.
    /// </summary>
    public Task RenewAsync(string key, AuthenticationTicket ticket, HttpContext httpContext, CancellationToken cancellationToken)
    {
        var state = SessionRequestState.Of(httpContext);
        return RenewCoreAsync(key, ticket, state, state.Effective(cancellationToken));
    }

    /// <summary>
    /// Look up a ticket by its key and slide its lifetime. Null when the key is unknown, expired,
    /// of a kind this store cannot read (a hash of the former format) or its bytes are unusable.
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
        try
        {
            var db = _redis.GetDatabase();
            for (var attempt = 1; attempt <= IssueAttempts; attempt++)
            {
                var key = KeyPrefix + NewSessionId();
                var bytes = TicketSerializer.Default.Serialize(SessionPrincipal.WithSessionKey(stored, key));
                if (await db.StringSetAsync(key, bytes, SessionLifetime, When.NotExists).WaitAsync(ct))
                {
                    state.IssuedKey = key;
                    await TryIndexAsync(ticket, key);
                    return key;
                }
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
            state.RenewOutcome = await TryRenewAsync(key, ticket, state.ExplicitRenewal, ct);
        }
        catch (RedisServerException ex) when (IsWrongType(ex))
        {
            // A row of the former format (a hash) is not a session of this store.
            state.RenewOutcome = RenewOutcome.KeyAbsent;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogFailure("renew", ex);
            if (state.ExplicitRenewal)
            {
                throw new SessionStoreUnavailableException();
            }
            state.RenewOutcome = RenewOutcome.TechnicalFailure;
        }
    }

    private async Task<RenewOutcome> TryRenewAsync(string key, AuthenticationTicket ticket, bool explicitRenewal, CancellationToken ct)
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

            // An explicit renewal (the SSO confirmation) writes the claims it confirmed. An automatic one
            // (the sliding renewal of the cookie handler) only moves the expiry: its ticket is a clone
            // of a read made earlier in the request and must not roll back claims a parallel
            // confirmation wrote since.
            var merged = SessionPrincipal.WithSessionKey(
                explicitRenewal ? MergePair(ticket, stored) : ExtendOnly(ticket, stored), key);
            var bytes = TicketSerializer.Default.Serialize(merged);
            var result = await db.ScriptEvaluateAsync(
                CompareAndSetScript,
                [(RedisKey)key],
                [(RedisValue)current, (RedisValue)bytes, (RedisValue)(long)SessionLifetime.TotalSeconds]).WaitAsync(ct);
            if ((long)result == 1)
            {
                await TryIndexAsync(ticket, key);
                return RenewOutcome.Written;
            }
        }

        return RenewOutcome.CasExhausted;
    }

    /// <summary>
    /// The ticket to write on a renewal. With <see cref="SsoPairWriteMarker"/> the pair of
    /// <paramref name="incoming"/> is an explicit confirmation and replaces the stored one;
    /// without it the pair is the one already stored (the incoming properties are a clone of an
    /// older read and must not overwrite a newer confirmation). The marker is never kept.
    /// </summary>
    private static AuthenticationTicket MergePair(AuthenticationTicket incoming, AuthenticationTicket stored)
    {
        var properties = incoming.Properties.Clone();
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

    /// <summary>
    /// The row as it is stored now, with its window (IssuedUtc and ExpiresUtc, always together: the cookie
    /// handler measures the window as their difference) replaced by the incoming one only when the incoming
    /// window ends later. Never earlier than what a parallel writer set, and never a window of another length.
    /// </summary>
    private static AuthenticationTicket ExtendOnly(AuthenticationTicket incoming, AuthenticationTicket stored)
    {
        var properties = stored.Properties.Clone();
        properties.Items.Remove(SsoPairWriteMarker);
        if (incoming.Properties.ExpiresUtc is { } incomingExpiry
            && (properties.ExpiresUtc is not { } storedExpiry || incomingExpiry > storedExpiry))
        {
            properties.ExpiresUtc = incomingExpiry;
            properties.IssuedUtc = incoming.Properties.IssuedUtc;
        }
        return new AuthenticationTicket(stored.Principal, properties, stored.AuthenticationScheme);
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
        try
        {
            var db = _redis.GetDatabase();
            byte[]? bytes = await db.StringGetAsync(key).WaitAsync(ct);
            if (bytes is null || bytes.Length == 0)
            {
                return null;
            }

            var ticket = TryDeserialize(bytes);
            if (ticket is not null)
            {
                await db.KeyExpireAsync(key, SessionLifetime).WaitAsync(ct);
            }
            return ticket;
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
    /// slide the lifetime: a session with an open hub connection must still expire.
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
    /// SADD the key into the user's reverse-index Set and set its TTL to the session lifetime.
    /// Best-effort: a failure only weakens event-driven invalidation (the SSO refresh fallback
    /// still catches stale claims), so it is logged and swallowed.
    /// </summary>
    private async Task TryIndexAsync(AuthenticationTicket ticket, string key)
    {
        if (TryReadUserId(ticket.Principal) is not { } userId)
        {
            return;
        }

        try
        {
            var db = _redis.GetDatabase();
            var indexKey = UserIndexPrefix + userId;
            await db.SetAddAsync(indexKey, key);
            await db.KeyExpireAsync(indexKey, SessionLifetime);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogFailure("index-add", ex);
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
