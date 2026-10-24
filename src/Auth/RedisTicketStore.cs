using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.StackExchangeRedis;
using Microsoft.Extensions.Options;
using SkeinWeb.Hubs;
using StackExchange.Redis;

namespace SkeinWeb.Auth;

/// <summary>
/// Server-side session store for the cookie auth scheme. The browser
/// cookie carries only an opaque session id (32 random bytes,
/// base64url-encoded); the actual <see cref="AuthenticationTicket"/> —
/// claims, expiry, properties — lives in Redis under
/// <c>skein:session:{sid}</c> with a sliding TTL.
/// </summary>
/// <remarks>
/// <para>
/// Why server-side storage? With ticket-only cookies the entire principal
/// rides in the cookie; logout cannot revoke a token (the browser still
/// holds a valid blob), and large claim sets blow past the 4 KiB cookie
/// limit. Storing the ticket in Redis lets us hard-invalidate sessions
/// (RemoveAsync deletes the row), keep the cookie tiny, and share state
/// across multiple skein-web replicas without sticky sessions.
/// </para>
/// <para>
/// Sid generation uses RandomNumberGenerator (CSPRNG); 32 bytes is 256 bits
/// of entropy — equivalent to a session token in any production-grade
/// session library. base64url encoding keeps it cookie-safe (no padding,
/// no <c>+</c>/<c>/</c>).
/// </para>
/// <para>
/// REVERSE INDEX: alongside each <c>skein:session:{sid}</c> entry the
/// store maintains <c>skein:user-tickets:{userId}</c> — a Redis Set of
/// every active session key belonging to that user. Populated on
/// <see cref="StoreAsync"/> / <see cref="RenewAsync"/>, pruned on
/// <see cref="RemoveAsync"/>, walked on <see cref="RemoveByUserIdAsync"/>.
/// The reverse index drives event-driven session invalidation: when
/// skein-api publishes a <c>skein.user.{uid}.field.role</c> (or
/// <c>deactivated-at</c>, <c>name</c>, <c>username</c>) event the
/// <see cref="SkeinWeb.Auth.UserChangedSubscriber"/> can wipe every
/// active ticket for that user in O(N) without scanning the entire
/// session keyspace.
/// </para>
/// </remarks>
public sealed class RedisTicketStore : ITicketStore, IUserSessionRevoker, ISessionTicketProbe
{
    /// <summary>Redis key prefix; combined with the random sid to form the lookup key.</summary>
    private const string KeyPrefix = "skein:session:";

    /// <summary>Reverse-index key prefix; combined with the user UUID to form a Set of ticket keys.</summary>
    private const string UserIndexPrefix = "skein:user-tickets:";

    /// <summary>Sliding session lifetime. 24h matches the cookie ExpireTimeSpan.</summary>
    private static readonly TimeSpan SessionLifetime = TimeSpan.FromHours(24);

    private readonly IDistributedCache _cache;
    private readonly IConnectionMultiplexer _redis;
    private readonly ConnectionRegistry _hubConnections;
    private readonly string _cacheKeyPrefix;
    private readonly ILogger<RedisTicketStore> _logger;

    /// <summary>Creates the store.</summary>
    /// <param name="cache">Ticket rows.</param>
    /// <param name="redis">Reverse index.</param>
    /// <param name="hubConnections">This replica's hub connections: a ticket key
    /// renewed for another user closes the connections of the previous owner
    /// opened with it (INV-26).</param>
    /// <param name="cacheOptions">Options of the Redis cache behind <paramref name="cache"/>:
    /// its <see cref="RedisCacheOptions.InstanceName"/> prefixes every cache key
    /// in Redis, which <see cref="ExistsAsync"/> needs to find a ticket's key.</param>
    /// <param name="logger">Logger.</param>
    public RedisTicketStore(
        IDistributedCache cache,
        IConnectionMultiplexer redis,
        ConnectionRegistry hubConnections,
        IOptions<RedisCacheOptions> cacheOptions,
        ILogger<RedisTicketStore> logger)
    {
        _cache = cache;
        _redis = redis;
        _hubConnections = hubConnections;
        _cacheKeyPrefix = cacheOptions.Value.InstanceName ?? "";
        _logger = logger;
    }

    /// <summary>
    /// Persist a freshly-issued ticket and return its server-side key
    /// (which becomes the cookie value). The key is generated server-side
    /// — the caller has no influence over it. Also registers the key in
    /// the per-user reverse index so <see cref="RemoveByUserIdAsync"/>
    /// can revoke every active session for that user later.
    /// </summary>
    public async Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var sid = NewSessionId();
        var key = KeyPrefix + sid;
        var bytes = TicketSerializer.Default.Serialize(WithSessionKey(ticket, key));

        await _cache.SetAsync(key, bytes, new DistributedCacheEntryOptions
        {
            SlidingExpiration = SessionLifetime,
        });

        await TryIndexAsync(ticket, key);

        return key;
    }

    /// <summary>
    /// Re-persist a ticket under the same key (used when claims rotate or
    /// the cookie middleware refreshes expiry). Resets the sliding TTL on
    /// both the session row and the reverse-index entry — without the
    /// latter the index expires on its own clock and a long-lived session
    /// would silently drop out of <see cref="RemoveByUserIdAsync"/>'s
    /// reach.
    /// </summary>
    public async Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        // sk-674.18 (K-16): the cookie handler also renews the CURRENT key
        // when a sign-in happens on a request that already carries a session
        // — the password-reset re-issue of the same user, but equally a signup,
        // an invitation signup or a login made in a tab that is logged in as
        // somebody else. In that last case the key changes owner: it must
        // leave the previous owner's reverse index, or revoking the previous
        // owner (RemoveByUserIdAsync) would delete the new owner's session.
        await PruneIndexOnOwnerChangeAsync(key, ticket);
        // The same key renewed for another user: a hub connection of the
        // previous owner opened with it must not go on receiving the previous
        // owner's frames in the tab now logged in as somebody else (INV-26).
        // Here at once on this replica; on the others by the re-check, whose
        // probe sees the key leave the previous owner's index.
        if (TryReadUserId(ticket.Principal) is { } newOwner)
        {
            _hubConnections.AbortSessionNotOwnedBy(key, newOwner);
        }

        var bytes = TicketSerializer.Default.Serialize(WithSessionKey(ticket, key));
        await _cache.SetAsync(key, bytes, new DistributedCacheEntryOptions
        {
            SlidingExpiration = SessionLifetime,
        });

        // Refresh the index — same set semantics as StoreAsync, so a
        // claim-rotation flow (SsoSessionMiddleware re-SignInAsync on
        // role change) keeps the key reachable from the user UUID.
        await TryIndexAsync(ticket, key);
    }

    /// <summary>
    /// Look up a ticket by its key. Returns null when the key is unknown,
    /// expired, or the stored bytes are malformed (defensive — a Redis
    /// rewrite or partial write should result in a 401, not a 500).
    /// </summary>
    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        var bytes = await _cache.GetAsync(key);
        if (bytes is null || bytes.Length == 0)
        {
            return null;
        }

        try
        {
            var ticket = TicketSerializer.Default.Deserialize(bytes);
            // A ticket stored before keys were stamped (an earlier release —
            // tickets outlive a deploy in Redis) gets its key here, so every
            // principal read from the store knows its ticket: its hub
            // connections are tied to it and a password reset can keep it
            // apart from the user's other sessions (INV-26). Nothing is written.
            return ticket is not null && SessionPrincipal.SessionKeyOf(ticket.Principal) is null
                ? WithSessionKey(ticket, key)
                : ticket;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "failed to deserialize session ticket; treating as logged out");
            return null;
        }
    }

    /// <summary>
    /// Hard-revoke the session. Called by the cookie middleware on
    /// SignOutAsync; afterwards the cookie value points at nothing. Also
    /// prunes the per-user reverse-index entry so the soon-to-expire
    /// ticket key is not left dangling in a Set.
    /// </summary>
    public async Task RemoveAsync(string key)
    {
        // Read the ticket FIRST so we know which user-index to prune. If
        // the key is already gone we have no way to recover the user id
        // — accept the orphaned entry, it expires with the Set TTL.
        Guid? userId = null;
        try
        {
            var ticket = await RetrieveAsync(key);
            if (ticket?.Principal is { } principal)
            {
                userId = TryReadUserId(principal);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "RemoveAsync: failed to pre-read ticket for user-index pruning (key suffix len={Suffix})", key.Length);
        }

        await _cache.RemoveAsync(key);

        if (userId.HasValue)
        {
            try
            {
                var db = _redis.GetDatabase();
                await db.SetRemoveAsync(UserIndexPrefix + userId.Value, key);
            }
            catch (Exception ex)
            {
                // Pruning is best-effort — the entry will TTL out with the
                // session lifetime even if we miss it here. Don't fail the
                // logout / cookie-refresh flow on a Redis hiccup.
                _logger.LogWarning(ex, "RemoveAsync: failed to prune user-index entry for {UserId}", userId.Value);
            }
        }
    }

    /// <summary>
    /// Hard-revoke EVERY active session belonging to <paramref name="userId"/>.
    /// Reads the <c>skein:user-tickets:{userId}</c> set, deletes each
    /// referenced session row, then drops the set itself. Returns the
    /// number of session keys that were enumerated (which is the upper
    /// bound on how many tickets were revoked — concurrent expirations
    /// may have already removed some).
    /// </summary>
    /// <remarks>
    /// Used by <see cref="SkeinWeb.Auth.UserChangedSubscriber"/> in
    /// response to <c>skein.user.{uid}.field.role</c> /
    /// <c>field.deactivated-at</c> / <c>field.name</c> /
    /// <c>field.username</c> NATS events — any of these change the
    /// claims baked into the cookie principal, so the existing tickets
    /// must die. After this call the affected user's next request will
    /// either (a) fail authentication and bounce to login (local mode)
    /// or (b) re-provision via <see cref="SkeinWeb.Middleware.SsoSessionMiddleware"/>
    /// against skein-api and mint a fresh ticket with the new claims
    /// (keycloak mode — the trust headers are still present).
    /// </remarks>
    /// <param name="userId">UUID of the user whose sessions to invalidate.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The count of ticket keys read from the reverse-index set.</returns>
    public async Task<int> RemoveByUserIdAsync(Guid userId, CancellationToken ct) =>
        (await RemoveUserSessionsAsync(userId, keepKey: null, ct)).Removed;

    /// <inheritdoc />
    /// <remarks>
    /// Each Redis step — the index read, every ticket delete — is tried
    /// <see cref="RemovalAttempts"/> times. The reverse index keeps the kept key
    /// and every key whose delete failed, so a later revocation still finds them.
    /// </remarks>
    public Task<SessionRemovalResult> RemoveSessionsAsync(Guid userId, string? keepKey, CancellationToken ct) =>
        RemoveUserSessionsAsync(userId, keepKey, ct);

    /// <summary>
    /// Whether the ticket <paramref name="key"/> is still stored (sk-674.18
    /// INV-26) — false once the session was signed out, revoked or removed, or
    /// has expired. The hub's access re-check closes connections whose ticket
    /// is gone.
    /// </summary>
    /// <remarks>
    /// Probes the ticket's Redis key (<c>EXISTS</c>) instead of reading the
    /// ticket: a read through <see cref="IDistributedCache"/> would refresh the
    /// sliding lifetime, and a session with an open hub connection would never
    /// expire. The Redis key is the cache key prefixed with
    /// <see cref="RedisCacheOptions.InstanceName"/>, as the cache stores it.
    /// </remarks>
    /// <exception cref="Exception">The store is unreachable; the caller decides.</exception>
    public Task<bool> ExistsAsync(string key, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return _redis.GetDatabase().KeyExistsAsync(_cacheKeyPrefix + key);
    }

    /// <inheritdoc />
    /// <remarks>
    /// Ownership is read from the reverse index: the key is in
    /// <c>skein:user-tickets:{userId}</c>. A renewal for another user takes it
    /// out of the previous owner's set (<see cref="RenewAsync"/>), a revocation
    /// of the user's sessions drops the set.
    /// </remarks>
    public async Task<bool> IsSessionOfAsync(string key, Guid userId, CancellationToken ct)
    {
        var db = _redis.GetDatabase();
        if (!await db.SetContainsAsync(UserIndexPrefix + userId, key))
        {
            return false;
        }
        return await ExistsAsync(key, ct);
    }

    /// <summary>Attempts of one Redis step of a removal (index read, one ticket delete) before it counts as failed.</summary>
    private const int RemovalAttempts = 3;

    /// <summary>Pause before the second attempt; doubled before the third.</summary>
    private static readonly TimeSpan RemovalRetryDelay = TimeSpan.FromMilliseconds(100);

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
                members = await db.SetMembersAsync(indexKey);
            }
            catch (Exception ex) when (attempt < RemovalAttempts && ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex, "session removal: user-index read failed, retrying userId={UserId} attempt={Attempt}",
                    userId, attempt);
                await Task.Delay(RemovalRetryDelay * attempt, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "session removal: failed to read user-index userId={UserId}", userId);
                return new SessionRemovalResult(0, 0, IndexRead: false);
            }
        }

        var removedKeys = new List<RedisValue>();
        var failed = 0;
        foreach (var member in members)
        {
            ct.ThrowIfCancellationRequested();
            var key = (string?)member;
            if (string.IsNullOrEmpty(key) || string.Equals(key, keepKey, StringComparison.Ordinal))
            {
                continue;
            }
            if (await TryRemoveTicketAsync(key, userId, ct))
            {
                removedKeys.Add(member);
            }
            else
            {
                failed++;
            }
        }

        // The index keeps exactly the keys still to be dealt with: the kept one
        // and any whose removal failed, so a later revocation still finds them.
        // Only a complete removal without a kept key drops the whole set.
        try
        {
            if (keepKey is null && failed == 0)
            {
                await db.KeyDeleteAsync(indexKey);
            }
            else
            {
                foreach (var key in removedKeys)
                {
                    await db.SetRemoveAsync(indexKey, key);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "session removal: failed to prune user-index set userId={UserId}", userId);
        }

        return new SessionRemovalResult(removedKeys.Count, failed, IndexRead: true);
    }

    private async Task<bool> TryRemoveTicketAsync(string key, Guid userId, CancellationToken ct)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                await _cache.RemoveAsync(key, ct);
                return true;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                if (attempt >= RemovalAttempts)
                {
                    _logger.LogWarning(ex, "session removal: ticket not removed userId={UserId} attempts={Attempts}",
                        userId, attempt);
                    return false;
                }
                await Task.Delay(RemovalRetryDelay * attempt, ct);
            }
        }
    }

    /// <summary>
    /// The ticket with <see cref="SessionPrincipal.SessionKeyClaim"/> set to
    /// <paramref name="key"/> (exactly one such claim), so the principal read
    /// back from the store knows its own ticket key.
    /// </summary>
    private static AuthenticationTicket WithSessionKey(AuthenticationTicket ticket, string key)
    {
        var identities = ticket.Principal.Identities.Select(i => i.Clone()).ToList();
        if (identities.Count == 0)
        {
            return ticket;
        }
        foreach (var identity in identities)
        {
            foreach (var stale in identity.FindAll(SessionPrincipal.SessionKeyClaim).ToArray())
            {
                identity.RemoveClaim(stale);
            }
        }
        identities[0].AddClaim(new Claim(SessionPrincipal.SessionKeyClaim, key));
        return new AuthenticationTicket(new ClaimsPrincipal(identities), ticket.Properties, ticket.AuthenticationScheme);
    }

    /// <summary>
    /// SADD the session key into the per-user reverse-index Set and refresh
    /// its TTL to match <see cref="SessionLifetime"/>. Defensive: any
    /// failure here is logged at debug and swallowed — losing an index
    /// entry only weakens event-driven invalidation (the TTL refresh
    /// fallback in SsoSessionMiddleware still catches stale claims
    /// within 5 minutes).
    /// </summary>
    private async Task TryIndexAsync(AuthenticationTicket ticket, string key)
    {
        var userId = TryReadUserId(ticket.Principal);
        if (!userId.HasValue)
        {
            // Anonymous / pre-auth ticket — nothing to index against.
            return;
        }

        try
        {
            var db = _redis.GetDatabase();
            var indexKey = UserIndexPrefix + userId.Value;
            await db.SetAddAsync(indexKey, key);
            // Refresh TTL on the set so it does not outlive the session
            // it points to. Sliding TTL on the session itself extends on
            // every RenewAsync, which calls back here — that path keeps
            // the index live as long as the user is active.
            await db.KeyExpireAsync(indexKey, SessionLifetime);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "TryIndexAsync: failed to add session to user-index for {UserId}", userId.Value);
        }
    }

    /// <summary>
    /// Before <see cref="RenewAsync"/> overwrites <paramref name="key"/>: when
    /// the ticket stored there belongs to another user than
    /// <paramref name="ticket"/>, drop the key from that user's reverse index.
    /// Best-effort like the rest of the index upkeep — a failure is logged and
    /// the renewal proceeds.
    /// </summary>
    private async Task PruneIndexOnOwnerChangeAsync(string key, AuthenticationTicket ticket)
    {
        try
        {
            var previous = await RetrieveAsync(key);
            var previousUserId = previous?.Principal is { } principal ? TryReadUserId(principal) : null;
            if (previousUserId.HasValue && previousUserId != TryReadUserId(ticket.Principal))
            {
                var db = _redis.GetDatabase();
                await db.SetRemoveAsync(UserIndexPrefix + previousUserId.Value, key);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "RenewAsync: failed to prune the previous owner's user-index entry");
        }
    }

    /// <summary>
    /// Read <see cref="ClaimTypes.NameIdentifier"/> off the principal and
    /// parse it as a UUID. Returns null on any shape mismatch so callers
    /// can no-op without an exception.
    /// </summary>
    private static Guid? TryReadUserId(ClaimsPrincipal principal)
    {
        var raw = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(raw))
        {
            return null;
        }
        return Guid.TryParse(raw, out var uid) ? uid : null;
    }

    /// <summary>
    /// Generate a 32-byte (256-bit) cryptographically random session id and
    /// encode it base64url (no padding) for cookie-safe transport.
    /// </summary>
    private static string NewSessionId()
    {
        Span<byte> raw = stackalloc byte[32];
        RandomNumberGenerator.Fill(raw);
        return Base64UrlEncode(raw);
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> bytes)
    {
        var b64 = Convert.ToBase64String(bytes);
        // RFC 4648 §5 (base64url): + → -, / → _, drop trailing =
        return b64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
