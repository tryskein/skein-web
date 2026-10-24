using StackExchange.Redis;

namespace SkeinWeb.Auth;

/// <summary>
/// Login throttle backed by Redis. Two independent buckets defend the BFF
/// login path (POST /api/auth/login) against brute force / credential
/// stuffing:
/// <list type="bullet">
///   <item><description><b>Per-email</b> — locks a single account after
///     <see cref="EmailFailureThreshold"/> failures in the rolling window.
///     Closes the targeted-account guessing vector.</description></item>
///   <item><description><b>Per-IP</b> — locks a single client IP after
///     <see cref="IpFailureThreshold"/> failures in the rolling window,
///     regardless of which emails were tried. Closes the SPRAY vector — one
///     IP walking many emails, each below the per-email threshold.</description></item>
/// </list>
/// Both are checked before the password is forwarded to skein-api; a hit on
/// either returns 429. The break-glass admin (sk-163 S4a) is the highest-value
/// target and is covered automatically — it logs in via the same path.
/// </summary>
/// <remarks>
/// <para>
/// We do NOT use <see cref="Microsoft.Extensions.Caching.Distributed.IDistributedCache"/>
/// here — it lacks an atomic INCR. Two concurrent failures could each
/// read 9 and write 10, missing the lockout threshold. Talking directly
/// to <see cref="IDatabase"/> via StackExchange.Redis gives us native
/// INCR + EXPIRE in two round-trips with single-key atomicity guaranteed
/// by Redis.
/// </para>
/// <para>
/// Thresholds and window are constants, not config — making them tunable
/// in production is a pre-deployment decision, not a runtime knob. The
/// per-email value mirrors common practice (cf. NIST 800-63B §5.2.2); the
/// per-IP value is deliberately higher so a shared corporate NAT egress
/// doesn't trip on a handful of fumbled passwords across people behind one address, while
/// still capping a sprayer at a slow rate. The per-IP bucket self-heals on
/// the rolling TTL, so a transient shared-NAT lockout clears within
/// <see cref="Window"/> of the last failure.
/// </para>
/// <para>
/// The trusted client IP is supplied by the caller (AuthController), which
/// reads <c>HttpContext.Connection.RemoteIpAddress</c> AFTER the
/// ForwardedHeaders middleware has resolved it from the trusted proxy chain
/// (see Program.cs / SKEIN_TRUSTED_PROXIES). A raw, spoofable X-Forwarded-For
/// is never used as the key — an attacker rotating XFF would otherwise make
/// the per-IP bucket worse than useless.
/// </para>
/// </remarks>
public sealed class LoginRateLimiter
{
    /// <summary>Redis key prefix for the per-email bucket; combined with lower-case email.</summary>
    private const string EmailKeyPrefix = "skein:login:fail:";

    /// <summary>Redis key prefix for the per-IP bucket; combined with the client IP literal.</summary>
    private const string IpKeyPrefix = "skein:login:failip:";

    /// <summary>Sentinel value written when a threshold is reached.</summary>
    private const string LockSentinel = "LOCK";

    /// <summary>
    /// Per-email failures in the rolling window before lockout. "N" in the
    /// spray-vs-targeted vocabulary: a single account locked after N tries.
    /// </summary>
    private const int EmailFailureThreshold = 10;

    /// <summary>
    /// Per-IP failures in the rolling window before lockout. "M" in the
    /// spray vocabulary: one IP locked after M tries ACROSS any mix of emails.
    /// Set higher than <see cref="EmailFailureThreshold"/> so a shared NAT
    /// egress with several people fumbling passwords does not trip, while
    /// a single IP spraying many accounts is still capped (~30/min).
    /// </summary>
    private const int IpFailureThreshold = 30;

    /// <summary>Both the rolling-window TTL and the lockout duration (both buckets).</summary>
    private static readonly TimeSpan Window = TimeSpan.FromSeconds(60);

    private readonly IConnectionMultiplexer _redis;

    public LoginRateLimiter(IConnectionMultiplexer redis)
    {
        _redis = redis;
    }

    /// <summary>
    /// Returns true when the email is currently locked out. Locked emails
    /// must be rejected with 429 BEFORE the password is sent to skein-api
    /// — otherwise an attacker can probe credentials at full rate by
    /// rotating the throttle outside the BFF.
    /// </summary>
    public Task<bool> IsLockedAsync(string emailLower, CancellationToken ct) =>
        IsKeyLockedAsync(EmailKeyPrefix + emailLower, ct);

    /// <summary>
    /// Returns true when the client IP is currently locked out (spray
    /// throttle). Checked alongside <see cref="IsLockedAsync"/> on every
    /// login so one IP walking many emails trips even when no single email
    /// has reached its own threshold.
    /// </summary>
    public Task<bool> IsIpLockedAsync(string clientIp, CancellationToken ct) =>
        IsKeyLockedAsync(IpKeyPrefix + clientIp, ct);

    private async Task<bool> IsKeyLockedAsync(string key, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var db = _redis.GetDatabase();
        var value = await db.StringGetAsync(key);
        return value.HasValue && value == LockSentinel;
    }

    /// <summary>
    /// Increment the per-email failure counter and roll/refresh the window
    /// TTL. When the counter reaches <see cref="EmailFailureThreshold"/>,
    /// replace the integer value with the LOCK sentinel for the same TTL —
    /// subsequent <see cref="IsLockedAsync(string,CancellationToken)"/> calls
    /// trip on the sentinel rather than re-comparing the integer.
    /// </summary>
    public Task RecordFailureAsync(string emailLower, CancellationToken ct) =>
        RecordFailureAsync(EmailKeyPrefix + emailLower, EmailFailureThreshold, ct);

    /// <summary>
    /// Increment the per-IP failure counter and roll/refresh the window TTL.
    /// Locks the IP at <see cref="IpFailureThreshold"/>. Records on EVERY
    /// failed attempt from the IP regardless of email — that is what makes it
    /// a spray throttle. The supplied <paramref name="clientIp"/> must be the
    /// trusted-proxy-resolved address, never a raw XFF value.
    /// </summary>
    public Task RecordIpFailureAsync(string clientIp, CancellationToken ct) =>
        RecordFailureAsync(IpKeyPrefix + clientIp, IpFailureThreshold, ct);

    private async Task RecordFailureAsync(string key, int threshold, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var db = _redis.GetDatabase();
        var redisKey = (RedisKey)key;

        var count = await db.StringIncrementAsync(redisKey);
        await db.KeyExpireAsync(redisKey, Window);

        if (count >= threshold)
        {
            // Replace the integer counter with the sentinel so the lock check
            // can short-circuit without a numeric parse, and refresh the TTL
            // so the lockout lasts the full window starting *now*.
            await db.StringSetAsync(redisKey, LockSentinel, Window);
        }
    }

    /// <summary>
    /// Clear the per-email bucket on a successful login. Two competing
    /// semantics exist (clear vs. preserve to enforce stricter throttling);
    /// we clear — a legitimate user who occasionally fumbles the password
    /// should not start each day with one fewer attempt.
    /// </summary>
    /// <remarks>
    /// We deliberately do NOT clear the per-IP bucket here. A single success
    /// (which could be a stolen credential the sprayer just landed) must not
    /// wipe the spray signal accumulated from the same IP. The per-IP bucket
    /// is short-lived (rolling <see cref="Window"/>) so it self-heals without
    /// an explicit reset.
    /// </remarks>
    public Task ResetAsync(string emailLower, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var db = _redis.GetDatabase();
        return db.KeyDeleteAsync(EmailKeyPrefix + emailLower);
    }
}
