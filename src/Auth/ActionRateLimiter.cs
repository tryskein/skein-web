using StackExchange.Redis;

namespace SkeinWeb.Auth;

/// <summary>
/// Rate limiter of the public account routes (plan K-17, contract
/// <see cref="PublicAuthRoutes"/>): the generalisation of
/// <see cref="LoginRateLimiter"/> from "failed logins" to "requests to an
/// action". Redis-backed, so the limit is shared by every replica.
/// </summary>
/// <remarks>
/// <para><b>Keys.</b> A key is always «action + one axis»
/// (<see cref="Policy"/>): «action + lower-cased email» for the routes with an
/// email in the input, «action + client IP» for every route. The action is the
/// route, so exhausting one route never limits another; nothing else from the
/// request — username, password, captcha token, language, the path token — is
/// ever part of a key.</para>
/// <para><b>Counting.</b> Every request counts, allowed or not: each call
/// increments every bucket it names (Redis <c>INCR</c>, atomic per key) and
/// refreshes the bucket's TTL to <see cref="Policy.Window"/>, as
/// <see cref="LoginRateLimiter"/> does. A bucket above its limit refuses; a
/// client that keeps hammering keeps its bucket alive, a client that stops is
/// released one window after its last request. Counting refused requests is
/// deliberate: otherwise a locked-out sprayer would be let back in at the full
/// rate the moment a counter decayed.</para>
/// <para><b>IP buckets</b> are used only when the caller passes a client IP,
/// which <c>AccountController</c> does only with a trusted proxy configured
/// (<c>SKEIN_TRUSTED_PROXIES</c>) — without one the address is the ingress's
/// and a bucket on it would lock everyone out at once.</para>
/// <para><b>Fail-open.</b> A Redis error lets the request through and is
/// logged: a cache outage must not turn into an outage of registration and
/// password reset. skein-api keeps its own per-pod backstop limit.</para>
/// </remarks>
public sealed class ActionRateLimiter
{
    /// <summary>Redis key prefix; followed by <c>{action}:email:{email}</c> or <c>{action}:ip:{ip}</c>.</summary>
    private const string KeyPrefix = "skein:ratelimit:";

    /// <summary>
    /// Limits of one action. <paramref name="EmailLimit"/> is null for an action
    /// whose input has no email (its only bucket is the IP one).
    /// </summary>
    /// <param name="Action">Action name — part of every key; one per route.</param>
    /// <param name="EmailLimit">Requests per email allowed within <paramref name="Window"/>; null = no email bucket.</param>
    /// <param name="IpLimit">Requests per client IP allowed within <paramref name="Window"/>.</param>
    /// <param name="Window">Rolling window: a bucket expires this long after its last request.</param>
    public sealed record Policy(string Action, int? EmailLimit, int IpLimit, TimeSpan Window);

    /// <summary>
    /// <c>POST /api/auth/signup</c>. Five registrations per email in ten
    /// minutes cover a person retrying through validation refusals
    /// (<c>username_taken</c>, <c>password_weak</c>…); twenty per IP leave room
    /// for a shared office egress while capping a scripted account farm.
    /// </summary>
    public static readonly Policy Signup = new("signup", EmailLimit: 5, IpLimit: 20, TimeSpan.FromMinutes(10));

    /// <summary>
    /// <c>GET /api/auth/username-suggestions</c>. A read the form issues on a
    /// button press, so the limits are higher; they still bound enumeration of
    /// taken usernames (the accepted risk of US-8).
    /// </summary>
    public static readonly Policy UsernameSuggestions = new("username-suggestions", EmailLimit: 30, IpLimit: 120, TimeSpan.FromMinutes(10));

    /// <summary>
    /// <c>POST /api/auth/password-reset</c>. Each allowed request may send an
    /// email, so the per-email limit is what keeps a mailbox from being
    /// flooded with reset links.
    /// </summary>
    public static readonly Policy PasswordReset = new("password-reset", EmailLimit: 5, IpLimit: 20, TimeSpan.FromMinutes(10));

    /// <summary><c>POST /api/auth/password-reset/{token}</c> — bounds token guessing per client.</summary>
    public static readonly Policy PasswordResetComplete = new("password-reset-complete", EmailLimit: null, IpLimit: 20, TimeSpan.FromMinutes(10));

    /// <summary><c>POST /api/auth/confirm-email/{token}</c> — bounds token guessing per client.</summary>
    public static readonly Policy ConfirmEmail = new("confirm-email", EmailLimit: null, IpLimit: 20, TimeSpan.FromMinutes(10));

    /// <summary>
    /// <c>GET /api/auth/invitations/{token}</c>. The SPA opens it on every load
    /// of an invitation link, so it allows more than the writes do.
    /// </summary>
    public static readonly Policy InvitationPreview = new("invitation-preview", EmailLimit: null, IpLimit: 60, TimeSpan.FromMinutes(10));

    /// <summary><c>POST /api/auth/invitations/{token}/signup</c> — same budget as a registration per IP.</summary>
    public static readonly Policy InvitationSignup = new("invitation-signup", EmailLimit: null, IpLimit: 20, TimeSpan.FromMinutes(10));

    private readonly IConnectionMultiplexer _redis;
    private readonly ILogger<ActionRateLimiter> _logger;

    /// <summary>Creates the limiter over the shared Redis multiplexer.</summary>
    public ActionRateLimiter(IConnectionMultiplexer redis, ILogger<ActionRateLimiter> logger)
    {
        _redis = redis;
        _logger = logger;
    }

    /// <summary>
    /// Counts one request to <paramref name="policy"/>'s action and reports
    /// whether it may proceed.
    /// </summary>
    /// <param name="policy">The route's limits.</param>
    /// <param name="emailLower">Lower-cased email of the input; ignored when
    /// <see cref="Policy.EmailLimit"/> is null; null or empty = no email bucket.</param>
    /// <param name="clientIp">Trusted client IP; null = no IP bucket (no trusted proxy).</param>
    /// <param name="ct">Request abort.</param>
    /// <returns><c>true</c> to proceed; <c>false</c> when any named bucket is above its limit.</returns>
    public async Task<bool> TryAcquireAsync(
        Policy policy, string? emailLower, string? clientIp, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            var db = _redis.GetDatabase();
            var allowed = true;
            if (policy.EmailLimit is { } emailLimit && !string.IsNullOrEmpty(emailLower))
            {
                allowed &= await CountAsync(db, $"{KeyPrefix}{policy.Action}:email:{emailLower}", policy.Window) <= emailLimit;
            }
            if (!string.IsNullOrEmpty(clientIp))
            {
                allowed &= await CountAsync(db, $"{KeyPrefix}{policy.Action}:ip:{clientIp}", policy.Window) <= policy.IpLimit;
            }
            return allowed;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "rate limiter failed (Redis) for action {Action}; failing open", policy.Action);
            return true;
        }
    }

    private static async Task<long> CountAsync(IDatabase db, string key, TimeSpan window)
    {
        var redisKey = (RedisKey)key;
        var count = await db.StringIncrementAsync(redisKey);
        await db.KeyExpireAsync(redisKey, window);
        return count;
    }
}
