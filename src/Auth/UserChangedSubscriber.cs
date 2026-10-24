using NATS.Client.Core;
using SkeinWeb.Hubs;

namespace SkeinWeb.Auth;

/// <summary>
/// Background NATS subscriber that wipes cached cookie tickets whenever
/// a user's claim-relevant fields change in skein-api.
/// </summary>
/// <remarks>
/// <para>
/// PROBLEM: the cookie principal — and therefore the
/// <c>X-Skein-User-Role</c> header the reverse-proxy forwards to skein-api
/// — is baked when <c>SignInAsync</c> runs. If an admin promotes a user
/// via <c>skein_user(action="update")</c> (or deactivates them, renames them, …),
/// the user's existing <see cref="RedisTicketStore"/> entry still carries
/// the old claims; skein-api will keep filtering them as a non-admin
/// until the cookie itself expires.
/// </para>
/// <para>
/// SOLUTION: skein-api already publishes per-field events to
/// <c>skein.user.{uid}.field.{kebab}</c> via the eventbus hybrid writer.
/// This subscriber listens on the user-namespace firehose (the existing
/// <see cref="NatsBridge"/> handles project events on a different
/// queue-group and discards <c>skein.user.&gt;</c> traffic that does not
/// match its dispatch contract — we attach a SECOND subscriber rather
/// than overloading that one because the two concerns are orthogonal:
/// SignalR fan-out vs cookie revocation, with different recovery
/// semantics).
/// </para>
/// <para>
/// FILTER: only fields that materially affect the cached principal
/// trigger revocation —
/// <list type="bullet">
///   <item><c>role</c> — switches between admin and user
///         (skein-api visibility depends on it).</item>
///   <item><c>deactivated-at</c> — flips the account to deactivated;
///         existing sessions must die or the user keeps working until
///         expiry.</item>
///   <item><c>name</c> / <c>username</c> — purely cosmetic on the
///         claims side but the cookie principal would otherwise drift
///         from the DB until the next natural login.</item>
/// </list>
/// Anything else (last_login_at, password hash, …) is skipped — they
/// either don't show up in the cookie or they re-sync naturally on the
/// next provision call.
/// </para>
/// <para>
/// QUEUE GROUP: shares the <c>skein-web</c> queue group with
/// <see cref="NatsBridge"/> so the multi-replica deployment processes
/// each event exactly once. After revocation the affected user's next
/// request lands without a valid cookie and either bounces to login
/// (local mode) or re-provisions via <see cref="SkeinWeb.Middleware.SsoSessionMiddleware"/>
/// (keycloak mode — the oauth2-proxy trust headers are still present).
/// </para>
/// <para>
/// FALLBACK: this subscriber is the FAST path (sub-second invalidation).
/// The <see cref="SkeinWeb.Middleware.SsoSessionMiddleware"/> TTL-refresh
/// loop is the SLOW path: even if NATS lag, pod crash, or the queue
/// group dropping the message means this subscriber never fires, the
/// middleware re-fetches claims from skein-api every 5 minutes and
/// catches the drift on its own.
/// </para>
/// </remarks>
public sealed class UserChangedSubscriber : IHostedService
{
    /// <summary>
    /// NATS subject pattern. Matches every user-namespace per-field
    /// child event published by skein-api's hybrid writer.
    /// </summary>
    private const string Subject = "skein.user.*.field.>";

    /// <summary>
    /// Shared with <see cref="NatsBridge"/> — every skein-web replica
    /// joins the same queue group so each NATS message reaches exactly
    /// one pod. Revocation only needs to happen once per cluster; the
    /// Valkey-backed <see cref="RedisTicketStore"/> is the shared state.
    /// </summary>
    private const string QueueGroup = "skein-web";

    /// <summary>
    /// Kebab-case field names that, when changed, force a session
    /// revocation. Anything outside this set is logged at debug and
    /// dropped — they do not flow into the cookie principal.
    /// </summary>
    private static readonly HashSet<string> RevokeOnFields = new(StringComparer.Ordinal)
    {
        "role",
        "deactivated-at",
        "name",
        "username",
    };

    private readonly INatsConnection _conn;
    private readonly RedisTicketStore _store;
    private readonly ILogger<UserChangedSubscriber> _logger;

    private CancellationTokenSource? _cts;
    private Task? _loopTask;

    public UserChangedSubscriber(
        INatsConnection conn,
        RedisTicketStore store,
        ILogger<UserChangedSubscriber> logger)
    {
        _conn = conn;
        _store = store;
        _logger = logger;
    }

    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = new CancellationTokenSource();
        _loopTask = Task.Run(() => SubscribeLoopAsync(_cts.Token), _cts.Token);
        _logger.LogInformation(
            "UserChangedSubscriber started, subscribed to {Subject} (queueGroup={QueueGroup})",
            Subject, QueueGroup);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _cts?.Cancel();
        if (_loopTask is { } t)
        {
            try
            {
                await t.WaitAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                // Cooperative shutdown.
            }
        }
        _logger.LogInformation("UserChangedSubscriber stopped");
    }

    /// <summary>
    /// Long-running subscription loop. NATS.Net handles reconnects
    /// internally; we exit only on linked-CTS cancellation.
    /// </summary>
    private async Task SubscribeLoopAsync(CancellationToken ct)
    {
        try
        {
            await foreach (var msg in _conn.SubscribeAsync<byte[]>(
                Subject,
                queueGroup: QueueGroup,
                cancellationToken: ct))
            {
                try
                {
                    await HandleAsync(msg.Subject, ct);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex,
                        "UserChangedSubscriber: handler failed subject={Subject}",
                        msg.Subject);
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Normal shutdown.
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "UserChangedSubscriber: subscription loop exited (subject={Subject})",
                Subject);
        }
    }

    /// <summary>
    /// Parse the subject and revoke matching tickets. Pulled out of the
    /// loop so tests can drive it directly without a live NATS server.
    /// </summary>
    internal async Task HandleAsync(string subject, CancellationToken ct)
    {
        if (!SubjectParser.TryParse(subject, out var parsed))
        {
            _logger.LogDebug(
                "UserChangedSubscriber: dropping malformed subject {Subject}", subject);
            return;
        }

        // We registered on skein.user.*.field.> so by construction every
        // message must have the User namespace + a field name. Defensive
        // check guards against a future change in SubjectParser shape.
        if (parsed.Namespace != SubjectNamespace.User
            || !parsed.UserId.HasValue
            || string.IsNullOrEmpty(parsed.FieldName))
        {
            return;
        }

        if (!RevokeOnFields.Contains(parsed.FieldName))
        {
            _logger.LogDebug(
                "UserChangedSubscriber: ignoring non-claim field {Field} for user {UserId}",
                parsed.FieldName, parsed.UserId.Value);
            return;
        }

        var userId = parsed.UserId.Value;
        var removed = await _store.RemoveByUserIdAsync(userId, ct);
        _logger.LogInformation(
            "session invalidated for user {UserId} (subject {Subject}, removed {Count} tickets)",
            userId, subject, removed);
    }
}
