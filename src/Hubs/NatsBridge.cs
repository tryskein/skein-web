using System.Text.Json;
using Microsoft.AspNetCore.SignalR;
using NATS.Client.Core;

namespace SkeinWeb.Hubs;

/// <summary>
/// Background service that subscribes to skein-api's NATS firehose and
/// forwards events to the connected SignalR clients (via
/// <see cref="IHubContext{SkeinHub}"/>).
/// </summary>
/// <remarks>
/// Two parallel subscriptions, each on its own loop, both in the queue group
/// <see cref="QueueGroup"/> (one replica takes each message; the Redis
/// backplane delivers to connections on every replica):
/// <list type="bullet">
///   <item><c>skein.events.&gt;</c> — every project-scoped event.</item>
///   <item><c>skein.user.&gt;</c> — user events, personal notifications,
///         personal reminder frames and the personal theme subjects.</item>
/// </list>
///
/// ADDRESSED DELIVERY (sk-622.21 US-9, K10): a project event of project P is
/// projected onto the compact <see cref="BrowserEnvelope"/>
/// (<see cref="BrowserEnvelopeProjector"/>) and sent to the groups
/// <see cref="HubGroups.Project"/>(P) only — never to <c>Clients.All</c>,
/// never to a group of all projects (there is none: sk-674.18 K-15, ADR-3)
/// and never to admins as such. Which connections are in that group is
/// decided by the hub (<see cref="SkeinHub.DeclareProjects"/>,
/// <see cref="SkeinHub.DeclareAllVisible"/> — the visible set, for the admin
/// too) and by the access re-check and <c>access_changed</c>, not here. So an
/// event of another user's personal space reaches no admin on any channel
/// (SC-005). Per-field child events and project <c>reminder.*</c> events are
/// not forwarded.
///
/// USER EVENTS (<c>skein.user.{uid}.{action}</c>, EventEnvelope shape):
/// projected the same way and sent to the user (<c>Clients.User</c> — every
/// connection of that user, including <c>user.deactivated</c>, which the tab
/// turns into a logout, K18) and — only for an event of the entity "user"
/// carrying no project data — to <see cref="HubGroups.InternalAdmins"/>
/// (K-15).
///
/// PERSONAL FRAMES: <c>skein.user.{uid}.reminder</c> →
/// <see cref="BrowserClientMethods.Reminder"/> to the owner's connections,
/// regardless of declarations. <c>skein.user.{uid}.signal</c> is NOT handled
/// here: personal signals are coalesced per connection on every replica by a
/// subscription without a queue group (T036); this loop skips them, and
/// likewise <c>skein.user.{uid}.access_changed</c>, the control event every
/// replica applies in <see cref="AccessControlSubscriber"/> (T014: the
/// queue-group bridge must not handle it).
///
/// NOTIFICATION SUBJECT: <c>skein.user.{uid}.notification</c> carries the
/// smaller <see cref="NotificationEnvelope"/> and is forwarded unchanged to
/// the targeted user's connections only.
///
/// THEME SUBJECTS, forwarded unchanged and outside the compact envelope,
/// each to the one user it names:
/// <list type="bullet">
///   <item><c>skein.user.{uid}.theme.preview</c> (sk-10.3) → SignalR
///         <c>theme.preview</c>. Body <c>{userId, variables}</c>.</item>
///   <item><c>skein.user.{uid}.theme.user-pref.updated</c> (sk-10.3) →
///         SignalR <c>theme.user-pref.updated</c>. Body <c>{}</c> (the
///         message itself is the refetch hint).</item>
///   <item><c>skein.user.{author}.theme.updated</c> (sk-674.18 K-31, US-21)
///         → SignalR <c>theme.updated</c> to the theme's AUTHOR only. Body
///         <c>{themeId, variables}</c>. Themes are personal: nobody else sees a
///         theme's name, author or changes. The former org-wide broadcast
///         <c>skein.events.theme.updated.{themeId}</c> is no longer published
///         by skein-api and no longer forwarded.</item>
/// </list>
/// Each of these paths defensively guards against non-object payloads
/// (a programmer-error publish of null / array / scalar gets dropped
/// with a warn rather than forwarded).
///
/// RESERVED SUBJECT: <c>skein.user.{uid}.membership_changed</c> is reserved;
/// the bridge drops it.
/// </remarks>
public sealed class NatsBridge : IHostedService
{
    private const string EventsSubject = "skein.events.>";
    private const string UserSubject = "skein.user.>";

    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    private readonly INatsConnection _conn;
    private readonly IHubContext<SkeinHub> _hub;
    private readonly ILogger<NatsBridge> _logger;
    private readonly IProjectDeliveryGate? _gate;
    private readonly IDeliveryFailureRecorder? _failures;

    private CancellationTokenSource? _cts;
    private Task? _eventsTask;
    private Task? _userTask;

    /// <summary>Creates the bridge.</summary>
    /// <param name="conn">NATS connection.</param>
    /// <param name="hub">Hub context.</param>
    /// <param name="logger">Logger.</param>
    /// <param name="gate">Holds project events back after a NATS reconnect until
    /// access has been re-checked (K10); <c>null</c> — no gate.</param>
    /// <param name="failures">Records failed sends so their addressees get a
    /// resync after the backplane is restored (K11); <c>null</c> — a failed
    /// send only surfaces as an error.</param>
    public NatsBridge(
        INatsConnection conn,
        IHubContext<SkeinHub> hub,
        ILogger<NatsBridge> logger,
        IProjectDeliveryGate? gate = null,
        IDeliveryFailureRecorder? failures = null)
    {
        ArgumentNullException.ThrowIfNull(conn);
        ArgumentNullException.ThrowIfNull(hub);
        ArgumentNullException.ThrowIfNull(logger);
        _conn = conn;
        _hub = hub;
        _logger = logger;
        _gate = gate;
        _failures = failures;
    }
    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = new CancellationTokenSource();
        _eventsTask = Task.Run(() => SubscribeLoop(EventsSubject, _cts.Token), _cts.Token);
        _userTask = Task.Run(() => SubscribeLoop(UserSubject, _cts.Token), _cts.Token);
        _logger.LogInformation(
            "NatsBridge started, subscribed to {EventsSubject} and {UserSubject}",
            EventsSubject,
            UserSubject);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _cts?.Cancel();
        var tasks = new List<Task>(2);
        if (_eventsTask != null) tasks.Add(_eventsTask);
        if (_userTask != null) tasks.Add(_userTask);
        try
        {
            await Task.WhenAll(tasks).WaitAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            // Cooperative shutdown — both loops exit on cancellation.
        }
        finally
        {
            _cts?.Dispose();
            _cts = null;
        }
        _logger.LogInformation("NatsBridge stopped");
    }

    /// <summary>
    /// NATS Core queue-group name shared by every skein-web replica.
    /// Subscribers in the same queue group divide messages round-robin
    /// (server-side) — at most one pod receives each event, so the
    /// dispatch into the SignalR Hub fires exactly once per replica
    /// deployment regardless of how many pods are running. The Redis
    /// backplane then fans the message out to every connected client,
    /// no matter which pod holds their WebSocket.
    /// </summary>
    private const string QueueGroup = "skein-web";

    /// <summary>
    /// Long-running subscription loop. NATS.Net handles reconnects
    /// internally; we only exit when the linked CTS is cancelled.
    /// </summary>
    private async Task SubscribeLoop(string subject, CancellationToken ct)
    {
        try
        {
            await foreach (var msg in _conn.SubscribeAsync<byte[]>(
                subject,
                queueGroup: QueueGroup,
                cancellationToken: ct))
            {
                try
                {
                    await Dispatch(msg.Subject, msg.Data, ct);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex,
                        "NatsBridge dispatch failed subject={Subject}",
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
            _logger.LogError(ex, "NatsBridge subscription loop exited subject={Subject}", subject);
        }
    }

    /// <summary>
    /// Routes one NATS message through the parser, the projector and the
    /// SignalR send. Pure dispatch — no I/O beyond SendAsync. Internal so
    /// tests can drive it directly.
    /// </summary>
    internal async Task Dispatch(string subject, byte[]? body, CancellationToken ct)
    {
        if (!SubjectParser.TryParse(subject, out var parsed))
        {
            _logger.LogWarning("NatsBridge dropping malformed subject {Subject}", subject);
            return;
        }

        if (parsed.Namespace == SubjectNamespace.User)
        {
            switch (parsed.Action)
            {
                case "signal":
                    // Delivered by PersonalSignalSubscriber (T036) — a
                    // subscription WITHOUT a queue group, coalesced per
                    // connection on every replica.
                    return;
                case "reminder":
                    await ForwardReminderFrame(parsed, body, ct);
                    return;
                case "notification":
                    // R3.3 — smaller envelope, addressed to one user.
                    await ForwardNotificationEvent(parsed, body, ct);
                    return;
                case "theme.preview":
                case "theme.user-pref.updated":
                case "theme.updated":
                    // sk-10.3 / K-31 — ad-hoc payloads, strictly one user.
                    await ForwardThemeUserEvent(parsed, body, ct);
                    return;
                case "access_changed":
                    // Control event of the hub (T014), applied on every
                    // replica by AccessControlSubscriber — never a frame.
                    return;
                case "membership_changed":
                    _logger.LogDebug("NatsBridge dropping reserved subject {Subject}", subject);
                    return;
            }
        }

        if (parsed.Namespace == SubjectNamespace.Malformed)
        {
            _logger.LogWarning("NatsBridge dropping malformed subject {Subject}", subject);
            return;
        }

        EventEnvelope? envelope;
        try
        {
            envelope = body is { Length: > 0 }
                ? JsonSerializer.Deserialize<EventEnvelope>(body, JsonOpts)
                : null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "NatsBridge envelope deserialise failed subject={Subject}",
                subject);
            return;
        }
        if (envelope is null)
        {
            _logger.LogWarning("NatsBridge null envelope on subject {Subject}", subject);
            return;
        }

        var browser = BrowserEnvelopeProjector.Project(envelope);
        if (browser is null)
        {
            // Per-field child edit, project reminder.* — not for browsers.
            return;
        }

        if (parsed.Namespace == SubjectNamespace.Project)
        {
            await ForwardProjectEvent(parsed, browser, ct);
        }
        else
        {
            await ForwardUserEvent(parsed, browser, ct);
        }
    }

    /// <summary>
    /// Sends a project event to the group <see cref="HubGroups.Project"/>(P):
    /// the connections that declared P or hold it in their "all visible" set —
    /// both decided by skein-api's visibility (K-15, ADR-3).
    /// </summary>
    private async Task ForwardProjectEvent(ParsedSubject parsed, BrowserEnvelope envelope, CancellationToken ct)
    {
        if (!parsed.ProjectId.HasValue)
        {
            return;
        }
        if (_gate is not null)
        {
            await _gate.WaitOpenAsync(ct);
        }
        string[] groups = [HubGroups.Project(parsed.ProjectId.Value)];
        await SendTrackedAsync(
            () => _hub.Clients.Group(groups[0]).SendAsync(BrowserClientMethods.Event, envelope, ct),
            r => r.RecordFailedGroupSend(groups), ct);
        HubMetrics.ProjectEventsForwarded.WithLabels(parsed.EntityType).Inc();
    }

    /// <summary>
    /// Sends a user event to every connection of the user it is about and —
    /// when it is an event of the entity "user" carrying no project data — to
    /// internal admins (K18 "User events"; sk-674.18 K-15: the admins'
    /// channel never carries project data). A user who is also an internal
    /// admin may receive it twice; the tab deduplicates on
    /// <see cref="BrowserEnvelope.Id"/>.
    /// </summary>
    private async Task ForwardUserEvent(ParsedSubject parsed, BrowserEnvelope envelope, CancellationToken ct)
    {
        if (!parsed.UserId.HasValue)
        {
            return;
        }
        var user = parsed.UserId.Value.ToString();
        await SendTrackedAsync(
            () => _hub.Clients.User(user).SendAsync(BrowserClientMethods.Event, envelope, ct),
            r => r.RecordFailedUserSend(user), ct);
        if (!IsUserEntityWithoutProjectData(envelope))
        {
            return;
        }
        await SendTrackedAsync(
            () => _hub.Clients.Group(HubGroups.InternalAdmins).SendAsync(BrowserClientMethods.Event, envelope, ct),
            r => r.RecordFailedGroupSend([HubGroups.InternalAdmins]), ct);
    }

    /// <summary>
    /// Whether a user-subject event may go to <see cref="HubGroups.InternalAdmins"/>:
    /// its entity is "user" and it names no project, project prefix, issue,
    /// dependency, re-parent or commit.
    /// </summary>
    private static bool IsUserEntityWithoutProjectData(BrowserEnvelope envelope) =>
        string.Equals(envelope.EntityType, "user", StringComparison.Ordinal)
        && envelope.ProjectId is null
        && string.IsNullOrEmpty(envelope.ProjectIdPrefix)
        && envelope.IssueId is null
        && envelope.Dep is null
        && envelope.Reparent is null
        && envelope.CommitHashes is null;

    /// <summary>
    /// Forwards a personal reminder frame (<c>skein.user.{owner}.reminder</c>,
    /// K14) to every connection of the owner, regardless of declarations.
    /// Never coalesced; the tab deduplicates the ring on
    /// <see cref="ReminderFrame.FiringId"/>.
    /// </summary>
    private async Task ForwardReminderFrame(ParsedSubject parsed, byte[]? body, CancellationToken ct)
    {
        if (!parsed.UserId.HasValue)
        {
            return;
        }
        ReminderFrame? frame;
        try
        {
            frame = body is { Length: > 0 }
                ? JsonSerializer.Deserialize<ReminderFrame>(body, JsonOpts)
                : null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "NatsBridge reminder frame deserialise failed userId={UserId}",
                parsed.UserId.Value);
            return;
        }
        if (frame is null || string.IsNullOrEmpty(frame.FiringId))
        {
            _logger.LogWarning("NatsBridge empty reminder frame userId={UserId}", parsed.UserId.Value);
            return;
        }
        var owner = parsed.UserId.Value.ToString();
        await SendTrackedAsync(
            () => _hub.Clients.User(owner).SendAsync(BrowserClientMethods.Reminder, frame, ct),
            r => r.RecordFailedUserSend(owner), ct);
    }

    /// <summary>
    /// Runs one SignalR send; a failure (other than shutdown) is recorded with
    /// the <see cref="IDeliveryFailureRecorder"/> and dropped — the addressees
    /// get a resync when the backplane is back (K11). Without a recorder the
    /// failure propagates as before.
    /// </summary>
    private async Task SendTrackedAsync(Func<Task> send, Action<IDeliveryFailureRecorder> record, CancellationToken ct)
    {
        try
        {
            await send();
        }
        catch (Exception ex) when (_failures is not null && !(ex is OperationCanceledException && ct.IsCancellationRequested))
        {
            _logger.LogWarning(ex, "NatsBridge send failed; addressees will get resync after the backplane recovers");
            record(_failures);
        }
    }

    /// <summary>
    /// Forward a per-user notification event (R3.3) to a single
    /// recipient's connections. No admin fan-out — notifications are
    /// strictly addressed.
    /// </summary>
    private async Task ForwardNotificationEvent(
        ParsedSubject parsed,
        byte[]? body,
        CancellationToken ct)
    {
        if (!parsed.UserId.HasValue)
        {
            _logger.LogWarning(
                "NatsBridge notification subject without userId: {Subject}",
                parsed.EntityId);
            return;
        }

        NotificationEnvelope? envelope;
        try
        {
            envelope = body is { Length: > 0 }
                ? JsonSerializer.Deserialize<NotificationEnvelope>(body, JsonOpts)
                : null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "NatsBridge notification envelope deserialise failed userId={UserId}",
                parsed.UserId.Value);
            return;
        }
        if (envelope is null)
        {
            _logger.LogWarning(
                "NatsBridge null notification envelope userId={UserId}",
                parsed.UserId.Value);
            return;
        }

        // Forward exclusively to the targeted user. SignalR's
        // Clients.User picks up every active connection of that user;
        // when no connection exists this is a no-op (the inbox is
        // refreshed on next REST poll / reconnect). A failed send is
        // recorded: the user gets resync after the backplane recovers (K11).
        var recipient = parsed.UserId.Value.ToString();
        await SendTrackedAsync(
            () => _hub.Clients.User(recipient).SendAsync(BrowserClientMethods.Event, envelope, ct),
            r => r.RecordFailedUserSend(recipient), ct);
    }

    /// <summary>
    /// Forward a user-scoped theme event to the targeted user's connections.
    /// Subjects handled here:
    /// <list type="bullet">
    ///   <item><c>skein.user.{uid}.theme.preview</c> — ephemeral preview frame (sk-10.3).</item>
    ///   <item><c>skein.user.{uid}.theme.user-pref.updated</c> — refetch hint (sk-10.3).</item>
    ///   <item><c>skein.user.{author}.theme.updated</c> — persisted change of the
    ///         author's theme, to the author only (sk-674.18 K-31).</item>
    /// </list>
    /// </summary>
    /// <remarks>
    /// The payload is forwarded verbatim under the SignalR message
    /// name <c>theme.preview</c> / <c>theme.user-pref.updated</c>
    /// (NOT the generic <c>event</c> channel) so the frontend can
    /// branch on the SignalR method name. We don't deserialise into
    /// a typed envelope on this path — the payload shape is
    /// <c>{userId, variables}</c> for preview and <c>{}</c> for
    /// user-pref; the frontend reads what it needs and ignores the
    /// rest.
    /// </remarks>
    private async Task ForwardThemeUserEvent(ParsedSubject parsed, byte[]? body, CancellationToken ct)
    {
        if (!parsed.UserId.HasValue)
        {
            _logger.LogWarning(
                "NatsBridge theme user subject without userId: action={Action}",
                parsed.Action);
            return;
        }
        JsonElement payload;
        try
        {
            // Parse the raw body into a generic JsonElement so we can
            // forward the payload as-is. SignalR will JSON-serialise
            // the element verbatim on the wire.
            payload = body is { Length: > 0 }
                ? JsonSerializer.Deserialize<JsonElement>(body, JsonOpts)
                : default;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "NatsBridge theme user payload deserialise failed action={Action} userId={UserId}",
                parsed.Action, parsed.UserId.Value);
            return;
        }
        // Defensive: documented theme.* payloads are JSON objects
        // (preview = {userId, variables}; user-pref.updated = {}).
        // Anything else (null, array, string, number) is a publisher
        // bug — surface it and drop. Symmetric with
        // ForwardThemeBroadcastEvent below.
        if (payload.ValueKind != JsonValueKind.Object)
        {
            _logger.LogWarning(
                "NatsBridge theme user-scoped non-object payload action={Action} kind={Kind} userId={UserId}",
                parsed.Action, payload.ValueKind, parsed.UserId.Value);
            return;
        }
        // Strip the leading "theme." so the SignalR method name matches
        // the documented frontend contract (theme.preview, not
        // event/theme.preview).
        var methodName = parsed.Action; // already "theme.preview" / "theme.user-pref.updated"
        var recipient = parsed.UserId.Value.ToString();
        await SendTrackedAsync(
            () => _hub.Clients.User(recipient).SendAsync(methodName, payload, ct),
            r => r.RecordFailedUserSend(recipient), ct);
    }
}
