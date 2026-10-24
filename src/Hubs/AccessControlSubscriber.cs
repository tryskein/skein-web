using System.Text.Json;
using Microsoft.AspNetCore.SignalR;
using NATS.Client.Core;
using SkeinWeb.Auth;

namespace SkeinWeb.Hubs;

/// <summary>
/// Control subscription of THIS replica (sk-622.21 K10, INV-9, US-10): events
/// that change who may see what are applied to the replica's own hub
/// connections, on every replica.
/// </summary>
/// <remarks>
/// <para>The subscriptions have NO queue group — every replica receives every
/// control event, because every replica holds connections of its own. (The
/// project-event bridge keeps its queue group: one replica forwards an event,
/// the backplane delivers it everywhere.)</para>
/// <list type="bullet">
///   <item><c>project.member_added</c> / <c>member_removed</c> /
///         <c>member_role_changed</c> — the member's local connections are
///         re-checked against skein-api (<see cref="AccessRecheckService"/>).</item>
///   <item><c>skein.user.{uid}.access_changed</c> (sk-674.18 K-15, D-10,
///         body <see cref="AccessChanged"/>) — the user's local connections
///         leave the groups of the lost projects AT ONCE, without waiting for
///         any re-check, then a re-check of the user against skein-api is
///         queued (it joins the gained projects). Each event is applied on its
///         own task and the re-checks run on a worker of their own, so neither
///         a slow skein-api nor a connection busy declaring holds up the next
///         event of another user. Groups of projects not lost stay.</item>
///   <item><c>user.reactivated</c>, <c>user.field_changed</c> of
///         <c>role</c> — the user's local connections are re-checked
///         (admin → user drops <c>admins:internal</c> and the projects the
///         role made visible).</item>
///   <item><c>user.deactivated</c> (<c>skein.user.{uid}.deactivated</c>) —
///         every group of the user's local connections is dropped at once,
///         and every session ticket of the user is removed
///         (<see cref="IUserSessionRevoker"/>; idempotent, so every replica
///         doing it is harmless).</item>
///   <item><c>project.created</c> / <c>updated</c> / <c>archived</c> /
///         <c>unarchived</c> — the local connections of internal admins are
///         re-checked: their visible set may have changed (sk-674.18 K-15; no
///         <c>projects</c> signal to every admin any more — a project of another
///         user's personal space is not the admin's business).</item>
/// </list>
/// A lost control event is caught by the periodic re-check
/// (<see cref="AccessRecheckService.Interval"/>).
/// </remarks>
public sealed class AccessControlSubscriber : IHostedService
{
    /// <summary>Project lifecycle and membership events of every project.</summary>
    public const string ProjectSubject = "skein.events.project.*.project.>";

    /// <summary>User deactivation.</summary>
    public const string DeactivatedSubject = "skein.user.*.deactivated";

    /// <summary>User reactivation.</summary>
    public const string ReactivatedSubject = "skein.user.*.reactivated";

    /// <summary>Global role change of a user.</summary>
    public const string RoleSubject = "skein.user.*.field.role";

    /// <summary>Access change of a user (T014 <c>AccessChangedSubjectPattern</c>).</summary>
    public const string AccessChangedSubject = "skein.user.*.access_changed";

    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    private readonly INatsConnection _conn;
    private readonly ConnectionRegistry _registry;
    private readonly AccessRecheckService _recheck;
    private readonly IUserSessionRevoker _sessions;
    private readonly IHubContext<SkeinHub> _hub;
    private readonly ILogger<AccessControlSubscriber> _logger;
    private CancellationTokenSource? _cts;
    private Task[] _loops = [];

    /// <summary>
    /// Users waiting for the re-check an <c>access_changed</c> asked for. The
    /// subscription loop only enqueues: it never waits on skein-api, so the
    /// next event — of any user — is applied at once (SC-015, US-19). A user
    /// already queued is not queued twice (coalescing); the worker re-checks
    /// the user's state as of when it runs.
    /// </summary>
    private readonly System.Threading.Channels.Channel<Guid> _recheckQueue =
        System.Threading.Channels.Channel.CreateUnbounded<Guid>(
            new System.Threading.Channels.UnboundedChannelOptions { SingleReader = true });

    private readonly HashSet<Guid> _queued = [];

    /// <summary>
    /// <c>access_changed</c> applications in progress. Each event is applied on
    /// its own task: a connection's <see cref="ConnectionState.Gate"/> may be
    /// held by its own declaration waiting on skein-api, and that must not hold
    /// up the events of other users. Applications only take projects away, so
    /// two of them for one user commute.
    /// </summary>
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Task, byte> _applying = new();

    /// <summary>Creates the subscriber.</summary>
    public AccessControlSubscriber(
        INatsConnection conn,
        ConnectionRegistry registry,
        AccessRecheckService recheck,
        IUserSessionRevoker sessions,
        IHubContext<SkeinHub> hub,
        ILogger<AccessControlSubscriber> logger)
    {
        ArgumentNullException.ThrowIfNull(conn);
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(recheck);
        ArgumentNullException.ThrowIfNull(sessions);
        ArgumentNullException.ThrowIfNull(hub);
        ArgumentNullException.ThrowIfNull(logger);
        _conn = conn;
        _registry = registry;
        _recheck = recheck;
        _sessions = sessions;
        _hub = hub;
        _logger = logger;
    }

    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        _loops =
        [
            Task.Run(() => SubscribeLoop(ProjectSubject, ct), ct),
            Task.Run(() => SubscribeLoop(DeactivatedSubject, ct), ct),
            Task.Run(() => SubscribeLoop(ReactivatedSubject, ct), ct),
            Task.Run(() => SubscribeLoop(RoleSubject, ct), ct),
            Task.Run(() => SubscribeLoop(AccessChangedSubject, ct), ct),
            Task.Run(() => RecheckWorker(ct), ct),
        ];
        _logger.LogInformation("AccessControlSubscriber started without queue group");
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _cts?.Cancel();
        try
        {
            await Task.WhenAll(_loops.Concat(_applying.Keys)).WaitAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            // Cooperative shutdown.
        }
        finally
        {
            _cts?.Dispose();
            _cts = null;
        }
    }

    private async Task SubscribeLoop(string subject, CancellationToken ct)
    {
        try
        {
            await foreach (var msg in _conn.SubscribeAsync<byte[]>(subject, queueGroup: null, cancellationToken: ct))
            {
                try
                {
                    await HandleAsync(msg.Subject, msg.Data, ct);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "AccessControlSubscriber handling failed subject={Subject}", msg.Subject);
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Normal shutdown.
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "AccessControlSubscriber loop exited subject={Subject}", subject);
        }
    }

    internal async Task HandleAsync(string subject, byte[]? body, CancellationToken ct)
    {
        if (!SubjectParser.TryParse(subject, out var parsed))
        {
            return;
        }

        if (parsed.Namespace == SubjectNamespace.User && parsed.UserId is { } userId)
        {
            if (parsed.Action == "deactivated")
            {
                await DeactivateAsync(userId, ct);
            }
            else if (parsed.Action == "access_changed")
            {
                Track(ApplyAccessChangedAsync(userId, body, ct));
            }
            else if (parsed.Action == "reactivated"
                     || (parsed.Action == "field_changed" && parsed.FieldName == "role"))
            {
                await _recheck.RecheckUserAsync(userId, "event");
            }
            return;
        }

        if (parsed.Namespace != SubjectNamespace.Project || parsed.EntityType != "project")
        {
            return;
        }
        switch (parsed.Action)
        {
            case "member_added":
            case "member_removed":
            case "member_role_changed":
                if (MemberOf(body) is { } member)
                {
                    await _recheck.RecheckUserAsync(member, "event");
                }
                return;
            case "created":
            case "updated":
            case "archived":
            case "unarchived":
                await _recheck.RecheckInternalAdminsAsync("event");
                return;
        }
    }

    /// <summary>
    /// Applies <c>access_changed</c>: the user's local connections leave the
    /// groups of the lost projects at once (each under its
    /// <see cref="ConnectionState.Gate"/>, bumping
    /// <see cref="ConnectionState.AccessGeneration"/> so an in-flight re-check
    /// cannot put them back), then a re-check of the user is QUEUED — it joins
    /// the gained projects on the worker, without holding up the next event.
    /// A body that cannot be read still queues the re-check.
    /// </summary>
    private async Task ApplyAccessChangedAsync(Guid userId, byte[]? body, CancellationToken ct)
    {
        AccessChanged? change = null;
        try
        {
            change = body is { Length: > 0 } ? JsonSerializer.Deserialize<AccessChanged>(body, JsonOpts) : null;
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "access_changed body deserialise failed userId={UserId}", userId);
        }
        var lost = new HashSet<Guid>(change?.LostProjectIds ?? []);
        foreach (var state in _registry.ConnectionsOf(userId))
        {
            await state.Gate.WaitAsync(ct);
            try
            {
                state.AccessGeneration++;
                if (lost.Count == 0)
                {
                    continue;
                }
                state.DeclaredAllowed = state.DeclaredAllowed.Where(p => !lost.Contains(p)).ToArray();
                state.AllVisibleProjects = state.AllVisibleProjects.Where(p => !lost.Contains(p)).ToArray();
                var removed = state.JoinedGroups.Except(state.DesiredGroups()).Count();
                await ConnectionRegistry.SyncGroupsAsync(state, _hub.Groups, ct);
                if (removed > 0)
                {
                    HubMetrics.AccessRevoked.WithLabels("event").Inc(removed);
                    _logger.LogInformation(
                        "access_changed: connection left lost project groups userId={UserId} connectionId={ConnectionId} groups={Removed}",
                        userId, state.ConnectionId, removed);
                }
            }
            finally
            {
                state.Gate.Release();
            }
        }
        RequestRecheck(userId);
    }

    private void Track(Task application)
    {
        _applying[application] = 0;
        application.ContinueWith(
            t =>
            {
                _applying.TryRemove(t, out _);
                if (t.IsFaulted)
                {
                    _logger.LogError(t.Exception, "access_changed application failed");
                }
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    /// <summary>Queues a re-check of <paramref name="userId"/> unless one is already queued.</summary>
    private void RequestRecheck(Guid userId)
    {
        lock (_queued)
        {
            if (!_queued.Add(userId))
            {
                return;
            }
        }
        _recheckQueue.Writer.TryWrite(userId);
    }

    /// <summary>
    /// Runs the queued re-checks one by one, apart from the subscription
    /// loops. A failing re-check is logged and the worker goes on — the
    /// periodic re-check remains the safety net.
    /// </summary>
    private async Task RecheckWorker(CancellationToken ct)
    {
        try
        {
            await foreach (var userId in _recheckQueue.Reader.ReadAllAsync(ct))
            {
                lock (_queued)
                {
                    // Dequeued before the call: an access_changed arriving while
                    // it runs queues a fresh re-check.
                    _queued.Remove(userId);
                }
                try
                {
                    await _recheck.RecheckUserAsync(userId, "event");
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "access_changed re-check failed userId={UserId}", userId);
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Normal shutdown.
        }
    }

    private async Task DeactivateAsync(Guid userId, CancellationToken ct)
    {
        foreach (var state in _registry.ConnectionsOf(userId))
        {
            await state.Gate.WaitAsync(ct);
            try
            {
                state.Suspended = true;
                state.IsInternalAdmin = false;
                var removed = state.JoinedGroups.Count;
                await ConnectionRegistry.SyncGroupsAsync(state, _hub.Groups, ct);
                await _hub.Groups.RemoveFromGroupAsync(state.ConnectionId, HubGroups.InternalAdmins, ct);
                state.InInternalAdminsGroup = false;
                await _hub.Groups.RemoveFromGroupAsync(state.ConnectionId, SkeinHub.OrgBroadcastGroup, ct);
                if (removed > 0)
                {
                    HubMetrics.AccessRevoked.WithLabels("event").Inc(removed);
                }
            }
            finally
            {
                state.Gate.Release();
            }
        }
        var ticketKeys = await _sessions.RemoveByUserIdAsync(userId, ct);
        _logger.LogInformation(
            "user deactivated: hub groups and session tickets removed userId={UserId} ticketKeysDeleted={TicketKeysDeleted}",
            userId, ticketKeys);
    }

    /// <summary>The member a membership event is about: <c>newData.userId</c>, else <c>oldData.userId</c>.</summary>
    private Guid? MemberOf(byte[]? body)
    {
        if (body is not { Length: > 0 })
        {
            return null;
        }
        EventEnvelope? envelope;
        try
        {
            envelope = JsonSerializer.Deserialize<EventEnvelope>(body, JsonOpts);
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "AccessControlSubscriber membership envelope deserialise failed");
            return null;
        }
        foreach (var data in new[] { envelope?.NewData, envelope?.OldData })
        {
            if (data is { ValueKind: JsonValueKind.Object } o
                && o.TryGetProperty("userId", out var uid)
                && uid.ValueKind == JsonValueKind.String
                && Guid.TryParse(uid.GetString(), out var id))
            {
                return id;
            }
        }
        _logger.LogWarning("AccessControlSubscriber membership event without userId");
        return null;
    }
}
