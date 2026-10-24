using Microsoft.AspNetCore.SignalR;
using NATS.Client.Core;
using SkeinWeb.Auth;

namespace SkeinWeb.Hubs;

/// <summary>
/// Gate the <see cref="NatsBridge"/> passes before forwarding a project event:
/// after the bridge's NATS connection is restored, forwarding waits until the
/// access of every connection has been re-checked (sk-622.21 K10).
/// </summary>
public interface IProjectDeliveryGate
{
    /// <summary>Completes when project events may be forwarded.</summary>
    Task WaitOpenAsync(CancellationToken ct);
}

/// <summary>
/// Re-checks the project access of the hub connections held by THIS replica
/// against skein-api (sk-622.21 K10, INV-9, SC-014): every
/// <see cref="Interval"/> for all connections in batch calls of at most
/// <see cref="SkeinServiceApiClient.MaxQueriesPerCall"/> entries, on demand
/// for one user's connections (control events,
/// <see cref="AccessControlSubscriber"/>), and after the NATS connection is
/// restored — before project events are forwarded again.
/// </summary>
/// <remarks>
/// <para>A successful answer re-applies, per connection, the declared
/// projects the user may still see, the groups of the projects skein-api
/// lists as visible in the "all visible" mode (version 2, sk-674.18 K-15 /
/// ADR-3: the set for every actor, the admin included), and the
/// <see cref="HubGroups.InternalAdmins"/> group (role from the database, not
/// from the cookie). An answer to a query built before the connection's last
/// <c>access_changed</c> (<see cref="ConnectionState.AccessGeneration"/>) is
/// stale and not applied.</para>
/// <para><b>Ended sessions (INV-26).</b> A sweep with its own
/// <see cref="Interval"/> timer — independent of the access runs and their
/// lock, so a slow skein-api does not delay it — closes the connections whose
/// session ticket is gone or now belongs to another user
/// (<see cref="ISessionTicketProbe"/>,
/// on every replica): a session revoked by skein-api, signed out, or removed
/// by a password reset stops receiving frames within <see cref="Interval"/>.
/// The replica that ends the session closes its own connections at once
/// (<see cref="SessionRevocation.EndSessionAsync"/>). The store unreachable —
/// nothing is closed in that run.</para>
/// <para><b>Fail-closed.</b> A check that fails (<see cref="SkeinServiceApiClient"/>
/// throws <see cref="HttpRequestException"/>, <see cref="TimeoutException"/>
/// or <see cref="OperationCanceledException"/>) changes nothing by itself; but
/// a connection whose access has not been confirmed for
/// <see cref="FailClosedAfter"/> or longer is taken out of every
/// project-delivery group (<c>project:{pid}</c>) until the
/// next successful check, which puts it back into the groups its declarations
/// still allow. The deadline is enforced by a sweep that does not wait for any
/// access call: at the start of every periodic run, before its calls, and by a
/// timer set to the earliest deadline of the connections still in groups — so
/// a call hanging until <see cref="SkeinServiceApiClient.CallBudget"/>, or a
/// later batch of the same run, never holds a connection in its groups past
/// the deadline. Access counts as confirmed at the moment the successful
/// check was sent. With <see cref="Interval"/> = 30 s a lost control event is
/// therefore applied within 30 s while skein-api answers, and within 60 s
/// while it does not.</para>
/// <para>Not covered by the sweep: a connection whose own declaration
/// (<see cref="SkeinHub.DeclareProjects"/>) is waiting on skein-api at its
/// deadline — the hub holds the connection's <see cref="ConnectionState.Gate"/>
/// for the call, so the sweep takes the connection out when that call ends,
/// at most <see cref="SkeinServiceApiClient.CallBudget"/> later.</para>
/// </remarks>
public sealed class AccessRecheckService : IHostedService, IProjectDeliveryGate, IDisposable
{
    /// <summary>Period of the full re-check.</summary>
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);

    /// <summary>Unconfirmed access older than this keeps a connection out of project groups.</summary>
    public static readonly TimeSpan FailClosedAfter = TimeSpan.FromSeconds(60);

    private readonly ConnectionRegistry _registry;
    private readonly SkeinServiceApiClient _access;
    private readonly IHubContext<SkeinHub> _hub;
    private readonly INatsConnection _nats;
    private readonly TimeProvider _time;
    private readonly ILogger<AccessRecheckService> _logger;
    private readonly ISessionTicketProbe _tickets;
    private readonly SemaphoreSlim _runLock = new(1, 1);
    private readonly object _gateLock = new();
    private TaskCompletionSource _open = NewOpenGate();
    private readonly object _deadlineLock = new();
    private ITimer? _timer;
    private ITimer? _sessionTimer;
    private int _sessionSweepRunning;
    private ITimer? _deadlineTimer;
    private CancellationTokenSource? _cts;

    /// <summary>Creates the service.</summary>
    /// <param name="registry">This replica's connections.</param>
    /// <param name="access">skein-api access client.</param>
    /// <param name="hub">Hub context (groups).</param>
    /// <param name="nats">NATS connection whose reconnect triggers a re-check.</param>
    /// <param name="time">Clock.</param>
    /// <param name="logger">Logger.</param>
    /// <param name="tickets">Session store probe for closing connections of ended
    /// sessions (INV-26). Required: without it a revoked session would go on
    /// receiving frames.</param>
    public AccessRecheckService(
        ConnectionRegistry registry,
        SkeinServiceApiClient access,
        IHubContext<SkeinHub> hub,
        INatsConnection nats,
        TimeProvider time,
        ILogger<AccessRecheckService> logger,
        ISessionTicketProbe tickets)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(access);
        ArgumentNullException.ThrowIfNull(hub);
        ArgumentNullException.ThrowIfNull(nats);
        ArgumentNullException.ThrowIfNull(time);
        ArgumentNullException.ThrowIfNull(logger);
        _registry = registry;
        _access = access;
        _hub = hub;
        _nats = nats;
        _time = time;
        _logger = logger;
        ArgumentNullException.ThrowIfNull(tickets);
        _tickets = tickets;
    }

    /// <summary>Connections of this replica whose session ticket is checked per run, at most, concurrently.</summary>
    private const int TicketProbeParallelism = 64;

    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = new CancellationTokenSource();
        _nats.ConnectionDisconnected += OnNatsDisconnected;
        _nats.ConnectionOpened += OnNatsOpened;
        lock (_deadlineLock)
        {
            _deadlineTimer = _time.CreateTimer(
                static state => _ = ((AccessRecheckService)state!).RunDeadlineSweepAsync(),
                this,
                Timeout.InfiniteTimeSpan,
                Timeout.InfiniteTimeSpan);
        }
        _timer = _time.CreateTimer(
            static state => _ = ((AccessRecheckService)state!).RunPeriodicAsync(),
            this,
            Interval,
            Interval);
        // Its own period: a slow skein-api or a long access run never delays
        // closing the connections of ended sessions.
        _sessionTimer = _time.CreateTimer(
            static state => _ = ((AccessRecheckService)state!).RunSessionSweepAsync(),
            this,
            Interval,
            Interval);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken)
    {
        _nats.ConnectionDisconnected -= OnNatsDisconnected;
        _nats.ConnectionOpened -= OnNatsOpened;
        _timer?.Dispose();
        _timer = null;
        _sessionTimer?.Dispose();
        _sessionTimer = null;
        lock (_deadlineLock)
        {
            _deadlineTimer?.Dispose();
            _deadlineTimer = null;
        }
        _cts?.Cancel();
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task WaitOpenAsync(CancellationToken ct)
    {
        Task gate;
        lock (_gateLock)
        {
            gate = _open.Task;
        }
        return gate.IsCompleted ? Task.CompletedTask : gate.WaitAsync(ct);
    }

    /// <summary>Re-checks every connection of this replica in one call.</summary>
    /// <param name="reason">Metric label of revocations it causes: <c>recheck</c> or <c>event</c>.</param>
    public Task RecheckAllAsync(string reason) => RecheckAsync(_registry.All(), reason);

    /// <summary>Re-checks the connections of one user on this replica.</summary>
    public Task RecheckUserAsync(Guid userId, string reason) => RecheckAsync(_registry.ConnectionsOf(userId), reason);

    /// <summary>
    /// Re-checks the connections of internal admins on this replica (sk-674.18
    /// K-15): a project was created, changed or archived, and the admin's
    /// visible set may have changed with it. Replaces version 1's signal of the
    /// <c>projects</c> area to every admin.
    /// </summary>
    public Task RecheckInternalAdminsAsync(string reason) =>
        RecheckAsync(_registry.All().Where(s => s.IsInternalAdmin && !s.IsExternal).ToArray(), reason);

    /// <summary>
    /// Closes every connection of this replica whose session ticket is gone or
    /// no longer belongs to the connection's user
    /// (INV-26). A failed probe closes nothing: the store being unreachable is
    /// not a verdict on the session.
    /// </summary>
    public async Task CloseEndedSessionsAsync()
    {
        var ct = _cts?.Token ?? CancellationToken.None;
        var candidates = _registry.All().Where(s => s.SessionKey is not null && !s.IsAborted).ToArray();
        await Parallel.ForEachAsync(
            candidates,
            new ParallelOptions { MaxDegreeOfParallelism = TicketProbeParallelism, CancellationToken = ct },
            async (state, token) =>
            {
                bool live;
                try
                {
                    live = await _tickets.IsSessionOfAsync(state.SessionKey!, state.UserId, token);
                }
                catch (Exception ex) when (ex is not OperationCanceledException || !token.IsCancellationRequested)
                {
                    _logger.LogWarning(ex,
                        "session ticket probe failed, connection kept userId={UserId} connectionId={ConnectionId}",
                        state.UserId, state.ConnectionId);
                    return;
                }
                if (!live && _registry.Get(state.ConnectionId) is not null)
                {
                    state.Abort();
                    _logger.LogInformation(
                        "hub connection closed: its session has ended or changed owner userId={UserId} connectionId={ConnectionId}",
                        state.UserId, state.ConnectionId);
                }
            });
    }

    private async Task RunPeriodicAsync()
    {
        try
        {
            // Before the calls and without waiting for _runLock: a run still
            // hanging on skein-api must not hold an expired connection in groups.
            await SweepExpiredAsync();
            await RecheckAllAsync("recheck");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "access re-check run failed");
        }
    }

    private async Task RunSessionSweepAsync()
    {
        // A sweep still running (a hanging Redis) is not overlapped.
        if (Interlocked.Exchange(ref _sessionSweepRunning, 1) == 1)
        {
            return;
        }
        try
        {
            await CloseEndedSessionsAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ended-session sweep failed");
        }
        finally
        {
            Volatile.Write(ref _sessionSweepRunning, 0);
        }
    }

    private async Task RunDeadlineSweepAsync()
    {
        try
        {
            await SweepExpiredAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "fail-closed sweep failed");
        }
    }

    /// <summary>
    /// Takes every connection whose access has been unconfirmed for
    /// <see cref="FailClosedAfter"/> out of its project groups, then sets the
    /// deadline timer to the earliest deadline of the connections left.
    /// </summary>
    private async Task SweepExpiredAsync()
    {
        var ct = _cts?.Token ?? CancellationToken.None;
        var now = _time.GetUtcNow();
        var expired = _registry.All()
            .Where(s => !s.Suspended && now - s.LastAccessConfirmedAt >= FailClosedAfter)
            .ToArray();
        // The next deadline is armed BEFORE waiting on the expired connections'
        // gates: a gate held by a connection's own declaration (up to
        // CallBudget) must not delay the deadline of any other connection.
        ScheduleNextSweep(expired);
        // Concurrently: a connection whose gate is held (its own declaration
        // waiting on skein-api) must not delay the others.
        await Task.WhenAll(expired.Select(s => FailCloseIfExpiredAsync(s, ct)));
        ScheduleNextSweep();
    }

    /// <summary>
    /// Arms the deadline timer at the earliest deadline of the connections still
    /// in groups, leaving out <paramref name="beingClosed"/> — connections the
    /// running sweep is already taking out (their deadline has passed; counting
    /// them would re-fire the timer at once while their gates are held).
    /// </summary>
    private void ScheduleNextSweep(IReadOnlyCollection<ConnectionState>? beingClosed = null)
    {
        DateTimeOffset? earliest = null;
        foreach (var state in _registry.All())
        {
            if (state.Suspended || (beingClosed is not null && beingClosed.Contains(state)))
            {
                continue;
            }
            var deadline = state.LastAccessConfirmedAt + FailClosedAfter;
            if (earliest is null || deadline < earliest)
            {
                earliest = deadline;
            }
        }
        lock (_deadlineLock)
        {
            if (_deadlineTimer is null)
            {
                return;
            }
            // No connection in groups: the next periodic run (at most Interval
            // < FailClosedAfter after any new connection) sets the timer.
            var due = earliest is { } at
                ? TimeSpan.FromTicks(Math.Max(0, (at - _time.GetUtcNow()).Ticks))
                : Timeout.InfiniteTimeSpan;
            _deadlineTimer.Change(due, Timeout.InfiniteTimeSpan);
        }
    }

    private async Task RecheckAsync(IReadOnlyList<ConnectionState> connections, string reason)
    {
        if (connections.Count == 0)
        {
            return;
        }
        var ct = _cts?.Token ?? CancellationToken.None;
        await _runLock.WaitAsync(ct);
        try
        {
            // T028 batch budget: at most MaxQueriesPerCall entries per call.
            // Each batch is checked and applied (or failed closed) on its own.
            foreach (var batch in connections.Chunk(SkeinServiceApiClient.MaxQueriesPerCall))
            {
                await RecheckBatchAsync(batch, reason, ct);
            }
        }
        finally
        {
            _runLock.Release();
        }
    }

    private async Task RecheckBatchAsync(ConnectionState[] connections, string reason, CancellationToken ct)
    {
        var queries = connections
            .Select(c => new ProjectAccessQuery(c.UserId, ProjectIds: c.DeclaredRequested, AllVisible: c.AllVisible))
            .ToArray();
        // Snapshot of each connection's access generation as of the query: an
        // access_changed applied while the call is in flight makes the answer stale.
        var generations = connections.Select(c => c.AccessGeneration).ToArray();
        // Access is confirmed as of the moment the check was sent.
        var checkedAt = _time.GetUtcNow();
        IReadOnlyList<ProjectAccessResult> results;
        try
        {
            results = await _access.CheckProjectAccessAsync(queries, ct);
        }
        catch (Exception ex) when (ex is HttpRequestException or TimeoutException
                                   || (ex is OperationCanceledException && !ct.IsCancellationRequested))
        {
            _logger.LogWarning(ex, "access re-check failed connections={Count}; applying fail-closed rule",
                connections.Length);
            await Task.WhenAll(connections.Select(s => FailCloseIfExpiredAsync(s, ct)));
            return;
        }

        for (var i = 0; i < connections.Length; i++)
        {
            await ApplyAsync(connections[i], queries[i], generations[i], results[i], checkedAt, reason, ct);
        }
        ScheduleNextSweep();
    }

    private async Task ApplyAsync(
        ConnectionState state, ProjectAccessQuery query, int generation, ProjectAccessResult result,
        DateTimeOffset checkedAt, string reason, CancellationToken ct)
    {
        if (_registry.Get(state.ConnectionId) is null)
        {
            return; // closed meanwhile
        }
        await state.Gate.WaitAsync(ct);
        try
        {
            if (!ReferenceEquals(query.ProjectIds, state.DeclaredRequested) || query.AllVisible != state.AllVisible)
            {
                // The tab re-declared while this check was in flight; the hub
                // has just checked the newer set — this answer is stale for it.
                return;
            }
            if (generation != state.AccessGeneration)
            {
                // An access_changed was applied while this check was in flight:
                // the answer may predate it and put back a lost project. The
                // re-check that event triggered answers for the current state.
                return;
            }
            if (_time.GetUtcNow() - checkedAt >= FailClosedAfter)
            {
                // Not a fresh answer: it says nothing about the last
                // FailClosedAfter, so it neither confirms nor restores.
                return;
            }
            var allowed = result.Active ? new HashSet<Guid>(result.Allowed) : [];
            state.DeclaredAllowed = state.DeclaredRequested.Where(allowed.Contains).ToArray();
            if (state.AllVisible)
            {
                // K-15, ADR-3: the visible set for every actor; internalAdmin
                // is the role only and widens nothing.
                state.AllVisibleProjects = result.Active
                    ? (IReadOnlyList<Guid>?)result.VisibleProjectIds?.ToArray() ?? []
                    : [];
            }
            state.IsInternalAdmin = result.InternalAdmin;
            if (checkedAt > state.LastAccessConfirmedAt)
            {
                state.LastAccessConfirmedAt = checkedAt;
            }
            state.Suspended = false;

            var before = state.JoinedGroups.Count;
            var removed = state.JoinedGroups.Except(state.DesiredGroups()).Count();
            await ConnectionRegistry.SyncGroupsAsync(state, _hub.Groups, ct);
            await SyncInternalAdminsAsync(state, ct);
            if (removed > 0)
            {
                HubMetrics.AccessRevoked.WithLabels(reason).Inc(removed);
                _logger.LogInformation(
                    "access revoked userId={UserId} connectionId={ConnectionId} groups={Removed} of {Before} reason={Reason}",
                    state.UserId, state.ConnectionId, removed, before, reason);
            }
        }
        finally
        {
            state.Gate.Release();
        }
    }

    private async Task SyncInternalAdminsAsync(ConnectionState state, CancellationToken ct)
    {
        if (state.IsInternalAdmin && !state.InInternalAdminsGroup)
        {
            await _hub.Groups.AddToGroupAsync(state.ConnectionId, HubGroups.InternalAdmins, ct);
            state.InInternalAdminsGroup = true;
        }
        else if (!state.IsInternalAdmin && state.InInternalAdminsGroup)
        {
            await _hub.Groups.RemoveFromGroupAsync(state.ConnectionId, HubGroups.InternalAdmins, ct);
            state.InInternalAdminsGroup = false;
        }
    }

    /// <summary>
    /// Takes the connection out of its project groups when its access is
    /// unconfirmed for <see cref="FailClosedAfter"/>. Decided under
    /// <see cref="ConnectionState.Gate"/> on the state read there: a
    /// declaration that confirmed access while this waited for the gate wins.
    /// </summary>
    private async Task FailCloseIfExpiredAsync(ConnectionState state, CancellationToken ct)
    {
        if (_registry.Get(state.ConnectionId) is null)
        {
            return;
        }
        await state.Gate.WaitAsync(ct);
        try
        {
            var unconfirmed = _time.GetUtcNow() - state.LastAccessConfirmedAt;
            if (state.Suspended || unconfirmed < FailClosedAfter || _registry.Get(state.ConnectionId) is null)
            {
                return;
            }
            state.Suspended = true;
            var removed = state.JoinedGroups.Count;
            await ConnectionRegistry.SyncGroupsAsync(state, _hub.Groups, ct);
            if (removed > 0)
            {
                HubMetrics.AccessRevoked.WithLabels("recheck").Inc(removed);
            }
            _logger.LogWarning(
                "access unconfirmed for {Seconds} s, connection taken out of project groups userId={UserId} connectionId={ConnectionId}",
                unconfirmed.TotalSeconds, state.UserId, state.ConnectionId);
        }
        finally
        {
            state.Gate.Release();
        }
    }

    private ValueTask OnNatsDisconnected(object? sender, NatsEventArgs args)
    {
        lock (_gateLock)
        {
            if (_open.Task.IsCompleted)
            {
                _open = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            }
        }
        return ValueTask.CompletedTask;
    }

    private async ValueTask OnNatsOpened(object? sender, NatsEventArgs args)
    {
        try
        {
            await RecheckAllAsync("recheck");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "access re-check after NATS reconnect failed");
        }
        finally
        {
            // Forwarding resumes after the re-check — successful or fail-closed.
            lock (_gateLock)
            {
                _open.TrySetResult();
            }
        }
    }

    private static TaskCompletionSource NewOpenGate()
    {
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        tcs.SetResult();
        return tcs;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _timer?.Dispose();
        _sessionTimer?.Dispose();
        lock (_deadlineLock)
        {
            _deadlineTimer?.Dispose();
        }
        _cts?.Dispose();
        _runLock.Dispose();
    }
}
