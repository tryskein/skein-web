using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using SkeinWeb.Auth;

namespace SkeinWeb.Hubs;

/// <summary>
/// SignalR hub at <c>/hub</c> the React SPA connects to for live event
/// streams. Authentication is enforced by the cookie middleware (the
/// <c>[Authorize]</c> attribute uses the default scheme). Events flow
/// server → client via <see cref="NatsBridge"/>; the client calls only the
/// declaration methods of <see cref="ISkeinHubDeclarations"/> (sk-622.21
/// US-9), which put the connection into the SignalR groups of the projects
/// it declared (<see cref="HubGroups"/>).
/// </summary>
/// <remarks>
/// Lifecycle:
/// <list type="number">
///   <item>Browser opens connection, cookie principal authenticated.</item>
///   <item><see cref="OnConnectedAsync"/> registers the connection in this
///         replica's <see cref="ConnectionRegistry"/> and joins the
///         connection-independent groups: <see cref="OrgBroadcastGroup"/>
///         (internal connections) and <see cref="HubGroups.InternalAdmins"/>
///         (internal admins; user events only). No project group yet — project
///         events reach a connection only after it declares projects, admins
///         included. The connection remembers the session ticket it was
///         opened with (<see cref="SessionPrincipal.SessionKeyClaim"/>): when
///         that session ends, the connection is closed (INV-26).</item>
///   <item>The tab calls <see cref="DeclareProjects"/> /
///         <see cref="DeclareAllVisible"/>; access is checked against
///         skein-api (<see cref="SkeinServiceApiClient"/>) and the connection
///         joins the <see cref="HubGroups.Project"/> groups of the projects the
///         user may see — for the "all visible" mode, of every project skein-api
///         lists as visible, for every actor, the admin included (sk-674.18
///         K-15, ADR-3: there is no group of all projects).</item>
///   <item><see cref="NatsBridge"/> sends project events to those groups;
///         the Redis backplane delivers them on every replica.</item>
///   <item><see cref="OnDisconnectedAsync"/> forgets the connection; SignalR
///         drops it from its groups.</item>
/// </list>
/// </remarks>
[Authorize]
public sealed class SkeinHub : Hub, ISkeinHubDeclarations
{
    /// <summary>
    /// SignalR group of connections eligible for org-wide
    /// <c>Clients.All</c>-style broadcasts (sk-163 S7b). INTERNAL
    /// connections join this group on connect; EXTERNAL connections (cookie
    /// claim <c>is_external=true</c>) are deliberately left OUT, so an org-wide
    /// broadcast could never reach an external collaborator.
    /// </summary>
    /// <remarks>
    /// Nothing is sent to this group today: its only broadcast,
    /// <c>theme.updated</c>, became a personal event of the theme's author
    /// (sk-674.18 K-31) and <see cref="NatsBridge"/> no longer forwards an
    /// org-wide theme subject. The membership is kept until the group is
    /// retired together with its tests.
    /// <para>
    /// SignalR removes a connection from all its groups automatically on
    /// disconnect. Group membership propagates across pods via the Redis
    /// backplane, so a broadcast from any replica reaches every internal
    /// connection regardless of which replica holds its socket.
    /// </para>
    /// </remarks>
    public const string OrgBroadcastGroup = "skein:org-broadcast";

    private readonly SkeinServiceApiClient _access;
    private readonly ConnectionRegistry _registry;
    private readonly DeclarationLimiter _limiter;
    private readonly HubDeliveryOptions _options;
    private readonly ILogger<SkeinHub> _logger;

    /// <summary>Creates the hub; resolved per invocation by SignalR.</summary>
    public SkeinHub(
        SkeinServiceApiClient access,
        ConnectionRegistry registry,
        DeclarationLimiter limiter,
        HubDeliveryOptions options,
        ILogger<SkeinHub> logger)
    {
        ArgumentNullException.ThrowIfNull(access);
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(limiter);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);
        _access = access;
        _registry = registry;
        _limiter = limiter;
        _options = options;
        _logger = logger;
    }

    /// <summary>
    /// Registers the connection and joins its connection-independent groups.
    /// Aborts a connection without a parseable user id.
    /// </summary>
    public override async Task OnConnectedAsync()
    {
        var userIdString = Context.UserIdentifier;
        if (string.IsNullOrEmpty(userIdString) || !Guid.TryParse(userIdString, out var userId))
        {
            // No NameIdentifier claim — should be impossible under
            // [Authorize] + cookie auth, but defence in depth.
            _logger.LogWarning("hub connect: missing or unparseable user id, aborting");
            Context.Abort();
            return;
        }

        var role = Context.User?.FindFirstValue(ClaimTypes.Role) ?? "";
        var isAdmin = string.Equals(role, "admin", StringComparison.Ordinal);
        // sk-163 S7b — the cookie principal carries is_external (minted in S1).
        // Missing/false → internal.
        var isExternal = string.Equals(
            Context.User?.FindFirstValue("is_external"),
            "true",
            StringComparison.OrdinalIgnoreCase);
        // sk-163 S2 — an external admin never rides an admin-wide path.
        var isInternalAdmin = isAdmin && !isExternal;

        // The HubCallerContext outlives this invocation: Abort closes the
        // connection later, when its session ends (INV-26).
        var context = Context;
        var state = new ConnectionState(
            Context.ConnectionId, userId, isExternal, isInternalAdmin,
            SessionPrincipal.SessionKeyOf(Context.User), context.Abort);
        _registry.Add(state);
        try
        {
            // Only internal connections are eligible for org-wide broadcasts.
            if (!isExternal)
            {
                await Groups.AddToGroupAsync(
                    Context.ConnectionId, OrgBroadcastGroup, Context.ConnectionAborted);
            }
            // Audience of user events (sk-622.21 K18 "User events").
            if (isInternalAdmin)
            {
                await Groups.AddToGroupAsync(
                    Context.ConnectionId, HubGroups.InternalAdmins, Context.ConnectionAborted);
                state.InInternalAdminsGroup = true;
            }
        }
        catch (OperationCanceledException) when (Context.ConnectionAborted.IsCancellationRequested)
        {
            // Browser disconnected while joining — OnDisconnectedAsync cleans up.
            return;
        }

        await base.OnConnectedAsync();
    }

    /// <summary>
    /// Forgets the connection and its declaration budget. SignalR drops it
    /// from every group itself.
    /// </summary>
    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        _registry.Remove(Context.ConnectionId);
        _limiter.Remove(Context.ConnectionId);
        await base.OnDisconnectedAsync(exception);
    }

    /// <inheritdoc />
    /// <exception cref="HubException">The access check against skein-api failed
    /// (transport, 5xx, timeout); the previous set stays in force and the tab
    /// may declare again.</exception>
    public async Task<DeclareResult> DeclareProjects(string[] projectIds)
    {
        var state = RequireState();
        projectIds ??= [];

        // 1. Syntax and the per-connection limit, in declaration order. The
        //    first spelling of an id is the one echoed back; repeats are ignored.
        var rejected = new List<DeclareRejection>();
        var candidates = new List<Guid>();
        var spelling = new Dictionary<Guid, string>();
        foreach (var raw in projectIds)
        {
            if (raw is null || !Guid.TryParse(raw, out var pid))
            {
                rejected.Add(new DeclareRejection(raw ?? "", DeclareRejectReason.Invalid));
                continue;
            }
            if (!spelling.TryAdd(pid, raw))
            {
                continue;
            }
            if (candidates.Count >= _options.MaxProjectsPerConnection)
            {
                rejected.Add(new DeclareRejection(raw, DeclareRejectReason.Limit));
                continue;
            }
            candidates.Add(pid);
        }

        await state.Gate.WaitAsync(Context.ConnectionAborted);
        try
        {
            // 2. The same candidate set as last time is not a change: no
            //    access call, no rate budget spent; answer from the state.
            var isChange = !new HashSet<Guid>(candidates).SetEquals(state.DeclaredRequested);
            if (isChange)
            {
                if (!_limiter.TryAcquire(state.ConnectionId))
                {
                    var rateRejected = projectIds
                        .Select(raw => new DeclareRejection(raw ?? "", DeclareRejectReason.Rate))
                        .ToArray();
                    CountRejections(rateRejected);
                    return new DeclareResult([], rateRejected);
                }

                // 3. One access call per change of the set.
                IReadOnlyList<Guid> allowed = [];
                if (candidates.Count > 0)
                {
                    var checkedAt = _registry.Now;
                    var answer = await CheckAccessAsync(state, new ProjectAccessQuery(state.UserId, ProjectIds: candidates));
                    var allowedSet = answer.Active ? new HashSet<Guid>(answer.Allowed) : [];
                    allowed = candidates.Where(allowedSet.Contains).ToArray();
                    ConfirmAccess(state, checkedAt, coversEveryGroup: answer.Active && !state.AllVisible);
                }
                state.DeclaredRequested = candidates.ToArray();
                state.DeclaredAllowed = allowed;
                await ConnectionRegistry.SyncGroupsAsync(state, Groups, Context.ConnectionAborted);
            }

            // 4. Answer: accepted in declaration order; the rest of the
            //    candidates are not visible to the user.
            var inForce = new HashSet<Guid>(state.DeclaredAllowed);
            var accepted = new List<string>();
            foreach (var pid in candidates)
            {
                if (inForce.Contains(pid))
                {
                    accepted.Add(spelling[pid]);
                    continue;
                }
                rejected.Add(new DeclareRejection(spelling[pid], DeclareRejectReason.NoAccess));
                _logger.LogWarning(
                    "hub declare: project access denied userId={UserId} projectId={ProjectId} connectionId={ConnectionId}",
                    state.UserId, pid, state.ConnectionId);
            }
            CountRejections(rejected);
            return new DeclareResult(accepted, rejected);
        }
        finally
        {
            state.Gate.Release();
        }
    }

    /// <inheritdoc />
    /// <exception cref="HubException">The access check against skein-api failed;
    /// the previous mode stays in force.</exception>
    public async Task<DeclareResult> DeclareAllVisible(bool enabled)
    {
        var state = RequireState();

        await state.Gate.WaitAsync(Context.ConnectionAborted);
        try
        {
            if (state.AllVisible == enabled)
            {
                return new DeclareResult([], []);
            }
            if (!_limiter.TryAcquire(state.ConnectionId))
            {
                DeclareRejection[] refused = [new DeclareRejection("", DeclareRejectReason.Rate)];
                CountRejections(refused);
                return new DeclareResult([], refused);
            }

            if (enabled)
            {
                var checkedAt = _registry.Now;
                var answer = await CheckAccessAsync(state, new ProjectAccessQuery(state.UserId, AllVisible: true));
                if (!answer.Active)
                {
                    DeclareRejection[] refused = [new DeclareRejection("", DeclareRejectReason.NoAccess)];
                    _logger.LogWarning(
                        "hub declare: all-visible refused, user inactive userId={UserId} connectionId={ConnectionId}",
                        state.UserId, state.ConnectionId);
                    CountRejections(refused);
                    return new DeclareResult([], refused);
                }
                // Every group of the mode is checked: the visible projects,
                // plus the declared ones only when there are none.
                ConfirmAccess(state, checkedAt, coversEveryGroup: state.DeclaredRequested.Count == 0);
                state.AllVisible = true;
                // K-15, ADR-3: the visible set for EVERY actor — internalAdmin
                // is the role only and widens nothing. Not limited by
                // MaxProjectsPerConnection (that bounds DeclareProjects).
                state.AllVisibleProjects = answer.VisibleProjectIds?.ToArray() ?? [];
            }
            else
            {
                state.AllVisible = false;
                state.AllVisibleProjects = [];
            }
            await ConnectionRegistry.SyncGroupsAsync(state, Groups, Context.ConnectionAborted);
            return new DeclareResult([], []);
        }
        finally
        {
            state.Gate.Release();
        }
    }

    /// <summary>
    /// A successful access answer to a declaration is a successful check
    /// (K10): access counts as confirmed as of <paramref name="checkedAt"/>, and
    /// a connection taken out of its groups by the fail-closed rule is put back
    /// when the answer covers every group it would rejoin. The caller holds
    /// <see cref="ConnectionState.Gate"/> and syncs the groups afterwards.
    /// </summary>
    private static void ConfirmAccess(ConnectionState state, DateTimeOffset checkedAt, bool coversEveryGroup)
    {
        if (checkedAt > state.LastAccessConfirmedAt)
        {
            state.LastAccessConfirmedAt = checkedAt;
        }
        if (coversEveryGroup)
        {
            state.Suspended = false;
        }
    }

    private ConnectionState RequireState() =>
        _registry.Get(Context.ConnectionId)
        ?? throw new HubException("connection is not registered");

    /// <summary>
    /// The access call of a declaration whose rate slot is already taken. A
    /// failure hands the slot back (the set did not change) and becomes a
    /// <see cref="HubException"/>.
    /// </summary>
    private async Task<ProjectAccessResult> CheckAccessAsync(ConnectionState state, ProjectAccessQuery query)
    {
        try
        {
            var results = await _access.CheckProjectAccessAsync([query], Context.ConnectionAborted);
            return results[0];
        }
        catch (Exception ex) when (ex is HttpRequestException or TimeoutException
                                   || (ex is OperationCanceledException && !Context.ConnectionAborted.IsCancellationRequested))
        {
            _limiter.Refund(state.ConnectionId);
            _logger.LogWarning(ex,
                "hub declare: project access check failed userId={UserId} connectionId={ConnectionId}",
                query.UserId, Context.ConnectionId);
            throw new HubException("project access check is unavailable, declare again later");
        }
    }

    private static void CountRejections(IEnumerable<DeclareRejection> rejections)
    {
        foreach (var r in rejections)
        {
            HubMetrics.DeclarationsRejected.WithLabels(r.Reason).Inc();
        }
    }
}
