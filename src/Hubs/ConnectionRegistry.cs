using System.Collections.Concurrent;
using Microsoft.AspNetCore.SignalR;
using SkeinWeb.Auth;

namespace SkeinWeb.Hubs;

/// <summary>
/// Names of the SignalR groups used for addressed delivery (spec sk-622.21
/// US-9, K10). Group membership is replicated across replicas by the Redis
/// backplane; the replica holding the connection decides it.
/// </summary>
public static class HubGroups
{
    /// <summary>Connections receiving the events of project <paramref name="projectId"/>.</summary>
    public static string Project(Guid projectId) => "project:" + projectId.ToString("D");

    /// <summary>
    /// Every connection of an internal admin (role admin, not external). It
    /// receives the events of the entity "user" only — never a project event
    /// or anything carrying project data (sk-674.18 K-15, ADR-3).
    /// </summary>
    /// <remarks>
    /// There is no group for "every project" (version 1's <c>projects:all</c>):
    /// with spaces the admin does not see other users' personal spaces, so the
    /// "all visible" mode of every actor, the admin included, joins the groups
    /// of the projects skein-api lists as visible (D-10).
    /// </remarks>
    public const string InternalAdmins = "admins:internal";
}

/// <summary>
/// State of one hub connection held by the replica that owns its socket.
/// </summary>
/// <remarks>
/// Every mutation of the declaration fields and of <see cref="JoinedGroups"/>
/// happens under <see cref="Gate"/>, so the hub methods (T032) and the access
/// re-check (T034) apply their changes one at a time.
/// </remarks>
public sealed class ConnectionState
{
    /// <summary>Creates the state of a freshly connected connection.</summary>
    /// <param name="connectionId">SignalR connection id.</param>
    /// <param name="userId">Owner of the connection.</param>
    /// <param name="isExternal">External-collaborator flag of the cookie principal.</param>
    /// <param name="isInternalAdmin">Role admin and not external per the cookie principal.</param>
    /// <param name="sessionKey">Key of the session ticket the connection was opened with
    /// (<see cref="SessionPrincipal.SessionKeyClaim"/>); null for a principal without it.</param>
    /// <param name="abort">Closes the connection from the server side; null — nothing to close (tests).</param>
    public ConnectionState(string connectionId, Guid userId, bool isExternal, bool isInternalAdmin,
        string? sessionKey = null, Action? abort = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(connectionId);
        ConnectionId = connectionId;
        UserId = userId;
        IsExternal = isExternal;
        IsInternalAdmin = isInternalAdmin;
        SessionKey = string.IsNullOrEmpty(sessionKey) ? null : sessionKey;
        _abort = abort;
    }

    private readonly Action? _abort;
    private int _aborted;

    /// <summary>
    /// Key of the session ticket the connection was opened with (sk-674.18
    /// INV-26): when that ticket is gone the session has ended — signed out,
    /// revoked by skein-api (<c>session_revoked</c>) or removed — and the
    /// connection is closed. Every principal read from the session store carries
    /// the key (tickets of an earlier release get it on read); null only for a
    /// principal from elsewhere, which is then not tied to a ticket.
    /// </summary>
    public string? SessionKey { get; }

    /// <summary>Whether <see cref="Abort"/> has been called.</summary>
    public bool IsAborted => Volatile.Read(ref _aborted) != 0;

    /// <summary>
    /// Closes the connection from the server side (once; later calls do
    /// nothing). SignalR then runs <c>OnDisconnectedAsync</c>, which forgets
    /// the connection and drops it from every group.
    /// </summary>
    public void Abort()
    {
        if (Interlocked.Exchange(ref _aborted, 1) == 0)
        {
            _abort?.Invoke();
        }
    }

    /// <summary>
    /// Incremented on every access change applied from a control event
    /// (<c>access_changed</c>). A re-check whose query was built under an
    /// older generation is stale for the connection and is not applied — it
    /// could put back a group the event has just taken away.
    /// </summary>
    public int AccessGeneration { get; set; }

    /// <summary>SignalR connection id.</summary>
    public string ConnectionId { get; }

    /// <summary>Owner of the connection.</summary>
    public Guid UserId { get; }

    /// <summary>External-collaborator flag of the cookie principal at connect time.</summary>
    public bool IsExternal { get; }

    /// <summary>Role admin and not external per the cookie principal at connect time.</summary>
    public bool IsInternalAdmin { get; set; }

    /// <summary>Serialises changes of this connection's declarations and groups.</summary>
    public SemaphoreSlim Gate { get; } = new(1, 1);

    /// <summary>
    /// The candidate set last sent to the access check (after the invalid and
    /// limit filters), in declaration order. Re-declaring the same set is not a
    /// change.
    /// </summary>
    public IReadOnlyList<Guid> DeclaredRequested { get; set; } = [];

    /// <summary>Declared projects the user may see — in force, in declaration order.</summary>
    public IReadOnlyList<Guid> DeclaredAllowed { get; set; } = [];

    /// <summary>"All projects visible to me" mode is on.</summary>
    public bool AllVisible { get; set; }

    /// <summary>
    /// In the "all visible" mode: the projects skein-api lists as visible to
    /// the user (<see cref="ProjectAccessResult.VisibleProjectIds"/>) — for
    /// every actor, the internal admin included. Not limited by
    /// <see cref="HubDeliveryOptions.MaxProjectsPerConnection"/>, which bounds
    /// <see cref="SkeinHub.DeclareProjects"/> only.
    /// </summary>
    public IReadOnlyList<Guid> AllVisibleProjects { get; set; } = [];

    /// <summary>Project-delivery groups (<see cref="HubGroups.Project"/>) the connection is in now.</summary>
    public HashSet<string> JoinedGroups { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Last moment skein-api confirmed this connection's access (connect time
    /// until the first check). Drives the fail-closed rule of K10.
    /// </summary>
    public DateTimeOffset LastAccessConfirmedAt { get; set; }

    /// <summary>
    /// Fail-closed (K10): no successful access check for too long — the
    /// connection is kept out of every project-delivery group until the next
    /// successful check.
    /// </summary>
    public bool Suspended { get; set; }

    /// <summary>Whether the connection is in <see cref="HubGroups.InternalAdmins"/>.</summary>
    public bool InInternalAdminsGroup { get; set; }

    /// <summary>
    /// The project-delivery groups this connection should be in, derived from
    /// its declarations.
    /// </summary>
    public HashSet<string> DesiredGroups()
    {
        var desired = new HashSet<string>(StringComparer.Ordinal);
        if (Suspended)
        {
            return desired;
        }
        foreach (var pid in DeclaredAllowed)
        {
            desired.Add(HubGroups.Project(pid));
        }
        if (AllVisible)
        {
            foreach (var pid in AllVisibleProjects)
            {
                desired.Add(HubGroups.Project(pid));
            }
        }
        return desired;
    }
}

/// <summary>
/// Registry of the hub connections held by THIS replica, indexed by
/// connection and by user (spec sk-622.21 K10). Used by the hub to keep each
/// connection's declarations and groups, by the access re-check (T034) and by
/// the personal-signal coalescer (T036) to find a user's local connections.
/// </summary>
/// <remarks>
/// Reads take no lock. Changes of the per-user index — take the user's
/// bucket, put a connection in, drop the bucket once empty — run under one
/// lock, so a last disconnect and a new connect of the same user cannot
/// interleave: a connection registered by <see cref="Add"/> is never lost
/// from <see cref="ConnectionsOf"/> while it is registered.
/// </remarks>
public sealed class ConnectionRegistry
{
    private readonly ConcurrentDictionary<string, ConnectionState> _byConnection = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<Guid, ConcurrentDictionary<string, ConnectionState>> _byUser = new();
    private readonly object _byUserLock = new();
    private readonly TimeProvider _time;

    /// <summary>Creates the registry on the given clock.</summary>
    public ConnectionRegistry(TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(time);
        _time = time;
    }

    /// <summary>Current time on the registry's clock.</summary>
    public DateTimeOffset Now => _time.GetUtcNow();

    /// <summary>Registers a connection; its access counts as confirmed at this moment.</summary>
    public void Add(ConnectionState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        state.LastAccessConfirmedAt = _time.GetUtcNow();
        _byConnection[state.ConnectionId] = state;
        lock (_byUserLock)
        {
            _byUser.GetOrAdd(state.UserId, _ => new ConcurrentDictionary<string, ConnectionState>(StringComparer.Ordinal))
                [state.ConnectionId] = state;
        }
    }

    /// <summary>Forgets a closed connection; returns its state when it was registered.</summary>
    public ConnectionState? Remove(string connectionId)
    {
        if (!_byConnection.TryRemove(connectionId, out var state))
        {
            return null;
        }
        lock (_byUserLock)
        {
            if (_byUser.TryGetValue(state.UserId, out var conns))
            {
                conns.TryRemove(connectionId, out _);
                if (conns.IsEmpty)
                {
                    // Under the same lock as Add: nothing can enter the bucket
                    // between the emptiness check and its removal.
                    _byUser.TryRemove(state.UserId, out _);
                }
            }
        }
        return state;
    }

    /// <summary>The state of a connection of this replica, or null.</summary>
    public ConnectionState? Get(string connectionId) =>
        _byConnection.TryGetValue(connectionId, out var state) ? state : null;

    /// <summary>The connections of <paramref name="userId"/> on this replica (a snapshot).</summary>
    public IReadOnlyList<ConnectionState> ConnectionsOf(Guid userId) =>
        _byUser.TryGetValue(userId, out var conns) ? conns.Values.ToArray() : [];

    /// <summary>Every connection on this replica (a snapshot).</summary>
    public IReadOnlyList<ConnectionState> All() => _byConnection.Values.ToArray();

    /// <summary>
    /// Closes every connection of this replica opened with the session ticket
    /// <paramref name="sessionKey"/> (sk-674.18 INV-26). Returns how many were closed.
    /// </summary>
    public int AbortSession(string sessionKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(sessionKey);
        return AbortWhere(_byConnection.Values, s => string.Equals(s.SessionKey, sessionKey, StringComparison.Ordinal));
    }

    /// <summary>
    /// Closes every connection of this replica opened with the session ticket
    /// <paramref name="sessionKey"/> by a user other than <paramref name="owner"/>
    /// — the ticket key now belongs to <paramref name="owner"/> (a login or
    /// signup in a tab logged in as somebody else). Returns how many were closed.
    /// </summary>
    public int AbortSessionNotOwnedBy(string sessionKey, Guid owner)
    {
        ArgumentException.ThrowIfNullOrEmpty(sessionKey);
        return AbortWhere(_byConnection.Values,
            s => s.UserId != owner && string.Equals(s.SessionKey, sessionKey, StringComparison.Ordinal));
    }

    /// <summary>
    /// Closes every connection of <paramref name="userId"/> on this replica
    /// except those opened with the session ticket <paramref name="keepSessionKey"/>
    /// (null — closes all of them). Returns how many were closed.
    /// </summary>
    public int AbortUserSessionsExcept(Guid userId, string? keepSessionKey) =>
        AbortWhere(ConnectionsOf(userId),
            s => keepSessionKey is null || !string.Equals(s.SessionKey, keepSessionKey, StringComparison.Ordinal));

    private static int AbortWhere(IEnumerable<ConnectionState> connections, Func<ConnectionState, bool> predicate)
    {
        var closed = 0;
        foreach (var state in connections.Where(predicate).ToArray())
        {
            if (!state.IsAborted)
            {
                state.Abort();
                closed++;
            }
        }
        return closed;
    }

    /// <summary>
    /// Brings the connection's project-delivery groups in line with
    /// <see cref="ConnectionState.DesiredGroups"/>: joins the missing ones,
    /// leaves the extra ones. The caller holds <see cref="ConnectionState.Gate"/>.
    /// </summary>
    public static async Task SyncGroupsAsync(ConnectionState state, IGroupManager groups, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(groups);
        await ApplyGroupsAsync(state, state.DesiredGroups(), groups, ct);
    }

    /// <summary>
    /// Brings the connection's project-delivery groups in line with
    /// <paramref name="desired"/>. The caller holds <see cref="ConnectionState.Gate"/>.
    /// </summary>
    public static async Task ApplyGroupsAsync(
        ConnectionState state, IReadOnlySet<string> desired, IGroupManager groups, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(desired);
        ArgumentNullException.ThrowIfNull(groups);
        foreach (var group in state.JoinedGroups.Where(g => !desired.Contains(g)).ToArray())
        {
            await groups.RemoveFromGroupAsync(state.ConnectionId, group, ct);
            state.JoinedGroups.Remove(group);
        }
        foreach (var group in desired.Where(g => !state.JoinedGroups.Contains(g)).ToArray())
        {
            await groups.AddToGroupAsync(state.ConnectionId, group, ct);
            state.JoinedGroups.Add(group);
        }
    }
}
