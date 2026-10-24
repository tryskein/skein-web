using Microsoft.AspNetCore.SignalR;
using NATS.Client.Core;
using StackExchange.Redis;

namespace SkeinWeb.Hubs;

/// <summary>
/// Where <see cref="NatsBridge"/> reports a SignalR send that failed (sk-622.21
/// K11), so the addressees can be told to re-read once the transport is back.
/// </summary>
public interface IDeliveryFailureRecorder
{
    /// <summary>A send to the given groups failed.</summary>
    void RecordFailedGroupSend(IReadOnlyList<string> groups);

    /// <summary>A send to the given user failed.</summary>
    void RecordFailedUserSend(string userId);
}

/// <summary>
/// Detects transport breaks of THIS replica and sends the
/// <see cref="BrowserClientMethods.Resync"/> frame to the connections that may
/// have missed something (sk-622.21 US-10, INV-10, SC-016, K11).
/// </summary>
/// <remarks>
/// <list type="bullet">
///   <item><b>NATS.</b> NATS does not keep messages for an absent subscriber:
///         after <c>ConnectionDisconnected</c> → <c>ConnectionOpened</c> this
///         replica may have lost events another replica did not take, so every
///         connection of this replica gets <c>resync</c> — after the access
///         re-check that follows the reconnect (<see cref="IProjectDeliveryGate"/>).</item>
///   <item><b>Backplane.</b> The Redis backplane does not buffer: after the
///         multiplexer's <c>ConnectionFailed</c> → <c>ConnectionRestored</c>,
///         this replica's own connections get <c>resync</c>, and so do the
///         groups and users a send to which failed meanwhile (recorded by
///         <see cref="NatsBridge"/> through <see cref="IDeliveryFailureRecorder"/>)
///         — they may live on other replicas. A failed send counts as a
///         break by itself, so its addressees are not left waiting for a
///         <c>ConnectionFailed</c> the multiplexer may never raise.</item>
/// </list>
/// Without a break no <c>resync</c> is sent. The state restored is the tab's,
/// not the missed events themselves (US-10).
/// </remarks>
public sealed class TransportHealthMonitor : IHostedService, IDeliveryFailureRecorder
{
    private readonly INatsConnection _nats;
    private readonly ConnectionRegistry _registry;
    private readonly IHubContext<SkeinHub> _hub;
    private readonly IProjectDeliveryGate _gate;
    private readonly BackplaneConnectionSlot _backplane;
    private readonly TimeProvider _time;
    private readonly ILogger<TransportHealthMonitor> _logger;
    private readonly object _lock = new();
    private readonly HashSet<string> _failedGroups = new(StringComparer.Ordinal);
    private readonly HashSet<string> _failedUsers = new(StringComparer.Ordinal);
    private bool _natsDown;
    private bool _backplaneDown;

    /// <summary>Creates the monitor.</summary>
    public TransportHealthMonitor(
        INatsConnection nats,
        ConnectionRegistry registry,
        IHubContext<SkeinHub> hub,
        IProjectDeliveryGate gate,
        BackplaneConnectionSlot backplane,
        TimeProvider time,
        ILogger<TransportHealthMonitor> logger)
    {
        ArgumentNullException.ThrowIfNull(nats);
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(hub);
        ArgumentNullException.ThrowIfNull(gate);
        ArgumentNullException.ThrowIfNull(backplane);
        ArgumentNullException.ThrowIfNull(time);
        ArgumentNullException.ThrowIfNull(logger);
        _nats = nats;
        _registry = registry;
        _hub = hub;
        _gate = gate;
        _backplane = backplane;
        _time = time;
        _logger = logger;
    }

    /// <summary>
    /// Subscribes to the NATS connection events and to the backplane's
    /// multiplexer (<see cref="BackplaneConnectionSlot"/>) — here and not in
    /// the constructor, so the backplane's options never wait for this
    /// monitor.
    /// </summary>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        _nats.ConnectionDisconnected += OnNatsDisconnected;
        _nats.ConnectionOpened += OnNatsOpened;
        _backplane.Subscribe(AttachBackplane);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken)
    {
        _nats.ConnectionDisconnected -= OnNatsDisconnected;
        _nats.ConnectionOpened -= OnNatsOpened;
        return Task.CompletedTask;
    }

    private void AttachBackplane(IConnectionMultiplexer multiplexer)
    {
        multiplexer.ConnectionFailed += (_, args) => OnBackplaneFailed(args);
        multiplexer.ConnectionRestored += (_, _) => _ = OnBackplaneRestoredAsync();
    }

    /// <summary>
    /// Records the groups of a failed send. A failed send counts as a backplane
    /// break even when the multiplexer reported no <c>ConnectionFailed</c>
    /// (a publish timeout, a command failure): the next
    /// <c>ConnectionRestored</c> sends the resync.
    /// </summary>
    public void RecordFailedGroupSend(IReadOnlyList<string> groups)
    {
        lock (_lock)
        {
            _failedGroups.UnionWith(groups);
            _backplaneDown = true;
        }
        HubMetrics.BridgeSendsFailed.Inc();
    }

    /// <summary>
    /// Records the user of a failed send; counts as a backplane break, as
    /// <see cref="RecordFailedGroupSend"/> does.
    /// </summary>
    public void RecordFailedUserSend(string userId)
    {
        lock (_lock)
        {
            _failedUsers.Add(userId);
            _backplaneDown = true;
        }
        HubMetrics.BridgeSendsFailed.Inc();
    }

    private ValueTask OnNatsDisconnected(object? sender, NatsEventArgs args)
    {
        lock (_lock)
        {
            _natsDown = true;
        }
        _logger.LogWarning("NATS connection lost; connections of this replica will get resync on reconnect");
        return ValueTask.CompletedTask;
    }

    private ValueTask OnNatsOpened(object? sender, NatsEventArgs args)
    {
        lock (_lock)
        {
            if (!_natsDown)
            {
                return ValueTask.CompletedTask; // first connect, no break
            }
            _natsDown = false;
        }
        // Not awaited: the gate opens from another ConnectionOpened handler
        // (AccessRecheckService), which must not wait behind this one.
        _ = ResyncAfterRecheckAsync();
        return ValueTask.CompletedTask;
    }

    private async Task ResyncAfterRecheckAsync()
    {
        try
        {
            await _gate.WaitOpenAsync(CancellationToken.None);
            var connections = _registry.All();
            foreach (var connection in connections)
            {
                await SendResyncAsync(_hub.Clients.Client(connection.ConnectionId));
            }
            _logger.LogInformation("NATS restored: resync sent to {Count} connections", connections.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "resync after NATS reconnect failed");
        }
    }

    private void OnBackplaneFailed(ConnectionFailedEventArgs args)
    {
        lock (_lock)
        {
            _backplaneDown = true;
        }
        _logger.LogWarning("SignalR backplane connection failed endpoint={Endpoint} failure={Failure}",
            args.EndPoint, args.FailureType);
    }

    private async Task OnBackplaneRestoredAsync()
    {
        string[] groups;
        string[] users;
        lock (_lock)
        {
            if (!_backplaneDown)
            {
                return;
            }
            _backplaneDown = false;
            groups = _failedGroups.ToArray();
            users = _failedUsers.ToArray();
            _failedGroups.Clear();
            _failedUsers.Clear();
        }
        try
        {
            foreach (var connection in _registry.All())
            {
                await SendResyncAsync(_hub.Clients.Client(connection.ConnectionId));
            }
            if (groups.Length > 0)
            {
                await SendResyncAsync(_hub.Clients.Groups(groups));
            }
            foreach (var user in users)
            {
                await SendResyncAsync(_hub.Clients.User(user));
            }
            _logger.LogInformation("backplane restored: resync sent, failed groups={Groups} users={Users}",
                groups.Length, users.Length);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "resync after backplane restore failed");
        }
    }

    private Task SendResyncAsync(IClientProxy proxy) =>
        proxy.SendAsync(BrowserClientMethods.Resync, new ResyncFrame(_time.GetUtcNow()));
}
