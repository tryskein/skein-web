using System.Globalization;
using Microsoft.AspNetCore.SignalR;

namespace SkeinWeb.Hubs;

/// <summary>
/// Settings of the personal-signal coalescing (spec sk-622.21 US-11, K9).
/// Built once in <c>Program.cs</c> and registered as a singleton.
/// </summary>
public sealed class PersonalSignalOptions
{
    /// <summary>Environment variable of <see cref="Window"/>, in milliseconds.</summary>
    public const string WindowEnvVar = "COUNTS_SIGNAL_WINDOW_MS";

    /// <summary>Default <see cref="Window"/>: 2000 ms (spec US-11).</summary>
    public static readonly TimeSpan DefaultWindow = TimeSpan.FromMilliseconds(2000);

    /// <summary>
    /// Per-connection coalescing window: a connection receives at most one
    /// <see cref="BrowserClientMethods.Signal"/> frame per window.
    /// </summary>
    public TimeSpan Window { get; init; } = DefaultWindow;

    /// <summary>
    /// Turns the raw value of <see cref="WindowEnvVar"/> into
    /// <see cref="Window"/>. <c>null</c> (variable not set) yields
    /// <see cref="DefaultWindow"/>; anything else must be a positive whole
    /// number of milliseconds.
    /// </summary>
    /// <exception cref="InvalidOperationException">The value is set but empty,
    /// not an integer, or not positive — startup must stop (spec edge 17).</exception>
    public static TimeSpan ParseWindow(string? raw)
    {
        if (raw is null)
        {
            return DefaultWindow;
        }
        if (!int.TryParse(raw.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var ms) || ms <= 0)
        {
            throw new InvalidOperationException(
                $"{WindowEnvVar} must be a positive whole number of milliseconds, got '{raw}'");
        }
        return TimeSpan.FromMilliseconds(ms);
    }
}

/// <summary>
/// Coalesces personal signals per hub connection of THIS replica (spec
/// sk-622.21 US-11, K9, R15): each connection gets at most one
/// <see cref="BrowserClientMethods.Signal"/> frame per
/// <see cref="PersonalSignalOptions.Window"/>, carrying the union of the areas
/// signalled within it.
/// </summary>
/// <remarks>
/// <para>The window of a connection opens with the first signal addressed to
/// it and closes <see cref="PersonalSignalOptions.Window"/> later on the
/// injected <see cref="TimeProvider"/>; at that moment exactly one frame goes
/// to that connection only (<c>Clients.Client</c>, never <c>Clients.User</c>:
/// every replica coalesces its own connections, so a user-wide send from two
/// replicas would duplicate frames). A signal after the window opens the
/// next one. A connection that closed before its window ends gets nothing.</para>
/// <para>Recipients are the user's connections on this replica, looked up in
/// <see cref="ConnectionRegistry"/> when the signal arrives — a tab opened
/// later does not inherit an already open window.</para>
/// <para>Area <see cref="PersonalSignalArea.Spaces"/> (sk-674.18 K-18, US-19):
/// the window also collects the <see cref="PersonalSignal.Spaces"/> entries of
/// its signals, and the frame carries their union — no reason is lost.
/// Entries equal in all three fields are carried once, at the position of
/// their LAST occurrence (<see cref="PersonalSignal"/>, T044), so the final
/// entry for a space is its latest event. The frame carries the field exactly
/// when its areas contain <c>spaces</c> and at least one entry was collected;
/// entries of a signal without the <c>spaces</c> area are ignored.</para>
/// </remarks>
public sealed class PersonalSignalCoalescer : IDisposable
{
    private readonly ConnectionRegistry _registry;
    private readonly IHubContext<SkeinHub> _hub;
    private readonly TimeProvider _time;
    private readonly PersonalSignalOptions _options;
    private readonly ILogger<PersonalSignalCoalescer> _logger;
    private readonly object _gate = new();
    private readonly Dictionary<string, PendingWindow> _pending = new(StringComparer.Ordinal);

    /// <summary>Creates the coalescer.</summary>
    public PersonalSignalCoalescer(
        ConnectionRegistry registry,
        IHubContext<SkeinHub> hub,
        TimeProvider time,
        PersonalSignalOptions options,
        ILogger<PersonalSignalCoalescer> logger)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(hub);
        ArgumentNullException.ThrowIfNull(time);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);
        _registry = registry;
        _hub = hub;
        _time = time;
        _options = options;
        _logger = logger;
    }

    /// <summary>Adds <paramref name="areas"/> (and the <paramref name="spaces"/> entries of a <c>spaces</c> signal) to the window of every connection of <paramref name="userId"/> on this replica.</summary>
    public void SignalUser(Guid userId, IReadOnlyCollection<string> areas,
        IReadOnlyList<PersonalSignalSpace>? spaces = null)
    {
        ArgumentNullException.ThrowIfNull(areas);
        foreach (var connection in _registry.ConnectionsOf(userId))
        {
            SignalConnection(connection.ConnectionId, areas, spaces);
        }
    }

    /// <summary>Adds <paramref name="areas"/> (and the <paramref name="spaces"/> entries of a <c>spaces</c> signal) to the window of one connection of this replica.</summary>
    public void SignalConnection(string connectionId, IReadOnlyCollection<string> areas,
        IReadOnlyList<PersonalSignalSpace>? spaces = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(connectionId);
        ArgumentNullException.ThrowIfNull(areas);
        if (areas.Count == 0)
        {
            return;
        }
        var spaceEntries = spaces is { Count: > 0 } && areas.Contains(PersonalSignalArea.Spaces)
            ? spaces
            : (IReadOnlyList<PersonalSignalSpace>)[];
        lock (_gate)
        {
            if (_pending.TryGetValue(connectionId, out var open))
            {
                foreach (var area in areas)
                {
                    open.Areas.Add(area);
                }
                open.Spaces.AddRange(spaceEntries);
                HubMetrics.PersonalSignalsCoalesced.Inc();
                return;
            }
            var window = new PendingWindow(new List<string>());
            foreach (var area in areas)
            {
                if (!window.Areas.Contains(area))
                {
                    window.Areas.Add(area);
                }
            }
            window.Spaces.AddRange(spaceEntries);
            _pending[connectionId] = window;
            window.Timer = _time.CreateTimer(
                static state =>
                {
                    var (self, conn) = ((PersonalSignalCoalescer, string))state!;
                    _ = self.FlushAsync(conn);
                },
                (this, connectionId),
                _options.Window,
                Timeout.InfiniteTimeSpan);
        }
    }

    private async Task FlushAsync(string connectionId)
    {
        PendingWindow? window;
        lock (_gate)
        {
            if (!_pending.Remove(connectionId, out window))
            {
                return;
            }
        }
        window.Timer?.Dispose();
        if (_registry.Get(connectionId) is null)
        {
            // The connection closed within its window: the frame is dropped.
            return;
        }
        try
        {
            var areas = window.Areas.Distinct(StringComparer.Ordinal).ToArray();
            var spaces = areas.Contains(PersonalSignalArea.Spaces, StringComparer.Ordinal)
                ? MergeSpaces(window.Spaces)
                : null;
            await _hub.Clients.Client(connectionId)
                .SendAsync(BrowserClientMethods.Signal, new PersonalSignal(areas, _time.GetUtcNow(), spaces));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "personal signal send failed connectionId={ConnectionId}", connectionId);
        }
    }

    /// <summary>
    /// The union of a window's <c>spaces</c> entries: each distinct entry once,
    /// at the position of its last occurrence, in the order of those positions
    /// (T044 <see cref="PersonalSignal"/>). Null when there are none — the
    /// frame then carries no field.
    /// </summary>
    private static IReadOnlyList<PersonalSignalSpace>? MergeSpaces(List<PersonalSignalSpace> collected)
    {
        if (collected.Count == 0)
        {
            return null;
        }
        var seen = new HashSet<PersonalSignalSpace>();
        var lastFirst = new List<PersonalSignalSpace>(collected.Count);
        for (var i = collected.Count - 1; i >= 0; i--)
        {
            if (seen.Add(collected[i]))
            {
                lastFirst.Add(collected[i]);
            }
        }
        lastFirst.Reverse();
        return lastFirst;
    }

    /// <summary>Stops every open window without sending.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            foreach (var window in _pending.Values)
            {
                window.Timer?.Dispose();
            }
            _pending.Clear();
        }
    }

    private sealed class PendingWindow(List<string> areas)
    {
        public List<string> Areas { get; } = areas;

        /// <summary><c>spaces</c> entries of the window's signals, in arrival order, repeats included.</summary>
        public List<PersonalSignalSpace> Spaces { get; } = [];

        public ITimer? Timer { get; set; }
    }
}
