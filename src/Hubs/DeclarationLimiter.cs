using System.Collections.Concurrent;

namespace SkeinWeb.Hubs;

/// <summary>
/// Per-connection rate limit of declaration-set changes (spec sk-622.21
/// US-9): at most <see cref="MaxChanges"/> changes within any
/// <see cref="Window"/>. Keyed by SignalR connection id, never by user — two
/// tabs of one user have independent budgets.
/// </summary>
/// <remarks>
/// A sliding window over the times of accepted changes, read from the
/// injected <see cref="TimeProvider"/>. Re-declaring the same set is not a
/// change and must not be counted — the caller asks only for real changes;
/// a change that did not happen (its access check failed) is handed back
/// with <see cref="Refund"/>.
/// </remarks>
public sealed class DeclarationLimiter
{
    /// <summary>Changes allowed per <see cref="Window"/>.</summary>
    public const int MaxChanges = 10;

    /// <summary>Length of the sliding window.</summary>
    public static readonly TimeSpan Window = TimeSpan.FromSeconds(10);

    private readonly TimeProvider _time;
    private readonly ConcurrentDictionary<string, LinkedList<DateTimeOffset>> _byConnection = new(StringComparer.Ordinal);

    /// <summary>Creates the limiter on the given clock.</summary>
    public DeclarationLimiter(TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(time);
        _time = time;
    }

    /// <summary>
    /// Records one set change of <paramref name="connectionId"/> if its budget
    /// allows it.
    /// </summary>
    /// <returns><c>true</c> when the change is allowed (and counted); <c>false</c> when the budget is exhausted.</returns>
    public bool TryAcquire(string connectionId)
    {
        ArgumentException.ThrowIfNullOrEmpty(connectionId);
        var now = _time.GetUtcNow();
        var changes = _byConnection.GetOrAdd(connectionId, _ => new LinkedList<DateTimeOffset>());
        lock (changes)
        {
            while (changes.First is { } oldest && now - oldest.Value >= Window)
            {
                changes.RemoveFirst();
            }
            if (changes.Count >= MaxChanges)
            {
                return false;
            }
            changes.AddLast(now);
            return true;
        }
    }

    /// <summary>
    /// Hands back the change most recently counted by <see cref="TryAcquire"/>
    /// for <paramref name="connectionId"/>: it did not happen. The caller
    /// serialises the declarations of one connection, so the most recent
    /// change is its own.
    /// </summary>
    public void Refund(string connectionId)
    {
        ArgumentException.ThrowIfNullOrEmpty(connectionId);
        if (!_byConnection.TryGetValue(connectionId, out var changes))
        {
            return;
        }
        lock (changes)
        {
            if (changes.Count > 0)
            {
                changes.RemoveLast();
            }
        }
    }

    /// <summary>Forgets the budget of a closed connection.</summary>
    public void Remove(string connectionId) => _byConnection.TryRemove(connectionId, out _);
}
