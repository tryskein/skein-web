using StackExchange.Redis;

namespace SkeinWeb.Hubs;

/// <summary>
/// Hands the SignalR Redis backplane's multiplexer to the components that
/// watch it (sk-622.21 K11), without making the backplane's options depend on
/// them.
/// </summary>
/// <remarks>
/// <para>The backplane's <c>RedisOptions.ConnectionFactory</c> creates the
/// multiplexer and only stores it here (<see cref="Publish"/>). A watcher
/// (<see cref="TransportHealthMonitor"/>) subscribes from its
/// <c>StartAsync</c> (<see cref="Subscribe"/>), after the container has built
/// the hub lifetime manager.</para>
/// <para>The slot has no dependencies on purpose: the options of the Redis
/// hub lifetime manager are configured from it, and the lifetime manager is
/// what every <c>IHubContext&lt;SkeinHub&gt;</c> consumer needs. A dependency
/// of the slot on such a consumer closes a resolution cycle in which the host
/// never starts.</para>
/// <para>Order does not matter: a subscriber registered before the
/// multiplexer exists is called on <see cref="Publish"/>; one registered
/// after it is called at once with the multiplexer already published.</para>
/// </remarks>
public sealed class BackplaneConnectionSlot
{
    private readonly object _lock = new();
    private readonly List<Action<IConnectionMultiplexer>> _subscribers = [];
    private IConnectionMultiplexer? _multiplexer;

    /// <summary>
    /// Stores the backplane's multiplexer and calls every subscriber with it.
    /// Called by the backplane's connection factory once per multiplexer.
    /// </summary>
    public void Publish(IConnectionMultiplexer multiplexer)
    {
        ArgumentNullException.ThrowIfNull(multiplexer);
        Action<IConnectionMultiplexer>[] subscribers;
        lock (_lock)
        {
            _multiplexer = multiplexer;
            subscribers = [.. _subscribers];
        }
        foreach (var subscriber in subscribers)
        {
            subscriber(multiplexer);
        }
    }

    /// <summary>
    /// Calls <paramref name="onMultiplexer"/> with every multiplexer the
    /// backplane publishes — at once if one is already published.
    /// </summary>
    public void Subscribe(Action<IConnectionMultiplexer> onMultiplexer)
    {
        ArgumentNullException.ThrowIfNull(onMultiplexer);
        IConnectionMultiplexer? current;
        lock (_lock)
        {
            _subscribers.Add(onMultiplexer);
            current = _multiplexer;
        }
        if (current is not null)
        {
            onMultiplexer(current);
        }
    }
}
