using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using Moq;
using NATS.Client.Core;
using SkeinWeb.Auth;
using SkeinWeb.Hubs;

namespace SkeinWeb.Tests.Hubs;

/// <summary>
/// Test double of the SignalR delivery fabric shared by several hub/bridge
/// test classes (sk-622.21 tests No. 59, No. 61, No. 63, No. 64, No. 65, No. 66): connections
/// held by one or more "replicas", group membership, and the client proxies
/// that resolve <c>Group</c> / <c>Groups</c> / <c>User</c> / <c>Client</c> /
/// <c>All</c> to connections AT SEND TIME — the role the Redis backplane plays
/// in production (tests-rationale No. 61). Every delivery is recorded per
/// connection.
/// </summary>
/// <remarks>
/// Not a test itself; it replaces nothing in the product. The product types
/// under test — <see cref="SkeinHub"/>, <see cref="NatsBridge"/>,
/// <see cref="ConnectionRegistry"/>, <see cref="SkeinServiceApiClient"/> —
/// are the real ones; only the boundaries (SignalR transport, skein-api HTTP,
/// NATS) are faked.
/// </remarks>
internal sealed class HubTestWorld
{
    private readonly object _gate = new();
    private readonly Dictionary<string, Guid> _connections = new(StringComparer.Ordinal);
    private readonly Dictionary<string, HashSet<string>> _groups = new(StringComparer.Ordinal);

    public HubTestWorld()
    {
        GroupManager = new FakeGroupManager(this);
        Clients = new FakeHubClients(this);
    }

    /// <summary>Every frame delivered: connection, client method, payload.</summary>
    public List<Delivery> Deliveries { get; } = [];

    /// <summary>Group calls in order: (Add|Remove, connection, group).</summary>
    public List<(string Op, string ConnectionId, string Group)> GroupOps { get; } = [];

    public IGroupManager GroupManager { get; }

    public IHubClients Clients { get; }

    /// <summary>skein-api's view of users, answered by <see cref="AccessApi"/>.</summary>
    public FakeAccessApi AccessApi { get; } = new();

    /// <summary>The NATS server every replica is connected to.</summary>
    public FakeNats Nats { get; } = new();

    /// <summary>The shared session store (Redis) as the hub's ticket probe sees it.</summary>
    public FakeTicketStore Tickets { get; } = new();

    /// <summary>While set, every send throws — the backplane is unreachable.</summary>
    public bool FailSends { get; set; }

    public void AddConnection(string connectionId, Guid userId)
    {
        lock (_gate)
        {
            _connections[connectionId] = userId;
        }
    }

    public void RemoveConnection(string connectionId)
    {
        lock (_gate)
        {
            _connections.Remove(connectionId);
            foreach (var members in _groups.Values)
            {
                members.Remove(connectionId);
            }
        }
    }

    public IReadOnlyCollection<string> GroupsOf(string connectionId)
    {
        lock (_gate)
        {
            return _groups.Where(g => g.Value.Contains(connectionId)).Select(g => g.Key).ToArray();
        }
    }

    public IReadOnlyList<Delivery> DeliveriesTo(string connectionId, string? method = null)
    {
        lock (_gate)
        {
            return Deliveries
                .Where(d => d.ConnectionId == connectionId && (method is null || d.Method == method))
                .ToArray();
        }
    }

    public void ClearDeliveries()
    {
        lock (_gate)
        {
            Deliveries.Clear();
        }
    }

    private Task Send(Func<IEnumerable<string>> targets, string method, object?[] args)
    {
        if (FailSends)
        {
            return Task.FromException(new InvalidOperationException("backplane unreachable"));
        }
        lock (_gate)
        {
            foreach (var conn in targets().Distinct(StringComparer.Ordinal).ToArray())
            {
                Deliveries.Add(new Delivery(conn, method, args.Length > 0 ? args[0] : null));
            }
        }
        return Task.CompletedTask;
    }

    private IEnumerable<string> InGroup(string group) =>
        _groups.TryGetValue(group, out var members) ? members.ToArray() : [];

    private IEnumerable<string> OfUser(string userId) =>
        _connections.Where(c => string.Equals(c.Value.ToString(), userId, StringComparison.OrdinalIgnoreCase))
            .Select(c => c.Key)
            .ToArray();

    public sealed record Delivery(string ConnectionId, string Method, object? Payload);

    private sealed class FakeGroupManager(HubTestWorld world) : IGroupManager
    {
        public Task AddToGroupAsync(string connectionId, string groupName, CancellationToken cancellationToken = default)
        {
            lock (world._gate)
            {
                world.GroupOps.Add(("Add", connectionId, groupName));
                if (!world._groups.TryGetValue(groupName, out var members))
                {
                    world._groups[groupName] = members = new HashSet<string>(StringComparer.Ordinal);
                }
                members.Add(connectionId);
            }
            return Task.CompletedTask;
        }

        public Task RemoveFromGroupAsync(string connectionId, string groupName, CancellationToken cancellationToken = default)
        {
            lock (world._gate)
            {
                world.GroupOps.Add(("Remove", connectionId, groupName));
                if (world._groups.TryGetValue(groupName, out var members))
                {
                    members.Remove(connectionId);
                }
            }
            return Task.CompletedTask;
        }
    }

    private sealed class Proxy(HubTestWorld world, Func<IEnumerable<string>> targets) : ISingleClientProxy
    {
        public Task SendCoreAsync(string method, object?[] args, CancellationToken cancellationToken = default) =>
            world.Send(targets, method, args);

        public Task<T> InvokeCoreAsync<T>(string method, object?[] args, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class FakeHubClients(HubTestWorld world) : IHubClients
    {
        public IClientProxy All => new Proxy(world, () => world._connections.Keys.ToArray());

        public IClientProxy AllExcept(IReadOnlyList<string> excludedConnectionIds) =>
            new Proxy(world, () => world._connections.Keys.Except(excludedConnectionIds).ToArray());

        public ISingleClientProxy Client(string connectionId) =>
            new Proxy(world, () => world._connections.ContainsKey(connectionId) ? [connectionId] : []);

        IClientProxy IHubClients<IClientProxy>.Client(string connectionId) => Client(connectionId);

        public IClientProxy Clients(IReadOnlyList<string> connectionIds) =>
            new Proxy(world, () => connectionIds.Where(world._connections.ContainsKey).ToArray());

        public IClientProxy Group(string groupName) => new Proxy(world, () => world.InGroup(groupName));

        public IClientProxy GroupExcept(string groupName, IReadOnlyList<string> excludedConnectionIds) =>
            new Proxy(world, () => world.InGroup(groupName).Except(excludedConnectionIds).ToArray());

        public IClientProxy Groups(IReadOnlyList<string> groupNames) =>
            new Proxy(world, () => groupNames.SelectMany(world.InGroup).ToArray());

        public IClientProxy User(string userId) => new Proxy(world, () => world.OfUser(userId));

        public IClientProxy Users(IReadOnlyList<string> userIds) =>
            new Proxy(world, () => userIds.SelectMany(world.OfUser).ToArray());
    }
}

/// <summary>
/// skein-api stand-in for <c>POST /api/v1/hub/project-access</c>, version 2
/// (T014 <c>internal/projects/access_contract.go</c>, ADR-3): a member sees its
/// projects; an internal admin additionally sees every KNOWN project outside
/// other users' personal spaces (no wildcard: an unknown project is denied to
/// the admin too); an external user only its memberships; an inactive user
/// nothing. <c>visibleProjectIds</c> answers every <c>allVisible</c> query, for
/// every actor, the admin included. Counts calls; can be switched to fail or to
/// hold its answers.
/// </summary>
internal sealed class FakeAccessApi : HttpMessageHandler
{
    private readonly object _gate = new();
    private readonly Dictionary<Guid, UserRow> _users = new();

    /// <summary>Every known project, with the owner of its personal space (null — not personal).</summary>
    private readonly Dictionary<Guid, Guid?> _projects = new();
    private readonly TaskCompletionSource _released = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _calls;
    private int _held;

    public int Calls => Volatile.Read(ref _calls);

    /// <summary>
    /// While set, a call that arrives does not answer until <see cref="ReleaseHeld"/>
    /// or until the caller cancels it (the client's call budget) — skein-api
    /// that accepted the request and hangs. Clearing it does not release calls
    /// already held.
    /// </summary>
    public bool HoldCalls { get; set; }

    /// <summary>Calls held right now.</summary>
    public int Held => Volatile.Read(ref _held);

    /// <summary>Lets every held call answer.</summary>
    public void ReleaseHeld() => _released.TrySetResult();

    /// <summary>Number of <c>users</c> entries of every answered call, in order.</summary>
    public List<int> BatchSizes { get; } = [];

    /// <summary>When set, every call answers this status instead of 200.</summary>
    public HttpStatusCode? FailWith { get; set; }

    public void SetUser(Guid userId, bool internalAdmin = false, bool external = false, bool active = true,
        params Guid[] memberOf)
    {
        lock (_gate)
        {
            _users[userId] = new UserRow(active, internalAdmin && !external && active, external, [.. memberOf]);
            foreach (var p in memberOf)
            {
                _projects.TryAdd(p, null);
            }
        }
    }

    /// <summary>Registers a project; <paramref name="personalOwner"/> set — it lies in that user's personal space.</summary>
    public void SetProject(Guid projectId, Guid? personalOwner = null)
    {
        lock (_gate)
        {
            _projects[projectId] = personalOwner;
        }
    }

    /// <summary>Whether <paramref name="row"/> of <paramref name="userId"/> sees <paramref name="projectId"/> (caller holds the gate).</summary>
    private bool Sees(Guid userId, UserRow row, Guid projectId) =>
        row.Active
        && (row.MemberOf.Contains(projectId)
            || (row.InternalAdmin
                && _projects.TryGetValue(projectId, out var owner)
                && (owner is null || owner == userId)));

    public void RemoveMembership(Guid userId, Guid projectId)
    {
        lock (_gate)
        {
            if (_users.TryGetValue(userId, out var row))
            {
                row.MemberOf.Remove(projectId);
            }
        }
    }

    public void SetInternalAdmin(Guid userId, bool internalAdmin)
    {
        lock (_gate)
        {
            if (_users.TryGetValue(userId, out var row))
            {
                _users[userId] = row with { InternalAdmin = internalAdmin && !row.External && row.Active };
            }
        }
    }

    public void Deactivate(Guid userId)
    {
        lock (_gate)
        {
            if (_users.TryGetValue(userId, out var row))
            {
                _users[userId] = row with { Active = false, InternalAdmin = false };
            }
        }
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        Interlocked.Increment(ref _calls);
        if (HoldCalls)
        {
            Interlocked.Increment(ref _held);
            try
            {
                await _released.Task.WaitAsync(ct);
            }
            finally
            {
                Interlocked.Decrement(ref _held);
            }
        }
        if (FailWith is { } status)
        {
            return new HttpResponseMessage(status) { Content = new StringContent("{\"error\":\"x\"}") };
        }
        var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))!;
        var results = new JsonArray();
        lock (_gate)
        {
            BatchSizes.Add(body["users"]!.AsArray().Count);
            foreach (var q in body["users"]!.AsArray())
            {
                var uid = Guid.Parse(q!["userId"]!.GetValue<string>());
                var row = _users.GetValueOrDefault(uid) ?? new UserRow(false, false, false, []);
                var requested = q["projectIds"]?.AsArray().Select(p => Guid.Parse(p!.GetValue<string>())).Distinct().ToArray() ?? [];
                var allowed = requested.Where(p => Sees(uid, row, p)).ToArray();
                var denied = requested.Except(allowed).ToArray();
                var r = new JsonObject
                {
                    ["userId"] = uid.ToString(),
                    ["active"] = row.Active,
                    ["internalAdmin"] = row.InternalAdmin,
                    ["external"] = row.External,
                    ["allowed"] = new JsonArray(allowed.Select(a => (JsonNode)a.ToString()).ToArray()),
                    ["denied"] = new JsonArray(denied.Select(a => (JsonNode)a.ToString()).ToArray()),
                };
                if (q["allVisible"]?.GetValue<bool>() == true)
                {
                    var visible = _projects.Keys.Concat(row.MemberOf).Distinct().Where(p => Sees(uid, row, p)).ToArray();
                    r["visibleProjectIds"] = new JsonArray(visible.Select(a => (JsonNode)a.ToString()).ToArray());
                }
                results.Add(r);
            }
        }
        var json = new JsonObject { ["users"] = results }.ToJsonString();
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        };
    }

    private sealed record UserRow(bool Active, bool InternalAdmin, bool External, HashSet<Guid> MemberOf);
}

/// <summary>
/// The shared session-ticket store as <see cref="ISessionTicketProbe"/> sees it:
/// every ticket key is live and owned by the user who connected with it,
/// unless removed or handed to another user. Counts probes.
/// </summary>
internal sealed class FakeTicketStore : ISessionTicketProbe
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, bool> _removed = new(StringComparer.Ordinal);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, Guid> _owner = new(StringComparer.Ordinal);
    private int _probes;

    /// <summary>Probes answered so far.</summary>
    public int Probes => Volatile.Read(ref _probes);

    /// <summary>Removes a ticket — the session ended.</summary>
    public void Remove(string key) => _removed[key] = true;

    /// <summary>The ticket key now belongs to <paramref name="userId"/> (renewed for another user).</summary>
    public void SetOwner(string key, Guid userId) => _owner[key] = userId;

    public Task<bool> IsSessionOfAsync(string key, Guid userId, CancellationToken ct)
    {
        Interlocked.Increment(ref _probes);
        var ownedByOther = _owner.TryGetValue(key, out var owner) && owner != userId;
        return Task.FromResult(!_removed.ContainsKey(key) && !ownedByOther);
    }
}

/// <summary>
/// One skein-web replica: its own <see cref="ConnectionRegistry"/>,
/// <see cref="DeclarationLimiter"/>, access client and <see cref="NatsBridge"/>
/// over the shared <see cref="HubTestWorld"/>.
/// </summary>
internal sealed class HubTestReplica : IDisposable
{
    private static int _seq;
    private readonly ServiceProvider _services;

    public HubTestReplica(HubTestWorld world, FakeTimeProvider clock, HubDeliveryOptions? options = null,
        INatsConnection? nats = null, PersonalSignalOptions? signalOptions = null)
    {
        World = world;
        Clock = clock;
        Options = options ?? new HubDeliveryOptions();
        Registry = new ConnectionRegistry(clock);
        Limiter = new DeclarationLimiter(clock);

        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.Trace).AddProvider(Logs));
        services.AddSingleton<TimeProvider>(clock);
        services.Configure<SkeinApiOptions>(o =>
        {
            o.Url = "http://skein-api.test/";
            o.InternalSecret = "test-secret";
        });
        services.AddSkeinServiceApiClient("http://skein-api.test/")
            .ConfigurePrimaryHttpMessageHandler(() => world.AccessApi);
        _services = services.BuildServiceProvider();
        Access = _services.GetRequiredService<SkeinServiceApiClient>();

        var hubContext = new Mock<IHubContext<SkeinHub>>();
        hubContext.SetupGet(h => h.Clients).Returns(world.Clients);
        hubContext.SetupGet(h => h.Groups).Returns(world.GroupManager);
        HubContext = hubContext.Object;

        Nats = nats ?? world.Nats.Connect();
        Recheck = new AccessRecheckService(
            Registry, Access, HubContext, Nats, clock, _services.GetRequiredService<ILogger<AccessRecheckService>>(),
            world.Tickets);
        Monitor = new TransportHealthMonitor(
            Nats, Registry, HubContext, Recheck, Backplane, clock,
            _services.GetRequiredService<ILogger<TransportHealthMonitor>>());
        Bridge = new NatsBridge(Nats, HubContext, _services.GetRequiredService<ILogger<NatsBridge>>(), Recheck, Monitor);
        SignalOptions = signalOptions ?? new PersonalSignalOptions();
        Coalescer = new PersonalSignalCoalescer(
            Registry, HubContext, clock, SignalOptions, _services.GetRequiredService<ILogger<PersonalSignalCoalescer>>());
        SignalSubscriber = new PersonalSignalSubscriber(
            Nats, Coalescer, _services.GetRequiredService<ILogger<PersonalSignalSubscriber>>());
        Control = new AccessControlSubscriber(
            Nats, Registry, Recheck, Sessions.Object, HubContext,
            _services.GetRequiredService<ILogger<AccessControlSubscriber>>());
    }

    public TransportHealthMonitor Monitor { get; }

    /// <summary>Where this replica's backplane factory would publish the multiplexer.</summary>
    public BackplaneConnectionSlot Backplane { get; } = new();
    public AccessRecheckService Recheck { get; }
    public AccessControlSubscriber Control { get; }
    public Mock<IUserSessionRevoker> Sessions { get; } = new();

    public INatsConnection Nats { get; }
    public PersonalSignalOptions SignalOptions { get; }
    public PersonalSignalCoalescer Coalescer { get; }
    public PersonalSignalSubscriber SignalSubscriber { get; }
    private readonly List<IHostedService> _started = [];

    /// <summary>
    /// Starts hosted services of this replica on its NATS connection (as the
    /// host does) and waits until they opened <paramref name="subscriptions"/>
    /// NATS subscriptions between them.
    /// </summary>
    public async Task StartAsync(int subscriptions, params IHostedService[] services)
    {
        var before = World.Nats.Subscriptions.Count;
        foreach (var service in services)
        {
            await service.StartAsync(CancellationToken.None);
            _started.Add(service);
        }
        await World.Nats.WaitSubscribedAsync(before + subscriptions);
    }

    public HubTestWorld World { get; }
    public FakeTimeProvider Clock { get; }
    public HubDeliveryOptions Options { get; }
    public ConnectionRegistry Registry { get; }
    public DeclarationLimiter Limiter { get; }
    public SkeinServiceApiClient Access { get; }
    public IHubContext<SkeinHub> HubContext { get; }
    public NatsBridge Bridge { get; }
    public CapturingLoggerProvider Logs { get; } = new();

    public ILogger<T> Logger<T>() => _services.GetRequiredService<ILogger<T>>();

    /// <summary>Opens a connection of <paramref name="userId"/> on this replica and runs OnConnectedAsync.</summary>
    /// <param name="userId">Owner.</param>
    /// <param name="role">Role claim.</param>
    /// <param name="isExternal">External claim.</param>
    /// <param name="sessionKey">Session ticket key claim (<see cref="SessionPrincipal.SessionKeyClaim"/>); null — none.</param>
    public async Task<string> ConnectAsync(Guid userId, string role = "user", bool isExternal = false,
        string? sessionKey = null)
    {
        var connectionId = $"conn-{Interlocked.Increment(ref _seq)}";
        World.AddConnection(connectionId, userId);
        var hub = CreateHub(connectionId, userId, role, isExternal, sessionKey);
        await hub.OnConnectedAsync();
        return connectionId;
    }

    /// <summary>Connections closed from the server side (<c>HubCallerContext.Abort</c>), in order.</summary>
    public List<string> Aborted { get; } = [];

    public async Task DisconnectAsync(string connectionId)
    {
        var state = Registry.Get(connectionId);
        if (state is not null)
        {
            var hub = CreateHub(connectionId, state.UserId, "user", state.IsExternal);
            await hub.OnDisconnectedAsync(null);
        }
        World.RemoveConnection(connectionId);
    }

    public Task<DeclareResult> DeclareAsync(string connectionId, params string[] projectIds) =>
        HubFor(connectionId).DeclareProjects(projectIds);

    public Task<DeclareResult> DeclareAsync(string connectionId, params Guid[] projectIds) =>
        HubFor(connectionId).DeclareProjects(projectIds.Select(p => p.ToString()).ToArray());

    public Task<DeclareResult> DeclareAllVisibleAsync(string connectionId, bool enabled) =>
        HubFor(connectionId).DeclareAllVisible(enabled);

    public Task DispatchAsync(string subject, object body) =>
        Bridge.Dispatch(subject, JsonSerializer.SerializeToUtf8Bytes(body, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
            CancellationToken.None);

    private SkeinHub HubFor(string connectionId)
    {
        var state = Registry.Get(connectionId) ?? throw new InvalidOperationException("unknown connection " + connectionId);
        return CreateHub(connectionId, state.UserId, state.IsInternalAdmin ? "admin" : "user", state.IsExternal);
    }

    private SkeinHub CreateHub(string connectionId, Guid userId, string role, bool isExternal, string? sessionKey = null)
    {
        List<Claim> claims =
        [
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Role, role),
            new Claim("is_external", isExternal ? "true" : "false"),
        ];
        if (sessionKey is not null)
        {
            claims.Add(new Claim(SessionPrincipal.SessionKeyClaim, sessionKey));
        }
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType: "TestCookie"));

        var context = new Mock<HubCallerContext>();
        context.SetupGet(c => c.UserIdentifier).Returns(userId.ToString());
        context.SetupGet(c => c.ConnectionId).Returns(connectionId);
        context.SetupGet(c => c.User).Returns(principal);
        context.SetupGet(c => c.ConnectionAborted).Returns(CancellationToken.None);
        // What SignalR does on a server-side abort: the transport closes and
        // OnDisconnectedAsync forgets the connection and drops its groups.
        // The connection is recorded as aborted only after it is forgotten:
        // a test that waits for the record and then sends a frame must not
        // find the connection still in its groups.
        context.Setup(c => c.Abort()).Callback(() =>
        {
            Registry.Remove(connectionId);
            Limiter.Remove(connectionId);
            World.RemoveConnection(connectionId);
            lock (Aborted)
            {
                Aborted.Add(connectionId);
            }
        });

        return new SkeinHub(Access, Registry, Limiter, Options, Logger<SkeinHub>())
        {
            Context = context.Object,
            Groups = World.GroupManager,
        };
    }

    public void Dispose()
    {
        foreach (var service in _started)
        {
            service.StopAsync(CancellationToken.None).GetAwaiter().GetResult();
        }
        Coalescer.Dispose();
        Recheck.Dispose();
        _services.Dispose();
    }
}

/// <summary>
/// In-process stand-in for the NATS server: connections whose
/// <c>SubscribeAsync&lt;byte[]&gt;</c> yields what the test publishes, with
/// subject wildcards (<c>*</c>, <c>&gt;</c>) and queue-group semantics (one
/// member of a group per message). Records every subscription's subject and
/// queue group. <see cref="DrainAsync"/> waits until every subscriber has
/// finished handling every message delivered to it.
/// </summary>
internal sealed class FakeNats
{
    private readonly object _gate = new();
    private readonly List<Subscription> _subscriptions = [];

    public IReadOnlyList<(string Subject, string? QueueGroup)> Subscriptions
    {
        get
        {
            lock (_gate)
            {
                return _subscriptions.Select(s => (s.Subject, s.QueueGroup)).ToArray();
            }
        }
    }

    /// <summary>Raises <c>ConnectionDisconnected</c> on a connection made by <see cref="Connect"/>.</summary>
    public static void RaiseDisconnected(INatsConnection connection) =>
        Mock.Get(connection).Raise(c => c.ConnectionDisconnected += null, connection, new NatsEventArgs("disconnected"));

    /// <summary>Raises <c>ConnectionOpened</c> on a connection made by <see cref="Connect"/>.</summary>
    public static void RaiseOpened(INatsConnection connection) =>
        Mock.Get(connection).Raise(c => c.ConnectionOpened += null, connection, new NatsEventArgs("opened"));

    public INatsConnection Connect()
    {
        var conn = new Mock<INatsConnection>();
        conn.Setup(c => c.SubscribeAsync<byte[]>(
                It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<INatsDeserialize<byte[]>?>(),
                It.IsAny<NatsSubOpts?>(), It.IsAny<CancellationToken>()))
            .Returns<string, string?, INatsDeserialize<byte[]>?, NatsSubOpts?, CancellationToken>(
                (subject, queueGroup, _, _, ct) => Subscribe(subject, queueGroup, ct));
        return conn.Object;
    }

    public void Publish(string subject, object body) =>
        Publish(subject, JsonSerializer.SerializeToUtf8Bytes(body, new JsonSerializerOptions(JsonSerializerDefaults.Web)));

    public void Publish(string subject, byte[] body)
    {
        lock (_gate)
        {
            var takenGroups = new HashSet<string>(StringComparer.Ordinal);
            foreach (var sub in _subscriptions)
            {
                if (!Matches(sub.Subject, subject))
                {
                    continue;
                }
                if (sub.QueueGroup is { } group && !takenGroups.Add(group))
                {
                    continue;
                }
                sub.Delivered++;
                sub.Channel.Writer.TryWrite(new NatsMsg<byte[]>(subject, null, body.Length, null, body, null));
            }
        }
    }

    /// <summary>Waits until every delivered message has been handled by its subscriber loop.</summary>
    public async Task DrainAsync()
    {
        for (var i = 0; i < 5000; i++)
        {
            lock (_gate)
            {
                if (_subscriptions.All(s => Volatile.Read(ref s.Handled) >= s.Delivered))
                {
                    return;
                }
            }
            await Task.Delay(1);
        }
        throw new TimeoutException("subscribers did not handle the published messages");
    }

    /// <summary>Waits until at least <paramref name="count"/> subscriptions are registered.</summary>
    public async Task WaitSubscribedAsync(int count)
    {
        for (var i = 0; i < 5000; i++)
        {
            lock (_gate)
            {
                if (_subscriptions.Count >= count)
                {
                    return;
                }
            }
            await Task.Delay(1);
        }
        throw new TimeoutException("subscriptions were not registered");
    }

    private async IAsyncEnumerable<NatsMsg<byte[]>> Subscribe(
        string subject, string? queueGroup, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        var sub = new Subscription(subject, queueGroup);
        lock (_gate)
        {
            _subscriptions.Add(sub);
        }
        await foreach (var msg in sub.Channel.Reader.ReadAllAsync(ct))
        {
            yield return msg;
            // The consumer asked for the next message: the previous one is handled.
            Interlocked.Increment(ref sub.Handled);
        }
    }

    private static bool Matches(string pattern, string subject)
    {
        var p = pattern.Split('.');
        var t = subject.Split('.');
        for (var i = 0; i < p.Length; i++)
        {
            if (p[i] == ">")
            {
                return t.Length > i;
            }
            if (i >= t.Length || (p[i] != "*" && p[i] != t[i]))
            {
                return false;
            }
        }
        return p.Length == t.Length;
    }

    private sealed class Subscription(string subject, string? queueGroup)
    {
        public string Subject { get; } = subject;
        public string? QueueGroup { get; } = queueGroup;
        public System.Threading.Channels.Channel<NatsMsg<byte[]>> Channel { get; } =
            System.Threading.Channels.Channel.CreateUnbounded<NatsMsg<byte[]>>();
        public int Delivered;
        public int Handled;
    }
}

/// <summary>Logger provider recording level and formatted message with structured values.</summary>
internal sealed class CapturingLoggerProvider : ILoggerProvider
{
    public System.Collections.Concurrent.ConcurrentQueue<(LogLevel Level, string Line)> Entries { get; } = new();

    public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);

    public void Dispose() { }

    private sealed class Logger(CapturingLoggerProvider owner, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var values = state is IEnumerable<KeyValuePair<string, object?>> kv
                ? string.Join(";", kv.Select(p => $"{p.Key}={p.Value}"))
                : "";
            owner.Entries.Enqueue((logLevel, $"{category} | {formatter(state, exception)} | {values}"));
        }
    }
}
