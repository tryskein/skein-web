using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Caching.StackExchangeRedis;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using SkeinWeb.Auth;
using SkeinWeb.Hubs;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// Regression (fix of T048): when a sign-in happens on a
/// request that already carries another user's session, the cookie handler
/// renews the SAME key with the new user's ticket. Revoking the previous
/// owner's sessions must not delete the new owner's ticket, and revoking the
/// new owner's sessions must.
/// </summary>
public class RedisTicketStoreTest
{
    private static readonly Guid PreviousOwner = Guid.Parse("0199a1b2-0000-7000-8000-000000000001");
    private static readonly Guid NewOwner = Guid.Parse("0199a1b2-0000-7000-8000-000000000002");

    /// <summary>
    /// Redis sets in memory (SADD / SREM / SISMEMBER / SMEMBERS / DEL / EXPIRE),
    /// and EXISTS answered from <paramref name="rows"/> — the ticket rows the
    /// cache keeps in Redis under <paramref name="instanceName"/> + cache key.
    /// </summary>
    private static IConnectionMultiplexer FakeRedisSets(IDistributedCache rows, int failSetReads = 0, string instanceName = "")
    {
        var sets = new Dictionary<string, HashSet<string>>();
        var setReadsFailed = 0;
        var db = new Mock<IDatabase>();
        db.Setup(d => d.SetAddAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync((RedisKey k, RedisValue v, CommandFlags _) =>
            {
                if (!sets.TryGetValue(k.ToString(), out var set))
                {
                    sets[k.ToString()] = set = [];
                }
                return set.Add(v.ToString());
            });
        db.Setup(d => d.SetRemoveAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync((RedisKey k, RedisValue v, CommandFlags _) =>
                sets.TryGetValue(k.ToString(), out var set) && set.Remove(v.ToString()));
        db.Setup(d => d.SetContainsAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync((RedisKey k, RedisValue v, CommandFlags _) =>
                sets.TryGetValue(k.ToString(), out var set) && set.Contains(v.ToString()));
        db.Setup(d => d.SetMembersAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
            .Returns((RedisKey k, CommandFlags _) =>
            {
                if (setReadsFailed < failSetReads)
                {
                    setReadsFailed++;
                    return Task.FromException<RedisValue[]>(new RedisConnectionException(ConnectionFailureType.SocketFailure, "down"));
                }
                return Task.FromResult(
                    sets.TryGetValue(k.ToString(), out var set) ? set.Select(x => (RedisValue)x).ToArray() : Array.Empty<RedisValue>());
            });
        db.Setup(d => d.KeyDeleteAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync((RedisKey k, CommandFlags _) => sets.Remove(k.ToString()));
        db.Setup(d => d.KeyExistsAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync((RedisKey k, CommandFlags _) =>
                k.ToString().StartsWith(instanceName, StringComparison.Ordinal)
                && rows.Get(k.ToString()[instanceName.Length..]) is { Length: > 0 });
        db.Setup(d => d.KeyExpireAsync(It.IsAny<RedisKey>(), It.IsAny<TimeSpan?>(),
                It.IsAny<ExpireWhen>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync(true);

        var mux = new Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(db.Object);
        return mux.Object;
    }

    private static RedisTicketStore Store(ConnectionRegistry? hubConnections = null, int failSetReads = 0,
        IDistributedCache? cache = null, string instanceName = "")
    {
        var rows = cache ?? new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        return new RedisTicketStore(
            rows,
            FakeRedisSets(rows, failSetReads, instanceName),
            hubConnections ?? new ConnectionRegistry(TimeProvider.System),
            Options.Create(new RedisCacheOptions { InstanceName = instanceName == "" ? null : instanceName }),
            NullLogger<RedisTicketStore>.Instance);
    }

    [Theory]
    [InlineData("")]
    [InlineData("skein-web:")]
    public async Task Exists_FindsTheTicketUnderTheCachesRedisKey_WithOrWithoutInstanceName(string instanceName)
    {
        // The probe asks Redis for the key itself (no
        // read, no sliding refresh), so it must spell the key as the cache does.
        var store = Store(instanceName: instanceName);
        var key = await store.StoreAsync(Ticket(PreviousOwner));

        Assert.True(await store.ExistsAsync(key, CancellationToken.None));
        await store.RemoveAsync(key);
        Assert.False(await store.ExistsAsync(key, CancellationToken.None));
    }

    /// <summary>Ticket rows whose delete of <see cref="Poisoned"/> fails while it is set.</summary>
    private sealed class FlakyCache : IDistributedCache
    {
        private readonly MemoryDistributedCache _inner = new(Options.Create(new MemoryDistributedCacheOptions()));

        public string? Poisoned { get; set; }

        public byte[]? Get(string key) => _inner.Get(key);
        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => _inner.GetAsync(key, token);
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => _inner.Set(key, value, options);
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default) =>
            _inner.SetAsync(key, value, options, token);
        public void Refresh(string key) => _inner.Refresh(key);
        public Task RefreshAsync(string key, CancellationToken token = default) => _inner.RefreshAsync(key, token);
        public void Remove(string key) => _inner.Remove(key);
        public Task RemoveAsync(string key, CancellationToken token = default) =>
            key == Poisoned
                ? Task.FromException(new RedisConnectionException(ConnectionFailureType.SocketFailure, "down"))
                : _inner.RemoveAsync(key, token);
    }

    [Fact]
    public async Task Removal_IndexReadFailingTwice_IsRetried_AndCompletes()
    {
        // a transient Redis failure is not reported as "no sessions".
        var store = Store(failSetReads: 2);
        var key = await store.StoreAsync(Ticket(PreviousOwner));

        var result = await store.RemoveSessionsAsync(PreviousOwner, keepKey: null, CancellationToken.None);

        Assert.True(result.Complete);
        Assert.Equal(1, result.Removed);
        Assert.False(await store.ExistsAsync(key, CancellationToken.None));
    }

    [Fact]
    public async Task Removal_IndexUnreadable_IsReportedNotComplete()
    {
        var store = Store(failSetReads: int.MaxValue);
        var key = await store.StoreAsync(Ticket(PreviousOwner));

        var result = await store.RemoveSessionsAsync(PreviousOwner, keepKey: null, CancellationToken.None);

        Assert.False(result.IndexRead);
        Assert.False(result.Complete);
        Assert.True(await store.ExistsAsync(key, CancellationToken.None));
    }

    [Fact]
    public async Task Removal_OneTicketUndeletable_IsReported_AndStaysRevocableLater()
    {
        // the undeleted ticket keeps its place in the user's
        // index, so a later revocation — Redis back — still ends it.
        var cache = new FlakyCache();
        var store = Store(cache: cache);
        var kept = await store.StoreAsync(Ticket(PreviousOwner));
        var stuck = await store.StoreAsync(Ticket(PreviousOwner));
        var gone = await store.StoreAsync(Ticket(PreviousOwner));
        cache.Poisoned = stuck;

        var result = await store.RemoveSessionsAsync(PreviousOwner, kept, CancellationToken.None);

        Assert.Equal(new SessionRemovalResult(Removed: 1, Failed: 1, IndexRead: true), result);
        Assert.False(await store.ExistsAsync(gone, CancellationToken.None));
        Assert.True(await store.IsSessionOfAsync(stuck, PreviousOwner, CancellationToken.None));

        cache.Poisoned = null;
        await store.RemoveSessionsAsync(PreviousOwner, kept, CancellationToken.None);
        Assert.False(await store.ExistsAsync(stuck, CancellationToken.None));
        Assert.True(await store.ExistsAsync(kept, CancellationToken.None));
    }

    private static AuthenticationTicket Ticket(Guid userId) => new(
        new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, userId.ToString())],
            CookieAuthenticationDefaults.AuthenticationScheme)),
        CookieAuthenticationDefaults.AuthenticationScheme);

    [Fact]
    public async Task KeyRenewedForAnotherUser_SurvivesRevocationOfThePreviousOwner()
    {
        var store = Store();
        var key = await store.StoreAsync(Ticket(PreviousOwner));

        // A signup / login of NewOwner in the tab that held PreviousOwner's session.
        await store.RenewAsync(key, Ticket(NewOwner));
        await store.RemoveByUserIdAsync(PreviousOwner, CancellationToken.None);

        var ticket = await store.RetrieveAsync(key);
        Assert.NotNull(ticket);
        Assert.Equal(NewOwner.ToString(), ticket!.Principal.FindFirstValue(ClaimTypes.NameIdentifier));
    }

    [Fact]
    public async Task KeyRenewedForAnotherUser_IsRevokedWithTheNewOwner()
    {
        var store = Store();
        var key = await store.StoreAsync(Ticket(PreviousOwner));

        await store.RenewAsync(key, Ticket(NewOwner));
        await store.RemoveByUserIdAsync(NewOwner, CancellationToken.None);

        Assert.Null(await store.RetrieveAsync(key));
    }

    [Fact]
    public async Task KeyRenewedForTheSameUser_IsStillRevokedWithThatUser()
    {
        // The password-reset re-issue path: same owner, new claims.
        var store = Store();
        var key = await store.StoreAsync(Ticket(PreviousOwner));

        await store.RenewAsync(key, Ticket(PreviousOwner));
        await store.RemoveByUserIdAsync(PreviousOwner, CancellationToken.None);

        Assert.Null(await store.RetrieveAsync(key));
    }

    [Fact]
    public async Task KeyRenewedForAnotherUser_ClosesThePreviousOwnersHubConnection_AndIsNoLongerTheirSession()
    {
        // (INV-26, account boundary): a login of NewOwner in the
        // tab logged in as PreviousOwner renews the same key. The previous
        // owner's hub connection opened with it is closed on this replica at
        // once, and the probe other replicas use no longer calls the key the
        // previous owner's session.
        var hub = new ConnectionRegistry(TimeProvider.System);
        var store = Store(hub);
        var key = await store.StoreAsync(Ticket(PreviousOwner));
        var closed = new List<string>();
        hub.Add(new ConnectionState("conn-prev", PreviousOwner, false, false, key, () => closed.Add("conn-prev")));
        hub.Add(new ConnectionState("conn-new", NewOwner, false, false, key, () => closed.Add("conn-new")));

        Assert.True(await store.IsSessionOfAsync(key, PreviousOwner, CancellationToken.None)); // control
        await store.RenewAsync(key, Ticket(NewOwner));

        Assert.Equal(["conn-prev"], closed);
        Assert.False(await store.IsSessionOfAsync(key, PreviousOwner, CancellationToken.None));
        Assert.True(await store.IsSessionOfAsync(key, NewOwner, CancellationToken.None));
    }

    [Fact]
    public async Task TicketOfAnEarlierRelease_WithoutTheClaim_KnowsItsKeyWhenRead()
    {
        // a ticket stored before this release (no session_key)
        // must not leave its hub connections untied to it.
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var store = Store(cache: cache);
        const string key = "skein:session:legacy";
        await cache.SetAsync(key, TicketSerializer.Default.Serialize(Ticket(PreviousOwner)), new DistributedCacheEntryOptions());

        var read = await store.RetrieveAsync(key);

        Assert.Equal(key, SessionPrincipal.SessionKeyOf(read!.Principal));
        Assert.Equal(PreviousOwner.ToString(), read.Principal.FindFirstValue(ClaimTypes.NameIdentifier));
    }

    [Fact]
    public async Task StoredAndRenewedTicket_KnowsItsOwnKey()
    {
        // INV-26 on the hub (T049): a connection is tied to its session through
        // this claim; without it a revoked session could not be told apart.
        var store = Store();
        var key = await store.StoreAsync(Ticket(PreviousOwner));

        var stored = await store.RetrieveAsync(key);
        Assert.Equal(key, SessionPrincipal.SessionKeyOf(stored!.Principal));

        // Renewed with a principal read back from the store: still exactly one claim.
        await store.RenewAsync(key, stored);
        var renewed = await store.RetrieveAsync(key);
        Assert.Equal(key, Assert.Single(renewed!.Principal.FindAll(SessionPrincipal.SessionKeyClaim)).Value);
    }

    [Fact]
    public async Task RemoveOtherSessions_EndsTheOthers_KeepsTheKeptOne_AndItStaysRevocable()
    {
        // The password reset (K-16, INV-26): every session but the re-issued one ends.
        var store = Store();
        var kept = await store.StoreAsync(Ticket(PreviousOwner));
        var other = await store.StoreAsync(Ticket(PreviousOwner));
        var anotherUsers = await store.StoreAsync(Ticket(NewOwner));

        await store.RemoveSessionsAsync(PreviousOwner, kept, CancellationToken.None);

        Assert.True(await store.ExistsAsync(kept, CancellationToken.None));
        Assert.False(await store.ExistsAsync(other, CancellationToken.None));
        Assert.True(await store.ExistsAsync(anotherUsers, CancellationToken.None));
        // The kept ticket is still in the user's index: a later revocation ends it.
        await store.RemoveByUserIdAsync(PreviousOwner, CancellationToken.None);
        Assert.False(await store.ExistsAsync(kept, CancellationToken.None));
    }
}
