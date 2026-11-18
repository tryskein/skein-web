using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using SkeinWeb.Auth;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// The session store against a real Redis: issue, renewal that never resurrects or re-owns a row,
/// the remembered SSO pair, sliding reads, revocation, mass removal with its index, and the
/// point of no return. Users and keys are unique per test; the rows of a test are removed at its end.
/// </summary>
[Trait("Category", "Integration")]
public sealed class RedisTicketStoreTest : IDisposable
{
    private const string KeyPrefix = "skein:session:";
    private readonly ConnectionMultiplexer _mux = TestRedis.Connect();
    private readonly List<string> _keys = [];
    private readonly List<Guid> _users = [];

    public void Dispose()
    {
        var db = _mux.GetDatabase();
        foreach (var key in _keys)
        {
            db.KeyDelete(key);
        }
        foreach (var user in _users)
        {
            db.KeyDelete("skein:user-tickets:" + user);
        }
        _mux.Dispose();
    }

    private IDatabase Db => _mux.GetDatabase();

    private Guid NewUser()
    {
        var user = Guid.NewGuid();
        _users.Add(user);
        return user;
    }

    private static string IndexOf(Guid user) => "skein:user-tickets:" + user;

    private async Task<string> IssueAsync(RedisTicketStore store, AuthenticationTicket ticket)
    {
        var key = await store.StoreAsync(ticket, new DefaultHttpContext(), CancellationToken.None);
        _keys.Add(key);
        return key;
    }

    private RedisTicketStore Store() => TestRedis.Store(_mux);

    private static async Task<RenewOutcome?> RenewAsync(
        RedisTicketStore store, string key, AuthenticationTicket ticket, DefaultHttpContext? ctx = null, bool explicitRenewal = false)
    {
        ctx ??= new DefaultHttpContext();
        SessionRequestState.Of(ctx).ExplicitRenewal = explicitRenewal;
        await store.RenewAsync(key, ticket, ctx, CancellationToken.None);
        return SessionRequestState.Of(ctx).RenewOutcome;
    }

    // ---- R17 ----------------------------------------------------------------------------------

    [RedisFact]
    public async Task Store_IssuesRandomKeysOfTheDocumentedShape_AsStringsWithTtl_AndIndexesThem()
    {
        var store = Store();
        var user = NewUser();
        var keys = new List<string>();
        for (var i = 0; i < 10; i++)
        {
            keys.Add(await IssueAsync(store, TestRedis.Ticket(user)));
        }

        Assert.Equal(10, keys.Distinct().Count());
        foreach (var key in keys)
        {
            Assert.StartsWith(KeyPrefix, key);
            Assert.Equal(KeyPrefix.Length + 43, key.Length);
            Assert.Equal(RedisType.String, await Db.KeyTypeAsync(key));
            var ttl = await Db.KeyTimeToLiveAsync(key);
            Assert.InRange(ttl!.Value, TimeSpan.FromHours(23), TimeSpan.FromHours(24));
            Assert.True(await Db.SetContainsAsync(IndexOf(user), key));
        }
        Assert.InRange((await Db.KeyTimeToLiveAsync(IndexOf(user)))!.Value, TimeSpan.FromHours(23), TimeSpan.FromHours(24));
    }

    [RedisFact]
    public async Task IssueReadRenewRead_KeepsExactlyOneClaimOfTheKey()
    {
        var store = Store();
        var user = NewUser();
        var key = await IssueAsync(store, TestRedis.Ticket(user));

        var read = await store.RetrieveAsync(key, new DefaultHttpContext(), CancellationToken.None);
        Assert.Equal(key, SessionPrincipal.SessionKeyOf(read!.Principal));
        Assert.Equal(RenewOutcome.Written, await RenewAsync(store, key, read));
        var again = await store.RetrieveAsync(key, new DefaultHttpContext(), CancellationToken.None);

        Assert.Equal(key, Assert.Single(again!.Principal.FindAll(SessionPrincipal.SessionKeyClaim)).Value);
    }

    // ---- R18 ----------------------------------------------------------------------------------

    [RedisFact]
    public async Task Renew_OfAnAbsentKey_IsKeyAbsent_AndCreatesNothing()
    {
        var store = Store();
        var key = KeyPrefix + "absent-" + Guid.NewGuid().ToString("N");
        _keys.Add(key);

        var outcome = await RenewAsync(store, key, TestRedis.Ticket(NewUser()));

        Assert.Equal(RenewOutcome.KeyAbsent, outcome);
        Assert.False(await Db.KeyExistsAsync(key));
    }

    [RedisFact]
    public async Task Renew_ForAnotherOwner_IsOwnerMismatch_AndChangesNeitherRowNorIndex()
    {
        var store = Store();
        var owner = NewUser();
        var stranger = NewUser();
        var key = await IssueAsync(store, TestRedis.Ticket(owner));
        byte[] before = (await Db.StringGetAsync(key))!;

        var outcome = await RenewAsync(store, key, TestRedis.Ticket(stranger));

        Assert.Equal(RenewOutcome.OwnerMismatch, outcome);
        Assert.Equal(before, (byte[])(await Db.StringGetAsync(key))!);
        Assert.True(await Db.SetContainsAsync(IndexOf(owner), key));
        Assert.False(await Db.KeyExistsAsync(IndexOf(stranger)));
    }

    [RedisFact]
    public async Task Renew_ForTheSameOwner_IsWritten_AndMovesBothTimeToLives()
    {
        var store = Store();
        var owner = NewUser();
        var key = await IssueAsync(store, TestRedis.Ticket(owner));
        await Db.KeyExpireAsync(key, TimeSpan.FromMinutes(1));
        await Db.KeyExpireAsync(IndexOf(owner), TimeSpan.FromMinutes(1));

        var outcome = await RenewAsync(store, key, TestRedis.Ticket(owner));

        Assert.Equal(RenewOutcome.Written, outcome);
        Assert.True((await Db.KeyTimeToLiveAsync(key))!.Value > TimeSpan.FromHours(23));
        Assert.True((await Db.KeyTimeToLiveAsync(IndexOf(owner)))!.Value > TimeSpan.FromHours(23));
    }

    // ---- R19 ----------------------------------------------------------------------------------

    private async Task<AuthenticationTicket> StoredAsync(RedisTicketStore store, string key) =>
        (await store.RetrieveAsync(key, new DefaultHttpContext(), CancellationToken.None))!;

    [RedisFact]
    public async Task Pair_ConfirmedByTheMarker_SurvivesALaterOrdinaryRenewal_AndTheMarkerIsNotStored()
    {
        var store = Store();
        var owner = NewUser();
        var key = await IssueAsync(store, TestRedis.Ticket(owner, "old@example.com", "old"));
        var staleClone = await StoredAsync(store, key); // an in-flight request that read the old pair

        var confirm = TestRedis.Ticket(owner, "new@example.com", "new");
        confirm.Properties.Items[RedisTicketStore.SsoPairWriteMarker] = "1";
        Assert.Equal(RenewOutcome.Written, await RenewAsync(store, key, confirm, explicitRenewal: true));
        Assert.Equal(RenewOutcome.Written, await RenewAsync(store, key, staleClone));

        var stored = await StoredAsync(store, key);
        Assert.Equal("new@example.com", stored.Properties.Items[RedisTicketStore.SsoEmailItem]);
        Assert.Equal("new", stored.Properties.Items[RedisTicketStore.SsoUserItem]);
        Assert.DoesNotContain(RedisTicketStore.SsoPairWriteMarker, stored.Properties.Items.Keys);
    }

    [RedisFact]
    public async Task ClaimWrittenByAParallelExplicitRenewal_IsNotRolledBackByALateAutomaticOne()
    {
        var store = Store();
        var owner = NewUser();
        var key = await IssueAsync(store, TestRedis.Ticket(owner, "p@example.com", "p", new Claim(ClaimTypes.Role, "user")));
        var staleClone = await StoredAsync(store, key); // the automatic renewal of a request that read the old claims

        var confirmed = TestRedis.Ticket(owner, extra: new Claim(ClaimTypes.Role, "admin"));
        Assert.Equal(RenewOutcome.Written, await RenewAsync(store, key, confirmed, explicitRenewal: true));
        staleClone.Properties.IssuedUtc = DateTimeOffset.UtcNow.AddHours(6);
        staleClone.Properties.ExpiresUtc = DateTimeOffset.UtcNow.AddHours(30);
        Assert.Equal(RenewOutcome.Written, await RenewAsync(store, key, staleClone));

        var stored = await StoredAsync(store, key);
        Assert.Equal("admin", stored.Principal.FindFirstValue(ClaimTypes.Role)); // the confirmed claim stays
        Assert.Equal("p@example.com", stored.Properties.Items[RedisTicketStore.SsoEmailItem]);
        Assert.True(stored.Properties.ExpiresUtc >= staleClone.Properties.ExpiresUtc); // while the expiry moved forward
    }

    [RedisFact]
    public async Task SuccessiveAutomaticRenewals_KeepTheWindowAt24Hours_AndNeverMoveTheExpiryBack()
    {
        var store = Store();
        var owner = NewUser();
        var key = await IssueAsync(store, TestRedis.Ticket(owner));
        var t0 = DateTimeOffset.UtcNow;
        var window = TimeSpan.FromHours(24);

        async Task<AuthenticationTicket> RenewAtAsync(TimeSpan after)
        {
            // What the cookie handler's sliding renewal hands over: a window of its own length starting now.
            var incoming = TestRedis.Ticket(owner);
            incoming.Properties.IssuedUtc = t0 + after;
            incoming.Properties.ExpiresUtc = t0 + after + window;
            Assert.Equal(RenewOutcome.Written, await RenewAsync(store, key, incoming));
            return await StoredAsync(store, key);
        }

        foreach (var after in new[] { TimeSpan.FromHours(13), TimeSpan.FromHours(26) })
        {
            var stored = await RenewAtAsync(after);
            Assert.Equal(window, stored.Properties.ExpiresUtc - stored.Properties.IssuedUtc);
            Assert.Equal(t0 + after + window, stored.Properties.ExpiresUtc);
        }

        var late = await RenewAtAsync(TimeSpan.FromHours(1)); // an older request arrives last
        Assert.Equal(window, late.Properties.ExpiresUtc - late.Properties.IssuedUtc);
        Assert.Equal(t0 + TimeSpan.FromHours(26) + window, late.Properties.ExpiresUtc); // the later window wins
    }

    [RedisFact]
    public async Task ClaimUpdate_DoesNotEraseThePair_NorReplaceItWithAProfile()
    {
        var store = Store();
        var owner = NewUser();
        var key = await IssueAsync(store, TestRedis.Ticket(owner, "proxy@example.com", "proxy-user"));

        var update = TestRedis.Ticket(owner, extra: new Claim(ClaimTypes.Role, "admin"));
        Assert.Equal(RenewOutcome.Written, await RenewAsync(store, key, update, explicitRenewal: true));

        var stored = await StoredAsync(store, key);
        Assert.Equal("proxy@example.com", stored.Properties.Items[RedisTicketStore.SsoEmailItem]);
        Assert.Equal("proxy-user", stored.Properties.Items[RedisTicketStore.SsoUserItem]);
        Assert.Equal("admin", stored.Principal.FindFirstValue(ClaimTypes.Role));
    }

    [RedisFact]
    public async Task ThreeLostCompareAndSets_AreCasExhausted_NotKeyAbsent()
    {
        var owner = NewUser();
        var real = Store();
        var key = await IssueAsync(real, TestRedis.Ticket(owner));
        var db = DbProxy.Create(Db, out var proxy);
        var writes = 0;
        proxy.After = async (name, args) =>
        {
            if (name == nameof(IDatabase.StringGetAsync) && (RedisKey)args[0]! == key)
            {
                // A different value every time, so no read ever matches the next write's expectation.
                var rival = TicketSerializer.Default.Serialize(
                    TestRedis.Ticket(owner, extra: new Claim("rival", (++writes).ToString())));
                await Db.StringSetAsync(key, rival, TimeSpan.FromHours(1));
            }
        };

        var outcome = await RenewAsync(TestRedis.Store(TestRedis.Over(_mux, db)), key, TestRedis.Ticket(owner));

        Assert.Equal(RenewOutcome.CasExhausted, outcome);
        Assert.True(await Db.KeyExistsAsync(key));
    }

    // ---- R20 ----------------------------------------------------------------------------------

    [RedisFact]
    public async Task Retrieve_SlidesTheLifetime()
    {
        var store = Store();
        var key = await IssueAsync(store, TestRedis.Ticket(NewUser()));
        await Db.KeyExpireAsync(key, TimeSpan.FromMinutes(1));

        Assert.NotNull(await store.RetrieveAsync(key, new DefaultHttpContext(), CancellationToken.None));

        Assert.True((await Db.KeyTimeToLiveAsync(key))!.Value > TimeSpan.FromHours(23));
    }

    [RedisFact]
    public async Task Retrieve_OfAHashOfTheFormerFormat_IsNoSession_AndTheRowIsUntouched()
    {
        var store = Store();
        var key = KeyPrefix + "legacy-" + Guid.NewGuid().ToString("N");
        _keys.Add(key);
        await Db.HashSetAsync(key, [new HashEntry("absexp", -1), new HashEntry("sldexp", 86400), new HashEntry("data", new byte[] { 1, 2, 3 })]);

        Assert.Null(await store.RetrieveAsync(key, new DefaultHttpContext(), CancellationToken.None));
        Assert.Equal(3, await Db.HashLengthAsync(key));
    }

    [RedisFact]
    public async Task Retrieve_OfGarbageBytes_IsNoSession_AndTheRowIsUntouched()
    {
        var store = Store();
        var key = KeyPrefix + "garbage-" + Guid.NewGuid().ToString("N");
        _keys.Add(key);
        await Db.StringSetAsync(key, new byte[] { 0xFF, 0x00, 0x13, 0x37 });

        Assert.Null(await store.RetrieveAsync(key, new DefaultHttpContext(), CancellationToken.None));
        Assert.Equal(new byte[] { 0xFF, 0x00, 0x13, 0x37 }, (byte[])(await Db.StringGetAsync(key))!);
    }

    // ---- R21 ----------------------------------------------------------------------------------

    [RedisFact]
    public async Task Revoke_ReportsWhetherARowWasThere_AndAnAbsentKeyIsASuccess()
    {
        var store = Store();
        var owner = NewUser();
        var key = await IssueAsync(store, TestRedis.Ticket(owner));

        Assert.True(await store.RevokeAsync(key, new DefaultHttpContext(), CancellationToken.None));
        Assert.False(await store.RevokeAsync(key, new DefaultHttpContext(), CancellationToken.None));

        Assert.False(await Db.KeyExistsAsync(key));
        Assert.False(await Db.SetContainsAsync(IndexOf(owner), key));
    }

    [RedisFact]
    public async Task RemoveAfterARevocationOfTheSameKey_DoesNotCallRedis()
    {
        var owner = NewUser();
        var key = await IssueAsync(Store(), TestRedis.Ticket(owner));
        var db = DbProxy.Create(Db, out var proxy);
        var store = TestRedis.Store(TestRedis.Over(_mux, db));
        var ctx = new DefaultHttpContext();

        await store.RevokeAsync(key, ctx, CancellationToken.None);
        proxy.Before = (name, _) => new InvalidOperationException("Redis was called: " + name);
        await store.RemoveAsync(key, ctx, CancellationToken.None);

        Assert.Contains(key, SessionRequestState.Of(ctx).RemovedKeys);
    }

    // ---- R22 ----------------------------------------------------------------------------------

    [RedisFact]
    public async Task MassRemoval_FindsASessionOlderThanTheFirstIndexLifetime()
    {
        var store = Store();
        var owner = NewUser();
        var key = await IssueAsync(store, TestRedis.Ticket(owner));
        await Db.KeyExpireAsync(IndexOf(owner), TimeSpan.FromMinutes(1));
        await RenewAsync(store, key, TestRedis.Ticket(owner)); // the renewal lifts the index again

        var result = await store.RemoveSessionsAsync(owner, keepKey: null, CancellationToken.None);

        Assert.True(result.Complete);
        Assert.False(await Db.KeyExistsAsync(key));
    }

    [RedisFact]
    public async Task MassRemoval_KeepsAMemberAddedMeanwhile_AndDropsOnlyTheProcessedOnes()
    {
        var owner = NewUser();
        var key = await IssueAsync(Store(), TestRedis.Ticket(owner));
        var late = KeyPrefix + "late-" + Guid.NewGuid().ToString("N");
        var db = DbProxy.Create(Db, out var proxy);
        proxy.After = async (name, _) =>
        {
            if (name == nameof(IDatabase.SetMembersAsync))
            {
                await Db.SetAddAsync(IndexOf(owner), late);
            }
        };

        var result = await TestRedis.Store(TestRedis.Over(_mux, db)).RemoveSessionsAsync(owner, keepKey: null, CancellationToken.None);

        Assert.Equal(1, result.Removed);
        Assert.False(await Db.SetContainsAsync(IndexOf(owner), key));
        Assert.True(await Db.SetContainsAsync(IndexOf(owner), late));
    }

    [RedisFact]
    public async Task Probes_AreTrueForALiveSession_FalseOtherwise_AndDoNotSlide()
    {
        var store = Store();
        var owner = NewUser();
        var stranger = NewUser();
        var live = await IssueAsync(store, TestRedis.Ticket(owner));
        var gone = await IssueAsync(store, TestRedis.Ticket(owner));
        await store.RevokeAsync(gone, new DefaultHttpContext(), CancellationToken.None);
        await Db.KeyExpireAsync(live, TimeSpan.FromMinutes(1));

        Assert.True(await store.ExistsAsync(live, CancellationToken.None));
        Assert.False(await store.ExistsAsync(gone, CancellationToken.None));
        Assert.True(await store.IsSessionOfAsync(live, owner, CancellationToken.None));
        Assert.False(await store.IsSessionOfAsync(live, stranger, CancellationToken.None));
        Assert.False(await store.IsSessionOfAsync(gone, owner, CancellationToken.None));
        Assert.True((await Db.KeyTimeToLiveAsync(live))!.Value <= TimeSpan.FromMinutes(1));
    }

    [RedisFact]
    public async Task RemoveOtherSessions_EndsTheOthers_KeepsTheKeptOne_AndItStaysRevocable()
    {
        var store = Store();
        var owner = NewUser();
        var kept = await IssueAsync(store, TestRedis.Ticket(owner));
        var other = await IssueAsync(store, TestRedis.Ticket(owner));
        var stranger = await IssueAsync(store, TestRedis.Ticket(NewUser()));

        await store.RemoveSessionsAsync(owner, kept, CancellationToken.None);

        Assert.True(await store.ExistsAsync(kept, CancellationToken.None));
        Assert.False(await store.ExistsAsync(other, CancellationToken.None));
        Assert.True(await store.ExistsAsync(stranger, CancellationToken.None));
        await store.RemoveByUserIdAsync(owner, CancellationToken.None);
        Assert.False(await store.ExistsAsync(kept, CancellationToken.None));
    }

    // ---- R23 ----------------------------------------------------------------------------------

    [RedisFact]
    public async Task Store_WithNoCancellation_CompletesDespiteACancelledRequest()
    {
        var store = Store();
        var ctx = new DefaultHttpContext();
        SessionRequestState.Of(ctx).NoCancellation = true;
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        var key = await store.StoreAsync(TestRedis.Ticket(NewUser()), ctx, cancelled.Token);
        _keys.Add(key);

        Assert.True(await Db.KeyExistsAsync(key));
    }

    [RedisFact]
    public async Task Store_WithoutTheFlag_ObservesTheCancellation()
    {
        var store = Store();
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => store.StoreAsync(TestRedis.Ticket(NewUser()), new DefaultHttpContext(), cancelled.Token));
    }
}
