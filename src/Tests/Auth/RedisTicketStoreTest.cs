using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using SkeinWeb.Auth;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// The session store against a real Redis: issue, renewal that never resurrects or re-owns a row and
/// never changes the window of the sign-in, the remembered SSO pair, the end-of-session check and the
/// row lifetime on every read, the reverse index kept alive with its rows, revocation, mass removal and
/// the point of no return. Users and keys are unique per test; the rows of a test are removed at its end.
/// <para>Two points of observation: the store's own clock (a <see cref="FakeTimeProvider"/>) decides
/// the end of a session; the row lifetime is observed as the PTTL Redis reports after the write.</para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class RedisTicketStoreTest : IDisposable
{
    private const string KeyPrefix = "skein:session:";

    private static readonly SessionTimeouts Defaults = new(120, 720);

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
            db.KeyDelete(IndexOf(user));
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

    private string NewKey(string kind)
    {
        var key = KeyPrefix + kind + "-" + Guid.NewGuid().ToString("N");
        _keys.Add(key);
        return key;
    }

    private static string IndexOf(Guid user) => "skein:user-tickets:" + user;

    // The ticket properties keep whole seconds; a clock on a whole second keeps the arithmetic exact.
    private static DateTimeOffset WholeSecond(DateTimeOffset t) => new(t.Ticks - t.Ticks % TimeSpan.TicksPerSecond, TimeSpan.Zero);

    private static FakeTimeProvider ClockAt(DateTimeOffset at) => new(at);

    private async Task<string> IssueAsync(RedisTicketStore store, AuthenticationTicket ticket)
    {
        var key = await store.StoreAsync(ticket, new DefaultHttpContext(), CancellationToken.None);
        _keys.Add(key);
        return key;
    }

    private RedisTicketStore Store(SessionTimeouts? timeouts = null, TimeProvider? time = null) =>
        TestRedis.Store(_mux, timeouts, time);

    private RedisTicketStore StoreOver(IDatabase db, SessionTimeouts? timeouts = null, TimeProvider? time = null, ILogger<RedisTicketStore>? logger = null) =>
        new(TestRedis.Over(_mux, db), timeouts ?? Defaults, time ?? TimeProvider.System,
            logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<RedisTicketStore>.Instance);

    /// <summary>A ticket of <paramref name="user"/> with the window of a sign-in at <paramref name="signIn"/> under <paramref name="timeouts"/>.</summary>
    private static AuthenticationTicket SignedInAt(Guid user, DateTimeOffset signIn, SessionTimeouts? timeouts = null)
    {
        var ticket = TestRedis.Ticket(user);
        TestRedis.WithWindow(ticket.Properties, signIn, timeouts ?? Defaults);
        return ticket;
    }

    /// <summary>The explicit SSO renewal, the only renewal path of the store.</summary>
    private static async Task<RenewOutcome?> RenewAsync(RedisTicketStore store, string key, AuthenticationTicket ticket)
    {
        var ctx = new DefaultHttpContext();
        await store.RenewAsync(key, ticket, ctx, CancellationToken.None);
        return SessionRequestState.Of(ctx).RenewOutcome;
    }

    private static Task<AuthenticationTicket?> ReadAsync(RedisTicketStore store, string key) =>
        store.RetrieveAsync(key, new DefaultHttpContext(), CancellationToken.None);

    private async Task<AuthenticationTicket> StoredAsync(string key) =>
        TicketSerializer.Default.Deserialize((byte[])(await Db.StringGetAsync(key))!)!;

    /// <summary>PTTL in milliseconds as Redis reports it: -2 = no key, -1 = no lifetime.</summary>
    private async Task<long> PttlAsync(string key) => (long)await Db.ExecuteAsync("PTTL", key);

    private static void AssertNear(TimeSpan expected, long pttlMs) =>
        Assert.InRange(pttlMs, (long)(expected - TimeSpan.FromSeconds(10)).TotalMilliseconds, (long)expected.TotalMilliseconds);

    /// <summary>A key that exists, to seed an index member the prune at sign-in keeps.</summary>
    private async Task<string> LiveMemberAsync()
    {
        var key = NewKey("member");
        await Db.StringSetAsync(key, "x", TimeSpan.FromHours(1));
        return key;
    }

    private async Task SeedAsync(string key, AuthenticationTicket ticket, TimeSpan lifetime) =>
        await Db.StringSetAsync(key, TicketSerializer.Default.Serialize(ticket), lifetime);

    // ---- Issue (rows 20, 83) ------------------------------------------------------------------

    public static TheoryData<int, int, int> IssueLifetimes() => new()
    {
        // idle, absolute → hours of the row: min(idle, absolute)
        { 7, 11, 7 },
        { 30, 11, 11 },
    };

    [RedisTheory]
    [MemberData(nameof(IssueLifetimes))]
    public async Task Store_IssuesRandomKeysOfTheDocumentedShape_AsStringsWithTtl_AndIndexesThem(int idle, int absolute, int expectedHours)
    {
        var timeouts = new SessionTimeouts(idle, absolute);
        var db = DbProxy.Create(Db, out var proxy);
        var issueKeys = new List<RedisKey[]>();
        proxy.Before = (name, args) =>
        {
            if (DbProxy.IsScript(name, args, StoreScripts.Issue))
            {
                lock (issueKeys)
                {
                    issueKeys.Add(DbProxy.KeysOf(name, args));
                }
            }
            return null;
        };
        var store = StoreOver(db, timeouts);
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
            AssertNear(TimeSpan.FromHours(expectedHours), await PttlAsync(key));
            Assert.True(await Db.SetContainsAsync(IndexOf(user), key));
            // The row and the index are both KEYS of the one issue script.
            Assert.Contains(issueKeys, k => k.Contains((RedisKey)key) && k.Contains(IndexOf(user)));
        }
        var lastRow = await PttlAsync(keys[^1]);
        var index = await PttlAsync(IndexOf(user));
        Assert.InRange(index - lastRow, -1000, 1000); // the index carries the actual lifetime of the row
    }

    // The window is given as hours from the moment the test runs (null: the
    // bound is absent), not as timestamps: a timestamp taken when the data is
    // built ends up in the test case's display name, and a runner that
    // discovers the cases and runs them in different seconds (Stryker.NET on
    // VSTest) then cannot match the results to the discovered cases.
    public static TheoryData<string, int?, int?> InvalidWindows() => new()
    {
        { "no issue time", null, 1 },
        { "no expiry time", 0, null },
        { "issued equals expiry", 0, 0 },
        { "issued after expiry", 1, 0 },
    };

    private static DateTimeOffset? HoursFromNow(DateTimeOffset now, int? hours) =>
        hours is { } h ? now.AddHours(h) : null;

    [RedisTheory]
    [MemberData(nameof(InvalidWindows))]
    public async Task Store_OfATicketWithoutAValidWindow_IsAnError_AndWritesNothing(string _, int? issuedHours, int? expiresHours)
    {
        var now = WholeSecond(DateTimeOffset.UtcNow);
        var issued = HoursFromNow(now, issuedHours);
        var expires = HoursFromNow(now, expiresHours);
        var user = NewUser();
        var db = DbProxy.Create(Db, out var proxy);
        var calls = new List<string>();
        proxy.Before = (name, args) =>
        {
            lock (calls)
            {
                calls.Add(name);
            }
            return null;
        };
        var ticket = TestRedis.Ticket(user);
        ticket.Properties.IssuedUtc = issued;
        ticket.Properties.ExpiresUtc = expires;

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => StoreOver(db).StoreAsync(ticket, new DefaultHttpContext(), CancellationToken.None));

        Assert.Empty(calls); // no row, no index member: Redis was not called at all
        Assert.False(await Db.KeyExistsAsync(IndexOf(user)));
    }

    // ---- Read: lifetime, end of session, window (rows 21, 22, 23, 25, 26, 82) -----------------

    [RedisFact]
    public async Task Retrieve_WritesTheRowLifetime_TheIdleLimitOrTheTimeLeft_AndKeepsTheBytes()
    {
        var now = WholeSecond(DateTimeOffset.UtcNow);
        var store = Store(Defaults, ClockAt(now));
        var user = NewUser();

        // Plenty left: the idle limit.
        var fresh = await IssueAsync(store, SignedInAt(user, now));
        await Db.KeyExpireAsync(fresh, TimeSpan.FromMinutes(1));
        var freshBytes = (byte[])(await Db.StringGetAsync(fresh))!;
        Assert.NotNull(await ReadAsync(store, fresh));
        AssertNear(TimeSpan.FromHours(120), await PttlAsync(fresh));
        Assert.Equal(freshBytes, (byte[])(await Db.StringGetAsync(fresh))!);

        // Five hours left, less than the idle limit: the time left, never more.
        var old = await IssueAsync(store, SignedInAt(user, now.AddHours(-715)));
        await Db.KeyExpireAsync(old, TimeSpan.FromMinutes(1));
        var oldBytes = (byte[])(await Db.StringGetAsync(old))!;
        Assert.NotNull(await ReadAsync(store, old));
        AssertNear(TimeSpan.FromHours(5), await PttlAsync(old));
        Assert.Equal(oldBytes, (byte[])(await Db.StringGetAsync(old))!);
    }

    public static TheoryData<int> AbsoluteLimitsOfTheReader() => new()
    {
        720, // the limit of the sign-in
        24, // a second store over the same Redis with the absolute limit lowered
    };

    [RedisTheory]
    [MemberData(nameof(AbsoluteLimitsOfTheReader))]
    public async Task Retrieve_AroundTheEndOfTheSession_IsATicketBefore_AndNoSessionFromTheEndOn(int readerAbsoluteHours)
    {
        var signIn = WholeSecond(DateTimeOffset.UtcNow);
        var issuer = Store(Defaults, ClockAt(signIn));
        var readerClock = ClockAt(signIn);
        var reader = Store(new SessionTimeouts(120, readerAbsoluteHours), readerClock);
        var end = signIn.AddHours(readerAbsoluteHours);
        var user = NewUser();

        var before = await IssueAsync(issuer, SignedInAt(user, signIn));
        readerClock.SetUtcNow(end.AddSeconds(-1));
        Assert.NotNull(await ReadAsync(reader, before));
        Assert.InRange(await PttlAsync(before), 1, 1000);

        foreach (var at in new[] { end - TimeSpan.FromTicks(5_000), end, end.AddSeconds(1) })
        {
            var key = await IssueAsync(issuer, SignedInAt(user, signIn));
            readerClock.SetUtcNow(at);

            Assert.Null(await ReadAsync(reader, key));
            Assert.False(await Db.KeyExistsAsync(key)); // deleted, no lifetime written
        }
    }

    public static TheoryData<string, int?, int?> StoredInvalidWindows() => InvalidWindows();

    [RedisTheory]
    [MemberData(nameof(StoredInvalidWindows))]
    public async Task Retrieve_OfARowWithoutAValidWindow_IsNoSession_AndTheRowIsDeleted(string _, int? issuedHours, int? expiresHours)
    {
        var now = WholeSecond(DateTimeOffset.UtcNow);
        var issued = HoursFromNow(now, issuedHours);
        var expires = HoursFromNow(now, expiresHours);
        var key = NewKey("window");
        var ticket = TestRedis.Ticket(NewUser());
        ticket.Properties.IssuedUtc = issued;
        ticket.Properties.ExpiresUtc = expires;
        await SeedAsync(key, ticket, TimeSpan.FromHours(1));

        Assert.Null(await ReadAsync(Store(), key));
        Assert.False(await Db.KeyExistsAsync(key));
    }

    [RedisFact]
    public async Task Retrieve_OfGarbageBytes_IsNoSession_AndTheRowIsDeleted()
    {
        var key = NewKey("garbage");
        await Db.StringSetAsync(key, new byte[] { 0xFF, 0x00, 0x13, 0x37 });

        Assert.Null(await ReadAsync(Store(), key));
        Assert.False(await Db.KeyExistsAsync(key));
    }

    [RedisFact]
    public async Task Retrieve_OfAnEmptyRow_IsNoSession_AndTheRowIsDeleted()
    {
        var key = NewKey("empty");
        await Db.StringSetAsync(key, Array.Empty<byte>(), TimeSpan.FromHours(1));
        Assert.True(await Db.KeyExistsAsync(key)); // control: the empty value is stored

        Assert.Null(await ReadAsync(Store(), key));
        Assert.False(await Db.KeyExistsAsync(key));
    }

    [RedisFact]
    public async Task Retrieve_OfARowGoneBeforeItsLifetimeIsWritten_IsNoSession_AndRecreatesNothing()
    {
        var user = NewUser();
        var key = await IssueAsync(Store(), TestRedis.Ticket(user));
        await Db.SetRemoveAsync(IndexOf(user), key);
        var db = DbProxy.Create(Db, out var proxy);
        proxy.After = async (name, args) =>
        {
            if (name == nameof(IDatabase.StringGetAsync) && (RedisKey)args[0]! == key)
            {
                await Db.KeyDeleteAsync(key); // gone between the read and the lifetime write
            }
        };

        Assert.Null(await ReadAsync(StoreOver(db), key));
        Assert.False(await Db.KeyExistsAsync(key));
        Assert.False(await Db.SetContainsAsync(IndexOf(user), key));
    }

    [RedisFact]
    public async Task Retrieve_OfAHashOfTheFormerFormat_IsNoSession_AndTheRowIsUntouched()
    {
        var key = NewKey("legacy");
        await Db.HashSetAsync(key, [new HashEntry("absexp", -1), new HashEntry("sldexp", 86400), new HashEntry("data", new byte[] { 1, 2, 3 })]);

        Assert.Null(await ReadAsync(Store(), key));
        Assert.Equal(3, await Db.HashLengthAsync(key));
    }

    // ---- Changed limits: a new process with new settings over the same Redis (row 26) --------

    [RedisFact]
    public async Task IdleLimitLowered_ARequestAfterALongerPause_IsAdmitted_WhileTheRowLives_AndGetsTheNewLimit()
    {
        var signIn = WholeSecond(DateTimeOffset.UtcNow);
        var key = await IssueAsync(Store(Defaults, ClockAt(signIn)), SignedInAt(NewUser(), signIn));
        var lowered = Store(new SessionTimeouts(24, 720), ClockAt(signIn.AddHours(48)));

        Assert.NotNull(await ReadAsync(lowered, key)); // the row of the former process is still alive
        AssertNear(TimeSpan.FromHours(24), await PttlAsync(key));
    }

    [RedisFact]
    public async Task AbsoluteLimitRaised_TheSessionEndsAtTheWrittenWindow_AndTheRowLifetimeIsNotRewritten()
    {
        var signIn = WholeSecond(DateTimeOffset.UtcNow);
        var user = NewUser();
        var alive = await IssueAsync(Store(Defaults, ClockAt(signIn)), SignedInAt(user, signIn));
        var written = await PttlAsync(alive);
        var raisedClock = ClockAt(signIn);
        var raised = Store(new SessionTimeouts(120, 1000), raisedClock);

        Assert.InRange(await PttlAsync(alive), written - 5000, written); // a new limit by itself writes nothing
        raisedClock.SetUtcNow(signIn.AddHours(720).AddSeconds(-1));
        Assert.NotNull(await ReadAsync(raised, alive));

        var ended = await IssueAsync(Store(Defaults, ClockAt(signIn)), SignedInAt(user, signIn));
        raisedClock.SetUtcNow(signIn.AddHours(720));
        Assert.Null(await ReadAsync(raised, ended));
    }

    [RedisFact]
    public async Task AbsoluteLimitLoweredAndRaisedAgain_WithoutARequest_TheRequestIsJudgedByTheLimitThen()
    {
        var signIn = WholeSecond(DateTimeOffset.UtcNow);
        var user = NewUser();
        var key = await IssueAsync(Store(Defaults, ClockAt(signIn)), SignedInAt(user, signIn));
        var other = await IssueAsync(Store(Defaults, ClockAt(signIn)), SignedInAt(user, signIn));
        // The process with the lowered limit ran and judged by it: another session of the same sign-in
        // time is rejected by it. The session under test got no request from that process.
        Assert.Null(await ReadAsync(Store(new SessionTimeouts(120, 24), ClockAt(signIn.AddHours(30))), other));
        Assert.False(await Db.KeyExistsAsync(other));

        Assert.NotNull(await ReadAsync(Store(Defaults, ClockAt(signIn.AddHours(48))), key));
    }

    [RedisFact]
    public async Task AbsoluteLimitLowered_AnEndNoticedByARequest_StaysEnded_WhenTheLimitIsRaisedBack()
    {
        var signIn = WholeSecond(DateTimeOffset.UtcNow);
        var key = await IssueAsync(Store(Defaults, ClockAt(signIn)), SignedInAt(NewUser(), signIn));

        Assert.Null(await ReadAsync(Store(new SessionTimeouts(120, 24), ClockAt(signIn.AddHours(48))), key));
        Assert.False(await Db.KeyExistsAsync(key));
        Assert.Null(await ReadAsync(Store(Defaults, ClockAt(signIn.AddHours(49))), key));
    }

    [RedisFact]
    public async Task IdleLimitRaised_OnALiveRow_TheNewLimitTakesEffectWithTheFirstAdmittedRequest()
    {
        var signIn = WholeSecond(DateTimeOffset.UtcNow);
        var key = await IssueAsync(Store(new SessionTimeouts(24, 720), ClockAt(signIn)), SignedInAt(NewUser(), signIn));
        AssertNear(TimeSpan.FromHours(24), await PttlAsync(key));
        var raised = Store(Defaults, ClockAt(signIn.AddHours(1)));

        AssertNear(TimeSpan.FromHours(24), await PttlAsync(key)); // the change of process alone writes nothing
        Assert.NotNull(await ReadAsync(raised, key));
        AssertNear(TimeSpan.FromHours(120), await PttlAsync(key)); // min(120 h, 719 h left)
    }

    // ---- Renewal (rows 27–32) -----------------------------------------------------------------

    [RedisFact]
    public async Task IssueReadRenewRead_KeepsExactlyOneClaimOfTheKey()
    {
        var store = Store();
        var key = await IssueAsync(store, TestRedis.Ticket(NewUser()));

        var read = await ReadAsync(store, key);
        Assert.Equal(key, SessionPrincipal.SessionKeyOf(read!.Principal));
        Assert.Equal(RenewOutcome.Written, await RenewAsync(store, key, read));
        var again = await ReadAsync(store, key);

        Assert.Equal(key, Assert.Single(again!.Principal.FindAll(SessionPrincipal.SessionKeyClaim)).Value);
    }

    [RedisFact]
    public async Task Renew_OfAnAbsentKey_IsKeyAbsent_AndCreatesNothing()
    {
        var key = NewKey("absent");

        var outcome = await RenewAsync(Store(), key, TestRedis.Ticket(NewUser()));

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

    public static TheoryData<int, int> RenewalLifetimes() => new()
    {
        // absolute limit of the renewing store → expected hours of the row at the sign-in moment
        { 720, 120 },
        { 24, 24 },
    };

    [RedisTheory]
    [MemberData(nameof(RenewalLifetimes))]
    public async Task Renew_ForTheSameOwner_IsWritten_AndMovesBothTimeToLives(int absoluteHours, int expectedHours)
    {
        var signIn = WholeSecond(DateTimeOffset.UtcNow);
        var owner = NewUser();
        var key = await IssueAsync(Store(Defaults, ClockAt(signIn)), SignedInAt(owner, signIn));
        var window = (await StoredAsync(key)).Properties;
        await Db.KeyExpireAsync(key, TimeSpan.FromMinutes(1));
        await Db.KeyExpireAsync(IndexOf(owner), TimeSpan.FromMinutes(1));

        var outcome = await RenewAsync(Store(new SessionTimeouts(120, absoluteHours), ClockAt(signIn)), key, TestRedis.Ticket(owner));

        Assert.Equal(RenewOutcome.Written, outcome);
        var row = await PttlAsync(key);
        AssertNear(TimeSpan.FromHours(expectedHours), row);
        Assert.True(await PttlAsync(IndexOf(owner)) >= row - 1000);
        var stored = (await StoredAsync(key)).Properties;
        Assert.Equal(window.IssuedUtc, stored.IssuedUtc);
        Assert.Equal(window.ExpiresUtc, stored.ExpiresUtc);
    }

    [RedisFact]
    public async Task SuccessiveRenewals_KeepTheWindowOfTheSignIn_WhateverWindowTheyCarry()
    {
        var signIn = WholeSecond(DateTimeOffset.UtcNow);
        var owner = NewUser();
        var store = Store(Defaults, ClockAt(signIn));
        var key = await IssueAsync(store, SignedInAt(owner, signIn));

        foreach (var (issued, expires) in new[]
                 {
                     (signIn.AddHours(13), signIn.AddHours(13 + 720)), // later
                     (signIn.AddHours(-30), signIn.AddHours(-30 + 720)), // earlier
                     (signIn.AddHours(2), signIn.AddHours(26)), // of another length
                 })
        {
            var incoming = TestRedis.Ticket(owner);
            incoming.Properties.IssuedUtc = issued;
            incoming.Properties.ExpiresUtc = expires;
            Assert.Equal(RenewOutcome.Written, await RenewAsync(store, key, incoming));

            var stored = (await StoredAsync(key)).Properties;
            Assert.Equal(signIn, stored.IssuedUtc);
            Assert.Equal(signIn.AddHours(720), stored.ExpiresUtc);
        }
    }

    [RedisFact]
    public async Task Pair_ConfirmedByTheMarker_SurvivesALaterOrdinaryRenewal_AndTheMarkerIsNotStored()
    {
        var store = Store();
        var owner = NewUser();
        var key = await IssueAsync(store, TestRedis.Ticket(owner, "old@example.com", "old"));
        var staleClone = await ReadAsync(store, key); // an in-flight request that read the old pair

        var confirm = TestRedis.Ticket(owner, "new@example.com", "new");
        confirm.Properties.Items[RedisTicketStore.SsoPairWriteMarker] = "1";
        Assert.Equal(RenewOutcome.Written, await RenewAsync(store, key, confirm));
        Assert.Equal(RenewOutcome.Written, await RenewAsync(store, key, staleClone!));

        var stored = await StoredAsync(key);
        Assert.Equal("new@example.com", stored.Properties.Items[RedisTicketStore.SsoEmailItem]);
        Assert.Equal("new", stored.Properties.Items[RedisTicketStore.SsoUserItem]);
        Assert.DoesNotContain(RedisTicketStore.SsoPairWriteMarker, stored.Properties.Items.Keys);
    }

    [RedisFact]
    public async Task ClaimsAndPairOfAnExplicitConfirmation_AreNotRewrittenByALaterRead()
    {
        var store = Store();
        var owner = NewUser();
        var key = await IssueAsync(store, TestRedis.Ticket(owner, "p@example.com", "p", new Claim(ClaimTypes.Role, "user")));

        var confirmed = TestRedis.Ticket(owner, "q@example.com", "q", new Claim(ClaimTypes.Role, "admin"));
        confirmed.Properties.Items[RedisTicketStore.SsoPairWriteMarker] = "1";
        Assert.Equal(RenewOutcome.Written, await RenewAsync(store, key, confirmed));
        var afterConfirmation = (byte[])(await Db.StringGetAsync(key))!;

        Assert.NotNull(await ReadAsync(store, key)); // an ordinary request

        Assert.Equal(afterConfirmation, (byte[])(await Db.StringGetAsync(key))!); // no automatic renewal wrote anything
        var stored = await StoredAsync(key);
        Assert.Equal("admin", stored.Principal.FindFirstValue(ClaimTypes.Role));
        Assert.Equal("q@example.com", stored.Properties.Items[RedisTicketStore.SsoEmailItem]);
    }

    [RedisFact]
    public async Task ClaimUpdate_DoesNotEraseThePair_NorReplaceItWithAProfile()
    {
        var store = Store();
        var owner = NewUser();
        var key = await IssueAsync(store, TestRedis.Ticket(owner, "proxy@example.com", "proxy-user"));

        var update = TestRedis.Ticket(owner, extra: new Claim(ClaimTypes.Role, "admin"));
        Assert.Equal(RenewOutcome.Written, await RenewAsync(store, key, update));

        var stored = await StoredAsync(key);
        Assert.Equal("proxy@example.com", stored.Properties.Items[RedisTicketStore.SsoEmailItem]);
        Assert.Equal("proxy-user", stored.Properties.Items[RedisTicketStore.SsoUserItem]);
        Assert.Equal("admin", stored.Principal.FindFirstValue(ClaimTypes.Role));
    }

    [RedisFact]
    public async Task ThreeLostCompareAndSets_AreCasExhausted_NotKeyAbsent()
    {
        var owner = NewUser();
        var key = await IssueAsync(Store(), TestRedis.Ticket(owner));
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

        var outcome = await RenewAsync(StoreOver(db), key, TestRedis.Ticket(owner));

        Assert.Equal(RenewOutcome.CasExhausted, outcome);
        Assert.True(await Db.KeyExistsAsync(key));
    }

    [RedisTheory]
    [InlineData(0)] // at the end
    [InlineData(5_000)] // 0.5 ms before it: less than 1 ms left
    public async Task Renew_OfASessionEndedByTheStoreClock_DeletesTheRow_AndIsKeyAbsent(long ticksBeforeTheEnd)
    {
        var signIn = WholeSecond(DateTimeOffset.UtcNow);
        var owner = NewUser();
        var key = await IssueAsync(Store(Defaults, ClockAt(signIn)), SignedInAt(owner, signIn));
        var late = Store(Defaults, ClockAt(signIn.AddHours(720) - TimeSpan.FromTicks(ticksBeforeTheEnd)));

        var outcome = await RenewAsync(late, key, TestRedis.Ticket(owner));

        Assert.Equal(RenewOutcome.KeyAbsent, outcome);
        Assert.False(await Db.KeyExistsAsync(key));
    }

    private async Task<DateTimeOffset> RedisNowAsync() =>
        new(await _mux.GetServers()[0].TimeAsync(), TimeSpan.Zero);

    /// <summary>Polls the clock of Redis until <paramref name="reached"/> holds; fails after 15 s.</summary>
    private async Task<DateTimeOffset> RedisClockUntilAsync(Func<DateTimeOffset, bool> reached)
    {
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (true)
        {
            var now = await RedisNowAsync();
            if (reached(now))
            {
                return now;
            }
            Assert.True(DateTime.UtcNow < deadline, $"the clock of Redis never reached the moment; last {now:O}");
            await Task.Delay(20);
        }
    }

    [RedisTheory]
    [InlineData(false)] // released while the clock of Redis is in (end − 2 s, end − 1 s]
    [InlineData(true)] // released once the clock of Redis is past the end
    public async Task Renew_TheEndIsDecidedByTheScript_ByTheClockOfRedis_AtTheMomentOfTheWrite(bool crossTheEnd)
    {
        var owner = NewUser();
        var key = NewKey("boundary");
        // A window that ends 3 to 4 s from now by the clock of Redis, a row that would live 60 s: no natural expiry.
        var end = WholeSecond(await RedisNowAsync()).AddSeconds(4);
        var ticket = TestRedis.Ticket(owner);
        ticket.Properties.IssuedUtc = end.AddHours(-720);
        ticket.Properties.ExpiresUtc = end;
        await SeedAsync(key, ticket, TimeSpan.FromSeconds(60));
        var db = DbProxy.Create(Db, out var proxy);
        // The compare-and-set of this row, told by its compare, not by the clock read under test.
        var cas = proxy.Hold((name, args) => DbProxy.IsScript(name, args, StoreScripts.Renew, key));
        var store = StoreOver(db, Defaults, ClockAt(end.AddMinutes(-10))); // the replica's last check allows the write

        var renewal = RenewAsync(store, key, TestRedis.Ticket(owner));
        try
        {
            await cas.Reached.WaitAsync(TimeSpan.FromSeconds(10));

            if (crossTheEnd)
            {
                await RedisClockUntilAsync(now => now > end);
                Assert.True(await Db.KeyExistsAsync(key)); // the row is still there on its own
                cas.Release();

                Assert.Equal(RenewOutcome.KeyAbsent, await renewal.WaitAsync(TimeSpan.FromSeconds(10)));
                Assert.False(await Db.KeyExistsAsync(key));
            }
            else
            {
                // As close to the end as the positive arm allows: an early refusal 1–2 s before it turns red.
                var at = await RedisClockUntilAsync(now => now > end.AddSeconds(-2));
                Assert.True(at <= end.AddSeconds(-1), $"the clock of Redis passed end − 1 s before the release: {at:O}");
                cas.Release();

                Assert.Equal(RenewOutcome.Written, await renewal.WaitAsync(TimeSpan.FromSeconds(10)));
                Assert.True(await Db.KeyExistsAsync(key));
            }
        }
        finally
        {
            cas.Release();
        }
    }

    [RedisFact]
    public async Task Renew_OfAKeyGoneBeforeTheLastCompareAndSet_IsKeyAbsent_AndWritesNothing()
    {
        var owner = NewUser();
        var key = await IssueAsync(Store(), TestRedis.Ticket(owner));
        var db = DbProxy.Create(Db, out var proxy);
        var reads = 0;
        proxy.After = async (name, args) =>
        {
            if (name == nameof(IDatabase.StringGetAsync) && (RedisKey)args[0]! == key)
            {
                if (++reads < 3)
                {
                    // The first two attempts lose to a rival write.
                    var rival = TicketSerializer.Default.Serialize(TestRedis.Ticket(owner, extra: new Claim("rival", reads.ToString())));
                    await Db.StringSetAsync(key, rival, TimeSpan.FromHours(1));
                }
                else
                {
                    await Db.KeyDeleteAsync(key); // gone before the last compare-and-set
                }
            }
        };

        var outcome = await RenewAsync(StoreOver(db), key, TestRedis.Ticket(owner));

        Assert.Equal(3, reads);
        Assert.Equal(RenewOutcome.KeyAbsent, outcome);
        Assert.False(await Db.KeyExistsAsync(key));
    }

    // ---- Index (rows 33–38, 84) ---------------------------------------------------------------

    [RedisFact]
    public async Task MassRemoval_FindsASessionOlderThanTheFirstIndexLifetime()
    {
        var store = Store();
        var owner = NewUser();
        var key = await IssueAsync(store, TestRedis.Ticket(owner));
        await Db.KeyExpireAsync(IndexOf(owner), TimeSpan.FromMinutes(1));

        Assert.NotNull(await ReadAsync(store, key)); // a read, not a renewal, lifts the index again
        Assert.True(await PttlAsync(IndexOf(owner)) >= await PttlAsync(key) - 1000);

        var result = await store.RemoveSessionsAsync(owner, keepKey: null, CancellationToken.None);

        Assert.True(result.Complete);
        Assert.False(await Db.KeyExistsAsync(key));
    }

    [RedisFact]
    public async Task AnIndexWithoutALifetime_GetsTheLifetimeOfTheRowWrittenNext()
    {
        var owner = NewUser();
        await Db.SetAddAsync(IndexOf(owner), await LiveMemberAsync());
        Assert.Equal(-1, await PttlAsync(IndexOf(owner)));

        var key = await IssueAsync(Store(new SessionTimeouts(7, 11)), TestRedis.Ticket(owner));

        var index = await PttlAsync(IndexOf(owner));
        Assert.True(index > 0);
        Assert.InRange(index - await PttlAsync(key), -1000, 1000);
    }

    [RedisFact]
    public async Task TheIndexLifetime_FollowsTheLongestLiveRow_AndIsNotSetAgainAfterThatRowIsGone()
    {
        var owner = NewUser();
        var stranger = NewUser();
        var strangerKey = await IssueAsync(Store(), TestRedis.Ticket(stranger));
        var strangerIndex = await PttlAsync(IndexOf(stranger));
        var shortStore = Store(new SessionTimeouts(24, 720));

        var longKey = await IssueAsync(Store(), TestRedis.Ticket(owner)); // 120 h
        var shortKey = await IssueAsync(shortStore, TestRedis.Ticket(owner)); // 24 h
        var longRow = await PttlAsync(longKey);
        var index = await PttlAsync(IndexOf(owner));
        // The write for the shorter session neither lowers the index below the longer row nor lifts it above.
        Assert.InRange(index, longRow - 1000, longRow + 1000);

        await Db.KeyDeleteAsync(longKey); // the longest row ends early
        await Db.KeyExpireAsync(IndexOf(owner), TimeSpan.FromHours(50)); // the lifetime the index has by now
        Assert.NotNull(await ReadAsync(shortStore, shortKey)); // the next write: 24 h for the short row

        var after = await PttlAsync(IndexOf(owner));
        Assert.InRange(after, (long)TimeSpan.FromHours(49).TotalMilliseconds, (long)TimeSpan.FromHours(50).TotalMilliseconds);
        Assert.True(await Db.SetContainsAsync(IndexOf(stranger), strangerKey)); // another user's index is untouched
        Assert.InRange(await PttlAsync(IndexOf(stranger)), strangerIndex - 10_000, strangerIndex);
    }

    private (RedisTicketStore Store, FormatterLogs Logs, ILoggerFactory Factory) LoggedStore()
    {
        var logs = new FormatterLogs();
        var factory = LoggerFactory.Create(b => b.SetMinimumLevel(LogLevel.Trace).AddProvider(logs));
        return (new RedisTicketStore(_mux, Defaults, TimeProvider.System, factory.CreateLogger<RedisTicketStore>()), logs, factory);
    }

    [RedisFact]
    public async Task AFailedIndexPartOfARead_LeavesTheReadAuthenticated_AndTheNextGoodReadRestoresTheMembership()
    {
        var owner = NewUser();
        var key = await IssueAsync(Store(), TestRedis.Ticket(owner));
        await Db.KeyDeleteAsync(IndexOf(owner));
        await Db.StringSetAsync(IndexOf(owner), "not a set"); // the index part fails on this key
        await Db.KeyExpireAsync(key, TimeSpan.FromMinutes(1));
        var (store, logs, factory) = LoggedStore();
        using var _ = factory;

        Assert.NotNull(await ReadAsync(store, key));
        AssertNear(TimeSpan.FromHours(120), await PttlAsync(key)); // the row lifetime is written regardless
        Assert.Contains("session index maintenance failed", logs.Output);
        Assert.DoesNotContain(key, logs.Output);

        Assert.NotNull(await ReadAsync(store, key)); // the failure again: still not the request's problem
        Assert.Equal(RedisType.String, await Db.KeyTypeAsync(IndexOf(owner))); // membership not restored

        await Db.KeyDeleteAsync(IndexOf(owner)); // the index key is repaired
        Assert.NotNull(await ReadAsync(store, key));
        Assert.True(await Db.SetContainsAsync(IndexOf(owner), key));
        Assert.InRange(await PttlAsync(IndexOf(owner)) - await PttlAsync(key), -1000, 1000);
    }

    [RedisFact]
    public async Task AFailedIndexPartOfAnIssueOrARenewal_LeavesTheirResult_AndTheNextGoodReadRestoresTheMembership()
    {
        var owner = NewUser();
        await Db.StringSetAsync(IndexOf(owner), "not a set");
        var (store, logs, factory) = LoggedStore();
        using var _ = factory;

        var key = await IssueAsync(store, TestRedis.Ticket(owner));
        AssertNear(TimeSpan.FromHours(120), await PttlAsync(key));
        await Db.KeyExpireAsync(key, TimeSpan.FromMinutes(1));
        Assert.Equal(RenewOutcome.Written, await RenewAsync(store, key, TestRedis.Ticket(owner)));
        AssertNear(TimeSpan.FromHours(120), await PttlAsync(key));
        Assert.Contains("session index maintenance failed operation=store", logs.Output);
        Assert.Contains("session index maintenance failed operation=renew", logs.Output);
        Assert.DoesNotContain(key, logs.Output);

        await Db.KeyDeleteAsync(IndexOf(owner));
        Assert.NotNull(await ReadAsync(store, key));
        Assert.True(await Db.SetContainsAsync(IndexOf(owner), key));
    }

    [RedisFact]
    public async Task ASignIn_RemovesTheIndexMembersWhoseRowsAreGone_AndKeepsTheLiveOnes()
    {
        var owner = NewUser();
        var store = Store();
        var live = await IssueAsync(store, TestRedis.Ticket(owner));
        var dead = new[] { NewKey("dead"), NewKey("dead") };
        await Db.SetAddAsync(IndexOf(owner), dead.Select(k => (RedisValue)k).ToArray());

        var next = await IssueAsync(store, TestRedis.Ticket(owner));

        var members = (await Db.SetMembersAsync(IndexOf(owner))).Select(m => (string)m!).ToHashSet();
        Assert.Equal(new HashSet<string> { live, next }, members);
    }

    [RedisFact]
    public async Task AFailedPruneOfTheIndex_DoesNotFailTheSignIn()
    {
        var owner = NewUser();
        await Db.StringSetAsync(IndexOf(owner), "not a set"); // SMEMBERS of the prune fails on it

        var key = await IssueAsync(Store(), TestRedis.Ticket(owner));

        Assert.True(await Db.KeyExistsAsync(key));
    }

    [RedisFact]
    public async Task ARestoredMembership_IsSeenByAMassRemovalThatReadsTheIndexLater_AndMissedByOneThatReadItBefore()
    {
        var owner = NewUser();
        var store = Store();

        // Restored before the removal reads the index: revoked, and a later read does not bring it back.
        var first = await IssueAsync(store, TestRedis.Ticket(owner));
        await Db.SetRemoveAsync(IndexOf(owner), first);
        Assert.NotNull(await ReadAsync(store, first));
        await store.RemoveSessionsAsync(owner, keepKey: null, CancellationToken.None);
        Assert.False(await Db.KeyExistsAsync(first));
        Assert.Null(await ReadAsync(store, first));

        // Restored after the removal read the index: missed, and nothing revokes it again.
        var second = await IssueAsync(store, TestRedis.Ticket(owner));
        await Db.SetRemoveAsync(IndexOf(owner), second);
        var db = DbProxy.Create(Db, out var proxy);
        AuthenticationTicket? restoring = null;
        proxy.After = async (name, _) =>
        {
            if (name == nameof(IDatabase.SetMembersAsync))
            {
                restoring = await ReadAsync(store, second);
            }
        };
        var result = await StoreOver(db).RemoveSessionsAsync(owner, keepKey: null, CancellationToken.None);

        Assert.NotNull(restoring); // the read restored the membership after the removal had read the index
        Assert.Equal(0, result.Removed);
        Assert.True(await Db.KeyExistsAsync(second));
        Assert.True(await Db.SetContainsAsync(IndexOf(owner), second));
    }

    public enum WritePath
    {
        Read,
        Issue,
        Renewal,
    }

    [RedisTheory]
    [InlineData(WritePath.Read)]
    [InlineData(WritePath.Issue)]
    [InlineData(WritePath.Renewal)]
    public async Task NoMomentAfterTheRowWrite_LeavesTheLiveRowOutsideALiveIndex(WritePath path)
    {
        var owner = NewUser();
        var existing = path == WritePath.Issue ? null : await IssueAsync(Store(), TestRedis.Ticket(owner));
        if (existing is not null)
        {
            await Db.KeyExpireAsync(existing, TimeSpan.FromSeconds(30)); // a row lifetime the write must visibly move
        }
        await Db.SetAddAsync(IndexOf(owner), await LiveMemberAsync());
        await Db.KeyExpireAsync(IndexOf(owner), TimeSpan.FromMilliseconds(300)); // an index about to expire
        var indexSeededAt = await RedisNowAsync();

        // Everything up to the first actual write of the row or its lifetime passes; every command the
        // request sends after it is held until the observation ends.
        var db = DbProxy.Create(Db, out var proxy);
        var written = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var writeFragment = path switch
        {
            WritePath.Read => StoreScripts.Read,
            WritePath.Issue => StoreScripts.Issue,
            _ => StoreScripts.Renew,
        };
        proxy.After = (name, args) =>
        {
            if (DbProxy.IsScript(name, args, writeFragment))
            {
                written.TrySetResult((string)DbProxy.KeysOf(name, args)[0]!);
            }
            return Task.CompletedTask;
        };
        var later = proxy.HoldAll((_, _) => written.Task.IsCompleted);
        var store = StoreOver(db);

        Task request = path switch
        {
            WritePath.Read => ReadAsync(store, existing!),
            WritePath.Issue => IssueAsync(store, TestRedis.Ticket(owner)),
            _ => RenewAsync(store, existing!, TestRedis.Ticket(owner)),
        };
        try
        {
            var key = await written.Task.WaitAsync(TimeSpan.FromSeconds(10));
            _keys.Add(key);
            // The row is written: a new key, or a lifetime moved far past the seeded 30 s.
            Assert.True(await PttlAsync(key) > (long)TimeSpan.FromMinutes(1).TotalMilliseconds);
            // The former lifetime of the index has passed, by the clock of Redis.
            await RedisClockUntilAsync(now => now > indexSeededAt.AddMilliseconds(400));

            var result = await Store().RemoveSessionsAsync(owner, keepKey: null, CancellationToken.None);

            Assert.True(result.Removed >= 1);
            Assert.False(await Db.KeyExistsAsync(key)); // the removal found the live row through the index
        }
        finally
        {
            later.Release();
        }
        await request.WaitAsync(TimeSpan.FromSeconds(10));
    }

    // ---- Revocation, removal, probes, cancellation --------------------------------------------

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
        var store = StoreOver(db);
        var ctx = new DefaultHttpContext();

        await store.RevokeAsync(key, ctx, CancellationToken.None);
        proxy.Before = (name, _) => new InvalidOperationException("Redis was called: " + name);
        await store.RemoveAsync(key, ctx, CancellationToken.None);

        Assert.Contains(key, SessionRequestState.Of(ctx).RemovedKeys);
    }

    [RedisFact]
    public async Task MassRemoval_KeepsAMemberAddedMeanwhile_AndDropsOnlyTheProcessedOnes()
    {
        var owner = NewUser();
        var key = await IssueAsync(Store(), TestRedis.Ticket(owner));
        var late = NewKey("late");
        var db = DbProxy.Create(Db, out var proxy);
        proxy.After = async (name, _) =>
        {
            if (name == nameof(IDatabase.SetMembersAsync))
            {
                await Db.SetAddAsync(IndexOf(owner), late);
            }
        };

        var result = await StoreOver(db).RemoveSessionsAsync(owner, keepKey: null, CancellationToken.None);

        Assert.Equal(1, result.Removed);
        Assert.False(await Db.SetContainsAsync(IndexOf(owner), key));
        Assert.True(await Db.SetContainsAsync(IndexOf(owner), late));
    }

    [RedisFact]
    public async Task Probes_AreTrueForALiveSession_FalseOtherwise_AndDoNotWriteTheLifetime()
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
