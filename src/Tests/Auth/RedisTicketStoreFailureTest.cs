using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Microsoft.Extensions.Logging;
using SkeinWeb.Auth;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// Failure branches of the ticket store on a mocked Redis boundary (INV-3, INV-4, INV-5, INV-9): a
/// technical failure is never read as "no session", never leaks the session key, and a failure of
/// the reverse index never fails an issue.
/// </summary>
public class RedisTicketStoreFailureTest
{
    private const string Key = "skein:session:SECRET-KEY-VALUE";
    private static readonly Guid Owner = Guid.Parse("0199a1b2-0000-7000-8000-000000000001");

    private static RedisConnectionException Down() =>
        new(ConnectionFailureType.SocketFailure, $"no connection for {Key}");

    private static (RedisTicketStore Store, Mock<IDatabase> Db) Build()
    {
        var db = new Mock<IDatabase>();
        var mux = new Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(db.Object);
        return (TestRedis.Store(mux.Object), db);
    }

    private static AuthenticationTicket Ticket() => new(
        new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, Owner.ToString())], "Cookies")),
        "Cookies");

    [Fact]
    public async Task Retrieve_TechnicalFailure_IsAnExceptionWithoutTheSourceText_NotNull()
    {
        var (store, db) = Build();
        db.Setup(d => d.StringGetAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>())).ThrowsAsync(Down());

        var ex = await Assert.ThrowsAsync<SessionStoreUnavailableException>(
            () => store.RetrieveAsync(Key, new DefaultHttpContext(), CancellationToken.None));

        Assert.Null(ex.InnerException);
        Assert.DoesNotContain("SECRET-KEY-VALUE", ex.ToString());
    }

    [Fact]
    public async Task Retrieve_WrongType_IsNoSession()
    {
        var (store, db) = Build();
        db.Setup(d => d.StringGetAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
            .ThrowsAsync(new RedisServerException("WRONGTYPE Operation against a key holding the wrong kind of value"));

        Assert.Null(await store.RetrieveAsync(Key, new DefaultHttpContext(), CancellationToken.None));
    }

    [Fact]
    public async Task Remove_TechnicalFailure_IsAnExceptionWithoutTheSourceText()
    {
        var (store, db) = Build();
        db.Setup(d => d.ScriptEvaluateAsync(It.IsAny<string>(), It.IsAny<RedisKey[]>(), It.IsAny<RedisValue[]>(), It.IsAny<CommandFlags>()))
            .ThrowsAsync(Down());

        var ex = await Assert.ThrowsAsync<SessionStoreUnavailableException>(
            () => store.RemoveAsync(Key, new DefaultHttpContext(), CancellationToken.None));

        Assert.Null(ex.InnerException);
        Assert.DoesNotContain("SECRET-KEY-VALUE", ex.ToString());
    }

    [Fact]
    public async Task BackgroundRenewal_TechnicalFailure_IsAbsorbed_WithoutAWrittenOutcome()
    {
        var (store, db) = Build();
        db.Setup(d => d.StringGetAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>())).ThrowsAsync(Down());
        var ctx = new DefaultHttpContext();

        await store.RenewAsync(Key, Ticket(), ctx, CancellationToken.None);

        Assert.Equal(RenewOutcome.TechnicalFailure, SessionRequestState.Of(ctx).RenewOutcome);
    }

    [Fact]
    public async Task ExplicitRenewal_TechnicalFailure_IsThrown()
    {
        var (store, db) = Build();
        db.Setup(d => d.StringGetAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>())).ThrowsAsync(Down());
        var ctx = new DefaultHttpContext();
        SessionRequestState.Of(ctx).ExplicitRenewal = true;

        await Assert.ThrowsAsync<SessionStoreUnavailableException>(
            () => store.RenewAsync(Key, Ticket(), ctx, CancellationToken.None));
    }

    [Fact]
    public async Task Issue_WhenTheIndexFails_StillIssuesTheKey()
    {
        var (store, db) = Build();
        db.Setup(d => d.StringSetAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<TimeSpan?>(), It.IsAny<When>()))
            .ReturnsAsync(true);
        db.Setup(d => d.SetAddAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<CommandFlags>())).ThrowsAsync(Down());
        var ctx = new DefaultHttpContext();

        var key = await store.StoreAsync(Ticket(), ctx, CancellationToken.None);

        Assert.StartsWith("skein:session:", key);
        Assert.Equal(key, SessionRequestState.Of(ctx).IssuedKey);
    }

    private static void SetupIndex(Mock<IDatabase> db, string[] members, int failReads = 0)
    {
        var failed = 0;
        db.Setup(d => d.SetMembersAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
            .Returns(() => failed++ < failReads
                ? Task.FromException<RedisValue[]>(Down())
                : Task.FromResult(members.Select(m => (RedisValue)m).ToArray()));
    }

    [Fact]
    public async Task MassRemoval_IndexReadFailingTwice_IsRetriedAndComplete()
    {
        var (store, db) = Build();
        SetupIndex(db, ["k1"], failReads: 2);
        db.Setup(d => d.KeyDeleteAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>())).ReturnsAsync(true);

        var result = await store.RemoveSessionsAsync(Owner, keepKey: null, CancellationToken.None);

        Assert.True(result.Complete);
        Assert.Equal(1, result.Removed);
    }

    [Fact]
    public async Task MassRemoval_IndexUnreadable_IsReportedNotComplete()
    {
        var (store, db) = Build();
        SetupIndex(db, [], failReads: int.MaxValue);

        var result = await store.RemoveSessionsAsync(Owner, keepKey: null, CancellationToken.None);

        Assert.False(result.IndexRead);
        Assert.False(result.Complete);
    }

    [Fact]
    public async Task MassRemoval_OneRowUndeletable_IsReported_AndStaysInTheIndex()
    {
        var (store, db) = Build();
        SetupIndex(db, ["kept", "stuck", "gone"]);
        db.Setup(d => d.KeyDeleteAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
            .Returns((RedisKey k, CommandFlags _) => k == (RedisKey)"stuck" ? Task.FromException<bool>(Down()) : Task.FromResult(true));
        var pruned = new List<string>();
        db.Setup(d => d.SetRemoveAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue[]>(), It.IsAny<CommandFlags>()))
            .Callback((RedisKey _, RedisValue[] values, CommandFlags _) => pruned.AddRange(values.Select(v => (string)v!)))
            .ReturnsAsync(1L);

        var result = await store.RemoveSessionsAsync(Owner, "kept", CancellationToken.None);

        Assert.Equal(new SessionRemovalResult(Removed: 1, Failed: 1, IndexRead: true), result);
        Assert.Equal(["gone"], pruned);
    }

    [Fact]
    public async Task Probes_OnATechnicalFailure_ThrowTheSourceFreeException_AndLogNoKey()
    {
        var log = new SessionPipelineHost.ErrorLogs();
        using var factory = LoggerFactory.Create(b => b.SetMinimumLevel(LogLevel.Trace).AddProvider(log));
        var db = new Mock<IDatabase>();
        db.Setup(d => d.KeyExistsAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>())).ThrowsAsync(Down());
        db.Setup(d => d.SetContainsAsync(It.IsAny<RedisKey>(), It.IsAny<RedisValue>(), It.IsAny<CommandFlags>())).ThrowsAsync(Down());
        var mux = new Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(db.Object);
        var store = new RedisTicketStore(mux.Object, TestRedis.DefaultTimeouts, TimeProvider.System, factory.CreateLogger<RedisTicketStore>());

        var exists = await Assert.ThrowsAsync<SessionStoreUnavailableException>(() => store.ExistsAsync(Key, CancellationToken.None));
        var owner = await Assert.ThrowsAsync<SessionStoreUnavailableException>(() => store.IsSessionOfAsync(Key, Owner, CancellationToken.None));

        Assert.All([exists, owner], e => Assert.Null(e.InnerException));
        Assert.Contains(log.Entries, e => e.Text.Contains("exists") || e.Text.Contains("is-session-of"));
        Assert.DoesNotContain(log.Entries, e => e.Text.Contains("SECRET-KEY-VALUE"));
    }
}
