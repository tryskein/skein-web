using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SkeinWeb.Auth;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// The startup session cleanup on the real pipeline (<see cref="SessionPipelineHost"/>, database
/// <see cref="SessionPipelineHost.Database"/>), run on the multiplexer of the stand: an issue whose
/// mark fails during a pass is refused without a row and without a cookie (ОСТ-3-2), and after the
/// cleanup the old cookie is no session on a protected request and on a new hub connection (US-5).
/// </summary>
[Trait("Category", "Integration")]
[Collection("session-pipeline")]
public sealed class SessionCleanupPipelineTest
{
    private static readonly Guid Alice = Guid.Parse("0199a1b2-0000-7000-8000-00000000000a");

    private static SessionStoreMigration Migration(SessionPipelineHost host, StackExchange.Redis.IDatabase? db = null) =>
        new(TestRedis.Over(host.Mux, db ?? host.Db), TimeProvider.System, NullLogger<SessionStoreMigration>.Instance);

    private static string[] SessionRows(SessionPipelineHost host) =>
        host.Mux.GetServers().First(s => !s.IsReplica).Keys(SessionPipelineHost.Database, CleanupCalls.SessionPattern)
            .Select(k => (string)k!).Order().ToArray();

    [RedisFact]
    public async Task AFailedMarkDuringThePass_RefusesTheIssue_WithoutARowAndWithoutACookie()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        await host.Db.StringSetAsync("skein:session:of-the-start", "row");
        await host.Db.KeyDeleteAsync(SessionStoreMigration.MarkerKey); // a pass is due
        var db = DbProxy.Create(host.Db, out var proxy);
        var held = proxy.Hold((name, args) => CleanupCalls.Of(name, args) == CleanupStep.Extend);
        var pass = Migration(host, db).RunAsync(TimeSpan.FromSeconds(30), CancellationToken.None);
        await held.Reached.WaitAsync(TimeSpan.FromSeconds(15));
        Assert.True(await host.Db.KeyExistsAsync(SessionStoreMigration.LockKey)); // the pass is running

        // The set of marks of the running pass is of another type: the mark cannot be written.
        await host.Db.StringSetAsync(SessionStoreMigration.IssuedDuringKey, "not-a-set");
        var rows = SessionRows(host);

        var reply = await host.SendAsync($"/test/issue?user={Alice}");

        // The issuer refuses (SessionIssueException); the endpoint of the stand does not map it, so it is a 500.
        Assert.Equal(HttpStatusCode.InternalServerError, reply.Status);
        Assert.Empty(reply.SessionWrites());
        Assert.Equal(rows, SessionRows(host));
        // The refusal came from the issue script: Redis refused the mark (WRONGTYPE) and the store failed the issue.
        lock (host.Logs.Entries)
        {
            Assert.Contains(host.Logs.Entries, e => e.Level == LogLevel.Warning
                && e.Category == typeof(RedisTicketStore).FullName
                && e.Text.Contains("operation=store", StringComparison.Ordinal)
                && e.Text.Contains("code=WRONGTYPE", StringComparison.Ordinal));
        }

        // The pass then finishes as usual.
        await host.Db.KeyDeleteAsync(SessionStoreMigration.IssuedDuringKey);
        held.Release();
        await pass.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Empty(SessionRows(host));
        Assert.Equal(SessionStoreMigration.MarkerValue, await host.Db.StringGetAsync(SessionStoreMigration.MarkerKey));
    }

    [RedisFact]
    public async Task AfterTheCleanup_TheOldCookie_IsNoSession_OnAProtectedRequest_AndOnANewHubConnection()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, key, _) = await host.SignInAsync(Alice);
        // Control: the session works on both surfaces before the cleanup.
        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync("/test/me", cookie)).Status);
        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync("/test/hub", cookie)).Status);
        await host.Db.KeyDeleteAsync(SessionStoreMigration.MarkerKey);

        await Migration(host).RunAsync(TimeSpan.FromSeconds(10), CancellationToken.None);

        Assert.False(await host.Db.KeyExistsAsync(key));
        var me = await host.SendAsync("/test/me", cookie);
        var hub = await host.SendAsync("/test/hub", cookie);
        Assert.Equal(HttpStatusCode.Unauthorized, me.Status);
        Assert.Equal(HttpStatusCode.Unauthorized, hub.Status);
        // As without a session: no session cookie is written for it.
        Assert.DoesNotContain(me.Cookies, c => c.Name == host.CookieName && !c.IsDeletion);
    }
}
