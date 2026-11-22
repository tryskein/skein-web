using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using SkeinWeb.Auth;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// The startup session cleanup on the real pipeline (<see cref="SessionPipelineHost"/>, database
/// <see cref="SessionPipelineHost.Database"/>), run on the multiplexer of the stand: an issue whose
/// mark fails during a pass is refused without a row and without a cookie (OST-3-2), and after the
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
        // The issue script on the boundary of the store's Redis: called, and never completed.
        var issueCalls = 0;
        var issueCompleted = 0;
        host.Faults.Before = (name, args) =>
        {
            if (DbProxy.IsScript(name, args, StoreScripts.Issue))
            {
                Interlocked.Increment(ref issueCalls);
            }
            return null;
        };
        host.Faults.After = (name, args) =>
        {
            if (DbProxy.IsScript(name, args, StoreScripts.Issue))
            {
                Interlocked.Increment(ref issueCompleted);
            }
            return Task.CompletedTask;
        };

        var reply = await host.SendAsync($"/test/issue?user={Alice}");

        // The issue is refused; the status a real surface gives is pinned by its own rows, not here.
        Assert.False(reply.Status is >= HttpStatusCode.OK and < HttpStatusCode.MultipleChoices, $"the issue succeeded: {reply.Status}");
        Assert.Empty(reply.SessionWrites());
        Assert.Equal(rows, SessionRows(host));
        // The refusal came from the issue script: it ran and failed on the mark, before any row.
        Assert.True(Volatile.Read(ref issueCalls) > 0, "the issue script was not called");
        Assert.Equal(0, Volatile.Read(ref issueCompleted));

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
