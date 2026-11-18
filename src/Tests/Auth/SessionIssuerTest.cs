using System.Net;
using System.Text.Json;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// The issuer and the revocation on the real handler and a real Redis (US-1, INV-1…INV-5, SC-007):
/// rotation with each kind of incoming cookie, its failures, the controlled end, the end of the
/// effective session, and the edge of an already decided renewal.
/// </summary>
[Trait("Category", "Integration")]
[Collection("session-pipeline")]
public sealed class SessionIssuerTest
{
    private static readonly Guid Alice = Guid.Parse("0199a1b2-0000-7000-8000-00000000000a");
    private static readonly Guid Bob = Guid.Parse("0199a1b2-0000-7000-8000-00000000000b");
    private static readonly Guid Carol = Guid.Parse("0199a1b2-0000-7000-8000-00000000000c");

    private static string KeyOf(SessionPipelineHost.Reply reply) =>
        JsonDocument.Parse(reply.Body).RootElement.GetProperty("key").GetString()!;

    private static IEnumerable<string> RowsOf(SessionPipelineHost host, Guid user) =>
        host.Db.SetMembers("skein:user-tickets:" + user).Select(m => (string)m!);

    // ---- R25 ----------------------------------------------------------------------------------

    [RedisTheory]
    [InlineData("another-users-live")]
    [InlineData("own-live")]
    [InlineData("expired")]
    [InlineData("arbitrary")]
    [InlineData("other-name-too")]
    public async Task Rotation_IssuesANewKey_AndKillsTheOldOne(string incoming)
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (bobCookie, bobKey, bobSet) = await host.SignInAsync(Bob);
        var (_, controlKey, _) = await host.SignInAsync(Carol);
        var (aliceCookie, aliceKey, _) = await host.SignInAsync(Alice);
        string cookie;
        string? dead = null;
        switch (incoming)
        {
            case "another-users-live": cookie = bobCookie; dead = bobKey; break;
            case "own-live": cookie = aliceCookie; dead = aliceKey; break;
            case "expired":
                await host.Db.KeyDeleteAsync(bobKey);
                cookie = bobCookie;
                break;
            case "arbitrary": cookie = $"{host.CookieName}=not-a-session-value"; break;
            default: cookie = $"{bobSet.AsRequestCookie(host.OtherName)}; {aliceCookie}"; dead = aliceKey; break;
        }

        var reply = await host.SendAsync($"/test/issue?user={Alice}", cookie);

        var set = Assert.Single(reply.Sessions(host.CookieName));
        var fresh = KeyOf(reply);
        Assert.NotEqual(dead ?? "-", fresh);
        Assert.Equal(fresh, Assert.Single(RowsOf(host, Alice).Where(k => k == fresh)));
        Assert.True(await host.Db.KeyExistsAsync(controlKey)); // the other session is untouched
        if (dead is not null)
        {
            Assert.False(await host.Db.KeyExistsAsync(dead));
            Assert.DoesNotContain(dead, RowsOf(host, incoming == "another-users-live" ? Bob : Alice));
            var withOld = await host.SendAsync("/test/me", cookie.Split(';').Last().Trim());
            Assert.Equal(HttpStatusCode.Unauthorized, withOld.Status);
        }
        if (incoming == "other-name-too")
        {
            Assert.True(await host.Db.KeyExistsAsync(bobKey)); // a value under another name is not revoked
        }
        Assert.NotEmpty(set.Value);
    }

    // ---- R26 ----------------------------------------------------------------------------------

    [RedisFact]
    public async Task FailedRevocationOfTheOldKey_IssuesNothing_AndLeavesTheOldKeyToItsOwner()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (bobCookie, bobKey, _) = await host.SignInAsync(Bob);
        host.Faults.Before = (name, _) => name == nameof(IDatabase.ScriptEvaluateAsync) ? new InvalidOperationException("injected") : null;

        var reply = await host.SendAsync($"/test/issue?user={Alice}", bobCookie);

        Assert.False((int)reply.Status < 300);
        Assert.Empty(reply.Sessions(host.CookieName));
        Assert.True(await host.Db.KeyExistsAsync(bobKey));
        Assert.Empty(RowsOf(host, Alice));
        host.Faults.Before = null;
        var still = await host.SendAsync("/test/me", bobCookie);
        Assert.Contains(Bob.ToString(), still.Body); // the old key is still Bob's, not Alice's
    }

    [RedisFact]
    public async Task FailedWriteOfTheNewKey_AfterTheOldOneWasDeleted_IssuesNoCookie()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (bobCookie, bobKey, _) = await host.SignInAsync(Bob);
        host.Faults.Before = (name, _) => name == nameof(IDatabase.StringSetAsync) ? new InvalidOperationException("injected") : null;

        var reply = await host.SendAsync($"/test/issue?user={Alice}", bobCookie);

        Assert.False((int)reply.Status < 300);
        Assert.Empty(reply.Sessions(host.CookieName));
        Assert.False(await host.Db.KeyExistsAsync(bobKey));
        Assert.Empty(RowsOf(host, Alice));
    }

    // ---- R27 ----------------------------------------------------------------------------------

    [RedisFact]
    public async Task EndCurrent_DeletesTheKeyAndTheCookie_WithoutANewSession()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, key, _) = await host.SignInAsync(Alice);
        host.Time.Advance(TimeSpan.FromHours(13)); // a late Main write would be due

        var reply = await host.SendAsync("/test/end-current", cookie);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        Assert.Contains("false", reply.Body);
        Assert.False(await host.Db.KeyExistsAsync(key));
        var only = Assert.Single(reply.Cookies);
        Assert.True(only.IsDeletion);
    }

    [RedisFact]
    public async Task EndCurrent_WhenTheRevocationFails_WritesNoCookie_AndTheKeyLives()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, key, _) = await host.SignInAsync(Alice);
        host.Faults.Before = (name, _) => name == nameof(IDatabase.ScriptEvaluateAsync) ? new InvalidOperationException("injected") : null;

        var reply = await host.SendAsync("/test/end-current", cookie);

        Assert.False((int)reply.Status < 300);
        Assert.Empty(reply.Cookies);
        Assert.True(await host.Db.KeyExistsAsync(key));
    }

    [RedisFact]
    public async Task EndCurrent_AFailureAfterTheConfirmedDeletion_DoesNotChangeTheOutcome()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, key, _) = await host.SignInAsync(Alice);
        host.Faults.After = (name, _) =>
        {
            if (name == nameof(IDatabase.ScriptEvaluateAsync))
            {
                host.Faults.Before = (_, _) => new InvalidOperationException("injected after the DEL");
            }
            return Task.CompletedTask;
        };

        var reply = await host.SendAsync("/test/end-current", cookie);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        Assert.True(Assert.Single(reply.Cookies).IsDeletion);
        host.Faults.Before = null;
        Assert.False(await host.Db.KeyExistsAsync(key));
    }

    // ---- R28 ----------------------------------------------------------------------------------

    [RedisFact]
    public async Task EndSession_RemovesTheRowOfTheEffectivePrincipal_ClosesItsConnection_AndWritesNoLateCookie()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (bobCookie, bobKey, _) = await host.SignInAsync(Bob);
        host.Time.Advance(TimeSpan.FromHours(13));

        var reply = await host.SendAsync($"/test/issue-then-end-session?user={Alice}", bobCookie);

        var body = JsonDocument.Parse(reply.Body).RootElement;
        var fresh = body.GetProperty("key").GetString()!;
        var connection = body.GetProperty("connection").GetString()!;
        Assert.NotEqual(bobKey, fresh);
        Assert.False(await host.Db.KeyExistsAsync(fresh));
        Assert.Contains(connection, host.Replica.Aborted);
        Assert.All(reply.Cookies.Where(c => c.Name == host.CookieName), c => Assert.True(c.IsDeletion));
        Assert.False(await host.Db.KeyExistsAsync(bobKey));
    }

    [RedisFact]
    public async Task EndSession_AfterALateRenewalWasDue_CreatesNoRowAndNoCookieOfTheOldKey()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, key, _) = await host.SignInAsync(Alice);
        host.Time.Advance(TimeSpan.FromHours(13));

        var reply = await host.SendAsync("/test/end-session", cookie);

        Assert.False(await host.Db.KeyExistsAsync(key));
        Assert.Empty(reply.Sessions(host.CookieName));
    }

    [RedisFact]
    public async Task OrdinaryLogout_RemovesTheRow_AndClosesTheHub()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, key, _) = await host.SignInAsync(Alice);
        var hub = await host.SendAsync("/test/hub", cookie);
        var connection = JsonDocument.Parse(hub.Body).RootElement.GetProperty("connection").GetString()!;

        await host.SendAsync("/test/logout", cookie);

        Assert.False(await host.Db.KeyExistsAsync(key));
        Assert.Contains(connection, host.Replica.Aborted);
    }

    // ---- R70 ----------------------------------------------------------------------------------

    [RedisFact]
    public async Task ADecidedRenewal_DoesNotResurrectTheRow_AfterAParallelRevocation()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, key, _) = await host.SignInAsync(Alice);
        host.Time.Advance(TimeSpan.FromHours(13));
        var written = new TaskCompletionSource();
        var release = new TaskCompletionSource();
        host.Faults.After = async (name, _) =>
        {
            if (name == nameof(IDatabase.ScriptEvaluateAsync))
            {
                host.Faults.After = null; // only the renewal of the first request pauses
                written.SetResult();
                await release.Task;
            }
        };

        var first = host.SendAsync("/test/me", cookie);
        await written.Task.WaitAsync(TimeSpan.FromSeconds(10));
        await host.Store.RevokeAsync(key, new Microsoft.AspNetCore.Http.DefaultHttpContext(), CancellationToken.None);
        release.SetResult();
        await first; // its headers may carry the key: that is allowed

        Assert.False(await host.Db.KeyExistsAsync(key));
        var after = await host.SendAsync("/test/me", cookie);
        Assert.Equal(HttpStatusCode.Unauthorized, after.Status);
    }
}
