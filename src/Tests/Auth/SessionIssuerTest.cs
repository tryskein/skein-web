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

    /// <summary>
    /// Fails the revocation script of <paramref name="key"/>, and only once a read of a ticket has
    /// completed in the request (the failure is the revocation's, not the read's).
    /// </summary>
    private static Func<bool> FailRevocationAfterARead(SessionPipelineHost host, string key)
    {
        var read = false;
        var injected = false;
        host.Faults.After = (name, args) =>
        {
            if (DbProxy.IsScript(name, args, StoreScripts.Read))
            {
                read = true;
            }
            return Task.CompletedTask;
        };
        host.Faults.Before = (name, args) =>
        {
            if (read && DbProxy.IsScript(name, args, StoreScripts.Revoke, key))
            {
                injected = true;
                return new InvalidOperationException("injected");
            }
            return null;
        };
        return () => injected;
    }

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
        Assert.Equal(fresh, Assert.Single(RowsOf(host, Alice), k => k == fresh));
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

    [RedisFact]
    public async Task Rotation_ClosesTheHubConnectionOfTheOldKey_ThroughTheRealPath()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, key, _) = await host.SignInAsync(Alice);
        var hub = await host.SendAsync("/test/hub", cookie);
        var connection = JsonDocument.Parse(hub.Body).RootElement.GetProperty("connection").GetString()!;
        Assert.DoesNotContain(connection, host.Replica.Aborted); // control: open before the rotation

        await host.SendAsync($"/test/issue?user={Alice}", cookie);

        Assert.Contains(connection, host.Replica.Aborted);
        Assert.False(await host.Db.KeyExistsAsync(key));
    }

    // ---- R26 ----------------------------------------------------------------------------------

    [RedisFact]
    public async Task FailedRevocationOfTheOldKey_IssuesNothing_AndLeavesTheOldKeyToItsOwner()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (bobCookie, bobKey, _) = await host.SignInAsync(Bob);
        var injected = FailRevocationAfterARead(host, bobKey);

        var reply = await host.SendAsync($"/test/issue?user={Alice}", bobCookie);

        Assert.True(injected(), "the revocation was never reached after a read: the test proves nothing");
        Assert.False((int)reply.Status < 300);
        Assert.Empty(reply.Sessions(host.CookieName));
        Assert.True(await host.Db.KeyExistsAsync(bobKey));
        Assert.Empty(RowsOf(host, Alice));
        host.Faults.Before = null;
        host.Faults.After = null;
        var still = await host.SendAsync("/test/me", bobCookie);
        Assert.Contains(Bob.ToString(), still.Body); // the old key is still Bob's, not Alice's
    }

    [RedisFact]
    public async Task FailedWriteOfTheNewKey_AfterTheOldOneWasDeleted_IssuesNoCookie()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (bobCookie, bobKey, _) = await host.SignInAsync(Bob);
        var revoked = false;
        var injected = false;
        host.Faults.After = (name, args) =>
        {
            if (DbProxy.IsScript(name, args, StoreScripts.Revoke, bobKey))
            {
                revoked = true;
            }
            return Task.CompletedTask;
        };
        host.Faults.Before = (name, args) =>
        {
            if (revoked && DbProxy.IsScript(name, args, StoreScripts.Issue))
            {
                injected = true;
                return new InvalidOperationException("injected");
            }
            return null;
        };

        var reply = await host.SendAsync($"/test/issue?user={Alice}", bobCookie);

        Assert.True(injected, "the issue was never reached after the confirmed revocation: the test proves nothing");
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
        var injected = FailRevocationAfterARead(host, key);

        var reply = await host.SendAsync("/test/end-current", cookie);

        Assert.True(injected(), "the revocation was never reached after a read: the test proves nothing");
        Assert.False((int)reply.Status < 300);
        Assert.Empty(reply.Cookies);
        Assert.True(await host.Db.KeyExistsAsync(key));
    }

    [RedisFact]
    public async Task EndCurrent_AFailureAfterTheConfirmedDeletion_DoesNotChangeTheOutcome()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, key, _) = await host.SignInAsync(Alice);
        var injected = false;
        // The step that really follows the confirmed DEL: the removal of the member from the index.
        host.Faults.Before = (name, _) =>
        {
            if (name == nameof(IDatabase.SetRemoveAsync))
            {
                injected = true;
                return new InvalidOperationException("injected after the DEL");
            }
            return null;
        };

        var reply = await host.SendAsync("/test/end-current", cookie);

        Assert.True(injected, "the failure was never injected: the test proves nothing");
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
    public async Task EndSession_CreatesNoRowAndNoCookieOfTheOldKey()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, key, _) = await host.SignInAsync(Alice);

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

    // The only renewal left is the explicit one; it is held at its compare-and-set command, the one
    // command that could write the row again.
    [RedisFact]
    public async Task ADecidedRenewal_DoesNotResurrectTheRow_AfterAParallelRevocation()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, key, _) = await host.SignInAsync(Alice);
        var cas = host.Faults.Hold((name, args) => DbProxy.IsScript(name, args, StoreScripts.Renew, key));

        var renewal = host.SendAsync("/test/renew", cookie);
        await cas.Reached.WaitAsync(TimeSpan.FromSeconds(10)); // decided, not yet sent to Redis
        await host.Store.RevokeAsync(key, new Microsoft.AspNetCore.Http.DefaultHttpContext(), CancellationToken.None);
        cas.Release();
        var reply = await renewal;

        Assert.False(await host.Db.KeyExistsAsync(key));
        Assert.NotEqual("Written", JsonDocument.Parse(reply.Body).RootElement.GetProperty("outcome").GetString());
        Assert.DoesNotContain(reply.Cookies, c => c.Name == host.CookieName && !c.IsDeletion);
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.SendAsync("/test/me", cookie)).Status);
    }

    [RedisFact]
    public async Task AnAppliedRenewal_FollowedByARevocation_LeavesNoRow()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, key, _) = await host.SignInAsync(Alice);
        var written = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        host.Faults.After = async (name, args) =>
        {
            if (DbProxy.IsScript(name, args, StoreScripts.Renew, key))
            {
                written.TrySetResult();
                await release.Task;
            }
        };

        var renewal = host.SendAsync("/test/renew", cookie);
        await written.Task.WaitAsync(TimeSpan.FromSeconds(10)); // the compare-and-set has run
        host.Faults.After = null;
        await host.Store.RevokeAsync(key, new Microsoft.AspNetCore.Http.DefaultHttpContext(), CancellationToken.None);
        release.SetResult();
        await renewal; // its headers may carry the key: that is allowed

        Assert.False(await host.Db.KeyExistsAsync(key));
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.SendAsync("/test/me", cookie)).Status);
    }

    [RedisFact]
    public async Task Control_AnOrdinaryRequest_DoesNotRewriteTheTicket()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, key, _) = await host.SignInAsync(Alice);
        var before = (byte[])(await host.Db.StringGetAsync(key))!;

        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync("/test/me", cookie)).Status);

        Assert.Equal(before, (byte[])(await host.Db.StringGetAsync(key))!);
    }
}
