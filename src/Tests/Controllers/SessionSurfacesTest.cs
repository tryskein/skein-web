using System.Net;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using SkeinWeb.Tests.Auth;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Controllers;

/// <summary>
/// The login and registration surfaces on the real controllers, handler and a real Redis: every kind
/// of incoming cookie gets a new key, a failure gives the surface's own error and no cookie, other
/// sessions and their hub connections are left alone, and two overlapping logins do not undo each other.
/// </summary>
[Trait("Category", "Integration")]
[Collection("session-surfaces")]
public sealed class SessionSurfacesTest
{
    private static readonly Guid A = SurfacesApi.UserA;
    private static readonly Guid B = SurfacesApi.UserB;

    private static readonly (string Path, object Body)[] Registrations =
    [
        ("/api/auth/signup", new { email = "dev@client.io", username = "dev", password = "correct horse", termsAccepted = true, language = "en" }),
        ("/api/auth/invitations/tok-1/signup", new { username = "dev", password = "correct horse", termsAccepted = true, language = "en" }),
    ];

    private static JsonElement Json(SessionPipelineHost.Reply r) => JsonDocument.Parse(r.Body).RootElement;

    private static async Task<(string Cookie, string Key, string Other)> SessionsOfAsync(SurfacesHost host, string kind)
    {
        // B holds K; A holds K1 (and, for "own-live", is the one logging in with it).
        var (bobCookie, bobKey) = await host.SignInAsync("b@x.io");
        var (aliceCookie, aliceKey) = await host.SignInAsync("a@x.io");
        var (_, controlKey) = await host.SignInAsync("a@x.io"); // another browser of A: never touched
        return kind switch
        {
            "another-users-live" => (bobCookie, bobKey, controlKey),
            "own-live" => (aliceCookie, aliceKey, controlKey),
            "expired" => await ExpiredAsync(host, bobCookie, bobKey, controlKey),
            "arbitrary" => ($"{host.CookieName}=not-a-session-value", "-", controlKey),
            _ => ($"{bobCookie}; __Host-skein.sid=not-a-session-value", bobKey, controlKey),
        };
    }

    private static async Task<(string, string, string)> ExpiredAsync(SurfacesHost host, string cookie, string key, string control)
    {
        await host.Db.KeyDeleteAsync(key);
        return (cookie, key, control); // the key stays known: the new key must differ from it
    }

    // ---- R40 ----------------------------------------------------------------------------------

    [RedisTheory]
    [InlineData("another-users-live")]
    [InlineData("own-live")]
    [InlineData("expired")]
    [InlineData("arbitrary")]
    [InlineData("both-names")]
    public async Task Login_IssuesANewKey_AndKillsTheOldOne(string kind)
    {
        await using var host = await SurfacesHost.StartAsync();
        var (cookie, old, control) = await SessionsOfAsync(host, kind);
        if (kind == "another-users-live")
        {
            Assert.Equal(HttpStatusCode.OK, (await host.SendAsync(HttpMethod.Get, "/test/me", cookie: cookie)).Status); // control: B's session works
        }

        var reply = await host.LoginAsync("a@x.io", cookie: cookie);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        var set = Assert.Single(reply.Sessions(host.CookieName));
        Assert.Contains("expires=", set.Raw, StringComparison.OrdinalIgnoreCase); // a login cookie is persistent: the contrast with OIDC
        var fresh = host.KeyOf(set);
        Assert.NotEqual(old, fresh);
        Assert.True(await host.Db.KeyExistsAsync(fresh));
        Assert.Contains(fresh, host.IndexOf(A));
        if (old != "-")
        {
            Assert.False(await host.Db.KeyExistsAsync(old));
            Assert.DoesNotContain(old, host.IndexOf(A)); // A's ticket was never written under the old key
            Assert.Equal(HttpStatusCode.Unauthorized, (await host.SendAsync(HttpMethod.Get, "/test/me", cookie: cookie.Split(';')[0])).Status);
        }
        Assert.True(await host.Db.KeyExistsAsync(control)); // another browser of A stays
    }

    // ---- R41 ----------------------------------------------------------------------------------

    [RedisFact]
    public async Task Login_WithAWrongPassword_LeavesTheLiveSessionAlone_AndSetsNoCookie()
    {
        await using var host = await SurfacesHost.StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");

        var reply = await host.LoginAsync("a@x.io", "wrong", cookie);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, reply.Status);
        Assert.Empty(reply.Cookies);
        Assert.True(await host.Db.KeyExistsAsync(key));
        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync(HttpMethod.Get, "/test/me", cookie: cookie)).Status);
    }

    private static void AssertLoginRefusalShape(SessionPipelineHost.Reply reply)
    {
        Assert.Equal(HttpStatusCode.BadGateway, reply.Status);
        Assert.Empty(reply.Cookies);
        var body = Json(reply);
        Assert.EndsWith("/upstream-unavailable", body.GetProperty("type").GetString());
        Assert.False(body.TryGetProperty("error", out _));
    }

    [RedisFact]
    public async Task Login_WhenTheOldKeyCannotBeDeleted_Is502WithoutError_AndTheOldKeyLives()
    {
        await using var host = await SurfacesHost.StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        var injected = false;
        host.Faults.Before = (name, _) =>
        {
            if (name == nameof(IDatabase.ScriptEvaluateAsync))
            {
                injected = true;
                return new InvalidOperationException("injected");
            }
            return null;
        };

        var reply = await host.LoginAsync("a@x.io", cookie: cookie);

        Assert.True(injected);
        AssertLoginRefusalShape(reply);
        host.Faults.Before = null;
        Assert.True(await host.Db.KeyExistsAsync(key));
    }

    [RedisFact]
    public async Task Login_WhenTheNewKeyCannotBeWritten_AfterTheDeletion_Is502WithoutError_AndTheOldKeyIsDead()
    {
        await using var host = await SurfacesHost.StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        var injected = false;
        host.Faults.Before = (name, _) =>
        {
            if (name == nameof(IDatabase.StringSetAsync))
            {
                injected = true;
                return new InvalidOperationException("injected");
            }
            return null;
        };

        var reply = await host.LoginAsync("a@x.io", cookie: cookie);

        Assert.True(injected);
        AssertLoginRefusalShape(reply);
        host.Faults.Before = null;
        Assert.False(await host.Db.KeyExistsAsync(key));
    }

    // ---- R42 ----------------------------------------------------------------------------------

    [RedisFact]
    public async Task ASecondLogin_ClosesOnlyTheHubConnectionOfTheReplacedKey()
    {
        await using var host = await SurfacesHost.StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        var (otherCookie, otherKey) = await host.SignInAsync("a@x.io");
        var onOld = JsonDocument.Parse((await host.SendAsync(HttpMethod.Get, "/test/hub", cookie: cookie)).Body).RootElement.GetProperty("connection").GetString()!;
        var onOther = JsonDocument.Parse((await host.SendAsync(HttpMethod.Get, "/test/hub", cookie: otherCookie)).Body).RootElement.GetProperty("connection").GetString()!;

        var reply = await host.LoginAsync("a@x.io", cookie: cookie);

        Assert.Single(reply.Sessions(host.CookieName));
        Assert.Contains(onOld, host.Replica.Aborted);
        Assert.DoesNotContain(onOther, host.Replica.Aborted);
        Assert.True(await host.Db.KeyExistsAsync(otherKey));
        Assert.False(await host.Db.KeyExistsAsync(key));
    }

    [RedisTheory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task ARegistration_ClosesTheHubConnectionOfTheReplacedKey(int which)
    {
        await using var host = await SurfacesHost.StartAsync();
        var (cookie, _) = await host.SignInAsync("a@x.io");
        var connection = JsonDocument.Parse((await host.SendAsync(HttpMethod.Get, "/test/hub", cookie: cookie)).Body).RootElement.GetProperty("connection").GetString()!;

        var reply = await host.SendAsync(HttpMethod.Post, Registrations[which].Path, Registrations[which].Body, cookie);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        Assert.Contains(connection, host.Replica.Aborted);
    }

    // ---- R43 ----------------------------------------------------------------------------------

    [RedisTheory]
    [InlineData(0, "another-users-live")]
    [InlineData(0, "own-live")]
    [InlineData(0, "expired")]
    [InlineData(0, "arbitrary")]
    [InlineData(1, "another-users-live")]
    [InlineData(1, "own-live")]
    [InlineData(1, "expired")]
    [InlineData(1, "arbitrary")]
    public async Task Registration_IssuesANewKey_WithTheEpochOfTheAnswer(int which, string kind)
    {
        await using var host = await SurfacesHost.StartAsync();
        var (cookie, old, control) = await SessionsOfAsync(host, kind);

        var reply = await host.SendAsync(HttpMethod.Post, Registrations[which].Path, Registrations[which].Body, cookie);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        var set = Assert.Single(reply.Sessions(host.CookieName));
        var fresh = host.KeyOf(set);
        Assert.NotEqual(old, fresh);
        if (old != "-")
        {
            Assert.False(await host.Db.KeyExistsAsync(old));
        }
        var ticket = await host.Services.GetRequiredService<SkeinWeb.Auth.RedisTicketStore>()
            .RetrieveAsync(fresh, new Microsoft.AspNetCore.Http.DefaultHttpContext(), CancellationToken.None);
        Assert.Equal("4", ticket!.Principal.FindFirst(SkeinWeb.Auth.SessionPrincipal.SessionEpochClaim)!.Value);
        Assert.True(await host.Db.KeyExistsAsync(control));
        if (which == 1)
        {
            Assert.True(Json(reply).TryGetProperty("space", out _));
        }
    }

    // ---- R44 ----------------------------------------------------------------------------------

    private static Func<HttpRequestMessage, HttpResponseMessage?> Answer(string pathEnd, HttpStatusCode status, string body) =>
        r => r.RequestUri!.AbsolutePath.EndsWith(pathEnd, StringComparison.Ordinal)
            ? new HttpResponseMessage(status) { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") }
            : null;

    [RedisTheory]
    [InlineData(0, "no-user")]
    [InlineData(0, "no-epoch")]
    [InlineData(1, "no-user")]
    [InlineData(1, "no-epoch")]
    [InlineData(1, "no-space")]
    [InlineData(0, "bad-id")]
    [InlineData(1, "empty-space")]
    public async Task Registration_ConfirmedWithUnusableData_IsAccountCreatedNotSignedIn(int which, string kind)
    {
        await using var host = await SurfacesHost.StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        var user = SurfacesApi.UserJson(A, "a@x.io", 4, space: true);
        var body = kind switch
        {
            "no-user" => "{}",
            "no-epoch" => user.Replace(",\"sessionEpoch\":4", ""),
            "bad-id" => user.Replace(A.ToString(), "not-a-uuid"),
            "empty-space" => user.Replace("{\"id\":\"k3x9p2qa\",\"slug\":\"acme\",\"name\":\"Acme\"}", "{}"),
            _ => user.Replace(",\"space\":{\"id\":\"k3x9p2qa\",\"slug\":\"acme\",\"name\":\"Acme\"}", ""),
        };
        host.Api.Override = Answer("/signup", HttpStatusCode.OK, body);
        await PasswordResetSessionTest.MakeSlidingDueAsync(host, key); // a sliding renewal is due on the incoming session

        var reply = await host.SendAsync(HttpMethod.Post, Registrations[which].Path, Registrations[which].Body, cookie);

        Assert.Equal(HttpStatusCode.BadGateway, reply.Status);
        Assert.Empty(reply.Cookies); // and it is not written beside the refusal
        var problem = Json(reply);
        Assert.Equal("upstream_unavailable", problem.GetProperty("error").GetString());
        Assert.EndsWith("/account-created-session-not-issued", problem.GetProperty("type").GetString());
        Assert.True(await host.Db.KeyExistsAsync(key)); // the issuer was not called: nothing was revoked
        Assert.Equal(1, host.Api.Calls.Count(c => c.EndsWith("/signup", StringComparison.Ordinal)));
        Assert.Contains(host.Logs.Entries, e => e.Level == Microsoft.Extensions.Logging.LogLevel.Error);
    }

    [RedisTheory]
    [InlineData(0, "delete")]
    [InlineData(0, "write")]
    [InlineData(1, "delete")]
    [InlineData(1, "write")]
    public async Task Registration_WhenTheIssueFails_IsAccountCreatedNotSignedIn(int which, string failing)
    {
        await using var host = await SurfacesHost.StartAsync();
        var (cookie, _) = await host.SignInAsync("a@x.io");
        var method = failing == "delete" ? nameof(IDatabase.ScriptEvaluateAsync) : nameof(IDatabase.StringSetAsync);
        host.Faults.Before = (name, _) => name == method ? new InvalidOperationException("injected") : null;

        var reply = await host.SendAsync(HttpMethod.Post, Registrations[which].Path, Registrations[which].Body, cookie);

        Assert.Equal(HttpStatusCode.BadGateway, reply.Status);
        Assert.Empty(reply.Cookies);
        Assert.EndsWith("/account-created-session-not-issued", Json(reply).GetProperty("type").GetString());
    }

    [RedisTheory]
    [InlineData(0, 201)]
    [InlineData(0, 500)]
    [InlineData(1, 201)]
    [InlineData(1, 500)]
    public async Task Registration_NotConfirmed_IsTheOrdinaryUpstreamError(int which, int status)
    {
        await using var host = await SurfacesHost.StartAsync();
        host.Api.Override = Answer("/signup", (HttpStatusCode)status, SurfacesApi.UserJson(A, "a@x.io", 4, space: true));

        var reply = await host.SendAsync(HttpMethod.Post, Registrations[which].Path, Registrations[which].Body);

        Assert.Equal(HttpStatusCode.BadGateway, reply.Status);
        Assert.Empty(reply.Cookies);
        Assert.EndsWith("/upstream-unavailable", Json(reply).GetProperty("type").GetString());
    }

    // ---- R69 ----------------------------------------------------------------------------------

    [RedisFact]
    public async Task TwoOverlappingLogins_WithOneCookie_BothGetTheirOwnLiveKey()
    {
        await using var host = await SurfacesHost.StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        host.Faults.After = async (name, _) =>
        {
            if (name == nameof(IDatabase.ScriptEvaluateAsync))
            {
                host.Faults.After = null; // only the first revocation waits, right after its deletion
                reached.SetResult();
                await release.Task;
            }
        };

        var first = host.LoginAsync("a@x.io", cookie: cookie);
        await reached.Task.WaitAsync(TimeSpan.FromSeconds(10));
        var second = await host.LoginAsync("a@x.io", cookie: cookie); // meets the already deleted key
        release.SetResult();
        var firstReply = await first;

        var firstSet = Assert.Single(firstReply.Sessions(host.CookieName));
        var secondSet = Assert.Single(second.Sessions(host.CookieName));
        var k1 = host.KeyOf(firstSet);
        var k2 = host.KeyOf(secondSet);
        Assert.NotEqual(k1, k2);
        Assert.DoesNotContain(key, new[] { k1, k2 });
        Assert.False(await host.Db.KeyExistsAsync(key));
        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync(HttpMethod.Get, "/test/me", cookie: firstSet.AsRequestCookie())).Status);
        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync(HttpMethod.Get, "/test/me", cookie: secondSet.AsRequestCookie())).Status);
    }
}
