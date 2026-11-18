using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using SkeinWeb.Auth;
using SkeinWeb.Tests.Auth;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Controllers;

/// <summary>
/// The password reset on the real controller, handler and Redis, against an API model with epochs:
/// the complete outcome with a new key (a), the partial outcome (b), the confirmed change without a
/// session and the unknown outcome (c), and parallel sign-ins, an unindexed ticket and a cancelled
/// request (d, e). What the BFF does and what the API model refuses are observed separately.
/// </summary>
[Trait("Category", "Integration")]
[Collection("session-surfaces")]
public sealed class PasswordResetSessionTest
{
    private const string Token = "tok-1";
    private const string ResetPath = "/api/auth/password-reset/" + Token;
    private const string HandlerSessionIdClaim = "Microsoft.AspNetCore.Authentication.Cookies-SessionId";
    private static readonly Guid A = SurfacesApi.UserA;
    private static readonly Guid B = SurfacesApi.UserB;

    private static Task<SessionPipelineHost.Reply> ResetAsync(SurfacesHost host, string? cookie) =>
        host.SendAsync(HttpMethod.Post, ResetPath, new { password = "new password" }, cookie);

    private static string TypeOf(SessionPipelineHost.Reply r) =>
        JsonDocument.Parse(r.Body).RootElement.GetProperty("type").GetString()!;

    private static string CookieFor(SurfacesHost host, string key) =>
        $"{host.CookieName}={Uri.EscapeDataString(host.Services.GetRequiredService<TicketDataFormat>().Protect(new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity([new Claim(HandlerSessionIdClaim, key)], "Cookies")), "Cookies")))}";

    /// <summary>A ticket of <paramref name="user"/> with the given epoch, stored and indexed like an issue does.</summary>
    private static async Task<string> StoreTicketAsync(SurfacesHost host, Guid user, long epoch, string email)
    {
        var principal = SessionPrincipal.Create(
            new UserDto(user.ToString(), email, email.Split('@')[0], email.Split('@')[0], "user", null, null, false), epoch);
        return await host.Services.GetRequiredService<RedisTicketStore>().StoreAsync(
            new AuthenticationTicket(principal, new AuthenticationProperties(), SessionSchemes.Issue),
            new DefaultHttpContext(), CancellationToken.None);
    }

    private static Task<SessionPipelineHost.Reply> ProxyAsync(SurfacesHost host, string cookie) =>
        host.SendAsync(HttpMethod.Get, "/api/v1/projects", cookie: cookie);

    private static string ConnectionOf(SessionPipelineHost.Reply r) =>
        JsonDocument.Parse(r.Body).RootElement.GetProperty("connection").GetString()!;

    // ---- R45: outcome (a) ----------------------------------------------------------------------

    [RedisTheory]
    [InlineData("another-users-live")]
    [InlineData("own-live")]
    [InlineData("expired")]
    [InlineData("arbitrary")]
    [InlineData("no-cookie")]
    public async Task Complete_Is204_WithANewKey_AndEveryOldTicketOfTheUserEnds(string kind)
    {
        await using var host = await SurfacesHost.StartAsync();
        var (aliceCookie, aliceKey) = await host.SignInAsync("a@x.io");
        var (_, aliceOther) = await host.SignInAsync("a@x.io");
        var (bobCookie, bobKey) = await host.SignInAsync("b@x.io");
        var (bobOtherCookie, bobOther) = await host.SignInAsync("b@x.io"); // control: another ticket of the other user
        var onAlice = ConnectionOf(await host.SendAsync(HttpMethod.Get, "/test/hub", cookie: aliceCookie));
        var onBob = ConnectionOf(await host.SendAsync(HttpMethod.Get, "/test/hub", cookie: bobCookie));
        var onBobOther = ConnectionOf(await host.SendAsync(HttpMethod.Get, "/test/hub", cookie: bobOtherCookie));
        string? cookie;
        switch (kind)
        {
            case "another-users-live": cookie = bobCookie; break;
            case "own-live": cookie = aliceCookie; break;
            case "expired": await host.Db.KeyDeleteAsync(bobKey); cookie = bobCookie; break;
            case "arbitrary": cookie = $"{host.CookieName}=not-a-session-value"; break;
            default: cookie = null; break;
        }

        var reply = await ResetAsync(host, cookie);

        Assert.Equal(HttpStatusCode.NoContent, reply.Status);
        var set = Assert.Single(reply.Sessions(host.CookieName));
        var fresh = host.KeyOf(set);
        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync(HttpMethod.Get, "/test/me", cookie: set.AsRequestCookie())).Status);
        Assert.Equal(HttpStatusCode.OK, (await ProxyAsync(host, set.AsRequestCookie())).Status); // epoch of the new session is accepted
        Assert.Equal([fresh], host.IndexOf(A));
        Assert.False(await host.Db.KeyExistsAsync(aliceKey));
        Assert.False(await host.Db.KeyExistsAsync(aliceOther));
        Assert.Contains(onAlice, host.Replica.Aborted);
        Assert.True(await host.Db.KeyExistsAsync(bobOther));
        Assert.DoesNotContain(onBobOther, host.Replica.Aborted);
        if (kind == "another-users-live")
        {
            Assert.False(await host.Db.KeyExistsAsync(bobKey)); // the incoming key goes, whoever owns it
            Assert.Contains(onBob, host.Replica.Aborted);       // and so does its connection
            Assert.DoesNotContain(host.IndexOf(B), k => k == bobKey);
        }
        // The new key is revocable later: it is in the user's index.
        await host.Services.GetRequiredService<RedisTicketStore>().RemoveByUserIdAsync(A, CancellationToken.None);
        Assert.False(await host.Db.KeyExistsAsync(fresh));
    }

    // ---- R46: outcome (b) ----------------------------------------------------------------------

    private static void AssertPartial(SurfacesHost host, SessionPipelineHost.Reply reply)
    {
        Assert.Equal(HttpStatusCode.BadGateway, reply.Status);
        Assert.EndsWith("/password-changed-session-not-issued", TypeOf(reply));
        Assert.Equal("upstream_unavailable", JsonDocument.Parse(reply.Body).RootElement.GetProperty("error").GetString());
        Assert.Empty(reply.Cookies); // after OnStarting: no session cookie, not even a late renewal
        Assert.Equal(4, host.Api.EpochA);                  // the API model: changed
        Assert.Contains(Token, host.Api.SpentTokens);      // and the token is spent
    }

    internal static async Task MakeSlidingDueAsync(SurfacesHost host, string key)
    {
        var store = host.Services.GetRequiredService<RedisTicketStore>();
        var ticket = (await store.RetrieveAsync(key, new DefaultHttpContext(), CancellationToken.None))!;
        var issued = DateTimeOffset.UtcNow.AddHours(-13);
        ticket.Properties.IssuedUtc = issued;
        ticket.Properties.ExpiresUtc = issued.AddHours(24);
        await host.Db.StringSetAsync(key, TicketSerializer.Default.Serialize(ticket), TimeSpan.FromHours(24));
    }

    [RedisFact]
    public async Task Partial_WhenTheIncomingKeyCannotBeDeleted_Is502_WithNoCookie_AndTheRowIsNotRewritten()
    {
        await using var host = await SurfacesHost.StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        var onAlice = ConnectionOf(await host.SendAsync(HttpMethod.Get, "/test/hub", cookie: cookie));
        await MakeSlidingDueAsync(host, key);
        byte[] before = (await host.Db.StringGetAsync(key))!;
        // The key cannot be deleted by either of the two ways the sequence has: the revocation of the incoming
        // key and the removal by the user's index.
        host.Faults.Before = (name, args) =>
            name == nameof(IDatabase.ScriptEvaluateAsync)
            || (name == nameof(IDatabase.KeyDeleteAsync) && ((RedisKey)args[0]!).ToString() == key)
                ? new InvalidOperationException("injected") : null;

        var reply = await ResetAsync(host, cookie);

        host.Faults.Before = null;
        AssertPartial(host, reply);
        Assert.Equal(before, (byte[])(await host.Db.StringGetAsync(key))!);
        Assert.Contains(onAlice, host.Replica.Aborted); // connections close even though a ticket stays
    }

    [RedisFact]
    public async Task Partial_WhenATicketOfTheUserCannotBeDeleted_ItStaysWithItsOwner_AndTheApiRefusesByEpoch()
    {
        await using var host = await SurfacesHost.StartAsync();
        var (oldCookie, oldKey) = await host.SignInAsync("a@x.io"); // epoch 3
        var newEpochKey = await StoreTicketAsync(host, A, 4, "a@x.io");
        var stuckKeys = new HashSet<string> { oldKey, newEpochKey };
        host.Faults.Before = (name, args) =>
            name == nameof(IDatabase.KeyDeleteAsync) && stuckKeys.Contains(((RedisKey)args[0]!).ToString())
                ? new InvalidOperationException("injected") : null;

        var reply = await ResetAsync(host, null);

        host.Faults.Before = null;
        AssertPartial(host, reply);
        Assert.True(await host.Db.KeyExistsAsync(oldKey));
        Assert.True(await host.Db.KeyExistsAsync(newEpochKey));
        // The ticket of the former epoch is refused by the API and ends; the one of the new epoch is accepted.
        var refused = await ProxyAsync(host, oldCookie);
        Assert.Equal(HttpStatusCode.Unauthorized, refused.Status);
        Assert.False(await host.Db.KeyExistsAsync(oldKey));
        Assert.Equal(HttpStatusCode.OK, (await ProxyAsync(host, CookieFor(host, newEpochKey))).Status);
    }

    [RedisFact]
    public async Task Partial_ForeignIncomingKeyThatCannotBeDeleted_StaysAcceptedForItsOwner()
    {
        await using var host = await SurfacesHost.StartAsync();
        var (bobCookie, bobKey) = await host.SignInAsync("b@x.io");
        host.Faults.Before = (name, args) =>
            name == nameof(IDatabase.ScriptEvaluateAsync) && args[1] is RedisKey[] keys && keys.Any(k => k.ToString() == bobKey)
                ? new InvalidOperationException("injected") : null;

        var reply = await ResetAsync(host, bobCookie);

        host.Faults.Before = null;
        AssertPartial(host, reply);
        Assert.True(await host.Db.KeyExistsAsync(bobKey));
        Assert.Empty(host.IndexOf(A)); // never rewritten as the reset user's
        Assert.Equal(HttpStatusCode.OK, (await ProxyAsync(host, bobCookie)).Status);
    }

    [RedisFact]
    public async Task Partial_WhenTheIndexCannotBeRead_IsTheSameOutcome()
    {
        await using var host = await SurfacesHost.StartAsync();
        var (_, key) = await host.SignInAsync("a@x.io");
        host.Faults.Before = (name, _) => name == nameof(IDatabase.SetMembersAsync) ? new InvalidOperationException("injected") : null;

        var reply = await ResetAsync(host, null);

        host.Faults.Before = null;
        AssertPartial(host, reply);
        Assert.True(await host.Db.KeyExistsAsync(key));
    }

    // ---- R47: outcome (c) ----------------------------------------------------------------------

    private static Func<HttpRequestMessage, HttpResponseMessage?> ConfirmedBut(SurfacesHost host, string body) => r =>
    {
        if (!r.RequestUri!.AbsolutePath.StartsWith("/ui/v1/auth/password-reset/", StringComparison.Ordinal))
        {
            return null;
        }
        // The API changed the password and spent the token; only its answer is unusable.
        host.Api.EpochA = 4;
        host.Api.SpentTokens.Add(Token);
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json"),
        };
    };

    [RedisTheory]
    [InlineData("no-id")]
    [InlineData("no-epoch")]
    [InlineData("unusable-claims")]
    [InlineData("issue-fails")]
    public async Task ConfirmedChangeWithoutASession_IsPasswordChanged_AndRevokesWhenTheSubjectIsKnown(string kind)
    {
        await using var host = await SurfacesHost.StartAsync();
        var (_, key) = await host.SignInAsync("a@x.io");
        var user = SurfacesApi.UserJson(A, "a@x.io", 4);
        host.Api.Override = ConfirmedBut(host, kind switch
        {
            "no-id" => "{\"sessionEpoch\":4}",
            "no-epoch" => user.Replace(",\"sessionEpoch\":4", ""),
            "unusable-claims" => "{\"id\":\"" + A + "\",\"sessionEpoch\":4}",
            _ => user,
        });
        if (kind == "issue-fails")
        {
            host.Faults.Before = (name, _) => name == nameof(IDatabase.StringSetAsync) ? new InvalidOperationException("injected") : null;
        }

        var reply = await ResetAsync(host, null);

        host.Faults.Before = null;
        AssertPartial(host, reply);
        if (kind == "no-id")
        {
            Assert.True(await host.Db.KeyExistsAsync(key)); // no subject: no obligation to revoke
        }
        else
        {
            Assert.False(await host.Db.KeyExistsAsync(key)); // the subject is known: revoked
        }
    }

    [RedisFact]
    public async Task UnknownOutcome_IsTheUnavailableError_WithNoClaimAboutTheChange_AndTicketsIntact()
    {
        await using var host = await SurfacesHost.StartAsync();
        var (_, key) = await host.SignInAsync("a@x.io");
        host.Api.Override = r => r.RequestUri!.AbsolutePath.StartsWith("/ui/v1/auth/password-reset/", StringComparison.Ordinal)
            ? throw new HttpRequestException("answer lost")
            : null;

        var reply = await ResetAsync(host, null);

        Assert.Equal(HttpStatusCode.BadGateway, reply.Status);
        Assert.EndsWith("/upstream-unavailable", TypeOf(reply));
        Assert.DoesNotContain("changed", reply.Body, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(reply.Cookies);
        Assert.True(await host.Db.KeyExistsAsync(key));
    }

    [RedisFact]
    public async Task StoreFailureBeforeTheApiCall_IsTheUnavailableError_AndTheApiIsNotCalled()
    {
        await using var host = await SurfacesHost.StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        host.Faults.Before = (name, _) => name == nameof(IDatabase.StringGetAsync) ? new InvalidOperationException("injected") : null;

        var reply = await ResetAsync(host, cookie);

        host.Faults.Before = null;
        Assert.Equal(HttpStatusCode.BadGateway, reply.Status);
        Assert.EndsWith("/upstream-unavailable", TypeOf(reply));
        Assert.Equal(0, host.Api.CallsTo("/ui/v1/auth/password-reset/" + Token));
        Assert.True(await host.Db.KeyExistsAsync(key));
    }

    // ---- R48: outcomes (d), (e) and cancellation -------------------------------------------------

    /// <summary>Holds the reset right after it read the user's index, runs <paramref name="meanwhile"/>, then lets it go.</summary>
    private static async Task<SessionPipelineHost.Reply> ResetWithAConcurrentStepAsync(
        SurfacesHost host, string? cookie, Func<Task> meanwhile)
    {
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        host.Faults.After = async (name, _) =>
        {
            if (name == nameof(IDatabase.SetMembersAsync))
            {
                host.Faults.After = null;
                reached.SetResult();
                await release.Task;
            }
        };
        var reset = ResetAsync(host, cookie);
        await reached.Task.WaitAsync(TimeSpan.FromSeconds(10));
        await meanwhile();
        release.SetResult();
        return await reset;
    }

    [RedisTheory]
    [InlineData(3, HttpStatusCode.Unauthorized)] // a login confirmed in the FORMER epoch, written after the index was read
    [InlineData(4, HttpStatusCode.OK)]           // a login of the NEW epoch: an ordinary sign-in
    public async Task AParallelLogin_WrittenAfterTheIndexRead_Stays_AndTheApiDecidesByEpoch(long epoch, HttpStatusCode firstProxyCall)
    {
        await using var host = await SurfacesHost.StartAsync();
        var (_, lying) = await host.SignInAsync("a@x.io"); // there when the pass starts
        string? lateCookie = null;
        string? lateKey = null;

        var reply = await ResetWithAConcurrentStepAsync(host, null, async () =>
        {
            host.Api.Override = r => r.RequestUri!.AbsolutePath == "/ui/v1/auth/login"
                ? new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(SurfacesApi.UserJson(A, "a@x.io", epoch), System.Text.Encoding.UTF8, "application/json"),
                }
                : null;
            var login = await host.LoginAsync("a@x.io");
            var set = login.Sessions(host.CookieName).Single();
            lateCookie = set.AsRequestCookie();
            lateKey = host.KeyOf(set);
        });

        Assert.Equal(HttpStatusCode.NoContent, reply.Status); // the pass completed over what it had read
        Assert.False(await host.Db.KeyExistsAsync(lying));    // the ticket lying there is gone
        Assert.True(await host.Db.KeyExistsAsync(lateKey!));  // the one written later stays: an accepted remainder of the BFF
        Assert.Equal(firstProxyCall, (await ProxyAsync(host, lateCookie!)).Status);
        if (firstProxyCall == HttpStatusCode.Unauthorized)
        {
            Assert.False(await host.Db.KeyExistsAsync(lateKey!)); // the revoked session ends
        }
    }

    [RedisFact]
    public async Task ATicketOutsideTheReadIndex_MayOutliveA204_ButTheOutcomeIsStillComplete()
    {
        await using var host = await SurfacesHost.StartAsync();
        var (_, kept) = await host.SignInAsync("a@x.io");
        var (_, listed) = await host.SignInAsync("a@x.io");
        await host.Db.SetRemoveAsync("skein:user-tickets:" + A, kept); // an index maintenance gap

        var reply = await ResetAsync(host, null);

        Assert.Equal(HttpStatusCode.NoContent, reply.Status);
        Assert.False(await host.Db.KeyExistsAsync(listed));
        Assert.Single(reply.Sessions(host.CookieName));
        // Nothing is asserted about 'kept': it is the accepted remainder.
    }

    [RedisFact]
    public async Task ACancelledRequest_AfterTheChangeIsConfirmed_StillEndsTheSessions_AndIssuesTheNewKey()
    {
        await using var host = await SurfacesHost.StartAsync();
        var (_, old) = await host.SignInAsync("a@x.io");
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        host.Faults.After = async (name, _) =>
        {
            if (name == nameof(IDatabase.SetMembersAsync))
            {
                host.Faults.After = null;
                reached.SetResult();
                await release.Task;
            }
        };
        using var cancel = new CancellationTokenSource();
        using var client = new HttpClient { BaseAddress = new Uri(host.Services.GetRequiredService<Microsoft.AspNetCore.Hosting.Server.IServer>()
            .Features.Get<Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>()!.Addresses.First()) };
        var request = client.PostAsJsonAsync(ResetPath, new { password = "new password" }, cancel.Token);
        await reached.Task.WaitAsync(TimeSpan.FromSeconds(10)); // the API has confirmed the change; the pass is running
        await cancel.CancelAsync();
        await Task.Delay(500); // the server sees the abort
        release.SetResult();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => request);
        // The client is gone, so the answer is not observable; its effects are.
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (DateTime.UtcNow < deadline && (await host.Db.KeyExistsAsync(old) || host.IndexOf(A).Count == 0))
        {
            await Task.Delay(50);
        }
        Assert.False(await host.Db.KeyExistsAsync(old));
        var issued = Assert.Single(host.IndexOf(A));
        var ticket = await host.Services.GetRequiredService<RedisTicketStore>().RetrieveAsync(issued, new DefaultHttpContext(), CancellationToken.None);
        Assert.Equal("4", ticket!.Principal.FindFirst(SessionPrincipal.SessionEpochClaim)!.Value);
    }
}
