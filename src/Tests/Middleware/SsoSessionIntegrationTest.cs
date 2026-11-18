using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using SkeinWeb.Auth;
using SkeinWeb.Tests.Auth;
using SkeinWeb.Tests.Controllers;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Middleware;

/// <summary>
/// The trust-headers (oauth2-proxy) middleware on the real controllers, issuer, store (real Redis) and cookie
/// schemes, against an API model: the local comparison of the remembered pair, the confirmation of the subject
/// and its three branches (another user, the same user in another epoch, the same user and epoch), the
/// outcomes of the renewal, the trust boundary, the explicit operations and the refusals.
/// </summary>
[Trait("Category", "Integration")]
[Collection("session-surfaces")]
public sealed class SsoSessionIntegrationTest
{
    private const string Provision = "/ui/v1/auth/oidc/provision";
    private const string HandlerSessionIdClaim = "Microsoft.AspNetCore.Authentication.Cookies-SessionId";
    private const string RefreshedAtClaim = "urn:skein:refreshed-at";
    private static readonly Guid A = SurfacesApi.UserA;
    private static readonly Guid B = SurfacesApi.UserB;

    // The headers oauth2-proxy sends: they differ from the canonical profile ("a@x.io" / "a"), so a
    // comparison against the profile would never match.
    private static readonly (string, string)[] HeadersA = [("X-Auth-Request-Email", "pa@corp.io"), ("X-Auth-Request-User", "pa")];
    private static readonly (string, string)[] HeadersB = [("X-Auth-Request-Email", "b@corp.io"), ("X-Auth-Request-User", "b")];

    private static Task<SurfacesHost> StartAsync() => SurfacesHost.StartAsync(trustHeaders: true);

    private static Task<SessionPipelineHost.Reply> GetAsync(
        SurfacesHost host, string? cookie, (string, string)[] headers, string path = "/test/me") =>
        host.SendAsync(HttpMethod.Get, path, null, cookie, headers);

    private static string ErrorOf(SessionPipelineHost.Reply r) =>
        JsonDocument.Parse(r.Body).RootElement.GetProperty("error").GetString()!;

    private static string UserOf(SessionPipelineHost.Reply r) =>
        JsonDocument.Parse(r.Body).RootElement.GetProperty("user").GetString()!;

    private static RedisTicketStore Store(SurfacesHost host) => host.Services.GetRequiredService<RedisTicketStore>();

    private static async Task<AuthenticationTicket> StoredAsync(SurfacesHost host, string key) =>
        (await Store(host).RetrieveAsync(key, new DefaultHttpContext(), CancellationToken.None))!;

    private static int SessionRows(SurfacesHost host) =>
        host.Mux.GetServers().First(s => !s.IsReplica).Keys(SurfacesHost.Database, "skein:session:*").Count();

    private static async Task<(string Cookie, string Key)> BootstrapAsync(SurfacesHost host, (string, string)[]? headers = null)
    {
        var reply = await GetAsync(host, null, headers ?? HeadersA);
        Assert.Equal(HttpStatusCode.OK, reply.Status);
        var set = Assert.Single(reply.Sessions(host.CookieName));
        return (set.AsRequestCookie(), host.KeyOf(set));
    }

    private static Func<HttpRequestMessage, HttpResponseMessage?> Provisioned(string body, Action? before = null) => r =>
    {
        if (r.RequestUri!.AbsolutePath != Provision)
        {
            return null;
        }
        before?.Invoke();
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    };

    /// <summary>The session of <paramref name="key"/> is due its periodic refresh: its stamp is old.</summary>
    private static async Task AgeRefreshAsync(SurfacesHost host, string key)
    {
        var ticket = await StoredAsync(host, key);
        var identity = (ClaimsIdentity)ticket.Principal.Identity!;
        foreach (var claim in identity.FindAll(RefreshedAtClaim).ToArray())
        {
            identity.RemoveClaim(claim);
        }
        identity.AddClaim(new Claim(RefreshedAtClaim, DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds().ToString()));
        await host.Db.StringSetAsync(key, TicketSerializer.Default.Serialize(ticket), TimeSpan.FromHours(24));
    }

    private static string WithRole(string json, string role) => json.Replace("\"role\":\"user\"", $"\"role\":\"{role}\"");

    // ---- R64: the first sign-in by headers and the four kinds of incoming cookie ---------------------

    [RedisFact]
    public async Task Bootstrap_WithNoCookie_IssuesASessionWithThePairInTheNewTicket()
    {
        await using var host = await StartAsync();

        var reply = await GetAsync(host, null, HeadersA);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        var set = Assert.Single(reply.Sessions(host.CookieName));
        var key = host.KeyOf(set);
        Assert.Equal(A.ToString(), UserOf(reply));
        Assert.Equal(1, host.Api.CallsTo(Provision));
        var stored = await StoredAsync(host, key);
        Assert.Equal("pa@corp.io", stored.Properties.Items[RedisTicketStore.SsoEmailItem]);
        Assert.Equal("pa", stored.Properties.Items[RedisTicketStore.SsoUserItem]);
        Assert.Equal([key], host.IndexOf(A));
    }

    [RedisTheory]
    [InlineData("another-users-live")]
    [InlineData("expired")]
    [InlineData("arbitrary")]
    public async Task Bootstrap_WithAnyOtherCookie_IssuesANewKey_AndTheOldOneIsDead(string kind)
    {
        await using var host = await StartAsync();
        var (bobCookie, bobKey) = await host.SignInAsync("b@x.io");
        var cookie = kind switch
        {
            "another-users-live" => bobCookie,
            "expired" => bobCookie,
            _ => $"{host.CookieName}=not-a-session-value",
        };
        if (kind == "expired")
        {
            await host.Db.KeyDeleteAsync(bobKey);
        }

        var reply = await GetAsync(host, cookie, HeadersA);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        var set = Assert.Single(reply.Sessions(host.CookieName));
        var fresh = host.KeyOf(set);
        Assert.NotEqual(bobKey, fresh);
        Assert.Equal(A.ToString(), UserOf(reply));
        if (kind != "arbitrary") // an unreadable cookie names no key: nothing of B's is touched by it
        {
            Assert.False(await host.Db.KeyExistsAsync(bobKey));
            Assert.Equal(HttpStatusCode.Unauthorized, (await host.SendAsync(HttpMethod.Get, "/test/me", cookie: bobCookie)).Status);
        }
    }

    // ---- R57: the local comparison -------------------------------------------------------------------

    [RedisFact]
    public async Task AMatchingPair_IsLocal_NoCallToSkeinApi_AndTheKeyStays()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await BootstrapAsync(host);
        byte[] before = (await host.Db.StringGetAsync(key))!;

        var reply = await GetAsync(host, cookie, HeadersA);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        Assert.Equal(1, host.Api.CallsTo(Provision)); // the bootstrap's call only
        Assert.Empty(reply.Sessions(host.CookieName));
        Assert.Equal(before, (byte[])(await host.Db.StringGetAsync(key))!); // not due: the ticket is not rewritten by a read
    }

    [RedisFact]
    public async Task AMatchingPair_RenewalWritesTheTicketByThePrincipal_WhenItIsDue()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await BootstrapAsync(host);
        await PasswordResetSessionTest.MakeSlidingDueAsync(host, key);
        var oldExpiry = (await StoredAsync(host, key)).Properties.ExpiresUtc;

        var reply = await GetAsync(host, cookie, HeadersA);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        Assert.Equal(1, host.Api.CallsTo(Provision)); // still local
        var stored = await StoredAsync(host, key);
        Assert.True(stored.Properties.ExpiresUtc > oldExpiry); // the ticket itself moved on, not only the row's TTL
        Assert.Equal("pa@corp.io", stored.Properties.Items[RedisTicketStore.SsoEmailItem]);
    }

    [RedisTheory]
    [InlineData("PA@corp.io", "pa")]
    [InlineData("pa@corp.io", "PA")]
    public async Task APairThatDiffersOnlyInCase_IsConfirmed_AndTheNewPairIsRememberedExactly(string email, string username)
    {
        await using var host = await StartAsync();
        var (cookie, key) = await BootstrapAsync(host);
        (string, string)[] headers = [("X-Auth-Request-Email", email), ("X-Auth-Request-User", username)];

        var first = await GetAsync(host, cookie, headers);

        Assert.Equal(HttpStatusCode.OK, first.Status);
        Assert.Equal(2, host.Api.CallsTo(Provision)); // the bootstrap and this confirmation
        Assert.All(first.Sessions(host.CookieName), c => Assert.Equal(key, host.KeyOf(c))); // the same user: the key stays
        var stored = await StoredAsync(host, key);
        Assert.Equal(email, stored.Properties.Items[RedisTicketStore.SsoEmailItem]);
        Assert.Equal(username, stored.Properties.Items[RedisTicketStore.SsoUserItem]);

        var second = await GetAsync(host, cookie, headers);

        Assert.Equal(HttpStatusCode.OK, second.Status);
        Assert.Equal(2, host.Api.CallsTo(Provision)); // the next request with this pair is local
    }

    // ---- R58: the same subject, confirmed ------------------------------------------------------------

    [RedisFact]
    public async Task APasswordSessionOfTheSameUser_IsConfirmedOnce_KeepsItsKey_AndTheNextRequestIsLocal()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io"); // no remembered pair

        var first = await GetAsync(host, cookie, HeadersA);
        var second = await GetAsync(host, cookie, HeadersA);

        Assert.Equal(HttpStatusCode.OK, first.Status);
        Assert.Equal(HttpStatusCode.OK, second.Status);
        Assert.Equal(1, host.Api.CallsTo(Provision));
        Assert.All(first.Sessions(host.CookieName), c => Assert.Equal(key, host.KeyOf(c)));
        Assert.True(await host.Db.KeyExistsAsync(key));
        var stored = await StoredAsync(host, key);
        Assert.Equal("pa@corp.io", stored.Properties.Items[RedisTicketStore.SsoEmailItem]);
        Assert.Equal("pa", stored.Properties.Items[RedisTicketStore.SsoUserItem]);
        Assert.Equal([key], host.IndexOf(A));
    }

    [RedisFact]
    public async Task AConfirmedChangeOfRole_KeepsTheKey_AndWritesTheConfirmedClaims()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        host.Api.Override = Provisioned(WithRole(SurfacesApi.UserJson(A, "a@x.io", 3), "admin"));

        var reply = await GetAsync(host, cookie, HeadersA);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        Assert.True(await host.Db.KeyExistsAsync(key));
        Assert.Equal("admin", (await StoredAsync(host, key)).Principal.FindFirstValue(ClaimTypes.Role));
    }

    // ---- R59: a change of subject ---------------------------------------------------------------------

    [RedisFact]
    public async Task AnotherUsersHeaders_OnALiveSession_RotateAfterTheConfirmation_NotBefore()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        var onOld = JsonDocument.Parse((await host.SendAsync(HttpMethod.Get, "/test/hub", cookie: cookie)).Body)
            .RootElement.GetProperty("connection").GetString()!;
        var aliveAtConfirmation = false;
        host.Api.Override = r =>
        {
            if (r.RequestUri!.AbsolutePath == Provision)
            {
                aliveAtConfirmation = host.Db.KeyExists(key);
            }
            return null;
        };

        var reply = await GetAsync(host, cookie, HeadersB);

        Assert.True(aliveAtConfirmation); // the old key lives until the subject is confirmed
        Assert.Equal(HttpStatusCode.OK, reply.Status);
        var set = Assert.Single(reply.Sessions(host.CookieName));
        var fresh = host.KeyOf(set);
        Assert.Equal(B.ToString(), UserOf(reply)); // downstream sees B ...
        Assert.Equal(fresh, JsonDocument.Parse(reply.Body).RootElement.GetProperty("key").GetString()); // ... on the new key
        Assert.False(await host.Db.KeyExistsAsync(key));
        Assert.Contains(onOld, host.Replica.Aborted);
        Assert.Contains(fresh, host.IndexOf(B));
        Assert.Empty(host.IndexOf(A));

        // A late request with the old cookie: no session, no write, no cookie of that key.
        var late = await host.SendAsync(HttpMethod.Get, "/test/me", cookie: cookie);
        Assert.Equal(HttpStatusCode.Unauthorized, late.Status);
        Assert.Empty(late.Sessions(host.CookieName));
        Assert.False(await host.Db.KeyExistsAsync(key));
    }

    [RedisFact]
    public async Task TheConnectionOpenedByTheNewPrincipal_IsBoundToTheNewKey()
    {
        await using var host = await StartAsync();
        var (cookie, _) = await host.SignInAsync("a@x.io");

        var reply = await GetAsync(host, cookie, HeadersB, "/test/hub");

        var fresh = host.KeyOf(Assert.Single(reply.Sessions(host.CookieName)));
        var connection = JsonDocument.Parse(reply.Body).RootElement.GetProperty("connection").GetString()!;
        host.Services.GetRequiredService<SkeinWeb.Hubs.ConnectionRegistry>().AbortSession(fresh);
        Assert.Contains(connection, host.Replica.Aborted);
    }

    // ---- R60: the confirmation fails -------------------------------------------------------------------

    [RedisTheory]
    [InlineData("server-error", 502, "sso_unavailable")]
    [InlineData("not-provisioned", 403, "user_not_provisioned")]
    public async Task AFailedConfirmation_WithASlidingRenewalDue_KeepsTheStatusAndCode_WritesNoCookie_AndLeavesTheRow(
        string failure, int status, string code)
    {
        await using var host = await StartAsync();
        var (cookie, key) = await BootstrapAsync(host);
        await PasswordResetSessionTest.MakeSlidingDueAsync(host, key); // Main plans a sliding renewal
        byte[] before = (await host.Db.StringGetAsync(key))!;
        host.Api.Override = r => r.RequestUri!.AbsolutePath != Provision
            ? null
            : failure == "server-error"
                ? new HttpResponseMessage(HttpStatusCode.InternalServerError)
                : new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    Content = new StringContent("{\"error\":\"user_not_provisioned\"}", Encoding.UTF8, "application/json"),
                };

        var reply = await GetAsync(host, cookie, HeadersB); // another pair: the subject must be confirmed

        Assert.Equal((HttpStatusCode)status, reply.Status);
        Assert.Equal(code, ErrorOf(reply));
        Assert.Empty(reply.Cookies);
        Assert.Equal(before, (byte[])(await host.Db.StringGetAsync(key))!);
    }

    [RedisFact]
    public async Task AMatchingPair_WithADueRefresh_WhenTheConfirmationFails_KeepsTheSession()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await BootstrapAsync(host);
        await AgeRefreshAsync(host, key);
        host.Api.Override = r => r.RequestUri!.AbsolutePath == Provision ? new HttpResponseMessage(HttpStatusCode.InternalServerError) : null;

        var reply = await GetAsync(host, cookie, HeadersA);

        Assert.Equal(HttpStatusCode.OK, reply.Status); // the same login: a failed refresh is not fatal
        Assert.Equal(A.ToString(), UserOf(reply));
        Assert.True(await host.Db.KeyExistsAsync(key));
        Assert.All(reply.Sessions(host.CookieName), c => Assert.Equal(key, host.KeyOf(c)));
    }

    [RedisFact]
    public async Task AMatchingPair_WithADueRefresh_WhenTheAnswerHasNoEpoch_KeepsTheSession_AndLogsAnError()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await BootstrapAsync(host);
        await AgeRefreshAsync(host, key);
        host.Api.Override = Provisioned(SurfacesApi.UserJson(A, "a@x.io", 3).Replace(",\"sessionEpoch\":3", ""));

        var reply = await GetAsync(host, cookie, HeadersA);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        Assert.True(await host.Db.KeyExistsAsync(key));
        Assert.Contains(host.Logs.Entries, e => e.Level == Microsoft.Extensions.Logging.LogLevel.Error);
    }

    [RedisTheory]
    [InlineData("unreachable", 502)]
    [InlineData("server-error", 502)]
    [InlineData("not-provisioned", 403)]
    public async Task WhenTheConfirmationFails_TheRequestIsNotExecuted_AndTheOldSessionIsNotRevoked(string failure, int status)
    {
        await using var host = await StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        host.Api.Override = r => r.RequestUri!.AbsolutePath != Provision
            ? null
            : failure switch
            {
                "unreachable" => throw new HttpRequestException("down"),
                "server-error" => new HttpResponseMessage(HttpStatusCode.InternalServerError),
                _ => new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    Content = new StringContent("{\"error\":\"user_not_provisioned\"}", Encoding.UTF8, "application/json"),
                },
            };

        var reply = await GetAsync(host, cookie, HeadersB);

        Assert.Equal((HttpStatusCode)status, reply.Status);
        Assert.Empty(reply.Cookies);
        Assert.True(await host.Db.KeyExistsAsync(key));
        Assert.Empty(host.IndexOf(B));
        Assert.DoesNotContain("\"user\"", reply.Body); // /test/me did not run
    }

    // ---- R61: branch (a), the same user in another epoch -------------------------------------------------

    private static async Task AssertEndedAsync(SurfacesHost host, SessionPipelineHost.Reply reply, string key)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, reply.Status); // the request went on anonymous
        Assert.NotEmpty(reply.Cookies);
        Assert.All(reply.Cookies, c => Assert.True(c.IsDeletion)); // nothing but the deletion
        Assert.False(await host.Db.KeyExistsAsync(key));
        Assert.Equal(0, SessionRows(host)); // no new session, no pair written
    }

    [RedisFact]
    public async Task SameUserOtherEpoch_OnConfirmation_EndsTheSession_AndTheNextRequestSignsInAfresh()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        host.Api.EpochA = 4;

        var reply = await GetAsync(host, cookie, HeadersA);

        await AssertEndedAsync(host, reply, key);
        var next = await GetAsync(host, null, HeadersA);
        Assert.Equal(HttpStatusCode.OK, next.Status);
        var fresh = host.KeyOf(Assert.Single(next.Sessions(host.CookieName)));
        Assert.Equal("4", (await StoredAsync(host, fresh)).Principal.FindFirstValue(SessionPrincipal.SessionEpochClaim));
    }

    [RedisFact]
    public async Task SameUserOtherEpoch_OnThePeriodicRefresh_EndsTheSession()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await BootstrapAsync(host);
        await AgeRefreshAsync(host, key);
        host.Api.EpochA = 4;

        var reply = await GetAsync(host, cookie, HeadersA); // the pair matches, the refresh is due

        await AssertEndedAsync(host, reply, key);
    }

    [RedisFact]
    public async Task SameUserOtherEpoch_WhenTheKeyCannotBeDeleted_IsUnavailable_WithNoCookie_AndTheKeyLives()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        host.Api.EpochA = 4;
        host.Faults.Before = (name, _) => name == nameof(IDatabase.ScriptEvaluateAsync) ? new InvalidOperationException("injected") : null;

        var reply = await GetAsync(host, cookie, HeadersA);

        host.Faults.Before = null;
        Assert.Equal(HttpStatusCode.BadGateway, reply.Status);
        Assert.Equal("sso_unavailable", ErrorOf(reply));
        Assert.Empty(reply.Cookies);
        Assert.True(await host.Db.KeyExistsAsync(key));
    }

    [RedisFact]
    public async Task SameUserOtherEpoch_WhenRedisFailsAfterTheConfirmedRevocation_TheOutcomeStands()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        host.Api.EpochA = 4;
        var revoked = false;
        host.Faults.After = (name, _) =>
        {
            revoked |= name == nameof(IDatabase.ScriptEvaluateAsync);
            return Task.CompletedTask;
        };
        host.Faults.Before = (name, _) =>
            revoked && name != nameof(IDatabase.ScriptEvaluateAsync) ? new InvalidOperationException("injected") : null;

        var reply = await GetAsync(host, cookie, HeadersA);

        host.Faults.Before = null;
        Assert.True(revoked);
        Assert.Equal(HttpStatusCode.Unauthorized, reply.Status); // not an unavailable answer
        Assert.NotEmpty(reply.Cookies);
        Assert.All(reply.Cookies, c => Assert.True(c.IsDeletion));
        Assert.False(await host.Db.KeyExistsAsync(key));
    }

    // ---- R62: the periodic refresh with a matching pair ---------------------------------------------------

    [RedisFact]
    public async Task Refresh_SameUserAndEpoch_UpdatesClaims_KeepsTheKey_AndThePairStaysTheHeadersOne()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await BootstrapAsync(host);
        await AgeRefreshAsync(host, key);
        host.Api.Override = Provisioned(WithRole(SurfacesApi.UserJson(A, "a@x.io", 3), "admin"));

        var reply = await GetAsync(host, cookie, HeadersA);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        Assert.Equal(2, host.Api.CallsTo(Provision));
        var stored = await StoredAsync(host, key);
        Assert.Equal("admin", stored.Principal.FindFirstValue(ClaimTypes.Role));
        Assert.Equal("pa@corp.io", stored.Properties.Items[RedisTicketStore.SsoEmailItem]); // not the canonical a@x.io
        Assert.Equal("pa", stored.Properties.Items[RedisTicketStore.SsoUserItem]);
        Assert.All(reply.Sessions(host.CookieName), c => Assert.Equal(key, host.KeyOf(c)));
    }

    [RedisFact]
    public async Task Refresh_WithAMatchingPair_ButAnotherUserInTheAnswer_IsAChangeOfSubject()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await BootstrapAsync(host);
        await AgeRefreshAsync(host, key);
        host.Api.Override = Provisioned(SurfacesApi.UserJson(B, "b@x.io", 3));

        var reply = await GetAsync(host, cookie, HeadersA);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        var fresh = host.KeyOf(Assert.Single(reply.Sessions(host.CookieName)));
        Assert.NotEqual(key, fresh);
        Assert.False(await host.Db.KeyExistsAsync(key)); // the other person is never written under the old key
        Assert.Equal(B.ToString(), UserOf(reply));
    }

    // ---- R63: the outcomes of the renewal ------------------------------------------------------------------

    [RedisFact]
    public async Task KeyAbsent_OnTheExplicitRenewal_IsANewAuthentication_WithThePairInTheNewTicket()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        host.Api.Override = Provisioned(SurfacesApi.UserJson(A, "a@x.io", 3), () => host.Db.KeyDelete(key));

        var reply = await GetAsync(host, cookie, HeadersA);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        var fresh = host.KeyOf(Assert.Single(reply.Sessions(host.CookieName)));
        Assert.NotEqual(key, fresh);
        Assert.False(await host.Db.KeyExistsAsync(key)); // never resurrected
        Assert.Equal("pa@corp.io", (await StoredAsync(host, fresh)).Properties.Items[RedisTicketStore.SsoEmailItem]);
        Assert.Equal(1, host.Api.CallsTo(Provision)); // the answer already in hand was used
    }

    [RedisFact]
    public async Task CasExhausted_KeepsTheLiveKey_NoRotation_AndTheRequestGoesOn()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        var armed = false;
        var round = 0;
        host.Api.Override = Provisioned(SurfacesApi.UserJson(A, "a@x.io", 3), () => armed = true);
        host.Faults.After = async (name, args) =>
        {
            if (armed && name == nameof(IDatabase.StringGetAsync) && ((RedisKey)args[0]!).ToString() == key)
            {
                // A parallel writer changes the row after every read, so the compare-and-set always loses.
                // Through the raw connection: going through the store would run this hook again.
                var ticket = TicketSerializer.Default.Deserialize((byte[])(await host.Db.StringGetAsync(key))!)!;
                ticket.Properties.ExpiresUtc = DateTimeOffset.UtcNow.AddHours(20).AddSeconds(++round);
                await host.Db.StringSetAsync(key, TicketSerializer.Default.Serialize(ticket), TimeSpan.FromHours(24));
            }
        };

        var reply = await GetAsync(host, cookie, HeadersA);

        host.Faults.After = null;
        Assert.Equal(HttpStatusCode.OK, reply.Status);
        Assert.True(round >= 3);
        Assert.True(await host.Db.KeyExistsAsync(key)); // a live key is not revoked
        Assert.All(reply.Sessions(host.CookieName), c => Assert.Equal(key, host.KeyOf(c))); // and not rotated
        Assert.Equal(A.ToString(), UserOf(reply));
    }

    [RedisFact]
    public async Task OwnerMismatch_KeepsTheRow_NoRotation_AndTheRequestGoesOn()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        var other = await StoredAsync(host, (await host.SignInAsync("b@x.io")).Key);
        host.Api.Override = Provisioned(
            SurfacesApi.UserJson(A, "a@x.io", 3),
            () => host.Db.StringSet(key, TicketSerializer.Default.Serialize(other), TimeSpan.FromHours(24)));

        var reply = await GetAsync(host, cookie, HeadersA);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        Assert.All(reply.Sessions(host.CookieName), c => Assert.Equal(key, host.KeyOf(c)));
        var stored = await StoredAsync(host, key);
        Assert.Equal(B.ToString(), stored.Principal.FindFirstValue(ClaimTypes.NameIdentifier)); // the owner was not changed to A
    }

    [RedisFact]
    public async Task ATechnicalFailureOfTheRenewal_IsUnavailable_AndTheRequestIsNotExecuted()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        var armed = false;
        host.Api.Override = Provisioned(SurfacesApi.UserJson(A, "a@x.io", 3), () => armed = true);
        host.Faults.Before = (name, _) => armed && name == nameof(IDatabase.StringGetAsync) ? new InvalidOperationException("injected") : null;

        var reply = await GetAsync(host, cookie, HeadersA);

        host.Faults.Before = null;
        Assert.Equal(HttpStatusCode.BadGateway, reply.Status);
        Assert.Equal("sso_unavailable", ErrorOf(reply));
        Assert.Empty(reply.Cookies);
        Assert.True(await host.Db.KeyExistsAsync(key));
    }

    // ---- R65: the trust boundary on the live store -----------------------------------------------------------

    [RedisTheory]
    [InlineData("untrusted-peer", "/test/me")]
    [InlineData("incomplete", "/test/me")]
    [InlineData("service-path", "/api/auth/config")]
    public async Task OutsideTheTrustBoundary_TheRowAndTheStoreAreUntouched(string kind, string path)
    {
        await using var host = await StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        byte[] before = (await host.Db.StringGetAsync(key))!;
        var rows = SessionRows(host);
        var headers = kind switch
        {
            "untrusted-peer" => [.. HeadersB, ("X-Test-Peer", "198.51.100.9")],
            "incomplete" => new[] { ("X-Auth-Request-Email", "b@corp.io") },
            _ => HeadersB,
        };

        var reply = await GetAsync(host, cookie, headers, path);

        Assert.Empty(reply.Cookies);
        Assert.Equal(before, (byte[])(await host.Db.StringGetAsync(key))!);
        Assert.Equal(rows, SessionRows(host));
        Assert.Equal(0, host.Api.CallsTo(Provision));
    }

    // ---- R66: the explicit operations with the proxy's headers --------------------------------------------------

    public static IEnumerable<object[]> ExplicitCases()
    {
        foreach (var operation in new[] { "login", "signup", "invitation", "reset" })
        {
            foreach (var headers in new[] { "other-user", "none" })
            {
                foreach (var cookie in new[] { "none", "another-users-live", "expired", "own-live" })
                {
                    yield return [operation, headers, cookie];
                }
            }
        }
    }

    private static int _resetToken;

    private static (string Path, object Body) Operation(string operation) => operation switch
    {
        "login" => ("/api/auth/login", new { email = "a@x.io", password = "pw" }),
        "signup" => ("/api/auth/signup", new { email = "dev@client.io", username = "dev", password = "correct horse", termsAccepted = true, language = "en" }),
        "invitation" => ("/api/auth/invitations/tok-1/signup", new { username = "dev", password = "correct horse", termsAccepted = true, language = "en" }),
        _ => ($"/api/auth/password-reset/tok-{Interlocked.Increment(ref _resetToken)}", new { password = "new password" }),
    };

    [RedisTheory]
    [MemberData(nameof(ExplicitCases))]
    public async Task AnExplicitOperation_IsTheIdentityOfTheOperation_WhateverTheHeadersAndTheCookie(
        string operation, string headers, string cookieKind)
    {
        await using var host = await StartAsync();
        string? cookie = null;
        string? old = null;
        if (cookieKind != "none")
        {
            var (aCookie, aKey) = await host.SignInAsync(cookieKind == "another-users-live" ? "b@x.io" : "a@x.io");
            cookie = aCookie;
            old = aKey;
            if (cookieKind == "expired")
            {
                await host.Db.KeyDeleteAsync(aKey);
            }
        }
        var (path, body) = Operation(operation);

        var reply = await host.SendAsync(HttpMethod.Post, path, body, cookie, headers == "none" ? [] : HeadersB);

        Assert.Equal(operation == "reset" ? HttpStatusCode.NoContent : HttpStatusCode.OK, reply.Status);
        var set = Assert.Single(reply.Sessions(host.CookieName));
        var fresh = host.KeyOf(set);
        Assert.NotEqual(old, fresh); // never the key of the request
        Assert.Equal(0, host.Api.CallsTo(Provision)); // no confirmation on an explicit operation
        var me = await host.SendAsync(HttpMethod.Get, "/test/me", cookie: set.AsRequestCookie());
        Assert.Equal(HttpStatusCode.OK, me.Status);
        Assert.Equal(A.ToString(), UserOf(me)); // the identity of the operation, not of the headers
        if (old is not null)
        {
            Assert.False(await host.Db.KeyExistsAsync(old));
        }

        // The next ordinary request: the session of the operation has no pair, so the subject is confirmed.
        await GetAsync(host, set.AsRequestCookie(), HeadersA);
        Assert.Equal(1, host.Api.CallsTo(Provision));
    }

    [RedisFact]
    public async Task AWrongPassword_WithTheProxysHeaders_KeepsTheLiveSession_AndAsksNobody()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");

        var reply = await host.SendAsync(HttpMethod.Post, "/api/auth/login", new { email = "a@x.io", password = "wrong" }, cookie, HeadersB);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, reply.Status);
        Assert.Empty(reply.Cookies);
        Assert.True(await host.Db.KeyExistsAsync(key));
        Assert.Equal(0, host.Api.CallsTo(Provision));
    }

    // ---- R67: the matrix of the SSO surface ------------------------------------------------------------------------

    [RedisFact]
    public async Task SessionRevokedAfterTheIssue_InTheSameRequest_EndsTheNewKey_ClosesItsConnection_AndAnswers401()
    {
        await using var host = await StartAsync();
        host.Api.Override = r => r.RequestUri!.AbsolutePath == "/ui/v1/projects"
            ? new HttpResponseMessage(HttpStatusCode.Unauthorized)
            {
                Content = new StringContent("{\"error\":\"session_revoked\"}", Encoding.UTF8, "application/json"),
            }
            : null;

        var reply = await GetAsync(host, null, HeadersA, "/test/chain");

        Assert.Equal(HttpStatusCode.Unauthorized, reply.Status);
        Assert.True(host.Api.CallsTo("/ui/v1/projects") >= 1); // the stub saw the call and answered session_revoked
        Assert.Equal(0, SessionRows(host)); // the new key is gone
        Assert.Empty(reply.Sessions(host.CookieName)); // and its cookie is deleted
        var connection = Assert.Single(host.ChainConnections); // opened from the principal this request carried downstream
        Assert.Contains(connection, host.Replica.Aborted);
    }

    [RedisFact]
    public async Task IssueFailure_OnTheBootstrap_Is502ProvisioningFailed_WithNoCookie()
    {
        await using var host = await StartAsync();
        host.Faults.Before = (name, _) => name == nameof(IDatabase.StringSetAsync) ? new InvalidOperationException("injected") : null;

        var reply = await GetAsync(host, null, HeadersA);

        host.Faults.Before = null;
        Assert.Equal(HttpStatusCode.BadGateway, reply.Status);
        Assert.Equal("sso_provisioning_failed", ErrorOf(reply));
        Assert.Empty(reply.Cookies);
    }

    [RedisFact]
    public async Task RevocationFailure_OnARotation_IsUnavailable_WithNoCookie_AndTheOldKeyLives()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        host.Faults.Before = (name, _) => name == nameof(IDatabase.ScriptEvaluateAsync) ? new InvalidOperationException("injected") : null;

        var reply = await GetAsync(host, cookie, HeadersB);

        host.Faults.Before = null;
        Assert.Equal(HttpStatusCode.BadGateway, reply.Status);
        Assert.Equal("sso_unavailable", ErrorOf(reply));
        Assert.Empty(reply.Cookies);
        Assert.True(await host.Db.KeyExistsAsync(key)); // still alive for its owner
    }

    [RedisFact]
    public async Task KeyAbsent_ThenAnIssueFailure_IsProvisioningFailed_AndTheKeyIsNotResurrected()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        var armed = false;
        host.Api.Override = Provisioned(SurfacesApi.UserJson(A, "a@x.io", 3), () =>
        {
            host.Db.KeyDelete(key);
            armed = true;
        });
        host.Faults.Before = (name, _) =>
            armed && name == nameof(IDatabase.StringSetAsync) ? new InvalidOperationException("injected") : null;

        var reply = await GetAsync(host, cookie, HeadersA);

        host.Faults.Before = null;
        Assert.Equal(HttpStatusCode.BadGateway, reply.Status);
        Assert.Equal("sso_provisioning_failed", ErrorOf(reply));
        Assert.Empty(reply.Cookies);
        Assert.False(await host.Db.KeyExistsAsync(key));
    }

    [RedisFact]
    public async Task AReadFailure_IsUnavailable_AndTheKnownTicketIsNeitherRemovedNorRewritten()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        byte[] before = (await host.Db.StringGetAsync(key))!;
        host.Faults.Before = (name, _) => name == nameof(IDatabase.StringGetAsync) ? new InvalidOperationException("injected") : null;

        var reply = await GetAsync(host, cookie, HeadersB);

        host.Faults.Before = null;
        Assert.Equal(HttpStatusCode.BadGateway, reply.Status);
        Assert.Equal("sso_unavailable", ErrorOf(reply));
        Assert.Empty(reply.Cookies);
        Assert.Equal(before, (byte[])(await host.Db.StringGetAsync(key))!);
    }
}
