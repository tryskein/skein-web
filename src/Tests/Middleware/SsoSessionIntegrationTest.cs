using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using SkeinWeb.Auth;
using SkeinWeb.Tests.Auth;
using SkeinWeb.Tests.Controllers;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Middleware;

/// <summary>
/// The trust-headers (oauth2-proxy) middleware on the real controllers, issuer, store (real Redis) and cookie
/// schemes, against an API model: the local comparison of the remembered pair, the confirmation of the subject
/// and its three branches (another user, the same user in another epoch, the same user and epoch), the
/// outcomes of the renewal, the trust boundary, the explicit operations and the refusals; the window of the
/// session and the expiry of its cookie across sign-ins by headers and explicit renewals, and the end of the
/// session reached by the moment of a renewal.
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

    // Another pair of headers of user A (the API model maps every email not starting with "b" to A).
    private static readonly (string, string)[] HeadersA2 = [("X-Auth-Request-Email", "pa2@corp.io"), ("X-Auth-Request-User", "pa2")];

    /// <summary>The absolute limit of the stand when a test names none: the default of the setting, 720 h.</summary>
    private const int DefaultAbsoluteHours = 720;

    private static Task<SurfacesHost> StartAsync(TimeProvider? time = null, SessionTimeouts? timeouts = null) =>
        SurfacesHost.StartAsync(trustHeaders: true, time: time, timeouts: timeouts);

    /// <summary>The ticket of the row as stored, read without the store (a read through it would write the row's lifetime).</summary>
    private static async Task<AuthenticationTicket> RowAsync(SurfacesHost host, string key) =>
        TicketSerializer.Default.Deserialize((byte[])(await host.Db.StringGetAsync(key))!)!;

    /// <summary>
    /// Gives the row of <paramref name="key"/> the window [<paramref name="issued"/>, <paramref name="expires"/>]
    /// and the lifetime <paramref name="lifetime"/>, as the process that wrote it would have; nothing else changes.
    /// </summary>
    private static async Task SeedWindowAsync(
        SurfacesHost host, string key, DateTimeOffset issued, DateTimeOffset expires, TimeSpan lifetime)
    {
        var ticket = await RowAsync(host, key);
        ticket.Properties.IssuedUtc = issued;
        ticket.Properties.ExpiresUtc = expires;
        await host.Db.StringSetAsync(key, TicketSerializer.Default.Serialize(ticket), lifetime);
    }

    /// <summary>The moment truncated to whole seconds, the precision of a stored ticket and of a cookie expiry.</summary>
    private static DateTimeOffset Whole(DateTimeOffset moment) => DateTimeOffset.FromUnixTimeSeconds(moment.ToUnixTimeSeconds());

    private static long ExpiresSeconds(SessionPipelineHost.SetCookie set) =>
        (SessionPipelineIntegrationTest.ExpiresOf(set) ?? throw new Xunit.Sdk.XunitException("the session cookie is not persistent"))
            .ToUnixTimeSeconds();

    private static async Task<DateTimeOffset> RedisNowAsync(SurfacesHost host) =>
        new(DateTime.SpecifyKind(await host.Mux.GetServers().First(s => !s.IsReplica).TimeAsync(), DateTimeKind.Utc));

    /// <summary>Polls <paramref name="condition"/>; a condition not met within 15 s fails the test's precondition.</summary>
    private static async Task UntilAsync(Func<Task<bool>> condition, string what)
    {
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (!await condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                Assert.Fail($"precondition not met within 15 s: {what}");
            }
            await Task.Delay(20);
        }
    }

    /// <summary>
    /// The window of a session signed in by this request: it starts at the sign-in (not before
    /// <paramref name="requested"/>, not after <paramref name="latest"/>), runs the absolute limit
    /// <paramref name="absoluteHours"/>, and the persistent cookie expires at its end.
    /// </summary>
    private static async Task AssertOwnWindowAsync(
        SurfacesHost host, SessionPipelineHost.SetCookie set, string key, DateTimeOffset requested, DateTimeOffset latest,
        int absoluteHours = DefaultAbsoluteHours)
    {
        var row = await RowAsync(host, key);
        var issued = row.Properties.IssuedUtc!.Value;
        Assert.InRange(issued, Whole(requested), latest);
        Assert.Equal(issued.AddHours(absoluteHours), row.Properties.ExpiresUtc);
        Assert.Equal(row.Properties.ExpiresUtc!.Value.ToUnixTimeSeconds(), ExpiresSeconds(set));
    }

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
        var requested = DateTimeOffset.UtcNow;

        var reply = await GetAsync(host, null, HeadersA);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        var set = Assert.Single(reply.Sessions(host.CookieName));
        var key = host.KeyOf(set);
        await AssertOwnWindowAsync(host, set, key, requested, DateTimeOffset.UtcNow);
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
        // The old session signed in five hours ago: a window it passed on would start then.
        var oldSignIn = Whole(DateTimeOffset.UtcNow.AddHours(-5));
        await SeedWindowAsync(host, bobKey, oldSignIn, oldSignIn.AddHours(DefaultAbsoluteHours), TimeSpan.FromHours(1));
        if (kind == "expired")
        {
            await host.Db.KeyDeleteAsync(bobKey);
        }
        var requested = DateTimeOffset.UtcNow;

        var reply = await GetAsync(host, cookie, HeadersA);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        var set = Assert.Single(reply.Sessions(host.CookieName));
        var fresh = host.KeyOf(set);
        Assert.NotEqual(bobKey, fresh);
        await AssertOwnWindowAsync(host, set, fresh, requested, DateTimeOffset.UtcNow);
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

    // SC-003, D-1, INV-8: a matching pair with no refresh due moves only the lifetime of the row; the
    // ticket is written only by an explicit confirmation, which keeps the window of the sign-in.
    [RedisFact]
    public async Task AMatchingPair_OnlyMovesTheRowLifetime_AndAnExplicitConfirmation_WritesTheClaimsInTheSignInWindow()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await BootstrapAsync(host);
        var signedIn = (await RowAsync(host, key)).Properties;
        byte[] before = (await host.Db.StringGetAsync(key))!;
        Assert.True(await host.Db.KeyExpireAsync(key, TimeSpan.FromMinutes(1)));

        var local = await GetAsync(host, cookie, HeadersA);

        Assert.Equal(HttpStatusCode.OK, local.Status);
        Assert.Equal(1, host.Api.CallsTo(Provision)); // still local
        Assert.Empty(local.SessionWrites());
        Assert.Equal(before, (byte[])(await host.Db.StringGetAsync(key))!); // the ticket is not written ...
        Assert.True(await host.Db.KeyTimeToLiveAsync(key) > TimeSpan.FromHours(1)); // ... the lifetime of the row moved

        await AgeRefreshAsync(host, key);
        host.Api.Override = Provisioned(WithRole(SurfacesApi.UserJson(A, "a@x.io", 3), "admin"));

        var confirmed = await GetAsync(host, cookie, HeadersA);

        Assert.Equal(HttpStatusCode.OK, confirmed.Status);
        Assert.Equal(2, host.Api.CallsTo(Provision));
        var row = await RowAsync(host, key);
        Assert.Equal("admin", row.Principal.FindFirstValue(ClaimTypes.Role)); // the confirmed claims are written
        Assert.Equal("pa@corp.io", row.Properties.Items[RedisTicketStore.SsoEmailItem]);
        Assert.Equal(signedIn.IssuedUtc, row.Properties.IssuedUtc); // in the window of the sign-in
        Assert.Equal(signedIn.ExpiresUtc, row.Properties.ExpiresUtc);
    }

    // SC-003, E-3, INV-1: a series of confirmations, then ordinary requests and confirmations of the same
    // session in parallel, on a replica whose clock moves on: the window of the row stays the sign-in's.
    [RedisFact]
    public async Task ConfirmationsInSeries_AndParallelRequestsOfTheSession_KeepTheSignInWindow()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        await using var host = await StartAsync(time);
        var (cookie, key) = await host.SignInAsync("a@x.io"); // no remembered pair: every new pair is confirmed
        var signedIn = (await RowAsync(host, key)).Properties;
        (string, string)[] headersA3 = [("X-Auth-Request-Email", "pa3@corp.io"), ("X-Auth-Request-User", "pa3")];

        foreach (var headers in new[] { HeadersA, HeadersA2, headersA3 })
        {
            time.Advance(TimeSpan.FromHours(1));
            var reply = await GetAsync(host, cookie, headers);
            Assert.Equal(HttpStatusCode.OK, reply.Status);
            Assert.Equal(key, host.KeyOf(Assert.Single(reply.Sessions(host.CookieName))));
        }
        Assert.Equal(3, host.Api.CallsTo(Provision));

        time.Advance(TimeSpan.FromHours(1));
        var parallel = await Task.WhenAll(
            GetAsync(host, cookie, headersA3), // ordinary: the remembered pair
            GetAsync(host, cookie, headersA3),
            GetAsync(host, cookie, HeadersA),  // confirmations of other pairs
            GetAsync(host, cookie, HeadersA2));

        Assert.All(parallel, r => Assert.Equal(HttpStatusCode.OK, r.Status));
        Assert.All(parallel, r => Assert.All(r.Sessions(host.CookieName), c => Assert.Equal(key, host.KeyOf(c))));
        Assert.True(host.Api.CallsTo(Provision) >= 5, "the parallel confirmations were not made");
        var row = await RowAsync(host, key);
        Assert.Equal(signedIn.IssuedUtc, row.Properties.IssuedUtc);
        Assert.Equal(signedIn.ExpiresUtc, row.Properties.ExpiresUtc);
    }

    // SC-007, D-3, INV-6, US-3: the cookie of a successful explicit renewal expires at the end of the session
    // as of the renewal, and the row lives no longer than what is left. The row is seeded as a process with
    // the limit of 720 h wrote it an hour after its sign-in; the stand runs the limit of the case.
    [RedisTheory]
    [InlineData(720, 720)]  // the limit of the sign-in: L + 720 h
    [InlineData(11, 11)]    // a lowered limit: L + 11 h
    [InlineData(1000, 720)] // a raised limit: the written end of the window, not L + 1000 h
    public async Task ASuccessfulExplicitRenewal_ExpiresTheCookieAtTheEndOfTheSession_AndTheRowLivesNoLonger(
        int absoluteHours, int expectedEndHours)
    {
        await using var host = await StartAsync(
            timeouts: new SessionTimeouts(SessionTimeouts.DefaultIdleTimeoutHours, absoluteHours));
        var (cookie, key) = await host.SignInAsync("a@x.io");
        var signIn = Whole(DateTimeOffset.UtcNow.AddHours(-1));
        await SeedWindowAsync(host, key, signIn, signIn.AddHours(720), TimeSpan.FromHours(SessionTimeouts.DefaultIdleTimeoutHours));
        var end = signIn.AddHours(expectedEndHours);

        var reply = await GetAsync(host, cookie, HeadersA);
        var observedAt = DateTimeOffset.UtcNow;
        var lifetime = await host.Db.KeyTimeToLiveAsync(key);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        var set = Assert.Single(reply.Sessions(host.CookieName));
        Assert.Equal(key, host.KeyOf(set));
        Assert.Equal(end.ToUnixTimeSeconds(), ExpiresSeconds(set));
        Assert.NotNull(lifetime);
        Assert.True(lifetime > TimeSpan.Zero);
        Assert.True(lifetime <= end - observedAt, $"the row lives {lifetime}, past the end of the session");
        Assert.Equal(signIn, (await RowAsync(host, key)).Properties.IssuedUtc); // the window is the written one
    }

    // ---- E-8: the session ends by the moment of the renewal ---------------------------------------------

    /// <summary>
    /// The outcome of a renewal whose session ended: the old row is gone, no Set-Cookie of the old key, and a
    /// new key with its own persistent cookie, its own window (from no earlier than <paramref name="notBefore"/>)
    /// and the pair of the headers.
    /// </summary>
    private static async Task AssertReplacedByANewKeyAsync(
        SurfacesHost host, SessionPipelineHost.Reply reply, string oldKey, DateTimeOffset notBefore, DateTimeOffset latest)
    {
        Assert.Equal(HttpStatusCode.OK, reply.Status);
        Assert.False(await host.Db.KeyExistsAsync(oldKey));
        var set = Assert.Single(reply.Sessions(host.CookieName));
        var fresh = host.KeyOf(set);
        Assert.NotEqual(oldKey, fresh);
        await AssertOwnWindowAsync(host, set, fresh, notBefore, latest);
        var row = await RowAsync(host, fresh);
        Assert.Equal("pa@corp.io", row.Properties.Items[RedisTicketStore.SsoEmailItem]);
        Assert.Equal("pa", row.Properties.Items[RedisTicketStore.SsoUserItem]);
        Assert.Equal(A.ToString(), UserOf(reply));
    }

    // (a) The replica decides: the answer of skein-api moves the clock of the stand past the end of the window.
    [RedisFact]
    public async Task TheSessionEndingDuringTheConfirmation_ByTheClockOfTheReplica_SendsNoCompareAndSet_AndIssuesANewKey()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        await using var host = await StartAsync(time);
        var (cookie, key) = await host.SignInAsync("a@x.io");
        var end = (await RowAsync(host, key)).Properties.ExpiresUtc!.Value;
        var after = end.AddMinutes(1);
        host.Api.Override = Provisioned(SurfacesApi.UserJson(A, "a@x.io", 3), () => time.SetUtcNow(after));
        var compareAndSets = 0;
        host.Faults.Before = (name, args) =>
        {
            if (DbProxy.IsScript(name, args, StoreScripts.Renew))
            {
                Interlocked.Increment(ref compareAndSets);
            }
            return null;
        };

        var reply = await GetAsync(host, cookie, HeadersA);

        host.Faults.Before = null;
        Assert.Equal(1, host.Api.CallsTo(Provision)); // the confirmation was made, and moved the clock
        Assert.Equal(0, compareAndSets);
        await AssertReplacedByANewKeyAsync(host, reply, key, after, after);
    }

    /// <summary>
    /// (b) The script decides. The row's window ends at <paramref name="end"/> (a few seconds of real time
    /// ahead); the compare-and-set of the renewal is held. While it is held the test gives the row a lifetime
    /// of 60 s (the read of the request set it to the time left), and checks that the held call is that
    /// compare-and-set and the replica decided with time left. <paramref name="beforeRelease"/> waits for the
    /// moment of the case; right before the release the row is checked alive with the bytes the renewal read
    /// and a lifetime far above the command timeout of the stand.
    /// </summary>
    private static async Task<SessionPipelineHost.Reply> RenewalHeldUntilAsync(
        SurfacesHost host, string cookie, string key, DateTimeOffset end, Func<Task> beforeRelease)
    {
        await SeedWindowAsync(host, key, end.AddHours(-1), end, TimeSpan.FromMinutes(1));
        byte[] read = (await host.Db.StringGetAsync(key))!;
        var compareAndSet = host.Faults.Hold((name, args) => DbProxy.IsScript(name, args, StoreScripts.Renew, key));
        try
        {
            var request = GetAsync(host, cookie, HeadersA);
            await compareAndSet.Reached.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.True(DateTimeOffset.UtcNow < end, "precondition: the replica decided after the end of the session");
            Assert.True(await host.Db.KeyExpireAsync(key, TimeSpan.FromSeconds(60)), "precondition: the row is gone before the release");

            await beforeRelease();

            Assert.Equal(read, (byte[]?)await host.Db.StringGetAsync(key));
            var lifetime = await host.Db.KeyTimeToLiveAsync(key);
            Assert.True(lifetime > TimeSpan.FromSeconds(10), $"precondition: the row has {lifetime} left at the release");
            compareAndSet.Release();
            return await request.WaitAsync(TimeSpan.FromSeconds(30));
        }
        finally
        {
            compareAndSet.Release();
        }
    }

    [RedisFact]
    public async Task TheSessionEndingBeforeTheCompareAndSet_ByTheClockOfRedis_WritesNothing_AndIssuesANewKey()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        var end = Whole(DateTimeOffset.UtcNow).AddSeconds(3);

        var reply = await RenewalHeldUntilAsync(host, cookie, key, end,
            () => UntilAsync(async () => await RedisNowAsync(host) >= end, "the clock of Redis reaches the end of the session"));

        await AssertReplacedByANewKeyAsync(host, reply, key, end, DateTimeOffset.UtcNow);
    }

    // The control at the boundary: the same compare-and-set released with at least 1 s left by the clock of Redis.
    [RedisFact]
    public async Task TheCompareAndSet_ReleasedASecondBeforeTheEnd_IsWritten_WithTheCookieOfTheSameKey()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        var end = Whole(DateTimeOffset.UtcNow).AddSeconds(6);

        var reply = await RenewalHeldUntilAsync(host, cookie, key, end, async () =>
            Assert.True(await RedisNowAsync(host) <= end.AddSeconds(-1), "precondition: less than 1 s left at the release"));

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        var set = Assert.Single(reply.Sessions(host.CookieName));
        Assert.Equal(key, host.KeyOf(set));
        Assert.Equal(end.ToUnixTimeSeconds(), ExpiresSeconds(set));
        Assert.Equal("pa@corp.io", (await RowAsync(host, key)).Properties.Items[RedisTicketStore.SsoEmailItem]); // written
    }

    // INV-8, residual 2-4: another explicit confirmation of the same owner and epoch replaces the pair and the
    // claims in the same window, and the next ordinary request keeps the replacement.
    [RedisFact]
    public async Task AnotherConfirmation_ReplacesThePairAndTheClaims_InTheSameWindow_AndAnOrdinaryRequestKeepsThem()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await BootstrapAsync(host);
        var signedIn = (await RowAsync(host, key)).Properties;
        host.Api.Override = Provisioned(WithRole(SurfacesApi.UserJson(A, "a@x.io", 3), "admin"));

        var confirmed = await GetAsync(host, cookie, HeadersA2);

        Assert.Equal(HttpStatusCode.OK, confirmed.Status);
        Assert.Equal(key, host.KeyOf(Assert.Single(confirmed.Sessions(host.CookieName))));
        var row = await RowAsync(host, key);
        Assert.Equal("pa2@corp.io", row.Properties.Items[RedisTicketStore.SsoEmailItem]);
        Assert.Equal("pa2", row.Properties.Items[RedisTicketStore.SsoUserItem]);
        Assert.Equal("admin", row.Principal.FindFirstValue(ClaimTypes.Role));
        Assert.Equal(signedIn.IssuedUtc, row.Properties.IssuedUtc);
        Assert.Equal(signedIn.ExpiresUtc, row.Properties.ExpiresUtc);
        byte[] written = (await host.Db.StringGetAsync(key))!;

        var ordinary = await GetAsync(host, cookie, HeadersA2);

        Assert.Equal(HttpStatusCode.OK, ordinary.Status);
        Assert.Equal(2, host.Api.CallsTo(Provision)); // the replaced pair is the remembered one: local
        Assert.Empty(ordinary.SessionWrites());
        Assert.Equal(written, (byte[])(await host.Db.StringGetAsync(key))!);
    }

    // SC-001 for an SSO request: the read script set the lifetime of the row, the renewal's compare-and-set is
    // held, the test sets the lifetime to 1 s; once released, the renewal (the last write) sets min(idle, time left).
    [RedisFact]
    public async Task OnARequestWithAnExplicitRenewal_TheRenewalAsTheLastWrite_SetsTheRowLifetime()
    {
        await using var host = await StartAsync();
        var (cookie, key) = await host.SignInAsync("a@x.io");
        var lifetimeRead = false;
        host.Faults.After = (name, args) =>
        {
            lifetimeRead |= DbProxy.IsScript(name, args, StoreScripts.Read, key);
            return Task.CompletedTask;
        };
        var compareAndSet = host.Faults.Hold((name, args) => DbProxy.IsScript(name, args, StoreScripts.Renew, key));
        try
        {
            var request = GetAsync(host, cookie, HeadersA);
            await compareAndSet.Reached.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.True(lifetimeRead, "precondition: the read of the request did not write the lifetime of the row");
            Assert.True(await host.Db.KeyExpireAsync(key, TimeSpan.FromSeconds(1)));
            compareAndSet.Release();
            var reply = await request.WaitAsync(TimeSpan.FromSeconds(30));

            Assert.Equal(HttpStatusCode.OK, reply.Status);
            Assert.Equal(key, host.KeyOf(Assert.Single(reply.Sessions(host.CookieName))));
            var lifetime = await host.Db.KeyTimeToLiveAsync(key);
            // min(idle 120 h, about 720 h left) = 120 h.
            Assert.NotNull(lifetime);
            Assert.InRange(lifetime.Value, TimeSpan.FromHours(120) - TimeSpan.FromMinutes(1), TimeSpan.FromHours(120));
        }
        finally
        {
            compareAndSet.Release();
            host.Faults.After = null;
        }
    }

    // US-1, SC-002, the trust-headers chain: once the old session has ended — (a) idle, its row gone by its
    // own lifetime in Redis; (b) its session end passed on the stand's clock — valid headers sign in afresh.
    [RedisTheory]
    [InlineData("idle")]
    [InlineData("absolute")]
    public async Task AfterTheOldSessionEnded_TheProvidersHeaders_SignInAfresh_UnderANewKeyWithItsOwnWindow(string ending)
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        await using var host = await StartAsync(time);
        var (cookie, key) = await BootstrapAsync(host);
        var oldIssued = (await RowAsync(host, key)).Properties.IssuedUtc;
        if (ending == "idle")
        {
            Assert.True(await host.Db.KeyExpireAsync(key, TimeSpan.FromMilliseconds(300)));
            await UntilAsync(async () => !await host.Db.KeyExistsAsync(key), "the row expires in Redis");
            time.Advance(TimeSpan.FromHours(1));
        }
        else
        {
            time.Advance(TimeSpan.FromHours(DefaultAbsoluteHours + 1));
        }
        var requested = time.GetUtcNow();

        var reply = await GetAsync(host, cookie, HeadersA);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        Assert.Equal(A.ToString(), UserOf(reply));
        var set = Assert.Single(reply.Sessions(host.CookieName));
        var fresh = host.KeyOf(set);
        Assert.NotEqual(key, fresh);
        Assert.False(await host.Db.KeyExistsAsync(key)); // the old key is not renewed
        await AssertOwnWindowAsync(host, set, fresh, requested, requested);
        Assert.NotEqual(oldIssued, (await RowAsync(host, fresh)).Properties.IssuedUtc);
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
        // The old session signed in five hours ago: a window it passed on would start then.
        var oldSignIn = Whole(DateTimeOffset.UtcNow.AddHours(-5));
        await SeedWindowAsync(host, key, oldSignIn, oldSignIn.AddHours(DefaultAbsoluteHours), TimeSpan.FromHours(1));
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

        var requested = DateTimeOffset.UtcNow;

        var reply = await GetAsync(host, cookie, HeadersB);

        Assert.True(aliveAtConfirmation); // the old key lives until the subject is confirmed
        Assert.Equal(HttpStatusCode.OK, reply.Status);
        var set = Assert.Single(reply.Sessions(host.CookieName));
        var fresh = host.KeyOf(set);
        await AssertOwnWindowAsync(host, set, fresh, requested, DateTimeOffset.UtcNow); // not the old session's window
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
    public async Task AFailedConfirmation_KeepsTheStatusAndCode_WritesNoCookie_AndLeavesTheRow(
        string failure, int status, string code)
    {
        await using var host = await StartAsync();
        var (cookie, key) = await BootstrapAsync(host);
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
        var injection = Injection.FailAfter(host.Faults, StoreScripts.Revoke, StoreScripts.Read, failingKey: key, precedingKey: key);

        var reply = await GetAsync(host, cookie, HeadersA);

        host.Faults.Before = null;
        host.Faults.After = null;
        Assert.True(injection.Fired, "the revocation was never reached after the read: the test proves nothing");
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
        host.Faults.After = (name, args) =>
        {
            revoked |= DbProxy.IsScript(name, args, StoreScripts.Revoke, key);
            return Task.CompletedTask;
        };
        // The step that follows the confirmed DEL of the row: the removal of its member from the index.
        var injected = false;
        host.Faults.Before = (name, args) =>
        {
            if (revoked && name == nameof(IDatabase.SetRemoveAsync))
            {
                injected = true;
                return new InvalidOperationException("injected");
            }
            return null;
        };

        var reply = await GetAsync(host, cookie, HeadersA);

        host.Faults.Before = null;
        host.Faults.After = null;
        Assert.True(revoked);
        Assert.True(injected, "the failure after the confirmed revocation never fired: the test proves nothing");
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
        Assert.Empty(reply.SessionWrites()); // not rotated, and no Set-Cookie of the old key
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
        Assert.Empty(reply.SessionWrites()); // not rotated, and no Set-Cookie of the old key
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
        Assert.DoesNotContain("\"user\"", reply.Body); // /test/me did not run
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
        host.Faults.Before = (name, args) => DbProxy.IsScript(name, args, StoreScripts.Issue) ? new InvalidOperationException("injected") : null;

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
        var injection = Injection.FailAfter(host.Faults, StoreScripts.Revoke, StoreScripts.Read, failingKey: key, precedingKey: key);

        var reply = await GetAsync(host, cookie, HeadersB);

        host.Faults.Before = null;
        host.Faults.After = null;
        Assert.True(injection.Fired, "the revocation was never reached after the read: the test proves nothing");
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
        host.Faults.Before = (name, args) =>
            armed && DbProxy.IsScript(name, args, StoreScripts.Issue) ? new InvalidOperationException("injected") : null;

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
