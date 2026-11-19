using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using SkeinWeb.Auth;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// The end of a session on the real pipeline (<see cref="SessionPipelineHost"/>, Redis database 9): by
/// idleness the row expires in Redis and the next request is not authenticated; by the absolute
/// limit the read rejects the request from the end of the session on, under the limit of the
/// running process; the three lifetimes of a sign-in come from one <see cref="SessionTimeouts"/>;
/// a request admitted before the end finishes; the lifetime of the row counts from its last write
/// (US-1, US-2, US-3, SC-001, SC-002, INV-3, E-1, E-2, E-5, E-11, R-3, R-5).
/// <para>Two points of observation: the stand's clock (<see cref="SessionPipelineHost.Time"/>)
/// decides the end of a session; the expiry by idleness is the row's PTTL and its disappearance in
/// Redis, which the stand's clock does not move.</para>
/// </summary>
[Trait("Category", "Integration")]
[Collection("session-pipeline")]
public sealed class SessionExpiryPipelineTest
{
    private static readonly Guid Alice = Guid.Parse("0199a1b2-0000-7000-8000-00000000000a");
    private const string HandlerSessionIdClaim = "Microsoft.AspNetCore.Authentication.Cookies-SessionId";

    private static string IndexOf(Guid user) => "skein:user-tickets:" + user;

    private static async Task<long> PttlAsync(SessionPipelineHost host, string key) =>
        (long)await host.Db.ExecuteAsync("PTTL", key);

    private static void AssertNear(TimeSpan expected, long pttlMs) =>
        Assert.InRange(pttlMs, (long)(expected - TimeSpan.FromSeconds(10)).TotalMilliseconds, (long)expected.TotalMilliseconds);

    private static async Task<AuthenticationProperties> WindowOfAsync(SessionPipelineHost host, string key) =>
        TicketSerializer.Default.Deserialize((byte[])(await host.Db.StringGetAsync(key))!)!.Properties;

    private static DateTimeOffset WholeSecond(DateTimeOffset t) => new(t.Ticks - t.Ticks % TimeSpan.TicksPerSecond, TimeSpan.Zero);

    /// <summary>The request cookie the browser holds for the session <paramref name="key"/>.</summary>
    private static string CookieFor(SessionPipelineHost host, string key) =>
        $"{host.CookieName}={Uri.EscapeDataString(host.Services.GetRequiredService<TicketDataFormat>().Protect(new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity([new Claim(HandlerSessionIdClaim, key)], "Cookies")), "Cookies")))}";

    /// <summary>
    /// A row as a former process wrote it: the window of a sign-in at <paramref name="signIn"/> under an
    /// absolute limit of <paramref name="absoluteHours"/>, the row lifetime <paramref name="lifetime"/>.
    /// </summary>
    private static async Task<(string Key, string Cookie)> SeedAsync(
        SessionPipelineHost host, DateTimeOffset signIn, int absoluteHours, TimeSpan lifetime)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, Alice.ToString()), new Claim(ClaimTypes.Role, "user")], "test"));
        var properties = new AuthenticationProperties { IssuedUtc = signIn, ExpiresUtc = signIn.AddHours(absoluteHours) };
        var key = "skein:session:seed-" + Guid.NewGuid().ToString("N");
        var ticket = SessionPrincipal.WithSessionKey(new AuthenticationTicket(principal, properties, SessionSchemes.Main), key);
        await host.Db.StringSetAsync(key, TicketSerializer.Default.Serialize(ticket), lifetime);
        return (key, CookieFor(host, key));
    }

    // ---- Idleness: the row expires in Redis (row 41) -------------------------------------------

    [RedisFact]
    public async Task ARequest_WritesTheIdleLifetimeAnew_AndOnlyForItsOwnSession()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, key, _) = await host.SignInAsync(Alice);
        var (_, control, _) = await host.SignInAsync(Alice);
        await host.Db.KeyExpireAsync(key, TimeSpan.FromSeconds(2));
        await host.Db.KeyExpireAsync(control, TimeSpan.FromMinutes(5));

        var reply = await host.SendAsync("/test/me", cookie);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        AssertNear(host.Timeouts.Idle, await PttlAsync(host, key));
        Assert.InRange(await PttlAsync(host, control), 1, (long)TimeSpan.FromMinutes(5).TotalMilliseconds);
    }

    [RedisFact]
    public async Task ARowExpiredInRedis_DoesNotAuthenticate_AndTheBrowserCookieIsNotTouched()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, key, _) = await host.SignInAsync(Alice);
        await host.Db.KeyExpireAsync(key, TimeSpan.FromMilliseconds(300));
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (await host.Db.KeyExistsAsync(key))
        {
            Assert.True(DateTime.UtcNow < deadline, "the row never expired in Redis");
            await Task.Delay(50);
        }

        var reply = await host.SendAsync("/test/me", cookie);

        Assert.Equal(HttpStatusCode.Unauthorized, reply.Status);
        Assert.Empty(reply.SessionWrites()); // neither a new session cookie nor a deletion of the browser's one
    }

    // ---- The absolute limit on the pipeline (row 42) ------------------------------------------

    [RedisFact]
    public async Task RequestsMoreOftenThanTheIdleLimit_EndAtTheAbsoluteLimit_AndASignInStartsANewWindow()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, key, _) = await host.SignInAsync(Alice);
        var end = (await WindowOfAsync(host, key)).ExpiresUtc!.Value;

        while (host.Time.GetUtcNow() < end.AddHours(-100))
        {
            host.Time.Advance(TimeSpan.FromHours(100)); // less than the idle limit of 120 h
            Assert.Equal(HttpStatusCode.OK, (await host.SendAsync("/test/me", cookie)).Status);
        }

        host.Time.SetUtcNow(end.AddSeconds(-1));
        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync("/test/me", cookie)).Status);
        Assert.InRange(await PttlAsync(host, key), 1, 1000);

        host.Time.SetUtcNow(end);
        var atTheEnd = await host.SendAsync("/test/me", cookie);
        Assert.Equal(HttpStatusCode.Unauthorized, atTheEnd.Status);
        Assert.False(await host.Db.KeyExistsAsync(key));
        Assert.Empty(atTheEnd.SessionWrites());

        var (_, fresh, _) = await host.SignInAsync(Alice);
        Assert.NotEqual(key, fresh);
        var window = await WindowOfAsync(host, fresh);
        Assert.Equal(WholeSecond(end), WholeSecond(window.IssuedUtc!.Value));
        Assert.Equal(window.IssuedUtc!.Value + host.Timeouts.Absolute, window.ExpiresUtc);
    }

    // ---- A lowered absolute limit for rows of a former process (row 43) ------------------------

    [RedisFact]
    public async Task ALoweredAbsoluteLimit_EndsRowsOfAFormerProcess_OnTheFirstRequestAndHandshake()
    {
        await using var host = await SessionPipelineHost.StartAsync(timeouts: new SessionTimeouts(120, 24));
        var signIn = WholeSecond(host.Time.GetUtcNow());
        // As the former process (absolute limit 720 h) wrote them: one seed per branch.
        var early = await SeedAsync(host, signIn, 720, TimeSpan.FromHours(120));
        var http = await SeedAsync(host, signIn, 720, TimeSpan.FromHours(120));
        var hub = await SeedAsync(host, signIn, 720, TimeSpan.FromHours(120));

        host.Time.SetUtcNow(signIn.AddHours(23));
        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync("/test/me", early.Cookie)).Status);
        Assert.InRange(await PttlAsync(host, early.Key), 1, (long)TimeSpan.FromHours(1).TotalMilliseconds);

        host.Time.SetUtcNow(signIn.AddHours(48));
        Assert.True(await host.Store.ExistsAsync(http.Key, CancellationToken.None)); // a probe still sees it alive (R-5)

        Assert.Equal(HttpStatusCode.Unauthorized, (await host.SendAsync("/test/me", http.Cookie)).Status);
        Assert.False(await host.Db.KeyExistsAsync(http.Key));

        Assert.Equal(HttpStatusCode.Unauthorized, (await host.SendAsync("/test/hub", hub.Cookie)).Status);
        Assert.Empty(host.Replica.Registry.ConnectionsOf(Alice));
        Assert.False(await host.Db.KeyExistsAsync(hub.Key));
    }

    // ---- One source of the three lifetimes (row 44) -------------------------------------------

    [RedisTheory]
    [InlineData(7, 13)]
    [InlineData(30, 11)]
    public async Task TheCookieExpiry_TheRowAndTheIndexLifetimes_AllComeFromTheRegisteredLimits(int idle, int absolute)
    {
        await using var host = await SessionPipelineHost.StartAsync(timeouts: new SessionTimeouts(idle, absolute));
        var row = TimeSpan.FromHours(Math.Min(idle, absolute));

        var reply = await host.SendAsync($"/test/issue?user={Alice}&persistent=true");

        var set = Assert.Single(reply.Sessions(host.CookieName));
        var key = System.Text.Json.JsonDocument.Parse(reply.Body).RootElement.GetProperty("key").GetString()!;
        var window = await WindowOfAsync(host, key);
        Assert.Equal(window.IssuedUtc!.Value.AddHours(absolute), SessionPipelineIntegrationTest.ExpiresOf(set));
        AssertNear(row, await PttlAsync(host, key));
        AssertNear(row, await PttlAsync(host, IndexOf(Alice)));

        await host.Db.KeyExpireAsync(key, TimeSpan.FromMinutes(1));
        await host.Db.KeyExpireAsync(IndexOf(Alice), TimeSpan.FromMinutes(1));
        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync("/test/me", set.AsRequestCookie())).Status);
        AssertNear(row, await PttlAsync(host, key));
        AssertNear(row, await PttlAsync(host, IndexOf(Alice)));
    }

    // ---- A request admitted before the end (row 95) --------------------------------------------

    public static TheoryData<int> StandAbsoluteLimits() => new()
    {
        720, // the limit the session was issued under
        24, // lowered for a row issued under 720 h
    };

    [RedisTheory]
    [MemberData(nameof(StandAbsoluteLimits))]
    public async Task ARequestAdmittedBeforeTheEnd_Finishes_AndTheNextOneIsNotAuthenticated(int standAbsoluteHours)
    {
        await using var host = await SessionPipelineHost.StartAsync(timeouts: new SessionTimeouts(120, standAbsoluteHours));
        var signIn = WholeSecond(host.Time.GetUtcNow());
        var (key, cookie) = await SeedAsync(host, signIn, 720, TimeSpan.FromHours(120));
        var end = signIn.AddHours(standAbsoluteHours);
        host.Time.SetUtcNow(end.AddMinutes(-1));

        var held = host.SendAsync("/test/hold", cookie);
        await host.Hold.Reached.WaitAsync(TimeSpan.FromSeconds(10)); // authenticated, waiting
        host.Time.SetUtcNow(end.AddSeconds(1));
        host.Hold.Release();

        Assert.Equal(HttpStatusCode.OK, (await held).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.SendAsync("/test/me", cookie)).Status);
        Assert.False(await host.Db.KeyExistsAsync(key));
    }

    [RedisTheory]
    [MemberData(nameof(StandAbsoluteLimits))]
    public async Task TheEndPassingInsideTheAuthentication_EitherOutcomeIsAllowed_AndARejectionDeletesTheRow(int standAbsoluteHours)
    {
        await using var host = await SessionPipelineHost.StartAsync(timeouts: new SessionTimeouts(120, standAbsoluteHours));
        var signIn = WholeSecond(host.Time.GetUtcNow());
        var (key, cookie) = await SeedAsync(host, signIn, 720, TimeSpan.FromHours(120));
        var end = signIn.AddHours(standAbsoluteHours);
        host.Time.SetUtcNow(end.AddMinutes(-1));
        var lifetimeWrite = host.Faults.Hold((name, args) => DbProxy.IsScript(name, args, StoreScripts.Read, key));

        var request = host.SendAsync("/test/me", cookie);
        await lifetimeWrite.Reached.WaitAsync(TimeSpan.FromSeconds(10));
        host.Time.SetUtcNow(end.AddSeconds(1));
        lifetimeWrite.Release();
        var reply = await request;

        Assert.Contains(reply.Status, new[] { HttpStatusCode.OK, HttpStatusCode.Unauthorized });
        if (reply.Status == HttpStatusCode.Unauthorized)
        {
            Assert.False(await host.Db.KeyExistsAsync(key));
        }
    }

    // ---- The lifetime counts from the last write (row 96) -------------------------------------

    [RedisFact]
    public async Task ParallelReads_TheRowLifetimeIsTheOneOfTheLastWrite()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, key, _) = await host.SignInAsync(Alice);
        var first = host.Faults.Hold((name, args) => DbProxy.IsScript(name, args, StoreScripts.Read, key));

        var held = host.SendAsync("/test/me", cookie);
        await first.Reached.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync("/test/me", cookie)).Status); // the second read completes
        await host.Db.KeyExpireAsync(key, TimeSpan.FromSeconds(1));
        first.Release();

        Assert.Equal(HttpStatusCode.OK, (await held).Status);
        AssertNear(host.Timeouts.Idle, await PttlAsync(host, key)); // the last write, the first request's
    }

    // ---- A row gone between the read and the lifetime write (row 99) --------------------------

    [RedisFact]
    public async Task ARowGoneBetweenTheReadAndTheLifetimeWrite_DoesNotAuthenticate_AndIsNotRecreated()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, key, _) = await host.SignInAsync(Alice);
        host.Faults.After = async (name, args) =>
        {
            if (name == nameof(IDatabase.StringGetAsync) && (RedisKey)args[0]! == key)
            {
                await host.Db.KeyDeleteAsync(key);
            }
        };

        var reply = await host.SendAsync("/test/me", cookie);

        host.Faults.After = null;
        Assert.Equal(HttpStatusCode.Unauthorized, reply.Status);
        Assert.Empty(reply.Sessions(host.CookieName));
        Assert.False(await host.Db.KeyExistsAsync(key));
    }
}
