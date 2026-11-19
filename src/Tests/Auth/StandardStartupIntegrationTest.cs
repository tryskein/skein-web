using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using StackExchange.Redis;
using SkeinWeb.Auth;

namespace SkeinWeb.Tests.Auth;

/// <summary>A fact that needs the Redis and the NATS of the harness (the stand starts the real application).</summary>
internal sealed class StartupFactAttribute : FactAttribute
{
    public StartupFactAttribute(
        [System.Runtime.CompilerServices.CallerFilePath] string? sourceFilePath = null,
        [System.Runtime.CompilerServices.CallerLineNumber] int sourceLineNumber = -1)
        : base(sourceFilePath, sourceLineNumber)
    {
        if (string.IsNullOrWhiteSpace(TestRedis.Url) || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("TEST_NATS_URL")))
        {
            Skip = "Requires TEST_REDIS_URL and TEST_NATS_URL (the integration harness).";
        }
    }
}

/// <summary>The built application as a process, with a stub skein-api and a Redis proxy of its own in front of the real Redis.</summary>
internal sealed class StartupStand : IAsyncDisposable
{
    public const string Internal = "stand-internal-secret-0123456789";
    public RedisProxy Proxy { get; }
    public StubSkeinApi Api { get; }
    public AppProcess App { get; }
    public ConnectionMultiplexer Mux { get; }
    public IDatabase Db => Mux.GetDatabase(RedisProxy.Database);
    public HttpClient Http { get; }

    private readonly IDictionary<string, string?> _environment;
    private readonly List<AppProcess> _others = [];

    private StartupStand(RedisProxy proxy, StubSkeinApi api, AppProcess app, ConnectionMultiplexer mux, IDictionary<string, string?> environment)
    {
        _environment = environment;
        Proxy = proxy;
        Api = api;
        App = app;
        Mux = mux;
        Http = new HttpClient(new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false })
        {
            BaseAddress = new Uri($"http://127.0.0.1:{app.Port}"),
        };
    }

    public static async Task<StartupStand> StartAsync(
        string environment = "Development", string insecure = "true", string authMode = "local", string? trusted = null,
        Func<RedisProxy, Task>? beforeLaunch = null)
    {
        var mux = TestRedis.Connect(RedisProxy.Database);
        mux.GetServers().First(s => !s.IsReplica).FlushDatabase(RedisProxy.Database);
        var options = StackExchange.Redis.ConfigurationOptions.Parse(TestRedis.Url!);
        var endpoint = options.EndPoints[0];
        var (host, port) = endpoint is DnsEndPoint dns ? (dns.Host, dns.Port) : (((IPEndPoint)endpoint).Address.ToString(), ((IPEndPoint)endpoint).Port);
        RedisProxy? proxy = null;
        StubSkeinApi? api = null;
        try
        {
            proxy = new RedisProxy(host, port);
            api = await StubSkeinApi.StartAsync(authMode);
            if (beforeLaunch is not null)
            {
                await beforeLaunch(proxy);
            }
            var environmentOfTheStand = new Dictionary<string, string?>
            {
                ["ASPNETCORE_ENVIRONMENT"] = environment,
                ["SKEIN_ALLOW_INSECURE_HTTP"] = insecure,
                ["SKEIN_API_URL"] = api.Url,
                ["SKEIN_INTERNAL_SECRET"] = Internal,
                ["REDIS_URL"] = $"redis://127.0.0.1:{proxy.Port}",
                ["NATS_URL"] = Environment.GetEnvironmentVariable("TEST_NATS_URL"),
                ["SKEIN_TRUSTED_PROXIES"] = trusted,
                ["SKEIN_API_STARTUP_TIMEOUT_SECONDS"] = "60",
            };
            var app = AppProcess.Start(environmentOfTheStand);
            return new StartupStand(proxy, api, app, mux, environmentOfTheStand);
        }
        catch
        {
            proxy?.Dispose();
            if (api is not null)
            {
                await api.DisposeAsync();
            }
            mux.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Starts one more process of the application with the settings of the stand, on the same
    /// Redis proxy, database and stub skein-api. The stand stays the only owner of the database: it
    /// is not flushed here, and the stand stops every process it started when it is disposed.
    /// </summary>
    public AppProcess StartAnother()
    {
        var app = AppProcess.Start(_environment);
        _others.Add(app);
        return app;
    }

    public async Task<(HttpStatusCode Status, string Body, string[] SetCookies)> SendAsync(
        string path, string? cookie = null, HttpMethod? method = null, params (string, string)[] headers)
    {
        using var request = new HttpRequestMessage(method ?? HttpMethod.Get, path);
        if (cookie is not null)
        {
            request.Headers.TryAddWithoutValidation("Cookie", cookie);
        }
        foreach (var (name, value) in headers)
        {
            request.Headers.TryAddWithoutValidation(name, value);
        }
        if (request.Method == HttpMethod.Post)
        {
            request.Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json");
        }
        using var response = await Http.SendAsync(request);
        var cookies = response.Headers.TryGetValues("Set-Cookie", out var values) ? values.ToArray() : [];
        return (response.StatusCode, await response.Content.ReadAsStringAsync(), cookies);
    }

    public async ValueTask DisposeAsync()
    {
        Http.Dispose();
        foreach (var other in _others)
        {
            other.Dispose();
        }
        App.Dispose();
        Proxy.Dispose();
        await Api.DisposeAsync();
        Mux.GetServers().First(s => !s.IsReplica).FlushDatabase(RedisProxy.Database);
        Mux.Dispose();
    }
}

/// <summary>
/// The startup order of the real application around the startup session cleanup (R68), two processes
/// on one Redis, and the agent bypass (R72), on the stand. The holds name the commands the
/// application really sends: the scan for rows of the former format, and the scripts of the pass by
/// their keys (an <c>EVALSHA</c> carries a SHA, not the script text).
/// </summary>
[Trait("Category", "Integration")]
[Collection("startup-stand")]
public sealed class StandardStartupIntegrationTest
{
    private const string Legacy = "skein:session:legacy";

    private static async Task AssertNoPortForAWhileAsync(AppProcess app)
    {
        for (var i = 0; i < 10; i++)
        {
            Assert.False(await app.AcceptsConnectionAsync(), "the port accepted a connection before the cleanup finished");
            await Task.Delay(100);
        }
    }

    private static async Task<(StartupStand Stand, RedisHold Hold)> StartHeldAsync(Func<RedisCommand, bool> predicate, bool marker = false)
    {
        RedisHold? hold = null;
        var stand = await StartupStand.StartAsync(beforeLaunch: async proxy =>
        {
            // The legacy hash (and the marker of an earlier deployment) must be there before the application starts.
            var seed = TestRedis.Connect(RedisProxy.Database);
            await seed.GetDatabase(RedisProxy.Database).HashSetAsync(Legacy, [new HashEntry("data", 1)]);
            if (marker)
            {
                await seed.GetDatabase(RedisProxy.Database).StringSetAsync(SessionStoreMigration.MarkerKey, SessionStoreMigration.MarkerValue);
            }
            seed.Dispose();
            hold = proxy.Hold(predicate);
        });
        try
        {
            await hold!.Reached.WaitAsync(TimeSpan.FromSeconds(60));
        }
        catch
        {
            // A start that never reaches the held command must not leave the process and the ports behind.
            await stand.DisposeAsync();
            throw;
        }
        return (stand, hold);
    }

    private static async Task<long> GenerationAsync(StartupStand stand) =>
        (long?)await stand.Db.StringGetAsync(SessionStoreMigration.GenerationKey) ?? 0;

    // ---- R68 (а): the early window ------------------------------------------------------------

    [StartupFact]
    public async Task EarlyWindow_OnTheScanForFormerRows_NoPortIsOpen_AndTheFormerHashIsThere()
    {
        var (stand, _) = await StartHeldAsync(c => c.Name == "SCAN" && c.Args.Contains(CleanupCalls.SessionPattern));
        await using var _stand = stand;

        // The scan the implementation sends asks for hashes of the session keys only.
        var scan = stand.Proxy.Commands().Last(c => c.Name == "SCAN");
        Assert.Equal(new[] { "MATCH", CleanupCalls.SessionPattern }, scan.Args.Skip(1).Take(2));
        Assert.Contains("TYPE", scan.Args);
        Assert.Equal("hash", scan.Args[Array.IndexOf(scan.Args, "TYPE") + 1]);
        await AssertNoPortForAWhileAsync(stand.App);
        Assert.True(await stand.Db.KeyExistsAsync(Legacy));
        Assert.False(await stand.Db.KeyExistsAsync(SessionStoreMigration.MarkerKey));
        Assert.False(stand.App.HasExited, stand.App.Output);
    }

    // ---- R68 (б), (в): the finish of the pass is the boundary ----------------------------------

    [StartupFact]
    public async Task TheFinishOfThePass_IsTheBoundary_BeforeIt_NoPortAndNoMarker_AfterIt_TheMarkerTheCountAndService()
    {
        var (stand, hold) = await StartHeldAsync(c => CleanupCalls.Of(c) == CleanupStep.Finish);
        await using var _stand = stand;

        // Held: the owner still has the lock, there is no marker, the count has not moved, the rows are gone.
        Assert.True(hold.Reached.IsCompletedSuccessfully);
        await AssertNoPortForAWhileAsync(stand.App);
        Assert.True(await stand.Db.KeyExistsAsync(SessionStoreMigration.LockKey));
        Assert.False(await stand.Db.KeyExistsAsync(SessionStoreMigration.MarkerKey));
        Assert.Equal(0, await GenerationAsync(stand));
        Assert.False(await stand.Db.KeyExistsAsync(Legacy));

        hold.Release();

        Assert.True(await stand.App.WaitForHealthAsync(TimeSpan.FromSeconds(60)), stand.App.Output);
        Assert.Equal(SessionStoreMigration.MarkerValue, await stand.Db.StringGetAsync(SessionStoreMigration.MarkerKey));
        Assert.Equal(1, await GenerationAsync(stand));
        Assert.False(await stand.Db.KeyExistsAsync(SessionStoreMigration.LockKey));
    }

    // ---- US-5: two processes on one Redis ---------------------------------------------------------

    [StartupFact]
    public async Task TwoProcesses_OnOneRedis_RunOnePass_AndTheSecondServesOnlyAfterIt()
    {
        // The marker of an earlier deployment and a hash of the former format: a re-rollout after a rollback.
        var (stand, hold) = await StartHeldAsync(c => CleanupCalls.Of(c) == CleanupStep.Finish, marker: true);
        await using var _stand = stand;
        var mark = stand.Proxy.Commands().Count;

        var second = stand.StartAnother();

        // The second process observes the pass of the first one and waits: it polls the state.
        var deadline = DateTime.UtcNow.AddSeconds(60);
        while (stand.Proxy.Commands().Skip(mark).Count(c => CleanupCalls.Of(c) == CleanupStep.Status) < 3)
        {
            Assert.True(DateTime.UtcNow < deadline, "the second process did not reach the wait for the pass: " + second.Output);
            Assert.False(second.HasExited, second.Output);
            await Task.Delay(50);
        }
        await AssertNoPortForAWhileAsync(second);
        await AssertNoPortForAWhileAsync(stand.App);
        Assert.DoesNotContain(stand.Proxy.Commands().Skip(mark), c => CleanupCalls.Of(c) == CleanupStep.Begin);

        hold.Release();

        Assert.True(await stand.App.WaitForHealthAsync(TimeSpan.FromSeconds(60)), stand.App.Output);
        Assert.True(await second.WaitForHealthAsync(TimeSpan.FromSeconds(60)), second.Output);
        Assert.Equal(1, await GenerationAsync(stand));
        Assert.Single(stand.Proxy.Commands(), c => CleanupCalls.Of(c) == CleanupStep.Finish);
        Assert.Equal(SessionStoreMigration.MarkerValue, await stand.Db.StringGetAsync(SessionStoreMigration.MarkerKey));
        Assert.False(await stand.Db.KeyExistsAsync(Legacy));
    }

    // ---- R68 (в) and the release of every window ------------------------------------------------

    [StartupFact]
    public async Task AfterTheCleanup_TheApplicationServes_AndTheEarlyBoundaryRefusesWhenRedisIsGone()
    {
        await using var stand = await StartupStand.StartAsync(beforeLaunch: async _ =>
        {
            var seed = TestRedis.Connect(RedisProxy.Database);
            await seed.GetDatabase(RedisProxy.Database).HashSetAsync(Legacy, [new HashEntry("data", 1)]);
            seed.Dispose();
        });

        Assert.True(await stand.App.WaitForHealthAsync(TimeSpan.FromSeconds(60)), stand.App.Output);
        Assert.False(await stand.Db.KeyExistsAsync(Legacy));
        Assert.Equal(SessionStoreMigration.MarkerValue, await stand.Db.StringGetAsync(SessionStoreMigration.MarkerKey));

        // A sign-in through the application; the control: its cookie is accepted.
        using var login = new HttpRequestMessage(HttpMethod.Post, "/api/auth/login")
        {
            Content = new StringContent("{\"email\":\"alice@example.com\",\"password\":\"correct-horse-battery\"}",
                System.Text.Encoding.UTF8, "application/json"),
        };
        using var loginReply = await stand.Http.SendAsync(login);
        Assert.Equal(HttpStatusCode.OK, loginReply.StatusCode);
        var cookie = loginReply.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("skein.sid=", StringComparison.Ordinal)).Split(';')[0];
        Assert.Equal(HttpStatusCode.OK, (await stand.SendAsync("/api/auth/me", cookie)).Status);

        var meCalls = stand.Api.MeCalls;
        stand.Proxy.Cut();
        var refused = await stand.SendAsync("/api/auth/me", cookie);

        Assert.Equal(HttpStatusCode.BadGateway, refused.Status);
        Assert.Empty(refused.SetCookies);
        Assert.Equal("upstream_unavailable", JsonDocument.Parse(refused.Body).RootElement.GetProperty("error").GetString());
        Assert.Equal(meCalls, stand.Api.MeCalls);
    }

    // ---- R72: /agent/v1 and /mcp do not touch the session; an ordinary path reads it ----------------

    [StartupFact]
    public async Task TheAgentPath_NeverReadsOrRenewsTheTicket_WhileAnOrdinaryPathDoes()
    {
        await using var stand = await StartupStand.StartAsync(authMode: "keycloak", trusted: "127.0.0.1");
        Assert.True(await stand.App.WaitForHealthAsync(TimeSpan.FromSeconds(60)), stand.App.Output);

        // Control of the bootstrap: headers without a cookie provision once and issue a cookie.
        var signIn = await stand.SendAsync("/api/auth/me", null, null, ("X-Auth-Request-User", "alice"), ("X-Auth-Request-Email", "alice@example.com"));
        Assert.Equal(HttpStatusCode.OK, signIn.Status);
        Assert.Equal(1, stand.Api.Provisions);
        var cookie = signIn.SetCookies.Single(c => c.StartsWith("skein.sid=", StringComparison.Ordinal)).Split(';')[0];

        // The row of that session, with a small lifetime left: a read writes the row's lifetime anew.
        var key = (string)stand.Mux.GetServers().First(s => !s.IsReplica).Keys(RedisProxy.Database, "skein:session:*").Single()!;
        Assert.True(await stand.Db.KeyExpireAsync(key, TimeSpan.FromSeconds(60)));
        var before = (byte[])(await stand.Db.StringGetAsync(key))!;

        // The agent path: no command names the key, the bytes and the lifetime are not written.
        var lifetime = await stand.Db.KeyTimeToLiveAsync(key);
        var mark = stand.Proxy.Commands().Count;
        var provisions = stand.Api.Provisions;
        var agent = await stand.SendAsync("/agent/v1/ping", cookie, null,
            ("X-Auth-Request-User", "bob"), ("X-Auth-Request-Email", "bob@example.com"), ("X-Skein-Api-Key", "ska_test"));

        Assert.Empty(agent.SetCookies);
        Assert.DoesNotContain(stand.Proxy.Commands().Skip(mark), c => c.Mentions(key));
        Assert.Equal(before, (byte[])(await stand.Db.StringGetAsync(key))!);
        Assert.True(await stand.Db.KeyTimeToLiveAsync(key) <= lifetime, "the agent path wrote a new lifetime of the row");
        Assert.Equal(provisions, stand.Api.Provisions);
        Assert.Equal(1, stand.Api.AgentCalls);

        // /mcp with the same cookie: the same — no new lifetime is written (the time left only goes down).
        lifetime = await stand.Db.KeyTimeToLiveAsync(key);
        mark = stand.Proxy.Commands().Count;
        await stand.SendAsync("/mcp", cookie, HttpMethod.Post, ("X-Skein-Api-Key", "ska_test"));

        Assert.DoesNotContain(stand.Proxy.Commands().Skip(mark), c => c.Mentions(key));
        Assert.Equal(before, (byte[])(await stand.Db.StringGetAsync(key))!);
        Assert.True(await stand.Db.KeyTimeToLiveAsync(key) <= lifetime, "/mcp wrote a new lifetime of the row");

        // The distinguishing control on the same row: an ordinary protected path reads the ticket and
        // writes the row's lifetime, the bytes of the ticket stay.
        mark = stand.Proxy.Commands().Count;
        var ordinary = await stand.SendAsync("/api/auth/me", cookie);
        Assert.Equal(HttpStatusCode.OK, ordinary.Status);
        Assert.Contains(stand.Proxy.Commands().Skip(mark), c => c.Mentions(key));
        Assert.True(await stand.Db.KeyTimeToLiveAsync(key) > TimeSpan.FromHours(1), "the ordinary path did not write the row's lifetime");
        Assert.Equal(before, (byte[])(await stand.Db.StringGetAsync(key))!);
    }
}
