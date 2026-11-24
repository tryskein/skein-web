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
        Func<RedisProxy, Task>? beforeLaunch = null, string? redisUrl = null)
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
                ["REDIS_URL"] = redisUrl ?? $"redis://127.0.0.1:{proxy.Port}",
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

/// <summary>A fact that needs, besides the Redis and the NATS of the harness, a Redis reached through Sentinel.</summary>
internal sealed class SentinelStartupFactAttribute : FactAttribute
{
    public SentinelStartupFactAttribute(
        [System.Runtime.CompilerServices.CallerFilePath] string? sourceFilePath = null,
        [System.Runtime.CompilerServices.CallerLineNumber] int sourceLineNumber = -1)
        : base(sourceFilePath, sourceLineNumber)
    {
        if (string.IsNullOrWhiteSpace(TestRedis.Url) || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("TEST_NATS_URL"))
            || string.IsNullOrWhiteSpace(StandardStartupIntegrationTest.SentinelUrl))
        {
            Skip = "Requires TEST_REDIS_URL, TEST_NATS_URL and TEST_REDIS_SENTINEL_URL (the integration harness).";
        }
    }
}

/// <summary>
/// The start of the real application and the agent bypass (R72), on the stand: the application
/// serves once it is up, whatever the Redis topology behind <c>REDIS_URL</c>, and leaves the session
/// rows it finds in Redis as they are.
/// </summary>
[Trait("Category", "Integration")]
[Collection("startup-stand")]
public sealed class StandardStartupIntegrationTest
{
    /// <summary>
    /// A StackExchange.Redis configuration string that names Sentinel endpoints and a
    /// <c>serviceName</c>, or null outside the harness. The harness's Sentinel names its own primary
    /// and still lists a replica of it that is down, so the connection knows a server that never
    /// connects.
    /// </summary>
    public static string? SentinelUrl => Environment.GetEnvironmentVariable("TEST_REDIS_SENTINEL_URL");

    private const string Legacy = "skein:session:legacy";

    private static async Task<string> SignInAsync(StartupStand stand)
    {
        using var login = new HttpRequestMessage(HttpMethod.Post, "/api/auth/login")
        {
            Content = new StringContent("{\"email\":\"alice@example.com\",\"password\":\"correct-horse-battery\"}",
                System.Text.Encoding.UTF8, "application/json"),
        };
        using var loginReply = await stand.Http.SendAsync(login);
        Assert.Equal(HttpStatusCode.OK, loginReply.StatusCode);
        return loginReply.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("skein.sid=", StringComparison.Ordinal)).Split(';')[0];
    }

    // ---- The start leaves the store as it is; a lost Redis is refused early --------------------------

    [StartupFact]
    public async Task TheStartLeavesARowOfTheFormerFormat_TheApplicationServes_AndTheEarlyBoundaryRefusesWhenRedisIsGone()
    {
        await using var stand = await StartupStand.StartAsync(beforeLaunch: async _ =>
        {
            // A session row of the former format (a hash), there before the application starts.
            var seed = TestRedis.Connect(RedisProxy.Database);
            await seed.GetDatabase(RedisProxy.Database).HashSetAsync(Legacy, [new HashEntry("data", 1)]);
            seed.Dispose();
        });

        Assert.True(await stand.App.WaitForHealthAsync(TimeSpan.FromSeconds(60)), stand.App.Output);
        Assert.Equal(1, await stand.Db.HashLengthAsync(Legacy));

        // A sign-in through the application; the control: its cookie is accepted.
        var cookie = await SignInAsync(stand);
        Assert.Equal(HttpStatusCode.OK, (await stand.SendAsync("/api/auth/me", cookie)).Status);

        var meCalls = stand.Api.MeCalls;
        stand.Proxy.Cut();
        var refused = await stand.SendAsync("/api/auth/me", cookie);

        Assert.Equal(HttpStatusCode.BadGateway, refused.Status);
        Assert.Empty(refused.SetCookies);
        Assert.Equal("upstream_unavailable", JsonDocument.Parse(refused.Body).RootElement.GetProperty("error").GetString());
        Assert.Equal(meCalls, stand.Api.MeCalls);
    }

    // ---- Redis behind Sentinel (sk-1006.9) -------------------------------------------------------------

    [SentinelStartupFact]
    public async Task WithRedisReachedThroughSentinel_AndAReplicaDown_TheApplicationStarts_AndItsSessionLivesOnThePrimary()
    {
        // The test reaches the primary the way the application does: through the Sentinel.
        var options = ConfigurationOptions.Parse(SentinelUrl!);
        options.AllowAdmin = true;
        using var primary = await ConnectionMultiplexer.ConnectAsync(options);
        var db = primary.GetDatabase();
        await db.ExecuteAsync("FLUSHDB");
        try
        {
            await using var stand = await StartupStand.StartAsync(redisUrl: SentinelUrl);

            Assert.True(await stand.App.WaitForHealthAsync(TimeSpan.FromSeconds(60)), stand.App.Output);
            var cookie = await SignInAsync(stand);
            Assert.Equal(HttpStatusCode.OK, (await stand.SendAsync("/api/auth/me", cookie)).Status);

            var rows = (RedisResult[])(await db.ExecuteAsync("KEYS", "skein:session:*"))!;
            Assert.Single(rows);
            Assert.Equal(RedisType.String, await db.KeyTypeAsync((string)rows[0]!));
        }
        finally
        {
            await db.ExecuteAsync("FLUSHDB");
        }
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
        var mcp = await stand.SendAsync("/mcp", cookie, HttpMethod.Post, ("X-Skein-Api-Key", "ska_test"));

        // The answer came from the application through to skein-api, not from an earlier refusal.
        Assert.Equal(HttpStatusCode.OK, mcp.Status);
        Assert.Equal(1, stand.Api.McpCalls);

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
