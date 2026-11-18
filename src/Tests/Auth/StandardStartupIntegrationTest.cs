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

    private StartupStand(RedisProxy proxy, StubSkeinApi api, AppProcess app, ConnectionMultiplexer mux)
    {
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
        var proxy = new RedisProxy(host, port);
        var api = await StubSkeinApi.StartAsync(authMode);
        if (beforeLaunch is not null)
        {
            await beforeLaunch(proxy);
        }
        var app = AppProcess.Start(new Dictionary<string, string?>
        {
            ["ASPNETCORE_ENVIRONMENT"] = environment,
            ["SKEIN_ALLOW_INSECURE_HTTP"] = insecure,
            ["SKEIN_API_URL"] = api.Url,
            ["SKEIN_INTERNAL_SECRET"] = Internal,
            ["REDIS_URL"] = $"redis://127.0.0.1:{proxy.Port}",
            ["NATS_URL"] = Environment.GetEnvironmentVariable("TEST_NATS_URL"),
            ["SKEIN_TRUSTED_PROXIES"] = trusted,
            ["SKEIN_API_STARTUP_TIMEOUT_SECONDS"] = "60",
        });
        return new StartupStand(proxy, api, app, mux);
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
        App.Dispose();
        Proxy.Dispose();
        await Api.DisposeAsync();
        Mux.GetServers().First(s => !s.IsReplica).FlushDatabase(RedisProxy.Database);
        Mux.Dispose();
    }
}

/// <summary>The startup order of the real application (R68) and the agent bypass (R72), on the stand.</summary>
[Trait("Category", "Integration")]
[Collection("startup-stand")]
public sealed class StandardStartupIntegrationTest
{
    private const string Legacy = "skein:session:legacy";

    private static async Task SeedLegacyAsync(StartupStand stand) =>
        await stand.Db.HashSetAsync(Legacy, [new HashEntry("absexp", -1), new HashEntry("sldexp", 86400), new HashEntry("data", new byte[] { 1 })]);

    private static async Task AssertNoPortForAWhileAsync(StartupStand stand)
    {
        for (var i = 0; i < 10; i++)
        {
            Assert.False(await stand.App.AcceptsConnectionAsync(), "the port accepted a connection before the cleanup finished");
            await Task.Delay(100);
        }
    }

    private static async Task<StartupStand> StartHeldAsync(Func<RedisCommand, bool> predicate)
    {
        RedisHold? hold = null;
        StartupStand? stand = null;
        stand = await StartupStand.StartAsync(beforeLaunch: async proxy =>
        {
            // The legacy hash must be there before the application starts.
            var seed = TestRedis.Connect(RedisProxy.Database);
            await seed.GetDatabase(RedisProxy.Database).HashSetAsync(Legacy, [new HashEntry("data", 1)]);
            seed.Dispose();
            hold = proxy.Hold(predicate);
        });
        await hold!.Reached.WaitAsync(TimeSpan.FromSeconds(60));
        return stand;
    }

    // ---- R68 (а): the early window ------------------------------------------------------------

    [StartupFact]
    public async Task EarlyWindow_NoPortIsOpen_TheLegacyKeyIsStillThere_AndThereIsNoMarker()
    {
        await using var stand = await StartHeldAsync(c => c.IsScriptWith("TYPE"));

        await AssertNoPortForAWhileAsync(stand);
        Assert.True(await stand.Db.KeyExistsAsync(Legacy));
        Assert.False(await stand.Db.KeyExistsAsync(SessionStoreMigration.MarkerKey));
        Assert.False(stand.App.HasExited, stand.App.Output);
    }

    // ---- R68 (б1): the marker script is held ---------------------------------------------------

    [StartupFact]
    public async Task FinalWindow_OnTheMarkerScript_NoPortIsOpen_AndThereIsNoMarker()
    {
        await using var stand = await StartHeldAsync(c => c.IsScriptWith("KEYS[2]"));

        await AssertNoPortForAWhileAsync(stand);
        Assert.False(await stand.Db.KeyExistsAsync(SessionStoreMigration.MarkerKey));
        Assert.False(await stand.Db.KeyExistsAsync(Legacy)); // the delete already ran
    }

    // ---- R68 (б2): the lock release after the marker is held ----------------------------------

    [StartupFact]
    public async Task FinalWindow_OnTheLockRelease_NoPortIsOpen_TheMarkerIsAlreadySet_AndTheLockIsStillThere()
    {
        await using var stand = await StartHeldAsync(c => c.IsScriptWith("return redis.call('DEL', KEYS[1])"));

        await AssertNoPortForAWhileAsync(stand);
        Assert.Equal(SessionStoreMigration.MarkerValue, await stand.Db.StringGetAsync(SessionStoreMigration.MarkerKey));
        Assert.True(await stand.Db.KeyExistsAsync(SessionStoreMigration.LockKey));
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

    // ---- R72: /agent/v1 bypasses Main and the SSO bootstrap -------------------------------------

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

        // The row of that session, rewritten as a LIVE ticket past half of its lifetime.
        var key = (string)stand.Mux.GetServers().First(s => !s.IsReplica).Keys(RedisProxy.Database, "skein:session:*").Single()!;
        var ticket = TicketSerializer.Default.Deserialize((byte[])(await stand.Db.StringGetAsync(key))!)!;
        var issued = DateTimeOffset.UtcNow.AddHours(-13);
        ticket.Properties.IssuedUtc = issued;
        ticket.Properties.ExpiresUtc = issued.AddHours(24);
        var before = TicketSerializer.Default.Serialize(ticket);
        await stand.Db.StringSetAsync(key, before, TimeSpan.FromHours(24));

        var mark = stand.Proxy.Commands().Count;
        var provisions = stand.Api.Provisions;
        var agent = await stand.SendAsync("/agent/v1/ping", cookie, null,
            ("X-Auth-Request-User", "bob"), ("X-Auth-Request-Email", "bob@example.com"), ("X-Skein-Api-Key", "ska_test"));

        Assert.Empty(agent.SetCookies);
        Assert.DoesNotContain(stand.Proxy.Commands().Skip(mark), c => c.Mentions(key));
        Assert.Equal(before, (byte[])(await stand.Db.StringGetAsync(key))!);
        Assert.Equal(provisions, stand.Api.Provisions);
        Assert.Equal(1, stand.Api.AgentCalls);

        // The distinguishing control on the same ticket: an ordinary protected path does read and slide it.
        mark = stand.Proxy.Commands().Count;
        var ordinary = await stand.SendAsync("/api/auth/me", cookie);
        Assert.Equal(HttpStatusCode.OK, ordinary.Status);
        Assert.Contains(stand.Proxy.Commands().Skip(mark), c => c.Mentions(key));
        var after = TicketSerializer.Default.Deserialize((byte[])(await stand.Db.StringGetAsync(key))!)!;
        Assert.True(after.Properties.ExpiresUtc > ticket.Properties.ExpiresUtc);
    }
}
