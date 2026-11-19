using System.Diagnostics;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// The session store on a real start of <c>SkeinWeb.dll</c> with session settings of its own
/// (<c>IDLE=9</c>, <c>ABS=15</c>): the settings reach the store (row and index lifetimes after a
/// sign-in), an ordinary authenticated read costs at most two commands to Redis whatever the size of
/// the user's index (the non-functional limit of D-4), and dead index members stay until the user's
/// next sign-in. The commands are counted in the log of the RESP proxy between a mark and the
/// answer; a control window of the same length without a request measures the background. Work
/// inside a script is not visible from outside; the dead member that survives the read holds it.
/// The stand is built from the parts of <c>StandardStartupStand.cs</c> (Redis proxy, process) and a
/// skein-api stand-in of its own that answers for one user with a stable id.
/// </summary>
[Trait("Category", "Integration")]
[Collection("startup-stand")]
public sealed class SessionStoreStartupIntegrationTest
{
    private const string Internal = "stand-internal-secret-0123456789";
    private static readonly Guid User = Guid.Parse("0199a1b2-0000-7000-8000-0000000000a5");
    private static readonly string Index = "skein:user-tickets:" + User;

    /// <summary>A skein-api stand-in: the instance configuration, a sign-in and the profile, always of <see cref="User"/>.</summary>
    private sealed class OneUserApi : IAsyncDisposable
    {
        private readonly WebApplication _app;

        private OneUserApi(WebApplication app)
        {
            _app = app;
            Url = app.Urls.First();
        }

        public string Url { get; }

        public static async Task<OneUserApi> StartAsync()
        {
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            builder.Logging.ClearProviders();
            var app = builder.Build();
            object Me() => new
            {
                id = User.ToString(),
                email = "alice@example.com",
                username = "alice",
                name = "alice",
                role = "user",
                isExternal = false,
                sessionEpoch = 3,
            };
            app.MapGet("/ui/v1/internal/instance-config", () => Results.Json(new
            {
                authMode = "local",
                signupEnabled = false,
                emailEnabled = false,
                turnstileSiteKey = (string?)null,
                projectPrefixMinLength = (int?)null,
                termsUrl = (string?)null,
                privacyUrl = (string?)null,
                instanceAdminEnabled = false,
            }));
            app.MapPost("/ui/v1/auth/login", () => Results.Json(Me()));
            app.MapGet("/ui/v1/auth/me", () => Results.Json(Me()));
            await app.StartAsync();
            return new OneUserApi(app);
        }

        public async ValueTask DisposeAsync()
        {
            await _app.StopAsync();
            await _app.DisposeAsync();
        }
    }

    private sealed class Stand : IAsyncDisposable
    {
        private Stand(RedisProxy proxy, OneUserApi api, AppProcess app, ConnectionMultiplexer mux)
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

        public RedisProxy Proxy { get; }
        public OneUserApi Api { get; }
        public AppProcess App { get; }
        public ConnectionMultiplexer Mux { get; }
        public HttpClient Http { get; }

        /// <summary>The stand's Redis database, reached directly: these commands are not in the proxy log.</summary>
        public IDatabase Db => Mux.GetDatabase(RedisProxy.Database);

        public static async Task<Stand> StartAsync()
        {
            var mux = TestRedis.Connect(RedisProxy.Database);
            mux.GetServers().First(s => !s.IsReplica).FlushDatabase(RedisProxy.Database);
            var endpoint = ConfigurationOptions.Parse(TestRedis.Url!).EndPoints[0];
            var (host, port) = endpoint is DnsEndPoint dns
                ? (dns.Host, dns.Port)
                : (((IPEndPoint)endpoint).Address.ToString(), ((IPEndPoint)endpoint).Port);
            var proxy = new RedisProxy(host, port);
            var api = await OneUserApi.StartAsync();
            var app = AppProcess.Start(new Dictionary<string, string?>
            {
                ["ASPNETCORE_ENVIRONMENT"] = "Development",
                ["SKEIN_ALLOW_INSECURE_HTTP"] = "true",
                ["SKEIN_API_URL"] = api.Url,
                ["SKEIN_INTERNAL_SECRET"] = Internal,
                ["REDIS_URL"] = $"redis://127.0.0.1:{proxy.Port}",
                ["NATS_URL"] = Environment.GetEnvironmentVariable("TEST_NATS_URL"),
                ["SKEIN_API_STARTUP_TIMEOUT_SECONDS"] = "60",
                [SessionTimeoutsSettings.Idle] = "9",
                [SessionTimeoutsSettings.Absolute] = "15",
            });
            return new Stand(proxy, api, app, mux);
        }

        public async Task<string> SignInAsync()
        {
            using var login = new HttpRequestMessage(HttpMethod.Post, "/api/auth/login")
            {
                Content = new StringContent("{\"email\":\"alice@example.com\",\"password\":\"correct-horse-battery\"}",
                    System.Text.Encoding.UTF8, "application/json"),
            };
            using var reply = await Http.SendAsync(login);
            Assert.Equal(HttpStatusCode.OK, reply.StatusCode);
            return reply.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("skein.sid=", StringComparison.Ordinal)).Split(';')[0];
        }

        public async Task<HttpStatusCode> ReadAsync(string cookie)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/auth/me");
            request.Headers.TryAddWithoutValidation("Cookie", cookie);
            using var reply = await Http.SendAsync(request);
            return reply.StatusCode;
        }

        public async ValueTask DisposeAsync()
        {
            Http.Dispose();
            App.Dispose();
            await Api.DisposeAsync();
            Proxy.Dispose();
            Mux.GetServers().First(s => !s.IsReplica).FlushDatabase(RedisProxy.Database);
            Mux.Dispose();
        }
    }

    /// <summary>The names of the two settings, as an operator sets them.</summary>
    private static class SessionTimeoutsSettings
    {
        public const string Idle = SkeinWeb.Auth.SessionTimeouts.IdleTimeoutSetting;
        public const string Absolute = SkeinWeb.Auth.SessionTimeouts.AbsoluteTimeoutSetting;
    }

    private async Task<long> PttlAsync(Stand stand, string key) => (long)await stand.Db.ExecuteAsync("PTTL", key);

    private static void AssertNear(TimeSpan expected, long pttlMs) =>
        Assert.InRange(pttlMs, (long)(expected - TimeSpan.FromSeconds(30)).TotalMilliseconds, (long)expected.TotalMilliseconds);

    private static string[] SessionKeys(Stand stand) =>
        stand.Mux.GetServers().First(s => !s.IsReplica).Keys(RedisProxy.Database, "skein:session:*").Select(k => (string)k!).ToArray();

    [StartupFact]
    public async Task AnOrdinaryRead_CostsAtMostTwoCommands_WhateverTheIndexSize_AndDeadMembersGoOnlyAtTheNextSignIn()
    {
        await using var stand = await Stand.StartAsync();
        Assert.True(await stand.App.WaitForHealthAsync(TimeSpan.FromSeconds(60)), stand.App.Output);

        var cookie = await stand.SignInAsync();
        var key = Assert.Single(SessionKeys(stand));
        // The settings of the process reach the store: min(9 h, 15 h) for the row and the index.
        AssertNear(TimeSpan.FromHours(9), await PttlAsync(stand, key));
        AssertNear(TimeSpan.FromHours(9), await PttlAsync(stand, Index));

        // A first read, to learn how long one takes; then a control window of that length without a request.
        var watch = Stopwatch.StartNew();
        Assert.Equal(HttpStatusCode.OK, await stand.ReadAsync(cookie));
        var window = TimeSpan.FromTicks(Math.Max(watch.Elapsed.Ticks, TimeSpan.FromMilliseconds(200).Ticks));
        var mark = stand.Proxy.Commands().Count;
        await Task.Delay(window);
        var background = stand.Proxy.Commands().Count - mark;

        var dead = new List<string>();
        var counts = new Dictionary<int, int>();
        foreach (var size in new[] { 1, 50, 500 })
        {
            // The user's index of the given size: dead members, and the session's own membership lost.
            await stand.Db.KeyDeleteAsync(Index);
            for (var i = dead.Count; i < size - 1; i++)
            {
                dead.Add("skein:session:dead-" + Guid.NewGuid().ToString("N"));
            }
            if (size > 1)
            {
                await stand.Db.SetAddAsync(Index, dead.Take(size - 1).Select(d => (RedisValue)d).ToArray());
            }

            mark = stand.Proxy.Commands().Count;
            Assert.Equal(HttpStatusCode.OK, await stand.ReadAsync(cookie));
            var commands = stand.Proxy.Commands().Skip(mark).ToList();

            Assert.Contains(commands, c => c.Mentions(key)); // control: the read went through the proxy
            Assert.True(commands.Count - background <= 2,
                $"index of {size}: {commands.Count} commands, background {background}: {string.Join(", ", commands.Select(c => c.Name))}");
            counts[size] = commands.Count(c => c.Mentions(key) || c.Mentions(Index));
            Assert.True(await stand.Db.SetContainsAsync(Index, key)); // the read restored the membership
            if (size > 1)
            {
                Assert.True(await stand.Db.SetContainsAsync(Index, dead[0])); // and left the dead member alone
            }
        }
        Assert.Single(counts.Values.Distinct()); // the same number of commands for 1, 50 and 500 members

        await stand.SignInAsync(); // the next sign-in of the same user
        var members = (await stand.Db.SetMembersAsync(Index)).Select(m => (string)m!).ToList();
        Assert.Contains(key, members);
        Assert.DoesNotContain(members, m => m.StartsWith("skein:session:dead-", StringComparison.Ordinal));
    }
}
