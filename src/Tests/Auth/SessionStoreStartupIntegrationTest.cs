using System.Globalization;
using System.Net.Sockets;
using System.Text;
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
/// answer, on the client connection that carried the read; commands of other connections are the
/// background. Work inside a script is not visible from outside; the dead member that survives the
/// read holds it. The stand runs the process of <c>StandardStartupStand.cs</c> behind a proxy of its
/// own that logs the connection of each command, with a skein-api stand-in of its own that answers
/// for one user with a stable id.
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

    /// <summary>One command a client sent, with the number of the client connection that carried it.</summary>
    private sealed record Sent(int Connection, string Name, string[] Args)
    {
        public bool Mentions(string key) => Args.Any(a => a == key);
    }

    /// <summary>
    /// A TCP proxy in front of the real Redis that logs every command with the number of the client
    /// connection that sent it, and selects <see cref="RedisProxy.Database"/> on every upstream
    /// connection. The stand's own proxy logs commands without their connection; the count of an
    /// ordinary read is per connection, so this test carries its own.
    /// </summary>
    private sealed class ConnectionLog : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly List<TcpClient> _sockets = [];
        private readonly List<Sent> _log = [];
        private int _connections;
        private volatile bool _closed;

        public ConnectionLog(string host, int port)
        {
            _listener.Start();
            _ = Task.Run(async () =>
            {
                while (!_closed)
                {
                    try
                    {
                        var client = await _listener.AcceptTcpClientAsync();
                        var upstream = new TcpClient();
                        await upstream.ConnectAsync(host, port);
                        var db = RedisProxy.Database.ToString(CultureInfo.InvariantCulture);
                        await upstream.GetStream().WriteAsync(Encoding.ASCII.GetBytes($"*2\r\n$6\r\nSELECT\r\n${db.Length}\r\n{db}\r\n"));
                        var ok = new byte[5];
                        await upstream.GetStream().ReadExactlyAsync(ok); // +OK\r\n
                        var id = Interlocked.Increment(ref _connections);
                        lock (_sockets)
                        {
                            _sockets.Add(client);
                            _sockets.Add(upstream);
                        }
                        _ = PumpAsync(id, client, upstream);
                        _ = upstream.GetStream().CopyToAsync(client.GetStream()).ContinueWith(_ => { });
                    }
                    catch (Exception)
                    {
                        return;
                    }
                }
            });
        }

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        public IReadOnlyList<Sent> Commands()
        {
            lock (_log)
            {
                return _log.ToArray();
            }
        }

        private async Task PumpAsync(int id, TcpClient client, TcpClient upstream)
        {
            var input = client.GetStream();
            var output = upstream.GetStream();
            var buffer = new List<byte>();
            var chunk = new byte[16 * 1024];
            try
            {
                while (true)
                {
                    var read = await input.ReadAsync(chunk);
                    if (read == 0)
                    {
                        return;
                    }
                    buffer.AddRange(chunk.AsSpan(0, read).ToArray());
                    while (TryParse(buffer, out var parts, out var length))
                    {
                        lock (_log)
                        {
                            _log.Add(new Sent(id, parts[0].ToUpperInvariant(), parts[1..]));
                        }
                        buffer.RemoveRange(0, length);
                    }
                    await output.WriteAsync(chunk.AsMemory(0, read));
                }
            }
            catch (Exception)
            {
                // a closed peer ends the pipe
            }
        }

        // One RESP array of bulk strings: *N, then N times $len and the bytes.
        private static bool TryParse(List<byte> buffer, out string[] parts, out int length)
        {
            parts = [];
            length = 0;
            var pos = 0;
            if (buffer.Count == 0 || buffer[0] != (byte)'*' || !ReadLine(buffer, ref pos, out var header))
            {
                return false;
            }
            var count = int.Parse(header[1..], CultureInfo.InvariantCulture);
            var read = new string[count];
            for (var i = 0; i < count; i++)
            {
                if (!ReadLine(buffer, ref pos, out var size) || size[0] != '$')
                {
                    return false;
                }
                var n = int.Parse(size[1..], CultureInfo.InvariantCulture);
                if (buffer.Count < pos + n + 2)
                {
                    return false;
                }
                read[i] = Encoding.UTF8.GetString(buffer.GetRange(pos, n).ToArray());
                pos += n + 2;
            }
            parts = read;
            length = pos;
            return true;
        }

        private static bool ReadLine(List<byte> buffer, ref int pos, out string line)
        {
            for (var i = pos; i + 1 < buffer.Count; i++)
            {
                if (buffer[i] == '\r' && buffer[i + 1] == '\n')
                {
                    line = Encoding.ASCII.GetString(buffer.GetRange(pos, i - pos).ToArray());
                    pos = i + 2;
                    return true;
                }
            }
            line = "";
            return false;
        }

        public void Dispose()
        {
            _closed = true;
            _listener.Stop();
            lock (_sockets)
            {
                foreach (var socket in _sockets)
                {
                    socket.Close();
                }
            }
        }
    }

    private sealed class Stand : IAsyncDisposable
    {
        private Stand(ConnectionLog proxy, OneUserApi api, AppProcess app, ConnectionMultiplexer mux)
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

        public ConnectionLog Proxy { get; }
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
            var proxy = new ConnectionLog(host, port);
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

        Assert.Equal(HttpStatusCode.OK, await stand.ReadAsync(cookie)); // the scripts are loaded before counting

        var dead = new List<string>();
        var counts = new Dictionary<int, int>();
        foreach (var size in new[] { 1, 50, 500 })
        {
            // The user's index at the declared size: only dead members, the session's own membership lost.
            await stand.Db.KeyDeleteAsync(Index);
            while (dead.Count < size)
            {
                dead.Add("skein:session:dead-" + Guid.NewGuid().ToString("N"));
            }
            await stand.Db.SetAddAsync(Index, dead.Take(size).Select(d => (RedisValue)d).ToArray());
            Assert.Equal(size, await stand.Db.SetLengthAsync(Index));

            var mark = stand.Proxy.Commands().Count;
            Assert.Equal(HttpStatusCode.OK, await stand.ReadAsync(cookie));
            var window = stand.Proxy.Commands().Skip(mark).ToList();

            // The foreground: every command, whatever its keys, on the connection that carried the read of
            // this session; commands of other connections in the same window are the background.
            var foreground = window.Where(c => c.Mentions(key)).Select(c => c.Connection).ToHashSet();
            Assert.NotEmpty(foreground); // control: the read went through the proxy
            var commands = window.Where(c => foreground.Contains(c.Connection)).ToList();
            Assert.True(commands.Count <= 2,
                $"index of {size}: {commands.Count} commands: {string.Join(", ", commands.Select(c => c.Name))}");
            counts[size] = commands.Count;

            Assert.True(await stand.Db.SetContainsAsync(Index, key)); // the read restored the membership
            Assert.True(await stand.Db.SetContainsAsync(Index, dead[0])); // and left the dead members alone
            Assert.Equal(size + 1, await stand.Db.SetLengthAsync(Index));
        }
        Assert.Single(counts.Values.Distinct()); // the same number of commands for 1, 50 and 500 members

        await stand.SignInAsync(); // the next sign-in of the same user
        var members = (await stand.Db.SetMembersAsync(Index)).Select(m => (string)m!).ToList();
        Assert.Contains(key, members);
        Assert.DoesNotContain(members, m => m.StartsWith("skein:session:dead-", StringComparison.Ordinal));
    }
}
