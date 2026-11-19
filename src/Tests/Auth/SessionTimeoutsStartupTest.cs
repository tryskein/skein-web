using System.Globalization;
using System.Net;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Auth;

/// <summary>A theory that runs only when the harness provides <c>TEST_REDIS_URL</c> and <c>TEST_NATS_URL</c>.</summary>
internal sealed class StartupTheoryAttribute : TheoryAttribute
{
    public StartupTheoryAttribute(
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

/// <summary>
/// The two session limits on a real start of <c>SkeinWeb.dll</c> (FR-001, SC-005, D-5, INV-4): a
/// set but invalid value stops the process before it listens, naming the setting; valid values,
/// the defaults included, are the ones in effect — logged once at startup and carried by the
/// expiry of a persistent session cookie. The stand is built from the parts of
/// <c>StandardStartupStand.cs</c>: a Redis proxy, a stub skein-api and the process.
/// </summary>
[Trait("Category", "Integration")]
[Collection("startup-stand")]
public sealed class SessionTimeoutsStartupTest
{
    private const string Idle = "SKEIN_SESSION_IDLE_TIMEOUT_HOURS";
    private const string Absolute = "SKEIN_SESSION_ABSOLUTE_TIMEOUT_HOURS";

    /// <summary>A process with its own Redis proxy and stub skein-api, and the session settings given.</summary>
    private sealed class Stand : IAsyncDisposable
    {
        private Stand(RedisProxy proxy, StubSkeinApi api, AppProcess app)
        {
            Proxy = proxy;
            Api = api;
            App = app;
        }

        public RedisProxy Proxy { get; }
        public StubSkeinApi Api { get; }
        public AppProcess App { get; }

        public static async Task<Stand> StartAsync(string? idle, string? absolute)
        {
            using (var mux = TestRedis.Connect(RedisProxy.Database))
            {
                mux.GetServers().First(s => !s.IsReplica).FlushDatabase(RedisProxy.Database);
            }
            var endpoint = ConfigurationOptions.Parse(TestRedis.Url!).EndPoints[0];
            var (host, port) = endpoint is DnsEndPoint dns
                ? (dns.Host, dns.Port)
                : (((IPEndPoint)endpoint).Address.ToString(), ((IPEndPoint)endpoint).Port);
            var proxy = new RedisProxy(host, port);
            StubSkeinApi? api = null;
            try
            {
                api = await StubSkeinApi.StartAsync("local");
                var app = AppProcess.Start(new Dictionary<string, string?>
                {
                    ["ASPNETCORE_ENVIRONMENT"] = "Development",
                    ["SKEIN_ALLOW_INSECURE_HTTP"] = "true",
                    ["SKEIN_API_URL"] = api.Url,
                    ["SKEIN_INTERNAL_SECRET"] = StartupStand.Internal,
                    ["REDIS_URL"] = $"redis://127.0.0.1:{proxy.Port}",
                    ["NATS_URL"] = Environment.GetEnvironmentVariable("TEST_NATS_URL"),
                    ["SKEIN_API_STARTUP_TIMEOUT_SECONDS"] = "60",
                    [Idle] = idle,
                    [Absolute] = absolute,
                });
                return new Stand(proxy, api, app);
            }
            catch
            {
                proxy.Dispose();
                if (api is not null)
                {
                    await api.DisposeAsync();
                }
                throw;
            }
        }

        public async ValueTask DisposeAsync()
        {
            App.Dispose();
            await Api.DisposeAsync();
            Proxy.Dispose();
            using var mux = TestRedis.Connect(RedisProxy.Database);
            mux.GetServers().First(s => !s.IsReplica).FlushDatabase(RedisProxy.Database);
        }
    }

    public static TheoryData<string, string, string> InvalidStarts()
    {
        var data = new TheoryData<string, string, string>();
        foreach (var (setting, other) in new[] { (Idle, Absolute), (Absolute, Idle) })
        {
            data.Add(setting, other, "");     // empty
            data.Add(setting, other, "1.5");  // not a whole number
            data.Add(setting, other, "8761"); // out of range
        }
        return data;
    }

    [StartupTheory]
    [MemberData(nameof(InvalidStarts))]
    public async Task AnInvalidValue_StopsTheProcessNamingTheSetting_AndItNeverAcceptsAConnection(
        string setting, string other, string value)
    {
        await using var stand = await Stand.StartAsync(
            idle: setting == Idle ? value : "24", absolute: setting == Absolute ? value : "24");

        var accepted = false;
        for (var i = 0; i < 1500 && !stand.App.HasExited; i++)
        {
            accepted |= await stand.App.AcceptsConnectionAsync();
            await Task.Delay(10);
        }

        Assert.True(await stand.App.WaitForExitAsync(TimeSpan.FromSeconds(30)), stand.App.Output);
        Assert.NotEqual(0, stand.App.ExitCode);
        Assert.False(accepted);
        Assert.Contains(setting, stand.App.Output);
        Assert.DoesNotContain(other, stand.App.Output);
    }

    [StartupTheory]
    // (a) neither setting: the defaults.
    [InlineData(null, null, 120, 720)]
    // (b), (c) values of their own, two different absolute limits.
    [InlineData("7", "13", 7, 13)]
    [InlineData("30", "11", 30, 11)]
    // (d) the absolute limit alone: the idle limit stays at its default.
    [InlineData(null, "13", 120, 13)]
    // (e) an idle limit larger than the absolute one: the process starts, the absolute one bounds the session.
    [InlineData("48", "24", 48, 24)]
    public async Task TheValuesInEffect_AreLoggedAtStartup_AndBoundThePersistentCookieOfASignIn(
        string? idle, string? absolute, int expectedIdleHours, int expectedAbsoluteHours)
    {
        await using var stand = await Stand.StartAsync(idle, absolute);
        Assert.True(await stand.App.WaitForHealthAsync(TimeSpan.FromSeconds(60)), stand.App.Output);

        var line = Assert.Single(
            stand.App.Output.Split('\n'),
            l => Fields(l).ContainsKey("SessionIdleTimeoutHours"));
        var fields = Fields(line);
        Assert.Equal("info", fields["level"]);
        Assert.Equal(expectedIdleHours.ToString(CultureInfo.InvariantCulture), fields["SessionIdleTimeoutHours"]);
        Assert.Equal(expectedAbsoluteHours.ToString(CultureInfo.InvariantCulture), fields["SessionAbsoluteTimeoutHours"]);

        using var http = new HttpClient(new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false })
        {
            BaseAddress = new Uri($"http://127.0.0.1:{stand.App.Port}"),
        };
        using var login = new HttpRequestMessage(HttpMethod.Post, "/api/auth/login")
        {
            Content = new StringContent("{\"email\":\"alice@example.com\",\"password\":\"correct-horse-battery\"}",
                System.Text.Encoding.UTF8, "application/json"),
        };
        var before = DateTimeOffset.UtcNow;
        using var reply = await http.SendAsync(login);
        var after = DateTimeOffset.UtcNow;

        Assert.Equal(HttpStatusCode.OK, reply.StatusCode);
        var cookie = SessionPipelineHost.SetCookie.Parse(
            reply.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("skein.sid=", StringComparison.Ordinal)));
        var expires = SessionPipelineIntegrationTest.ExpiresOf(cookie);
        Assert.NotNull(expires);
        // expires carries whole seconds: within [login start, login end] + the absolute limit, ±1 s.
        Assert.InRange(expires!.Value,
            before.AddHours(expectedAbsoluteHours).AddSeconds(-1),
            after.AddHours(expectedAbsoluteHours).AddSeconds(1));
    }

    /// <summary>The fields of a logfmt line (<c>name=value</c>, values optionally quoted).</summary>
    private static Dictionary<string, string> Fields(string line)
    {
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        var i = 0;
        while (i < line.Length)
        {
            while (i < line.Length && line[i] == ' ')
            {
                i++;
            }
            var eq = line.IndexOf('=', i);
            if (eq < 0)
            {
                break;
            }
            var name = line[i..eq];
            i = eq + 1;
            string value;
            if (i < line.Length && line[i] == '"')
            {
                var end = i + 1;
                var text = new System.Text.StringBuilder();
                while (end < line.Length && line[end] != '"')
                {
                    if (line[end] == '\\' && end + 1 < line.Length)
                    {
                        end++;
                    }
                    text.Append(line[end]);
                    end++;
                }
                value = text.ToString();
                i = end + 1;
            }
            else
            {
                var end = line.IndexOf(' ', i);
                end = end < 0 ? line.Length : end;
                value = line[i..end].TrimEnd('\r');
                i = end;
            }
            fields[name] = value;
        }
        return fields;
    }
}
