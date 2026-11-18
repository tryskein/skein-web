using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using SkeinWeb.Auth;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// INV-12 and the observability rule: a failed store operation is logged without the session key (the
/// stimulus is a real cut connection whose own exception does carry the key), and a rotation is
/// logged once at Information with the user, the surface and the "had a previous key" flag, and no
/// e-mail, session key or cookie value.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SessionLogRedactionTest
{
    private static readonly Guid Alice = Guid.Parse("0199a1b2-0000-7000-8000-00000000000a");

    /// <summary>A byte pipe between the client and Redis that can be cut for good.</summary>
    private sealed class CuttableProxy : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly List<TcpClient> _sockets = [];
        private volatile bool _cut;

        public CuttableProxy(string redisHost, int redisPort)
        {
            _listener.Start();
            _ = Task.Run(async () =>
            {
                while (!_cut)
                {
                    TcpClient client;
                    try
                    {
                        client = await _listener.AcceptTcpClientAsync();
                    }
                    catch (Exception)
                    {
                        return;
                    }
                    var upstream = new TcpClient();
                    await upstream.ConnectAsync(redisHost, redisPort);
                    lock (_sockets)
                    {
                        _sockets.Add(client);
                        _sockets.Add(upstream);
                    }
                    _ = client.GetStream().CopyToAsync(upstream.GetStream()).ContinueWith(_ => { });
                    _ = upstream.GetStream().CopyToAsync(client.GetStream()).ContinueWith(_ => { });
                }
            });
        }

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        public void Cut()
        {
            _cut = true;
            _listener.Stop();
            lock (_sockets)
            {
                foreach (var socket in _sockets)
                {
                    socket.Close();
                }
            }
        }

        public void Dispose() => Cut();
    }

    private static (string Host, int Port) RedisEndpoint()
    {
        var options = ConfigurationOptions.Parse(TestRedis.Url!);
        var endpoint = options.EndPoints[0];
        return endpoint is DnsEndPoint dns ? (dns.Host, dns.Port) : (((IPEndPoint)endpoint).Address.ToString(), ((IPEndPoint)endpoint).Port);
    }

    [RedisFact]
    public async Task AFailedOperationOnACutConnection_IsLoggedWithoutTheSessionKey()
    {
        var (host, port) = RedisEndpoint();
        using var proxy = new CuttableProxy(host, port);
        var options = new ConfigurationOptions { AbortOnConnectFail = false, SyncTimeout = 1000, AsyncTimeout = 1000, ConnectTimeout = 1000, IncludeDetailInExceptions = true };
        options.EndPoints.Add(IPAddress.Loopback.ToString(), proxy.Port);
        await using var mux = await ConnectionMultiplexer.ConnectAsync(options);
        var key = "skein:session:SECRET-" + Guid.NewGuid().ToString("N");
        await mux.GetDatabase().StringSetAsync(key, "x"); // the connection is open and works
        proxy.Cut();
        await Task.Delay(300);

        // The stimulus is suitable only when the real exception of the operation carries the key.
        var actual = await Assert.ThrowsAnyAsync<Exception>(() => mux.GetDatabase().StringGetAsync(key));
        if (!actual.ToString().Contains(key, StringComparison.Ordinal))
        {
            // The row is not accepted on a stimulus whose own exception carries no key: it proves nothing.
            Assert.Skip("Row R34(a) not accepted: the exception of a cut connection carries no session key in this client version; a human decides the stimulus.");
        }

        var log = new SessionPipelineHost.ErrorLogs();
        using var factory = LoggerFactory.Create(b => b.SetMinimumLevel(LogLevel.Trace).AddProvider(log));
        var store = new RedisTicketStore(mux, factory.CreateLogger<RedisTicketStore>());
        var ex = await Assert.ThrowsAsync<SessionStoreUnavailableException>(
            () => store.RetrieveAsync(key, new DefaultHttpContext(), CancellationToken.None));

        Assert.Contains(log.Entries, e => e.Text.Contains("retrieve", StringComparison.Ordinal)); // control: the operation was logged
        Assert.DoesNotContain(log.Entries, e => e.Text.Contains("SECRET-", StringComparison.Ordinal));
        Assert.DoesNotContain("SECRET-", ex.ToString());
    }

    [RedisFact]
    public async Task ARotation_IsLoggedOnceAtInformation_WithTheFlagAndWithoutPersonalData()
    {
        await using var host = await SessionPipelineHost.StartAsync();

        var first = await host.SendAsync($"/test/issue?user={Alice}");
        var firstSet = Assert.Single(first.Sessions(host.CookieName));
        host.Logs.Entries.Clear();
        var second = await host.SendAsync($"/test/issue?user={Alice}", firstSet.AsRequestCookie());
        var secondSet = Assert.Single(second.Sessions(host.CookieName));

        var events = host.Logs.Entries.Where(e => e.Level == LogLevel.Information && e.Text.Contains("session issued")).ToList();
        var entry = Assert.Single(events);
        Assert.Contains(Alice.ToString(), entry.Text);
        Assert.Contains("surface=Test", entry.Text);
        Assert.Contains("previousSession=True", entry.Text);
        var everything = string.Join('\n', host.Logs.Entries.Select(e => e.Text));
        Assert.DoesNotContain("alice@example.com", everything);
        Assert.DoesNotContain("skein:session:", everything);
        Assert.DoesNotContain(secondSet.Value, everything);
        Assert.DoesNotContain(Uri.UnescapeDataString(secondSet.Value), everything);

        // The line the formatter really prints: the flag is a value, not masked.
        Assert.Contains("previousSession=True", host.Formatted.Output);
        Assert.DoesNotContain("previousSession=***", host.Formatted.Output);

        var fresh = await host.SendAsync($"/test/issue?user={Alice}");
        Assert.Single(fresh.Sessions(host.CookieName));
        Assert.Contains(host.Logs.Entries, e => e.Text.Contains("previousSession=False"));
    }

    [RedisFact]
    public async Task APublicIssueAfterARevocation_LogsThatAPreviousSessionExisted()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, _, _) = await host.SignInAsync(Alice);
        host.Logs.Entries.Clear();

        await host.SendAsync($"/test/revoke-then-issue?user={Alice}", cookie);

        Assert.Contains(host.Logs.Entries, e => e.Text.Contains("surface=Reset") && e.Text.Contains("previousSession=True"));
    }
}
