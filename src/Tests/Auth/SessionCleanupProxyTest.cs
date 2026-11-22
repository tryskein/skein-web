using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using SkeinWeb.Auth;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// The startup session cleanup and the issue of sessions on the wire, through the Redis proxy of the
/// stand (<see cref="RedisProxy"/>, database <see cref="RedisProxy.Database"/>), on a store of more
/// than one page of <c>SCAN</c>: a session issued by a serving replica between two pages of the pass
/// is marked and survives (US-5, OST-3-2), every page extends the lock and the marks, and a pass of
/// another replica between the two observations of a start gives no readiness from the stale one
/// (OST-3-1). The pages are told apart by the cursors of the replies.
/// </summary>
[Trait("Category", "Integration")]
[Collection("startup-stand")]
public sealed class SessionCleanupProxyTest
{
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(30);

    /// <summary>A scan of the pass: every row under <c>skein:session:*</c>, not only the hashes of the former format.</summary>
    private static bool IsPassScan(RedisCommand command) =>
        command.Name == "SCAN" && command.Args.Contains(CleanupCalls.SessionPattern) && !command.Args.Contains("TYPE");

    private static bool IsFormerRowScan(RedisCommand command) =>
        command.Name == "SCAN" && command.Args.Contains(CleanupCalls.SessionPattern) && command.Args.Contains("TYPE");

    /// <summary>
    /// The proxy, a multiplexer of the cleanup and one of the issue through it, and a direct one to
    /// observe; the database is flushed before and after.
    /// </summary>
    private sealed class Bench : IAsyncDisposable
    {
        public required RedisProxy Proxy { get; init; }
        public required ConnectionMultiplexer Cleanup { get; init; }
        public required ConnectionMultiplexer Issuing { get; init; }
        public required ConnectionMultiplexer Direct { get; init; }
        public IDatabase Db => Direct.GetDatabase(RedisProxy.Database);

        public static async Task<Bench> StartAsync()
        {
            var direct = TestRedis.Connect(RedisProxy.Database);
            direct.GetServers().First(s => !s.IsReplica).FlushDatabase(RedisProxy.Database);
            var endpoint = ConfigurationOptions.Parse(TestRedis.Url!).EndPoints[0];
            var (host, port) = endpoint is DnsEndPoint dns
                ? (dns.Host, dns.Port)
                : (((IPEndPoint)endpoint).Address.ToString(), ((IPEndPoint)endpoint).Port);
            var proxy = new RedisProxy(host, port, parseReplies: true);
            return new Bench
            {
                Proxy = proxy,
                Cleanup = await ThroughAsync(proxy),
                Issuing = await ThroughAsync(proxy),
                Direct = direct,
            };
        }

        private static Task<ConnectionMultiplexer> ThroughAsync(RedisProxy proxy)
        {
            // A reply kept back by the test is not a client timeout.
            var options = new ConfigurationOptions
            {
                DefaultDatabase = RedisProxy.Database,
                AbortOnConnectFail = true,
                AsyncTimeout = 120_000,
                SyncTimeout = 120_000,
            };
            options.EndPoints.Add("127.0.0.1", proxy.Port);
            return ConnectionMultiplexer.ConnectAsync(options);
        }

        public SessionStoreMigration Migration() =>
            new(Cleanup, TimeProvider.System, NullLogger<SessionStoreMigration>.Instance);

        /// <summary>Rows of the store at the start: hashes of the former format and strings of this version; more than one page.</summary>
        public async Task<List<string>> SeedAsync(int hashes, int strings)
        {
            var keys = new List<string>();
            var batch = Db.CreateBatch();
            var writes = new List<Task>();
            for (var i = 0; i < hashes; i++)
            {
                var key = $"skein:session:seed-former-{i}";
                keys.Add(key);
                writes.Add(batch.HashSetAsync(key, [new HashEntry("data", i)]));
            }
            for (var i = 0; i < strings; i++)
            {
                var key = $"skein:session:seed-row-{i}";
                keys.Add(key);
                writes.Add(batch.StringSetAsync(key, "row"));
            }
            batch.Execute();
            await Task.WhenAll(writes);
            return keys;
        }

        public async Task<long> GenerationAsync() => (long?)await Db.StringGetAsync(SessionStoreMigration.GenerationKey) ?? 0;

        public async ValueTask DisposeAsync()
        {
            var parsed = Proxy.ReplyFailure;
            Proxy.Dispose();
            await Cleanup.DisposeAsync();
            await Issuing.DisposeAsync();
            Direct.GetServers().First(s => !s.IsReplica).FlushDatabase(RedisProxy.Database);
            await Direct.DisposeAsync();
            // Every scenario that parses replies ends with this check: an unparsed reply fails it.
            if (parsed is not null)
            {
                throw new InvalidOperationException("the Redis proxy met a reply it could not parse", parsed);
            }
        }
    }

    private static async Task UntilAsync(Func<bool> condition, string what)
    {
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                Assert.Fail($"precondition not met within 15 s: {what}");
            }
            await Task.Delay(20);
        }
    }

    private static async Task AssertFinishedAsync(Bench bench, long generation)
    {
        Assert.Equal(SessionStoreMigration.MarkerValue, await bench.Db.StringGetAsync(SessionStoreMigration.MarkerKey));
        Assert.Equal(generation, await bench.GenerationAsync());
        Assert.False(await bench.Db.KeyExistsAsync(SessionStoreMigration.LockKey));
        Assert.False(await bench.Db.KeyExistsAsync(SessionStoreMigration.IssuedDuringKey));
    }

    // ---- the proxy of the bench fails a scenario on a reply it cannot parse --------------------------

    [Fact]
    public async Task AReplyOfAnUnknownType_AfterTheLastReplyHold_FailsTheScenario()
    {
        var ct = TestContext.Current.CancellationToken;
        // An upstream that answers the proxy's SELECT, then a known reply, then a reply of a type
        // the proxy does not know.
        var upstream = new TcpListener(IPAddress.Loopback, 0);
        upstream.Start();
        var port = ((IPEndPoint)upstream.LocalEndpoint).Port;
        var served = Task.Run(async () =>
        {
            using var socket = await upstream.AcceptTcpClientAsync(ct);
            var stream = socket.GetStream();
            var buffer = new byte[1024];
            foreach (var reply in new[] { "+OK\r\n", "+PONG\r\n", "?unknown\r\n" })
            {
                if (await stream.ReadAsync(buffer, ct) == 0)
                {
                    return;
                }
                await stream.WriteAsync(System.Text.Encoding.ASCII.GetBytes(reply), ct);
            }
            await Task.Delay(TimeSpan.FromSeconds(5), ct);
        }, ct);
        using var proxy = new RedisProxy("127.0.0.1", port, parseReplies: true);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, proxy.Port, ct);
        var stream = client.GetStream();
        var ping = System.Text.Encoding.ASCII.GetBytes("*1\r\n$4\r\nPING\r\n");
        var answer = new byte[64];

        // The last reply hold of the scenario: armed, reached and released.
        var hold = proxy.HoldReply((c, _) => c.Name == "PING");
        await stream.WriteAsync(ping, ct);
        await hold.Reached.WaitAsync(Wait, ct);
        hold.Release();
        Assert.Equal("+PONG\r\n", System.Text.Encoding.ASCII.GetString(answer, 0, await stream.ReadAsync(answer, ct)));

        // A reply of an unknown type afterwards: passed on, recorded, and the final check fails.
        await stream.WriteAsync(ping, ct);
        Assert.Equal("?unknown\r\n", System.Text.Encoding.ASCII.GetString(answer, 0, await stream.ReadAsync(answer, ct)));
        Assert.NotNull(proxy.ReplyFailure);
        Assert.Throws<InvalidOperationException>(proxy.AssertRepliesParsed);

        upstream.Stop();
        try
        {
            await served.WaitAsync(Wait, ct);
        }
        catch (Exception)
        {
            // the stub upstream ends with the proxy; how it ends is not the subject
        }
    }

    // ---- a session issued between two pages of the pass (US-5, the guarantee of T006, OST-3-2) -------

    [RedisFact]
    public async Task ASessionIssuedBetweenTwoPagesOfThePass_IsMarkedByTokenAndKey_AndSurvives_WhileTheRowsOfTheStartAreDeleted()
    {
        // SCAN does not promise to return a key written during the walk: the scenario is repeated
        // until the pass meets an issued row on a later page, and stops with a named precondition
        // failure if it never does.
        for (var attempt = 1; attempt <= 3; attempt++)
        {
            if (await IssueBetweenTwoPagesAsync())
            {
                return;
            }
        }
        Assert.Fail("precondition not met in 3 attempts: the pass never met a row issued between its pages");
    }

    /// <summary>One run of the scenario of row 66; false when the pass met none of the issued rows.</summary>
    private static async Task<bool> IssueBetweenTwoPagesAsync()
    {
        await using var bench = await Bench.StartAsync();
        var seeded = await bench.SeedAsync(hashes: 300, strings: 300);
        var firstPage = bench.Proxy.HoldReply((c, r) => IsPassScan(c) && r.Cursor is { } cursor && cursor != "0");
        var run = bench.Migration().RunAsync(Wait, CancellationToken.None);
        await firstPage.Reached.WaitAsync(Wait);
        var token = (string?)await bench.Db.StringGetAsync(SessionStoreMigration.LockKey);
        Assert.NotNull(token);

        // A serving replica issues sessions while the reply to the first page is kept back.
        var store = TestRedis.Store(bench.Issuing);
        var issued = new List<(Guid User, string Key)>();
        for (var i = 0; i < 16; i++)
        {
            var user = Guid.NewGuid();
            var key = await store.StoreAsync(TestRedis.Ticket(user), new DefaultHttpContext(), CancellationToken.None);
            issued.Add((user, key));
            // The set of marks lives at least as long as the lock (the marks first, the lock later:
            // both only go down between the two reads).
            var marks = await bench.Db.KeyTimeToLiveAsync(SessionStoreMigration.IssuedDuringKey);
            var held = await bench.Db.KeyTimeToLiveAsync(SessionStoreMigration.LockKey);
            Assert.NotNull(marks);
            Assert.NotNull(held);
            Assert.True(marks > TimeSpan.Zero, $"the set of marks has no positive lifetime: {marks}");
            Assert.True(marks >= held, $"the set of marks ({marks}) lives shorter than the lock ({held})");
        }
        foreach (var (user, key) in issued)
        {
            // The issue script names the row, the index, the lock and the set of marks in KEYS.
            var command = Assert.Single(bench.Proxy.Commands(), c => CleanupCalls.KeysOf(c) is [var first, ..] && first == key);
            Assert.Equal(
                new[] { key, "skein:user-tickets:" + user, SessionStoreMigration.LockKey, SessionStoreMigration.IssuedDuringKey }.Order(),
                CleanupCalls.KeysOf(command).Order());
            Assert.True(await bench.Db.SetContainsAsync(SessionStoreMigration.IssuedDuringKey, token + ":" + key));
        }

        firstPage.Release();
        await run.WaitAsync(Wait);

        // The page deletes name the lock, the set of marks and the keys of the page in KEYS.
        var deletes = bench.Proxy.Commands().Where(c => CleanupCalls.Of(c) == CleanupStep.Delete).Select(CleanupCalls.KeysOf).ToList();
        Assert.NotEmpty(deletes);
        Assert.All(deletes, keys => Assert.All(keys.Skip(2), k => Assert.StartsWith("skein:session:", k)));
        var presented = deletes.SelectMany(keys => keys.Skip(2)).ToHashSet();
        Assert.Subset(presented, seeded.ToHashSet());
        foreach (var key in seeded)
        {
            Assert.False(await bench.Db.KeyExistsAsync(key));
        }
        await AssertFinishedAsync(bench, 1);

        // The property, on the issued rows the pass really met: presented to a page delete, kept for the mark.
        var met = issued.Where(i => presented.Contains(i.Key)).ToList();
        foreach (var (_, key) in met)
        {
            Assert.True(await bench.Db.KeyExistsAsync(key), "a marked row the pass met was deleted");
        }
        return met.Count > 0;
    }

    // ---- every page extends the lock and the marks --------------------------------------------------

    [RedisFact]
    public async Task TheLockIsExtendedByTheScan_AndSoAreTheMarks_OnEveryPage()
    {
        await using var bench = await Bench.StartAsync();
        await bench.SeedAsync(hashes: 400, strings: 300);
        var pages = new List<string>();
        var reply = bench.Proxy.HoldReply((c, _) => IsPassScan(c));
        var run = bench.Migration().RunAsync(Wait, CancellationToken.None);
        TimeSpan? lockLowered = null;
        TimeSpan? marksLowered = null;

        async Task AssertTheLastPageExtendedBothAsync()
        {
            var page = pages.Count - 1;
            Assert.True(await bench.Db.KeyTimeToLiveAsync(SessionStoreMigration.LockKey) > lockLowered, $"page {page} did not extend the lock");
            Assert.True(await bench.Db.KeyTimeToLiveAsync(SessionStoreMigration.IssuedDuringKey) > marksLowered, $"page {page} did not extend the marks");
        }

        while (true)
        {
            // The reply to every page of the scan is the barrier: the page before it, empty or not,
            // has been handled by now.
            await reply.Reached.WaitAsync(Wait);
            var cursor = reply.Reply!.Cursor!;
            pages.Add(cursor);
            if (pages.Count > 1)
            {
                await AssertTheLastPageExtendedBothAsync();
            }
            else
            {
                // A session issued during the pass: the set of marks exists from here on.
                await TestRedis.Store(bench.Issuing).StoreAsync(TestRedis.Ticket(Guid.NewGuid()), new DefaultHttpContext(), CancellationToken.None);
            }
            Assert.True(await bench.Db.KeyExistsAsync(SessionStoreMigration.IssuedDuringKey));

            // As if the scan had run long: both lifetimes are low when this page is handed over.
            await bench.Db.KeyExpireAsync(SessionStoreMigration.LockKey, TimeSpan.FromSeconds(5));
            await bench.Db.KeyExpireAsync(SessionStoreMigration.IssuedDuringKey, TimeSpan.FromSeconds(5));
            lockLowered = await bench.Db.KeyTimeToLiveAsync(SessionStoreMigration.LockKey);
            marksLowered = await bench.Db.KeyTimeToLiveAsync(SessionStoreMigration.IssuedDuringKey);

            if (cursor == "0")
            {
                // The last page: its handling ends before the finish of the pass.
                var finish = bench.Proxy.Hold(c => CleanupCalls.Of(c) == CleanupStep.Finish);
                reply.Release();
                await finish.Reached.WaitAsync(Wait);
                pages.Add("finish");
                await AssertTheLastPageExtendedBothAsync();
                finish.Release();
                break;
            }
            var next = bench.Proxy.HoldReply((c, _) => IsPassScan(c));
            reply.Release();
            reply = next;
        }
        await run.WaitAsync(Wait);
        pages.RemoveAt(pages.Count - 1);

        // Two pages and more were really walked: a cursor that goes on, and the last one that ends.
        Assert.True(pages.Count >= 2, $"the scan had {pages.Count} page(s)");
        Assert.NotEqual("0", pages[0]);
        Assert.Equal("0", pages[^1]);
        Assert.Null(bench.Proxy.ReplyFailure);
        await AssertFinishedAsync(bench, 1);
    }

    // ---- a pass of another replica between the observations (OST-3-1, the condition of the start) ----

    [RedisTheory]
    [InlineData(false)] // the other pass began between the observations
    [InlineData(true)]  // it began and finished between them
    public async Task APassOfAnotherReplicaBetweenTheObservations_GivesNoReadinessFromTheStaleOne(bool finishedBeforeTheSecond)
    {
        await using var bench = await Bench.StartAsync();
        var rows = await bench.SeedAsync(hashes: 0, strings: 600); // sessions of this version only
        await bench.Db.StringSetAsync(SessionStoreMigration.MarkerKey, SessionStoreMigration.MarkerValue);
        var lastPage = bench.Proxy.HoldReply((c, r) => IsFormerRowScan(c) && r.Cursor == "0");
        var run = bench.Migration().RunAsync(Wait, CancellationToken.None);
        await lastPage.Reached.WaitAsync(Wait);

        // The first observation showed the marker, no lock, the count 0, and the scan found no hash.
        int Statuses() => bench.Proxy.Commands().Count(c => CleanupCalls.Of(c) == CleanupStep.Status);
        Assert.Equal(1, Statuses());

        // Another replica's pass: its begin takes the lock and deletes the marker.
        await bench.Db.StringSetAsync(SessionStoreMigration.LockKey, "another-replica", TimeSpan.FromMinutes(1));
        await bench.Db.KeyDeleteAsync(SessionStoreMigration.MarkerKey);
        async Task FinishTheOtherPassAsync()
        {
            await bench.Db.StringSetAsync(SessionStoreMigration.MarkerKey, SessionStoreMigration.MarkerValue);
            await bench.Db.StringIncrementAsync(SessionStoreMigration.GenerationKey);
            await bench.Db.KeyDeleteAsync(SessionStoreMigration.LockKey);
        }
        if (finishedBeforeTheSecond)
        {
            await FinishTheOtherPassAsync();
        }
        lastPage.Release();

        if (!finishedBeforeTheSecond)
        {
            // While the other pass holds its lock, the replica keeps observing and is not ready.
            await UntilAsync(() => Statuses() >= 5, "the replica observes the other pass");
            Assert.False(run.IsCompleted);
            await FinishTheOtherPassAsync();
        }
        await run.WaitAsync(Wait);

        // Ready only after observing anew: two more observations followed the stale one.
        Assert.True(Statuses() >= 4, $"{Statuses()} observation(s)");
        Assert.DoesNotContain(bench.Proxy.Commands(), c => CleanupCalls.Of(c) is CleanupStep.Begin or CleanupStep.Delete);
        foreach (var key in rows)
        {
            Assert.True(await bench.Db.KeyExistsAsync(key));
        }
        await AssertFinishedAsync(bench, 2); // the other pass, then the confirmation of this replica
    }
}
