using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using SkeinWeb.Auth;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// The startup session cleanup and the issue of sessions on the wire, through the Redis proxy of the
/// stand (<see cref="RedisProxy"/>, database <see cref="RedisProxy.Database"/>), on a store of more
/// than one page of <c>SCAN</c>: a session issued by a serving replica between two pages of the pass
/// is marked and survives (US-5, ОСТ-3-2), every page extends the lock and the marks, and a pass of
/// another replica between the two observations of a start gives no readiness from the stale one
/// (ОСТ-3-1). The pages are told apart by the cursors of the replies.
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
            var proxy = new RedisProxy(host, port);
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
            var options = new ConfigurationOptions { DefaultDatabase = RedisProxy.Database, AbortOnConnectFail = true };
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
            Proxy.Dispose();
            await Cleanup.DisposeAsync();
            await Issuing.DisposeAsync();
            Direct.GetServers().First(s => !s.IsReplica).FlushDatabase(RedisProxy.Database);
            await Direct.DisposeAsync();
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

    // ---- a session issued between two pages of the pass (US-5, the guarantee of T006, ОСТ-3-2) -------

    [RedisFact]
    public async Task ASessionIssuedBetweenTwoPagesOfThePass_IsMarkedByTokenAndKey_AndSurvives_WhileTheRowsOfTheStartAreDeleted()
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
            issued.Add((user, await store.StoreAsync(TestRedis.Ticket(user), new DefaultHttpContext(), CancellationToken.None)));
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

        foreach (var key in seeded)
        {
            Assert.False(await bench.Db.KeyExistsAsync(key));
        }
        foreach (var (_, key) in issued)
        {
            Assert.True(await bench.Db.KeyExistsAsync(key));
        }
        // The page deletes name the lock, the set of marks and the keys of the page in KEYS.
        var deletes = bench.Proxy.Commands().Where(c => CleanupCalls.Of(c) == CleanupStep.Delete).Select(CleanupCalls.KeysOf).ToList();
        Assert.NotEmpty(deletes);
        Assert.All(deletes, keys => Assert.All(keys.Skip(2), k => Assert.StartsWith("skein:session:", k)));
        var presented = deletes.SelectMany(keys => keys.Skip(2)).ToHashSet();
        Assert.Subset(presented, seeded.ToHashSet());
        // Precondition: the pass met an issued row on a later page and kept it for its mark.
        Assert.Contains(issued, i => presented.Contains(i.Key));
        await AssertFinishedAsync(bench, 1);
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

        while (true)
        {
            await reply.Reached.WaitAsync(Wait);
            var cursor = reply.Reply!.Cursor!;
            pages.Add(cursor);
            if (pages.Count == 1)
            {
                // A session issued during the pass: the set of marks exists from here on.
                await TestRedis.Store(bench.Issuing).StoreAsync(TestRedis.Ticket(Guid.NewGuid()), new DefaultHttpContext(), CancellationToken.None);
            }
            Assert.True(await bench.Db.KeyExistsAsync(SessionStoreMigration.IssuedDuringKey));

            // As if the scan had run long: both lifetimes are low when the page arrives.
            await bench.Db.KeyExpireAsync(SessionStoreMigration.LockKey, TimeSpan.FromSeconds(5));
            await bench.Db.KeyExpireAsync(SessionStoreMigration.IssuedDuringKey, TimeSpan.FromSeconds(5));
            var lockBefore = await bench.Db.KeyTimeToLiveAsync(SessionStoreMigration.LockKey);
            var marksBefore = await bench.Db.KeyTimeToLiveAsync(SessionStoreMigration.IssuedDuringKey);
            var afterThePage = bench.Proxy.Hold(c => CleanupCalls.Of(c) is CleanupStep.Delete or CleanupStep.Finish);
            reply.Release();

            await afterThePage.Reached.WaitAsync(Wait);
            Assert.True(await bench.Db.KeyTimeToLiveAsync(SessionStoreMigration.LockKey) > lockBefore, $"page {pages.Count} did not extend the lock");
            Assert.True(await bench.Db.KeyTimeToLiveAsync(SessionStoreMigration.IssuedDuringKey) > marksBefore, $"page {pages.Count} did not extend the marks");
            if (cursor == "0")
            {
                afterThePage.Release();
                break;
            }
            reply = bench.Proxy.HoldReply((c, _) => IsPassScan(c));
            afterThePage.Release();
        }
        await run.WaitAsync(Wait);

        // Two pages and more were really walked: a cursor that goes on, and the last one that ends.
        Assert.True(pages.Count >= 2, $"the scan had {pages.Count} page(s)");
        Assert.NotEqual("0", pages[0]);
        Assert.Equal("0", pages[^1]);
        await AssertFinishedAsync(bench, 1);
    }

    // ---- a pass of another replica between the observations (ОСТ-3-1, the condition of the start) ----

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
        await AssertFinishedAsync(bench, 1);
    }
}
