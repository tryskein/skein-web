using Moq;
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
[Collection("session-pipeline")]
public sealed class SessionLogRedactionTest
{
    private static readonly Guid Alice = Guid.Parse("0199a1b2-0000-7000-8000-00000000000a");

    private static readonly string Key = "skein:session:SECRET-" + Guid.NewGuid().ToString("N");

    // The client library of this version puts no key into the exception of a cut connection, so the
    // stimulus is an exception shaped as the library shapes one when it does name the key (the text
    // of a timeout or of a refused command), injected on the database boundary. The check is on the
    // line the console formatter really prints, at both levels the store logs at.
    [Theory]
    [InlineData("retrieve")]
    [InlineData("exists")]
    public async Task AFailedOperation_IsLoggedWithoutTheSessionKey_InTheLineTheFormatterPrints(string operation)
    {
        var failure = new RedisConnectionException(ConnectionFailureType.SocketFailure, CommandFlags.None,
            $"No connection is active/available to service this operation: GET {Key}; Timeout performing GET ({Key}), inst: 1",
            null, CommandStatus.Unknown);
        Assert.Contains(Key, failure.ToString()); // the stimulus is suitable only with the key in its own text

        var db = new Moq.Mock<IDatabase>();
        db.Setup(d => d.StringGetAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>())).ThrowsAsync(failure);
        db.Setup(d => d.KeyExistsAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>())).ThrowsAsync(failure);
        var mux = new Moq.Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(db.Object);
        var formatted = new FormatterLogs();
        using var factory = LoggerFactory.Create(b => b.SetMinimumLevel(LogLevel.Trace).AddProvider(formatted));
        var store = new RedisTicketStore(mux.Object, TestRedis.DefaultTimeouts, TimeProvider.System, factory.CreateLogger<RedisTicketStore>());

        var ex = operation == "retrieve"
            ? await Assert.ThrowsAsync<SessionStoreUnavailableException>(() => store.RetrieveAsync(Key, new DefaultHttpContext(), CancellationToken.None))
            : await Assert.ThrowsAsync<SessionStoreUnavailableException>(() => store.ExistsAsync(Key, CancellationToken.None));

        Assert.Contains(operation, formatted.Output); // control: the failed operation is in the log
        Assert.Contains("RedisConnectionException", formatted.Output);
        Assert.DoesNotContain("SECRET-", formatted.Output);
        Assert.DoesNotContain("SECRET-", ex.ToString());
    }

    private static int WarningsAndAbove(string output) =>
        output.Split('\n').Count(line =>
            line.Contains("level=warn") || line.Contains("\"level\":\"error\"") || line.Contains("\"level\":\"fatal\""));

    // Observability: deleting a row whose window is not valid is one Warning per session, with neither the
    // session key nor a claim value in the printed line; the regular end of a session logs nothing at
    // Warning or above.
    [RedisFact]
    public async Task ARowWithoutAValidWindow_IsOneWarningWithoutKeyOrClaims_AndARegularEndLogsNoWarning()
    {
        using var mux = TestRedis.Connect();
        var db = mux.GetDatabase();
        var formatted = new FormatterLogs();
        using var factory = LoggerFactory.Create(b => b.SetMinimumLevel(LogLevel.Trace).AddProvider(formatted));
        var store = new RedisTicketStore(mux, TestRedis.DefaultTimeouts, TimeProvider.System, factory.CreateLogger<RedisTicketStore>());
        var invalid = "skein:session:SECRET-" + Guid.NewGuid().ToString("N");
        var ended = "skein:session:SECRET-" + Guid.NewGuid().ToString("N");
        try
        {
            var withoutExpiry = TestRedis.Ticket(Alice, "alice@example.com", "alice-sso",
                new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Email, "alice.claim@example.com"));
            withoutExpiry.Properties.ExpiresUtc = null;
            await db.StringSetAsync(invalid, Microsoft.AspNetCore.Authentication.TicketSerializer.Default.Serialize(withoutExpiry), TimeSpan.FromMinutes(5));

            Assert.Null(await store.RetrieveAsync(invalid, new DefaultHttpContext(), CancellationToken.None));

            Assert.Equal(1, WarningsAndAbove(formatted.Output));
            Assert.Contains("session row without a valid window deleted", formatted.Output);
            Assert.DoesNotContain("SECRET-", formatted.Output);
            Assert.DoesNotContain("alice", formatted.Output);
            Assert.DoesNotContain(Alice.ToString(), formatted.Output);

            var before = formatted.Output.Length;
            var over = TestRedis.Ticket(Alice);
            TestRedis.WithWindow(over.Properties, DateTimeOffset.UtcNow.AddHours(-(TestRedis.DefaultTimeouts.AbsoluteHours + 1)));
            await db.StringSetAsync(ended, Microsoft.AspNetCore.Authentication.TicketSerializer.Default.Serialize(over), TimeSpan.FromMinutes(5));

            Assert.Null(await store.RetrieveAsync(ended, new DefaultHttpContext(), CancellationToken.None));

            Assert.False(await db.KeyExistsAsync(ended)); // control: the read did reject it by its end
            Assert.Equal(0, WarningsAndAbove(formatted.Output[before..]));
        }
        finally
        {
            await db.KeyDeleteAsync([invalid, ended]);
        }
    }

    // Two reads of one row without a valid window: only the read whose DEL removed the row logs it.
    [RedisFact]
    public async Task TwoReadsOfOneRowWithoutAValidWindow_LogOneWarning()
    {
        using var mux = TestRedis.Connect();
        var real = mux.GetDatabase();
        var formatted = new FormatterLogs();
        using var factory = LoggerFactory.Create(b => b.SetMinimumLevel(LogLevel.Trace).AddProvider(formatted));
        var proxied = DbProxy.Create(real, out var proxy);
        var store = new RedisTicketStore(TestRedis.Over(mux, proxied), TestRedis.DefaultTimeouts, TimeProvider.System, factory.CreateLogger<RedisTicketStore>());
        var key = "skein:session:SECRET-" + Guid.NewGuid().ToString("N");
        try
        {
            var withoutExpiry = TestRedis.Ticket(Alice);
            withoutExpiry.Properties.ExpiresUtc = null;
            await real.StringSetAsync(key, Microsoft.AspNetCore.Authentication.TicketSerializer.Default.Serialize(withoutExpiry), TimeSpan.FromMinutes(5));
            // The DEL of the first read is held until the second read has read and deleted the row.
            var firstDelete = proxy.Hold((name, args) => name == nameof(IDatabase.KeyDeleteAsync));

            var first = store.RetrieveAsync(key, new DefaultHttpContext(), CancellationToken.None);
            await firstDelete.Reached.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Null(await store.RetrieveAsync(key, new DefaultHttpContext(), CancellationToken.None));
            Assert.False(await real.KeyExistsAsync(key)); // the second read removed it
            firstDelete.Release();
            Assert.Null(await first.WaitAsync(TimeSpan.FromSeconds(10)));

            Assert.Equal(1, WarningsAndAbove(formatted.Output));
        }
        finally
        {
            await real.KeyDeleteAsync(key);
        }
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
