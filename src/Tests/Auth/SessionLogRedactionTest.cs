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
        var failure = new RedisConnectionException(ConnectionFailureType.SocketFailure,
            $"No connection is active/available to service this operation: GET {Key}; Timeout performing GET ({Key}), inst: 1");
        Assert.Contains(Key, failure.ToString()); // the stimulus is suitable only with the key in its own text

        var db = new Moq.Mock<IDatabase>();
        db.Setup(d => d.StringGetAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>())).ThrowsAsync(failure);
        db.Setup(d => d.KeyExistsAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>())).ThrowsAsync(failure);
        var mux = new Moq.Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(db.Object);
        var formatted = new FormatterLogs();
        using var factory = LoggerFactory.Create(b => b.SetMinimumLevel(LogLevel.Trace).AddProvider(formatted));
        var store = new RedisTicketStore(mux.Object, factory.CreateLogger<RedisTicketStore>());

        var ex = operation == "retrieve"
            ? await Assert.ThrowsAsync<SessionStoreUnavailableException>(() => store.RetrieveAsync(Key, new DefaultHttpContext(), CancellationToken.None))
            : await Assert.ThrowsAsync<SessionStoreUnavailableException>(() => store.ExistsAsync(Key, CancellationToken.None));

        Assert.Contains(operation, formatted.Output); // control: the failed operation is in the log
        Assert.Contains("RedisConnectionException", formatted.Output);
        Assert.DoesNotContain("SECRET-", formatted.Output);
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
