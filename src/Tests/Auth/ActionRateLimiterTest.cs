using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SkeinWeb.Auth;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// K-17: a Redis failure lets the request through
/// (fail-open, as <see cref="LoginRateLimiter"/> does in the login path) — a
/// cache outage must not close registration and password reset.
/// </summary>
public class ActionRateLimiterTest
{
    private static RedisConnectionException Outage() =>
        new(ConnectionFailureType.UnableToConnect, "Redis is down");

    /// <summary>Redis broken at the given step of the counting call.</summary>
    private static IConnectionMultiplexer BrokenRedis(string where)
    {
        var db = new Mock<IDatabase>();
        if (where == "incr")
        {
            db.Setup(d => d.StringIncrementAsync(It.IsAny<RedisKey>(), It.IsAny<long>(), It.IsAny<CommandFlags>()))
                .ThrowsAsync(Outage());
        }
        else
        {
            db.Setup(d => d.StringIncrementAsync(It.IsAny<RedisKey>(), It.IsAny<long>(), It.IsAny<CommandFlags>()))
                .ReturnsAsync(1);
            db.Setup(d => d.KeyExpireAsync(It.IsAny<RedisKey>(), It.IsAny<TimeSpan?>(),
                    It.IsAny<ExpireWhen>(), It.IsAny<CommandFlags>()))
                .ThrowsAsync(Outage());
        }

        var mux = new Mock<IConnectionMultiplexer>();
        if (where == "connection")
        {
            mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Throws(Outage());
        }
        else
        {
            mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(db.Object);
        }
        return mux.Object;
    }

    public static TheoryData<string, string> Cases()
    {
        var data = new TheoryData<string, string>();
        foreach (var where in new[] { "connection", "incr", "expire" })
        {
            // An action with email + IP buckets, and one with the IP bucket only.
            data.Add(where, ActionRateLimiter.Signup.Action);
            data.Add(where, ActionRateLimiter.ConfirmEmail.Action);
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task RedisError_LetsTheRequestThrough(string where, string action)
    {
        var policy = action == ActionRateLimiter.Signup.Action ? ActionRateLimiter.Signup : ActionRateLimiter.ConfirmEmail;
        var limiter = new ActionRateLimiter(BrokenRedis(where), NullLogger<ActionRateLimiter>.Instance);

        var allowed = await limiter.TryAcquireAsync(policy, "dev@client.io", "203.0.113.7", CancellationToken.None);

        Assert.True(allowed);
    }
}
