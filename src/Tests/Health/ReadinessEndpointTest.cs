using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SkeinWeb.Health;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Health;

/// <summary>
/// Regression: <c>/ready</c> is anonymous, so a failed Redis ping must not put
/// the client's exception text (endpoints, connection details) in the body.
/// </summary>
public class ReadinessEndpointTest
{
    private const string ConnectionDetail = "redis-internal.example:6379,user=skein";

    private static async Task<(int Status, JsonElement Body)> ExecuteAsync(IConnectionMultiplexer redis)
    {
        var result = await ReadinessEndpoint.CheckAsync(redis, NullLoggerFactory.Instance);
        var ctx = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection().AddLogging().BuildServiceProvider(),
        };
        ctx.Response.Body = new MemoryStream();
        await result.ExecuteAsync(ctx);
        ctx.Response.Body.Position = 0;
        using var doc = await JsonDocument.ParseAsync(ctx.Response.Body);
        return (ctx.Response.StatusCode, doc.RootElement.Clone());
    }

    private static IConnectionMultiplexer Redis(Func<Task<TimeSpan>> ping)
    {
        var db = new Mock<IDatabase>();
        db.Setup(d => d.PingAsync(It.IsAny<CommandFlags>())).Returns(ping);
        var mux = new Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object?>())).Returns(db.Object);
        return mux.Object;
    }

    [Fact]
    public async Task Failed_ping_answers_503_without_the_exception_text()
    {
        var redis = Redis(() => throw new RedisConnectionException(
            ConnectionFailureType.UnableToConnect,
            CommandFlags.None,
            $"It was not possible to connect: {ConnectionDetail}",
            null,
            CommandStatus.Unknown));

        var (status, body) = await ExecuteAsync(redis);

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, status);
        Assert.Equal("not ready", body.GetProperty("status").GetString());
        Assert.Equal("redis_unavailable", body.GetProperty("error").GetString());
        Assert.DoesNotContain(ConnectionDetail, body.GetRawText());
    }

    [Fact]
    public async Task Successful_ping_answers_ready()
    {
        var redis = Redis(() => Task.FromResult(TimeSpan.FromMilliseconds(1)));

        var (status, body) = await ExecuteAsync(redis);

        Assert.Equal(StatusCodes.Status200OK, status);
        Assert.Equal("ready", body.GetProperty("status").GetString());
    }
}
