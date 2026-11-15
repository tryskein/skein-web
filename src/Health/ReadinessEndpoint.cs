using StackExchange.Redis;

namespace SkeinWeb.Health;

/// <summary>
/// <c>GET /ready</c>: the readiness probe. Ready when Redis answers a ping —
/// sessions, the DataProtection key ring and the SignalR backplane live there;
/// the database is skein-api's, not ours.
/// </summary>
/// <remarks>
/// The route is anonymous, so a failure answers a fixed body: the exception
/// text of the Redis client names endpoints and connection details, and goes
/// to the log only.
/// </remarks>
public static class ReadinessEndpoint
{
    /// <summary>Pings Redis and answers 200 <c>ready</c> or 503 <c>not ready</c>.</summary>
    /// <param name="redis">The shared Redis multiplexer.</param>
    /// <param name="loggerFactory">Source of the logger for a failed ping.</param>
    public static async Task<IResult> CheckAsync(IConnectionMultiplexer redis, ILoggerFactory loggerFactory)
    {
        try
        {
            await redis.GetDatabase().PingAsync();
            return Results.Json(new { status = "ready" });
        }
        catch (Exception ex)
        {
            loggerFactory.CreateLogger(typeof(ReadinessEndpoint).FullName!)
                .LogWarning(ex, "readiness: Redis ping failed");
            return Results.Json(
                new { status = "not ready", error = "redis_unavailable" },
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }
    }
}
