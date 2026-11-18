using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SkeinWeb.Auth;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Auth;

/// <summary>A fact that runs only when the harness provides <c>TEST_REDIS_URL</c>.</summary>
internal sealed class RedisFactAttribute : FactAttribute
{
    public RedisFactAttribute(
        [System.Runtime.CompilerServices.CallerFilePath] string? sourceFilePath = null,
        [System.Runtime.CompilerServices.CallerLineNumber] int sourceLineNumber = -1)
        : base(sourceFilePath, sourceLineNumber)
    {
        if (string.IsNullOrWhiteSpace(TestRedis.Url))
        {
            Skip = "Requires TEST_REDIS_URL (the integration harness).";
        }
    }
}

/// <summary>A theory that runs only when the harness provides <c>TEST_REDIS_URL</c>.</summary>
internal sealed class RedisTheoryAttribute : TheoryAttribute
{
    public RedisTheoryAttribute(
        [System.Runtime.CompilerServices.CallerFilePath] string? sourceFilePath = null,
        [System.Runtime.CompilerServices.CallerLineNumber] int sourceLineNumber = -1)
        : base(sourceFilePath, sourceLineNumber)
    {
        if (string.IsNullOrWhiteSpace(TestRedis.Url))
        {
            Skip = "Requires TEST_REDIS_URL (the integration harness).";
        }
    }
}

/// <summary>Connection helpers for the tests that talk to the Redis of the harness.</summary>
internal static class TestRedis
{
    public static string? Url => Environment.GetEnvironmentVariable("TEST_REDIS_URL");

    public static ConnectionMultiplexer Connect(int? database = null)
    {
        var options = ConfigurationOptions.Parse(Url!);
        options.AllowAdmin = true;
        options.AbortOnConnectFail = true;
        if (database is { } db)
        {
            options.DefaultDatabase = db;
        }
        return ConnectionMultiplexer.Connect(options);
    }

    /// <summary>A multiplexer whose database is <paramref name="db"/> and whose servers are those of <paramref name="real"/>.</summary>
    public static IConnectionMultiplexer Over(IConnectionMultiplexer real, IDatabase db)
    {
        var mux = new Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(db);
        mux.Setup(m => m.GetServers()).Returns(real.GetServers());
        return mux.Object;
    }

    public static RedisTicketStore Store(IConnectionMultiplexer mux) =>
        new(mux, NullLogger<RedisTicketStore>.Instance);

    public static AuthenticationTicket Ticket(Guid user, string? pairEmail = null, string? pairUser = null, params Claim[] extra)
    {
        var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, user.ToString()) };
        claims.AddRange(extra);
        var properties = new AuthenticationProperties();
        if (pairEmail is not null)
        {
            properties.Items[RedisTicketStore.SsoEmailItem] = pairEmail;
        }
        if (pairUser is not null)
        {
            properties.Items[RedisTicketStore.SsoUserItem] = pairUser;
        }
        return new AuthenticationTicket(
            new ClaimsPrincipal(new ClaimsIdentity(claims, "Cookies")), properties, "Cookies");
    }
}

/// <summary>
/// A forwarding <see cref="IDatabase"/>: every call goes to the real database, and a test can fail a
/// call before it runs (<see cref="Before"/>) or act after it completed (<see cref="After"/>), which is
/// how a write "between the read and the script" or a failure "after the DEL" is injected.
/// </summary>
public class DbProxy : DispatchProxy
{
    public IDatabase Real { get; private set; } = null!;

    /// <summary>Returns an exception to throw instead of running the call, or null.</summary>
    public Func<string, object?[], Exception?>? Before { get; set; }

    /// <summary>Runs after a call that returns <c>Task&lt;T&gt;</c> completed, before the caller sees the result.</summary>
    public Func<string, object?[], Task>? After { get; set; }

    public static IDatabase Create(IDatabase real, out DbProxy handle)
    {
        var proxy = Create<IDatabase, DbProxy>();
        handle = (DbProxy)(object)proxy;
        handle.Real = real;
        return proxy;
    }

    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
    {
        args ??= [];
        var method = targetMethod!;
        if (Before?.Invoke(method.Name, args) is { } failure)
        {
            throw failure;
        }

        object? result;
        try
        {
            result = method.Invoke(Real, args);
        }
        catch (TargetInvocationException ex)
        {
            ExceptionDispatchInfo.Capture(ex.InnerException!).Throw();
            throw;
        }

        if (After is not null && result is Task task && method.ReturnType.IsGenericType)
        {
            return typeof(DbProxy)
                .GetMethod(nameof(Continue), BindingFlags.Static | BindingFlags.NonPublic)!
                .MakeGenericMethod(method.ReturnType.GetGenericArguments()[0])
                .Invoke(null, [task, method.Name, args, After]);
        }
        return result;
    }

    private static async Task<T> Continue<T>(Task<T> task, string name, object?[] args, Func<string, object?[], Task> after)
    {
        var value = await task;
        await after(name, args);
        return value;
    }
}
