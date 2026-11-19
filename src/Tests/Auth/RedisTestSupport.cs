using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using SkeinWeb.Logging;
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

    /// <summary>
    /// A store over a Redis that answers every revocation script with "a row was deleted": for the
    /// tests that only need the end of a session to complete (the effective key is revoked, the
    /// cookie scheme is signed out).
    /// </summary>
    public static RedisTicketStore RevokingStore()
    {
        var db = new Mock<IDatabase>();
        db.Setup(d => d.ScriptEvaluateAsync(It.IsAny<string>(), It.IsAny<RedisKey[]>(), It.IsAny<RedisValue[]>(), It.IsAny<CommandFlags>()))
            .ReturnsAsync(RedisResult.Create((RedisValue)1, ResultType.Integer));
        var mux = new Mock<IConnectionMultiplexer>();
        mux.Setup(m => m.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(db.Object);
        return Store(mux.Object);
    }

    /// <summary>A session issuer over a store that confirms every revocation, for tests that only build a controller.</summary>
    public static SessionIssuer Issuer() => new(
        RevokingStore(),
        new SkeinWeb.Hubs.ConnectionRegistry(TimeProvider.System),
        new SessionCookiePolicy(AllowInsecureHttp: true),
        new TicketDataFormat(new Microsoft.AspNetCore.DataProtection.EphemeralDataProtectionProvider().CreateProtector("test")),
        TimeProvider.System,
        new SessionTimeouts(SessionTimeouts.DefaultIdleTimeoutHours, SessionTimeouts.DefaultAbsoluteTimeoutHours),
        NullLogger<SessionIssuer>.Instance);

    /// <summary>The limits a store gets when a test names none: the defaults of the settings.</summary>
    public static SessionTimeouts DefaultTimeouts { get; } =
        new(SessionTimeouts.DefaultIdleTimeoutHours, SessionTimeouts.DefaultAbsoluteTimeoutHours);

    public static RedisTicketStore Store(IConnectionMultiplexer mux, SessionTimeouts? timeouts = null, TimeProvider? time = null) =>
        new(mux, timeouts ?? DefaultTimeouts, time ?? TimeProvider.System, NullLogger<RedisTicketStore>.Instance);

    /// <summary>
    /// Gives <paramref name="properties"/> the window of a sign-in at <paramref name="signIn"/>
    /// (now when omitted) under <paramref name="timeouts"/> (the defaults when omitted): the valid
    /// window a ticket needs to be read back by the store. The seeds of the tests take it from here.
    /// </summary>
    public static AuthenticationProperties WithWindow(
        AuthenticationProperties properties, DateTimeOffset? signIn = null, SessionTimeouts? timeouts = null)
    {
        var window = SessionWindow.ForSignIn(timeouts ?? DefaultTimeouts, signIn ?? DateTimeOffset.UtcNow);
        properties.IssuedUtc = window.IssuedUtc;
        properties.ExpiresUtc = window.ExpiresUtc;
        return properties;
    }

    public static AuthenticationTicket Ticket(Guid user, string? pairEmail = null, string? pairUser = null, params Claim[] extra)
    {
        var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, user.ToString()) };
        claims.AddRange(extra);
        var properties = WithWindow(new AuthenticationProperties());
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

/// <summary>Feeds every log call to the real <see cref="SkeinConsoleFormatter"/> and keeps its output lines.</summary>
internal sealed class FormatterLogs : ILoggerProvider, ISupportExternalScope
{
    private readonly SkeinConsoleFormatter _formatter = new();
    private IExternalScopeProvider _scopes = new LoggerExternalScopeProvider();
    private readonly StringWriter _output = new();

    public string Output
    {
        get
        {
            lock (_output)
            {
                return _output.ToString();
            }
        }
    }

    public ILogger CreateLogger(string categoryName) => new Capture(this, categoryName);

    public void SetScopeProvider(IExternalScopeProvider scopeProvider) => _scopes = scopeProvider;

    public void Dispose()
    {
    }

    private sealed class Capture(FormatterLogs owner, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => owner._scopes.Push(state);

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (owner._output)
            {
                owner._formatter.Write(new LogEntry<TState>(logLevel, category, eventId, state, exception, formatter), owner._scopes, owner._output);
            }
        }
    }
}
