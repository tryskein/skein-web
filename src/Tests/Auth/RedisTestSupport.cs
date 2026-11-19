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
/// call before it runs (<see cref="Before"/>), hold it before it reaches Redis (<see cref="Hold"/>) or
/// act after it completed (<see cref="After"/>), which is how a write "between the read and the
/// script", a failure "after the DEL" or a command "kept back until a moment" is injected.
/// </summary>
public class DbProxy : DispatchProxy
{
    private readonly List<Barrier> _barriers = [];

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

    /// <summary>
    /// Holds the first asynchronous call that <paramref name="match"/> accepts (method name and
    /// arguments) before it is passed to Redis, until the test releases it. The call returns a
    /// pending task at once; nothing reaches Redis until <see cref="Barrier.Release"/>.
    /// </summary>
    public Barrier Hold(Func<string, object?[], bool> match)
    {
        var barrier = new Barrier(match);
        lock (_barriers)
        {
            _barriers.Add(barrier);
        }
        return barrier;
    }

    /// <summary>The script text of a <c>ScriptEvaluateAsync(string, …)</c> call, or null for any other call.</summary>
    public static string? ScriptOf(string method, object?[] args) =>
        method == nameof(IDatabase.ScriptEvaluateAsync) && args.Length > 0 && args[0] is string script ? script : null;

    /// <summary>The <c>KEYS</c> of a <c>ScriptEvaluateAsync(string, RedisKey[], …)</c> call; empty for any other call.</summary>
    public static RedisKey[] KeysOf(string method, object?[] args) =>
        ScriptOf(method, args) is not null && args.Length > 1 && args[1] is RedisKey[] keys ? keys : [];

    /// <summary>Whether the call is a script whose text contains <paramref name="fragment"/> and whose keys include <paramref name="key"/>, when given.</summary>
    public static bool IsScript(string method, object?[] args, string fragment, string? key = null) =>
        ScriptOf(method, args) is { } script
        && script.Contains(fragment, StringComparison.Ordinal)
        && (key is null || KeysOf(method, args).Contains((RedisKey)key));

    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
    {
        args ??= [];
        var method = targetMethod!;
        if (Before?.Invoke(method.Name, args) is { } failure)
        {
            throw failure;
        }

        Barrier? held = null;
        if (method.ReturnType.IsGenericType && method.ReturnType.GetGenericTypeDefinition() == typeof(Task<>))
        {
            lock (_barriers)
            {
                held = _barriers.FirstOrDefault(b => !b.Taken && b.Match(method.Name, args));
                held?.Take();
            }
        }
        if (held is not null)
        {
            return typeof(DbProxy)
                .GetMethod(nameof(RunAfterRelease), BindingFlags.Instance | BindingFlags.NonPublic)!
                .MakeGenericMethod(method.ReturnType.GetGenericArguments()[0])
                .Invoke(this, [held, method, args]);
        }

        return Run(method, args);
    }

    private object? Run(MethodInfo method, object?[] args)
    {
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

    private async Task<T> RunAfterRelease<T>(Barrier barrier, MethodInfo method, object?[] args)
    {
        barrier.Arrive();
        await barrier.Released;
        return await (Task<T>)Run(method, args)!;
    }

    private static async Task<T> Continue<T>(Task<T> task, string name, object?[] args, Func<string, object?[], Task> after)
    {
        var value = await task;
        await after(name, args);
        return value;
    }

    /// <summary>One held call: the test awaits <see cref="Reached"/>, then calls <see cref="Release"/>.</summary>
    public sealed class Barrier(Func<string, object?[], bool> match)
    {
        private readonly TaskCompletionSource _reached = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _released = new(TaskCreationOptions.RunContinuationsAsynchronously);

        internal Func<string, object?[], bool> Match { get; } = match;

        internal bool Taken { get; private set; }

        /// <summary>Completes when the matching call arrived and is being held (it has not reached Redis).</summary>
        public Task Reached => _reached.Task;

        internal Task Released => _released.Task;

        /// <summary>Lets the held call go on to Redis.</summary>
        public void Release() => _released.TrySetResult();

        internal void Take() => Taken = true;

        internal void Arrive() => _reached.TrySetResult();
    }
}

/// <summary>
/// Distinctive fragments of the store's scripts, to tell its calls apart on the Redis boundary
/// (<see cref="DbProxy.IsScript"/>): the lifetime write of a read, the revocation (read and delete),
/// the issue, the compare-and-set of the explicit renewal and the prune of the index at sign-in.
/// </summary>
internal static class StoreScripts
{
    public const string Read = "PEXPIRE', KEYS[1], ARGV[1]";
    public const string Revoke = "redis.pcall('GET', KEYS[1])";
    public const string Issue = "'NX', 'PX'";
    public const string Renew = "redis.call('TIME')";
    public const string Prune = "SMEMBERS";
}

/// <summary>What an injected failure saw: whether the step it waits for completed, and whether it fired.</summary>
internal sealed class Injection
{
    public bool Preceded { get; set; }

    public bool Fired { get; set; }

    /// <summary>
    /// Fails the script <paramref name="failing"/> of <paramref name="failingKey"/>, with no earlier step to
    /// wait for: for a request that reads no ticket before that step.
    /// </summary>
    public static Injection Fail(DbProxy faults, string failing, string failingKey)
    {
        var injection = new Injection { Preceded = true };
        faults.Before = (name, args) =>
        {
            if (DbProxy.IsScript(name, args, failing, failingKey))
            {
                injection.Fired = true;
                return new InvalidOperationException("injected");
            }
            return null;
        };
        return injection;
    }

    /// <summary>
    /// Fails the script <paramref name="failing"/> (of <paramref name="failingKey"/>, when given), and only
    /// once the script <paramref name="preceding"/> (of <paramref name="precedingKey"/>, when given) has
    /// completed in the same stand: the failure belongs to the named step, after the one before it.
    /// </summary>
    public static Injection FailAfter(DbProxy faults, string failing, string preceding, string? failingKey = null, string? precedingKey = null)
    {
        var injection = new Injection();
        faults.After = (name, args) =>
        {
            if (DbProxy.IsScript(name, args, preceding, precedingKey))
            {
                injection.Preceded = true;
            }
            return Task.CompletedTask;
        };
        faults.Before = (name, args) =>
        {
            if (injection.Preceded && DbProxy.IsScript(name, args, failing, failingKey))
            {
                injection.Fired = true;
                return new InvalidOperationException("injected");
            }
            return null;
        };
        return injection;
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
