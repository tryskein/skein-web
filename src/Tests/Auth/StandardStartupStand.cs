using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Routing;

namespace SkeinWeb.Tests.Auth;

/// <summary>One command a client sent to Redis, as the proxy parsed it.</summary>
internal sealed record RedisCommand(string Name, string[] Args)
{
    /// <summary>Whether the command names <paramref name="key"/> among its arguments.</summary>
    public bool Mentions(string key) => Args.Any(a => a == key);

    public bool IsScriptWith(string fragment) =>
        Name is "EVAL" or "EVALSHA" && Args.Length > 0 && Args[0].Contains(fragment, StringComparison.Ordinal);
}

/// <summary>A command the proxy keeps back until the test lets it go.</summary>
internal sealed class RedisHold(Func<RedisCommand, bool> predicate)
{
    private readonly TaskCompletionSource _reached = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _released = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public bool Matches(RedisCommand command) => predicate(command);
    public Task Reached => _reached.Task;
    public void MarkReached() => _reached.TrySetResult();
    public Task WaitReleased() => _released.Task;
    public void Release() => _released.TrySetResult();
}

/// <summary>
/// What the server answered to one command, as the proxy parsed it: the cursor of a reply shaped like
/// the reply of <c>SCAN</c> (an array whose first element is a bulk string and whose second is an
/// array), else null.
/// </summary>
internal sealed record RedisReply(string? Cursor);

/// <summary>
/// The reply to a command that the proxy keeps back after the server answered and before the
/// client gets it, until the test lets it go.
/// </summary>
internal sealed class RedisReplyHold(Func<RedisCommand, RedisReply, bool> predicate)
{
    private readonly TaskCompletionSource _reached = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _released = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public bool Matches(RedisCommand command, RedisReply reply) => predicate(command, reply);

    /// <summary>Completes when the matching reply arrived from the server and is kept back.</summary>
    public Task Reached => _reached.Task;

    /// <summary>The command whose reply is kept back; set when <see cref="Reached"/> completes.</summary>
    public RedisCommand? Command { get; private set; }

    /// <summary>The reply kept back (for <c>SCAN</c>, its cursor: the page); set when <see cref="Reached"/> completes.</summary>
    public RedisReply? Reply { get; private set; }

    public void MarkReached(RedisCommand command, RedisReply reply)
    {
        Command = command;
        Reply = reply;
        _reached.TrySetResult();
    }

    public Task WaitReleased() => _released.Task;
    public void Release() => _released.TrySetResult();
}

/// <summary>
/// A TCP proxy in front of the real Redis that parses what the client sends (RESP arrays), logs each
/// command, can keep a chosen command back (not forwarded) until released, can keep the reply to a
/// chosen command back (answered by the server, not yet passed to the client) until released, can be
/// cut for good, and selects database <see cref="Database"/> on every upstream connection so the
/// stand has a Redis of its own. Replies are matched to commands in the order of the connection;
/// push frames (RESP3 <c>&gt;</c>) answer no command.
/// </summary>
internal sealed class RedisProxy : IDisposable
{
    public const int Database = 11;
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly List<TcpClient> _sockets = [];
    private readonly object _gate = new();
    private RedisHold? _hold;
    private RedisReplyHold? _replyHold;
    private volatile bool _cut;

    public RedisProxy(string host, int port)
    {
        _listener.Start();
        _ = Task.Run(async () =>
        {
            while (!_cut)
            {
                try
                {
                    var client = await _listener.AcceptTcpClientAsync();
                    var upstream = new TcpClient();
                    await upstream.ConnectAsync(host, port);
                    var select = Encoding.ASCII.GetBytes($"*2\r\n$6\r\nSELECT\r\n${Database.ToString().Length}\r\n{Database}\r\n");
                    await upstream.GetStream().WriteAsync(select);
                    var ok = new byte[5];
                    await upstream.GetStream().ReadExactlyAsync(ok); // +OK\r\n
                    lock (_gate)
                    {
                        _sockets.Add(client);
                        _sockets.Add(upstream);
                    }
                    var sent = new Queue<RedisCommand>();
                    _ = Pump(client, upstream, sent);
                    _ = PumpReplies(upstream, client, sent);
                }
                catch (Exception)
                {
                    return;
                }
            }
        });
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
    public List<RedisCommand> Log { get; } = [];

    public RedisHold Hold(Func<RedisCommand, bool> predicate)
    {
        var hold = new RedisHold(predicate);
        lock (_gate)
        {
            _hold = hold;
        }
        return hold;
    }

    /// <summary>
    /// Keeps back the first reply that <paramref name="predicate"/> accepts — the command it answers
    /// and the reply — after the server answered and before the client gets it. The holds by command
    /// (<see cref="Hold"/>) are not affected.
    /// </summary>
    public RedisReplyHold HoldReply(Func<RedisCommand, RedisReply, bool> predicate)
    {
        var hold = new RedisReplyHold(predicate);
        lock (_gate)
        {
            _replyHold = hold;
        }
        return hold;
    }

    public void Cut()
    {
        _cut = true;
        _listener.Stop();
        lock (_gate)
        {
            foreach (var socket in _sockets)
            {
                socket.Close();
            }
        }
    }

    public IReadOnlyList<RedisCommand> Commands()
    {
        lock (Log)
        {
            return Log.ToArray();
        }
    }

    private async Task Pump(TcpClient client, TcpClient upstream, Queue<RedisCommand> sent)
    {
        var input = client.GetStream();
        var output = upstream.GetStream();
        var buffer = new List<byte>();
        var chunk = new byte[16 * 1024];
        try
        {
            while (true)
            {
                var read = await input.ReadAsync(chunk);
                if (read == 0)
                {
                    return;
                }
                buffer.AddRange(chunk.AsSpan(0, read).ToArray());
                while (TryParse(buffer, out var command, out var length))
                {
                    var raw = buffer.GetRange(0, length).ToArray();
                    buffer.RemoveRange(0, length);
                    lock (Log)
                    {
                        Log.Add(command);
                    }
                    RedisHold? hold;
                    lock (_gate)
                    {
                        hold = _hold is not null && _hold.Matches(command) ? _hold : null;
                        if (hold is not null)
                        {
                            _hold = null;
                        }
                    }
                    if (hold is not null)
                    {
                        hold.MarkReached();
                        await hold.WaitReleased();
                    }
                    lock (sent)
                    {
                        sent.Enqueue(command);
                    }
                    await output.WriteAsync(raw);
                }
            }
        }
        catch (Exception)
        {
            // a cut or a closed peer ends the pipe
        }
    }

    private async Task PumpReplies(TcpClient upstream, TcpClient client, Queue<RedisCommand> sent)
    {
        var input = upstream.GetStream();
        var output = client.GetStream();
        var buffer = new List<byte>();
        var chunk = new byte[16 * 1024];
        try
        {
            while (true)
            {
                var read = await input.ReadAsync(chunk);
                if (read == 0)
                {
                    return;
                }
                buffer.AddRange(chunk.AsSpan(0, read).ToArray());
                while (TryParseReply(buffer, out var reply, out var push, out var length))
                {
                    var raw = buffer.GetRange(0, length).ToArray();
                    buffer.RemoveRange(0, length);
                    RedisCommand? command = null;
                    if (!push)
                    {
                        lock (sent)
                        {
                            sent.TryDequeue(out command);
                        }
                    }
                    RedisReplyHold? hold = null;
                    if (command is not null)
                    {
                        lock (_gate)
                        {
                            if (_replyHold is not null && _replyHold.Matches(command, reply))
                            {
                                hold = _replyHold;
                                _replyHold = null;
                            }
                        }
                    }
                    if (hold is not null)
                    {
                        hold.MarkReached(command!, reply);
                        await hold.WaitReleased();
                    }
                    await output.WriteAsync(raw);
                }
            }
        }
        catch (Exception)
        {
            // a cut or a closed peer ends the pipe
        }
    }

    // One complete RESP2/RESP3 value at the start of the buffer: its length, whether it is a push
    // frame, and the cursor when it has the shape of a SCAN reply.
    private static bool TryParseReply(List<byte> buffer, out RedisReply reply, out bool push, out int length)
    {
        reply = new RedisReply(null);
        push = buffer.Count > 0 && buffer[0] == (byte)'>';
        length = 0;
        var pos = 0;
        if (!SkipValue(buffer, ref pos, out var first, out var elements))
        {
            return false;
        }
        length = pos;
        if (elements is [{ } cursor, null] && first == '*')
        {
            reply = new RedisReply(cursor);
        }
        return true;
    }

    // Skips one value; for an aggregate, reports the bulk-string text of each direct element (null
    // for an element that is not a bulk string).
    private static bool SkipValue(List<byte> buffer, ref int pos, out char type, out List<string?>? elements)
    {
        elements = null;
        type = '\0';
        if (pos >= buffer.Count)
        {
            return false;
        }
        type = (char)buffer[pos];
        if (!ReadLine(buffer, ref pos, out var line))
        {
            return false;
        }
        switch (type)
        {
            case '+' or '-' or ':' or '_' or '#' or ',' or '(':
                return true;
            case '$' or '=' or '!':
            {
                var n = int.Parse(line[1..]);
                if (n < 0)
                {
                    return true;
                }
                if (buffer.Count < pos + n + 2)
                {
                    return false;
                }
                pos += n + 2;
                return true;
            }
            case '*' or '~' or '>' or '%' or '|':
            {
                var n = int.Parse(line[1..]);
                if (n < 0)
                {
                    return true;
                }
                var count = type is '%' or '|' ? 2 * n : n;
                elements = new List<string?>(count);
                for (var i = 0; i < count; i++)
                {
                    var start = pos;
                    if (!SkipValue(buffer, ref pos, out var inner, out _))
                    {
                        return false;
                    }
                    elements.Add(inner == '$' && buffer[start] == (byte)'$' ? BulkText(buffer, start, pos) : null);
                }
                // An attribute precedes the value it describes.
                return type != '|' || SkipValue(buffer, ref pos, out _, out _);
            }
            default:
                throw new InvalidOperationException($"the proxy cannot parse a reply of type '{type}'");
        }
    }

    private static string? BulkText(List<byte> buffer, int start, int end)
    {
        var header = start;
        if (!ReadLine(buffer, ref header, out var line) || line == "$-1")
        {
            return null;
        }
        return Encoding.UTF8.GetString(buffer.GetRange(header, end - header - 2).ToArray());
    }

    private static bool TryParse(List<byte> buffer, out RedisCommand command, out int length)
    {
        command = null!;
        length = 0;
        var pos = 0;
        if (buffer.Count == 0 || buffer[0] != (byte)'*')
        {
            return false;
        }
        if (!ReadLine(buffer, ref pos, out var header))
        {
            return false;
        }
        var count = int.Parse(header[1..]);
        var parts = new string[count];
        for (var i = 0; i < count; i++)
        {
            if (!ReadLine(buffer, ref pos, out var size) || size[0] != '$')
            {
                return false;
            }
            var n = int.Parse(size[1..]);
            if (buffer.Count < pos + n + 2)
            {
                return false;
            }
            parts[i] = Encoding.UTF8.GetString(buffer.GetRange(pos, n).ToArray());
            pos += n + 2;
        }
        command = new RedisCommand(parts[0].ToUpperInvariant(), parts[1..]);
        length = pos;
        return true;
    }

    private static bool ReadLine(List<byte> buffer, ref int pos, out string line)
    {
        for (var i = pos; i + 1 < buffer.Count; i++)
        {
            if (buffer[i] == '\r' && buffer[i + 1] == '\n')
            {
                line = Encoding.ASCII.GetString(buffer.GetRange(pos, i - pos).ToArray());
                pos = i + 2;
                return true;
            }
        }
        line = "";
        return false;
    }

    public void Dispose() => Cut();
}

/// <summary>A skein-api stand-in with the few routes the BFF calls at start and on a sign-in.</summary>
internal sealed class StubSkeinApi : IAsyncDisposable
{
    private readonly WebApplication _app;
    private int _provision;
    private int _me;
    private int _agent;

    public string Url { get; }
    public int Provisions => Volatile.Read(ref _provision);
    public int MeCalls => Volatile.Read(ref _me);
    public int AgentCalls => Volatile.Read(ref _agent);

    private StubSkeinApi(WebApplication app, string url)
    {
        _app = app;
        Url = url;
    }

    public static async Task<StubSkeinApi> StartAsync(string authMode)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        var app = builder.Build();
        StubSkeinApi? self = null;
        object User(string name) => new
        {
            id = Guid.NewGuid().ToString(),
            email = $"{name}@example.com",
            username = name,
            name,
            role = "user",
            isExternal = false,
            sessionEpoch = 3,
        };
        app.MapGet("/ui/v1/internal/instance-config", () => Results.Json(new
        {
            authMode,
            signupEnabled = false,
            emailEnabled = false,
            turnstileSiteKey = (string?)null,
            projectPrefixMinLength = (int?)null,
            termsUrl = (string?)null,
            privacyUrl = (string?)null,
            instanceAdminEnabled = false,
        }));
        app.MapPost("/ui/v1/auth/login", () => Results.Json(User("alice")));
        app.MapGet("/ui/v1/auth/me", () =>
        {
            Interlocked.Increment(ref self!._me);
            return Results.Json(User("alice"));
        });
        app.MapPost("/ui/v1/auth/oidc/provision", async (HttpContext ctx) =>
        {
            Interlocked.Increment(ref self!._provision);
            using var doc = await System.Text.Json.JsonDocument.ParseAsync(ctx.Request.Body);
            var username = doc.RootElement.GetProperty("username").GetString()!;
            return Results.Json(User(username));
        });
        app.Map("/agent/v1/{**rest}", () =>
        {
            Interlocked.Increment(ref self!._agent);
            return Results.Json(new { ok = true });
        });
        await app.StartAsync();
        self = new StubSkeinApi(app, app.Urls.First());
        return self;
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }
}

/// <summary>The built <c>SkeinWeb.dll</c> run as a process.</summary>
internal sealed class AppProcess : IDisposable
{
    private readonly Process _process;
    private readonly StringBuilder _output = new();

    public int Port { get; }
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
    public bool HasExited => _process.HasExited;
    public int ExitCode => _process.ExitCode;

    private AppProcess(Process process, int port)
    {
        _process = process;
        Port = port;
    }

    public static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    public static AppProcess Start(IDictionary<string, string?> environment)
    {
        var directory = Path.GetDirectoryName(typeof(SkeinWeb.Auth.SessionCookiePolicy).Assembly.Location)!;
        var port = FreePort();
        var info = new ProcessStartInfo("dotnet", ["SkeinWeb.dll"])
        {
            WorkingDirectory = directory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        info.Environment["PORT"] = port.ToString();
        foreach (var (name, value) in environment)
        {
            if (value is null)
            {
                info.Environment.Remove(name);
            }
            else
            {
                info.Environment[name] = value;
            }
        }
        var process = Process.Start(info)!;
        var app = new AppProcess(process, port);
        process.OutputDataReceived += (_, e) => app.Append(e.Data);
        process.ErrorDataReceived += (_, e) => app.Append(e.Data);
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        return app;
    }

    private void Append(string? line)
    {
        if (line is null)
        {
            return;
        }
        lock (_output)
        {
            _output.AppendLine(line);
        }
    }

    public async Task<bool> AcceptsConnectionAsync()
    {
        try
        {
            using var client = new TcpClient();
            using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
            await client.ConnectAsync(IPAddress.Loopback, Port, timeout.Token);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public async Task<bool> WaitForHealthAsync(TimeSpan timeout)
    {
        using var http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{Port}") };
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline && !_process.HasExited)
        {
            try
            {
                if ((await http.GetAsync("/healthz")).IsSuccessStatusCode)
                {
                    return true;
                }
            }
            catch (HttpRequestException)
            {
            }
            await Task.Delay(100);
        }
        return false;
    }

    public async Task<bool> WaitForExitAsync(TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            await _process.WaitForExitAsync(cts.Token);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    public void Dispose()
    {
        if (!_process.HasExited)
        {
            _process.Kill(entireProcessTree: true);
        }
        _process.Dispose();
    }
}
