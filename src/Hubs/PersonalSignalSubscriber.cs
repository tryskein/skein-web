using System.Text.Json;
using NATS.Client.Core;

namespace SkeinWeb.Hubs;

/// <summary>
/// Receives personal signals published by skein-api on
/// <c>skein.user.{uid}.signal</c> (contract T005,
/// <c>internal/signals/contract.go</c>) and hands them to the per-connection
/// <see cref="PersonalSignalCoalescer"/> (spec sk-622.21 US-11, K9, R15),
/// together with the <c>spaces</c> entries of a signal of that area
/// (sk-674.18 K-18).
/// </summary>
/// <remarks>
/// The subscription has NO queue group: every replica receives every signal
/// and coalesces it for its own connections of the user. With a queue group a
/// signal would reach one replica only and the user's tabs held by the other
/// replicas would never hear of it. <see cref="NatsBridge"/>'s queue-group loop
/// on <c>skein.user.&gt;</c> skips these subjects.
/// </remarks>
public sealed class PersonalSignalSubscriber : IHostedService
{
    /// <summary>NATS wildcard of every personal signal subject (T005 <c>SignalSubjectPattern</c>).</summary>
    public const string SignalSubjectPattern = "skein.user.*.signal";

    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    private readonly INatsConnection _conn;
    private readonly PersonalSignalCoalescer _coalescer;
    private readonly ILogger<PersonalSignalSubscriber> _logger;
    private CancellationTokenSource? _cts;
    private Task? _loop;

    /// <summary>Creates the subscriber.</summary>
    public PersonalSignalSubscriber(
        INatsConnection conn, PersonalSignalCoalescer coalescer, ILogger<PersonalSignalSubscriber> logger)
    {
        ArgumentNullException.ThrowIfNull(conn);
        ArgumentNullException.ThrowIfNull(coalescer);
        ArgumentNullException.ThrowIfNull(logger);
        _conn = conn;
        _coalescer = coalescer;
        _logger = logger;
    }

    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = new CancellationTokenSource();
        _loop = Task.Run(() => SubscribeLoop(_cts.Token), _cts.Token);
        _logger.LogInformation("PersonalSignalSubscriber started, subscribed to {Subject} without queue group",
            SignalSubjectPattern);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _cts?.Cancel();
        try
        {
            if (_loop is not null)
            {
                await _loop.WaitAsync(cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Cooperative shutdown.
        }
        finally
        {
            _cts?.Dispose();
            _cts = null;
        }
    }

    private async Task SubscribeLoop(CancellationToken ct)
    {
        try
        {
            await foreach (var msg in _conn.SubscribeAsync<byte[]>(
                               SignalSubjectPattern, queueGroup: null, cancellationToken: ct))
            {
                try
                {
                    Handle(msg.Subject, msg.Data);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "PersonalSignalSubscriber handling failed subject={Subject}", msg.Subject);
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Normal shutdown.
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "PersonalSignalSubscriber loop exited subject={Subject}", SignalSubjectPattern);
        }
    }

    private void Handle(string subject, byte[]? body)
    {
        // skein.user.{uid}.signal
        var parts = subject.Split('.');
        if (parts.Length != 4 || !Guid.TryParse(parts[2], out var userId))
        {
            _logger.LogWarning("PersonalSignalSubscriber dropping malformed subject {Subject}", subject);
            return;
        }
        PersonalSignal? signal;
        try
        {
            signal = body is { Length: > 0 } ? JsonSerializer.Deserialize<PersonalSignal>(body, JsonOpts) : null;
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "PersonalSignalSubscriber signal deserialise failed userId={UserId}", userId);
            return;
        }
        var areas = signal?.Areas?.Where(a => !string.IsNullOrEmpty(a)).ToArray();
        if (areas is not { Length: > 0 })
        {
            _logger.LogWarning("PersonalSignalSubscriber empty signal userId={UserId}", userId);
            return;
        }
        // Area spaces (sk-674.18 K-18): its entries ride along so the
        // coalescer can merge them without losing a reason.
        var spaces = signal!.Spaces?
            .Where(e => e is not null && !string.IsNullOrEmpty(e.Reason) && !string.IsNullOrEmpty(e.SpaceId))
            .ToArray();
        _coalescer.SignalUser(userId, areas, spaces);
    }
}
