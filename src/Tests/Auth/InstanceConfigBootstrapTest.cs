using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using SkeinWeb.Auth;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// E-13, K-12: skein-web takes its installation
/// settings from skein-api before the host is built. Without an answer inside
/// <c>SKEIN_API_STARTUP_TIMEOUT_SECONDS</c> the load fails (the process does not
/// start); temporary failures followed by an answer let it start; an answer
/// that is not the T012 contract fails without a default mode. Time runs on
/// <see cref="FakeTimeProvider"/>: the window and the backoff are observed on
/// the fake clock, never measured live.
/// </summary>
public class InstanceConfigBootstrapTest
{
    private static readonly TimeSpan Window = TimeSpan.FromSeconds(3);

    // T012 godoc literal (internal/accounts/contract.go#InstanceConfig), with
    // authMode "hybrid" so a value taken from the answer is told apart from a
    // "local" a default would produce.
    private const string HybridLiteral = """
        {"authMode":"hybrid","signupEnabled":true,"emailEnabled":true,
         "turnstileSiteKey":"0x4AAAAAAA","projectPrefixMinLength":3,
         "termsUrl":"https://skein.example.com/terms","privacyUrl":null,
         "instanceAdminEnabled":false}
        """;

    /// <summary>One scripted answer per attempt; the last one repeats.</summary>
    private sealed class ScriptedHandler(params Func<CancellationToken, Task<HttpResponseMessage>>[] script)
        : HttpMessageHandler
    {
        private int _attempts;
        private readonly List<DateTimeOffset> _attemptTimes = [];

        public int Attempts => Volatile.Read(ref _attempts);

        /// <summary>Fake-clock reading at each attempt.</summary>
        public Func<DateTimeOffset>? Clock { get; set; }

        public DateTimeOffset[] AttemptTimes
        {
            get { lock (_attemptTimes) { return [.. _attemptTimes]; } }
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (Clock is { } clock)
            {
                lock (_attemptTimes) { _attemptTimes.Add(clock()); }
            }
            var i = Interlocked.Increment(ref _attempts) - 1;
            return script[Math.Min(i, script.Length - 1)](ct);
        }
    }

    private static Func<CancellationToken, Task<HttpResponseMessage>> Status(HttpStatusCode code) =>
        _ => Task.FromResult(new HttpResponseMessage(code));

    private static Func<CancellationToken, Task<HttpResponseMessage>> Json(string body) =>
        _ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        });

    private static readonly Func<CancellationToken, Task<HttpResponseMessage>> Refused =
        _ => Task.FromException<HttpResponseMessage>(new HttpRequestException("Connection refused"));

    // Never answers: completes only when the attempt's own timeout cancels it.
    private static readonly Func<CancellationToken, Task<HttpResponseMessage>> Hang =
        ct => Task.Delay(Timeout.Infinite, ct).ContinueWith<HttpResponseMessage>(
            _ => throw new OperationCanceledException(ct), TaskScheduler.Default);

    private sealed record Run(Task<InstanceConfig> Load, ScriptedHandler Handler, FakeTimeProvider Time, DateTimeOffset Start);

    private static Run Start(params Func<CancellationToken, Task<HttpResponseMessage>>[] script) =>
        StartWithWindow(Window, script);

    private static Run StartWithWindow(TimeSpan window, params Func<CancellationToken, Task<HttpResponseMessage>>[] script)
    {
        var handler = new ScriptedHandler(script);
        var time = new FakeTimeProvider();
        handler.Clock = time.GetUtcNow;
        var http = new HttpClient(handler) { BaseAddress = new Uri("http://skein-api.test/") };
        var start = time.GetUtcNow();
        var load = InstanceConfigBootstrap.LoadAsync(http, window, time, NullLogger.Instance, CancellationToken.None);
        return new Run(load, handler, time, start);
    }

    /// <summary>Granularity of <see cref="DriveToCompletionAsync"/>: an event is seen at most one step late.</summary>
    private static readonly TimeSpan Step = TimeSpan.FromMilliseconds(100);

    /// <summary>
    /// Moves the fake clock forward in small steps until the load completes.
    /// The short real yield between steps only lets continuations run; no
    /// assertion reads real time. Bounded so a broken loader fails the test
    /// instead of hanging it.
    /// </summary>
    private static async Task DriveToCompletionAsync(Run run)
    {
        for (var step = 0; !run.Load.IsCompleted; step++)
        {
            Assert.True(step < 2000, "the load did not complete within 200 s of fake time");
            run.Time.Advance(Step);
            await Task.WhenAny(run.Load, Task.Delay(5));
        }
    }

    public static TheoryData<string> NoAnswerKinds => new() { "503", "refused", "hang" };

    [Theory]
    [MemberData(nameof(NoAnswerKinds))]
    public async Task NoAnswerWithinWindow_LoadFails_OnlyAfterTheWindow(string kind)
    {
        var run = kind switch
        {
            "503" => Start(Status(HttpStatusCode.ServiceUnavailable)),
            "refused" => Start(Refused),
            _ => Start(Hang),
        };

        await DriveToCompletionAsync(run);

        await Assert.ThrowsAsync<InstanceConfigUnavailableException>(() => run.Load);
        // Not a zero window: the failure comes only once the window has run out…
        var elapsed = run.Time.GetUtcNow() - run.Start;
        Assert.True(elapsed >= Window, $"failed after {elapsed} of fake time, window is {Window}");
        // …and not later: the window bounds the whole load, a hanging attempt
        // included (it is cut at the window, not at its own 10 s timeout).
        Assert.True(elapsed <= Window + Step, $"failed only after {elapsed} of fake time, window is {Window}");
        if (kind != "hang")
        {
            // A refusal answered at once is retried, not taken as final.
            Assert.True(run.Handler.Attempts >= 2, $"only {run.Handler.Attempts} attempt(s) inside the window");
        }
    }

    [Fact]
    public async Task Backoff_DoublesFromHalfASecond_UpToFiveSeconds()
    {
        var run = StartWithWindow(TimeSpan.FromSeconds(20), Status(HttpStatusCode.ServiceUnavailable));

        await DriveToCompletionAsync(run);

        await Assert.ThrowsAsync<InstanceConfigUnavailableException>(() => run.Load);
        var times = run.Handler.AttemptTimes;
        var gaps = times.Zip(times.Skip(1), (a, b) => (b - a).TotalSeconds).ToArray();
        // Pauses between attempts: 0.5, 1, 2, 4, then capped at 5 (window 20 s:
        // attempts at 0, 0.5, 1.5, 3.5, 7.5, 12.5, 17.5; the next pause is cut at the window).
        double[] expected = [0.5, 1, 2, 4, 5, 5];
        Assert.Equal(expected.Length, gaps.Length);
        for (var i = 0; i < expected.Length; i++)
        {
            Assert.InRange(gaps[i], expected[i] - Step.TotalSeconds, expected[i] + Step.TotalSeconds);
        }
    }

    [Fact]
    public async Task TemporaryFailures_ThenAnswer_LoadReturnsTheApiSettings()
    {
        var run = Start(Status(HttpStatusCode.ServiceUnavailable), Refused, Json(HybridLiteral));

        await DriveToCompletionAsync(run);

        var config = await run.Load;
        Assert.Equal(3, run.Handler.Attempts);
        Assert.Equal("hybrid", config.AuthMode);
        Assert.True(config.SignupEnabled);
        Assert.Equal(3, config.ProjectPrefixMinLength);
        Assert.Equal("0x4AAAAAAA", config.TurnstileSiteKey);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)] // wrong SKEIN_INTERNAL_SECRET
    [InlineData(HttpStatusCode.NotFound)]     // wrong SKEIN_API_URL / no route
    public async Task DeterministicRefusal_FailsAtOnce_WithoutWaitingOutTheWindow(HttpStatusCode status)
    {
        var run = Start(Status(status));

        await DriveToCompletionAsync(run);

        await Assert.ThrowsAsync<InstanceConfigUnavailableException>(() => run.Load);
        Assert.Equal(1, run.Handler.Attempts);
        Assert.Equal(run.Start, run.Handler.AttemptTimes.Single());
        Assert.True(run.Time.GetUtcNow() - run.Start < Window);
    }

    public static TheoryData<string> NonContractBodies => new()
    {
        // authMode outside local|keycloak|hybrid
        """{"authMode":"corporate","signupEnabled":true,"emailEnabled":true,"turnstileSiteKey":null,"projectPrefixMinLength":null,"termsUrl":null,"privacyUrl":null,"instanceAdminEnabled":false}""",
        // authMode key missing
        """{"signupEnabled":true,"emailEnabled":true,"turnstileSiteKey":null,"projectPrefixMinLength":null,"termsUrl":null,"privacyUrl":null,"instanceAdminEnabled":false}""",
        // not JSON
        "<html>gateway</html>",
    };

    [Theory]
    [MemberData(nameof(NonContractBodies))]
    public async Task AnswerOutsideTheContract_FailsAtOnce_WithoutADefaultMode(string body)
    {
        var run = Start(Json(body));

        await DriveToCompletionAsync(run);

        await Assert.ThrowsAsync<InstanceConfigUnavailableException>(() => run.Load);
        Assert.Equal(1, run.Handler.Attempts);
    }

    [Fact]
    public void StartupTimeout_Unset_IsSixtySeconds() =>
        Assert.Equal(TimeSpan.FromSeconds(60), InstanceConfigBootstrap.ParseStartupTimeout(null));

    [Theory]
    [InlineData("0")]
    [InlineData("-5")]
    [InlineData("")]
    [InlineData("ten")]
    [InlineData("3601")]
    public void StartupTimeout_ZeroOrMalformed_StopsStartup(string raw) =>
        Assert.Throws<InvalidOperationException>(() => InstanceConfigBootstrap.ParseStartupTimeout(raw));
}
