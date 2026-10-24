using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using SkeinWeb.Auth;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// Wire contract of <see cref="SkeinServiceApiClient.CheckProjectAccessAsync"/>
/// (sk-622.21 T031) against the literals fixed by the skein-api
/// godoc of <c>internal/projects/access_contract.go</c> (T028): request and
/// response shape, service-secret-only authentication with no user identity,
/// retry-then-throw on 5xx, no retry on 401, and the secret never reaching a
/// log or an exception message, a call bounded by a 15 s budget, and a 200
/// body breaking the T028 shape refused.
/// </summary>
/// <remarks>
/// The client is resolved from a <see cref="ServiceCollection"/> composed by
/// <see cref="SkeinServiceApiClientRegistration.AddSkeinServiceApiClient"/> —
/// the same registration <c>Program.cs</c> uses — with only the primary
/// (transport) handler replaced by a stub. An authenticated
/// <see cref="HttpContext"/> is ambient in the container's
/// <see cref="IHttpContextAccessor"/> and <see cref="InternalApiHandler"/> is
/// resolvable, so attaching that handler to the registration would put the
/// user's identity on the wire; retry policy and header redaction are
/// observed on that same pipeline.
/// </remarks>
public class SkeinServiceApiClient_CheckProjectAccessTest
{
    private const string Secret = "svc-secret-aaaaaa";

    private static readonly Guid U1 = Guid.Parse("0199a1b2-0000-7000-8000-000000000001");
    private static readonly Guid U2 = Guid.Parse("0199a1b2-0000-7000-8000-000000000002");
    private static readonly Guid A1 = Guid.Parse("0199a1b2-0000-7000-8000-0000000000a1");
    private static readonly Guid A2 = Guid.Parse("0199a1b2-0000-7000-8000-0000000000a2");
    private static readonly Guid A3 = Guid.Parse("0199a1b2-0000-7000-8000-0000000000a3");

    // T028 godoc literals, version 2 (T014, ADR-3: visibleProjectIds).
    private const string RequestLiteral = """
        {"users":[
          {"userId":"0199a1b2-0000-7000-8000-000000000001",
           "projectIds":["0199a1b2-0000-7000-8000-0000000000a1","0199a1b2-0000-7000-8000-0000000000a2"]},
          {"userId":"0199a1b2-0000-7000-8000-000000000002","allVisible":true}
        ]}
        """;

    private const string ResponseLiteral = """
        {"users":[
          {"userId":"0199a1b2-0000-7000-8000-000000000001","active":true,
           "internalAdmin":false,"external":false,
           "allowed":["0199a1b2-0000-7000-8000-0000000000a1"],
           "denied":["0199a1b2-0000-7000-8000-0000000000a2"]},
          {"userId":"0199a1b2-0000-7000-8000-000000000002","active":true,
           "internalAdmin":false,"external":false,
           "allowed":[],"denied":[],
           "visibleProjectIds":["0199a1b2-0000-7000-8000-0000000000a1","0199a1b2-0000-7000-8000-0000000000a3"]}
        ]}
        """;

    private static readonly ProjectAccessQuery[] LiteralQueries =
    [
        new(U1, ProjectIds: [A1, A2]),
        new(U2, AllVisible: true),
    ];

    [Fact]
    public async Task Request_IsTheT028Literal_PostedToTheServicePath()
    {
        var stub = new StubHandler(_ => Json(HttpStatusCode.OK, ResponseLiteral));
        using var sut = Sut.Create(stub);

        await sut.Client.CheckProjectAccessAsync(LiteralQueries, CancellationToken.None);

        var req = Assert.Single(stub.Requests);
        Assert.Equal(HttpMethod.Post, req.Method);
        Assert.Equal("/api/v1/hub/project-access", req.Path);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(RequestLiteral), JsonNode.Parse(req.Body)),
            $"request body differs from the T028 literal: {req.Body}");
    }

    [Fact]
    public async Task Request_CarriesOnlyTheServiceSecret_EvenWithAnAmbientAuthenticatedUser()
    {
        // An authenticated user is ambient (as inside a hub invocation); the
        // service call must still carry no identity of its own caller.
        var stub = new StubHandler(_ => Json(HttpStatusCode.OK, ResponseLiteral));
        using var sut = Sut.Create(stub);
        var accessor = sut.Services.GetRequiredService<IHttpContextAccessor>();
        accessor.HttpContext = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, U1.ToString()),
                new Claim(ClaimTypes.Email, "u1@example.test"),
                new Claim("username", "u1"),
                new Claim(ClaimTypes.Role, "admin"),
            ], authenticationType: "cookie")),
        };
        try
        {
            await sut.Client.CheckProjectAccessAsync(LiteralQueries, CancellationToken.None);

            var req = Assert.Single(stub.Requests);
            Assert.Equal(new[] { Secret }, req.Headers[SkeinHeaders.InternalSecret]);
            var skeinHeaders = req.Headers.Keys
                .Where(h => h.StartsWith("X-Skein-", StringComparison.OrdinalIgnoreCase))
                .ToArray();
            Assert.Equal(new[] { SkeinHeaders.InternalSecret }, skeinHeaders);
        }
        finally
        {
            accessor.HttpContext = null;
        }
    }

    [Fact]
    public async Task Response_TheT028Literal_IsReturnedPerQueryInOrder()
    {
        var stub = new StubHandler(_ => Json(HttpStatusCode.OK, ResponseLiteral));
        using var sut = Sut.Create(stub);

        var results = await sut.Client.CheckProjectAccessAsync(LiteralQueries, CancellationToken.None);

        Assert.Equal(2, results.Count);

        Assert.Equal(U1, results[0].UserId);
        Assert.True(results[0].Active);
        Assert.False(results[0].InternalAdmin);
        Assert.False(results[0].External);
        Assert.Equal(new[] { A1 }, results[0].Allowed);
        Assert.Equal(new[] { A2 }, results[0].Denied);
        Assert.Null(results[0].VisibleProjectIds); // absent: allVisible not asked

        Assert.Equal(U2, results[1].UserId);
        Assert.Empty(results[1].Allowed);
        Assert.Empty(results[1].Denied);
        Assert.Equal(new[] { A1, A3 }, results[1].VisibleProjectIds);
    }

    [Fact]
    public async Task Response_InactiveUserAskingAllVisible_GetsEmptyNotAbsentVisibleList()
    {
        // T028 v2: inactive/unknown user → active:false, every requested project
        // denied, visibleProjectIds [] when allVisible was asked.
        const string body = """
            {"users":[{"userId":"0199a1b2-0000-7000-8000-000000000001","active":false,
              "internalAdmin":false,"external":false,"allowed":[],
              "denied":["0199a1b2-0000-7000-8000-0000000000a1"],"visibleProjectIds":[]}]}
            """;
        var stub = new StubHandler(_ => Json(HttpStatusCode.OK, body));
        using var sut = Sut.Create(stub);

        var results = await sut.Client.CheckProjectAccessAsync(
            [new ProjectAccessQuery(U1, ProjectIds: [A1], AllVisible: true)], CancellationToken.None);

        var r = Assert.Single(results);
        Assert.False(r.Active);
        Assert.Equal(new[] { A1 }, r.Denied);
        Assert.NotNull(r.VisibleProjectIds);
        Assert.Empty(r.VisibleProjectIds!);
    }

    [Theory]
    // T014 / ADR-3: visibleProjectIds is present for EVERY user whenever
    // allVisible was asked. A version-1 answer — memberProjectIds for an
    // ordinary user, or the bare internalAdmin flag for an admin — is refused,
    // never read as "every project".
    [InlineData("""{"users":[{"userId":"0199a1b2-0000-7000-8000-000000000001","active":true,"internalAdmin":false,"external":false,"allowed":[],"denied":[],"memberProjectIds":["0199a1b2-0000-7000-8000-0000000000a1"]}]}""")]
    [InlineData("""{"users":[{"userId":"0199a1b2-0000-7000-8000-000000000001","active":true,"internalAdmin":true,"external":false,"allowed":[],"denied":[]}]}""")]
    public async Task Ok_AllVisibleAskedWithoutVisibleProjectIds_IsAContractViolation(string body)
    {
        var stub = new StubHandler(_ => Json(HttpStatusCode.OK, body));
        using var sut = Sut.Create(stub);

        var ex = await Assert.ThrowsAsync<HttpRequestException>(
            () => sut.Client.CheckProjectAccessAsync([new ProjectAccessQuery(U1, AllVisible: true)], CancellationToken.None));

        Assert.Null(ex.StatusCode);
    }

    [Theory]
    // 1 attempt + 3 retries (plan T031: "Polly 3 retries").
    [InlineData(HttpStatusCode.InternalServerError, 4)]
    [InlineData(HttpStatusCode.ServiceUnavailable, 4)]
    [InlineData(HttpStatusCode.Unauthorized, 1)]
    public async Task Failure_ThrowsWithStatus_AfterTheRetryPolicy_WithoutLeakingTheSecret(
        HttpStatusCode status, int expectedAttempts)
    {
        var stub = new StubHandler(_ => Json(status, """{"error":"x"}"""));
        using var sut = Sut.Create(stub);

        var ex = await Assert.ThrowsAsync<HttpRequestException>(
            () => sut.Client.CheckProjectAccessAsync(LiteralQueries, CancellationToken.None));

        Assert.Equal(status, ex.StatusCode);
        Assert.Equal(expectedAttempts, stub.Requests.Count);
        Assert.DoesNotContain(Secret, ex.ToString(), StringComparison.Ordinal);
        AssertSecretNeverLogged(sut.Logs);
    }

    [Fact]
    public async Task Success_HttpClientLogging_RedactsTheSecretHeader()
    {
        var stub = new StubHandler(_ => Json(HttpStatusCode.OK, ResponseLiteral));
        using var sut = Sut.Create(stub);

        await sut.Client.CheckProjectAccessAsync(LiteralQueries, CancellationToken.None);

        AssertSecretNeverLogged(sut.Logs);
    }

    [Theory]
    [InlineData("")]
    [InlineData("null")]
    [InlineData("{}")]
    [InlineData("""{"users":null}""")]
    [InlineData("not json")]
    public async Task Ok_WithoutAUsersBody_IsAContractViolation(string body)
    {
        var stub = new StubHandler(_ => Json(HttpStatusCode.OK, body));
        using var sut = Sut.Create(stub);

        var ex = await Assert.ThrowsAsync<HttpRequestException>(
            () => sut.Client.CheckProjectAccessAsync(LiteralQueries, CancellationToken.None));

        Assert.Null(ex.StatusCode);
        Assert.Single(stub.Requests);
    }

    [Theory]
    [InlineData("""{"users":[]}""")]
    [InlineData("""{"users":[{"userId":"0199a1b2-0000-7000-8000-000000000001","active":true,"internalAdmin":false,"external":false,"allowed":[],"denied":[]}]}""")]
    public async Task Ok_WithAResultCountOtherThanTheBatch_IsAContractViolation(string body)
    {
        var stub = new StubHandler(_ => Json(HttpStatusCode.OK, body));
        using var sut = Sut.Create(stub);

        var ex = await Assert.ThrowsAsync<HttpRequestException>(
            () => sut.Client.CheckProjectAccessAsync(LiteralQueries, CancellationToken.None));

        Assert.Null(ex.StatusCode);
    }

    [Theory]
    // T028: allowed and denied are "Always present; [] when none".
    [InlineData("""{"users":[{"userId":"0199a1b2-0000-7000-8000-000000000001","active":true,"internalAdmin":false,"external":false,"allowed":null,"denied":[]}]}""")]
    [InlineData("""{"users":[{"userId":"0199a1b2-0000-7000-8000-000000000001","active":true,"internalAdmin":false,"external":false,"allowed":[],"denied":null}]}""")]
    [InlineData("""{"users":[{"userId":"0199a1b2-0000-7000-8000-000000000001","active":true,"internalAdmin":false,"external":false,"denied":[]}]}""")]
    [InlineData("""{"users":[{"userId":"0199a1b2-0000-7000-8000-000000000001","active":true,"internalAdmin":false,"external":false,"allowed":[]}]}""")]
    [InlineData("""{"users":[null]}""")]
    public async Task Ok_WithAResultLackingAllowedOrDenied_IsAContractViolation(string body)
    {
        var stub = new StubHandler(_ => Json(HttpStatusCode.OK, body));
        using var sut = Sut.Create(stub);

        var ex = await Assert.ThrowsAsync<HttpRequestException>(
            () => sut.Client.CheckProjectAccessAsync([new ProjectAccessQuery(U1, ProjectIds: [A1])], CancellationToken.None));

        Assert.Null(ex.StatusCode);
    }

    public enum Stall
    {
        Headers,
        OkBody,
        ErrorBody,
    }

    [Theory]
    [InlineData(Stall.Headers)]
    [InlineData(Stall.OkBody)]
    [InlineData(Stall.ErrorBody)]
    public async Task StalledResponse_FailsWithTimeout_AtTheFifteenSecondBudget_WithoutCallerCancellation(Stall stall)
    {
        var stalled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var stub = new StubHandler(async (_, token) =>
        {
            if (stall == Stall.Headers)
            {
                stalled.TrySetResult();
                await Task.Delay(Timeout.Infinite, token);
            }
            var status = stall == Stall.ErrorBody ? HttpStatusCode.Unauthorized : HttpStatusCode.OK;
            return new HttpResponseMessage(status) { Content = new StreamContent(new StalledStream(stalled)) };
        });
        using var sut = Sut.Create(stub);

        var call = sut.Client.CheckProjectAccessAsync(LiteralQueries, CancellationToken.None);
        // Hang guard only: the stub reports the moment the response stalls.
        await stalled.Task.WaitAsync(TimeSpan.FromSeconds(30));

        sut.Clock.Advance(TimeSpan.FromSeconds(15) - TimeSpan.FromTicks(1));
        Assert.False(call.IsCompleted);

        sut.Clock.Advance(TimeSpan.FromTicks(1));
        // Hang guard only: without the budget the call would never complete.
        Assert.Same(call, await Task.WhenAny(call, Task.Delay(TimeSpan.FromSeconds(30))));
        var ex = await Assert.ThrowsAsync<TimeoutException>(() => call);
        Assert.DoesNotContain(Secret, ex.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task CallerCancellation_SurfacesAsCancellation_NotTimeout()
    {
        var stalled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var stub = new StubHandler((_, _) => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new StalledStream(stalled)) }));
        using var sut = Sut.Create(stub);
        using var caller = new CancellationTokenSource();

        var call = sut.Client.CheckProjectAccessAsync(LiteralQueries, caller.Token);
        await stalled.Task.WaitAsync(TimeSpan.FromSeconds(30));
        caller.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => call);
    }

    [Fact]
    public async Task EmptyBatch_MakesNoCall()
    {
        var stub = new StubHandler(_ => Json(HttpStatusCode.OK, """{"users":[]}"""));
        using var sut = Sut.Create(stub);

        var results = await sut.Client.CheckProjectAccessAsync([], CancellationToken.None);

        Assert.Empty(results);
        Assert.Empty(stub.Requests);
    }

    private static void AssertSecretNeverLogged(IReadOnlyCollection<string> logs)
    {
        // HttpClient logging writes request headers at Trace: the secret
        // header must appear by name (logging is on) but never by value.
        Assert.Contains(logs, line => line.Contains(SkeinHeaders.InternalSecret, StringComparison.Ordinal));
        Assert.All(logs, line => Assert.DoesNotContain(Secret, line, StringComparison.Ordinal));
    }

    /// <summary>The client resolved from the production registration, plus its observation points.</summary>
    private sealed class Sut : IDisposable
    {
        private Sut(ServiceProvider services, FakeTimeProvider clock, CapturingLoggerProvider logs)
        {
            Services = services;
            Clock = clock;
            LogProvider = logs;
            Client = services.GetRequiredService<SkeinServiceApiClient>();
        }

        public ServiceProvider Services { get; }
        public FakeTimeProvider Clock { get; }
        public SkeinServiceApiClient Client { get; }
        private CapturingLoggerProvider LogProvider { get; }
        public IReadOnlyCollection<string> Logs => LogProvider.Lines.ToArray();

        public static Sut Create(HttpMessageHandler transport)
        {
            var clock = new FakeTimeProvider(new DateTimeOffset(2026, 10, 9, 10, 0, 0, TimeSpan.Zero));
            var logs = new CapturingLoggerProvider();
            var services = new ServiceCollection();
            services.AddLogging(b => b.SetMinimumLevel(LogLevel.Trace).AddProvider(logs));
            services.AddSingleton<TimeProvider>(clock);
            services.Configure<SkeinApiOptions>(o =>
            {
                o.Url = "http://skein-api.test/";
                o.InternalSecret = Secret;
            });
            // What Program.cs has in the same container: the ambient-user
            // accessor and the identity-forwarding handler.
            services.AddHttpContextAccessor();
            services.AddTransient<InternalApiHandler>();
            services.AddSkeinServiceApiClient("http://skein-api.test/")
                .ConfigurePrimaryHttpMessageHandler(() => transport);
            return new Sut(services.BuildServiceProvider(), clock, logs);
        }

        public void Dispose() => Services.Dispose();
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private sealed record CapturedRequest(
        HttpMethod Method, string Path, string Body, IReadOnlyDictionary<string, string[]> Headers);

    /// <summary>Transport stub: records every request (headers + body) and answers with a canned response.</summary>
    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _respond;

        public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
            : this((r, _) => Task.FromResult(respond(r)))
        {
        }

        public StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) =>
            _respond = respond;

        public List<CapturedRequest> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
            var headers = request.Headers
                .Concat(request.Content?.Headers ?? Enumerable.Empty<KeyValuePair<string, IEnumerable<string>>>())
                .ToDictionary(h => h.Key, h => h.Value.ToArray(), StringComparer.OrdinalIgnoreCase);
            Requests.Add(new CapturedRequest(request.Method, request.RequestUri!.PathAndQuery, body, headers));
            return await _respond(request, cancellationToken);
        }
    }

    /// <summary>Response body that never yields a byte: each read reports the stall and waits for cancellation.</summary>
    private sealed class StalledStream(TaskCompletionSource stalled) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            stalled.TrySetResult();
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return 0;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>Logger provider recording every message of every category with its structured state values.</summary>
    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public System.Collections.Concurrent.ConcurrentQueue<string> Lines { get; } = new();

        public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);

        public void Dispose() { }

        private sealed class Logger(CapturingLoggerProvider owner, string category) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                var values = state is IEnumerable<KeyValuePair<string, object?>> kv
                    ? string.Join(";", kv.Select(p => $"{p.Key}={p.Value}"))
                    : "";
                owner.Lines.Enqueue($"{category} | {formatter(state, exception)} | {values} | {exception}");
            }
        }
    }
}
