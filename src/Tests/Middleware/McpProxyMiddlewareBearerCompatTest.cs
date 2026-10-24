using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SkeinWeb.Auth;
using SkeinWeb.Middleware;

namespace SkeinWeb.Tests.Middleware;

/// <summary>
/// sk-304 stage 2 — the Bearer compatibility mode on the public boundary.
///
/// Stage 1 (RFC 9728 metadata + <c>WWW-Authenticate</c>) shipped and did not
/// cure the disease: a headless MCP client, told correctly where to get a
/// token, walks off to Keycloak for one it cannot obtain without a browser and
/// never tries its static key. Measured: <c>X-Skein-Api-Key</c>
/// → 200, the SAME key as <c>Authorization: Bearer</c> → 401, because this
/// middleware dropped the header before skein-api could see it.
///
/// These tests pin the translation and, just as importantly, everything the
/// translation must NOT loosen.
/// </summary>
public class McpProxyMiddlewareBearerCompatTest
{
    private const string UpstreamBase = "http://skein-api.test";
    private const string Key = "ska_aaaaaaaaaaaaaaaaaaaaaa";
    private const string OtherKey = "ska_bbbbbbbbbbbbbbbbbbbbbb";

    private sealed class ScriptedHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;

        public ScriptedHandler(HttpStatusCode status) => _status = status;

        public HttpRequestMessage? Captured { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Captured = request;
            var resp = new HttpResponseMessage(_status)
            {
                Content = new StringContent("{\"jsonrpc\":\"2.0\"}"),
            };
            resp.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            return Task.FromResult(resp);
        }
    }

    private sealed class StubHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;
        public StubHttpClientFactory(HttpMessageHandler handler) => _handler = handler;
        public HttpClient CreateClient(string name) =>
            new(_handler, disposeHandler: false) { BaseAddress = new Uri(UpstreamBase) };
    }

    /// <summary>Records every formatted log line so the audit claim can be asserted.</summary>
    private sealed class RecordingLogger : ILogger<McpProxyMiddleware>
    {
        public List<(LogLevel Level, string Message)> Lines { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
            => Lines.Add((logLevel, formatter(state, exception)));
    }

    private static (McpProxyMiddleware mw, ScriptedHandler handler, RecordingLogger log) Build(
        HttpStatusCode status = HttpStatusCode.OK)
    {
        var handler = new ScriptedHandler(status);
        var log = new RecordingLogger();
        var mw = new McpProxyMiddleware(
            new StubHttpClientFactory(handler),
            Options.Create(new SkeinApiOptions
            {
                Url = UpstreamBase,
                InternalSecret = "s",
            }),
            TimeProvider.System,
            log);
        return (mw, handler, log);
    }

    private static DefaultHttpContext Request(string method, string path)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = method;
        ctx.Request.Path = path;
        ctx.Request.Host = new HostString("skein-mcp.test");
        ctx.Request.Body = new MemoryStream();
        ctx.Request.ContentLength = 0;
        ctx.Response.Body = new MemoryStream();
        return ctx;
    }

    private static string ReadBody(HttpContext ctx)
    {
        ctx.Response.Body.Position = 0;
        return new StreamReader(ctx.Response.Body, Encoding.UTF8).ReadToEnd();
    }

    private static string? ForwardedApiKey(HttpRequestMessage upstream) =>
        upstream.Headers.TryGetValues(SkeinHeaders.ApiKey, out var v)
            ? string.Join(",", v)
            : null;

    private static void AssertAuthorizationNeverForwarded(HttpRequestMessage upstream)
    {
        Assert.False(
            upstream.Headers.TryGetValues("Authorization", out var auth),
            $"Authorization reached skein-api: {string.Join(",", auth ?? Array.Empty<string>())}. "
            + "Compatibility mode COPIES an ska_ key into X-Skein-Api-Key; it does not relax "
            + "the strip. skein-api has no token validator, so forwarding a bearer token there "
            + "is the token-passthrough the MCP security guidance forbids.");
    }

    // ---------------------------------------------------------------- 1. translate

    [Fact]
    public async Task BearerSkeinKey_IsTranslatedIntoTheInternalApiKeyHeader()
    {
        var (mw, handler, _) = Build();
        var ctx = Request(HttpMethods.Post, "/mcp");
        ctx.Request.Headers["Authorization"] = $"Bearer {Key}";

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.NotNull(handler.Captured);
        Assert.Equal(Key, ForwardedApiKey(handler.Captured!));
        AssertAuthorizationNeverForwarded(handler.Captured!);
        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
    }

    /// <summary>
    /// RFC 9110 §11.1: "Authentication scheme names are case-insensitive."
    /// A client spelling the scheme <c>bearer</c> must not be quietly
    /// unauthenticated — that is a variant of the very bug sk-304 is about.
    /// </summary>
    [Theory]
    [InlineData("Bearer")]
    [InlineData("bearer")]
    [InlineData("BEARER")]
    [InlineData("BeArEr")]
    public async Task BearerScheme_IsMatchedCaseInsensitively(string scheme)
    {
        var (mw, handler, _) = Build();
        var ctx = Request(HttpMethods.Post, "/mcp");
        ctx.Request.Headers["Authorization"] = $"{scheme} {Key}";

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.NotNull(handler.Captured);
        Assert.Equal(Key, ForwardedApiKey(handler.Captured!));
        AssertAuthorizationNeverForwarded(handler.Captured!);
    }

    // ------------------------------------------------------------- 2. do not translate

    /// <summary>
    /// Anything that is not a Skein key stays untranslated. This is the future
    /// OAuth branch: when R5.1 mints real Keycloak tokens they must reach a
    /// validator that checks issuer, signature, expiry and audience — not get
    /// swallowed by the api-key path because both happen to be "bearer".
    /// </summary>
    [Theory]
    [InlineData("Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig")] // Keycloak JWT
    [InlineData("Basic c2thXzEyMzQ1Njc4OTA=")]                                      // wrong scheme
    [InlineData("BearerX ska_aaaaaaaaaaaaaaaaaaaaaa")]                              // scheme name is not "Bearer"
    [InlineData("Bearer\tska_aaaaaaaaaaaaaaaaaaaaaa")]                              // 1*SP required after the scheme
    [InlineData("Bearer ska_short")]                                                // too short to be a key
    [InlineData("Bearer SKA_Ab3xY7qKlmNoPqRsTuVwXy")]                               // tag is case-sensitive
    [InlineData("Bearer")]                                                          // no credential at all
    public async Task NonSkeinAuthorization_IsNeitherTranslatedNorForwarded(string authorization)
    {
        var (mw, handler, _) = Build();
        var ctx = Request(HttpMethods.Post, "/mcp");
        ctx.Request.Headers["Authorization"] = authorization;

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.NotNull(handler.Captured);
        Assert.Null(ForwardedApiKey(handler.Captured!));
        AssertAuthorizationNeverForwarded(handler.Captured!);
        // Upstream still gets the request and answers the 401 with the RFC 9728
        // challenge — the stage-1 behaviour is untouched.
        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
    }

    // ------------------------------------------------------------------ 3. both headers

    /// <summary>
    /// The shape of the workaround sk-304 documented in
    /// <c>~/.grok/config.toml</c>: the same key in both headers. It worked
    /// before this change and must keep working after it — silently breaking
    /// the one configuration people are running today would be a regression
    /// dressed as a fix.
    /// </summary>
    [Fact]
    public async Task BothHeaders_SameValue_AreProxied()
    {
        var (mw, handler, _) = Build();
        var ctx = Request(HttpMethods.Post, "/mcp");
        ctx.Request.Headers["Authorization"] = $"Bearer {Key}";
        ctx.Request.Headers[SkeinHeaders.ApiKey] = Key;

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.NotNull(handler.Captured);
        Assert.Equal(Key, ForwardedApiKey(handler.Captured!));
        AssertAuthorizationNeverForwarded(handler.Captured!);
        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
    }

    /// <summary>
    /// Two different credentials in one request is refused, not resolved.
    /// RFC 6750 §2: "Clients MUST NOT use more than one method to transmit the
    /// token in each request"; §3.1 puts that under <c>invalid_request</c> with
    /// "The resource server SHOULD respond with the HTTP 400 (Bad Request)
    /// status code". Picking one silently would put an identity in the audit
    /// trail that nobody can afterwards prove was the intended one.
    /// </summary>
    [Fact]
    public async Task BothHeaders_DifferentValues_AreRefusedWithoutReachingUpstream()
    {
        var (mw, handler, _) = Build();
        var ctx = Request(HttpMethods.Post, "/mcp");
        ctx.Request.Headers["Authorization"] = $"Bearer {Key}";
        ctx.Request.Headers[SkeinHeaders.ApiKey] = OtherKey;

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(StatusCodes.Status400BadRequest, ctx.Response.StatusCode);
        Assert.Null(handler.Captured); // never dispatched — no ambiguous identity upstream

        var challenge = ctx.Response.Headers["WWW-Authenticate"].ToString();
        Assert.StartsWith("Bearer ", challenge);
        Assert.Contains("error=\"invalid_request\"", challenge);

        var body = ReadBody(ctx);
        Assert.Contains("\"invalid_request\"", body);
        // The refusal must not become a place where credentials leak out again.
        Assert.DoesNotContain(Key, body);
        Assert.DoesNotContain(OtherKey, body);
        Assert.DoesNotContain(Key, challenge);
        Assert.DoesNotContain(OtherKey, challenge);
    }

    /// <summary>
    /// <c>Authorization</c> is a singleton field (RFC 9110 §5.5); a repeated one
    /// has no defined meaning, so we refuse rather than pick a line. Gated on at
    /// least one repeat being a Skein key, so traffic that never enters
    /// compatibility mode gains no new failure mode — the companion case is
    /// pinned by <see cref="RepeatedForeignAuthorization_IsStillJustStripped"/>.
    /// </summary>
    [Fact]
    public async Task RepeatedAuthorization_WithSkeinKey_IsRefused()
    {
        var (mw, handler, _) = Build();
        var ctx = Request(HttpMethods.Post, "/mcp");
        ctx.Request.Headers["Authorization"] = new[] { $"Bearer {Key}", $"Bearer {OtherKey}" };

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(StatusCodes.Status400BadRequest, ctx.Response.StatusCode);
        Assert.Null(handler.Captured);
    }

    [Fact]
    public async Task RepeatedForeignAuthorization_IsStillJustStripped()
    {
        var (mw, handler, _) = Build();
        var ctx = Request(HttpMethods.Post, "/mcp");
        ctx.Request.Headers["Authorization"] = new[] { "Bearer aaa.bbb.ccc", "Bearer ddd.eee.fff" };
        ctx.Request.Headers[SkeinHeaders.ApiKey] = Key;

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
        Assert.NotNull(handler.Captured);
        Assert.Equal(Key, ForwardedApiKey(handler.Captured!));
        AssertAuthorizationNeverForwarded(handler.Captured!);
    }

    // ------------------------------------------------------------ 4. nothing weakened

    /// <summary>
    /// The Cookie strip is orthogonal to credentials and must survive the new
    /// code path — a browser session cookie has no consumer on /mcp and
    /// forwarding it is pure attack surface. Asserted here as well as in
    /// <c>McpProxyMiddlewareMetadataTest</c> because compatibility mode is a new
    /// route through the same forwarding loop.
    /// </summary>
    [Fact]
    public async Task CompatibilityMode_StillStripsCookie()
    {
        var (mw, handler, _) = Build();
        var ctx = Request(HttpMethods.Post, "/mcp");
        ctx.Request.Headers["Authorization"] = $"Bearer {Key}";
        ctx.Request.Headers["Cookie"] = ".AspNetCore.Cookies=a-session-that-must-not-travel";

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.NotNull(handler.Captured);
        Assert.False(
            handler.Captured!.Headers.TryGetValues("Cookie", out var cookie),
            $"Cookie was forwarded upstream: {string.Join(",", cookie ?? Array.Empty<string>())}");
        Assert.Equal(Key, ForwardedApiKey(handler.Captured!));
    }

    /// <summary>
    /// The protected-resource metadata documents are public and take no
    /// credentials. Enforcing a credential contract on them would mean a client
    /// with a misconfigured header could not even READ the document that tells
    /// it how to authenticate — the exact dead end sk-304 is about. So they are
    /// classified for the log but never translated and never refused.
    /// </summary>
    [Theory]
    [InlineData("/.well-known/oauth-protected-resource")]
    [InlineData("/.well-known/oauth-protected-resource/mcp")]
    public async Task MetadataPaths_AreNotCredentialGated(string path)
    {
        var (mw, handler, _) = Build();
        var ctx = Request(HttpMethods.Get, path);
        ctx.Request.Headers["Authorization"] = $"Bearer {Key}";
        ctx.Request.Headers[SkeinHeaders.ApiKey] = OtherKey; // would be a conflict on /mcp

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
        Assert.NotNull(handler.Captured);
        AssertAuthorizationNeverForwarded(handler.Captured!);
    }

    // ------------------------------------------------------------------- 5. audit log

    /// <summary>
    /// The audit requirement of sk-304 stage 2: the journal must show WHICH
    /// transport carried the credential — and must never show the credential.
    /// </summary>
    [Fact]
    public async Task AccessLog_RecordsTheTransport_AndNeverTheKey()
    {
        var (mw, _, log) = Build();
        var ctx = Request(HttpMethods.Post, "/mcp");
        ctx.Request.Headers["Authorization"] = $"Bearer {Key}";

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        var line = Assert.Single(log.Lines, l => l.Message.Contains("mcp proxy request")).Message;
        Assert.Contains(nameof(McpCredentialTransport.BearerCompatibility), line);
        Assert.Contains("path=/mcp", line);
        Assert.Contains("nativeHdr=False", line);
        Assert.Contains("authzHdr=True", line);
        Assert.Contains("status=200", line);
        Assert.DoesNotContain(Key, line);
        Assert.DoesNotContain(Key[4..], line); // not even the random half of it

        // sk-304 stage-2 review (grok security): the field NAMES must stay clear of
        // the org secret-sanitiser denylist. Every argument on this line is a bool
        // or an enum, so the sanitiser would protect nothing — it would just blank
        // the presence facts and leave "***" where the evidence should be. Pinned
        // here so a well-meaning rename back to apiKeyHeader / authorizationHeader
        // goes red instead of silently emptying the log in production.
        foreach (var needle in new[]
                 {
                     "password", "token", "secret", "key",
                     "credential", "authorization", "apikey", "api_key",
                 })
        {
            Assert.DoesNotContain(needle, line, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task AccessLog_MarksTheUnauthenticatedProbe()
    {
        // The discovery probe: no credential at all. This is the request whose
        // absence from the journals made sk-304 undiagnosable.
        var (mw, _, log) = Build(HttpStatusCode.Unauthorized);
        var ctx = Request(HttpMethods.Post, "/mcp");

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        var entry = Assert.Single(log.Lines, l => l.Message.Contains("mcp proxy request"));
        Assert.Equal(LogLevel.Information, entry.Level);
        Assert.Contains(nameof(McpCredentialTransport.None), entry.Message);
        Assert.Contains("status=401", entry.Message);
    }

    [Fact]
    public async Task AccessLog_WarnsOnCredentialConflict()
    {
        var (mw, _, log) = Build();
        var ctx = Request(HttpMethods.Post, "/mcp");
        ctx.Request.Headers["Authorization"] = $"Bearer {Key}";
        ctx.Request.Headers[SkeinHeaders.ApiKey] = OtherKey;

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        var entry = Assert.Single(log.Lines, l => l.Message.Contains("mcp proxy request"));
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains(nameof(McpCredentialTransport.Conflict), entry.Message);
        Assert.DoesNotContain(Key, entry.Message);
        Assert.DoesNotContain(OtherKey, entry.Message);
    }

    /// <summary>
    /// Steady-state traffic (a session already open, native header) stays at
    /// Debug so production journals are not flooded with one line per tool call.
    /// </summary>
    [Fact]
    public async Task AccessLog_IsDebugForSteadyStateTraffic()
    {
        var (mw, _, log) = Build();
        var ctx = Request(HttpMethods.Post, "/mcp");
        ctx.Request.Headers[SkeinHeaders.ApiKey] = Key;
        ctx.Request.Headers[SkeinHeaders.McpSessionId] = "mcp-session-1";

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        var entry = Assert.Single(log.Lines, l => l.Message.Contains("mcp proxy request"));
        Assert.Equal(LogLevel.Debug, entry.Level);
        Assert.Contains(nameof(McpCredentialTransport.ApiKeyHeader), entry.Message);
    }

    /// <summary>A dropped foreign bearer is logged, not swallowed in silence.</summary>
    [Fact]
    public async Task AccessLog_ReportsADroppedForeignBearer()
    {
        var (mw, _, log) = Build();
        var ctx = Request(HttpMethods.Post, "/mcp");
        ctx.Request.Headers["Authorization"] = "Bearer eyJhbGciOiJSUzI1NiJ9.e30.sig";
        ctx.Request.Headers[SkeinHeaders.ApiKey] = Key;
        ctx.Request.Headers[SkeinHeaders.McpSessionId] = "mcp-session-1";

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        var entry = Assert.Single(log.Lines, l => l.Message.Contains("mcp proxy request"));
        Assert.Equal(LogLevel.Information, entry.Level);
        Assert.Contains(nameof(McpCredentialTransport.ForeignBearerIgnored), entry.Message);
    }

    // Guards the constants against drift from skein-api's internal/auth/apikey.go.
    [Fact]
    public void KeyShapeRecognition_MirrorsSkeinApi()
    {
        Assert.True(McpBearerCompatibility.LooksLikeSkeinApiKey(Key));
        Assert.True(McpBearerCompatibility.LooksLikeSkeinApiKey("ska_12345678"));   // len(tag)+8
        Assert.False(McpBearerCompatibility.LooksLikeSkeinApiKey("ska_1234567"));   // one short
        Assert.False(McpBearerCompatibility.LooksLikeSkeinApiKey("skm_12345678"));  // monitor door
        Assert.False(McpBearerCompatibility.LooksLikeSkeinApiKey(" ska_12345678")); // no leniency
        Assert.False(McpBearerCompatibility.LooksLikeSkeinApiKey(null));
    }
}
