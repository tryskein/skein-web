using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using Polly;
using Polly.Extensions.Http;

namespace SkeinWeb.Auth;

/// <summary>
/// Typed client wrapping <see cref="HttpClient"/> for skein-api auth
/// endpoints. Used by <c>AuthController</c>; the reverse-proxy path uses
/// the named "skein-api" client directly.
/// </summary>
/// <remarks>
/// The <see cref="HttpClient"/> registered for this typed client has
/// <see cref="InternalApiHandler"/> attached, so <c>X-Skein-Internal-Secret</c>
/// is added automatically. <c>X-Skein-User-*</c> headers are NOT added on
/// login because the user is not yet authenticated; on the post-login
/// flows (which we do not call from here) they would be.
/// </remarks>
public sealed class SkeinApiClient
{
    private readonly HttpClient _http;
    private readonly ILogger<SkeinApiClient> _logger;

    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    public SkeinApiClient(HttpClient http, ILogger<SkeinApiClient> logger)
    {
        _http = http;
        _logger = logger;
    }

    /// <summary>
    /// Verify credentials against skein-api and translate the response status
    /// into a <see cref="LoginResult"/> the controller can map per auth-mode
    /// (sk-163 S4b). Throws only on transport errors / unexpected 5xx so the
    /// controller can surface 502.
    /// </summary>
    /// <remarks>
    /// Status → outcome mapping (matches skein-api <c>handler/auth.go</c>, S4a):
    /// <list type="bullet">
    ///   <item><c>200</c> → <see cref="LoginOutcome.Success"/> with the user
    ///         (carries <c>isExternal</c> verbatim from the API row) and the
    ///         <c>sessionEpoch</c> of the authentication response, null when
    ///         absent (sk-674.18 K-16).</item>
    ///   <item><c>422</c> → <see cref="LoginOutcome.InvalidCredentials"/>. This
    ///         is the GENERIC invalid-credentials bucket: by S4a's
    ///         anti-enumeration design it also covers an internal account
    ///         attempting password login in hybrid mode (the API collapses
    ///         "wrong password" and "internal-account-not-allowed" into the
    ///         SAME 422 so account class never leaks). The body is NOT parsed
    ///         — its shape could otherwise reveal existence.</item>
    ///   <item><c>410</c> → <see cref="LoginOutcome.Disabled"/>. The standalone
    ///         password endpoint is retired for this deployment (keycloak mode,
    ///         non-break-glass email). The controller keeps today's 410 in pure
    ///         keycloak mode.</item>
    ///   <item><c>403</c> → <see cref="LoginOutcome.SsoRequired"/>. Defensive:
    ///         the committed S4a <c>/auth/login</c> does not currently emit 403,
    ///         but if a future revision distinguishes "must use SSO" from a
    ///         generic failure, the controller already routes it to the SSO
    ///         affordance instead of a 502.</item>
    ///   <item>anything else (4xx/5xx) → throw → controller turns into 502.</item>
    /// </list>
    /// </remarks>
    /// <param name="email">Email address (already lowercased by caller).</param>
    /// <param name="password">Plaintext password.</param>
    /// <param name="ct">Cancellation token tied to the inbound request.</param>
    public async Task<LoginResult> LoginAsync(string email, string password, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/login")
        {
            Content = JsonContent.Create(new { email, password }, options: JsonOpts),
        };

        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);

        if (resp.StatusCode == HttpStatusCode.OK)
        {
            var auth = await resp.Content.ReadFromJsonAsync<LoginResponse>(JsonOpts, ct);
            if (auth?.Id is null)
            {
                throw new HttpRequestException("skein-api returned 200 with empty body on login");
            }
            // sessionEpoch is passed on as answered — null when absent; the
            // controller refuses the login then (K-16, no fallback).
            return LoginResult.Success(
                new UserDto(auth.Id, auth.Email, auth.Username, auth.Name, auth.Role,
                    auth.CreatedAt, auth.LastLoginAt, auth.IsExternal),
                auth.SessionEpoch);
        }

        if (resp.StatusCode == HttpStatusCode.UnprocessableEntity)
        {
            // Business error — generic invalid credentials (also covers the
            // hybrid internal-account gate per S4a). Body intentionally not
            // parsed; we don't want to surface the API's exact message to
            // the BFF caller (it might leak existence info via shape).
            return LoginResult.InvalidCredentials;
        }

        if (resp.StatusCode == HttpStatusCode.Gone)
        {
            // Standalone login retired (keycloak mode, non-break-glass).
            return LoginResult.Disabled;
        }

        if (resp.StatusCode == HttpStatusCode.Forbidden)
        {
            // Account must sign in via SSO (defensive — see remarks).
            return LoginResult.SsoRequired;
        }

        // 4xx other than 422/410/403, or any 5xx — wrong shape, treat as
        // transport failure. Caller turns into 502.
        var body = await resp.Content.ReadAsStringAsync(ct);
        _logger.LogError(
            "skein-api login returned unexpected status {StatusCode}; body length={BodyLen}",
            (int)resp.StatusCode,
            body.Length);
        throw new HttpRequestException(
            $"skein-api login returned unexpected status {(int)resp.StatusCode}");
    }

    /// <summary>
    /// The current session's user as skein-api sees it —
    /// <c>GET /api/v1/auth/me</c>, with the session's identity and
    /// <c>X-Skein-Session-Epoch</c> (added by <see cref="InternalApiHandler"/>
    /// from the cookie principal of the ambient request).
    /// </summary>
    /// <remarks>
    /// 200 → the user; 401 <c>session_revoked</c> → <see cref="MeResult.Revoked"/>
    /// (sk-674.18 K-16: the caller ends the session); any other status or an
    /// unreadable 200 → <see cref="HttpRequestException"/>.
    /// </remarks>
    /// <param name="ct">Cancellation token tied to the inbound request.</param>
    public async Task<MeResult> MeAsync(CancellationToken ct)
    {
        using var resp = await _http.GetAsync("/api/v1/auth/me", HttpCompletionOption.ResponseHeadersRead, ct);
        if (resp.StatusCode == HttpStatusCode.OK)
        {
            var me = await resp.Content.ReadFromJsonAsync<LoginResponse>(JsonOpts, ct);
            if (me?.Id is null)
            {
                throw new HttpRequestException("skein-api /auth/me returned 200 without a user");
            }
            return new MeResult(
                new UserDto(me.Id, me.Email, me.Username, me.Name, me.Role, me.CreatedAt, me.LastLoginAt, me.IsExternal),
                Revoked: false);
        }
        if (resp.StatusCode == HttpStatusCode.Unauthorized &&
            SessionRevocation.IsRevokedBody(await resp.Content.ReadAsByteArrayAsync(ct)))
        {
            return new MeResult(null, Revoked: true);
        }
        _logger.LogError("skein-api /auth/me returned unexpected status {StatusCode}", (int)resp.StatusCode);
        throw new HttpRequestException(
            $"skein-api /auth/me returned unexpected status {(int)resp.StatusCode}", null, resp.StatusCode);
    }

    /// <summary>
    /// Provision (or refresh) an SSO user identity on skein-api after
    /// the BFF has read the trust headers forwarded by oauth2-proxy.
    /// Posts <c>{email, username, name}</c> to
    /// <c>POST /api/v1/auth/oidc/provision</c>
    /// (<c>X-Skein-Internal-Secret</c> is injected by
    /// <see cref="InternalApiHandler"/>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The Keycloak <c>sub</c> claim is NOT forwarded — oauth2-proxy in
    /// this cluster runs with <c>pass_access_token=false</c>, so backends
    /// never see the JWT. skein-api accepts an empty <c>sub</c> and uses
    /// email as the primary match/insert key (trust-headers org pattern).
    /// </para>
    /// <para>Backend contract:
    /// <list type="bullet">
    ///   <item>200 — the authentication response (<c>{id, email, username,
    ///         role, …, sessionEpoch}</c>). User existed
    ///         (UPDATE) or was created (INSERT). Returned <see cref="UserDto"/>
    ///         carries null timestamps; clients that need them must call
    ///         <c>/api/v1/auth/me</c> via the proxy.</item>
    ///   <item>403 <c>user_not_provisioned</c> — email unknown and
    ///         <c>SKEIN_AUTO_PROVISION=false</c>. Surface as a friendly
    ///         "Access denied" message to the user.</item>
    ///   <item>422 <c>missing_claims</c> — any of email/username/name
    ///         was empty in the request body.</item>
    ///   <item>409 <c>username_conflict</c> — every <c>john</c>,
    ///         <c>john2</c>, … colliding.</item>
    ///   <item>Anything else — transport failure; caller turns into 502.</item>
    /// </list></para>
    /// </remarks>
    /// <param name="email">Email from <c>X-Auth-Request-Email</c>.</param>
    /// <param name="username">Username from <c>X-Auth-Request-User</c>.</param>
    /// <param name="name">Inbound display name; typically <see cref="string.Empty"/>
    /// because oauth2-proxy does not forward a <c>name</c> claim. The
    /// backend COALESCEs an empty value to either the username (on
    /// INSERT) or the row's existing name (on UPDATE), then returns the
    /// post-COALESCE value in the response body for cookie binding.</param>
    /// <param name="ct">Cancellation token tied to the inbound request.</param>
    /// <returns>The user identity and the <c>sessionEpoch</c> of the
    /// authentication response (sk-674.18 K-16; <c>null</c> when skein-api
    /// omitted the REQUIRED field — the caller issues no session then).
    /// Never null on a 200 response.</returns>
    /// <exception cref="SsoProvisioningException">Carries the upstream
    /// error code on 403 / 422 / 409 business responses.</exception>
    /// <exception cref="HttpRequestException">Transport failure or
    /// unexpected status (e.g. 5xx).</exception>
    public async Task<AuthenticatedUser> OidcProvisionAsync(
        string email, string username, string name, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/oidc/provision")
        {
            // camelCase via JsonSerializerDefaults.Web — matches the
            // skein-api struct tags (email/username/name). `sub` is
            // intentionally omitted; the backend treats it as optional
            // and uses email as the match key (trust-headers pattern).
            Content = JsonContent.Create(
                new { email, username, name },
                options: JsonOpts),
        };

        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);

        if (resp.StatusCode == HttpStatusCode.OK)
        {
            // Backend returns {id, email, username, role}; createdAt /
            // lastLoginAt are NOT present.
            var body = await resp.Content.ReadFromJsonAsync<OidcProvisionResponse>(JsonOpts, ct);
            if (body is null || string.IsNullOrEmpty(body.Id))
            {
                throw new HttpRequestException("skein-api /auth/oidc/provision returned 200 with empty body");
            }
            var user = new UserDto(
                Id: body.Id,
                Email: body.Email ?? email,
                Username: body.Username ?? username,
                // Trust the post-COALESCE name from skein-api over the
                // caller-supplied value: we typically send `name=""` (no
                // header claim) and the backend returns either the
                // username fallback (INSERT) or the row's existing name
                // (UPDATE). Falling back to `username` if the backend
                // somehow returned an empty string keeps the cookie
                // principal's display name non-empty.
                Name: string.IsNullOrEmpty(body.Name) ? username : body.Name,
                Role: body.Role ?? "user",
                CreatedAt: null,
                LastLoginAt: null,
                // OIDC-provisioned users are internal by construction; the
                // backend still returns the flag explicitly (sk-163 S1) so
                // we carry whatever it says rather than hardcoding false.
                IsExternal: body.IsExternal);
            // sessionEpoch as answered (K-16): null when absent — the caller
            // issues no session then.
            return new AuthenticatedUser(user, body.SessionEpoch);
        }

        // Business errors carry a stable `error` code in the JSON body.
        if (resp.StatusCode == HttpStatusCode.Forbidden ||
            resp.StatusCode == HttpStatusCode.UnprocessableEntity ||
            resp.StatusCode == HttpStatusCode.Conflict)
        {
            var err = await TryReadErrorAsync(resp, ct);
            // err.Code is the machine-readable code (user_not_provisioned,
            // missing_claims, username_conflict). Empty when the body
            // didn't parse — middleware treats that as "user_not_provisioned"
            // for 403, "unknown" otherwise.
            throw new SsoProvisioningException(
                (int)resp.StatusCode,
                err.Code,
                err.Message ?? "skein-api rejected provisioning request");
        }

        var raw = await resp.Content.ReadAsStringAsync(ct);
        _logger.LogError(
            "skein-api /auth/oidc/provision returned unexpected status {StatusCode}; body length={BodyLen}",
            (int)resp.StatusCode,
            raw.Length);
        throw new HttpRequestException(
            $"skein-api /auth/oidc/provision returned unexpected status {(int)resp.StatusCode}");
    }

    private async Task<(string Code, string? Message)> TryReadErrorAsync(
        HttpResponseMessage resp, CancellationToken ct)
    {
        try
        {
            var body = await resp.Content.ReadFromJsonAsync<ErrorBody>(JsonOpts, ct);
            return (body?.Error ?? "", body?.Message);
        }
        catch (Exception ex)
        {
            // Body wasn't JSON or didn't match — treat as opaque error.
            // Log at debug so we can detect "we are losing error codes"
            // in post-incident analysis without flooding regular logs.
            _logger.LogDebug(ex, "skein-api: error body did not parse as JSON envelope");
            return ("", null);
        }
    }

    private sealed record OidcProvisionResponse(
        // Id typed as nullable string — System.Text.Json happily binds
        // `null` into a non-nullable record param without raising; the
        // explicit `?` keeps the type system honest about the actual
        // contract. The caller checks IsNullOrEmpty before use.
        [property: JsonPropertyName("id")] string? Id,
        [property: JsonPropertyName("email")] string? Email,
        [property: JsonPropertyName("username")] string? Username,
        // Name = post-COALESCE display name as stored in the DB. On
        // INSERT this is the username fallback; on UPDATE this is the
        // existing row's name (preserved when caller sent name=""). The
        // cookie principal's ClaimTypes.Name uses this, so an empty
        // body.Name would render a blank name in the UI on every login.
        [property: JsonPropertyName("name")] string? Name,
        [property: JsonPropertyName("role")] string? Role,
        // is_external (sk-163 S1). Absent in the JSON → System.Text.Json
        // binds default(bool) = false, which is the correct internal default.
        [property: JsonPropertyName("isExternal")] bool IsExternal,
        // sk-674.18 K-16: REQUIRED in the authentication response; nullable
        // so that an absent field stays distinguishable from epoch 0.
        [property: JsonPropertyName("sessionEpoch")] long? SessionEpoch);

    /// <summary>200 body of <c>POST /api/v1/auth/login</c> — skein-api
    /// <c>AuthResponse</c>; <c>sessionEpoch</c> nullable so absence is visible.</summary>
    private sealed record LoginResponse(
        string? Id,
        string Email,
        string Username,
        string Name,
        string Role,
        DateTimeOffset? CreatedAt,
        DateTimeOffset? LastLoginAt,
        bool IsExternal,
        long? SessionEpoch);

    private sealed record ErrorBody(
        [property: JsonPropertyName("error")] string? Error,
        [property: JsonPropertyName("message")] string? Message);
}

/// <summary>
/// Retry policy shared by the typed skein-api clients: transient transport
/// errors, 5xx and 408 are retried three times with exponential backoff
/// (200 ms, 400 ms, 800 ms) — small enough not to stall the caller, large
/// enough to absorb a single skein-api restart. 4xx other than 408 are not
/// retried: they are deterministic.
/// </summary>
public static class SkeinApiRetryPolicy
{
    /// <summary>Number of retries after the first attempt.</summary>
    public const int RetryCount = 3;

    /// <summary>Builds the policy; attach it with <c>AddPolicyHandler</c>.</summary>
    public static IAsyncPolicy<HttpResponseMessage> Create() =>
        HttpPolicyExtensions
            .HandleTransientHttpError()
            .OrResult(r => r.StatusCode == HttpStatusCode.RequestTimeout)
            .WaitAndRetryAsync(
                retryCount: RetryCount,
                sleepDurationProvider: attempt => TimeSpan.FromMilliseconds(200 * Math.Pow(2, attempt - 1)));
}

/// <summary>
/// Typed client for skein-api SERVICE endpoints — calls made by skein-web on
/// its own behalf, outside any user request: from hub methods and from
/// background loops. Authenticates with the service secret only.
/// </summary>
/// <remarks>
/// Deliberately separate from <see cref="SkeinApiClient"/>: that client's
/// pipeline carries <see cref="InternalApiHandler"/>, which forwards the
/// <c>X-Skein-User-*</c> identity of whatever <see cref="HttpContext"/> is
/// ambient. A service call must not depend on, or leak, an ambient user — so
/// this client has no <see cref="IHttpContextAccessor"/> in its dependency
/// graph and sets <c>X-Skein-Internal-Secret</c> itself on each request. The
/// secret is never written to a log or an exception message.
/// </remarks>
public sealed class SkeinServiceApiClient
{
    private const string ProjectAccessPath = "/api/v1/hub/project-access";

    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _http;
    private readonly string _internalSecret;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<SkeinServiceApiClient> _logger;

    /// <summary>
    /// Budget of one call, end to end: every attempt, the retry pauses and the
    /// response body read. Past it the call fails with
    /// <see cref="TimeoutException"/>.
    /// </summary>
    public static readonly TimeSpan CallBudget = TimeSpan.FromSeconds(15);

    /// <summary>
    /// Most queries one <see cref="CheckProjectAccessAsync"/> call may carry —
    /// the T028 batch budget (4,000 entries; skein-api answers a body past its
    /// 16 MiB cap with 400 as a whole). A caller with more splits them.
    /// </summary>
    public const int MaxQueriesPerCall = 4000;

    /// <summary>Creates the client over an <see cref="HttpClient"/> whose <c>BaseAddress</c> is skein-api.</summary>
    /// <param name="http">HTTP client, composed by <see cref="SkeinServiceApiClientRegistration.AddSkeinServiceApiClient"/>.</param>
    /// <param name="options">skein-api options; <see cref="SkeinApiOptions.InternalSecret"/> is the service secret.</param>
    /// <param name="timeProvider">Clock of <see cref="CallBudget"/>.</param>
    /// <param name="logger">Logger.</param>
    public SkeinServiceApiClient(
        HttpClient http,
        IOptions<SkeinApiOptions> options,
        TimeProvider timeProvider,
        ILogger<SkeinServiceApiClient> logger)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(logger);
        _http = http;
        _internalSecret = options.Value.InternalSecret;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    /// <summary>
    /// Checks, for many users in one call, which projects each user can see —
    /// <c>POST /api/v1/hub/project-access</c> (skein-api
    /// <c>internal/projects/access_contract.go</c>, T028).
    /// </summary>
    /// <remarks>
    /// <para>Used when a hub connection declares projects or the "all visible"
    /// mode, and by the periodic access re-check (K10). The role and the
    /// deactivation state are read by skein-api from the database on every
    /// call; whose access is checked is named in the body.</para>
    /// <para>Responses: 200 → one result per query, in query order; 400 (bad
    /// shape), 401 (bad service secret) and 5xx after
    /// <see cref="SkeinApiRetryPolicy.RetryCount"/> retries →
    /// <see cref="HttpRequestException"/> carrying the status code. An unknown
    /// user or project is not an error — it is answered inside the result
    /// (inactive user, project in <see cref="ProjectAccessResult.Denied"/>).</para>
    /// <para>A 200 body that breaks the T028 shape — empty, not JSON, without
    /// <c>users</c>, a result count other than the batch size, a null result,
    /// <c>allowed</c>/<c>denied</c> null or absent (T028: "Always present;
    /// <c>[]</c> when none"), or — version 2 (T014, ADR-3) —
    /// <c>visibleProjectIds</c> absent from the result of a query that asked
    /// <c>allVisible</c> — is a contract violation:
    /// <see cref="HttpRequestException"/> without a status code.</para>
    /// <para>The whole call is bounded by <see cref="CallBudget"/>.</para>
    /// </remarks>
    /// <param name="queries">The batch; an empty batch makes no call and returns an empty list.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Exactly one <see cref="ProjectAccessResult"/> per query, in query order.</returns>
    /// <exception cref="HttpRequestException">Non-200 status (with <see cref="HttpRequestException.StatusCode"/>), or a 200 body violating the T028 shape.</exception>
    /// <exception cref="TimeoutException">The call did not complete within <see cref="CallBudget"/>.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="ct"/> was cancelled.</exception>
    public async Task<IReadOnlyList<ProjectAccessResult>> CheckProjectAccessAsync(
        IReadOnlyList<ProjectAccessQuery> queries, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(queries);
        if (queries.Count > MaxQueriesPerCall)
        {
            throw new ArgumentException(
                $"at most {MaxQueriesPerCall} queries per call (T028 batch budget), got {queries.Count}",
                nameof(queries));
        }
        if (queries.Count == 0)
        {
            return [];
        }

        using var budget = new CancellationTokenSource(CallBudget, _timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, budget.Token);
        try
        {
            return await SendAndReadAsync(queries, linked.Token);
        }
        catch (OperationCanceledException ex) when (budget.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            _logger.LogError(
                "skein-api {Path} did not complete within {BudgetSeconds} s; users={Users}",
                ProjectAccessPath,
                CallBudget.TotalSeconds,
                queries.Count);
            throw new TimeoutException(
                $"skein-api {ProjectAccessPath} did not complete within {CallBudget.TotalSeconds} s", ex);
        }
    }

    /// <summary>
    /// Reads the installation settings — <c>GET /api/v1/internal/instance-config</c>
    /// (skein-api <c>internal/accounts/contract.go#InstanceConfig</c>, T012).
    /// </summary>
    /// <remarks>
    /// <para>Called on every <c>GET /api/auth/config</c> (plan K-14): skein-web
    /// keeps no copy of the behaviour flags, so a restart of skein-api alone with
    /// a new value shows up on the next call. Startup reads the same route once,
    /// through <see cref="InstanceConfigBootstrap"/>, before DI exists.</para>
    /// <para>Responses: 200 → the settings; 401 (bad service secret) and 5xx
    /// after <see cref="SkeinApiRetryPolicy.RetryCount"/> retries →
    /// <see cref="HttpRequestException"/> carrying the status code. A 200 body
    /// that breaks the contract — empty, not JSON, a key missing, or an
    /// <c>authMode</c> outside the three values — is
    /// <see cref="HttpRequestException"/> without a status code.</para>
    /// <para>The whole call is bounded by <see cref="CallBudget"/>.</para>
    /// </remarks>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The settings, with <see cref="InstanceConfig.HasKnownAuthMode"/> true.</returns>
    /// <exception cref="HttpRequestException">Non-200 status (with <see cref="HttpRequestException.StatusCode"/>), or a 200 body violating the contract.</exception>
    /// <exception cref="TimeoutException">The call did not complete within <see cref="CallBudget"/>.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="ct"/> was cancelled.</exception>
    public async Task<InstanceConfig> GetInstanceConfigAsync(CancellationToken ct)
    {
        using var budget = new CancellationTokenSource(CallBudget, _timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, budget.Token);
        try
        {
            return await ReadInstanceConfigAsync(linked.Token);
        }
        catch (OperationCanceledException ex) when (budget.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            _logger.LogError(
                "skein-api {Path} did not complete within {BudgetSeconds} s",
                InstanceConfigBootstrap.Path,
                CallBudget.TotalSeconds);
            throw new TimeoutException(
                $"skein-api {InstanceConfigBootstrap.Path} did not complete within {CallBudget.TotalSeconds} s", ex);
        }
    }

    private async Task<InstanceConfig> ReadInstanceConfigAsync(CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, InstanceConfigBootstrap.Path);
        req.Headers.TryAddWithoutValidation(SkeinHeaders.InternalSecret, _internalSecret);

        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        if (resp.StatusCode != HttpStatusCode.OK)
        {
            _logger.LogError(
                "skein-api {Path} returned {StatusCode}",
                InstanceConfigBootstrap.Path,
                (int)resp.StatusCode);
            throw new HttpRequestException(
                $"skein-api {InstanceConfigBootstrap.Path} returned status {(int)resp.StatusCode}",
                inner: null,
                statusCode: resp.StatusCode);
        }

        InstanceConfig? parsed;
        try
        {
            parsed = await resp.Content.ReadFromJsonAsync<InstanceConfig>(JsonOpts, ct);
        }
        catch (JsonException ex)
        {
            throw InstanceConfigViolation("returned 200 with a body that is not the InstanceConfig JSON", ex);
        }
        if (parsed is null)
        {
            throw InstanceConfigViolation("returned 200 with an empty body", null);
        }
        if (!parsed.HasKnownAuthMode)
        {
            throw InstanceConfigViolation($"returned authMode '{parsed.AuthMode}'", null);
        }
        return parsed;
    }

    private HttpRequestException InstanceConfigViolation(string what, Exception? inner)
    {
        _logger.LogError(inner, "skein-api {Path} contract violation: {What}", InstanceConfigBootstrap.Path, what);
        return new HttpRequestException(
            $"skein-api {InstanceConfigBootstrap.Path} {what} (T012 contract violation)", inner);
    }

    private async Task<IReadOnlyList<ProjectAccessResult>> SendAndReadAsync(
        IReadOnlyList<ProjectAccessQuery> queries, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, ProjectAccessPath)
        {
            Content = JsonContent.Create(new ProjectAccessRequest(queries), options: JsonOpts),
        };
        req.Headers.TryAddWithoutValidation(SkeinHeaders.InternalSecret, _internalSecret);

        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        if (resp.StatusCode != HttpStatusCode.OK)
        {
            var body = await resp.Content.ReadAsStringAsync(ct);
            _logger.LogError(
                "skein-api {Path} returned {StatusCode}; users={Users} body length={BodyLen}",
                ProjectAccessPath,
                (int)resp.StatusCode,
                queries.Count,
                body.Length);
            throw new HttpRequestException(
                $"skein-api {ProjectAccessPath} returned status {(int)resp.StatusCode}",
                inner: null,
                statusCode: resp.StatusCode);
        }

        ProjectAccessResponse? parsed;
        try
        {
            parsed = await resp.Content.ReadFromJsonAsync<ProjectAccessResponse>(JsonOpts, ct);
        }
        catch (JsonException ex)
        {
            throw ContractViolation("returned 200 with a body that is not the T028 JSON", ex);
        }
        if (parsed?.Users is null)
        {
            throw ContractViolation("returned 200 without users", null);
        }
        if (parsed.Users.Count != queries.Count)
        {
            throw ContractViolation($"returned {parsed.Users.Count} results for {queries.Count} queries", null);
        }
        for (var i = 0; i < parsed.Users.Count; i++)
        {
            var r = parsed.Users[i];
            if (r is null || r.Allowed is null || r.Denied is null)
            {
                throw ContractViolation($"result {i} lacks the always-present allowed/denied lists", null);
            }
            if (queries[i].AllVisible && r.VisibleProjectIds is null)
            {
                // Version 2 (T014, ADR-3): visibleProjectIds is present for every
                // user whenever allVisible was asked. Its absence is never read as
                // "everything" — a version-1 answer to the admin is refused.
                throw ContractViolation($"result {i} lacks visibleProjectIds although allVisible was asked", null);
            }
        }
        return parsed.Users;
    }

    private HttpRequestException ContractViolation(string what, Exception? inner)
    {
        var message = $"skein-api {ProjectAccessPath} {what} (T028 contract violation)";
        _logger.LogError(inner, "skein-api {Path} contract violation: {What}", ProjectAccessPath, what);
        return new HttpRequestException(message, inner);
    }
}

/// <summary>Body of <c>POST /api/v1/hub/project-access</c> (T028 <c>ProjectAccessRequest</c>).</summary>
/// <param name="Users">The batch to check.</param>
public sealed record ProjectAccessRequest(
    [property: JsonPropertyName("users")] IReadOnlyList<ProjectAccessQuery> Users);

/// <summary>One user's question (T028 <c>ProjectAccessQuery</c>).</summary>
/// <param name="UserId">The user whose access is checked.</param>
/// <param name="ProjectIds">Declared projects whose visibility is asked; omitted from the JSON when null.</param>
/// <param name="AllVisible">Asks for the "all projects visible to me" mode; omitted from the JSON when false.</param>
public sealed record ProjectAccessQuery(
    [property: JsonPropertyName("userId")] Guid UserId,
    [property: JsonPropertyName("projectIds"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    IReadOnlyList<Guid>? ProjectIds = null,
    [property: JsonPropertyName("allVisible"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    bool AllVisible = false);

/// <summary>200 body of <c>POST /api/v1/hub/project-access</c> (T028 <c>ProjectAccessResponse</c>).</summary>
/// <param name="Users">One result per query, in query order.</param>
public sealed record ProjectAccessResponse(
    [property: JsonPropertyName("users")] IReadOnlyList<ProjectAccessResult> Users);

/// <summary>
/// Answer for one <see cref="ProjectAccessQuery"/> — version 2 of T028
/// <c>ProjectAccessResult</c> (skein-api <c>internal/projects/access_contract.go</c>,
/// T014, ADR-3). Visibility follows the access relation: an inactive or unknown
/// user sees nothing; an external user sees only its memberships; nobody but the
/// owner sees a personal space's projects, the internal admin included.
/// </summary>
/// <param name="UserId">Echo of the query's user.</param>
/// <param name="Active">The user exists and is not deactivated (false for an unknown user too).</param>
/// <param name="InternalAdmin">Active, admin role and not external. Version 2: the role ONLY — no project is visible because of it; the hub derives no subscription from it (it keeps the user in <c>admins:internal</c>, which carries user events only).</param>
/// <param name="External">The user's external-collaborator flag.</param>
/// <param name="Allowed">Requested projects the user can see, in request order.</param>
/// <param name="Denied">Requested projects the user cannot see (or that do not exist), in request order.</param>
/// <param name="VisibleProjectIds">Every project the user can see: present exactly when <c>allVisible</c> was asked, for every user, the internal admin included (for the admin — every project outside other users' personal spaces, plus its own); <c>[]</c> for an inactive or unknown user; null when <c>allVisible</c> was not asked. Replaces version 1's <c>memberProjectIds</c>.</param>
public sealed record ProjectAccessResult(
    [property: JsonPropertyName("userId")] Guid UserId,
    [property: JsonPropertyName("active")] bool Active,
    [property: JsonPropertyName("internalAdmin")] bool InternalAdmin,
    [property: JsonPropertyName("external")] bool External,
    [property: JsonPropertyName("allowed")] IReadOnlyList<Guid> Allowed,
    [property: JsonPropertyName("denied")] IReadOnlyList<Guid> Denied,
    [property: JsonPropertyName("visibleProjectIds")] IReadOnlyList<Guid>? VisibleProjectIds = null);

/// <summary>Result of <see cref="SkeinApiClient.MeAsync"/>.</summary>
/// <param name="User">The user; non-null unless <paramref name="Revoked"/>.</param>
/// <param name="Revoked">skein-api answered 401 <c>session_revoked</c>.</param>
public sealed record MeResult(UserDto? User, bool Revoked);

/// <summary>
/// Raw answer of a public account route of skein-api: the status and the body
/// as text. <c>AccountController</c> maps it onto the browser contract
/// (<see cref="PublicAuthRoutes"/>) — success bodies per route, refusals
/// <c>{"error","message",…}</c> onto ProblemDetails.
/// </summary>
/// <param name="Status">HTTP status skein-api answered with.</param>
/// <param name="Body">Response body; empty for 204.</param>
public sealed record AccountApiResult(HttpStatusCode Status, string Body);

/// <summary>
/// Typed client of skein-api's public account routes
/// (<c>internal/accounts/contract.go</c>, T012) — the upstream of the BFF's
/// <see cref="PublicAuthRoutes"/> (plan K-17).
/// </summary>
/// <remarks>
/// <para>No identity: unlike <see cref="SkeinApiClient"/> this client has no
/// <see cref="InternalApiHandler"/>, so a logged-in tab calling a public route
/// (a password reset, say) never puts its <c>X-Skein-User-*</c> on these
/// calls. Each request is built fresh — nothing the browser sent is copied —
/// and carries only <c>X-Skein-Internal-Secret</c> and, when the controller
/// supplies a trusted client address, <c>X-Skein-Client-Ip</c>.</para>
/// <para>Retries (<see cref="SkeinApiRetryPolicy"/>) apply to the GET routes
/// only, wired in <see cref="Register"/>: a POST that reached skein-api and
/// failed after committing (signup) must not be replayed into a misleading
/// <c>email_taken</c>.</para>
/// <para>Throws only on transport failure (<see cref="HttpRequestException"/>,
/// or <see cref="OperationCanceledException"/> past
/// <see cref="HttpClient.Timeout"/>); every HTTP status is returned as an
/// <see cref="AccountApiResult"/>.</para>
/// </remarks>
public sealed class SkeinAccountsApiClient
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _http;
    private readonly string _internalSecret;

    /// <summary>Creates the client over an <see cref="HttpClient"/> whose <c>BaseAddress</c> is skein-api.</summary>
    public SkeinAccountsApiClient(HttpClient http, IOptions<SkeinApiOptions> options)
    {
        _http = http;
        _internalSecret = options.Value.InternalSecret;
    }

    /// <summary>
    /// Registers the client: skein-api base address, 15 s per call, retry on
    /// GET only, no HttpClient request logging (the URIs carry tokens and
    /// emails). Called from <c>Program.cs</c>.
    /// </summary>
    /// <param name="services">Service collection.</param>
    /// <param name="skeinApiUrl"><c>SKEIN_API_URL</c>.</param>
    public static IHttpClientBuilder Register(IServiceCollection services, string skeinApiUrl)
    {
        var retry = SkeinApiRetryPolicy.Create();
        var noRetry = Policy.NoOpAsync<HttpResponseMessage>();
        return services.AddHttpClient<SkeinAccountsApiClient>(client =>
            {
                client.BaseAddress = new Uri(skeinApiUrl);
                client.Timeout = TimeSpan.FromSeconds(15);
            })
            // No request logging of IHttpClientFactory: its default handlers
            // write the full URI at Information, and these URIs carry reset,
            // confirmation and invitation tokens in the path and the email in
            // the username-suggestions query (CLAUDE_DEV "What NOT to log").
            .RemoveAllLoggers()
            .AddPolicyHandler(request => request.Method == HttpMethod.Get ? retry : noRetry);
    }

    /// <summary><c>POST /api/v1/auth/signup</c>.</summary>
    public Task<AccountApiResult> SignupAsync(SignupRequest body, string? clientIp, CancellationToken ct) =>
        SendAsync(HttpMethod.Post, "/api/v1/auth/signup", body, clientIp, ct);

    /// <summary><c>GET /api/v1/auth/username-suggestions?email=</c>.</summary>
    public Task<AccountApiResult> UsernameSuggestionsAsync(string email, string? clientIp, CancellationToken ct) =>
        SendAsync(HttpMethod.Get, "/api/v1/auth/username-suggestions?email=" + Uri.EscapeDataString(email), null, clientIp, ct);

    /// <summary><c>POST /api/v1/auth/password-reset</c>.</summary>
    public Task<AccountApiResult> PasswordResetAsync(PasswordResetRequest body, string? clientIp, CancellationToken ct) =>
        SendAsync(HttpMethod.Post, "/api/v1/auth/password-reset", body, clientIp, ct);

    /// <summary><c>POST /api/v1/auth/password-reset/{token}</c>.</summary>
    public Task<AccountApiResult> PasswordResetCompleteAsync(
        string token, PasswordResetCompleteRequest body, string? clientIp, CancellationToken ct) =>
        SendAsync(HttpMethod.Post, "/api/v1/auth/password-reset/" + Uri.EscapeDataString(token), body, clientIp, ct);

    /// <summary><c>POST /api/v1/auth/confirm-email/{token}</c> (no body).</summary>
    public Task<AccountApiResult> ConfirmEmailAsync(string token, string? clientIp, CancellationToken ct) =>
        SendAsync(HttpMethod.Post, "/api/v1/auth/confirm-email/" + Uri.EscapeDataString(token), null, clientIp, ct);

    /// <summary><c>GET /api/v1/auth/invitations/{token}</c>.</summary>
    public Task<AccountApiResult> InvitationPreviewAsync(string token, string? clientIp, CancellationToken ct) =>
        SendAsync(HttpMethod.Get, "/api/v1/auth/invitations/" + Uri.EscapeDataString(token), null, clientIp, ct);

    /// <summary><c>POST /api/v1/auth/invitations/{token}/signup</c>.</summary>
    public Task<AccountApiResult> InvitationSignupAsync(
        string token, InvitationSignupRequest body, string? clientIp, CancellationToken ct) =>
        SendAsync(HttpMethod.Post, "/api/v1/auth/invitations/" + Uri.EscapeDataString(token) + "/signup", body, clientIp, ct);

    private async Task<AccountApiResult> SendAsync(
        HttpMethod method, string path, object? body, string? clientIp, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(method, path);
        if (body is not null)
        {
            req.Content = JsonContent.Create(body, body.GetType(), options: JsonOpts);
        }
        req.Headers.TryAddWithoutValidation(SkeinHeaders.InternalSecret, _internalSecret);
        if (!string.IsNullOrEmpty(clientIp))
        {
            req.Headers.TryAddWithoutValidation(SkeinHeaders.ClientIp, clientIp);
        }

        using var resp = await _http.SendAsync(req, ct);
        var text = await resp.Content.ReadAsStringAsync(ct);
        return new AccountApiResult(resp.StatusCode, text);
    }
}
