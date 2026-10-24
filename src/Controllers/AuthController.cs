using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SkeinWeb.Auth;
using Swashbuckle.AspNetCore.Annotations;

namespace SkeinWeb.Controllers;

/// <summary>
/// Cookie-based authentication endpoints exposed by the BFF. These do
/// NOT live under <c>/api/v1/*</c> (which is the reverse-proxy namespace
/// for skein-api) — they live under <c>/api/auth/*</c> and are owned by
/// the .NET BFF.
/// </summary>
[ApiController]
[Route("api/auth")]
[SwaggerTag("BFF authentication: cookie-backed login / logout / me. " +
            "Sets the skein.sid cookie on login (session id only — full ticket lives in Redis).")]
public sealed class AuthController : ControllerBase
{
    private readonly SkeinApiClient _api;
    private readonly LoginRateLimiter _rateLimiter;
    private readonly ILogger<AuthController> _logger;
    private readonly WebAuthMode _mode;
    private readonly SsoOptions _sso;
    private readonly SkeinApiOptions _apiOptions;

    public AuthController(
        SkeinApiClient api,
        LoginRateLimiter rateLimiter,
        WebAuthMode mode,
        IOptions<SsoOptions> sso,
        IOptions<SkeinApiOptions> apiOptions,
        ILogger<AuthController> logger)
    {
        _api = api;
        _rateLimiter = rateLimiter;
        _mode = mode;
        _sso = sso.Value;
        _apiOptions = apiOptions.Value;
        _logger = logger;
    }

    /// <summary>
    /// Check on the process's auth mode (taken from skein-api at startup).
    /// Delegates to <see cref="WebAuthMode.IsSsoMode"/> so this returns true for both
    /// the legacy trust-headers <c>Keycloak</c> mode and the native
    /// <c>KeycloakOidc</c> mode — in both cases the password-login
    /// endpoint is disabled and the logout flow has to coordinate with
    /// the upstream IdP.
    /// </summary>
    private bool IsSsoMode() => _mode.IsSsoMode;

    /// <summary>
    /// 410 Gone — the standalone password endpoint is retired for this
    /// deployment (pure keycloak/OIDC). Body carries <c>error=login_disabled</c>
    /// so the SPA shows the SSO button. Returned when skein-api reports
    /// <see cref="LoginOutcome.Disabled"/> in non-hybrid (pure keycloak) mode
    /// — see the switch in <see cref="Login"/>. sk-303.8 removed the
    /// Request.Host-based public/internal short-circuit that used to reach
    /// this independently of the API's outcome; this is now the only path
    /// to it.
    /// </summary>
    private ObjectResult LoginDisabled410() => Problem(
        statusCode: StatusCodes.Status410Gone,
        title: "Login disabled",
        detail: "Standalone login is disabled. Use SSO at /oauth2/start.",
        type: "https://skein.local/errors/login-disabled",
        extensions: new Dictionary<string, object?>
        {
            ["error"] = "login_disabled",
        });

    /// <summary>
    /// 403 Forbidden with <c>error=sso_required</c> (sk-163 S4b) — the SPA
    /// renders "this account must sign in via Keycloak" and shows the SSO
    /// button. Distinct from the 410 (endpoint retired) so the SPA can show a
    /// per-account message without disabling the whole password form, and from
    /// the generic 422 so a future S4a that distinguishes account-class is
    /// routed sensibly. The SPA must NOT auto-redirect on this — it surfaces an
    /// affordance, avoiding a redirect loop.
    /// </summary>
    private ObjectResult SsoRequired403() => Problem(
        statusCode: StatusCodes.Status403Forbidden,
        title: "SSO required",
        detail: "This account must sign in via Keycloak.",
        type: "https://skein.local/errors/sso-required",
        extensions: new Dictionary<string, object?>
        {
            ["error"] = "sso_required",
            ["loginUrl"] = "/oauth2/start",
        });

    /// <summary>
    /// 422 Unprocessable Entity — generic invalid credentials. The SAME shape
    /// is returned for a wrong password and for an internal account on the
    /// hybrid password channel (skein-api collapses both into
    /// <see cref="LoginOutcome.InvalidCredentials"/> on purpose, so account
    /// class never leaks from this response). sk-303.8 removed a third case
    /// this used to also cover — a Request.Host-classified "public" caller
    /// that authenticated as a non-external (necessarily break-glass) account
    /// was collapsed into this same 422 instead of minting a cookie; that
    /// host-based oracle guard is gone (see the comment after the outcome
    /// switch in <see cref="Login"/>), so a successful non-external auth now
    /// always mints a cookie.
    /// </summary>
    private ObjectResult InvalidCredentials422() => Problem(
        statusCode: StatusCodes.Status422UnprocessableEntity,
        title: "Invalid credentials",
        detail: "Email or password is incorrect.",
        type: "https://skein.local/errors/invalid-credentials");

    /// <summary>
    /// Record a failed login against the throttle buckets, fail-OPEN on Redis
    /// errors (a throttle write failing must not change the auth outcome). Hits
    /// the per-email bucket always and the per-IP bucket only when a trusted
    /// proxy is configured (<paramref name="perIpEnabled"/>).
    /// </summary>
    private async Task RecordLoginFailureAsync(
        string emailLower, string? clientIp, bool perIpEnabled, CancellationToken ct)
    {
        try
        {
            await _rateLimiter.RecordFailureAsync(emailLower, ct);
            if (perIpEnabled)
            {
                await _rateLimiter.RecordIpFailureAsync(clientIp!, ct);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "login throttle record failed (Redis); continuing");
        }
    }

    /// <summary>
    /// Authenticate with email + password and start a cookie-backed session.
    /// </summary>
    /// <remarks>
    /// Algorithm:
    /// 1. Lower-case the email and check the per-email lockout bucket in Redis;
    ///    if locked, return 429 without contacting skein-api.
    /// 2. Forward {email, password} to skein-api POST /api/v1/auth/login.
    ///    The internal-secret header is added by InternalApiHandler.
    /// 3. On 422 from skein-api: increment the failure counter (rolls a 60s
    ///    window; 10 failures = 60s lockout) and return 422 ourselves.
    /// 4. On 200 without <c>sessionEpoch</c> (sk-674.18 K-16): log Error,
    ///    502, no session. On 200: clear the failure counter, build a
    ///    ClaimsPrincipal with the user's id/email/username/name/role and the
    ///    session epoch of the answer, SignIn under the "Cookies"
    ///    scheme (this writes the skein.sid cookie + stores the ticket in
    ///    Redis via RedisTicketStore), and return the user JSON.
    ///
    /// Side effects:
    /// - Writes <c>skein.sid</c> HttpOnly cookie (SameSite=Lax, Secure on HTTPS).
    /// - Writes a session blob to Redis under <c>skein:session:&lt;sid&gt;</c>
    ///   with sliding 24h TTL.
    /// - Increments <c>skein:login:fail:&lt;email&gt;</c> on failure or DELs on success.
    ///
    /// Logging never includes email or password — sanitiser-friendly.
    /// </remarks>
    /// <param name="req">Login credentials.</param>
    /// <param name="ct">Cancellation token tied to the request.</param>
    /// <response code="200">Login succeeded. Body is the authenticated user; cookie is set.</response>
    /// <response code="400">Request body validation failed (malformed JSON, missing fields).</response>
    /// <response code="422">Invalid credentials — same response for unknown email and wrong password.</response>
    /// <response code="429">Too many failed attempts for this email; locked out for 60 seconds.</response>
    /// <response code="502">Upstream skein-api was unreachable, returned an unexpected status, or answered 200 without <c>sessionEpoch</c>.</response>
    [HttpPost("login")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status410Gone)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status422UnprocessableEntity)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status502BadGateway)]
    [SwaggerOperation(
        Summary = "Login with email + password",
        Description =
            "Verifies credentials via skein-api and sets an encrypted session cookie. " +
            "Per-email throttle: 10 failed attempts in 60 seconds → 429 lockout for 60 seconds. " +
            "In LOCAL mode every account may password-login. In HYBRID mode (sk-163 S4b) the " +
            "password channel stays open and is forwarded to skein-api, which authenticates only " +
            "external collaborators (+ the break-glass admin) and returns a generic 422 otherwise. " +
            "In pure KEYCLOAK/OIDC mode the request is forwarded to skein-api, which returns 410 " +
            "Gone for a non-break-glass account (clients navigate to /oauth2/start) but still lets " +
            "the break-glass admin sign in; a 403 with error=sso_required steers an account to SSO " +
            "without a loop.",
        OperationId = "Login")]
    public async Task<ActionResult<UserDto>> Login(
        [FromBody, SwaggerRequestBody("Login credentials", Required = true)] LoginRequest req,
        CancellationToken ct)
    {
        // sk-163 S4b — auth-mode gate for the password channel.
        //
        //   - local:   forward unchanged (every account may password-login).
        //   - hybrid:  SSO is active but the password channel stays OPEN; we
        //              forward to skein-api. The API (S4a hybrid gate)
        //              authenticates only external accounts (+ the
        //              break-glass admin) and collapses everything else into a
        //              generic 422 — so account class never leaks here.
        //   - keycloak (pure SSO, not hybrid): the standalone password endpoint
        //              is retired for normal users. We still forward so the
        //              break-glass admin can obtain a session under active
        //              OIDC (the API applies its own break-glass gate); a
        //              non-break-glass account gets the API's 410 (see the
        //              LoginOutcome.Disabled case below).
        //
        // sk-303.8 — this used to also branch on Request.Host (the S7a
        // SKEIN_INTERNAL_HOSTS allowlist): on a classified PUBLIC host in pure
        // keycloak mode it short-circuited straight to 410 without forwarding,
        // so the public surface could never be probed as an internal-password
        // oracle. That allowlist was removed (it derived the decision from a
        // client-controlled header and never divided anything in this
        // deployment — see McpProxyMiddleware for the fuller rationale), so
        // every request now takes the "forward and let skein-api decide" path
        // that already ran under the allowlist's empty-by-default production
        // value.
        var emailLower = (req.Email ?? "").Trim().ToLowerInvariant();

        // Trusted client IP for the per-IP (spray) throttle. RemoteIpAddress
        // has already been resolved by the ForwardedHeaders middleware from the
        // trusted proxy chain (SKEIN_TRUSTED_PROXIES), so it is the real client
        // — NOT a spoofable raw X-Forwarded-For. The per-IP bucket is engaged
        // ONLY when a trusted proxy is configured (ClientIpTrusted): without one
        // RemoteIpAddress is the constant ingress IP, and a per-IP bucket keyed
        // on it would let an attacker lock out the whole org with ~30 garbage
        // POSTs/min. The per-email throttle is always on.
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        var perIpEnabled = _apiOptions.ClientIpTrusted && clientIp is not null;

        // 1) Lockout pre-check — either bucket trips a 429. The per-IP bucket
        // closes the spray vector (one IP walking many emails); the break-glass
        // admin (the single privileged password target) is covered by both,
        // since it logs in through this same path.
        //
        // FAIL-OPEN on Redis errors (deliberate): a Redis outage must NOT 500
        // every login — that would turn a cache blip into a total login DoS. We
        // log and let the attempt proceed; the API's in-memory backstop still
        // provides throttle cover while Redis is down.
        bool locked;
        try
        {
            locked = await _rateLimiter.IsLockedAsync(emailLower, ct) ||
                     (perIpEnabled && await _rateLimiter.IsIpLockedAsync(clientIp!, ct));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "login throttle check failed (Redis); failing open");
            locked = false;
        }
        if (locked)
        {
            _logger.LogWarning("login locked-out");
            return Problem(
                statusCode: StatusCodes.Status429TooManyRequests,
                title: "Too many failed attempts",
                detail: "Too many failed login attempts. Try again in 60 seconds.",
                type: "https://skein.local/errors/login-rate-limited",
                // sk-674.18 T044: the one 429 frame of the BFF — the public
                // account routes refuse with the same code (PublicAuthRoutes).
                extensions: new Dictionary<string, object?>
                {
                    ["error"] = AccountErrorCode.RateLimited,
                });
        }

        // 2) Forward to skein-api.
        LoginResult result;
        try
        {
            result = await _api.LoginAsync(emailLower, req.Password, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Client went away mid-login — not an error.
            return new EmptyResult();
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "login error: skein-api unavailable");
            return Problem(
                statusCode: StatusCodes.Status502BadGateway,
                title: "Authentication service unavailable",
                detail: "The authentication service is temporarily unavailable. Try again in a moment.",
                type: "https://skein.local/errors/upstream-unavailable");
        }

        // 3) Translate the API outcome per mode.
        switch (result.Outcome)
        {
            case LoginOutcome.InvalidCredentials:
                // Generic invalid credentials (in hybrid this ALSO covers an
                // internal account hitting the password channel — the API
                // collapses it here on purpose so account class never leaks).
                await RecordLoginFailureAsync(emailLower, clientIp, perIpEnabled, ct);
                _logger.LogWarning("login failed (invalid credentials)");
                return InvalidCredentials422();

            case LoginOutcome.Disabled:
                // API said the password endpoint is retired (keycloak,
                // non-break-glass). In pure keycloak mode keep today's 410; in
                // hybrid (where the API does not 410) fall back to the SSO
                // affordance defensively rather than 410-ing a live channel.
                _logger.LogInformation("login rejected: password channel disabled upstream");
                return _mode.IsHybridMode ? SsoRequired403() : LoginDisabled410();

            case LoginOutcome.SsoRequired:
                // Defensive: API distinguished "must use SSO" (403). Route to
                // the affordance — the SPA shows "sign in via Keycloak", no loop.
                _logger.LogInformation("login rejected: account must use SSO");
                return SsoRequired403();

            case LoginOutcome.Success:
                break;

            default:
                // Unreachable — every LoginOutcome is handled above. Treat an
                // unexpected value as a server fault rather than silently
                // minting a session.
                _logger.LogError("login: unexpected outcome {Outcome}", result.Outcome);
                return Problem(
                    statusCode: StatusCodes.Status502BadGateway,
                    title: "Authentication service error",
                    detail: "Unexpected authentication outcome.",
                    type: "https://skein.local/errors/upstream-unavailable");
        }

        var user = result.User!;

        // sk-674.18 K-16: the epoch the session will carry comes from THIS
        // answer. Without it no session is issued — never a default, never an
        // epoch from an older cookie: a session minted without it would be
        // refused by skein-api on its first request (session_revoked) at best,
        // or outlive a revocation at worst.
        if (result.SessionEpoch is not { } sessionEpoch)
        {
            _logger.LogError(
                "login: skein-api authentication response for {UserId} has no sessionEpoch; no session issued",
                user.Id);
            return Problem(
                statusCode: StatusCodes.Status502BadGateway,
                title: "Authentication service error",
                detail: "The authentication service returned an incomplete response. Try again in a moment.",
                type: "https://skein.local/errors/upstream-unavailable");
        }

        // sk-303.8 — this used to also run a "public-surface oracle guard"
        // here: on a Request.Host classified PUBLIC (S7a SKEIN_INTERNAL_HOSTS),
        // a successful auth for a non-external account (necessarily the
        // break-glass admin, since the API allows it regardless of host) was
        // collapsed into the generic invalid-credentials 422 rather than
        // minting a cookie, so the public host could never confirm a valid
        // internal credential. Removed along with the allowlist it read
        // (client-controlled Request.Host, never actually divided anything in
        // this deployment — see McpProxyMiddleware for the rationale): every
        // successful skein-api auth now mints a cookie the same way the
        // internal-host case always did.

        // 4) Success — reset the per-email counter, sign in. Fail-OPEN: a Redis
        // error clearing the bucket must not block a valid login (the bucket
        // self-expires on its TTL anyway).
        try
        {
            await _rateLimiter.ResetAsync(emailLower, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "login throttle reset failed (Redis); continuing");
        }

        // Same principal shape as signup and signup by invitation (SessionPrincipal).
        var principal = SessionPrincipal.Create(user, sessionEpoch);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            new AuthenticationProperties
            {
                IsPersistent = true,
                AllowRefresh = true,
            });

        _logger.LogInformation("login success for {UserId}", user.Id);
        return Ok(user);
    }

    /// <summary>
    /// Sign out: clear the session cookie and revoke the Redis ticket.
    /// </summary>
    /// <remarks>
    /// <para>
    /// SignOutAsync triggers <see cref="RedisTicketStore.RemoveAsync"/>,
    /// hard-deleting the session row in Redis. Even if the user keeps the
    /// cookie value, RetrieveAsync will return null and the cookie is
    /// rejected on the next request.
    /// </para>
    /// <para>
    /// In keycloak mode the response is a JSON body containing the URL
    /// the SPA should redirect the browser to next:
    /// <c>{ "redirectTo": "/oauth2/sign_out" }</c>. oauth2-proxy clears
    /// its own cookie and then (optionally) redirects on to Keycloak's
    /// <c>end_session</c> endpoint. The SPA does an explicit
    /// <c>window.location.assign</c> rather than the BFF returning a
    /// 302 — same-origin fetch follows redirects opaquely and would
    /// not actually navigate the browser.
    /// </para>
    /// </remarks>
    /// <param name="ct">Cancellation token.</param>
    /// <response code="200">Session terminated. Body carries a redirectTo URL in keycloak mode; empty in local mode.</response>
    /// <response code="401">Not authenticated.</response>
    [HttpPost("logout")]
    [Authorize]
    [ProducesResponseType(typeof(LogoutResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [SwaggerOperation(
        Summary = "Logout",
        Description =
            "Clears the skein.sid cookie and deletes the Redis session row. " +
            "Response body carries a redirectTo URL the SPA should navigate to so " +
            "the upstream session is also terminated: the configured " +
            "Authentication:LogoutRedirectUrl in legacy Keycloak mode (null when it " +
            "is unset — the external session then survives, see the startup " +
            "warning), same-origin /api/auth/oidc-signout in native KeycloakOidc " +
            "mode (initiates RP-logout against the realm), or null in local mode.",
        OperationId = "Logout")]
    public async Task<ActionResult<LogoutResponse>> Logout(CancellationToken ct)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        // `ct` is deliberately NOT observed here. Cookie SignOutAsync has no
        // CancellationToken overload, and wrapping it in WaitAsync(ct) would
        // abandon the await on client disconnect — which on logout is the
        // normal case, since the browser navigates away immediately. The
        // response below carries `redirectTo`, the URL the SPA must visit to
        // tear down the UPSTREAM session (oauth2-proxy / Keycloak realm); if
        // the await is abandoned, that response is never produced and the SSO
        // session survives a "successful" logout. Session teardown is past the
        // point of no return: cancelling here would abandon the teardown
        // half-done, which is exactly the case the .NET guidelines carve out
        // from "always forward the CancellationToken".
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        _logger.LogInformation("logout for {UserId}", userId);

        // The cookie above is only half the story when SSO is in play —
        // the upstream session (oauth2-proxy cookie in legacy mode, or
        // the Keycloak realm session in native OIDC mode) still holds a
        // valid identity. The SPA navigates the browser to a URL that
        // tears that down, then redirects back to /login.
        //
        //   - Legacy Keycloak (trust-headers): the sign-out endpoint of the
        //     authenticating proxy at the edge, configured per deployment as
        //     Authentication:LogoutRedirectUrl (sk-303.42). The address is a
        //     property of the deployment's topology — which proxy, on which
        //     host, with which cookie domain — so there is no value that could
        //     be compiled in and be right for anyone but the install that set
        //     it. Unset, we return null rather than sending the browser to
        //     another org's proxy: the local cookie is still cleared, and the
        //     startup warning in Program.cs has already said the external
        //     session will survive.
        //   - Native OIDC (KeycloakOidc): same-origin /api/auth/oidc-signout
        //     in this BFF — the OpenIdConnect handler issues the OIDC
        //     RP-initiated logout (end_session_endpoint), Keycloak
        //     bounces back to SignedOutCallbackPath, and from there to
        //     SignedOutRedirectUri (/login by default).
        if (_mode.IsKeycloakMode)
        {
            var external = _sso.LogoutRedirectUrl;
            return Ok(new LogoutResponse(
                RedirectTo: string.IsNullOrWhiteSpace(external) ? null : external));
        }
        if (_mode.IsKeycloakOidcMode)
        {
            return Ok(new LogoutResponse(RedirectTo: "/api/auth/oidc-signout"));
        }
        return Ok(new LogoutResponse(RedirectTo: null));
    }

    /// <summary>
    /// Start the OIDC RP-initiated logout. Called by the SPA via
    /// <c>window.location.assign</c> after <c>POST /api/auth/logout</c>
    /// returns <c>{ redirectTo: "/api/auth/oidc-signout" }</c> in
    /// <c>KeycloakOidc</c> mode.
    /// </summary>
    /// <remarks>
    /// Algorithm: call <c>SignOutAsync</c> on the OpenIdConnect scheme.
    /// The .NET handler builds an end_session request against the
    /// realm (issuer + client_id + post_logout_redirect_uri pointing
    /// to <see cref="OidcOptions.SignedOutCallbackPath"/>) and returns
    /// a 302 to Keycloak. Keycloak clears its realm session cookie
    /// and bounces back to the callback, which finally lands the
    /// user on <see cref="OidcOptions.SignedOutRedirectUri"/>.
    /// 404 outside <c>KeycloakOidc</c> mode so the path does not
    /// accidentally hit the legacy or local stacks.
    /// </remarks>
    /// <response code="302">Browser redirect to Keycloak end_session.</response>
    /// <response code="404">Not in KeycloakOidc mode.</response>
    [HttpGet("oidc-signout")]
    [AllowAnonymous]
    [ApiExplorerSettings(IgnoreApi = true)]
    public IActionResult OidcSignout()
    {
        if (!_mode.IsKeycloakOidcMode)
        {
            return NotFound();
        }
        // SignOut() result issues SignOutAsync against both schemes —
        // cookie (idempotent if already cleared above by /api/auth/logout)
        // and OpenIdConnect (this is what actually navigates to
        // Keycloak's end_session_endpoint with the right query string).
        return SignOut(
            new AuthenticationProperties { RedirectUri = _sso.Oidc.SignedOutRedirectUri },
            CookieAuthenticationDefaults.AuthenticationScheme,
            "OpenIdConnect");
    }

    /// <summary>
    /// Current user of the session, as skein-api sees it.
    /// </summary>
    /// <remarks>
    /// <para>Algorithm: the cookie principal must be authenticated
    /// ([Authorize]); then <c>GET /api/v1/auth/me</c> is called on behalf of the
    /// session — its identity headers and <c>X-Skein-Session-Epoch</c> — and
    /// skein-api's user is returned.</para>
    /// <para>sk-674.18 (INV-26, K-16): this is where a revoked session is
    /// refused on the BFF's own routes, not only on the <c>/api/v1</c> proxy.
    /// skein-api's 401 <c>session_revoked</c> ends the session here (cookie
    /// deleted, Redis ticket removed) and answers 401 ProblemDetails
    /// <c>error = session_revoked</c>; the SPA, which boots on this route, goes
    /// to the login screen. skein-api unreachable or answering outside its
    /// contract → 502 <c>upstream_unavailable</c>, never the cookie's claims
    /// as a fallback.</para>
    /// </remarks>
    /// <param name="ct">Request abort.</param>
    /// <response code="200">The user of the session.</response>
    /// <response code="401">No session, or skein-api revoked it (<c>error = session_revoked</c>; the cookie is cleared).</response>
    /// <response code="502">skein-api unreachable or outside its contract.</response>
    [HttpGet("me")]
    [Authorize]
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status502BadGateway)]
    [SwaggerOperation(
        Summary = "Current user of the session",
        Description =
            "Asks skein-api GET /api/v1/auth/me on behalf of the session (identity headers + " +
            "X-Skein-Session-Epoch) and returns its user. A session skein-api revoked " +
            "(401 session_revoked) is ended here — cookie cleared — and answered 401 with " +
            "error=session_revoked; skein-api unavailable → 502 upstream_unavailable.",
        OperationId = "Me")]
    public async Task<ActionResult<UserDto>> Me(CancellationToken ct)
    {
        if (string.IsNullOrEmpty(User.FindFirstValue(ClaimTypes.NameIdentifier)))
        {
            // Defensive: [Authorize] should have already 401'd if not authenticated.
            return Unauthorized();
        }

        MeResult result;
        try
        {
            result = await _api.MeAsync(ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return new EmptyResult();
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
        {
            _logger.LogError(ex, "me: skein-api unavailable");
            return Problem(
                statusCode: StatusCodes.Status502BadGateway,
                title: "Authentication service unavailable",
                detail: "The authentication service is temporarily unavailable. Try again in a moment.",
                type: "https://skein.local/errors/upstream-unavailable",
                extensions: new Dictionary<string, object?> { ["error"] = "upstream_unavailable" });
        }

        if (result.Revoked)
        {
            _logger.LogInformation(
                "me: skein-api revoked the session of {UserId}; signing out",
                User.FindFirstValue(ClaimTypes.NameIdentifier));
            await SessionRevocation.EndSessionAsync(HttpContext);
            return Problem(
                statusCode: StatusCodes.Status401Unauthorized,
                title: "Session revoked",
                detail: "This session has ended. Sign in again.",
                type: "https://skein.local/errors/session-revoked",
                extensions: new Dictionary<string, object?> { ["error"] = SkeinHeaders.SessionRevokedCode });
        }

        return Ok(result.User);
    }
}
