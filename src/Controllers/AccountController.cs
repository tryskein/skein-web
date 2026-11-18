using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SkeinWeb.Auth;
using SkeinWeb.Hubs;
using Swashbuckle.AspNetCore.Annotations;

namespace SkeinWeb.Controllers;

/// <summary>
/// Public account routes of the BFF (spec sk-674.18 US-8, US-9, US-5; plan
/// K-17): registration, username suggestions, password reset, email
/// confirmation and the invitation link for a visitor without a session. The
/// browser contract — paths, bodies, codes, rate-limit keys — is
/// <see cref="PublicAuthRoutes"/>; the upstream is skein-api
/// <c>internal/accounts/contract.go</c> (T012).
/// </summary>
/// <remarks>
/// <para>Every route here is reachable without a session and is the only kind
/// that is (besides login and <c>GET /api/auth/config</c>): <c>/api/v1/*</c>
/// without a session stays 401 in <c>ApiProxyMiddleware</c>, which keeps no
/// list of anonymous exceptions.</para>
/// <para>Common algorithm of a route:</para>
/// <list type="number">
///   <item>Model validation ([ApiController]): a body not of the declared shape
///         → 400 <c>ValidationProblemDetails</c>, before anything else.</item>
///   <item>BFF rate limit (<see cref="ActionRateLimiter"/>, the route's
///         <see cref="ActionRateLimiter.Policy"/>): the request is counted; an
///         exhausted bucket → 429 ProblemDetails <c>error = rate_limited</c>
///         without calling skein-api. The IP bucket and
///         <c>X-Skein-Client-Ip</c> exist only with a trusted proxy
///         (<c>SKEIN_TRUSTED_PROXIES</c>).</item>
///   <item>The call to skein-api through <see cref="SkeinAccountsApiClient"/>:
///         service secret and client IP only, no identity headers, nothing the
///         browser sent copied.</item>
///   <item>Mapping: success only on the route's contract status (200 with a
///         body of the contract shape, or 204) — any other 2xx is outside the
///         contract (502); a 400/422/429 refusal of skein-api →
///         ProblemDetails with the same status and its code in <c>error</c>
///         (plus <c>suggestions</c> on <c>username_taken</c>); unreachable,
///         timed out, any other status or an unreadable body → 502
///         ProblemDetails <c>error = upstream_unavailable</c>.</item>
/// </list>
/// <para>Signup and signup by invitation log the user in exactly as a password
/// login does (<see cref="SessionPrincipal"/>, the session cookie,
/// ticket in Redis), with the <c>sessionEpoch</c> of skein-api's answer in the
/// session (plan K-16); an answer without it issues no session (502, logged as
/// Error).</para>
/// </remarks>
[ApiController]
[Route("api/auth")]
[AllowAnonymous]
[SwaggerTag("Public account routes without a session: signup, username suggestions, " +
            "password reset, email confirmation, invitation link (plan K-17).")]
public sealed class AccountController : ControllerBase
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    private readonly SkeinAccountsApiClient _api;
    private readonly ActionRateLimiter _limiter;
    private readonly SkeinApiOptions _apiOptions;
    private readonly IUserSessionRevoker _sessions;
    private readonly ConnectionRegistry _hubConnections;
    private readonly SessionIssuer _issuer;
    private readonly ILogger<AccountController> _logger;

    public AccountController(
        SkeinAccountsApiClient api,
        ActionRateLimiter limiter,
        IOptions<SkeinApiOptions> apiOptions,
        IUserSessionRevoker sessions,
        ConnectionRegistry hubConnections,
        SessionIssuer issuer,
        ILogger<AccountController> logger)
    {
        _api = api;
        _limiter = limiter;
        _apiOptions = apiOptions.Value;
        _sessions = sessions;
        _hubConnections = hubConnections;
        _issuer = issuer;
        _logger = logger;
    }

    /// <summary>Register an account and log in.</summary>
    /// <remarks>
    /// Rate limit: «signup + email» and «signup + IP». On skein-api's 200 the
    /// account, its personal space and the consent record exist and a
    /// confirmation email is queued (skein-api side); the BFF then signs the
    /// user in (Set-Cookie of the session cookie) and returns the user.
    /// Refusal codes: <c>signup_disabled</c>, <c>rate_limited</c>,
    /// <c>captcha_failed</c>, <c>terms_required</c>, <c>username_invalid</c>,
    /// <c>password_weak</c>, <c>password_pwned</c>, <c>email_taken</c>,
    /// <c>username_taken</c> (+ <c>suggestions</c>), <c>invalid_request</c>.
    /// <para>Session cookie: the session is read from <c>__Host-skein.sid</c> (<c>skein.sid</c> when the Development-only setting <c>SKEIN_ALLOW_INSECURE_HTTP</c> is on) — <c>Secure</c> (not in that mode), <c>HttpOnly</c>, <c>Path=/</c>, no <c>Domain</c>, <c>SameSite=Lax</c>, whatever <c>X-Forwarded-Proto</c> says. A cookie under the other name, or issued before the update, does not authenticate.</para>
    /// </remarks>
    /// <param name="req">Registration form.</param>
    /// <param name="ct">Request abort.</param>
    /// <response code="200">Registered and logged in; body is the user, the session cookie is set.</response>
    /// <response code="400">Body not of the declared shape (BFF) or <c>invalid_request</c> (skein-api).</response>
    /// <response code="422">Business refusal; code in <c>error</c>.</response>
    /// <response code="429"><c>rate_limited</c> — BFF limiter or skein-api backstop.</response>
    /// <response code="502"><c>upstream_unavailable</c> — skein-api unreachable or answered outside the contract. Refused before the operation when the session store failed technically while the session was read: ProblemDetails (<c>type</c> …/upstream-unavailable, <c>error = upstream_unavailable</c>). No Set-Cookie. Account created but no session issued (a confirmed answer that cannot yield a session, or a failed revocation or issue): ProblemDetails of type …/account-created-session-not-issued with error=upstream_unavailable and no Set-Cookie; the account exists and the new credentials work for a normal sign-in.</response>
    [HttpPost("signup")]
    [ExplicitSignIn(Surface.Signup)]
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status422UnprocessableEntity)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status502BadGateway)]
    [SwaggerOperation(
        Summary = "Register an account (self-service signup)",
        Description =
            "Forwards the form to skein-api POST /ui/v1/auth/signup (no identity headers). " +
            "On success the user is logged in exactly as after POST /api/auth/login " +
            "(a new session key; the key the request carried is revoked first) and the user is returned. Rate limit per lower-cased email " +
            "and per client IP (IP only behind a trusted proxy): exceeded → 429 rate_limited " +
            "without calling skein-api. Refusals are ProblemDetails with the skein-api code in " +
            "'error'; username_taken adds 'suggestions'." +
            " Session cookie: __Host-skein.sid (skein.sid with the Development-only SKEIN_ALLOW_INSECURE_HTTP), Secure (not in that mode), HttpOnly, Path=/, no Domain, SameSite=Lax, whatever X-Forwarded-Proto says. Technical failure of the session store while reading the session → 502 ProblemDetails error=upstream_unavailable before the operation, no Set-Cookie.",
        OperationId = "Signup")]
    public async Task<ActionResult<UserDto>> Signup(
        [FromBody, SwaggerRequestBody("Registration form", Required = true)] SignupRequest req,
        CancellationToken ct)
    {
        var emailLower = req.Email.Trim().ToLowerInvariant();
        var clientIp = TrustedClientIp();
        if (!await _limiter.TryAcquireAsync(ActionRateLimiter.Signup, emailLower, clientIp, ct))
        {
            return RateLimited();
        }

        return await RelayAsync(
            () => _api.SignupAsync(req with { Email = emailLower }, clientIp, ct),
            HttpStatusCode.OK,
            async ok =>
            {
                var user = Deserialize<UserDto>(ok.Body);
                if (!IsIssuable(user))
                {
                    return SessionNotIssued("signup", "200 without a usable user");
                }
                if (SessionEpochOf(ok) is not { } epoch)
                {
                    return SessionNotIssued("signup", "200 without sessionEpoch");
                }
                if (!await IssueNewSessionAsync(user!, epoch, nameof(Surface.Signup)))
                {
                    return SessionNotIssued("signup", "the session could not be issued");
                }
                _logger.LogInformation("signup success for {UserId}", user!.Id);
                return Ok(user);
            },
            "signup",
            ct);
    }

    /// <summary>Suggest free usernames derived from an email.</summary>
    /// <remarks>
    /// Rate limit: «username-suggestions + email» and «… + IP». Refusal codes:
    /// <c>signup_disabled</c>, <c>rate_limited</c>, <c>invalid_request</c>.
    /// <para>Session cookie: the session is read from <c>__Host-skein.sid</c> (<c>skein.sid</c> when the Development-only setting <c>SKEIN_ALLOW_INSECURE_HTTP</c> is on) — <c>Secure</c> (not in that mode), <c>HttpOnly</c>, <c>Path=/</c>, no <c>Domain</c>, <c>SameSite=Lax</c>, whatever <c>X-Forwarded-Proto</c> says. A cookie under the other name, or issued before the update, does not authenticate.</para>
    /// </remarks>
    /// <param name="email">Email whose local part seeds the suggestions.</param>
    /// <param name="ct">Request abort.</param>
    /// <response code="200">2–3 usernames free at the moment of the answer.</response>
    /// <response code="400">Email missing or malformed.</response>
    /// <response code="422">Business refusal; code in <c>error</c>.</response>
    /// <response code="429"><c>rate_limited</c>.</response>
    /// <response code="502"><c>upstream_unavailable</c>. Refused before the operation when the session store failed technically while the session was read: ProblemDetails (<c>type</c> …/upstream-unavailable, <c>error = upstream_unavailable</c>); in the legacy trust-headers mode, for a trusted proxy with both identity headers, JSON <c>{ "error": "sso_unavailable", "message": … }</c> instead. No Set-Cookie.</response>
    [HttpGet("username-suggestions")]
    [ProducesResponseType(typeof(UsernameSuggestionsResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status422UnprocessableEntity)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status502BadGateway, "application/problem+json")]
    [SwaggerOperation(
        Summary = "Suggest usernames from an email",
        Description =
            "Forwards to skein-api GET /ui/v1/auth/username-suggestions. Rate limit per " +
            "lower-cased email and per client IP; exceeded → 429 rate_limited." +
            " Session cookie: __Host-skein.sid (skein.sid with the Development-only SKEIN_ALLOW_INSECURE_HTTP), Secure (not in that mode), HttpOnly, Path=/, no Domain, SameSite=Lax, whatever X-Forwarded-Proto says. Technical failure of the session store while reading the session → 502 before the operation (ProblemDetails error=upstream_unavailable; JSON error=sso_unavailable in the legacy trust-headers mode for a trusted proxy with both identity headers), no Set-Cookie.",
        OperationId = "GetUsernameSuggestions")]
    public async Task<ActionResult<UsernameSuggestionsResponse>> UsernameSuggestions(
        [FromQuery, Required, EmailAddress, StringLength(320, MinimumLength = 3),
         SwaggerParameter("Email whose local part (before @) seeds the suggestions", Required = true)] string email,
        CancellationToken ct)
    {
        var emailLower = email.Trim().ToLowerInvariant();
        var clientIp = TrustedClientIp();
        if (!await _limiter.TryAcquireAsync(ActionRateLimiter.UsernameSuggestions, emailLower, clientIp, ct))
        {
            return RateLimited();
        }

        return await RelayAsync(
            () => _api.UsernameSuggestionsAsync(emailLower, clientIp, ct),
            HttpStatusCode.OK,
            ok =>
            {
                var body = Deserialize<UsernameSuggestionsResponse>(ok.Body);
                return Task.FromResult<ActionResult>(body?.Suggestions is null
                    ? UpstreamBroken("username-suggestions", "200 without suggestions")
                    : Ok(body));
            },
            "username-suggestions",
            ct);
    }

    /// <summary>Request a password-reset email.</summary>
    /// <remarks>
    /// Rate limit: «password-reset + email» and «… + IP». The 204 is neutral:
    /// identical whether or not an account with the email exists. Refusal
    /// codes (independent of the email): <c>password_login_disabled</c>,
    /// <c>email_disabled</c>, <c>rate_limited</c>, <c>invalid_request</c>.
    /// <para>Session cookie: the session is read from <c>__Host-skein.sid</c> (<c>skein.sid</c> when the Development-only setting <c>SKEIN_ALLOW_INSECURE_HTTP</c> is on) — <c>Secure</c> (not in that mode), <c>HttpOnly</c>, <c>Path=/</c>, no <c>Domain</c>, <c>SameSite=Lax</c>, whatever <c>X-Forwarded-Proto</c> says. A cookie under the other name, or issued before the update, does not authenticate.</para>
    /// </remarks>
    /// <param name="req">Email and the interface language of the email.</param>
    /// <param name="ct">Request abort.</param>
    /// <response code="204">Accepted (neutral).</response>
    /// <response code="400">Body not of the declared shape.</response>
    /// <response code="422">Business refusal; code in <c>error</c>.</response>
    /// <response code="429"><c>rate_limited</c>.</response>
    /// <response code="502"><c>upstream_unavailable</c>. Refused before the operation when the session store failed technically while the session was read: ProblemDetails (<c>type</c> …/upstream-unavailable, <c>error = upstream_unavailable</c>); in the legacy trust-headers mode, for a trusted proxy with both identity headers, JSON <c>{ "error": "sso_unavailable", "message": … }</c> instead. No Set-Cookie.</response>
    [HttpPost("password-reset")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status422UnprocessableEntity)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status502BadGateway, "application/problem+json")]
    [SwaggerOperation(
        Summary = "Request a password reset",
        Description =
            "Forwards to skein-api POST /ui/v1/auth/password-reset; 204 whether or not the " +
            "account exists. Rate limit per lower-cased email and per client IP." +
            " Session cookie: __Host-skein.sid (skein.sid with the Development-only SKEIN_ALLOW_INSECURE_HTTP), Secure (not in that mode), HttpOnly, Path=/, no Domain, SameSite=Lax, whatever X-Forwarded-Proto says. Technical failure of the session store while reading the session → 502 before the operation (ProblemDetails error=upstream_unavailable; JSON error=sso_unavailable in the legacy trust-headers mode for a trusted proxy with both identity headers), no Set-Cookie.",
        OperationId = "RequestPasswordReset")]
    public async Task<ActionResult> PasswordReset(
        [FromBody, SwaggerRequestBody("Email and email language", Required = true)] PasswordResetRequest req,
        CancellationToken ct)
    {
        var emailLower = req.Email.Trim().ToLowerInvariant();
        var clientIp = TrustedClientIp();
        if (!await _limiter.TryAcquireAsync(ActionRateLimiter.PasswordReset, emailLower, clientIp, ct))
        {
            return RateLimited();
        }

        return await RelayAsync(
            () => _api.PasswordResetAsync(req with { Email = emailLower }, clientIp, ct),
            HttpStatusCode.NoContent,
            _ => Task.FromResult<ActionResult>(NoContent()),
            "password-reset",
            ct);
    }

    /// <summary>Set a new password by the token of the reset link.</summary>
    /// <remarks>
    /// Rate limit: «password-reset-complete + IP» (the token is never part of a
    /// key). skein-api sets the password, uses the token up, raises the
    /// session epoch — every session of the user ends there, API keys keep working —
    /// and answers with the authentication response carrying the NEW epoch.
    /// The BFF then revokes locally (INV-13): the key of the session cookie the request
    /// carried, whoever owns it, and every ticket of the token's user found by the
    /// user's index; this replica's hub connections of the user close at once. Only
    /// after a complete revocation a NEW session of the user is issued under a new key
    /// (204 with Set-Cookie, whatever cookie came in: none, another user's, the user's own).
    /// An incomplete revocation, an unreadable user id, data unusable for a session or a
    /// failed issue answer 502 of type …/password-changed-session-not-issued without a cookie
    /// (the password and the spent token stay); no answer from skein-api is a different 502,
    /// of type …/upstream-unavailable, that does not claim the change.
    /// Refusal codes: <c>password_login_disabled</c>, <c>email_disabled</c>,
    /// <c>rate_limited</c>, <c>token_invalid</c>, <c>password_weak</c>,
    /// <c>password_pwned</c>, <c>invalid_request</c>.
    /// <para>Session cookie: the session is read from <c>__Host-skein.sid</c> (<c>skein.sid</c> when the Development-only setting <c>SKEIN_ALLOW_INSECURE_HTTP</c> is on) — <c>Secure</c> (not in that mode), <c>HttpOnly</c>, <c>Path=/</c>, no <c>Domain</c>, <c>SameSite=Lax</c>, whatever <c>X-Forwarded-Proto</c> says. A cookie under the other name, or issued before the update, does not authenticate.</para>
    /// </remarks>
    /// <param name="token">Token from the reset link.</param>
    /// <param name="req">The new password.</param>
    /// <param name="ct">Request abort.</param>
    /// <response code="204">Password set. The key of the session cookie the request carried (any user's) and every ticket of the token's user are revoked, and a NEW session of that user is issued: Set-Cookie with the new key, whatever cookie came in (none, another user's, the user's own).</response>
    /// <response code="400">Body not of the declared shape.</response>
    /// <response code="422">Business refusal; code in <c>error</c>.</response>
    /// <response code="429"><c>rate_limited</c>.</response>
    /// <response code="502"><c>upstream_unavailable</c>. Refused before the operation when the session store failed technically while the session was read: ProblemDetails (<c>type</c> …/upstream-unavailable, <c>error = upstream_unavailable</c>). No Set-Cookie. Password changed but the session not issued (a user id that cannot be read, the previous sessions not all removed, data unusable for a session, or a failed issue): ProblemDetails of type …/password-changed-session-not-issued with error=upstream_unavailable, no Set-Cookie; the password and the spent token stay. No confirmation of the change (skein-api did not answer): ProblemDetails of type …/upstream-unavailable, which does not claim the change or the token spend.</response>
    [HttpPost("password-reset/{token}")]
    [ExplicitSignIn(Surface.PasswordResetComplete)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status422UnprocessableEntity)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status502BadGateway)]
    [SwaggerOperation(
        Summary = "Complete a password reset",
        Description =
            "Forwards to skein-api POST /ui/v1/auth/password-reset/{token}; 204 on success. " +
            "Every session of the user ends and the key of the cookie the request carried is revoked, " +
            "whoever it belongs to; then a new session with a NEW key is issued (204 with Set-Cookie, " +
            "whatever cookie came in). This replica's hub connections of the user are closed at once " +
            "(other replicas close theirs on the next access re-check, within 30 s). If the password " +
            "is changed but the sessions cannot all be removed or the new one cannot be issued, the " +
            "answer is 502 of type password-changed-session-not-issued without a cookie; the password " +
            "and the spent token stay. No answer from skein-api: 502 of type upstream-unavailable. " +
            "Rate limit per client IP only." +
            " Session cookie: __Host-skein.sid (skein.sid with the Development-only SKEIN_ALLOW_INSECURE_HTTP), Secure (not in that mode), HttpOnly, Path=/, no Domain, SameSite=Lax, whatever X-Forwarded-Proto says. Technical failure of the session store while reading the session → 502 ProblemDetails error=upstream_unavailable before the operation, no Set-Cookie.",
        OperationId = "CompletePasswordReset")]
    public async Task<ActionResult> PasswordResetComplete(
        [FromRoute, StringLength(512, MinimumLength = 1), SwaggerParameter("Token from the reset link", Required = true)] string token,
        [FromBody, SwaggerRequestBody("The new password", Required = true)] PasswordResetCompleteRequest req,
        CancellationToken ct)
    {
        var clientIp = TrustedClientIp();
        if (!await _limiter.TryAcquireAsync(ActionRateLimiter.PasswordResetComplete, null, clientIp, ct))
        {
            return RateLimited();
        }

        return await RelayAsync(
            () => _api.PasswordResetCompleteAsync(token, req, clientIp, ct),
            HttpStatusCode.OK,
            async ok =>
            {
                // The password is set and the epoch moved: from here nothing may stop the revocation.
                var subject = ReadSubjectId(ok.Body);
                _issuer.MarkSessionWriteSuppressed(HttpContext);
                _issuer.MarkPointOfNoReturn(HttpContext);
                if (subject is not { } userId)
                {
                    // No known subject: nothing to revoke by index, and no session to issue.
                    return PasswordChangedNotIssued("200 without a readable user id");
                }

                var revoked = await EndSessionsAfterResetAsync(userId);
                var user = Deserialize<UserDto>(ok.Body);
                if (!revoked)
                {
                    return PasswordChangedNotIssued("the previous sessions could not all be revoked");
                }
                if (!IsIssuable(user) || SessionEpochOf(ok) is not { } epoch)
                {
                    return PasswordChangedNotIssued("200 without usable data for a session");
                }
                try
                {
                    await _issuer.IssueAsync(
                        HttpContext,
                        SessionPrincipal.Create(user!, epoch),
                        new AuthenticationProperties { IsPersistent = true, AllowRefresh = true },
                        nameof(Surface.PasswordResetComplete));
                }
                catch (SessionIssueException)
                {
                    return PasswordChangedNotIssued("the new session could not be issued");
                }
                return NoContent();
            },
            "password-reset-complete",
            ct);
    }

    /// <summary>Confirm the email by the token of the confirmation email.</summary>
    /// <remarks>
    /// Rate limit: «confirm-email + IP». No session is issued or changed.
    /// Refusal codes: <c>email_disabled</c>, <c>rate_limited</c>,
    /// <c>token_invalid</c>.
    /// <para>Session cookie: the session is read from <c>__Host-skein.sid</c> (<c>skein.sid</c> when the Development-only setting <c>SKEIN_ALLOW_INSECURE_HTTP</c> is on) — <c>Secure</c> (not in that mode), <c>HttpOnly</c>, <c>Path=/</c>, no <c>Domain</c>, <c>SameSite=Lax</c>, whatever <c>X-Forwarded-Proto</c> says. A cookie under the other name, or issued before the update, does not authenticate.</para>
    /// </remarks>
    /// <param name="token">Token from the confirmation email.</param>
    /// <param name="ct">Request abort.</param>
    /// <response code="204">Email confirmed (also when it already was).</response>
    /// <response code="400">Token malformed.</response>
    /// <response code="422">Business refusal; code in <c>error</c>.</response>
    /// <response code="429"><c>rate_limited</c>.</response>
    /// <response code="502"><c>upstream_unavailable</c>. Refused before the operation when the session store failed technically while the session was read: ProblemDetails (<c>type</c> …/upstream-unavailable, <c>error = upstream_unavailable</c>); in the legacy trust-headers mode, for a trusted proxy with both identity headers, JSON <c>{ "error": "sso_unavailable", "message": … }</c> instead. No Set-Cookie.</response>
    [HttpPost("confirm-email/{token}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status422UnprocessableEntity)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status502BadGateway, "application/problem+json")]
    [SwaggerOperation(
        Summary = "Confirm an email address",
        Description =
            "Forwards to skein-api POST /ui/v1/auth/confirm-email/{token}; 204 on success. " +
            "Rate limit per client IP only." +
            " Session cookie: __Host-skein.sid (skein.sid with the Development-only SKEIN_ALLOW_INSECURE_HTTP), Secure (not in that mode), HttpOnly, Path=/, no Domain, SameSite=Lax, whatever X-Forwarded-Proto says. Technical failure of the session store while reading the session → 502 before the operation (ProblemDetails error=upstream_unavailable; JSON error=sso_unavailable in the legacy trust-headers mode for a trusted proxy with both identity headers), no Set-Cookie.",
        OperationId = "ConfirmEmail")]
    public async Task<ActionResult> ConfirmEmail(
        [FromRoute, StringLength(512, MinimumLength = 1), SwaggerParameter("Token from the confirmation email", Required = true)] string token,
        CancellationToken ct)
    {
        var clientIp = TrustedClientIp();
        if (!await _limiter.TryAcquireAsync(ActionRateLimiter.ConfirmEmail, null, clientIp, ct))
        {
            return RateLimited();
        }

        return await RelayAsync(
            () => _api.ConfirmEmailAsync(token, clientIp, ct),
            HttpStatusCode.NoContent,
            _ => Task.FromResult<ActionResult>(NoContent()),
            "confirm-email",
            ct);
    }

    /// <summary>Invitation state for a visitor without a session.</summary>
    /// <remarks>
    /// Rate limit: «invitation-preview + IP». Opening the link changes
    /// nothing; every invitation state is a 200. Refusal codes:
    /// <c>rate_limited</c>, <c>invalid_request</c>.
    /// <para>Session cookie: the session is read from <c>__Host-skein.sid</c> (<c>skein.sid</c> when the Development-only setting <c>SKEIN_ALLOW_INSECURE_HTTP</c> is on) — <c>Secure</c> (not in that mode), <c>HttpOnly</c>, <c>Path=/</c>, no <c>Domain</c>, <c>SameSite=Lax</c>, whatever <c>X-Forwarded-Proto</c> says. A cookie under the other name, or issued before the update, does not authenticate.</para>
    /// </remarks>
    /// <param name="token">Token from the invitation link.</param>
    /// <param name="ct">Request abort.</param>
    /// <response code="200">Invitation state.</response>
    /// <response code="400">Token malformed.</response>
    /// <response code="429"><c>rate_limited</c>.</response>
    /// <response code="502"><c>upstream_unavailable</c>. Refused before the operation when the session store failed technically while the session was read: ProblemDetails (<c>type</c> …/upstream-unavailable, <c>error = upstream_unavailable</c>); in the legacy trust-headers mode, for a trusted proxy with both identity headers, JSON <c>{ "error": "sso_unavailable", "message": … }</c> instead. No Set-Cookie.</response>
    [HttpGet("invitations/{token}")]
    [ProducesResponseType(typeof(InvitationPreviewResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status502BadGateway, "application/problem+json")]
    [SwaggerOperation(
        Summary = "Preview an invitation",
        Description =
            "Forwards to skein-api GET /ui/v1/auth/invitations/{token}. For a visitor without " +
            "a session; a logged-in tab uses GET /api/v1/invitations/{token}. Rate limit per " +
            "client IP only." +
            " Session cookie: __Host-skein.sid (skein.sid with the Development-only SKEIN_ALLOW_INSECURE_HTTP), Secure (not in that mode), HttpOnly, Path=/, no Domain, SameSite=Lax, whatever X-Forwarded-Proto says. Technical failure of the session store while reading the session → 502 before the operation (ProblemDetails error=upstream_unavailable; JSON error=sso_unavailable in the legacy trust-headers mode for a trusted proxy with both identity headers), no Set-Cookie.",
        OperationId = "GetInvitationPreview")]
    public async Task<ActionResult<InvitationPreviewResponse>> Invitation(
        [FromRoute, StringLength(512, MinimumLength = 1), SwaggerParameter("Token from the invitation link", Required = true)] string token,
        CancellationToken ct)
    {
        var clientIp = TrustedClientIp();
        if (!await _limiter.TryAcquireAsync(ActionRateLimiter.InvitationPreview, null, clientIp, ct))
        {
            return RateLimited();
        }

        return await RelayAsync(
            () => _api.InvitationPreviewAsync(token, clientIp, ct),
            HttpStatusCode.OK,
            ok =>
            {
                var body = Deserialize<InvitationPreviewResponse>(ok.Body);
                return Task.FromResult<ActionResult>(body?.Status is null
                    ? UpstreamBroken("invitation-preview", "200 without status")
                    : Ok(body));
            },
            "invitation-preview",
            ct);
    }

    /// <summary>Register by invitation and log in.</summary>
    /// <remarks>
    /// Rate limit: «invitation-signup + IP» (the email is the invitation's,
    /// unknown before the call). On skein-api's 200 the account (email
    /// confirmed), its personal space, the consent and the membership in the
    /// invitation's space exist; the BFF signs the user in and returns the user
    /// with the space for the redirect to <c>/spaces/&lt;id&gt;-&lt;slug&gt;</c>.
    /// Refusal codes: <c>signup_disabled</c>, <c>rate_limited</c>,
    /// <c>captcha_failed</c>, <c>space_deleted</c>, <c>invitation_invalid</c>,
    /// <c>terms_required</c>, <c>username_invalid</c>, <c>password_weak</c>,
    /// <c>password_pwned</c>, <c>email_taken</c>, <c>username_taken</c>
    /// (+ <c>suggestions</c>), <c>invalid_request</c>.
    /// <para>Session cookie: the session is read from <c>__Host-skein.sid</c> (<c>skein.sid</c> when the Development-only setting <c>SKEIN_ALLOW_INSECURE_HTTP</c> is on) — <c>Secure</c> (not in that mode), <c>HttpOnly</c>, <c>Path=/</c>, no <c>Domain</c>, <c>SameSite=Lax</c>, whatever <c>X-Forwarded-Proto</c> says. A cookie under the other name, or issued before the update, does not authenticate.</para>
    /// </remarks>
    /// <param name="token">Token from the invitation link.</param>
    /// <param name="req">Registration form.</param>
    /// <param name="ct">Request abort.</param>
    /// <response code="200">Registered, joined and logged in; the session cookie is set.</response>
    /// <response code="400">Body not of the declared shape.</response>
    /// <response code="422">Business refusal; code in <c>error</c>.</response>
    /// <response code="429"><c>rate_limited</c>.</response>
    /// <response code="502"><c>upstream_unavailable</c>. Refused before the operation when the session store failed technically while the session was read: ProblemDetails (<c>type</c> …/upstream-unavailable, <c>error = upstream_unavailable</c>). No Set-Cookie. Account created but no session issued (a confirmed answer that cannot yield a session, or a failed revocation or issue): ProblemDetails of type …/account-created-session-not-issued with error=upstream_unavailable and no Set-Cookie; the account exists and the new credentials work for a normal sign-in.</response>
    [HttpPost("invitations/{token}/signup")]
    [ExplicitSignIn(Surface.InvitationSignup)]
    [ProducesResponseType(typeof(InvitationSignupResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status422UnprocessableEntity)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status502BadGateway)]
    [SwaggerOperation(
        Summary = "Register by invitation",
        Description =
            "Forwards to skein-api POST /ui/v1/auth/invitations/{token}/signup. On success the " +
            "user is logged in (a new session key; the key the request carried is revoked first) and the joined space is returned for the " +
            "redirect. Rate limit per client IP only." +
            " Session cookie: __Host-skein.sid (skein.sid with the Development-only SKEIN_ALLOW_INSECURE_HTTP), Secure (not in that mode), HttpOnly, Path=/, no Domain, SameSite=Lax, whatever X-Forwarded-Proto says. Technical failure of the session store while reading the session → 502 ProblemDetails error=upstream_unavailable before the operation, no Set-Cookie.",
        OperationId = "InvitationSignup")]
    public async Task<ActionResult<InvitationSignupResponse>> InvitationSignup(
        [FromRoute, StringLength(512, MinimumLength = 1), SwaggerParameter("Token from the invitation link", Required = true)] string token,
        [FromBody, SwaggerRequestBody("Registration form", Required = true)] InvitationSignupRequest req,
        CancellationToken ct)
    {
        var clientIp = TrustedClientIp();
        if (!await _limiter.TryAcquireAsync(ActionRateLimiter.InvitationSignup, null, clientIp, ct))
        {
            return RateLimited();
        }

        return await RelayAsync(
            () => _api.InvitationSignupAsync(token, req, clientIp, ct),
            HttpStatusCode.OK,
            async ok =>
            {
                var body = Deserialize<InvitationSignupResponse>(ok.Body);
                if (body is null || body.Space is not { Id.Length: > 0, Slug.Length: > 0, Name.Length: > 0 })
                {
                    return SessionNotIssued("invitation-signup", "200 without the user or the space");
                }
                var invited = new UserDto(
                    body.Id, body.Email, body.Username, body.Name, body.Role,
                    body.CreatedAt, body.LastLoginAt, body.IsExternal);
                if (!IsIssuable(invited))
                {
                    return SessionNotIssued("invitation-signup", "200 without a usable user");
                }
                if (SessionEpochOf(ok) is not { } epoch)
                {
                    return SessionNotIssued("invitation-signup", "200 without sessionEpoch");
                }
                if (!await IssueNewSessionAsync(invited, epoch, nameof(Surface.InvitationSignup)))
                {
                    return SessionNotIssued("invitation-signup", "the session could not be issued");
                }
                _logger.LogInformation("invitation signup success for {UserId}", body.Id);
                return Ok(body);
            },
            "invitation-signup",
            ct);
    }

    // -- helpers -------------------------------------------------------------

    /// <summary>
    /// The client address for the IP bucket and <c>X-Skein-Client-Ip</c>:
    /// <c>RemoteIpAddress</c> as resolved by the ForwardedHeaders middleware
    /// from the trusted proxy chain — and null without a trusted proxy, when it
    /// is only the ingress's address (see <see cref="PublicAuthRoutes"/>).
    /// </summary>
    private string? TrustedClientIp() =>
        _apiOptions.ClientIpTrusted ? HttpContext.Connection.RemoteIpAddress?.ToString() : null;

    /// <summary>The user id of a confirmed reset answer, read on its own before any claim or epoch is looked at.</summary>
    private static Guid? ReadSubjectId(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.ValueKind == JsonValueKind.Object
                && doc.RootElement.TryGetProperty("id", out var id)
                && id.ValueKind == JsonValueKind.String
                && Guid.TryParse(id.GetString(), out var parsed)
                ? parsed
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// The local revocation after a confirmed reset (INV-13): the key the request carried, whoever owns
    /// it, then every ticket of the user found by the reverse index, and this replica's hub connections
    /// of the user — all with tokens that the request abort cannot cancel. False when the input key or
    /// any ticket could not be removed, or the index could not be read; the connections close anyway.
    /// </summary>
    private async Task<bool> EndSessionsAfterResetAsync(Guid userId)
    {
        var complete = true;
        try
        {
            await _issuer.RevokeIncomingAsync(HttpContext);
        }
        catch (SessionIssueException)
        {
            complete = false;
        }

        var result = await _sessions.RemoveSessionsAsync(userId, keepKey: null, CancellationToken.None);
        var closed = _hubConnections.AbortUserSessionsExcept(userId, keepSessionKey: null);
        if (!result.Complete)
        {
            complete = false;
        }

        using (_logger.BeginScope(new Dictionary<string, object>
        {
            ["userId"] = userId,
            ["ticketsRemoved"] = result.Removed,
            ["ticketsNotRemoved"] = result.Failed,
            ["userIndexRead"] = result.IndexRead,
            ["hubConnectionsClosed"] = closed,
        }))
        {
            if (complete)
            {
                _logger.LogInformation("password-reset-complete: the sessions of the user ended");
            }
            else
            {
                _logger.LogError("password-reset-complete: the sessions of the user could not all be removed; the password change is kept");
            }
        }
        return complete;
    }

    /// <summary>
    /// The password change is confirmed but no session is issued: a named outcome, distinct from "no
    /// confirmation of the change". The password and the spent token stay as they are.
    /// </summary>
    private ObjectResult PasswordChangedNotIssued(string what)
    {
        _issuer.MarkSessionWriteSuppressed(HttpContext);
        _logger.LogError("password-reset-complete: the password was changed but no session was issued ({What})", what);
        return Problem(
            statusCode: StatusCodes.Status502BadGateway,
            title: "Password changed, session not issued",
            detail: "The password was changed, but signing in failed. Sign in with the new password.",
            type: "https://skein.local/errors/password-changed-session-not-issued",
            extensions: new Dictionary<string, object?> { ["error"] = "upstream_unavailable" });
    }

    /// <summary>Whether the user of a confirmed answer carries everything a session principal needs.</summary>
    private static bool IsIssuable(UserDto? user) =>
        user is { Id: not null, Email: not null, Username: not null, Name: not null, Role: not null } && Guid.TryParse(user.Id, out _);

    /// <summary>
    /// Issues the session of a just created account under a NEW key; the key the request carried is
    /// revoked first. False when the revocation or the issue failed, with no cookie written.
    /// </summary>
    private async Task<bool> IssueNewSessionAsync(UserDto user, long epoch, string surface)
    {
        try
        {
            await _issuer.RotateAsync(
                HttpContext,
                SessionPrincipal.Create(user, epoch),
                new AuthenticationProperties { IsPersistent = true, AllowRefresh = true },
                surface);
            return true;
        }
        catch (SessionIssueException)
        {
            return false;
        }
    }

    /// <summary>
    /// The account exists but no session can be issued: a named outcome, neither a success nor the
    /// generic upstream failure. The new credentials work for a normal sign-in.
    /// </summary>
    private ObjectResult SessionNotIssued(string action, string what)
    {
        // The request's own session must not be renewed late next to this refusal.
        _issuer.MarkSessionWriteSuppressed(HttpContext);
        _logger.LogError("{Action}: the account was created but no session was issued ({What})", action, what);
        return Problem(
            statusCode: StatusCodes.Status502BadGateway,
            title: "Account created, session not issued",
            detail: "The account was created, but signing it in failed. Sign in with the new credentials.",
            type: "https://skein.local/errors/account-created-session-not-issued",
            extensions: new Dictionary<string, object?> { ["error"] = "upstream_unavailable" });
    }

    /// <summary>
    /// Calls skein-api and maps its answer. Success is ONLY the status the T012
    /// contract names for the route (<paramref name="success"/>): any other
    /// 2xx — an empty 200 where 204 is due, a gateway's HTML 200 — is outside
    /// the contract and answered 502 like an unreachable upstream, never
    /// passed off as success. A 200 body is further checked by
    /// <paramref name="onSuccess"/>.
    /// </summary>
    private async Task<ActionResult> RelayAsync(
        Func<Task<AccountApiResult>> call,
        HttpStatusCode success,
        Func<AccountApiResult, Task<ActionResult>> onSuccess,
        string action,
        CancellationToken ct)
    {
        AccountApiResult result;
        try
        {
            result = await call();
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Client went away — not an error.
            return new EmptyResult();
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
        {
            _logger.LogError(ex, "{Action}: skein-api unavailable", action);
            return UpstreamUnavailable();
        }

        var status = (int)result.Status;
        if (result.Status == success)
        {
            return await onSuccess(result);
        }

        if (result.Status is HttpStatusCode.BadRequest or HttpStatusCode.UnprocessableEntity or HttpStatusCode.TooManyRequests)
        {
            var refusal = Deserialize<ApiRefusal>(result.Body);
            if (!string.IsNullOrEmpty(refusal?.Error))
            {
                _logger.LogInformation("{Action}: refused by skein-api ({Status} {Code})", action, status, refusal.Error);
                var extensions = new Dictionary<string, object?> { ["error"] = refusal.Error };
                if (refusal.Error == AccountErrorCode.UsernameTaken && refusal.Suggestions is not null)
                {
                    extensions["suggestions"] = refusal.Suggestions;
                }
                return Problem(
                    statusCode: status,
                    title: "Request refused",
                    detail: refusal.Message,
                    type: "https://skein.local/errors/" + refusal.Error.Replace('_', '-'),
                    extensions: extensions);
            }
        }

        return UpstreamBroken(action, $"status {status}");
    }

    private ObjectResult RateLimited() => Problem(
        statusCode: StatusCodes.Status429TooManyRequests,
        title: "Too many requests",
        detail: "Too many requests for this action. Try again in a few minutes.",
        type: "https://skein.local/errors/rate-limited",
        extensions: new Dictionary<string, object?> { ["error"] = AccountErrorCode.RateLimited });

    private ObjectResult UpstreamBroken(string action, string what)
    {
        _logger.LogError("{Action}: skein-api answered outside the contract ({What})", action, what);
        return UpstreamUnavailable();
    }

    private ObjectResult UpstreamUnavailable() => Problem(
        statusCode: StatusCodes.Status502BadGateway,
        title: "Account service unavailable",
        detail: "The account service is temporarily unavailable. Try again in a moment.",
        type: "https://skein.local/errors/upstream-unavailable",
        extensions: new Dictionary<string, object?> { ["error"] = "upstream_unavailable" });

    private static T? Deserialize<T>(string body) where T : class
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return null;
        }
        try
        {
            return JsonSerializer.Deserialize<T>(body, JsonOpts);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>The REQUIRED <c>sessionEpoch</c> of an authentication response (K-16); null when absent.</summary>
    private static long? SessionEpochOf(AccountApiResult ok) => Deserialize<EpochBody>(ok.Body)?.SessionEpoch;

    private sealed record EpochBody(long? SessionEpoch);

    /// <summary>skein-api refusal body: <c>{"error","message"}</c>, plus <c>suggestions</c> on <c>username_taken</c>.</summary>
    private sealed record ApiRefusal(string? Error, string? Message, IReadOnlyList<string>? Suggestions);
}
