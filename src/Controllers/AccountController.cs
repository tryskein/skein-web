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
/// login does (<see cref="SessionPrincipal"/>, cookie <c>skein.sid</c>,
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
    private readonly ILogger<AccountController> _logger;

    public AccountController(
        SkeinAccountsApiClient api,
        ActionRateLimiter limiter,
        IOptions<SkeinApiOptions> apiOptions,
        IUserSessionRevoker sessions,
        ConnectionRegistry hubConnections,
        ILogger<AccountController> logger)
    {
        _api = api;
        _limiter = limiter;
        _apiOptions = apiOptions.Value;
        _sessions = sessions;
        _hubConnections = hubConnections;
        _logger = logger;
    }

    /// <summary>Register an account and log in.</summary>
    /// <remarks>
    /// Rate limit: «signup + email» and «signup + IP». On skein-api's 200 the
    /// account, its personal space and the consent record exist and a
    /// confirmation email is queued (skein-api side); the BFF then signs the
    /// user in (Set-Cookie <c>skein.sid</c>) and returns the user.
    /// Refusal codes: <c>signup_disabled</c>, <c>rate_limited</c>,
    /// <c>captcha_failed</c>, <c>terms_required</c>, <c>username_invalid</c>,
    /// <c>password_weak</c>, <c>password_pwned</c>, <c>email_taken</c>,
    /// <c>username_taken</c> (+ <c>suggestions</c>), <c>invalid_request</c>.
    /// </remarks>
    /// <param name="req">Registration form.</param>
    /// <param name="ct">Request abort.</param>
    /// <response code="200">Registered and logged in; body is the user, the session cookie is set.</response>
    /// <response code="400">Body not of the declared shape (BFF) or <c>invalid_request</c> (skein-api).</response>
    /// <response code="422">Business refusal; code in <c>error</c>.</response>
    /// <response code="429"><c>rate_limited</c> — BFF limiter or skein-api backstop.</response>
    /// <response code="502"><c>upstream_unavailable</c> — skein-api unreachable or answered outside the contract.</response>
    [HttpPost("signup")]
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status422UnprocessableEntity)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status502BadGateway)]
    [SwaggerOperation(
        Summary = "Register an account (self-service signup)",
        Description =
            "Forwards the form to skein-api POST /api/v1/auth/signup (no identity headers). " +
            "On success the user is logged in exactly as after POST /api/auth/login " +
            "(skein.sid cookie) and the user is returned. Rate limit per lower-cased email " +
            "and per client IP (IP only behind a trusted proxy): exceeded → 429 rate_limited " +
            "without calling skein-api. Refusals are ProblemDetails with the skein-api code in " +
            "'error'; username_taken adds 'suggestions'.",
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
                if (user?.Id is null)
                {
                    return UpstreamBroken("signup", "200 without a user");
                }
                if (SessionEpochOf(ok) is not { } epoch)
                {
                    return UpstreamBroken("signup", "200 without sessionEpoch — no session issued");
                }
                await SignInAsync(user, epoch);
                _logger.LogInformation("signup success for {UserId}", user.Id);
                return Ok(user);
            },
            "signup",
            ct);
    }

    /// <summary>Suggest free usernames derived from an email.</summary>
    /// <remarks>
    /// Rate limit: «username-suggestions + email» and «… + IP». Refusal codes:
    /// <c>signup_disabled</c>, <c>rate_limited</c>, <c>invalid_request</c>.
    /// </remarks>
    /// <param name="email">Email whose local part seeds the suggestions.</param>
    /// <param name="ct">Request abort.</param>
    /// <response code="200">2–3 usernames free at the moment of the answer.</response>
    /// <response code="400">Email missing or malformed.</response>
    /// <response code="422">Business refusal; code in <c>error</c>.</response>
    /// <response code="429"><c>rate_limited</c>.</response>
    /// <response code="502"><c>upstream_unavailable</c>.</response>
    [HttpGet("username-suggestions")]
    [ProducesResponseType(typeof(UsernameSuggestionsResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status422UnprocessableEntity)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status502BadGateway)]
    [SwaggerOperation(
        Summary = "Suggest usernames from an email",
        Description =
            "Forwards to skein-api GET /api/v1/auth/username-suggestions. Rate limit per " +
            "lower-cased email and per client IP; exceeded → 429 rate_limited.",
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
    /// </remarks>
    /// <param name="req">Email and the interface language of the email.</param>
    /// <param name="ct">Request abort.</param>
    /// <response code="204">Accepted (neutral).</response>
    /// <response code="400">Body not of the declared shape.</response>
    /// <response code="422">Business refusal; code in <c>error</c>.</response>
    /// <response code="429"><c>rate_limited</c>.</response>
    /// <response code="502"><c>upstream_unavailable</c>.</response>
    [HttpPost("password-reset")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status422UnprocessableEntity)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status502BadGateway)]
    [SwaggerOperation(
        Summary = "Request a password reset",
        Description =
            "Forwards to skein-api POST /api/v1/auth/password-reset; 204 whether or not the " +
            "account exists. Rate limit per lower-cased email and per client IP.",
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
    /// session epoch — every session of the user ends, API keys keep working —
    /// and answers with the authentication response carrying the NEW epoch.
    /// The BFF answers 204 and, only when this request carries a session of
    /// the SAME user the token belongs to, re-issues that session with the
    /// new epoch (same session id, Set-Cookie): the tab that reset its own
    /// password stays logged in, every other session of the user is refused by
    /// skein-api from now on (INV-26 "except the current one", plan K-16). Without a
    /// session, or with a session of another user, no session is issued or
    /// changed — another user's session is never turned into the token owner's.
    /// Refusal codes: <c>password_login_disabled</c>, <c>email_disabled</c>,
    /// <c>rate_limited</c>, <c>token_invalid</c>, <c>password_weak</c>,
    /// <c>password_pwned</c>, <c>invalid_request</c>.
    /// </remarks>
    /// <param name="token">Token from the reset link.</param>
    /// <param name="req">The new password.</param>
    /// <param name="ct">Request abort.</param>
    /// <response code="204">Password set; the current session re-issued only if it belongs to the token's user.</response>
    /// <response code="400">Body not of the declared shape.</response>
    /// <response code="422">Business refusal; code in <c>error</c>.</response>
    /// <response code="429"><c>rate_limited</c>.</response>
    /// <response code="502"><c>upstream_unavailable</c>.</response>
    [HttpPost("password-reset/{token}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status422UnprocessableEntity)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status502BadGateway)]
    [SwaggerOperation(
        Summary = "Complete a password reset",
        Description =
            "Forwards to skein-api POST /api/v1/auth/password-reset/{token}; 204 on success. " +
            "Every session of the user ends; if this request carries a session of the same " +
            "user, that session is re-issued with the new session epoch (Set-Cookie) and stays " +
            "logged in; a session of another user is left as it is. The user's other session " +
            "tickets are removed and this replica's hub connections of those sessions are " +
            "closed (other replicas close theirs on the next access re-check, within 30 s). " +
            "Rate limit per client IP only.",
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
                // T012: 200 AuthResponse with the NEW epoch. A body without the
                // user or the epoch is outside the contract — 502, not a 204
                // that would hide it (the password is set either way; the
                // session is not re-issued).
                var user = Deserialize<UserDto>(ok.Body);
                if (user?.Id is null || SessionEpochOf(ok) is not { } epoch)
                {
                    return UpstreamBroken("password-reset-complete", "200 without the user or sessionEpoch — no session re-issued");
                }
                var kept = await ReissueSameUserSessionAsync(user, epoch);
                await EndOtherSessionsAsync(user, kept);
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
    /// </remarks>
    /// <param name="token">Token from the confirmation email.</param>
    /// <param name="ct">Request abort.</param>
    /// <response code="204">Email confirmed (also when it already was).</response>
    /// <response code="400">Token malformed.</response>
    /// <response code="422">Business refusal; code in <c>error</c>.</response>
    /// <response code="429"><c>rate_limited</c>.</response>
    /// <response code="502"><c>upstream_unavailable</c>.</response>
    [HttpPost("confirm-email/{token}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status422UnprocessableEntity)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status502BadGateway)]
    [SwaggerOperation(
        Summary = "Confirm an email address",
        Description =
            "Forwards to skein-api POST /api/v1/auth/confirm-email/{token}; 204 on success. " +
            "Rate limit per client IP only.",
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
    /// </remarks>
    /// <param name="token">Token from the invitation link.</param>
    /// <param name="ct">Request abort.</param>
    /// <response code="200">Invitation state.</response>
    /// <response code="400">Token malformed.</response>
    /// <response code="429"><c>rate_limited</c>.</response>
    /// <response code="502"><c>upstream_unavailable</c>.</response>
    [HttpGet("invitations/{token}")]
    [ProducesResponseType(typeof(InvitationPreviewResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status502BadGateway)]
    [SwaggerOperation(
        Summary = "Preview an invitation",
        Description =
            "Forwards to skein-api GET /api/v1/auth/invitations/{token}. For a visitor without " +
            "a session; a logged-in tab uses GET /api/v1/invitations/{token}. Rate limit per " +
            "client IP only.",
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
    /// </remarks>
    /// <param name="token">Token from the invitation link.</param>
    /// <param name="req">Registration form.</param>
    /// <param name="ct">Request abort.</param>
    /// <response code="200">Registered, joined and logged in; the session cookie is set.</response>
    /// <response code="400">Body not of the declared shape.</response>
    /// <response code="422">Business refusal; code in <c>error</c>.</response>
    /// <response code="429"><c>rate_limited</c>.</response>
    /// <response code="502"><c>upstream_unavailable</c>.</response>
    [HttpPost("invitations/{token}/signup")]
    [ProducesResponseType(typeof(InvitationSignupResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status422UnprocessableEntity)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status502BadGateway)]
    [SwaggerOperation(
        Summary = "Register by invitation",
        Description =
            "Forwards to skein-api POST /api/v1/auth/invitations/{token}/signup. On success the " +
            "user is logged in (skein.sid cookie) and the joined space is returned for the " +
            "redirect. Rate limit per client IP only.",
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
                if (body?.Id is null || body.Space is null)
                {
                    return UpstreamBroken("invitation-signup", "200 without the user or the space");
                }
                if (SessionEpochOf(ok) is not { } epoch)
                {
                    return UpstreamBroken("invitation-signup", "200 without sessionEpoch — no session issued");
                }
                await SignInAsync(
                    new UserDto(
                        body.Id, body.Email, body.Username, body.Name, body.Role,
                        body.CreatedAt, body.LastLoginAt, body.IsExternal),
                    epoch);
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

    /// <summary>
    /// Re-issues the current session after a successful password reset (plan
    /// K-16): only when the request is authenticated AND its user is the one
    /// the reset response names. The cookie handler renews the SAME session
    /// key with the new principal, so the browser keeps its session id and
    /// only the epoch (and any refreshed field) changes.
    /// </summary>
    /// <returns>Whether a session of the user was re-issued, and its ticket key
    /// (null for a session minted before keys were stamped into tickets).</returns>
    private async Task<KeptSession> ReissueSameUserSessionAsync(UserDto user, long epoch)
    {
        if (User.Identity is not { IsAuthenticated: true })
        {
            return new KeptSession(false, null);
        }
        var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!string.Equals(currentUserId, user.Id, StringComparison.OrdinalIgnoreCase))
        {
            // Another user's tab: leave its session alone.
            return new KeptSession(false, null);
        }
        var key = SessionPrincipal.SessionKeyOf(User);
        await SignInAsync(user, epoch);
        _logger.LogInformation("password-reset-complete: current session of {UserId} re-issued with the new epoch", user.Id);
        return new KeptSession(true, key);
    }

    /// <summary>The outcome of <see cref="ReissueSameUserSessionAsync"/>.</summary>
    private sealed record KeptSession(bool Reissued, string? Key);

    /// <summary>
    /// Ends the user's other sessions after a successful reset (INV-26): their
    /// tickets are removed, and this replica's hub connections of them are
    /// closed at once — skein-api already refuses them (new epoch), and a
    /// connection of a removed ticket is closed on every other replica by the
    /// access re-check. Every session read from the store knows its ticket key
    /// (<see cref="RedisTicketStore.RetrieveAsync"/> adds it to tickets of an
    /// earlier release); should a re-issued session still lack one, it cannot be
    /// told apart from the others and every session of the user ends, the
    /// current one included — the user logs in again with the new password.
    /// <para>A removal that does not complete — the user's index unreadable or a
    /// ticket undeletable after the store's retries — is logged as an Error
    /// with the user id and the count left, and the route still answers 204:
    /// skein-api has already set the password and moved the session epoch, and
    /// the reset token is spent, so failing the request would only hide that
    /// success. The tickets left stay in the user's index for a later
    /// revocation; skein-api refuses every request of those sessions (old
    /// epoch), and a hub connection of a ticket that disappears later is closed
    /// by the access re-check.</para>
    /// </summary>
    private async Task EndOtherSessionsAsync(UserDto user, KeptSession kept)
    {
        if (!Guid.TryParse(user.Id, out var userId))
        {
            return;
        }
        if (kept.Reissued && kept.Key is null)
        {
            _logger.LogWarning(
                "password-reset-complete: re-issued session of {UserId} has no ticket key, every session of the user ends",
                user.Id);
        }
        // Past the point of no return: the password is set, the epoch moved.
        var result = await _sessions.RemoveSessionsAsync(userId, kept.Key, CancellationToken.None);
        var closed = _hubConnections.AbortUserSessionsExcept(userId, kept.Key);
        if (!result.Complete)
        {
            using (_logger.BeginScope(new Dictionary<string, object>
            {
                ["userId"] = user.Id,
                ["ticketsRemoved"] = result.Removed,
                ["ticketsNotRemoved"] = result.Failed,
                ["userIndexRead"] = result.IndexRead,
                ["hubConnectionsClosed"] = closed,
            }))
            {
                _logger.LogError(
                    "password-reset-complete: the user's other sessions could not all be removed; password reset kept");
            }
            return;
        }
        _logger.LogInformation(
            "password-reset-complete: other sessions of {UserId} ended tickets={Removed} hubConnections={Closed}",
            user.Id, result.Removed, closed);
    }

    private async Task SignInAsync(UserDto user, long sessionEpoch)
    {
        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            SessionPrincipal.Create(user, sessionEpoch),
            new AuthenticationProperties
            {
                IsPersistent = true,
                AllowRefresh = true,
            });
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
