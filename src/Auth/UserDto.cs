using System.ComponentModel.DataAnnotations;

namespace SkeinWeb.Auth;

/// <summary>
/// Public representation of a user as returned by the BFF. Mirrors the
/// JSON shape produced by skein-api so a successful login round-trips
/// without reshaping. Server-side fields (CreatedAt, LastLoginAt) come
/// only from skein-api responses; the cookie principal does not carry
/// them, so /api/auth/me leaves them null and clients that need fresh
/// values should hit /api/v1/auth/me through the proxy.
/// </summary>
/// <param name="Id">User unique identifier (UUID v4).</param>
/// <param name="Email">Lower-cased email address used for login.</param>
/// <param name="Username">URL-safe handle (immutable; unique).</param>
/// <param name="Name">Display name shown in the UI.</param>
/// <param name="Role">Authorisation role: <c>admin</c> or <c>user</c>.</param>
/// <param name="CreatedAt">Account creation timestamp; null when not available from cookie principal.</param>
/// <param name="LastLoginAt">Last successful login timestamp; null when never logged in or unavailable.</param>
/// <param name="IsExternal">
/// External-collaborator flag (sk-163). <c>true</c> = an external user
/// (role is always <c>user</c>; never admin/owner). Defaults to
/// <c>false</c> so existing call sites and JSON payloads that omit the
/// field deserialize as internal — the safe default until later slices
/// enforce the ceiling.
/// </param>
public sealed record UserDto(
    string Id,
    string Email,
    string Username,
    string Name,
    string Role,
    DateTimeOffset? CreatedAt,
    DateTimeOffset? LastLoginAt,
    bool IsExternal = false);

/// <summary>
/// Request body for <c>POST /api/auth/login</c>. Validation runs on the
/// BFF before reaching skein-api so malformed payloads never consume an
/// internal-secret round-trip.
/// </summary>
/// <param name="Email">User email address. Compared case-insensitively.</param>
/// <param name="Password">Plaintext password — verified by skein-api via bcrypt.</param>
public sealed record LoginRequest(
    [Required, EmailAddress, StringLength(320, MinimumLength = 3)] string Email,
    [Required, StringLength(200, MinimumLength = 1)] string Password);

/// <summary>
/// Outcome of a <c>POST /api/v1/auth/login</c> call as translated by
/// <see cref="SkeinApiClient.LoginAsync"/> (sk-163 S4b). Distinguishes the
/// status codes the controller must branch on per auth-mode, so the
/// controller never has to inspect raw <see cref="System.Net.HttpStatusCode"/>.
/// </summary>
public enum LoginOutcome
{
    /// <summary>200 — credentials verified; <see cref="LoginResult.User"/> set.</summary>
    Success,

    /// <summary>
    /// 422 — generic invalid credentials. Also the bucket the API uses for an
    /// internal account attempting password login in hybrid mode (collapsed
    /// with wrong-password by S4a's anti-enumeration design).
    /// </summary>
    InvalidCredentials,

    /// <summary>410 — standalone password login retired (keycloak, non-break-glass).</summary>
    Disabled,

    /// <summary>403 — account must use SSO (defensive; not currently emitted by S4a login).</summary>
    SsoRequired,
}

/// <summary>
/// Result of <see cref="SkeinApiClient.LoginAsync"/> — an
/// <see cref="LoginOutcome"/> plus the authenticated <see cref="UserDto"/>
/// (non-null only when <see cref="Outcome"/> is
/// <see cref="LoginOutcome.Success"/>).
/// </summary>
/// <param name="Outcome">The translated status outcome.</param>
/// <param name="User">Authenticated user; non-null iff Success.</param>
/// <param name="SessionEpoch">
/// sk-674.18 K-16 — the <c>sessionEpoch</c> of skein-api's authentication
/// response (<c>internal/accounts/contract.go#AuthResponse</c>), REQUIRED on
/// success; <c>null</c> when the response did not carry it, which the caller
/// treats as a login failure (no session, no fallback to an older value or a
/// default).
/// </param>
public sealed record LoginResult(LoginOutcome Outcome, UserDto? User, long? SessionEpoch = null)
{
    /// <summary>Shared singleton for the 422 invalid-credentials outcome.</summary>
    public static readonly LoginResult InvalidCredentials = new(LoginOutcome.InvalidCredentials, null);

    /// <summary>Shared singleton for the 410 disabled outcome.</summary>
    public static readonly LoginResult Disabled = new(LoginOutcome.Disabled, null);

    /// <summary>Shared singleton for the 403 sso-required outcome.</summary>
    public static readonly LoginResult SsoRequired = new(LoginOutcome.SsoRequired, null);

    /// <summary>Build a Success result carrying the authenticated user and the epoch as answered.</summary>
    public static LoginResult Success(UserDto user, long? sessionEpoch) => new(LoginOutcome.Success, user, sessionEpoch);
}

/// <summary>
/// A user skein-api has just authenticated — OIDC provisioning
/// (<c>POST /api/v1/auth/oidc/provision</c>) — together with the
/// <c>sessionEpoch</c> of the authentication response (sk-674.18 K-16).
/// </summary>
/// <param name="User">The user.</param>
/// <param name="SessionEpoch">The epoch as answered; <c>null</c> = the response
/// lacked the REQUIRED field — no session may be issued from it.</param>
public sealed record AuthenticatedUser(UserDto User, long? SessionEpoch);

/// <summary>
/// Response body for <c>POST /api/auth/logout</c>. In keycloak mode the
/// <see cref="RedirectTo"/> field carries the URL the SPA should
/// navigate to next (typically <c>/oauth2/sign_out</c>) so the
/// oauth2-proxy cookie is cleared and the upstream Keycloak session
/// ends. In local mode the field is null; the SPA can ignore it.
/// </summary>
/// <param name="RedirectTo">
/// URL to navigate to after the local cookie is cleared, or null if no
/// further action is required.
/// </param>
public sealed record LogoutResponse(string? RedirectTo);

/// <summary>
/// Response body for <c>GET /api/auth/config</c>. Read by the SPA at
/// boot to choose the right login experience (password form in local
/// mode; "Login via Keycloak" button in keycloak mode; BOTH in hybrid
/// mode) and to gate admin UI (e.g. disable "+ New user" when users
/// auto-provision via SSO).
/// </summary>
/// <remarks>
/// sk-303.8 — this record used to carry a second field, <c>IsExternalHost</c>,
/// derived from a Host-header allowlist (S7a <c>SKEIN_INTERNAL_HOSTS</c>) that
/// was removed: it derived a privilege/UI signal from a header the client
/// controls, and never actually divided anything in this deployment (both
/// routes to skein-web go through the internal gateway; there is no public
/// route). The field is gone rather than hardened — see
/// <c>McpProxyMiddleware</c> for the fuller rationale and for where to build
/// this kind of boundary again (on a server-controlled signal, e.g. listener
/// port) if a public surface ever ships.
/// <para>
/// sk-674.18 (US-18, D-7, K-14): the six behaviour fields above are NOT
/// kept by skein-web. Every <c>GET /api/auth/config</c> reads them from
/// skein-api (<c>GET /api/v1/internal/instance-config</c>,
/// <c>internal/accounts/contract.go#InstanceConfig</c>), so a restart of
/// skein-api alone with a new value changes this response without a
/// restart of skein-web; skein-api unavailable → 503 instead of a stale or
/// default value. <c>authMode</c> is the mode skein-web took from skein-api
/// at its start (changing it needs a restart of both services). Wire form:
/// <c>{"authMode":"local","logoutRedirectUrl":null,"mcpUrl":null,"signupEnabled":true,"emailEnabled":true,"turnstileSiteKey":"0x4AAAAAAA","projectPrefixMinLength":3,"termsUrl":"https://skein.example.com/terms","privacyUrl":null}</c>
/// — every key always present, <c>null</c> meaning "not configured". The six
/// fields have no defaults: whoever builds this record states every value.
/// </para>
/// </remarks>
/// <param name="AuthMode">
/// One of <c>"local"</c>, <c>"keycloak"</c>, or <c>"hybrid"</c> (sk-163
/// S4b), always lower-case so the SPA can compare without normalising.
/// <list type="bullet">
///   <item><c>local</c> — password form only.</item>
///   <item><c>keycloak</c> — SSO button only (legacy trust-headers OR
///         native OIDC; the SPA does not care which).</item>
///   <item><c>hybrid</c> — SSO is active but the password channel is also
///         open for external collaborators; the SPA renders BOTH the SSO
///         button and the password form.</item>
/// </list>
/// </param>
/// <param name="LogoutRedirectUrl">
/// sk-303.42 — the ONE absolute URL the SPA is allowed to navigate to when
/// <c>POST /api/auth/logout</c> hands back a <c>redirectTo</c>, or
/// <c>null</c> when this deployment has no external session to terminate.
/// Read from <c>Authentication:LogoutRedirectUrl</c>.
/// <para>
/// It exists so the client's redirect allow-list is a DEPLOYMENT fact rather
/// than a compiled-in constant. The SPA previously accepted exactly one
/// hard-coded host, so any other install's sign-out URL was rejected — and
/// rejected quietly, leaving the external session alive behind a logout that
/// looked successful.
/// </para>
/// </param>
/// <param name="McpUrl">
/// sk-303.42 — absolute URL of the MCP endpoint for the <c>.mcp.json</c>
/// snippet on the Api Keys page, or <c>null</c> when MCP is served from this
/// same origin (the SPA then builds <c>&lt;origin&gt;/mcp</c>). Read from
/// <c>SKEIN_MCP_URL</c>. Replaces a client-side derivation that rewrote a
/// known host prefix into a sibling host — right for one deployment, wrong
/// for every other install that shared the prefix.
/// </param>
/// <param name="SignupEnabled">
/// sk-674.18 US-18, T044 — self-service registration is open
/// (<c>SKEIN_SIGNUP_ENABLED</c> of skein-api). <c>false</c> = the SPA shows no
/// registration link and the signup screens tell the visitor honestly that
/// registration is closed. Always present.
/// </param>
/// <param name="EmailEnabled">
/// sk-674.18 US-9 — outgoing mail works (<c>SKEIN_EMAIL_ENABLED</c>).
/// <c>false</c> = no "Forgot password?" link, the reset and confirmation
/// screens show the honest text, and accepting an invitation from Inbox does
/// not require a confirmed email. Always present.
/// </param>
/// <param name="TurnstileSiteKey">
/// sk-674.18 US-8 — public Cloudflare Turnstile site key for the registration
/// captcha (<c>SKEIN_TURNSTILE_SITE_KEY</c>); <c>null</c> = no captcha, the
/// signup form sends no <c>turnstileToken</c>.
/// </param>
/// <param name="ProjectPrefixMinLength">
/// sk-674.18 US-15 — minimum length of a new project id prefix
/// (<c>SKEIN_PROJECT_PREFIX_MIN_LENGTH</c>); <c>null</c> = no minimum.
/// </param>
/// <param name="TermsUrl">
/// sk-674.18 US-8 — terms of service linked from the consent checkbox
/// (<c>SKEIN_TERMS_URL</c>); <c>null</c> = the consent label is plain text.
/// </param>
/// <param name="PrivacyUrl">
/// sk-674.18 US-8 — privacy policy linked from the consent checkbox
/// (<c>SKEIN_PRIVACY_URL</c>); <c>null</c> = the consent label is plain text.
/// </param>
public sealed record AuthConfigResponse(
    string AuthMode,
    string? LogoutRedirectUrl,
    string? McpUrl,
    bool SignupEnabled,
    bool EmailEnabled,
    string? TurnstileSiteKey,
    int? ProjectPrefixMinLength,
    string? TermsUrl,
    string? PrivacyUrl);

// ---------------------------------------------------------------------------
// Public account routes of the BFF (spec sk-674.18 US-8, US-9, US-5; plan K-17,
// T044). Browser-facing contract with skein-frontend: paths, bodies, codes and
// the rate-limit keys below are stable; additive changes only. The handlers
// are T047 (routes, rate limiter) and T048 (session epoch); the skein-api side
// is internal/accounts/contract.go (T012).
// ---------------------------------------------------------------------------

/// <summary>
/// Paths of the public account routes of the BFF (plan K-17). They are the
/// ONLY routes besides <c>POST /api/auth/login</c> and
/// <c>GET /api/auth/config</c> reachable without a session; <c>/api/v1/*</c>
/// without a session stays 401.
/// </summary>
/// <remarks>
/// <para><b>Routes.</b></para>
/// <list type="table">
///   <listheader><term>Route</term><description>Body → success</description></listheader>
///   <item><term><c>POST /api/auth/signup</c></term>
///         <description><see cref="SignupRequest"/> → 200 <see cref="UserDto"/>; the user is logged in (Set-Cookie <c>skein.sid</c>) exactly as after <c>POST /api/auth/login</c>.</description></item>
///   <item><term><c>GET /api/auth/username-suggestions?email=</c></term>
///         <description>→ 200 <see cref="UsernameSuggestionsResponse"/> ("Generate from email").</description></item>
///   <item><term><c>POST /api/auth/password-reset</c></term>
///         <description><see cref="PasswordResetRequest"/> → 204, NEUTRAL: identical whether or not an account with the email exists.</description></item>
///   <item><term><c>POST /api/auth/password-reset/{token}</c></term>
///         <description><see cref="PasswordResetCompleteRequest"/> → 204 with no body. The password is set and every other session of the user ends (API keys keep working). If the request carried a session of the SAME user the token belongs to, that session is re-issued with the new session epoch (Set-Cookie) and stays logged in; without a session, or with a session of another user, no session is issued or changed — the other user's session is NOT turned into the token owner's — and the SPA sends the visitor to <c>/login</c>.</description></item>
///   <item><term><c>POST /api/auth/confirm-email/{token}</c></term>
///         <description>No body → 204: the email of the token's account is confirmed. No session is issued or changed.</description></item>
///   <item><term><c>GET /api/auth/invitations/{token}</c></term>
///         <description>→ 200 <see cref="InvitationPreviewResponse"/> — every invitation state is a 200. For a visitor WITHOUT a session; a logged-in tab uses <c>GET /api/v1/invitations/{token}</c> through the proxy (spaces contract), which also accepts and declines.</description></item>
///   <item><term><c>POST /api/auth/invitations/{token}/signup</c></term>
///         <description><see cref="InvitationSignupRequest"/> → 200 <see cref="InvitationSignupResponse"/>; the user is logged in (Set-Cookie) as after a password login and the SPA redirects to <c>/spaces/&lt;space.id&gt;-&lt;space.slug&gt;</c>.</description></item>
/// </list>
/// <para><b>Refusals.</b> One frame for every refusal: RFC 7807
/// <c>ProblemDetails</c> (<c>application/problem+json</c>) carrying the
/// machine code in the extension member <c>error</c> — the frame of
/// <c>POST /api/auth/login</c>'s refusals. The SPA branches on <c>error</c>
/// (and on the status); <c>title</c> and <c>detail</c> are prose for logs and
/// may change. Example:
/// <c>{"type":"https://skein.local/errors/rate-limited","title":"Too many requests","status":429,"detail":"…","error":"rate_limited"}</c>.</para>
/// <list type="bullet">
///   <item>400 <c>ValidationProblemDetails</c> without <c>error</c> — the body
///         is not of the declared shape (a required field missing, an email
///         not of email shape, an unknown <c>language</c>); answered by the
///         BFF before skein-api is called. The BFF puts no length or content
///         rule on a username or a password: those are skein-api's, each
///         refused once with its own code (<c>username_invalid</c>,
///         <c>password_weak</c>).</item>
///   <item>422 / 400 / 429 with the code skein-api gave — the codes each route
///         may return are those listed at its route in
///         <c>internal/accounts/contract.go</c> (see
///         <see cref="AccountErrorCode"/>). <see cref="AccountErrorCode.UsernameTaken"/>
///         adds the extension member <c>suggestions</c>: an array of 2–3 free
///         usernames.</item>
///   <item>429 <see cref="AccountErrorCode.RateLimited"/> from the BFF's own
///         limiter, without calling skein-api — the same frame and code as the
///         login throttle's 429.</item>
///   <item>502 <c>ProblemDetails</c> — skein-api unreachable (as for login).</item>
/// </list>
/// <para><b>Rate-limit keys (BFF, Redis).</b> Every request to a route counts,
/// successful or not. A key is always «action + one axis»; the action is the
/// route, so exhausting one route never limits another. Request fields other
/// than the email — username, password, terms flag, captcha token, language —
/// and the <c>{token}</c> of the path are never part of a key.</para>
/// <list type="bullet">
///   <item><b>Routes with an email in the input</b> — <c>/signup</c>
///         (body <c>email</c>), <c>/password-reset</c> (body <c>email</c>),
///         <c>/username-suggestions</c> (query <c>email</c>): two independent
///         buckets, «action + lower-cased email» and «action + client IP»;
///         either exhausted → 429.</item>
///   <item><b>Routes without an email in the input</b> —
///         <c>/password-reset/{token}</c>, <c>/confirm-email/{token}</c>,
///         <c>GET /invitations/{token}</c>, <c>/invitations/{token}/signup</c>
///         (its email is the invitation's, unknown to the BFF before the
///         call): one bucket, «action + client IP».</item>
///   <item>IP buckets exist only when a trusted proxy is configured
///         (<c>SKEIN_TRUSTED_PROXIES</c>), as for login: without one the
///         client address seen by the BFF is the ingress's, and a bucket keyed
///         on it would let anyone lock the whole installation out. Without a
///         trusted proxy there are NO IP buckets on either side — the BFF
///         stamps no <c>X-Skein-Client-Ip</c>, so skein-api's per-IP limit
///         does not apply either. Then the email routes are limited per email
///         only (BFF and skein-api), and the token routes are limited by
///         neither side: they are protected by the token itself — secret,
///         expiring and single-use (a used reset, confirmation or invitation
///         token answers <c>token_invalid</c> / <c>invitation_invalid</c>).</item>
///   <item>A Redis error lets the request through (fail-open, as for
///         login).</item>
/// </list>
/// <para>skein-api receives no identity headers on these routes. When a
/// trusted proxy is configured the BFF stamps <c>X-Skein-Client-Ip</c> (the
/// trusted client address); any client-supplied <c>X-Skein-*</c> header is
/// stripped in every case.</para>
/// </remarks>
public static class PublicAuthRoutes
{
    /// <summary><c>POST</c> — registration (US-8, screens 2.6).</summary>
    public const string Signup = "/api/auth/signup";

    /// <summary><c>GET ?email=</c> — free usernames derived from an email (screens 2.6).</summary>
    public const string UsernameSuggestions = "/api/auth/username-suggestions";

    /// <summary><c>POST</c> — request a password-reset email (US-9, screens 2.8).</summary>
    public const string PasswordReset = "/api/auth/password-reset";

    /// <summary><c>POST</c> — set a new password by the token of the reset link (screens 2.8). Template; <c>{token}</c> is the link token.</summary>
    public const string PasswordResetComplete = "/api/auth/password-reset/{token}";

    /// <summary><c>POST</c> — confirm the email by the token of the confirmation email (screens 2.9). Template.</summary>
    public const string ConfirmEmail = "/api/auth/confirm-email/{token}";

    /// <summary><c>GET</c> — invitation state for a visitor without a session (US-5, screens 2.5). Template.</summary>
    public const string Invitation = "/api/auth/invitations/{token}";

    /// <summary><c>POST</c> — registration by invitation (screens 2.7). Template.</summary>
    public const string InvitationSignup = "/api/auth/invitations/{token}/signup";
}

/// <summary>
/// Machine codes of the public account routes (the <c>error</c> extension
/// member of the refusal <c>ProblemDetails</c>, see <see cref="PublicAuthRoutes"/>). Values are those of skein-api
/// <c>internal/accounts/contract.go</c> (T012), relayed unchanged; a route
/// returns only the codes its skein-api route lists.
/// </summary>
public static class AccountErrorCode
{
    /// <summary>400 — syntax refused by skein-api.</summary>
    public const string InvalidRequest = "invalid_request";

    /// <summary>429 — the action's rate limit (BFF limiter or skein-api backstop).</summary>
    public const string RateLimited = "rate_limited";

    /// <summary>422 — registration is closed on this installation.</summary>
    public const string SignupDisabled = "signup_disabled";

    /// <summary>422 — outgoing mail is off: no reset link or confirmation can be sent.</summary>
    public const string EmailDisabled = "email_disabled";

    /// <summary>422 — keycloak mode: passwords are recovered at the SSO provider.</summary>
    public const string PasswordLoginDisabled = "password_login_disabled";

    /// <summary>422 — the email belongs to an account (a deleted one included).</summary>
    public const string EmailTaken = "email_taken";

    /// <summary>422 — the username belongs to an account; the refusal carries the extension member <c>suggestions</c> (2–3 free usernames).</summary>
    public const string UsernameTaken = "username_taken";

    /// <summary>422 — the username breaks the username rule.</summary>
    public const string UsernameInvalid = "username_invalid";

    /// <summary>422 — the password breaks the password policy.</summary>
    public const string PasswordWeak = "password_weak";

    /// <summary>422 — the password is in the Pwned Passwords corpus.</summary>
    public const string PasswordPwned = "password_pwned";

    /// <summary>422 — the consent checkbox is not ticked.</summary>
    public const string TermsRequired = "terms_required";

    /// <summary>422 — Turnstile is configured and the token is missing or did not verify.</summary>
    public const string CaptchaFailed = "captcha_failed";

    /// <summary>422 — the reset or confirmation link token is unknown, expired or used.</summary>
    public const string TokenInvalid = "token_invalid";

    /// <summary>422 — the invitation is unknown, expired, revoked or used (registration by invitation).</summary>
    public const string InvitationInvalid = "invitation_invalid";

    /// <summary>422 — the invitation's space was deleted (registration by invitation).</summary>
    public const string SpaceDeleted = "space_deleted";
}

/// <summary>Body of <c>POST /api/auth/signup</c> (<see cref="PublicAuthRoutes.Signup"/>).</summary>
/// <param name="Email">Login email; compared case-insensitively. Rate-limit axis.</param>
/// <param name="Username">The @-mention handle; the username rule is checked by skein-api (<c>username_invalid</c>).</param>
/// <param name="Password">New password; the policy is checked by skein-api (<c>password_weak</c>, <c>password_pwned</c>).</param>
/// <param name="TermsAccepted">The consent checkbox; anything but <c>true</c> is <c>terms_required</c>.</param>
/// <param name="TurnstileToken">Turnstile widget token; send it when <see cref="AuthConfigResponse.TurnstileSiteKey"/> is set (otherwise <c>captcha_failed</c>), omit or null when it is null.</param>
/// <param name="Language">Interface language for the confirmation email: <c>ru</c> | <c>en</c>.</param>
public sealed record SignupRequest(
    [Required, EmailAddress, StringLength(320, MinimumLength = 3)] string Email,
    [Required] string Username,
    [Required] string Password,
    bool TermsAccepted,
    [StringLength(4096)] string? TurnstileToken,
    [Required, AllowedValues("ru", "en")] string Language);

/// <summary>200 body of <c>GET /api/auth/username-suggestions?email=</c>.</summary>
/// <param name="Suggestions">2–3 usernames free at the moment of the answer, best first.</param>
public sealed record UsernameSuggestionsResponse(IReadOnlyList<string> Suggestions);

/// <summary>Body of <c>POST /api/auth/password-reset</c> (<see cref="PublicAuthRoutes.PasswordReset"/>).</summary>
/// <param name="Email">Account email. Rate-limit axis. The answer does not depend on whether an account exists.</param>
/// <param name="Language">Interface language for the reset email: <c>ru</c> | <c>en</c>.</param>
public sealed record PasswordResetRequest(
    [Required, EmailAddress, StringLength(320, MinimumLength = 3)] string Email,
    [Required, AllowedValues("ru", "en")] string Language);

/// <summary>Body of <c>POST /api/auth/password-reset/{token}</c> (<see cref="PublicAuthRoutes.PasswordResetComplete"/>).</summary>
/// <param name="Password">New password; the policy is checked by skein-api.</param>
public sealed record PasswordResetCompleteRequest(
    [Required] string Password);

/// <summary>
/// Closed set of <see cref="InvitationPreviewResponse.Status"/> values, in
/// the order skein-api checks them (screens 2.5).
/// </summary>
public static class InvitationPreviewStatus
{
    /// <summary>The invitation's space was deleted — "deleted".</summary>
    public const string SpaceDeleted = "space_deleted";

    /// <summary>The token is unknown, expired, revoked or used — "invalid or expired".</summary>
    public const string Invalid = "invalid";

    /// <summary>The invitation can be accepted (log in) or signed up for.</summary>
    public const string Valid = "valid";
}

/// <summary>
/// 200 body of <c>GET /api/auth/invitations/{token}</c>: mirror of skein-api
/// <c>InvitationPreview</c>. Opening the link changes nothing.
/// </summary>
/// <remarks>
/// The fields after <c>status</c> are non-null only when status is
/// <c>valid</c>: a dead link reveals nothing about whom it was for. Wire form:
/// <c>{"status":"valid","space":{"id":"k3x9p2qa","slug":"acme","name":"Acme"},"inviterUsername":"anna","email":"dev@client.io","hasAccount":false}</c>.
/// </remarks>
/// <param name="Status">One of <see cref="InvitationPreviewStatus"/>.</param>
/// <param name="Space">The space invited to; null unless valid.</param>
/// <param name="InviterUsername">Who sent the invitation; null unless valid.</param>
/// <param name="Email">The invited email; null unless valid.</param>
/// <param name="HasAccount">An account with the invited email exists (log in to accept) or not (sign up by invitation when <see cref="AuthConfigResponse.SignupEnabled"/>); null unless valid.</param>
public sealed record InvitationPreviewResponse(
    string Status,
    InvitationSpaceDto? Space,
    string? InviterUsername,
    string? Email,
    bool? HasAccount);

/// <summary>A space named by an invitation (mirror of skein-api <c>InvitationSpace</c>).</summary>
/// <param name="Id">Space short id, as <c>GET /api/v1/me/spaces</c> returns it.</param>
/// <param name="Slug">Address slug of the space name; the place address is <c>/spaces/&lt;id&gt;-&lt;slug&gt;</c>.</param>
/// <param name="Name">Space name.</param>
public sealed record InvitationSpaceDto(string Id, string Slug, string Name);

/// <summary>
/// Body of <c>POST /api/auth/invitations/{token}/signup</c>. The email is the
/// invitation's; no confirmation email (the link proved the mailbox). Like
/// every registration (US-8) it is protected by Turnstile when a site key is
/// configured — skein-api <c>InvitationSignupRequest</c>, refusal
/// <c>captcha_failed</c> checked right after <c>rate_limited</c>.
/// </summary>
/// <param name="Username">The @-mention handle.</param>
/// <param name="Password">New password.</param>
/// <param name="TermsAccepted">The consent checkbox; anything but <c>true</c> is <c>terms_required</c>.</param>
/// <param name="TurnstileToken">Turnstile widget token; send it when <see cref="AuthConfigResponse.TurnstileSiteKey"/> is set (otherwise <c>captcha_failed</c>), omit or null when it is null. Never part of a rate-limit key.</param>
public sealed record InvitationSignupRequest(
    [Required] string Username,
    [Required] string Password,
    bool TermsAccepted,
    [StringLength(4096)] string? TurnstileToken = null);

/// <summary>
/// 200 body of <c>POST /api/auth/invitations/{token}/signup</c>: the logged-in
/// user (same fields as <see cref="UserDto"/>) plus the space joined, for the
/// redirect. The session epoch skein-api returns stays in the session and is
/// not sent to the browser.
/// </summary>
/// <param name="Id">User id (UUID).</param>
/// <param name="Email">Login email, lower-cased (the invitation's).</param>
/// <param name="Username">The @-mention handle.</param>
/// <param name="Name">Display name.</param>
/// <param name="Role">Always <c>user</c> for a new account.</param>
/// <param name="CreatedAt">Account creation time (UTC).</param>
/// <param name="LastLoginAt">Last login recorded; null when none.</param>
/// <param name="IsExternal">External-collaborator flag; <c>false</c> for an account created by invitation signup.</param>
/// <param name="Space">The space the new account joined.</param>
public sealed record InvitationSignupResponse(
    string Id,
    string Email,
    string Username,
    string Name,
    string Role,
    DateTimeOffset? CreatedAt,
    DateTimeOffset? LastLoginAt,
    bool IsExternal,
    InvitationSpaceDto Space);
