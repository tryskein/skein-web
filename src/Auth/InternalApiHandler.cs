using System.Security.Claims;
using Microsoft.Extensions.Options;

namespace SkeinWeb.Auth;

/// <summary>
/// HttpClient delegating handler that injects the BFF -> skein-api
/// authentication headers on every outbound request:
/// <list type="bullet">
///   <item><description><c>X-Skein-Internal-Secret</c> — channel auth, always present.</description></item>
///   <item><description><c>X-Skein-User-*</c> — identity headers, present only when the
///       current <see cref="HttpContext"/> has an authenticated user (login is
///       skipped because the user does not exist yet from the API's perspective).</description></item>
///   <item><description><c>X-Skein-Session-Epoch</c> — with the identity headers, from the
///       session's <see cref="SessionPrincipal.SessionEpochClaim"/> (sk-674.18 K-16); any
///       caller-supplied value is dropped first.</description></item>
/// </list>
/// </summary>
/// <remarks>
/// The handler reads claims from <see cref="IHttpContextAccessor"/>. It is
/// registered as transient because <see cref="DelegatingHandler"/> instances
/// are bound to the lifetime of the <see cref="HttpClient"/> created by
/// <see cref="IHttpClientFactory"/>; transient lifetime keeps the handler
/// chain reusable while the captured accessor (singleton) gives a
/// per-request <see cref="HttpContext"/>.
///
/// The handler never trusts inbound X-Skein-* headers from the browser —
/// stripping happens in <c>ApiProxyMiddleware</c> before this handler runs.
/// </remarks>
public sealed class InternalApiHandler : DelegatingHandler
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly SkeinApiOptions _options;

    public InternalApiHandler(IHttpContextAccessor httpContextAccessor, IOptions<SkeinApiOptions> options)
    {
        _httpContextAccessor = httpContextAccessor;
        _options = options.Value;
    }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        // Channel auth: always present, even on /auth/login (the user is
        // not yet authenticated, but the BFF -> API channel still must be).
        request.Headers.Remove(SkeinHeaders.InternalSecret);
        request.Headers.TryAddWithoutValidation(SkeinHeaders.InternalSecret, _options.InternalSecret);

        var ctx = _httpContextAccessor.HttpContext;

        // Trusted client IP (sk-163 S9): forwarded on EVERY internal call,
        // including /auth/login which has no authenticated user yet. skein-api
        // keys its defense-in-depth login limiter on this so the per-IP throttle
        // reflects the real client rather than the single BFF egress address.
        // Drop any caller-supplied copy first (the browser must not forge it).
        //
        // Forwarded ONLY when a trusted proxy chain is configured (ClientIpTrusted):
        // without one, RemoteIpAddress is the constant ingress/peer IP, which is
        // meaningless — and harmful — as a throttle key (it would lump every
        // user into one per-IP bucket). In that state we send no header, and the
        // API skips the per-IP bucket (per-email still applies on both sides).
        request.Headers.Remove(SkeinHeaders.ClientIp);
        var clientIp = ctx?.Connection.RemoteIpAddress;
        if (_options.ClientIpTrusted && clientIp is not null)
        {
            request.Headers.TryAddWithoutValidation(SkeinHeaders.ClientIp, clientIp.ToString());
        }

        // Session epoch (sk-674.18 K-16): part of the identity family, so a
        // caller-supplied copy is dropped unconditionally — a request without
        // a user must not carry one either.
        request.Headers.Remove(SkeinHeaders.SessionEpoch);

        // Identity forwarding: only when an authenticated user exists in
        // the current request context. Login does not have one yet.
        var user = ctx?.User;
        if (user?.Identity is { IsAuthenticated: true })
        {
            var userId = user.FindFirstValue(ClaimTypes.NameIdentifier);
            var email = user.FindFirstValue(ClaimTypes.Email);
            var username = user.FindFirstValue("username");
            var role = user.FindFirstValue(ClaimTypes.Role);
            // is_external (sk-163 S1): custom claim minted at sign-in, same
            // shape as the "username" claim. Absent claim → "false".
            var isExternal = user.FindFirstValue("is_external");

            // Drop any caller-supplied values to avoid double-headers.
            request.Headers.Remove(SkeinHeaders.UserId);
            request.Headers.Remove(SkeinHeaders.UserEmail);
            request.Headers.Remove(SkeinHeaders.Username);
            request.Headers.Remove(SkeinHeaders.UserRole);
            request.Headers.Remove(SkeinHeaders.UserIsExternal);

            if (!string.IsNullOrEmpty(userId))
            {
                request.Headers.TryAddWithoutValidation(SkeinHeaders.UserId, userId);
            }
            if (!string.IsNullOrEmpty(email))
            {
                request.Headers.TryAddWithoutValidation(SkeinHeaders.UserEmail, email);
            }
            if (!string.IsNullOrEmpty(username))
            {
                request.Headers.TryAddWithoutValidation(SkeinHeaders.Username, username);
            }
            if (!string.IsNullOrEmpty(role))
            {
                request.Headers.TryAddWithoutValidation(SkeinHeaders.UserRole, role);
            }
            // Always forward an explicit value so skein-api never has to
            // distinguish "internal" from "header dropped in transit" —
            // normalise the claim to the literal "true" / "false".
            var isExternalValue = string.Equals(isExternal, "true", StringComparison.OrdinalIgnoreCase)
                ? "true"
                : "false";
            request.Headers.TryAddWithoutValidation(SkeinHeaders.UserIsExternal, isExternalValue);

            // The epoch the session was issued with. A session without the
            // claim (minted before this release) sends none, and skein-api
            // answers session_revoked — the browser logs in again and gets a
            // session that carries it (no default value is ever invented).
            var epoch = user.FindFirstValue(SessionPrincipal.SessionEpochClaim);
            if (!string.IsNullOrEmpty(epoch))
            {
                request.Headers.TryAddWithoutValidation(SkeinHeaders.SessionEpoch, epoch);
            }
        }

        return base.SendAsync(request, cancellationToken);
    }
}
