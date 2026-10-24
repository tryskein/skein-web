using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using SkeinWeb.Auth;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// Pins the BFF -> skein-api trust-boundary emit for the sk-163 S1
/// <c>is_external</c> flag in <see cref="InternalApiHandler"/>. This is the
/// security-sensitive forwarding path flagged by the S1 security review: the
/// API parser treats an absent <c>X-Skein-User-Is-External</c> header as
/// internal (false), so a BFF regression that drops/mis-forwards the flag
/// would silently fail open for surfaces that later gate external
/// collaborators. These tests lock the contract:
/// <list type="bullet">
///   <item><description>authenticated principal with <c>is_external=true</c> → header "true";</description></item>
///   <item><description>absent <c>is_external</c> claim → explicit header "false" (never dropped);</description></item>
///   <item><description>a caller-supplied header value is stripped and replaced by the principal-derived value;</description></item>
///   <item><description>unauthenticated context forwards no identity header (channel secret only).</description></item>
/// </list>
/// sk-674.18: the session epoch travels as
/// <c>X-Skein-Session-Epoch</c> from the session claim; a caller-supplied value
/// is replaced, and dropped when there is no user.
/// </summary>
public class InternalApiHandlerTest
{
    private static HttpContextAccessor Accessor(ClaimsPrincipal? user)
    {
        var ctx = new DefaultHttpContext();
        if (user is not null)
        {
            ctx.User = user;
        }
        return new HttpContextAccessor { HttpContext = ctx };
    }

    private static ClaimsPrincipal AuthedUser(params Claim[] claims)
    {
        // A non-empty authenticationType makes Identity.IsAuthenticated true,
        // which is the gate InternalApiHandler checks before forwarding identity.
        var identity = new ClaimsIdentity(claims, authenticationType: "cookie");
        return new ClaimsPrincipal(identity);
    }

    private static async Task<HttpRequestMessage> SendAsync(
        ClaimsPrincipal? user, Action<HttpRequestMessage>? seed = null)
    {
        HttpRequestMessage? captured = null;
        var handler = new InternalApiHandler(
            Accessor(user),
            Options.Create(new SkeinApiOptions { InternalSecret = "test-secret" }))
        {
            InnerHandler = new CapturingHandler(req =>
            {
                captured = req;
                return new HttpResponseMessage(System.Net.HttpStatusCode.OK);
            }),
        };
        using var invoker = new HttpMessageInvoker(handler);
        var request = new HttpRequestMessage(HttpMethod.Get, "http://skein-api.test/api/v1/me");
        seed?.Invoke(request);
        await invoker.SendAsync(request, CancellationToken.None);
        Assert.NotNull(captured);
        return captured!;
    }

    private static string? HeaderOrNull(HttpRequestMessage req, string name) =>
        req.Headers.TryGetValues(name, out var vals) ? string.Join(",", vals) : null;

    [Fact]
    public async Task SessionTicketKey_NeverLeavesTheServer_InAnyHeader()
    {
        // The session_key claim is the Redis ticket
        // key — as good as the cookie. The identity skein-api receives must
        // carry it nowhere. Positive control: the identity itself is forwarded.
        const string ticketKey = "skein:session:secret-ticket-key";
        var req = await SendAsync(AuthedUser(
            new Claim(ClaimTypes.NameIdentifier, "0199a1b2-0000-7000-8000-000000000001"),
            new Claim(SessionPrincipal.SessionEpochClaim, "3"),
            new Claim(SessionPrincipal.SessionKeyClaim, ticketKey)));

        Assert.Equal("0199a1b2-0000-7000-8000-000000000001", HeaderOrNull(req, SkeinHeaders.UserId));
        Assert.DoesNotContain(req.Headers, h => h.Value.Any(v => v.Contains("secret-ticket-key", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task ForwardsTrue_WhenPrincipalIsExternal()
    {
        var req = await SendAsync(AuthedUser(
            new Claim(ClaimTypes.NameIdentifier, "u-1"),
            new Claim("is_external", "true")));

        Assert.Equal("true", HeaderOrNull(req, SkeinHeaders.UserIsExternal));
        // Channel secret is always present.
        Assert.Equal("test-secret", HeaderOrNull(req, SkeinHeaders.InternalSecret));
    }

    [Fact]
    public async Task ForwardsExplicitFalse_WhenClaimAbsent()
    {
        // No is_external claim → the handler must still emit an explicit
        // "false" so the API never has to distinguish "internal" from
        // "header dropped in transit".
        var req = await SendAsync(AuthedUser(
            new Claim(ClaimTypes.NameIdentifier, "u-1")));

        Assert.Equal("false", HeaderOrNull(req, SkeinHeaders.UserIsExternal));
    }

    [Fact]
    public async Task StripsAndReplacesCallerSuppliedHeader()
    {
        // A spoofed inbound X-Skein-User-Is-External: true must be dropped and
        // replaced by the principal-derived value (here: internal → "false").
        var req = await SendAsync(
            AuthedUser(new Claim(ClaimTypes.NameIdentifier, "u-1")),
            seed: r => r.Headers.TryAddWithoutValidation(SkeinHeaders.UserIsExternal, "true"));

        // Exactly one value, principal-derived, not the spoofed "true".
        Assert.Equal("false", HeaderOrNull(req, SkeinHeaders.UserIsExternal));
    }

    [Fact]
    public async Task NoIdentityHeader_WhenUnauthenticated()
    {
        // Anonymous context (e.g. /auth/login before sign-in): no identity
        // headers forwarded, only the channel secret.
        var req = await SendAsync(user: null);

        Assert.Null(HeaderOrNull(req, SkeinHeaders.UserIsExternal));
        Assert.Equal("test-secret", HeaderOrNull(req, SkeinHeaders.InternalSecret));
    }

    // ---- sk-674.18 (INV-26, K-16): X-Skein-Session-Epoch ----

    [Fact]
    public async Task ForwardsSessionEpoch_FromTheSessionClaim()
    {
        var req = await SendAsync(AuthedUser(
            new Claim(ClaimTypes.NameIdentifier, "u-1"),
            new Claim(SessionPrincipal.SessionEpochClaim, "7")));

        Assert.Equal("7", HeaderOrNull(req, SkeinHeaders.SessionEpoch));
    }

    [Fact]
    public async Task ReplacesCallerSuppliedSessionEpoch_WithTheClaim()
    {
        // A client forging a newer epoch must not reach skein-api with it.
        var req = await SendAsync(
            AuthedUser(
                new Claim(ClaimTypes.NameIdentifier, "u-1"),
                new Claim(SessionPrincipal.SessionEpochClaim, "7")),
            seed: r => r.Headers.TryAddWithoutValidation(SkeinHeaders.SessionEpoch, "999"));

        Assert.Equal("7", HeaderOrNull(req, SkeinHeaders.SessionEpoch));
    }

    [Fact]
    public async Task DropsCallerSuppliedSessionEpoch_WhenUnauthenticated()
    {
        var req = await SendAsync(
            user: null,
            seed: r => r.Headers.TryAddWithoutValidation(SkeinHeaders.SessionEpoch, "999"));

        Assert.Null(HeaderOrNull(req, SkeinHeaders.SessionEpoch));
    }

    private sealed class CapturingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;

        public CapturingHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
        {
            _respond = respond;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(_respond(request));
        }
    }
}
