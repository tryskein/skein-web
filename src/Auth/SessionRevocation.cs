using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using SkeinWeb.Hubs;

namespace SkeinWeb.Auth;

/// <summary>
/// skein-api's verdict that a browser session is revoked (sk-674.18 K-16,
/// INV-26): a 401 whose body is <c>{"error":"session_revoked"}</c>
/// (<see cref="SkeinHeaders.SessionRevokedCode"/>). Every BFF path that calls
/// skein-api on behalf of a session ends that session on it — the
/// <c>/api/v1</c> proxy (<c>ApiProxyMiddleware</c>) and <c>GET /api/auth/me</c>
/// — so a revoked session is refused from skein-api's answer on, whichever
/// route the browser uses next.
/// </summary>
public static class SessionRevocation
{
    /// <summary>
    /// True when a 401 body is skein-api's <c>session_revoked</c>. A body that
    /// is not JSON, or names another code, is not a revocation.
    /// </summary>
    /// <param name="body">The 401 response body.</param>
    public static bool IsRevokedBody(ReadOnlySpan<byte> body)
    {
        if (body.IsEmpty)
        {
            return false;
        }
        try
        {
            var reader = new Utf8JsonReader(body);
            using var doc = JsonDocument.ParseValue(ref reader);
            return doc.RootElement.ValueKind == JsonValueKind.Object
                && doc.RootElement.TryGetProperty("error", out var error)
                && error.ValueKind == JsonValueKind.String
                && error.GetString() == SkeinHeaders.SessionRevokedCode;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// Ends the session of the current request: signs out of the cookie scheme,
    /// which deletes the cookie and removes the Redis ticket, then closes this
    /// replica's hub connections opened with that session (INV-26: a revoked
    /// session receives no more hub frames). Connections on other replicas are
    /// closed by their access re-check once the ticket is gone
    /// (<see cref="AccessRecheckService"/>). Never retried, and not cancellable —
    /// tearing a session down is past the point of no return (same reasoning
    /// as logout).
    /// </summary>
    /// <param name="context">The request whose session skein-api revoked.</param>
    public static async Task EndSessionAsync(HttpContext context)
    {
        var sessionKey = SessionPrincipal.SessionKeyOf(context.User);
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (sessionKey is not null)
        {
            context.RequestServices.GetService<ConnectionRegistry>()?.AbortSession(sessionKey);
        }
    }
}
