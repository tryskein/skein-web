using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
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
    /// Ends the session of the current request. The row of the key of the EFFECTIVE principal
    /// (the new key after an issue on this request, otherwise the key of the cookie) is deleted
    /// first, this replica's hub connections opened with that session are closed (INV-26: a revoked
    /// session receives no more hub frames), the late sliding write of Main is suppressed, and only
    /// then the cookie scheme is signed out, which deletes the cookie. The sign-out's own removal of
    /// the incoming key is a no-op when that key was just deleted
    /// (<see cref="SessionRequestState.RemovedKeys"/>). Connections on other replicas are closed by
    /// their access re-check once the ticket is gone (<see cref="AccessRecheckService"/>). Never
    /// retried, and not cancellable — tearing a session down is past the point of no return (same
    /// reasoning as logout).
    /// </summary>
    /// <param name="context">The request whose session ends: revoked by
    /// skein-api, or signed out by the user (<c>POST /api/auth/logout</c>).</param>
    /// <exception cref="SessionStoreUnavailableException">The store failed technically.</exception>
    public static async Task EndSessionAsync(HttpContext context)
    {
        var sessionKey = SessionPrincipal.SessionKeyOf(context.User);
        var state = SessionRequestState.Of(context);
        state.SuppressMainWrite = true;
        state.NoCancellation = true;

        if (sessionKey is not null)
        {
            await context.RequestServices.GetRequiredService<RedisTicketStore>()
                .RevokeAsync(sessionKey, context, CancellationToken.None);
            context.RequestServices.GetService<ConnectionRegistry>()?.AbortSession(sessionKey);
        }
        await context.SignOutAsync(SessionSchemes.Main);
    }
}
