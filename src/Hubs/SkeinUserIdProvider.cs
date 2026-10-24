using System.Security.Claims;
using Microsoft.AspNetCore.SignalR;

namespace SkeinWeb.Hubs;

/// <summary>
/// Maps a SignalR <see cref="HubConnectionContext"/> to a stable user
/// identifier (the <see cref="ClaimTypes.NameIdentifier"/> claim from
/// the cookie principal). Registered as the
/// <see cref="IUserIdProvider"/> implementation so
/// <c>Clients.User(userId)</c> in <see cref="NatsBridge"/> can fan an
/// event out to every active connection of one user (multi-tab support).
/// </summary>
/// <remarks>
/// SignalR's default <c>DefaultUserIdProvider</c> reads the same claim
/// but accepts <c>null</c> — we surface it explicitly so the policy is
/// auditable in one file. The claim is set by the cookie middleware in
/// <c>Program.cs</c> when the user authenticates; if it is missing, the
/// hub's <see cref="SkeinHub.OnConnectedAsync"/> aborts the connection
/// before any fan-out can happen, so a null return here is benign.
/// </remarks>
public sealed class SkeinUserIdProvider : IUserIdProvider
{
    /// <summary>
    /// Returns the user id (stringified UUID) for the connection, or
    /// <c>null</c> when the principal carries no NameIdentifier claim.
    /// </summary>
    public string? GetUserId(HubConnectionContext connection) =>
        connection.User?.FindFirstValue(ClaimTypes.NameIdentifier);
}
