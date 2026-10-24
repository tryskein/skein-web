using System.Text.Json.Serialization;

namespace SkeinWeb.Hubs;

/// <summary>
/// Body of the control subject <c>skein.user.{uid}.access_changed</c>
/// (sk-674.18 K-15, D-10, ADR-3) — mirror of Go
/// <c>internal/signals/contract.go#AccessChanged</c> (T014). Not a browser
/// frame: <see cref="AccessControlSubscriber"/> applies it to this replica's
/// connections of the user.
/// </summary>
/// <remarks>
/// Published after the final commit of a change of the user's access, with
/// exact sets; best-effort (the periodic re-check is the safety net). Wire form:
/// <c>{"lostProjectIds":["0199…a1"],"gainedProjectIds":[],"lostSpaceIds":["k3x9p2qa"],"sentAt":"2026-10-12T10:15:03.123456Z"}</c>.
/// </remarks>
/// <param name="LostProjectIds">Projects the user can no longer see; the connections leave their groups at once.</param>
/// <param name="GainedProjectIds">Projects the user can now see; joined after a re-check against skein-api.</param>
/// <param name="LostSpaceIds">Spaces (short ids) the user is no longer in. Diagnostic for the hub: the projects of a lost space are in <paramref name="LostProjectIds"/>.</param>
/// <param name="SentAt">Publish time (UTC). Diagnostic only.</param>
public sealed record AccessChanged(
    [property: JsonPropertyName("lostProjectIds")] IReadOnlyList<Guid>? LostProjectIds,
    [property: JsonPropertyName("gainedProjectIds")] IReadOnlyList<Guid>? GainedProjectIds,
    [property: JsonPropertyName("lostSpaceIds")] IReadOnlyList<string>? LostSpaceIds,
    [property: JsonPropertyName("sentAt")] DateTimeOffset SentAt);
