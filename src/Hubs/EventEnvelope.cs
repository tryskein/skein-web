using System.Text.Json;
using System.Text.Json.Serialization;

namespace SkeinWeb.Hubs;

/// <summary>
/// Wire shape of every NATS message published by skein-api's outbox
/// dispatcher (Go <c>internal/outbox/envelope.go</c>). The .NET side
/// deserialises this and projects it onto the compact <see cref="BrowserEnvelope"/>
/// (<see cref="BrowserEnvelopeProjector"/>) before anything reaches a browser.
/// </summary>
/// <remarks>
/// Field set is a stable contract — additive changes only. Subscribers
/// MUST dedup on <see cref="Id"/> because the dispatcher is at-least-once
/// (a crash between Publish and tx.Commit re-publishes the same row on
/// the next tick).
///
/// <see cref="Payload"/> / <see cref="OldData"/> / <see cref="NewData"/>
/// are <see cref="JsonElement"/> rather than typed records because the
/// shape varies per <c>EventType</c> — the projector reads a closed list
/// of keys from them (field names, ids, hashes) and never forwards their
/// values to browsers (sk-622.21 INV-13).
/// </remarks>
/// <param name="Id">Bigserial id of the events row in skein-api. Stable across replays — dedup key.</param>
/// <param name="OccurredAt">Canonical event time (UTC) recorded on the row.</param>
/// <param name="EventType">Event type, e.g. <c>issue.created</c>, <c>project.member_added</c>, <c>user.deactivated</c>.</param>
/// <param name="EntityType">Top-level entity tag — issue, project, comment, dep, attachment, component, user.</param>
/// <param name="EntityId">Primary key of the affected row, in string form (uuid or hierarchical id).</param>
/// <param name="ProjectId">Project the event scopes to. Null on user-global events.</param>
/// <param name="Payload">Free-form per-event payload (omitted when empty).</param>
/// <param name="OldData">events.old_data jsonb — pre-mutation snapshot for diff/audit (omitted when null).</param>
/// <param name="NewData">events.new_data jsonb — post-mutation snapshot (omitted when null).</param>
/// <param name="Actor">sk-21 enrichment — username of the event author (resolved at dispatch time on skein-api). Null on legacy publishers (&lt; 0.9.0).</param>
/// <param name="ActorType">sk-21 enrichment — actor transport axis: <c>human</c> | <c>agent</c> | <c>system</c>. Null on legacy publishers.</param>
/// <param name="ActorUserId">sk-21 enrichment — actor user UUID as string. Null on system-emitted rows and on legacy publishers.</param>
/// <param name="EntityTitle">sk-21 enrichment — human-readable label for the entity (issue.title for issue events, parent issue.title for comment events). Empty / null for other entity types and on legacy publishers.</param>
/// <param name="Row">sk-622.21 phase 2 (T009) — the issue's neutral list row with <c>rowSeq</c>; absent on other events and on publishers before phase 2.</param>
/// <param name="ProjectIdPrefix">sk-21 enrichment — project idPrefix (e.g. <c>demo</c>, <c>sk</c>). Lets the SPA render the project chip without a separate lookup. Null when ProjectId is null and on legacy publishers.</param>
public sealed record EventEnvelope(
    [property: JsonPropertyName("id")] long Id,
    [property: JsonPropertyName("occurredAt")] DateTimeOffset OccurredAt,
    [property: JsonPropertyName("eventType")] string EventType,
    [property: JsonPropertyName("entityType")] string EntityType,
    [property: JsonPropertyName("entityId")] string EntityId,
    [property: JsonPropertyName("projectId")] Guid? ProjectId,
    [property: JsonPropertyName("payload")] JsonElement? Payload,
    [property: JsonPropertyName("oldData")] JsonElement? OldData,
    [property: JsonPropertyName("newData")] JsonElement? NewData,
    // sk-21 enrichment — resolved at dispatch time on skein-api via LEFT JOIN
    // issues / comments / projects. All optional on the wire (omitempty Go
    // side); null when a legacy publisher (< 0.9.0) emitted the envelope.
    // Forwarded verbatim to SignalR clients — sk-27 caught these being
    // silently dropped because the record didn't declare the properties.
    [property: JsonPropertyName("actor")] string? Actor = null,
    [property: JsonPropertyName("actorType")] string? ActorType = null,
    [property: JsonPropertyName("actorUserId")] string? ActorUserId = null,
    [property: JsonPropertyName("entityTitle")] string? EntityTitle = null,
    [property: JsonPropertyName("projectIdPrefix")] string? ProjectIdPrefix = null,
    // sk-622.21 T009 — phase-2 neutral list row of the issue (carries
    // rowSeq); opaque here and forwarded unchanged in BrowserEnvelope.Row.
    [property: JsonPropertyName("row")] JsonElement? Row = null
);
