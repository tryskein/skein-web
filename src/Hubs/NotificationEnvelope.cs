using System.Text.Json.Serialization;

namespace SkeinWeb.Hubs;

/// <summary>
/// Wire shape of NATS messages published on
/// <c>skein.user.{uid}.notification</c> by skein-api's outbox dispatcher
/// (Go <c>internal/outbox/envelope.go</c>, <c>NotificationEnvelope</c>).
/// </summary>
/// <remarks>
/// Distinct from <see cref="EventEnvelope"/>: notifications carry only
/// the metadata the frontend needs to bump its inbox badge and
/// invalidate cached queries — the actual notification rendering reads
/// from REST. Keeping the envelope small keeps multi-recipient fan-out
/// cheap (one row in <c>notifications</c> can be read by a single user
/// at a time, but the same EventId may have produced N rows for N
/// recipients).
///
/// Subscribers MUST dedup on <see cref="NotificationId"/> — at-least-once
/// delivery means a crash between Publish and tx.Commit re-publishes the
/// same row.
/// </remarks>
/// <param name="NotificationId">Bigserial id from the notifications row.</param>
/// <param name="UserId">Recipient user id — the event is forwarded to this user only.</param>
/// <param name="EventId">Underlying events row id (foreign key on notifications.event_id).</param>
/// <param name="EventType">Event type, e.g. <c>comment.created</c>.</param>
/// <param name="ProjectId">Optional project scoping for the notification.</param>
/// <param name="CreatedAt">Notification row creation timestamp (UTC).</param>
public sealed record NotificationEnvelope(
    [property: JsonPropertyName("notificationId")] long NotificationId,
    [property: JsonPropertyName("userId")] Guid UserId,
    [property: JsonPropertyName("eventId")] long EventId,
    [property: JsonPropertyName("eventType")] string EventType,
    [property: JsonPropertyName("projectId")] Guid? ProjectId,
    [property: JsonPropertyName("createdAt")] DateTimeOffset CreatedAt
);
