using System.Text.Json;
using System.Text.Json.Serialization;

namespace SkeinWeb.Hubs;

// Browser contract of the SignalR hub /hub (spec sk-622.21, US-9 / US-11 /
// US-12 / US-10; plan T030; extended by spec sk-674.18 plan T044). Every name in this file — client method names,
// hub method names, JSON field names, enumerated string values — is a stable
// contract with skein-frontend (frontend and skein-web ship together, R5).
// Additive changes only: never rename or remove a field or a value.
//
// Wire names are pinned with [JsonPropertyName] so the shape does not depend
// on the hub protocol's naming policy.

/// <summary>
/// Names of the client-side methods the server invokes on browser
/// connections (<c>Clients.*.SendAsync(name, frame)</c>).
/// </summary>
/// <remarks>
/// The three theme methods (<c>theme.preview</c>,
/// <c>theme.user-pref.updated</c>, <c>theme.{action}</c>) are not part of
/// this contract and keep their current names and payloads; they live in
/// <see cref="NatsBridge"/>.
/// </remarks>
public static class BrowserClientMethods
{
    /// <summary>
    /// A project or user event, payload <see cref="BrowserEnvelope"/>. Also
    /// carries the personal notification envelope
    /// (<see cref="NotificationEnvelope"/>) exactly as today; the client tells
    /// them apart by shape.
    /// </summary>
    public const string Event = "event";

    /// <summary>
    /// Coalesced personal signal, payload <see cref="PersonalSignal"/>: at
    /// most one per connection per <c>COUNTS_SIGNAL_WINDOW_MS</c>, areas
    /// unioned over the window.
    /// </summary>
    public const string Signal = "signal";

    /// <summary>
    /// Personal reminder frame, payload <see cref="ReminderFrame"/>. Sent to
    /// every connection of the reminder's owner regardless of the declared
    /// projects; never coalesced; may arrive more than once.
    /// </summary>
    public const string Reminder = "reminder";

    /// <summary>
    /// "Re-read" frame, payload <see cref="ResyncFrame"/>: the connection may
    /// have missed events during a transport break (NATS or the SignalR
    /// backplane). The tab reacts exactly as after a reconnect: declares its
    /// projects first, then re-reads its active data (US-10, US-14).
    /// </summary>
    public const string Resync = "resync";
}

/// <summary>
/// Names of the hub methods the browser invokes
/// (<c>connection.invoke(name, …)</c>). See <see cref="ISkeinHubDeclarations"/>
/// for their semantics.
/// </summary>
public static class SkeinHubMethods
{
    /// <summary>Name of <see cref="ISkeinHubDeclarations.DeclareProjects"/>.</summary>
    public const string DeclareProjects = "DeclareProjects";

    /// <summary>Name of <see cref="ISkeinHubDeclarations.DeclareAllVisible"/>.</summary>
    public const string DeclareAllVisible = "DeclareAllVisible";
}

/// <summary>
/// Client-callable hub methods with which a tab tells the server which
/// projects' events it needs (US-9). Implemented by <see cref="SkeinHub"/>.
/// </summary>
/// <remarks>
/// <para>
/// Project events (issues, comments, attachments, dependencies, components,
/// the project itself and its membership) are delivered to a connection only
/// if it declared that project — or declared "all visible" — and the user
/// can see the project. Today "can see" is: a member, or an internal admin
/// (an external admin is limited to membership). With T049 (sk-674.18 ADR-3)
/// it becomes the set of visible projects skein-api reports for the user —
/// for an instance admin a set too, which never contains another user's
/// personal space; the internal-admin shortcut goes away. This applies to
/// admins too: an admin receives project events only for declared projects
/// (or all visible on <c>/activity</c>). User events (<c>user.*</c>), personal frames and theme
/// messages do not depend on declarations.
/// </para>
/// <para>
/// A tab declares on every change of its set and after every reconnect,
/// before it starts re-reading. A rejection of one project never breaks the
/// others; the tab logs <see cref="DeclareResult.Rejected"/> to the console.
/// </para>
/// </remarks>
public interface ISkeinHubDeclarations
{
    /// <summary>
    /// Replaces the connection's declared project set with
    /// <paramref name="projectIds"/>.
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    ///   <item>Order matters: the per-connection limit
    ///         <c>HUB_MAX_PROJECTS_PER_CONNECTION</c> (default 50) is applied
    ///         in declaration order; ids past it are rejected with
    ///         <see cref="DeclareRejectReason.Limit"/>.</item>
    ///   <item>Access is checked against skein-api at most once per change of
    ///         the set; re-declaring the same set makes no call.</item>
    ///   <item>At most 10 set changes per 10 s per connection; a change past
    ///         that is rejected with <see cref="DeclareRejectReason.Rate"/> for
    ///         every id it carried, and the previous set stays in force.</item>
    ///   <item>An id that is not a UUID is rejected with
    ///         <see cref="DeclareRejectReason.Invalid"/>; a project the user
    ///         cannot see — with <see cref="DeclareRejectReason.NoAccess"/>.</item>
    ///   <item>An empty array clears the set.</item>
    ///   <item>skein-api unavailable (transport error, 5xx after retries,
    ///         timeout of the 15 s call budget): the invocation fails with a
    ///         <c>HubException</c> (the SignalR invoke rejects), the previous
    ///         set and groups stay in force, and the attempt does not count
    ///         against the rate limit — the tab may declare again.</item>
    /// </list>
    /// </remarks>
    /// <param name="projectIds">Project UUIDs in priority order (most important first).</param>
    /// <returns>Accepted ids and per-id rejections.</returns>
    Task<DeclareResult> DeclareProjects(string[] projectIds);

    /// <summary>
    /// Turns the "all projects visible to me" mode on or off (the
    /// <c>/activity</c> page, R2).
    /// </summary>
    /// <remarks>
    /// While on, the connection receives events of every project the user can
    /// see; the per-connection project limit does not apply. Turning it off
    /// returns the connection to its declared project set. Subject to the same
    /// set-change rate limit as <see cref="DeclareProjects"/>. Turning it on
    /// with skein-api unavailable fails the same way as
    /// <see cref="DeclareProjects"/>: <c>HubException</c>, the previous mode
    /// stays in force, the attempt does not count against the rate limit.
    /// </remarks>
    /// <param name="enabled"><c>true</c> to turn the mode on, <c>false</c> to turn it off.</param>
    /// <returns>
    /// The result of the switch: <see cref="DeclareResult.Accepted"/> is
    /// always empty (the mode names no project); on success
    /// <see cref="DeclareResult.Rejected"/> is empty too. A refused switch
    /// carries exactly one rejection whose <c>projectId</c> is the empty
    /// string — the refusal concerns the mode, not a project — e.g.
    /// <c>{"accepted":[],"rejected":[{"projectId":"","reason":"rate"}]}</c>
    /// when the set-change rate limit is exceeded; the previous mode stays in
    /// force.
    /// </returns>
    Task<DeclareResult> DeclareAllVisible(bool enabled);
}

/// <summary>
/// Result of <see cref="ISkeinHubDeclarations.DeclareProjects"/> and
/// <see cref="ISkeinHubDeclarations.DeclareAllVisible"/>.
/// </summary>
/// <remarks>Wire form: <c>{"accepted":["…"],"rejected":[{"projectId":"…","reason":"no_access"}]}</c>.</remarks>
/// <param name="Accepted">Ids of THIS call that entered the connection's set, in declaration order, as the client sent them. A call refused with <c>rate</c> accepts nothing: <c>accepted</c> is <c>[]</c> and the previous set stays in force without being echoed. Always <c>[]</c> for <see cref="ISkeinHubDeclarations.DeclareAllVisible"/>.</param>
/// <param name="Rejected">One entry per rejected id; empty when everything was accepted.</param>
public sealed record DeclareResult(
    [property: JsonPropertyName("accepted")] IReadOnlyList<string> Accepted,
    [property: JsonPropertyName("rejected")] IReadOnlyList<DeclareRejection> Rejected);

/// <summary>One rejected project of a declaration.</summary>
/// <param name="ProjectId">The id exactly as the client sent it (may be a non-UUID string when <paramref name="Reason"/> is <c>invalid</c>). The empty string on a refusal of <see cref="ISkeinHubDeclarations.DeclareAllVisible"/>: the refusal concerns the mode, not a project.</param>
/// <param name="Reason">One of <see cref="DeclareRejectReason"/>.</param>
public sealed record DeclareRejection(
    [property: JsonPropertyName("projectId")] string ProjectId,
    [property: JsonPropertyName("reason")] string Reason);

/// <summary>
/// Closed set of <see cref="DeclareRejection.Reason"/> values.
/// </summary>
public static class DeclareRejectReason
{
    /// <summary>The user cannot see the project (today: not a member and not an internal admin; with T049, sk-674.18 ADR-3: not in skein-api's set of visible projects, an admin included), or it does not exist.</summary>
    public const string NoAccess = "no_access";

    /// <summary>The id is past <c>HUB_MAX_PROJECTS_PER_CONNECTION</c> in declaration order.</summary>
    public const string Limit = "limit";

    /// <summary>The connection exceeded 10 set changes per 10 s; the previous set stays in force.</summary>
    public const string Rate = "rate";

    /// <summary>The id is not a UUID.</summary>
    public const string Invalid = "invalid";
}

/// <summary>
/// Compact event envelope sent to browsers with
/// <see cref="BrowserClientMethods.Event"/> (US-12, phase 1; plus
/// <see cref="Row"/> in phase 2). Projected from the NATS
/// <see cref="EventEnvelope"/>; replaces it on the browser wire.
/// </summary>
/// <remarks>
/// <para>
/// The envelope carries no field values of the issue: no
/// <c>payload</c>, <c>oldData</c> or <c>newData</c>. Values of the issue text
/// fields (description, design, acceptance criteria, notes) and comment
/// bodies never appear in it — neither at the top level nor inside
/// <see cref="ChangedFields"/>, which holds field NAMES only (INV-13).
/// Per-field child edit events (<c>*.field_changed</c>) are not delivered to
/// browsers; the parent edit event carries <see cref="ChangedFields"/>.
/// </para>
/// <para>
/// The envelope identifies no issue outside the recipient's horizon
/// (INV-17): a dependency end lying in another project is omitted.
/// </para>
/// <para>
/// Delivery is at-least-once: the client deduplicates on <see cref="Id"/>.
/// Optional fields are omitted from the JSON when absent.
/// </para>
/// </remarks>
/// <param name="Id">Bigserial id of the events row in skein-api; stable across replays — the dedup key.</param>
/// <param name="OccurredAt">Canonical event time (UTC, RFC 3339).</param>
/// <param name="EventType">Event type, e.g. <c>issue.updated</c>, <c>dependency.created</c>, <c>user.deactivated</c>.</param>
/// <param name="EntityType">Top-level entity tag — issue, project, comment, dep, attachment, component, user.</param>
/// <param name="EntityId">Primary key of the affected entity in string form (uuid or hierarchical issue id).</param>
/// <param name="ProjectId">Project the event belongs to; null on user events.</param>
/// <param name="Actor">Username of the event author; null when unknown.</param>
/// <param name="ActorType">Actor transport axis: <c>human</c> | <c>agent</c> | <c>system</c>; null when unknown.</param>
/// <param name="ActorUserId">Actor user UUID as string; null on system events.</param>
/// <param name="EntityTitle">Human-readable label of the entity (issue title; parent issue title for comments); null when none.</param>
/// <param name="ProjectIdPrefix">Project id prefix (e.g. <c>sk</c>); null when <paramref name="ProjectId"/> is null.</param>
/// <param name="IssueId">The issue a comment or attachment event belongs to (hierarchical id); omitted for other entities.</param>
/// <param name="ChangedFields">Names of the issue fields changed by a parent edit event (e.g. <c>["status","description"]</c>), never their values; omitted on other events.</param>
/// <param name="Dep">Dependency type and the ends lying in the event's project; omitted on non-dependency events.</param>
/// <param name="Reparent">Old and new parents of a re-parent event; omitted on other events.</param>
/// <param name="CommitHashes">Commit hashes linked by a commit-attach event (the commit race counts them); omitted on other events.</param>
/// <param name="Row">Phase 2: the issue's neutral list row as produced by skein-api (opaque here, forwarded unchanged; carries <c>rowSeq</c> — substitute only if greater than the shown one); omitted when absent.</param>
public sealed record BrowserEnvelope(
    [property: JsonPropertyName("id")] long Id,
    [property: JsonPropertyName("occurredAt")] DateTimeOffset OccurredAt,
    [property: JsonPropertyName("eventType")] string EventType,
    [property: JsonPropertyName("entityType")] string EntityType,
    [property: JsonPropertyName("entityId")] string EntityId,
    [property: JsonPropertyName("projectId")] Guid? ProjectId,
    [property: JsonPropertyName("actor")] string? Actor,
    [property: JsonPropertyName("actorType")] string? ActorType,
    [property: JsonPropertyName("actorUserId")] string? ActorUserId,
    [property: JsonPropertyName("entityTitle")] string? EntityTitle,
    [property: JsonPropertyName("projectIdPrefix")] string? ProjectIdPrefix,
    [property: JsonPropertyName("issueId"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? IssueId = null,
    [property: JsonPropertyName("changedFields"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    IReadOnlyList<string>? ChangedFields = null,
    [property: JsonPropertyName("dep"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    BrowserDependency? Dep = null,
    [property: JsonPropertyName("reparent"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    BrowserReparent? Reparent = null,
    [property: JsonPropertyName("commitHashes"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    IReadOnlyList<string>? CommitHashes = null,
    [property: JsonPropertyName("row"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    JsonElement? Row = null);

/// <summary>
/// Dependency part of a <see cref="BrowserEnvelope"/> (R8, K15): the type
/// and only those ends whose project equals the event's project.
/// </summary>
/// <param name="Type">Dependency type, e.g. <c>blocks</c>, <c>parent-child</c>, <c>related</c>.</param>
/// <param name="FromId">Hierarchical id of the "from" end; omitted when it lies in another project.</param>
/// <param name="ToId">Hierarchical id of the "to" end; omitted when it lies in another project.</param>
public sealed record BrowserDependency(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("fromId"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? FromId = null,
    [property: JsonPropertyName("toId"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? ToId = null);

/// <summary>Re-parent part of a <see cref="BrowserEnvelope"/>.</summary>
/// <param name="OldParentIds">Hierarchical ids of the old parents the issue was
/// detached from — only those of the event's project (sk-622.21 R19, INV-17).
/// An end of another or of an unknown project is omitted. The skein-api payload
/// does not carry the projects of old parents, so today the array is always
/// empty. An old parent is invalidated by the <c>dependency.deleted</c>
/// (<c>parent-child</c>) the same reparent writes for each detached edge.</param>
/// <param name="NewParentId">Hierarchical id of the new parent; always in the
/// event's project (skein-api rejects a cross-project new parent).</param>
public sealed record BrowserReparent(
    [property: JsonPropertyName("oldParentIds")] IReadOnlyList<string> OldParentIds,
    [property: JsonPropertyName("newParentId")] string NewParentId);

/// <summary>
/// Personal signal (US-11). Body of the NATS subject
/// <c>skein.user.{uid}.signal</c> published by skein-api (mirror of Go
/// <c>internal/signals/contract.go#Signal</c>, T005) and, after per-connection
/// coalescing, the payload of <see cref="BrowserClientMethods.Signal"/>.
/// </summary>
/// <remarks>
/// Carries no data — only the personal areas whose header counters or
/// personal-screen contents may have changed; the tab re-reads those areas
/// through REST. Sent after commit, best-effort (a lost signal is covered by
/// the tab's safety poll, focus and the resync frame). Wire form from
/// skein-api (NATS, T005): <c>{"areas":["inbox","watching"],"sentAt":"2026-10-09T10:15:03.123456Z"}</c>;
/// to the browser: <c>{"areas":["inbox","watching"],"sentAt":"2026-10-09T10:15:03.123456+00:00"}</c>.
/// Both are RFC 3339 UTC (T005: "RFC 3339 on the wire"): Go writes the
/// offset as <c>Z</c>, System.Text.Json as <c>+00:00</c>.
/// <para>
/// The area <see cref="PersonalSignalArea.Spaces"/> (sk-674.18, US-19, K-18;
/// mirror of Go <c>signals.AreaSpaces</c>, T014) is the only area with a
/// payload: <see cref="Spaces"/>, so the tab can show the right toast and
/// leave a space page that no longer exists. Wire form to the browser:
/// <c>{"areas":["spaces","inbox"],"spaces":[{"reason":"invited","spaceId":"k3x9p2qa","spaceName":"Acme"}],"sentAt":"2026-10-12T10:15:03.123456+00:00"}</c>.
/// A frame without the <c>spaces</c> area never carries the field — the
/// wire of the seven older areas is unchanged.
/// </para>
/// <para>
/// Coalescing (<see cref="BrowserClientMethods.Signal"/>): when the window
/// unions several signals, <see cref="Spaces"/> is the union of their
/// entries — no entry is lost. Entries identical in all three fields
/// (<c>reason</c>, <c>spaceId</c>, <c>spaceName</c>) are carried once, at the
/// position of their LAST occurrence; the list is ordered by last occurrence,
/// so the final entry for a space is its latest event. Example: renames
/// Acme → Acme Ltd → Acme within one window give
/// <c>[{"reason":"renamed","spaceId":"k3x9p2qa","spaceName":"Acme Ltd"},{"reason":"renamed","spaceId":"k3x9p2qa","spaceName":"Acme"}]</c>
/// — the current name is the last one. Implemented by the coalescer in T049.
/// </para>
/// </remarks>
/// <param name="Areas">Non-empty set of <see cref="PersonalSignalArea"/> values, each at most once.</param>
/// <param name="SentAt">Publish time (UTC). Diagnostic only: receivers must not order or deduplicate by it.</param>
/// <param name="Spaces">Space-level events for this user, in the order they happened. Serialization: omitted from the JSON when null; a non-null list is written as it is — an empty one as <c>[]</c>. Senders set it to a non-empty list exactly when <paramref name="Areas"/> contains <see cref="PersonalSignalArea.Spaces"/> and leave it null otherwise; skein-api never sends an empty list (Go <c>omitempty</c> drops it), so a well-formed frame carries no <c>"spaces":[]</c>.</param>
public sealed record PersonalSignal(
    [property: JsonPropertyName("areas")] IReadOnlyList<string> Areas,
    [property: JsonPropertyName("sentAt")] DateTimeOffset SentAt,
    [property: JsonPropertyName("spaces"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    IReadOnlyList<PersonalSignalSpace>? Spaces = null);

/// <summary>
/// One entry of <see cref="PersonalSignal.Spaces"/> (sk-674.18, US-19,
/// K-18): mirror of Go <c>internal/signals/contract.go#SpaceEvent</c> (T014).
/// </summary>
/// <remarks>
/// Names the space only by its short id and, where the tab needs it for a
/// toast and may no longer be able to read it, its name. No issue or project
/// data. Wire form: <c>{"reason":"renamed","spaceId":"k3x9p2qa","spaceName":"Acme Ltd"}</c>.
/// </remarks>
/// <param name="Reason">Why the entry was sent, one of <see cref="SpaceSignalReason"/>.</param>
/// <param name="SpaceId">Space short id — the <c>id</c> of <c>GET /api/v1/me/spaces</c>; with the slug it forms the place address <c>/spaces/&lt;id&gt;-&lt;slug&gt;</c>.</param>
/// <param name="SpaceName">Space name at the time of the event (the new name for <c>renamed</c>). Present for <c>invited</c>, <c>added</c>, <c>owner_assigned</c>, <c>removed</c>, <c>deleted</c> and <c>renamed</c>; omitted from the JSON otherwise.</param>
public sealed record PersonalSignalSpace(
    [property: JsonPropertyName("reason")] string Reason,
    [property: JsonPropertyName("spaceId")] string SpaceId,
    [property: JsonPropertyName("spaceName"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? SpaceName = null);

/// <summary>
/// Closed set of <see cref="PersonalSignalSpace.Reason"/> values — the literal
/// set of spec sk-674.18 US-19 (screens 1.15), mirror of Go
/// <c>signals.SpaceReason</c>. Every reason re-reads «my spaces», projects,
/// invitations and counters; the reason only chooses the toast and whether an
/// open space page is left (<c>removed</c>, <c>deleted</c>).
/// </summary>
public static class SpaceSignalReason
{
    /// <summary>The user was invited to the space.</summary>
    public const string Invited = "invited";

    /// <summary>An invitation the user sent was accepted (to whoever invited; the accepting user gets <see cref="Added"/>).</summary>
    public const string Accepted = "accepted";

    /// <summary>An invitation the user sent was declined (to the space owner and the sender).</summary>
    public const string Declined = "declined";

    /// <summary>An invitation expired (to the space owner and the sender).</summary>
    public const string Expired = "expired";

    /// <summary>The user was removed from the space — an open page of it is left.</summary>
    public const string Removed = "removed";

    /// <summary>The user became a member (accepted, or added by an admin).</summary>
    public const string Added = "added";

    /// <summary>The user became the owner (created for them by an admin, or an owner change).</summary>
    public const string OwnerAssigned = "owner_assigned";

    /// <summary>The owner changed (to the previous owner and the members).</summary>
    public const string OwnerChanged = "owner_changed";

    /// <summary>The space was deleted (to its members) — an open page of it is left.</summary>
    public const string Deleted = "deleted";

    /// <summary>The space was renamed (to its members); the entry carries the new name.</summary>
    public const string Renamed = "renamed";

    /// <summary>Every reason in canonical order (Go <c>signals.SpaceReasons()</c>).</summary>
    public static IReadOnlyList<string> All { get; } =
        [Invited, Accepted, Declined, Expired, Removed, Added, OwnerAssigned, OwnerChanged, Deleted, Renamed];
}

/// <summary>
/// Closed set of <see cref="PersonalSignal.Areas"/> values — the literal set of
/// spec sk-622.21 US-11 plus <see cref="Spaces"/> (sk-674.18 US-19), mirror of
/// Go <c>signals.Area</c>. Strings rather than
/// an enum so an additively introduced area does not fail deserialization.
/// </summary>
public static class PersonalSignalArea
{
    /// <summary>The Inbox header badge and the Inbox queue.</summary>
    public const string Inbox = "inbox";

    /// <summary>The Mentions header badge and the Mentions queue.</summary>
    public const string Mentions = "mentions";

    /// <summary>The Watching header badge and the Watching column.</summary>
    public const string Watching = "watching";

    /// <summary>The "on me" / "delegated" lenses: header, tasks column, projects column.</summary>
    public const string Lens = "lens";

    /// <summary>The author's unreviewed counter, lists filtered by "unreviewed", private review fields of an open card.</summary>
    public const string Unreviewed = "unreviewed";

    /// <summary>Contents of the personal task lists: "on me", "delegated", "created by me".</summary>
    public const string Tasks = "tasks";

    /// <summary>The project list and the user's memberships.</summary>
    public const string Projects = "projects";

    /// <summary>
    /// The user's spaces, their projects, invitations and counters (sk-674.18,
    /// K-18). The only area with a payload: <see cref="PersonalSignal.Spaces"/>.
    /// </summary>
    public const string Spaces = "spaces";

    /// <summary>Every area in canonical order (Go <c>signals.Areas()</c>).</summary>
    public static IReadOnlyList<string> All { get; } =
        [Inbox, Mentions, Watching, Lens, Unreviewed, Tasks, Projects, Spaces];
}

/// <summary>
/// Personal reminder frame (US-11). Body of the NATS subject
/// <c>skein.user.{owner}.reminder</c> (mirror of Go
/// <c>internal/signals/contract.go#ReminderFrame</c>, T005) and the payload of
/// <see cref="BrowserClientMethods.Reminder"/>, forwarded unchanged to the
/// owner's connections.
/// </summary>
/// <remarks>
/// At-least-once: the same frame may arrive twice; the tab rings at most once
/// per <see cref="FiringId"/>. Never coalesced. Holds no review data.
/// </remarks>
/// <param name="ReminderId">Reminder id.</param>
/// <param name="IssueId">Hierarchical id of the reminded issue (e.g. <c>sk-42</c>).</param>
/// <param name="ProjectId">The issue's project.</param>
/// <param name="Kind">Lifecycle step, one of <see cref="ReminderFrameKind"/>.</param>
/// <param name="RemindAt">Due time (UTC) after this step.</param>
/// <param name="FiringId">Firing-instance key <c>{reminderId}@{remindAt}</c> — the ring dedup key.</param>
public sealed record ReminderFrame(
    [property: JsonPropertyName("reminderId")] Guid ReminderId,
    [property: JsonPropertyName("issueId")] string IssueId,
    [property: JsonPropertyName("projectId")] Guid ProjectId,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("remindAt")] DateTimeOffset RemindAt,
    [property: JsonPropertyName("firingId")] string FiringId);

/// <summary>
/// Closed set of <see cref="ReminderFrame.Kind"/> values, mirror of Go
/// <c>signals.ReminderKind</c>.
/// </summary>
public static class ReminderFrameKind
{
    /// <summary>A reminder was created or re-armed.</summary>
    public const string Set = "set";

    /// <summary>A reminder was postponed.</summary>
    public const string Snoozed = "snoozed";

    /// <summary>A due reminder fired — the only kind that rings the bell.</summary>
    public const string Rang = "rang";

    /// <summary>A reminder was cancelled.</summary>
    public const string Dismissed = "dismissed";
}

/// <summary>
/// Payload of <see cref="BrowserClientMethods.Resync"/> (US-10, K11). The frame
/// itself is the instruction; its content is diagnostic.
/// </summary>
/// <remarks>Wire form: <c>{"sentAt":"2026-10-09T10:15:03+00:00"}</c> — RFC 3339 UTC, offset written as <c>+00:00</c> by System.Text.Json.</remarks>
/// <param name="SentAt">Time (UTC) the replica sent the frame. Diagnostic only.</param>
public sealed record ResyncFrame(
    [property: JsonPropertyName("sentAt")] DateTimeOffset SentAt);
