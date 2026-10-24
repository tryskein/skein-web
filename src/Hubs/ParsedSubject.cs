namespace SkeinWeb.Hubs;

/// <summary>
/// Top-level grouping of a parsed NATS subject. Drives the dispatch
/// branch in <see cref="NatsBridge"/>.
/// </summary>
public enum SubjectNamespace
{
    /// <summary>Subject under <c>skein.events.project.{pid}.…</c> — project-scoped events.</summary>
    Project,

    /// <summary>Subject under <c>skein.user.{uid}.…</c> — user-global events.</summary>
    User,

    /// <summary>
    /// Subject under <c>skein.events.malformed.…</c> or any subject the
    /// parser couldn't recognise. The bridge logs and drops these.
    /// </summary>
    Malformed,
}

/// <summary>
/// Structured result of parsing a NATS subject. Mirrors the inputs to
/// skein-api's Go <c>BuildSubject</c> — keeping the two in sync is what
/// lets the .NET hub authorise events without re-fetching from skein-api.
/// </summary>
/// <remarks>
/// Subject schemes (R3.2 plan, finalised, plus sk-10.3 theme additions):
/// <list type="bullet">
///   <item><c>skein.events.project.{pid}.{entity}.{action}.{eid}</c> — project-scoped lifecycle / parent</item>
///   <item><c>skein.events.project.{pid}.{entity}.field.{kebab}.{eid}</c> — project-scoped per-field child</item>
///   <item><c>skein.user.{uid}.{action}</c> — user-global lifecycle</item>
///   <item><c>skein.user.{uid}.field.{kebab}</c> — user-global per-field child</item>
///   <item><c>skein.user.{uid}.theme.preview</c> — sk-10.3 ephemeral
///         theme preview push (user-scoped; payload <c>{userId, variables}</c>);
///         forwarded to SignalR <c>theme.preview</c>.</item>
///   <item><c>skein.user.{uid}.theme.user-pref.updated</c> — sk-10.3
///         user-pref refetch hint (user-scoped; payload <c>{}</c>);
///         forwarded to SignalR <c>theme.user-pref.updated</c>.</item>
///   <item><c>skein.user.{author}.theme.updated</c> — sk-674.18 K-31
///         change of the author's theme (user-scoped; payload
///         <c>{themeId, variables}</c>); forwarded to SignalR
///         <c>theme.updated</c> on the author's connections only. The former
///         org-wide <c>skein.events.theme.*</c> is not recognised.</item>
///   <item><c>skein.events.malformed.…</c> — fallback for malformed event_type</item>
/// </list>
/// </remarks>
/// <param name="Namespace">Top-level grouping. Drives the dispatch branch.</param>
/// <param name="ProjectId">Project UUID for project-scoped events; null otherwise.</param>
/// <param name="UserId">User UUID for user-scoped events; null otherwise.</param>
/// <param name="EntityType">Entity short-name (issue, project, comment, dep, component, user).</param>
/// <param name="Action">Action token (created, updated, member_added, field_changed, etc.) or "field" for field-changed children.</param>
/// <param name="EntityId">Trailing entity id token. For user-namespace subjects this is the user UUID string (same value as <see cref="UserId"/>, from subject parts[2]); for project-scoped subjects it is the entity id (issue hierarchical id, component uuid, etc.).</param>
/// <param name="FieldName">Kebab-case field name on field-changed subjects; null otherwise.</param>
public sealed record ParsedSubject(
    SubjectNamespace Namespace,
    Guid? ProjectId,
    Guid? UserId,
    string EntityType,
    string Action,
    string EntityId,
    string? FieldName
);
