using System.Text.Json;

namespace SkeinWeb.Hubs;

/// <summary>
/// Projects the full NATS <see cref="EventEnvelope"/> onto the compact
/// <see cref="BrowserEnvelope"/> sent to browsers (spec sk-622.21 US-12,
/// INV-13, INV-17; plan T033).
/// </summary>
/// <remarks>
/// <para>Only what the consumers of §"Envelope consumers" read is carried;
/// no field VALUE of the issue is ever copied — <c>payload</c>,
/// <c>oldData</c> and <c>newData</c> are read for a closed list of keys
/// (field names, ids, hashes) and dropped.</para>
/// <list type="bullet">
///   <item>Per-field child edit events (<c>*.field_changed</c>) are not
///         projected: the parent <c>*.updated</c> carries
///         <see cref="BrowserEnvelope.ChangedFields"/> from
///         <c>payload.changes[].field</c>.</item>
///   <item>Project-scoped <c>reminder.*</c> events are not projected: a
///         reminder reaches its owner as a personal frame (K14).</item>
///   <item>Comment and attachment events carry
///         <see cref="BrowserEnvelope.IssueId"/>.</item>
///   <item>Dependency events carry the type and only the ends whose project
///         equals the event's project (K15, R8); an end of another project —
///         or of an unknown project — is omitted, from
///         <see cref="BrowserEnvelope.Dep"/> and from the composite
///         <see cref="BrowserEnvelope.EntityId"/> (<c>from::to::type</c>)
///         alike.</item>
///   <item><c>issue.commits_attached</c> carries
///         <see cref="BrowserEnvelope.CommitHashes"/>;
///         <c>issue.reparented</c> carries
///         <see cref="BrowserEnvelope.Reparent"/> — the new parent and only
///         the old parents whose project is confirmed equal to the event's
///         project (R19; today none, see <see cref="BrowserReparent"/>); the phase-2
///         <see cref="EventEnvelope.Row"/> is forwarded unchanged.</item>
/// </list>
/// </remarks>
public static class BrowserEnvelopeProjector
{
    private const string FieldChangedSuffix = ".field_changed";
    private const string UpdatedSuffix = ".updated";
    private const string ReminderPrefix = "reminder.";
    private const string DepEntity = "dep";
    private const string DepIdSeparator = "::";

    /// <summary>
    /// Projects <paramref name="envelope"/>; returns <c>null</c> when the event
    /// is not delivered to browsers at all.
    /// </summary>
    public static BrowserEnvelope? Project(EventEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);

        if (envelope.EventType.EndsWith(FieldChangedSuffix, StringComparison.Ordinal)
            || envelope.EventType.StartsWith(ReminderPrefix, StringComparison.Ordinal))
        {
            return null;
        }

        var entityId = envelope.EntityId;
        BrowserDependency? dep = null;
        if (string.Equals(envelope.EntityType, DepEntity, StringComparison.Ordinal))
        {
            (dep, entityId) = ProjectDependency(envelope);
        }

        return new BrowserEnvelope(
            Id: envelope.Id,
            OccurredAt: envelope.OccurredAt,
            EventType: envelope.EventType,
            EntityType: envelope.EntityType,
            EntityId: entityId,
            ProjectId: envelope.ProjectId,
            Actor: envelope.Actor,
            ActorType: envelope.ActorType,
            ActorUserId: envelope.ActorUserId,
            EntityTitle: envelope.EntityTitle,
            ProjectIdPrefix: envelope.ProjectIdPrefix,
            IssueId: IssueIdOf(envelope),
            ChangedFields: ChangedFieldsOf(envelope),
            Dep: dep,
            Reparent: ReparentOf(envelope),
            CommitHashes: CommitHashesOf(envelope),
            Row: envelope.Row);
    }

    private static string? IssueIdOf(EventEnvelope envelope)
    {
        if (envelope.EntityType is not ("comment" or "attachment"))
        {
            return null;
        }
        return StringProp(envelope.Payload, "issueId")
               ?? StringProp(envelope.NewData, "issueId")
               ?? StringProp(envelope.OldData, "issueId");
    }

    private static IReadOnlyList<string>? ChangedFieldsOf(EventEnvelope envelope)
    {
        if (!envelope.EventType.EndsWith(UpdatedSuffix, StringComparison.Ordinal)
            || envelope.Payload is not { ValueKind: JsonValueKind.Object } payload
            || !payload.TryGetProperty("changes", out var changes)
            || changes.ValueKind != JsonValueKind.Array)
        {
            return null;
        }
        var fields = new List<string>();
        foreach (var change in changes.EnumerateArray())
        {
            var field = StringProp(change, "field");
            if (field is not null && !fields.Contains(field, StringComparer.Ordinal))
            {
                fields.Add(field);
            }
        }
        return fields;
    }

    private static (BrowserDependency? Dep, string EntityId) ProjectDependency(EventEnvelope envelope)
    {
        // new_data on dependency.created, old_data on dependency.deleted (T007).
        var data = envelope.NewData is { ValueKind: JsonValueKind.Object } ? envelope.NewData : envelope.OldData;
        var type = StringProp(data, "type");
        var fromId = InEventProject(envelope, StringProp(data, "fromId"), StringProp(data, "fromProjectId"));
        var toId = InEventProject(envelope, StringProp(data, "toId"), StringProp(data, "toProjectId"));
        var entityId = type is null
            ? ""
            : (fromId ?? "") + DepIdSeparator + (toId ?? "") + DepIdSeparator + type;
        return (type is null ? null : new BrowserDependency(type, fromId, toId), entityId);
    }

    private static string? InEventProject(EventEnvelope envelope, string? endId, string? endProject)
    {
        if (endId is null || envelope.ProjectId is not { } eventProject)
        {
            return null;
        }
        return Guid.TryParse(endProject, out var p) && p == eventProject ? endId : null;
    }

    private static BrowserReparent? ReparentOf(EventEnvelope envelope)
    {
        if (!string.Equals(envelope.EventType, "issue.reparented", StringComparison.Ordinal))
        {
            return null;
        }
        var newParent = StringProp(envelope.Payload, "newParentId");
        if (newParent is null)
        {
            return null;
        }
        // R19 (INV-17, SC-010): an old parent goes to the browser only when its
        // project is confirmed equal to the event's project. The payload
        // (skein-api dependencies.WriteReparentEvent) carries no project of the
        // old parents, and an old parent may lie in another project (a
        // cross-project parent is allowed at create, Reparent detaches every
        // parent-child edge) — so no old parent is confirmed and none is sent.
        // The project is never inferred from the id prefix. The tab refreshes
        // an old parent of its own project from the dependency.deleted that
        // the same reparent writes per detached edge (K15). The new parent is
        // in the event's project: skein-api rejects a cross-project new parent
        // (ErrReparentCrossProject).
        return new BrowserReparent([], newParent);
    }

    private static IReadOnlyList<string>? CommitHashesOf(EventEnvelope envelope) =>
        string.Equals(envelope.EventType, "issue.commits_attached", StringComparison.Ordinal)
            ? StringArrayProp(envelope.NewData, "hashes") ?? []
            : null;

    private static string? StringProp(JsonElement? obj, string name) =>
        obj is { ValueKind: JsonValueKind.Object } o
        && o.TryGetProperty(name, out var v)
        && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;

    private static IReadOnlyList<string>? StringArrayProp(JsonElement? obj, string name)
    {
        if (obj is not { ValueKind: JsonValueKind.Object } o
            || !o.TryGetProperty(name, out var arr)
            || arr.ValueKind != JsonValueKind.Array)
        {
            return null;
        }
        return arr.EnumerateArray()
            .Where(e => e.ValueKind == JsonValueKind.String)
            .Select(e => e.GetString()!)
            .ToArray();
    }
}
