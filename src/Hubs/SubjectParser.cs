namespace SkeinWeb.Hubs;

/// <summary>
/// Reverses the NATS subject scheme produced by skein-api's Go
/// <c>BuildSubject</c> (see <c>internal/outbox/subject.go</c>) into a
/// <see cref="ParsedSubject"/> the SignalR bridge can route on.
/// </summary>
/// <remarks>
/// CRITICAL: this parser MUST mirror <c>BuildSubject</c> exactly. Drift
/// between the two breaks live updates silently — events get published
/// on a subject the .NET side doesn't recognise, the cache never sees
/// the delta, and clients miss the message.
///
/// Subject patterns recognised:
/// <code>
///   skein.events.project.{pid}.{entity}.{action}.{entityId}
///   skein.events.project.{pid}.{entity}.field.{kebabName}.{entityId}
///   skein.user.{uid}.{action}
///   skein.user.{uid}.field.{kebabName}
///   skein.user.{uid}.theme.preview | theme.updated | theme.user-pref.updated
///   skein.events.malformed.&lt;anything&gt;   (caught and reported as Malformed)
/// </code>
///
/// Note: project-scoped <c>{entityId}</c> may itself contain dots — issue
/// ids like <c>demo-42.1</c> are valid. The parser accounts for this by
/// treating tokens 5+ as "the entity id, possibly compound" when token 4
/// is the entity name and tokens 4-5 do not match the
/// <c>field.{kebab}</c> infix.
/// </remarks>
public static class SubjectParser
{
    /// <summary>
    /// Try to parse a NATS subject string into its structured form.
    /// </summary>
    /// <param name="subject">Raw subject string from the NATS message.</param>
    /// <param name="parsed">Populated on success; set to a Malformed sentinel on failure.</param>
    /// <returns>
    /// <c>true</c> when the subject matches one of the known schemes.
    /// <c>false</c> when the subject is malformed or unrecognised — caller
    /// should log a warning and drop the message.
    /// </returns>
    public static bool TryParse(string subject, out ParsedSubject parsed)
    {
        parsed = MalformedSentinel(subject);

        if (string.IsNullOrEmpty(subject))
        {
            return false;
        }

        var parts = subject.Split('.');

        // skein.events.malformed.<anything> — explicit malformed namespace.
        if (parts.Length >= 3
            && parts[0] == "skein"
            && parts[1] == "events"
            && parts[2] == "malformed")
        {
            return false;
        }

        // skein.user.{uid}.{action}                    (4 tokens)
        // skein.user.{uid}.field.{kebab}               (5 tokens)
        // skein.user.{uid}.theme.preview               (5 tokens, sk-10.3)
        // skein.user.{uid}.theme.updated               (5 tokens, sk-674.18 K-31)
        // skein.user.{uid}.theme.user-pref.updated     (6 tokens, sk-10.3)
        if (parts.Length >= 4 && parts[0] == "skein" && parts[1] == "user")
        {
            if (!Guid.TryParse(parts[2], out var uid))
            {
                return false;
            }

            // skein.user.{uid}.field.{kebab}
            if (parts.Length == 5 && parts[3] == "field")
            {
                var field = parts[4];
                if (string.IsNullOrEmpty(field))
                {
                    return false;
                }
                parsed = new ParsedSubject(
                    Namespace: SubjectNamespace.User,
                    ProjectId: null,
                    UserId: uid,
                    EntityType: "user",
                    Action: "field_changed",
                    EntityId: parts[2],
                    FieldName: field);
                return true;
            }

            // skein.user.{uid}.theme.preview (sk-10.3) — ephemeral
            // theme preview frame for this one user.
            // skein.user.{author}.theme.updated (sk-674.18 K-31) — a
            // persisted change of the author's theme, for the author only
            // (replaces the org-wide skein.events.theme.updated.{themeId}).
            // Action is encoded as "theme.{verb}" (a single compound action
            // token) so the bridge can branch on it without inspecting
            // FieldName.
            if (parts.Length == 5
                && string.Equals(parts[3], "theme", StringComparison.Ordinal)
                && (string.Equals(parts[4], "preview", StringComparison.Ordinal)
                    || string.Equals(parts[4], "updated", StringComparison.Ordinal)))
            {
                parsed = new ParsedSubject(
                    Namespace: SubjectNamespace.User,
                    ProjectId: null,
                    UserId: uid,
                    EntityType: "theme",
                    Action: "theme." + parts[4],
                    EntityId: parts[2],
                    FieldName: null);
                return true;
            }

            // skein.user.{uid}.theme.user-pref.updated (sk-10.3) — the
            // caller's customThemeId moved (typically after a fork).
            // Frontend refetches /me/theme.
            if (parts.Length == 6
                && string.Equals(parts[3], "theme", StringComparison.Ordinal)
                && string.Equals(parts[4], "user-pref", StringComparison.Ordinal)
                && string.Equals(parts[5], "updated", StringComparison.Ordinal))
            {
                parsed = new ParsedSubject(
                    Namespace: SubjectNamespace.User,
                    ProjectId: null,
                    UserId: uid,
                    EntityType: "theme",
                    Action: "theme.user-pref.updated",
                    EntityId: parts[2],
                    FieldName: null);
                return true;
            }

            // skein.user.{uid}.{action}
            if (parts.Length == 4)
            {
                var action = parts[3];
                if (string.IsNullOrEmpty(action))
                {
                    return false;
                }
                parsed = new ParsedSubject(
                    Namespace: SubjectNamespace.User,
                    ProjectId: null,
                    UserId: uid,
                    EntityType: "user",
                    Action: action,
                    EntityId: parts[2],
                    FieldName: null);
                return true;
            }

            // Anything else under skein.user.* is malformed.
            return false;
        }

        // skein.events.project.{pid}.{entity}.{action}.{entityId...}
        // skein.events.project.{pid}.{entity}.field.{kebab}.{entityId...}
        //
        // EntityId may contain dots (issue hierarchical ids), so the trailing
        // segment is "everything after the action / field-name token".
        if (parts.Length >= 7
            && parts[0] == "skein"
            && parts[1] == "events"
            && parts[2] == "project")
        {
            if (!Guid.TryParse(parts[3], out var pid))
            {
                return false;
            }

            var entity = parts[4];
            if (string.IsNullOrEmpty(entity))
            {
                return false;
            }

            // Field-changed shape: parts[5] == "field", parts[6] == kebab,
            // parts[7..] == entity id (possibly compound).
            if (parts[5] == "field")
            {
                if (parts.Length < 8)
                {
                    return false;
                }
                var field = parts[6];
                if (string.IsNullOrEmpty(field))
                {
                    return false;
                }
                var entityId = string.Join('.', parts, 7, parts.Length - 7);
                if (string.IsNullOrEmpty(entityId))
                {
                    return false;
                }
                parsed = new ParsedSubject(
                    Namespace: SubjectNamespace.Project,
                    ProjectId: pid,
                    UserId: null,
                    EntityType: entity,
                    Action: "field_changed",
                    EntityId: entityId,
                    FieldName: field);
                return true;
            }

            // Lifecycle / parent shape: parts[5] is the action token,
            // parts[6..] is the entity id (possibly compound).
            var actionToken = parts[5];
            if (string.IsNullOrEmpty(actionToken))
            {
                return false;
            }
            var eid = string.Join('.', parts, 6, parts.Length - 6);
            if (string.IsNullOrEmpty(eid))
            {
                return false;
            }
            parsed = new ParsedSubject(
                Namespace: SubjectNamespace.Project,
                ProjectId: pid,
                UserId: null,
                EntityType: entity,
                Action: actionToken,
                EntityId: eid,
                FieldName: null);
            return true;
        }

        return false;
    }

    /// <summary>
    /// Returns a Malformed-namespace sentinel <see cref="ParsedSubject"/>.
    /// Used as the default <c>out</c> value so callers that ignore the
    /// boolean still see <see cref="SubjectNamespace.Malformed"/>.
    /// </summary>
    private static ParsedSubject MalformedSentinel(string subject) =>
        new(
            Namespace: SubjectNamespace.Malformed,
            ProjectId: null,
            UserId: null,
            EntityType: "",
            Action: "",
            EntityId: subject,
            FieldName: null);
}
