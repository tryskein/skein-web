using System.Text;

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
/// Project-scoped <c>{entityId}</c> is one token in the %XX encoding of
/// skein-api's <c>EncodeEntityToken</c>: the bytes <c>A-Z a-z 0-9 _ : -</c>
/// stand for themselves, every other byte of the UTF-8 id (<c>.</c> and
/// <c>%</c> among them) is <c>%</c> and two upper-case hex digits, and the
/// empty id is the lone token <c>%</c>. <see cref="TryParse(string, out ParsedSubject, out string?)"/>
/// decodes it, so <see cref="ParsedSubject.EntityId"/> is the real id
/// (<c>demo-42%2E1</c> gives <c>demo-42.1</c>). A token that is not in
/// that form — a byte outside the alphabet, a lower-case or truncated
/// escape, an escaped byte that stands for itself, bytes that are not
/// UTF-8 — fails the parse.
///
/// A skein-api that predates the encoding writes the raw id, whose dots
/// split it over several tokens (<c>demo-42.1</c> as <c>demo-42</c> and
/// <c>1</c>). Such a tail is joined back with dots. It is never confused
/// with the encoded form: an encoded id is always exactly one token, and a
/// raw id never holds <c>%</c> (neither the issue id alphabet nor any
/// generated id admits it), so a multi-token tail with <c>%</c> fails the
/// parse. A single-token raw id consists of bytes that stand for
/// themselves and decodes to itself.
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
    public static bool TryParse(string subject, out ParsedSubject parsed) =>
        TryParse(subject, out parsed, out _);

    /// <summary>
    /// Try to parse a NATS subject string into its structured form, and say
    /// why when it cannot be parsed.
    /// </summary>
    /// <param name="subject">Raw subject string from the NATS message.</param>
    /// <param name="parsed">Populated on success; set to a Malformed sentinel on failure.</param>
    /// <param name="failure">
    /// <c>null</c> on success. On failure, a short English description of
    /// what is wrong with the subject, for the caller's log line.
    /// </param>
    /// <returns><c>true</c> when the subject matches one of the known schemes.</returns>
    public static bool TryParse(string subject, out ParsedSubject parsed, out string? failure)
    {
        parsed = MalformedSentinel(subject);
        failure = "subject does not match a known scheme";

        if (string.IsNullOrEmpty(subject))
        {
            failure = "subject is empty";
            return false;
        }

        var parts = subject.Split('.');

        // skein.events.malformed.<anything> — explicit malformed namespace.
        if (parts.Length >= 3
            && parts[0] == "skein"
            && parts[1] == "events"
            && parts[2] == "malformed")
        {
            failure = "subject is in the skein.events.malformed namespace";
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
        // The trailing segment is "everything after the action / field-name
        // token": one encoded token, or the raw id of an older skein-api
        // split on its dots (see the remarks on the class).
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
            // parts[7..] == entity id.
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
                if (!TryDecodeEntityId(parts, 7, out var entityId, out failure))
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
            // parts[6..] is the entity id.
            var actionToken = parts[5];
            if (string.IsNullOrEmpty(actionToken))
            {
                return false;
            }
            if (!TryDecodeEntityId(parts, 6, out var eid, out failure))
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
    /// Recovers the entity id from the tail of a project-scoped subject,
    /// <paramref name="parts"/>[<paramref name="start"/>..]: decodes the one
    /// encoded token, or joins the raw tokens of an older skein-api.
    /// </summary>
    private static bool TryDecodeEntityId(string[] parts, int start, out string entityId, out string? failure)
    {
        entityId = "";
        var count = parts.Length - start;
        if (count == 1)
        {
            return TryDecodeEntityToken(parts[start], out entityId, out failure);
        }

        for (var i = start; i < parts.Length; i++)
        {
            if (parts[i].Length == 0)
            {
                failure = "entity id has an empty token";
                return false;
            }
            if (parts[i].Contains('%'))
            {
                failure = "entity id spans several tokens and contains '%': it is neither encoded nor raw";
                return false;
            }
        }
        entityId = string.Join('.', parts, start, count);
        failure = null;
        return true;
    }

    private static readonly UTF8Encoding StrictUtf8 =
        new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>
    /// Decodes one entity id token written by skein-api's
    /// <c>EncodeEntityToken</c>; the format is in the remarks on the class.
    /// Only the canonical encoding is accepted, so one id has exactly one
    /// token.
    /// </summary>
    private static bool TryDecodeEntityToken(string token, out string entityId, out string? failure)
    {
        entityId = "";
        if (token.Length == 0)
        {
            failure = "entity id token is empty";
            return false;
        }
        if (token == "%")
        {
            failure = null;
            return true;
        }

        var bytes = new byte[token.Length];
        var n = 0;
        for (var i = 0; i < token.Length; i++)
        {
            var c = token[i];
            if (IsUnescaped(c))
            {
                bytes[n++] = (byte)c;
                continue;
            }
            if (c != '%')
            {
                failure = $"entity id token has a character outside the encoding alphabet at offset {i}";
                return false;
            }
            if (i + 2 >= token.Length
                || HexValue(token[i + 1]) is not { } hi
                || HexValue(token[i + 2]) is not { } lo)
            {
                failure = $"entity id token has an incomplete or non-upper-case escape at offset {i}";
                return false;
            }
            var b = (byte)((hi << 4) | lo);
            if (IsUnescaped((char)b))
            {
                failure = $"entity id token escapes a byte that stands for itself at offset {i}";
                return false;
            }
            bytes[n++] = b;
            i += 2;
        }

        try
        {
            entityId = StrictUtf8.GetString(bytes, 0, n);
        }
        catch (DecoderFallbackException)
        {
            failure = "entity id token does not decode to UTF-8";
            return false;
        }
        failure = null;
        return true;
    }

    /// <summary>The bytes that stand for themselves in an entity id token.</summary>
    private static bool IsUnescaped(char c) =>
        c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '_' or ':' or '-';

    /// <summary>Value of one upper-case hex digit; null for anything else.</summary>
    private static int? HexValue(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'A' and <= 'F' => c - 'A' + 10,
        _ => null,
    };

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
