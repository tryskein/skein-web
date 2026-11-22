using SkeinWeb.Hubs;

namespace SkeinWeb.Tests.Hubs;

/// <summary>
/// Mirror of skein-api/internal/outbox/subject_test.go. Every case here
/// must match the corresponding Go test exactly — drift between the two
/// breaks live updates silently.
/// </summary>
public class SubjectParserTests
{
    // The fixed project / user UUIDs match the Go tests' fixtures so a
    // regression is easy to triangulate.
    private static readonly Guid FixedProjectId =
        Guid.Parse("11111111-2222-3333-4444-555555555555");

    private static readonly Guid FixedUserId =
        Guid.Parse("77777777-7777-7777-7777-777777777777");

    [Fact]
    public void IssueCreated_ReturnsProjectScoped()
    {
        var subject = $"skein.events.project.{FixedProjectId}.issue.created.demo-42";
        Assert.True(SubjectParser.TryParse(subject, out var parsed));
        Assert.Equal(SubjectNamespace.Project, parsed.Namespace);
        Assert.Equal(FixedProjectId, parsed.ProjectId);
        Assert.Null(parsed.UserId);
        Assert.Equal("issue", parsed.EntityType);
        Assert.Equal("created", parsed.Action);
        Assert.Equal("demo-42", parsed.EntityId);
        Assert.Null(parsed.FieldName);
    }

    [Fact]
    public void IssueClosed_HierarchicalIdDecoded()
    {
        // sk-977.7.74: skein-api writes the id as one %XX token; demo-42.1
        // arrives as demo-42%2E1 and must come back as the real id.
        var subject = $"skein.events.project.{FixedProjectId}.issue.closed.demo-42%2E1";
        Assert.True(SubjectParser.TryParse(subject, out var parsed));
        Assert.Equal("issue", parsed.EntityType);
        Assert.Equal("closed", parsed.Action);
        Assert.Equal("demo-42.1", parsed.EntityId);
    }

    // sk-977.7.74: the entity id token in the format of skein-api's
    // EncodeEntityToken (subject_test.go TestBuildSubject_EntityTailIsOneToken
    // holds the same pairs), for both project-scoped shapes.
    [Theory]
    [InlineData("demo-42", "demo-42")]
    [InlineData("demo-42%2E1%2E3", "demo-42.1.3")]
    [InlineData("demo-a%2E%2Eb", "demo-a..b")]
    [InlineData("demo-x%2E", "demo-x.")]
    [InlineData("demo-a%252Eb", "demo-a%2Eb")]
    [InlineData("%25", "%")]
    [InlineData("%", "")]
    [InlineData("a%20b%2A%3E", "a b*>")]
    [InlineData("%C3%A9", "\u00e9")]
    [InlineData("demo-1::demo-2::blocks", "demo-1::demo-2::blocks")]
    public void ProjectSubject_EntityIdTokenDecoded(string token, string wantId)
    {
        var lifecycle = $"skein.events.project.{FixedProjectId}.issue.created.{token}";
        Assert.True(SubjectParser.TryParse(lifecycle, out var parsed, out var failure));
        Assert.Null(failure);
        Assert.Equal("created", parsed.Action);
        Assert.Equal(wantId, parsed.EntityId);

        var field = $"skein.events.project.{FixedProjectId}.issue.field.priority.{token}";
        Assert.True(SubjectParser.TryParse(field, out parsed, out failure));
        Assert.Null(failure);
        Assert.Equal("field_changed", parsed.Action);
        Assert.Equal("priority", parsed.FieldName);
        Assert.Equal(wantId, parsed.EntityId);
    }

    // sk-977.7.74: a token that is not the canonical encoding of any id is
    // refused with a reason, in both project-scoped shapes.
    [Theory]
    [InlineData("demo%")]          // truncated escape
    [InlineData("demo%2")]         // truncated escape
    [InlineData("demo%2e1")]       // lower-case hex
    [InlineData("demo%G0")]        // not hex
    [InlineData("demo%41")]        // escapes a byte that stands for itself
    [InlineData("demo%%")]         // escape of an escape character
    [InlineData("demo+1")]         // byte outside the alphabet, unescaped
    [InlineData("%C3")]            // not UTF-8
    [InlineData("%FF%FE")]         // not UTF-8
    [InlineData("demo-42.%2E1")]   // several tokens holding '%'
    [InlineData("demo-42.1+2")]    // several tokens, a byte outside the raw id alphabet
    [InlineData("%%ABC")]          // digest token too short
    [InlineData("%%833a0585255e446c16e719145efbffae39c44fce96540c01f4e46af7090d1626")] // digest in lower case
    [InlineData("%%833A0585255E446C16E719145EFBFFAE39C44FCE96540C01F4E46AF7090D16260")] // digest too long
    public void ProjectSubject_BadEntityIdToken_ReturnsFalseWithReason(string tail)
    {
        foreach (var subject in new[]
        {
            $"skein.events.project.{FixedProjectId}.issue.created.{tail}",
            $"skein.events.project.{FixedProjectId}.issue.field.priority.{tail}",
        })
        {
            Assert.False(SubjectParser.TryParse(subject, out var parsed, out var failure));
            Assert.Equal(SubjectNamespace.Malformed, parsed.Namespace);
            Assert.False(string.IsNullOrWhiteSpace(failure));
        }
    }

    [Fact]
    public void ProjectSubject_DigestTokenOfOverlongId_IsOpaque()
    {
        // sk-977.7.74: an id whose encoding exceeds 1024 bytes travels as
        // "%%" + its SHA-256; the parse succeeds and the token stands for
        // the id, which the envelope carries.
        const string digest = "%%833A0585255E446C16E719145EFBFFAE39C44FCE96540C01F4E46AF7090D1626";
        foreach (var subject in new[]
        {
            $"skein.events.project.{FixedProjectId}.dependency.created.{digest}",
            $"skein.events.project.{FixedProjectId}.issue.field.priority.{digest}",
        })
        {
            Assert.True(SubjectParser.TryParse(subject, out var parsed, out var failure));
            Assert.Null(failure);
            Assert.Equal(SubjectNamespace.Project, parsed.Namespace);
            Assert.Equal(digest, parsed.EntityId);
        }
    }

    [Theory]
    [InlineData("demo-42.1", "demo-42.1")]
    [InlineData("demo-1::demo-2.1::blocks", "demo-1::demo-2.1::blocks")]
    public void ProjectSubject_RawIdOfOlderSkeinApi_JoinedBack(string tail, string wantId)
    {
        // A skein-api without the encoding writes the raw id, split over
        // several tokens by its dots; the parser keeps accepting it so the
        // services can be upgraded in either order.
        var subject = $"skein.events.project.{FixedProjectId}.issue.closed.{tail}";
        Assert.True(SubjectParser.TryParse(subject, out var parsed, out var failure));
        Assert.Null(failure);
        Assert.Equal(wantId, parsed.EntityId);
    }

    [Fact]
    public void IssueFieldChanged_Priority()
    {
        var subject = $"skein.events.project.{FixedProjectId}.issue.field.priority.demo-42";
        Assert.True(SubjectParser.TryParse(subject, out var parsed));
        Assert.Equal(SubjectNamespace.Project, parsed.Namespace);
        Assert.Equal("issue", parsed.EntityType);
        Assert.Equal("field_changed", parsed.Action);
        Assert.Equal("priority", parsed.FieldName);
        Assert.Equal("demo-42", parsed.EntityId);
    }

    [Fact]
    public void IssueFieldChanged_AcceptanceCriteriaKebab()
    {
        // Go BuildSubject uses kebab-case in the subject path even though
        // the Go/JSON payload stays camelCase (acceptanceCriteria → acceptance-criteria).
        var subject = $"skein.events.project.{FixedProjectId}.issue.field.acceptance-criteria.demo-42";
        Assert.True(SubjectParser.TryParse(subject, out var parsed));
        Assert.Equal("acceptance-criteria", parsed.FieldName);
    }

    // The reason overload reports no failure for a subject it parses, in
    // every scheme it recognises.
    [Theory]
    [InlineData("skein.user.77777777-7777-7777-7777-777777777777.created")]
    [InlineData("skein.user.77777777-7777-7777-7777-777777777777.field.name")]
    [InlineData("skein.user.77777777-7777-7777-7777-777777777777.theme.preview")]
    [InlineData("skein.user.77777777-7777-7777-7777-777777777777.theme.updated")]
    [InlineData("skein.user.77777777-7777-7777-7777-777777777777.theme.user-pref.updated")]
    [InlineData("skein.events.project.11111111-2222-3333-4444-555555555555.issue.created.demo-42")]
    [InlineData("skein.events.project.11111111-2222-3333-4444-555555555555.issue.field.priority.demo-42")]
    public void ParsedSubject_ReportsNoFailure(string subject)
    {
        Assert.True(SubjectParser.TryParse(subject, out _, out var failure));
        Assert.Null(failure);
    }

    [Fact]
    public void UserCreated_ReturnsUserScoped()
    {
        var subject = $"skein.user.{FixedUserId}.created";
        Assert.True(SubjectParser.TryParse(subject, out var parsed));
        Assert.Equal(SubjectNamespace.User, parsed.Namespace);
        Assert.Null(parsed.ProjectId);
        Assert.Equal(FixedUserId, parsed.UserId);
        Assert.Equal("user", parsed.EntityType);
        Assert.Equal("created", parsed.Action);
    }

    [Fact]
    public void UserDeactivated_ReturnsUserScoped()
    {
        var subject = $"skein.user.{FixedUserId}.deactivated";
        Assert.True(SubjectParser.TryParse(subject, out var parsed));
        Assert.Equal(SubjectNamespace.User, parsed.Namespace);
        Assert.Equal("deactivated", parsed.Action);
    }

    [Fact]
    public void UserFieldChanged_Name()
    {
        var subject = $"skein.user.{FixedUserId}.field.name";
        Assert.True(SubjectParser.TryParse(subject, out var parsed));
        Assert.Equal(SubjectNamespace.User, parsed.Namespace);
        Assert.Equal("field_changed", parsed.Action);
        Assert.Equal("name", parsed.FieldName);
    }

    [Fact]
    public void CommentCreated_PreservesCommentUuid()
    {
        var commentId = "abcd1234-0000-0000-0000-aabbccddeeff";
        var subject = $"skein.events.project.{FixedProjectId}.comment.created.{commentId}";
        Assert.True(SubjectParser.TryParse(subject, out var parsed));
        Assert.Equal("comment", parsed.EntityType);
        Assert.Equal("created", parsed.Action);
        Assert.Equal(commentId, parsed.EntityId);
    }

    [Fact]
    public void DependencyCreated_UsesEventTypeShortName()
    {
        // Go events.entity_type is "dep", but BuildSubject uses the
        // event-type token "dependency" — the parser sees only the
        // subject, so EntityType reflects the subject token.
        var subject = $"skein.events.project.{FixedProjectId}.dependency.created.demo-42";
        Assert.True(SubjectParser.TryParse(subject, out var parsed));
        Assert.Equal("dependency", parsed.EntityType);
        Assert.Equal("created", parsed.Action);
        Assert.Equal("demo-42", parsed.EntityId);
    }

    [Fact]
    public void ProjectMemberAdded_ProjectIdAlsoIsEntityId()
    {
        // For project-level events the project_id appears twice — once as
        // the namespace, once as the trailing entity id.
        var subject = $"skein.events.project.{FixedProjectId}.project.member_added.{FixedProjectId}";
        Assert.True(SubjectParser.TryParse(subject, out var parsed));
        Assert.Equal("project", parsed.EntityType);
        Assert.Equal("member_added", parsed.Action);
        Assert.Equal(FixedProjectId.ToString(), parsed.EntityId);
    }

    [Fact]
    public void ComponentCreated_PreservesComponentUuid()
    {
        var componentId = "deadbeef-0000-0000-0000-000000000001";
        var subject = $"skein.events.project.{FixedProjectId}.component.created.{componentId}";
        Assert.True(SubjectParser.TryParse(subject, out var parsed));
        Assert.Equal("component", parsed.EntityType);
        Assert.Equal("created", parsed.Action);
        Assert.Equal(componentId, parsed.EntityId);
    }

    [Fact]
    public void MalformedNamespace_ReturnsFalseAndMalformedSentinel()
    {
        var subject = "skein.events.malformed.no_dot";
        Assert.False(SubjectParser.TryParse(subject, out var parsed));
        Assert.Equal(SubjectNamespace.Malformed, parsed.Namespace);
    }

    [Fact]
    public void EmptySubject_ReturnsFalse()
    {
        Assert.False(SubjectParser.TryParse("", out var parsed));
        Assert.Equal(SubjectNamespace.Malformed, parsed.Namespace);
    }

    [Fact]
    public void UnknownPrefix_ReturnsFalse()
    {
        Assert.False(SubjectParser.TryParse("weird.unknown.subject", out var parsed));
        Assert.Equal(SubjectNamespace.Malformed, parsed.Namespace);
    }

    [Fact]
    public void InvalidProjectUuid_ReturnsFalse()
    {
        var subject = "skein.events.project.NOT-A-UUID.issue.created.demo-1";
        Assert.False(SubjectParser.TryParse(subject, out var parsed));
        Assert.Equal(SubjectNamespace.Malformed, parsed.Namespace);
    }

    [Fact]
    public void InvalidUserUuid_ReturnsFalse()
    {
        Assert.False(SubjectParser.TryParse("skein.user.NOT-A-UUID.created", out var parsed));
        Assert.Equal(SubjectNamespace.Malformed, parsed.Namespace);
    }

    [Fact]
    public void ShortProjectSubject_ReturnsFalse()
    {
        // Need at least 7 tokens for a project-scoped subject.
        var subject = $"skein.events.project.{FixedProjectId}.issue";
        Assert.False(SubjectParser.TryParse(subject, out _));
    }

    // ---------------- sk-10.3 — theme subjects ----------------

    [Fact]
    public void ThemePreview_UserScoped()
    {
        var subject = $"skein.user.{FixedUserId}.theme.preview";
        Assert.True(SubjectParser.TryParse(subject, out var parsed));
        Assert.Equal(SubjectNamespace.User, parsed.Namespace);
        Assert.Equal(FixedUserId, parsed.UserId);
        Assert.Equal("theme", parsed.EntityType);
        Assert.Equal("theme.preview", parsed.Action);
        Assert.Null(parsed.ProjectId);
    }

    [Fact]
    public void ThemeUserPrefUpdated_UserScoped()
    {
        var subject = $"skein.user.{FixedUserId}.theme.user-pref.updated";
        Assert.True(SubjectParser.TryParse(subject, out var parsed));
        Assert.Equal(SubjectNamespace.User, parsed.Namespace);
        Assert.Equal(FixedUserId, parsed.UserId);
        Assert.Equal("theme.user-pref.updated", parsed.Action);
    }

    [Fact]
    public void ThemeUpdated_UserScoped_EventOfTheAuthorOnly()
    {
        // sk-674.18 K-31: a theme change is published to its author only.
        var subject = $"skein.user.{FixedUserId}.theme.updated";
        Assert.True(SubjectParser.TryParse(subject, out var parsed));
        Assert.Equal(SubjectNamespace.User, parsed.Namespace);
        Assert.Equal(FixedUserId, parsed.UserId);
        Assert.Equal("theme.updated", parsed.Action);
        Assert.Null(parsed.ProjectId);
    }

    [Theory]
    [InlineData("skein.events.theme.updated.aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")]
    [InlineData("skein.events.theme.updated.NOT-A-UUID")]
    public void FormerThemeBroadcastSubject_IsNotRecognised(string subject)
    {
        // K-31: skein-api no longer publishes the org-wide subject; a stray
        // message on it is dropped, never routed to anybody.
        Assert.False(SubjectParser.TryParse(subject, out var parsed));
        Assert.Equal(SubjectNamespace.Malformed, parsed.Namespace);
    }
}
