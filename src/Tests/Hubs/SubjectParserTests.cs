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
    public void IssueClosed_HierarchicalIdPreserved()
    {
        // Issue ids may contain dots — demo-42.1 is one entity id, not two
        // tokens. The parser must reassemble the trailing segment.
        var subject = $"skein.events.project.{FixedProjectId}.issue.closed.demo-42.1";
        Assert.True(SubjectParser.TryParse(subject, out var parsed));
        Assert.Equal("issue", parsed.EntityType);
        Assert.Equal("closed", parsed.Action);
        Assert.Equal("demo-42.1", parsed.EntityId);
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
