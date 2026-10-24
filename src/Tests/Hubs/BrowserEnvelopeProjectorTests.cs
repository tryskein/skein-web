using System.Text.Json;
using Microsoft.AspNetCore.SignalR;
using SkeinWeb.Hubs;

namespace SkeinWeb.Tests.Hubs;

/// <summary>
/// <see cref="BrowserEnvelopeProjector"/> (sk-622.21 tests No. 60; US-12,
/// INV-13, INV-17, SC-010): what the compact browser envelope carries and,
/// above all, what it never carries. Inputs are NATS envelopes in the shape
/// skein-api writes them (eventbus.WriteHybridUpdateEvents, WriteCommentEvent,
/// dependencies.WriteDependencyEvent with T007 project keys); expected values
/// are literals. The leak check runs on the JSON the SignalR protocol would
/// actually write.
/// </summary>
public class BrowserEnvelopeProjectorTests
{
    private static readonly JsonSerializerOptions NatsJson = new(JsonSerializerDefaults.Web);
    private static readonly JsonSerializerOptions HubJson = new JsonHubProtocolOptions().PayloadSerializerOptions;

    private const string P1 = "0199a1b2-0000-7000-8000-0000000000a1";
    private const string P2 = "0199a1b2-0000-7000-8000-0000000000a2";

    private static EventEnvelope Nats(string json) => JsonSerializer.Deserialize<EventEnvelope>(json, NatsJson)!;

    private static string Wire(BrowserEnvelope env) => JsonSerializer.Serialize(env, HubJson);

    [Fact]
    public void DescriptionEdit_CarriesFieldNamesOnly_NoTextAnywhere()
    {
        var env = Nats($$$"""
        {"id":10,"occurredAt":"2026-10-09T10:00:00Z","eventType":"issue.updated","entityType":"issue",
         "entityId":"sk-7","projectId":"{{{P1}}}","entityTitle":"Title",
         "payload":{"changes":[
           {"field":"description","oldValue":"OLD-DESCRIPTION-TEXT","newValue":"NEW-DESCRIPTION-TEXT"},
           {"field":"acceptanceCriteria","oldValue":"OLD-ACCEPTANCE-TEXT","newValue":"NEW-ACCEPTANCE-TEXT"}]},
         "oldData":{"description":"OLD-DESCRIPTION-TEXT","notes":"NOTES-TEXT"},
         "newData":{"description":"NEW-DESCRIPTION-TEXT","design":"DESIGN-TEXT"}}
        """);

        var browser = BrowserEnvelopeProjector.Project(env);

        Assert.NotNull(browser);
        Assert.Equal(new[] { "description", "acceptanceCriteria" }, browser!.ChangedFields);
        var wire = Wire(browser);
        foreach (var text in new[]
                 {
                     "OLD-DESCRIPTION-TEXT", "NEW-DESCRIPTION-TEXT", "OLD-ACCEPTANCE-TEXT",
                     "NEW-ACCEPTANCE-TEXT", "NOTES-TEXT", "DESIGN-TEXT",
                 })
        {
            Assert.DoesNotContain(text, wire, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("issue.field_changed", "issue")]
    [InlineData("user.field_changed", "user")]
    public void FieldChangedChild_IsNotForBrowsers(string eventType, string entityType)
    {
        var env = Nats($$$"""
        {"id":11,"occurredAt":"2026-10-09T10:00:00Z","eventType":"{{{eventType}}}","entityType":"{{{entityType}}}",
         "entityId":"sk-7","projectId":"{{{P1}}}",
         "payload":{"parent_event_id":10},"oldData":"OLD","newData":"NEW"}
        """);

        Assert.Null(BrowserEnvelopeProjector.Project(env));
    }

    [Fact]
    public void Comment_CarriesIssueId_NotTheBody()
    {
        var env = Nats($$$"""
        {"id":12,"occurredAt":"2026-10-09T10:00:00Z","eventType":"comment.created","entityType":"comment",
         "entityId":"0199a1b2-0000-7000-8000-00000000c001","projectId":"{{{P1}}}","entityTitle":"Parent title",
         "payload":{"issueId":"sk-7"},
         "newData":{"id":"0199a1b2-0000-7000-8000-00000000c001","issueId":"sk-7","body":"COMMENT-BODY-TEXT"}}
        """);

        var browser = BrowserEnvelopeProjector.Project(env);

        Assert.NotNull(browser);
        Assert.Equal("sk-7", browser!.IssueId);
        Assert.DoesNotContain("COMMENT-BODY-TEXT", Wire(browser), StringComparison.Ordinal);
    }

    [Fact]
    public void CrossProjectDependency_OmitsTheForeignEnd_InDepAndInEntityId()
    {
        var env = Nats($$$"""
        {"id":13,"occurredAt":"2026-10-09T10:00:00Z","eventType":"dependency.created","entityType":"dep",
         "entityId":"sk-1::demo-7::blocks","projectId":"{{{P1}}}",
         "newData":{"fromId":"sk-1","toId":"demo-7","type":"blocks","metadata":{},
                    "fromProjectId":"{{{P1}}}","toProjectId":"{{{P2}}}"}}
        """);

        var browser = BrowserEnvelopeProjector.Project(env);

        Assert.NotNull(browser);
        Assert.Equal("blocks", browser!.Dep!.Type);
        Assert.Equal("sk-1", browser.Dep.FromId);
        Assert.Null(browser.Dep.ToId);
        Assert.DoesNotContain("demo-7", Wire(browser), StringComparison.Ordinal);
    }

    [Fact]
    public void SameProjectDependency_KeepsBothEnds()
    {
        var env = Nats($$$"""
        {"id":14,"occurredAt":"2026-10-09T10:00:00Z","eventType":"dependency.deleted","entityType":"dep",
         "entityId":"sk-1::sk-2::blocks","projectId":"{{{P1}}}",
         "oldData":{"fromId":"sk-1","toId":"sk-2","type":"blocks","fromProjectId":"{{{P1}}}","toProjectId":"{{{P1}}}"}}
        """);

        var browser = BrowserEnvelopeProjector.Project(env);

        Assert.Equal("sk-1", browser!.Dep!.FromId);
        Assert.Equal("sk-2", browser.Dep.ToId);
        Assert.Equal("sk-1::sk-2::blocks", browser.EntityId);
    }

    [Fact]
    public void Reparent_OmitsOldParentsOfUnconfirmedProject_KeepsNewParent()
    {
        // R19: the payload of skein-api (dependencies.WriteReparentEvent)
        // carries no project of the old parents; an old parent may be in
        // another project — it must not reach the browser.
        var env = Nats($$$"""
        {"id":16,"occurredAt":"2026-10-09T10:00:00Z","eventType":"issue.reparented","entityType":"issue",
         "entityId":"sk-7","projectId":"{{{P1}}}",
         "payload":{"oldParentIds":["secret-42"],"newParentId":"sk-2"}}
        """);

        var browser = BrowserEnvelopeProjector.Project(env);

        Assert.NotNull(browser);
        Assert.Equal("sk-2", browser!.Reparent!.NewParentId);
        Assert.Empty(browser.Reparent.OldParentIds);
        var wire = Wire(browser);
        Assert.DoesNotContain("secret-42", wire, StringComparison.Ordinal);
        Assert.Contains("sk-2", wire, StringComparison.Ordinal);
    }

    [Fact]
    public void CommitsAttached_CarriesCommitHashes()
    {
        var env = Nats($$$"""
        {"id":15,"occurredAt":"2026-10-09T10:00:00Z","eventType":"issue.commits_attached","entityType":"issue",
         "entityId":"sk-7","projectId":"{{{P1}}}","actor":"alice","actorUserId":"0199a1b2-0000-7000-8000-000000000001",
         "newData":{"hashes":["abc1234","def5678"]}}
        """);

        var browser = BrowserEnvelopeProjector.Project(env);

        Assert.Equal(new[] { "abc1234", "def5678" }, browser!.CommitHashes);
        Assert.Equal("alice", browser.Actor);
    }

    [Fact]
    public void Row_IsForwardedUnchanged()
    {
        var env = Nats($$$"""
        {"id":16,"occurredAt":"2026-10-09T10:00:00Z","eventType":"issue.updated","entityType":"issue",
         "entityId":"sk-7","projectId":"{{{P1}}}","payload":{"changes":[{"field":"status"}]},
         "row":{"id":"sk-7","status":"closed","rowSeq":9001}}
        """);

        var browser = BrowserEnvelopeProjector.Project(env);

        using var wire = JsonDocument.Parse(Wire(browser!));
        var row = wire.RootElement.GetProperty("row");
        Assert.Equal("sk-7", row.GetProperty("id").GetString());
        Assert.Equal("closed", row.GetProperty("status").GetString());
        Assert.Equal(9001, row.GetProperty("rowSeq").GetInt64());
    }

    [Fact]
    public void ProjectReminderEvent_IsNotProjected()
    {
        var env = Nats($$$"""
        {"id":17,"occurredAt":"2026-10-09T10:00:00Z","eventType":"reminder.rang","entityType":"issue",
         "entityId":"sk-7","projectId":"{{{P1}}}","newData":{"ownerId":"0199a1b2-0000-7000-8000-000000000001"}}
        """);

        Assert.Null(BrowserEnvelopeProjector.Project(env));
    }
}
