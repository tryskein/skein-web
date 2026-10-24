using System.Text.Json;
using SkeinWeb.Hubs;

namespace SkeinWeb.Tests.Hubs;

/// <summary>
/// JSON round-trip tests for <see cref="EventEnvelope"/>. Fixtures match
/// what skein-api's Go <c>buildEnvelope</c> produces verbatim — drift
/// here means the .NET hub will mis-deserialise live messages.
/// </summary>
public class EventEnvelopeTests
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    [Fact]
    public void Deserialize_IssueCreated_FullEnvelope()
    {
        // Canonical shape produced by Go buildEnvelope when an issue is
        // created. ProjectId present, Payload empty, OldData null.
        var json = """
        {
          "id": 42,
          "occurredAt": "2026-04-01T10:15:03Z",
          "eventType": "issue.created",
          "entityType": "issue",
          "entityId": "demo-42",
          "projectId": "11111111-2222-3333-4444-555555555555",
          "newData": {"title": "Bug", "priority": 3}
        }
        """;

        var env = JsonSerializer.Deserialize<EventEnvelope>(json, JsonOpts);
        Assert.NotNull(env);
        Assert.Equal(42, env!.Id);
        Assert.Equal("issue.created", env.EventType);
        Assert.Equal("issue", env.EntityType);
        Assert.Equal("demo-42", env.EntityId);
        Assert.Equal(Guid.Parse("11111111-2222-3333-4444-555555555555"), env.ProjectId);
        Assert.Null(env.Payload);
        Assert.Null(env.OldData);
        Assert.NotNull(env.NewData);
        Assert.Equal("Bug", env.NewData!.Value.GetProperty("title").GetString());
    }

    [Fact]
    public void Deserialize_UserDeactivated_NoProjectId()
    {
        // User-scoped event has no projectId.
        var json = """
        {
          "id": 99,
          "occurredAt": "2026-04-02T08:00:00Z",
          "eventType": "user.deactivated",
          "entityType": "user",
          "entityId": "77777777-7777-7777-7777-777777777777"
        }
        """;
        var env = JsonSerializer.Deserialize<EventEnvelope>(json, JsonOpts);
        Assert.NotNull(env);
        Assert.Null(env!.ProjectId);
        Assert.Equal("user.deactivated", env.EventType);
    }

    [Fact]
    public void Deserialize_ProjectMemberAdded_NewDataCarriesUserId()
    {
        // Cache-delta path: new_data.userId is the user who joined.
        var json = """
        {
          "id": 7,
          "occurredAt": "2026-04-03T12:00:00Z",
          "eventType": "project.member_added",
          "entityType": "project",
          "entityId": "11111111-2222-3333-4444-555555555555",
          "projectId": "11111111-2222-3333-4444-555555555555",
          "newData": {"userId": "88888888-8888-8888-8888-888888888888", "role": "member"}
        }
        """;
        var env = JsonSerializer.Deserialize<EventEnvelope>(json, JsonOpts);
        Assert.NotNull(env);
        Assert.NotNull(env!.NewData);
        Assert.Equal(
            "88888888-8888-8888-8888-888888888888",
            env.NewData!.Value.GetProperty("userId").GetString());
    }

    [Fact]
    public void Deserialize_ProjectMemberRemoved_OldDataCarriesUserId()
    {
        var json = """
        {
          "id": 8,
          "occurredAt": "2026-04-03T12:30:00Z",
          "eventType": "project.member_removed",
          "entityType": "project",
          "entityId": "11111111-2222-3333-4444-555555555555",
          "projectId": "11111111-2222-3333-4444-555555555555",
          "oldData": {"userId": "88888888-8888-8888-8888-888888888888", "role": "member"}
        }
        """;
        var env = JsonSerializer.Deserialize<EventEnvelope>(json, JsonOpts);
        Assert.NotNull(env);
        Assert.NotNull(env!.OldData);
        Assert.Equal(
            "88888888-8888-8888-8888-888888888888",
            env.OldData!.Value.GetProperty("userId").GetString());
    }

    [Fact]
    public void Deserialize_OmittedFields_StayNull()
    {
        // Lifecycle events with no payload / no diff produce a minimal
        // envelope. Optional fields must come back null, not throw.
        var json = """
        {
          "id": 1,
          "occurredAt": "2026-04-01T10:15:03Z",
          "eventType": "project.archived",
          "entityType": "project",
          "entityId": "11111111-2222-3333-4444-555555555555",
          "projectId": "11111111-2222-3333-4444-555555555555"
        }
        """;
        var env = JsonSerializer.Deserialize<EventEnvelope>(json, JsonOpts);
        Assert.NotNull(env);
        Assert.Null(env!.Payload);
        Assert.Null(env.OldData);
        Assert.Null(env.NewData);
    }

    // sk-27 — sk-21 enrichment fields (actor, actorType, actorUserId,
    // entityTitle, projectIdPrefix) must round-trip through the record so
    // SendAsync forwards them to SignalR clients verbatim. Before sk-27 the
    // record lacked these properties, System.Text.Json silently dropped them
    // on deserialise, and every live ticker row landed with actor=`?` and
    // an empty title.

    [Fact]
    public void Deserialize_Sk21Enrichment_ParsesAllFields()
    {
        // Shape matches skein-api >= v0.9.0 envelope for an issue.created
        // event authored by a human user.
        var json = """
        {
          "id": 1234,
          "occurredAt": "2026-05-23T10:30:00Z",
          "eventType": "issue.created",
          "entityType": "issue",
          "entityId": "demo-6.12",
          "projectId": "11111111-2222-3333-4444-555555555555",
          "actor": "alice",
          "actorType": "human",
          "actorUserId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
          "entityTitle": "core-api: enforce alias recreation delay",
          "projectIdPrefix": "demo"
        }
        """;
        var env = JsonSerializer.Deserialize<EventEnvelope>(json, JsonOpts);
        Assert.NotNull(env);
        Assert.Equal("alice", env!.Actor);
        Assert.Equal("human", env.ActorType);
        Assert.Equal("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", env.ActorUserId);
        Assert.Equal("core-api: enforce alias recreation delay", env.EntityTitle);
        Assert.Equal("demo", env.ProjectIdPrefix);
    }

    [Fact]
    public void Roundtrip_Sk21Enrichment_AllFieldsSurviveSerializeToClient()
    {
        // The bridge deserialises NATS bytes into EventEnvelope, projects it
        // onto the compact BrowserEnvelope (sk-622.21 T033) and SendAsync
        // serialises THAT to the browser. The regression sk-27 closed — sk-21
        // enrichment silently dropped on the way out — must stay closed
        // through the projection.
        var inputJson = """
        {
          "id": 1234,
          "occurredAt": "2026-05-23T10:30:00Z",
          "eventType": "issue.created",
          "entityType": "issue",
          "entityId": "demo-6.12",
          "projectId": "11111111-2222-3333-4444-555555555555",
          "actor": "alice",
          "actorType": "agent",
          "actorUserId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
          "entityTitle": "core-api: enforce alias recreation delay",
          "projectIdPrefix": "demo"
        }
        """;
        var env = JsonSerializer.Deserialize<EventEnvelope>(inputJson, JsonOpts);
        Assert.NotNull(env);

        var browser = BrowserEnvelopeProjector.Project(env!);
        Assert.NotNull(browser);

        // The SignalR JSON hub protocol's own payload options — what the
        // browser actually receives.
        var outputJson = JsonSerializer.Serialize(
            browser!, new Microsoft.AspNetCore.SignalR.JsonHubProtocolOptions().PayloadSerializerOptions);
        using var doc = JsonDocument.Parse(outputJson);
        var root = doc.RootElement;
        Assert.Equal("alice", root.GetProperty("actor").GetString());
        Assert.Equal("agent", root.GetProperty("actorType").GetString());
        Assert.Equal("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", root.GetProperty("actorUserId").GetString());
        Assert.Equal("core-api: enforce alias recreation delay", root.GetProperty("entityTitle").GetString());
        Assert.Equal("demo", root.GetProperty("projectIdPrefix").GetString());
    }

    [Fact]
    public void Deserialize_LegacyPublisher_EnrichmentFieldsNull()
    {
        // Pre-sk-21 skein-api (< 0.9.0) emits envelopes without the 5 new
        // keys. Deserialise must NOT throw and must surface null on each
        // enrichment field, so the frontend's `?`-fallback path keeps
        // working without a wire-shape regression for existing consumers.
        var json = """
        {
          "id": 1,
          "occurredAt": "2026-04-01T10:15:03Z",
          "eventType": "issue.created",
          "entityType": "issue",
          "entityId": "demo-1",
          "projectId": "11111111-2222-3333-4444-555555555555"
        }
        """;
        var env = JsonSerializer.Deserialize<EventEnvelope>(json, JsonOpts);
        Assert.NotNull(env);
        Assert.Null(env!.Actor);
        Assert.Null(env.ActorType);
        Assert.Null(env.ActorUserId);
        Assert.Null(env.EntityTitle);
        Assert.Null(env.ProjectIdPrefix);
    }
}
