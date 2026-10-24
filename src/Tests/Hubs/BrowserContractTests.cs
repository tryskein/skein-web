using System.Text.Json;
using Microsoft.AspNetCore.SignalR;
using SkeinWeb.Hubs;

namespace SkeinWeb.Tests.Hubs;

/// <summary>
/// Wire shape of the browser contract (sk-622.21 T030): the
/// compact <see cref="BrowserEnvelope"/>, the personal frames
/// <see cref="PersonalSignal"/> / <see cref="ReminderFrame"/> (mirror of
/// skein-api <c>internal/signals/contract.go</c>, T005),
/// <see cref="ResyncFrame"/> and <see cref="DeclareResult"/>; the
/// <c>spaces</c> area and its entries (sk-674.18 T044; mirror of
/// T014).
/// </summary>
/// <remarks>
/// Expected field names are the literals of plan T030 and of the T005 godoc,
/// not read back from the records. Serialization goes through the SignalR
/// JSON hub protocol's own payload options — the serializer that actually
/// writes these frames to browsers.
/// </remarks>
public class BrowserContractTests
{
    private static readonly JsonSerializerOptions HubJson = new JsonHubProtocolOptions().PayloadSerializerOptions;

    private static readonly Guid ProjectA = Guid.Parse("0199a1b2-0000-7000-8000-0000000000a1");

    private static JsonElement Serialize<T>(T value) =>
        JsonDocument.Parse(JsonSerializer.Serialize(value, HubJson)).RootElement;

    private static string[] Keys(JsonElement obj) =>
        obj.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray();

    private static string[] Sorted(params string[] names) =>
        names.OrderBy(n => n, StringComparer.Ordinal).ToArray();

    [Fact]
    public void BrowserEnvelope_AllFieldsSet_HasExactlyTheT030FieldNames()
    {
        var row = JsonDocument.Parse("""{"id":"sk-7","title":"T","rowSeq":42}""").RootElement;
        var env = new BrowserEnvelope(
            Id: 1001,
            OccurredAt: new DateTimeOffset(2026, 10, 9, 10, 15, 3, TimeSpan.Zero),
            EventType: "issue.updated",
            EntityType: "issue",
            EntityId: "sk-7",
            ProjectId: ProjectA,
            Actor: "alice",
            ActorType: "human",
            ActorUserId: "0199a1b2-0000-7000-8000-000000000001",
            EntityTitle: "Title",
            ProjectIdPrefix: "sk",
            IssueId: "sk-7",
            ChangedFields: ["status", "description"],
            Dep: new BrowserDependency("blocks", FromId: "sk-7", ToId: "sk-8"),
            Reparent: new BrowserReparent(["sk-1"], "sk-2"),
            CommitHashes: ["abc1234"],
            Row: row);

        var json = Serialize(env);

        Assert.Equal(
            Sorted("id", "occurredAt", "eventType", "entityType", "entityId", "projectId", "actor",
                "actorType", "actorUserId", "entityTitle", "projectIdPrefix", "issueId", "changedFields",
                "dep", "reparent", "commitHashes", "row"),
            Keys(json));
        Assert.Equal(Sorted("type", "fromId", "toId"), Keys(json.GetProperty("dep")));
        Assert.Equal(Sorted("oldParentIds", "newParentId"), Keys(json.GetProperty("reparent")));

        Assert.Equal(1001, json.GetProperty("id").GetInt64());
        Assert.Equal(ProjectA, json.GetProperty("projectId").GetGuid());
        Assert.Equal(new[] { "status", "description" },
            json.GetProperty("changedFields").EnumerateArray().Select(e => e.GetString()).ToArray());
        // Phase-2 row is forwarded opaquely, rowSeq included.
        Assert.Equal(42, json.GetProperty("row").GetProperty("rowSeq").GetInt64());
    }

    [Fact]
    public void BrowserEnvelope_NeverCarriesPayloadOldDataOrNewData()
    {
        var env = new BrowserEnvelope(
            1, DateTimeOffset.UnixEpoch, "issue.updated", "issue", "sk-7", ProjectA,
            null, null, null, null, null,
            ChangedFields: ["description"]);

        var json = Serialize(env);

        Assert.False(json.TryGetProperty("payload", out _));
        Assert.False(json.TryGetProperty("oldData", out _));
        Assert.False(json.TryGetProperty("newData", out _));
    }

    [Fact]
    public void BrowserEnvelope_OptionalPartsAbsent_AreOmitted()
    {
        var env = new BrowserEnvelope(
            7, DateTimeOffset.UnixEpoch, "project.updated", "project", ProjectA.ToString(), ProjectA,
            "alice", "human", "0199a1b2-0000-7000-8000-000000000001", "Proj", "sk");

        var json = Serialize(env);

        Assert.Equal(
            Sorted("id", "occurredAt", "eventType", "entityType", "entityId", "projectId", "actor",
                "actorType", "actorUserId", "entityTitle", "projectIdPrefix"),
            Keys(json));
    }

    [Fact]
    public void BrowserDependency_EndOutsideProject_IsOmitted()
    {
        // R8 / INV-17: only the end lying in the event's project is carried.
        var json = Serialize(new BrowserDependency("blocks", ToId: "sk-8"));

        Assert.Equal(Sorted("type", "toId"), Keys(json));
        Assert.Equal("sk-8", json.GetProperty("toId").GetString());
    }

    [Fact]
    public void PersonalSignal_RoundTripsTheT005Literal()
    {
        const string goLiteral = """{"areas":["inbox","watching"],"sentAt":"2026-10-09T10:15:03.123456Z"}""";

        var signal = JsonSerializer.Deserialize<PersonalSignal>(goLiteral, HubJson);
        Assert.NotNull(signal);
        Assert.Equal(new[] { "inbox", "watching" }, signal!.Areas);
        Assert.Equal(DateTimeOffset.Parse("2026-10-09T10:15:03.123456Z"), signal.SentAt);

        var json = Serialize(signal);
        Assert.Equal(Sorted("areas", "sentAt"), Keys(json));
        Assert.Equal(new[] { "inbox", "watching" },
            json.GetProperty("areas").EnumerateArray().Select(e => e.GetString()).ToArray());
        Assert.Equal(DateTimeOffset.Parse("2026-10-09T10:15:03.123456Z"),
            json.GetProperty("sentAt").GetDateTimeOffset());
    }

    [Fact]
    public void PersonalSignal_SpacesArea_RoundTripsTheT014Literal()
    {
        // sk-674.18 US-19 / K-18: literal of the "Area spaces" section of
        // skein-api internal/signals/contract.go (T014).
        const string goLiteral = """
        {"areas":["spaces","inbox"],
         "spaces":[{"reason":"invited","spaceId":"k3x9p2qa","spaceName":"Acme"},
                   {"reason":"owner_changed","spaceId":"m7d2w4zt"}],
         "sentAt":"2026-10-12T10:15:03.123456Z"}
        """;

        var signal = JsonSerializer.Deserialize<PersonalSignal>(goLiteral, HubJson);
        Assert.NotNull(signal);
        Assert.Equal(new[] { "spaces", "inbox" }, signal!.Areas);
        Assert.NotNull(signal.Spaces);
        Assert.Equal(2, signal.Spaces!.Count);
        Assert.Equal(("invited", "k3x9p2qa", (string?)"Acme"),
            (signal.Spaces[0].Reason, signal.Spaces[0].SpaceId, signal.Spaces[0].SpaceName));
        Assert.Equal(("owner_changed", "m7d2w4zt", (string?)null),
            (signal.Spaces[1].Reason, signal.Spaces[1].SpaceId, signal.Spaces[1].SpaceName));

        var json = Serialize(signal);
        Assert.Equal(Sorted("areas", "spaces", "sentAt"), Keys(json));
        var entries = json.GetProperty("spaces").EnumerateArray().ToArray();
        Assert.Equal(2, entries.Length);
        Assert.Equal(Sorted("reason", "spaceId", "spaceName"), Keys(entries[0]));
        Assert.Equal("invited", entries[0].GetProperty("reason").GetString());
        Assert.Equal("k3x9p2qa", entries[0].GetProperty("spaceId").GetString());
        Assert.Equal("Acme", entries[0].GetProperty("spaceName").GetString());
        // spaceName is omitted, not null, when the entry carries no name (Go omitempty).
        Assert.Equal(Sorted("reason", "spaceId"), Keys(entries[1]));
        Assert.Equal("owner_changed", entries[1].GetProperty("reason").GetString());
    }

    [Fact]
    public void PersonalSignal_WithoutSpacesArea_CarriesNoSpacesKey()
    {
        // The wire of the seven older areas is unchanged: no "spaces" key at all.
        var json = Serialize(new PersonalSignal(["inbox", "projects"], DateTimeOffset.UnixEpoch));

        Assert.Equal(Sorted("areas", "sentAt"), Keys(json));
    }

    [Fact]
    public void SpaceSignalReason_All_OnTheWire_IsTheClosedSetOfUS19InCanonicalOrder()
    {
        // The reasons are an external contract (spec sk-674.18 US-19, screens
        // 1.15; order of Go signals.SpaceReasons()): checked as written on the
        // browser wire, one entry per reason of the set.
        var signal = new PersonalSignal(
            [PersonalSignalArea.Spaces],
            DateTimeOffset.UnixEpoch,
            SpaceSignalReason.All.Select(r => new PersonalSignalSpace(r, "k3x9p2qa")).ToArray());

        var wire = Serialize(signal).GetProperty("spaces").EnumerateArray()
            .Select(e => e.GetProperty("reason").GetString())
            .ToArray();

        Assert.Equal(
            new[]
            {
                "invited", "accepted", "declined", "expired", "removed",
                "added", "owner_assigned", "owner_changed", "deleted", "renamed",
            },
            wire);
    }

    [Fact]
    public void ReminderFrame_RoundTripsTheT005Shape()
    {
        const string goLiteral = """
        {"reminderId":"0199a1b2-0000-7000-8000-0000000000f1","issueId":"sk-42",
         "projectId":"0199a1b2-0000-7000-8000-0000000000a1","kind":"rang",
         "remindAt":"2026-10-09T10:00:00Z",
         "firingId":"0199a1b2-0000-7000-8000-0000000000f1@2026-10-09T10:00:00Z"}
        """;

        var frame = JsonSerializer.Deserialize<ReminderFrame>(goLiteral, HubJson);
        Assert.NotNull(frame);
        Assert.Equal(Guid.Parse("0199a1b2-0000-7000-8000-0000000000f1"), frame!.ReminderId);
        Assert.Equal("sk-42", frame.IssueId);
        Assert.Equal(ProjectA, frame.ProjectId);
        Assert.Equal("rang", frame.Kind);
        Assert.Equal(DateTimeOffset.Parse("2026-10-09T10:00:00Z"), frame.RemindAt);
        Assert.Equal("0199a1b2-0000-7000-8000-0000000000f1@2026-10-09T10:00:00Z", frame.FiringId);

        var json = Serialize(frame);
        Assert.Equal(
            Sorted("reminderId", "issueId", "projectId", "kind", "remindAt", "firingId"),
            Keys(json));
        Assert.Equal("0199a1b2-0000-7000-8000-0000000000f1@2026-10-09T10:00:00Z",
            json.GetProperty("firingId").GetString());
    }

    [Fact]
    public void ResyncFrame_HasOnlySentAt_InTheDocumentedWireForm()
    {
        var json = Serialize(new ResyncFrame(new DateTimeOffset(2026, 10, 9, 10, 15, 3, TimeSpan.Zero)));

        Assert.Equal(new[] { "sentAt" }, Keys(json));
        // Literal of the ResyncFrame XML doc: RFC 3339 UTC with a numeric offset.
        Assert.Equal("2026-10-09T10:15:03+00:00", json.GetProperty("sentAt").GetString());
    }

    [Fact]
    public void PersonalSignal_AllAreas_AreTheT005AndT014LiteralsInCanonicalOrder()
    {
        // T005 godoc / spec US-11 plus sk-674.18 T014 (area "spaces"):
        // signals.Areas() in canonical order.
        var json = Serialize(new PersonalSignal(PersonalSignalArea.All, DateTimeOffset.UnixEpoch));

        Assert.Equal(
            new[] { "inbox", "mentions", "watching", "lens", "unreviewed", "tasks", "projects", "spaces" },
            json.GetProperty("areas").EnumerateArray().Select(e => e.GetString()).ToArray());
    }

    [Theory]
    [InlineData(ReminderFrameKind.Set, "set")]
    [InlineData(ReminderFrameKind.Snoozed, "snoozed")]
    [InlineData(ReminderFrameKind.Rang, "rang")]
    [InlineData(ReminderFrameKind.Dismissed, "dismissed")]
    public void ReminderFrame_Kind_IsTheT005Literal(string kind, string wire)
    {
        var frame = new ReminderFrame(Guid.Empty, "sk-42", ProjectA, kind, DateTimeOffset.UnixEpoch, "x");

        Assert.Equal(wire, Serialize(frame).GetProperty("kind").GetString());
    }

    [Theory]
    [InlineData(DeclareRejectReason.NoAccess, "no_access")]
    [InlineData(DeclareRejectReason.Limit, "limit")]
    [InlineData(DeclareRejectReason.Rate, "rate")]
    [InlineData(DeclareRejectReason.Invalid, "invalid")]
    public void DeclareRejection_Reason_IsTheT030Literal(string reason, string wire)
    {
        var json = Serialize(new DeclareRejection("p", reason));

        Assert.Equal(wire, json.GetProperty("reason").GetString());
    }

    [Fact]
    public void DeclareAllVisible_Refusal_IsOneRejectionWithAnEmptyProjectId()
    {
        // Form documented on ISkeinHubDeclarations.DeclareAllVisible: the
        // refusal concerns the mode, so projectId is "" and accepted is [].
        var result = new DeclareResult(
            Accepted: [],
            Rejected: [new DeclareRejection("", DeclareRejectReason.Rate)]);

        var json = Serialize(result);

        Assert.Equal(0, json.GetProperty("accepted").GetArrayLength());
        var rejection = Assert.Single(json.GetProperty("rejected").EnumerateArray());
        Assert.Equal(Sorted("projectId", "reason"), Keys(rejection));
        Assert.Equal("", rejection.GetProperty("projectId").GetString());
        Assert.Equal("rate", rejection.GetProperty("reason").GetString());
    }

    [Fact]
    public void DeclareResult_SerializesAcceptedAndRejected()
    {
        var result = new DeclareResult(
            Accepted: [ProjectA.ToString()],
            Rejected: [new DeclareRejection("not-a-uuid", DeclareRejectReason.Invalid)]);

        var json = Serialize(result);

        Assert.Equal(Sorted("accepted", "rejected"), Keys(json));
        Assert.Equal(ProjectA.ToString(), json.GetProperty("accepted")[0].GetString());
        var rejection = json.GetProperty("rejected")[0];
        Assert.Equal(Sorted("projectId", "reason"), Keys(rejection));
        Assert.Equal("not-a-uuid", rejection.GetProperty("projectId").GetString());
        Assert.Equal("invalid", rejection.GetProperty("reason").GetString());
    }
}
