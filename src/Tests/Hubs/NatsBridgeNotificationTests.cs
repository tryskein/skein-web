using System.Text.Json;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NATS.Client.Core;
using SkeinWeb.Hubs;

namespace SkeinWeb.Tests.Hubs;

/// <summary>
/// Tests for the R3.3 per-user notification subject
/// (<c>skein.user.{uid}.notification</c>).
/// </summary>
/// <remarks>
/// Notifications are forwarded exclusively to the targeted user — no
/// admin fan-out (in contrast to the user-namespace lifecycle events
/// which include admins). The bridge deserialises a smaller
/// <see cref="NotificationEnvelope"/> shape, distinct from the
/// <see cref="EventEnvelope"/> used everywhere else.
/// </remarks>
public class NatsBridgeNotificationTests
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    private static readonly Guid AdminUser = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private static readonly Guid TargetUser = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
    private static readonly Guid OtherUser = Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc");

    /// <summary>
    /// Build a bridge over a hub whose per-user proxies record every
    /// SendAsync invocation, tagged with the receiving user id. An admin
    /// (<see cref="AdminUser"/>) and a bystander (<see cref="OtherUser"/>)
    /// exist only as possible wrong recipients.
    /// </summary>
    private static (NatsBridge bridge, List<(string userId, string method, object env)> sent)
        BuildBridge()
    {
        var sent = new List<(string, string, object)>();
        var clientsByUser = new Dictionary<string, Mock<IClientProxy>>();
        Mock<IClientProxy> ProxyFor(string userId)
        {
            if (clientsByUser.TryGetValue(userId, out var existing)) return existing;
            var mock = new Mock<IClientProxy>();
            mock.Setup(c => c.SendCoreAsync(It.IsAny<string>(), It.IsAny<object?[]>(), It.IsAny<CancellationToken>()))
                .Returns<string, object?[], CancellationToken>((method, args, _) =>
                {
                    lock (sent)
                    {
                        sent.Add((userId, method, args[0]!));
                    }
                    return Task.CompletedTask;
                });
            clientsByUser[userId] = mock;
            return mock;
        }

        var clientsMock = new Mock<IHubClients>();
        clientsMock.Setup(c => c.User(It.IsAny<string>()))
            .Returns<string>(uid => ProxyFor(uid).Object);

        var hubContext = new Mock<IHubContext<SkeinHub>>();
        hubContext.SetupGet(h => h.Clients).Returns(clientsMock.Object);

        var conn = new Mock<INatsConnection>();
        var bridge = new NatsBridge(
            conn.Object,
            hubContext.Object,
            NullLogger<NatsBridge>.Instance);
        return (bridge, sent);
    }

    private static byte[] Encode(NotificationEnvelope env) =>
        JsonSerializer.SerializeToUtf8Bytes(env, JsonOpts);

    [Fact]
    public async Task NotificationEvent_ForwardsToTargetUserOnly_NoAdminFanout()
    {
        var (bridge, sent) = BuildBridge();
        var subject = $"skein.user.{TargetUser}.notification";
        var env = new NotificationEnvelope(
            NotificationId: 42,
            UserId: TargetUser,
            EventId: 100,
            EventType: "comment.created",
            ProjectId: null,
            CreatedAt: DateTimeOffset.UtcNow);

        await bridge.Dispatch(subject, Encode(env), CancellationToken.None);

        // Only the target user receives the frame — not the admin, not
        // the other user. Notifications are addressed; admin fan-out is
        // intentionally excluded for privacy (admins shouldn't see every
        // user's inbox events).
        Assert.Single(sent);
        var (uid, method, payload) = sent[0];
        Assert.Equal(TargetUser.ToString(), uid);
        Assert.Equal("event", method);
        Assert.IsType<NotificationEnvelope>(payload);
    }

    [Fact]
    public async Task NotificationEvent_NoBody_DropsSilently()
    {
        var (bridge, sent) = BuildBridge();
        var subject = $"skein.user.{TargetUser}.notification";

        await bridge.Dispatch(subject, Array.Empty<byte>(), CancellationToken.None);

        Assert.Empty(sent);
    }

    [Fact]
    public async Task NotificationEvent_MalformedBody_DoesNotThrow()
    {
        var (bridge, sent) = BuildBridge();
        var subject = $"skein.user.{TargetUser}.notification";

        await bridge.Dispatch(subject, "not json"u8.ToArray(), CancellationToken.None);

        Assert.Empty(sent);
    }
}
