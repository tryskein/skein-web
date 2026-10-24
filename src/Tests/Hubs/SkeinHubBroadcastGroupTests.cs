using System.Security.Claims;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SkeinWeb.Auth;
using SkeinWeb.Hubs;

namespace SkeinWeb.Tests.Hubs;

/// <summary>
/// sk-163 S7b — Hub half of the external-broadcast-suppression contract. An
/// INTERNAL connection joins <see cref="SkeinHub.OrgBroadcastGroup"/> on
/// connect (so it receives org-wide broadcasts such as theme.updated); an
/// EXTERNAL connection (cookie claim <c>is_external=true</c>) does NOT. The
/// bridge half (org-wide broadcasts target the group, not Clients.All) is
/// covered by NatsBridgeThemeBroadcastTests.
/// </summary>
public class SkeinHubBroadcastGroupTests
{
    /// <summary>
    /// A hub over the production collaborators. Connecting makes no call to
    /// skein-api any more (sk-622.21: access is checked on declaration), so
    /// the access client's transport is never reached here.
    /// </summary>
    private static SkeinHub NewHub(HubCallerContext context, IGroupManager groups)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(TimeProvider.System);
        services.Configure<SkeinApiOptions>(o => o.InternalSecret = "test-secret");
        services.AddSkeinServiceApiClient("http://api.local/");
        var provider = services.BuildServiceProvider();
        return new SkeinHub(
            provider.GetRequiredService<SkeinServiceApiClient>(),
            new ConnectionRegistry(TimeProvider.System),
            new DeclarationLimiter(TimeProvider.System),
            new HubDeliveryOptions(),
            NullLogger<SkeinHub>.Instance)
        {
            Context = context,
            Groups = groups,
            Clients = new Mock<IHubCallerClients>().Object,
        };
    }

    private static ClaimsPrincipal Principal(Guid userId, string role, bool isExternal)
    {
        var identity = new ClaimsIdentity(
            new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
                new Claim(ClaimTypes.Role, role),
                new Claim("is_external", isExternal ? "true" : "false"),
            },
            authenticationType: "TestCookie");
        return new ClaimsPrincipal(identity);
    }

    /// <summary>
    /// Drive OnConnectedAsync for a principal and return the set of group names
    /// the connection was added to.
    /// </summary>
    private static async Task<List<string>> ConnectAndCaptureGroups(Guid userId, string role, bool isExternal)
    {
        var addedGroups = new List<string>();

        var groups = new Mock<IGroupManager>();
        groups.Setup(g => g.AddToGroupAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns<string, string, CancellationToken>((_, group, _) =>
            {
                addedGroups.Add(group);
                return Task.CompletedTask;
            });

        var context = new Mock<HubCallerContext>();
        context.SetupGet(c => c.UserIdentifier).Returns(userId.ToString());
        context.SetupGet(c => c.ConnectionId).Returns("conn-" + userId.ToString("N")[..8]);
        context.SetupGet(c => c.User).Returns(Principal(userId, role, isExternal));
        context.SetupGet(c => c.ConnectionAborted).Returns(CancellationToken.None);

        var hub = NewHub(context.Object, groups.Object);

        await hub.OnConnectedAsync();
        return addedGroups;
    }

    [Fact]
    public async Task InternalConnection_JoinsOrgBroadcastGroup()
    {
        var groups = await ConnectAndCaptureGroups(Guid.NewGuid(), "user", isExternal: false);
        Assert.Contains(SkeinHub.OrgBroadcastGroup, groups);
    }

    [Fact]
    public async Task ExternalConnection_DoesNotJoinOrgBroadcastGroup()
    {
        var groups = await ConnectAndCaptureGroups(Guid.NewGuid(), "user", isExternal: true);
        Assert.DoesNotContain(SkeinHub.OrgBroadcastGroup, groups);
    }

    /// <summary>
    /// sk-163 S7b — pins the deliberate "absent is_external claim → treated as
    /// internal → joins the group" choice. This is safe by construction: the
    /// is_external claim is minted unconditionally ("true"/"false") at every
    /// sign-in/refresh path (AuthController / SsoSessionMiddleware / OIDC), so a
    /// real external principal ALWAYS carries is_external=true. The only way to
    /// reach the Hub with the claim absent is a stale pre-S1 cookie, which is
    /// necessarily an internal user — so absent ⟺ internal, and joining is
    /// correct. Locking it here guards against a future regression that would
    /// flip this default.
    /// </summary>
    [Fact]
    public async Task AbsentExternalClaim_DefaultsInternal_JoinsOrgBroadcastGroup()
    {
        var addedGroups = new List<string>();
        var groups = new Mock<IGroupManager>();
        groups.Setup(g => g.AddToGroupAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns<string, string, CancellationToken>((_, group, _) =>
            {
                addedGroups.Add(group);
                return Task.CompletedTask;
            });

        var userId = Guid.NewGuid();
        // Principal WITHOUT an is_external claim (pre-S1 cookie shape).
        var identity = new ClaimsIdentity(
            new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
                new Claim(ClaimTypes.Role, "user"),
            },
            authenticationType: "TestCookie");

        var context = new Mock<HubCallerContext>();
        context.SetupGet(c => c.UserIdentifier).Returns(userId.ToString());
        context.SetupGet(c => c.ConnectionId).Returns("conn-absent");
        context.SetupGet(c => c.User).Returns(new ClaimsPrincipal(identity));
        context.SetupGet(c => c.ConnectionAborted).Returns(CancellationToken.None);

        var hub = NewHub(context.Object, groups.Object);

        await hub.OnConnectedAsync();

        Assert.Contains(SkeinHub.OrgBroadcastGroup, addedGroups);
    }
}
