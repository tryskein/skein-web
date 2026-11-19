using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using SkeinWeb.Auth;
using SkeinWeb.Tests.Auth;

namespace SkeinWeb.Tests.Controllers;

/// <summary>
/// The startup session cleanup in the trust-headers mode, on the real chain of
/// <c>SsoSessionMiddleware</c> (<see cref="SurfacesHost"/>, database <see cref="SurfacesHost.Database"/>):
/// after the cleanup, the old cookie with valid headers of the provider signs the user in afresh,
/// under a new key with a window of its own (US-5).
/// </summary>
[Trait("Category", "Integration")]
[Collection("session-surfaces")]
public sealed class SessionCleanupSurfacesTest
{
    private static readonly (string, string)[] HeadersA = [("X-Auth-Request-Email", "pa@corp.io"), ("X-Auth-Request-User", "pa")];

    /// <summary>The absolute limit of the stand: the default of the setting, 720 h.</summary>
    private const int AbsoluteHours = 720;

    private static DateTimeOffset Whole(DateTimeOffset moment) => DateTimeOffset.FromUnixTimeSeconds(moment.ToUnixTimeSeconds());

    private static async Task<AuthenticationTicket> RowAsync(SurfacesHost host, string key) =>
        TicketSerializer.Default.Deserialize((byte[])(await host.Db.StringGetAsync(key))!)!;

    [RedisFact]
    public async Task AfterTheCleanup_TheOldCookieWithValidProviderHeaders_SignsInAfresh_UnderANewKeyWithANewWindow()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        await using var host = await SurfacesHost.StartAsync(trustHeaders: true, time: time);
        var first = await host.SendAsync(HttpMethod.Get, "/test/me", null, null, HeadersA);
        Assert.Equal(HttpStatusCode.OK, first.Status);
        var oldSet = Assert.Single(first.Sessions(host.CookieName));
        var cookie = oldSet.AsRequestCookie();
        var oldKey = host.KeyOf(oldSet);
        var oldIssued = (await RowAsync(host, oldKey)).Properties.IssuedUtc!.Value;

        time.Advance(TimeSpan.FromHours(5));
        await host.Db.KeyDeleteAsync(SessionStoreMigration.MarkerKey);
        await new SessionStoreMigration(TestRedis.Over(host.Mux, host.Db), TimeProvider.System, NullLogger<SessionStoreMigration>.Instance)
            .RunAsync(TimeSpan.FromSeconds(10), CancellationToken.None);
        Assert.False(await host.Db.KeyExistsAsync(oldKey));

        var requested = time.GetUtcNow();
        var reply = await host.SendAsync(HttpMethod.Get, "/test/me", null, cookie, HeadersA);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        var set = Assert.Single(reply.Sessions(host.CookieName));
        var key = host.KeyOf(set);
        Assert.NotEqual(oldKey, key);
        // The window of the new sign-in: it starts at this request, not at the old sign-in, and runs the absolute limit.
        var row = await RowAsync(host, key);
        var issued = row.Properties.IssuedUtc!.Value;
        Assert.InRange(issued, Whole(requested), time.GetUtcNow());
        Assert.True(issued > oldIssued);
        Assert.Equal(issued.AddHours(AbsoluteHours), row.Properties.ExpiresUtc);
        Assert.Equal(row.Properties.ExpiresUtc!.Value.ToUnixTimeSeconds(), SessionPipelineIntegrationTest.ExpiresOf(set)!.Value.ToUnixTimeSeconds());
    }
}
