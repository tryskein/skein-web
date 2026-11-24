using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// The session formats of the former version (1.x) and of this one do not accept each other: a value
/// of the former purpose and a former hash row are no session here, while a value of the current
/// purpose on the same keyring and row is accepted; and a session this version has just issued is
/// readable by nothing of the former reader (US-6, SC-011, SC-013).
/// </summary>
[Trait("Category", "Integration")]
[Collection("session-pipeline")]
public sealed class SessionFormatRejectionTest
{
    private static readonly Guid Alice = Guid.Parse("0199a1b2-0000-7000-8000-00000000000a");

    private static AuthenticationTicket Ticket(string key) => new(
        new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(
            [new System.Security.Claims.Claim("Microsoft.AspNetCore.Authentication.Cookies-SessionId", key)], "Cookies")),
        "Cookies");

    /// <summary>The cookie format of the former version: the default purpose of the cookie handler.</summary>
    private static TicketDataFormat FormerFormat(SessionPipelineHost host) =>
        new(host.Services.GetRequiredService<IDataProtectionProvider>().CreateProtector(
            "Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware", "Cookies", "v2"));

    [RedisTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AValueOfTheFormerPurpose_IsRejectedUnderBothNames_AndTheCurrentOneIsAccepted(bool insecureHttp)
    {
        await using var host = await SessionPipelineHost.StartAsync(insecureHttp);
        var (_, key, _) = await host.SignInAsync(Alice); // a LIVE row under this key
        var former = FormerFormat(host);
        var current = host.Services.GetRequiredService<TicketDataFormat>();

        foreach (var name in new[] { "skein.sid", "__Host-skein.sid" })
        {
            var old = await host.SendAsync("/test/me", $"{name}={Uri.EscapeDataString(former.Protect(Ticket(key)))}");
            Assert.Equal(HttpStatusCode.Unauthorized, old.Status);
        }
        var fresh = await host.SendAsync("/test/me", $"{host.CookieName}={Uri.EscapeDataString(current.Protect(Ticket(key)))}");
        Assert.Equal(HttpStatusCode.OK, fresh.Status); // control, and (insecure mode) the new skein.sid works
    }

    [RedisFact]
    public async Task AFormerHashWithALongTtl_AndAFormerCookie_AreRejected()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var key = "skein:session:legacy-" + Guid.NewGuid().ToString("N");
        await host.Db.HashSetAsync(key, [new HashEntry("absexp", -1), new HashEntry("sldexp", 86400), new HashEntry("data", new byte[] { 1 })]);
        await host.Db.KeyExpireAsync(key, TimeSpan.FromDays(30));

        var reply = await host.SendAsync("/test/me", $"{host.CookieName}={Uri.EscapeDataString(FormerFormat(host).Protect(Ticket(key)))}");

        Assert.Equal(HttpStatusCode.Unauthorized, reply.Status);
    }

    [RedisFact]
    public async Task ASessionJustIssued_IsAcceptedHere_AndTheReaderOfTheFormerVersionAcceptsNeitherItsCookieNorItsRow()
    {
        await using var host = await SessionPipelineHost.StartAsync();

        var (cookie, key, set) = await host.SignInAsync(Alice);

        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync("/test/me", cookie)).Status);
        // The former reader unprotects with its own purpose and reads the row as a hash (HGETALL).
        Assert.Null(FormerFormat(host).Unprotect(Uri.UnescapeDataString(set.Value)));
        var wrongType = await Assert.ThrowsAsync<RedisServerException>(() => host.Db.HashGetAllAsync(key));
        Assert.StartsWith("WRONGTYPE", wrongType.Message, StringComparison.Ordinal);
    }
}
