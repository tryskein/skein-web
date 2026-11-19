using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// The early refusal on the real middleware order and the real metadata of the four explicit
/// operations (INV-9, SC-010): which form a technical store failure gets, that it carries no
/// Set-Cookie and no source text, and that "no session" is not a failure.
/// </summary>
[Trait("Category", "Integration")]
[Collection("session-pipeline")]
public sealed class SessionStoreFailureMiddlewareTest
{
    private static readonly Guid Alice = Guid.Parse("0199a1b2-0000-7000-8000-00000000000a");

    private static void FailReads(SessionPipelineHost host) =>
        host.Faults.Before = (name, _) => name == nameof(IDatabase.StringGetAsync)
            ? new RedisConnectionException(ConnectionFailureType.SocketFailure, "injected-secret-source-text")
            : null;

    private static JsonElement Json(SessionPipelineHost.Reply reply) => JsonDocument.Parse(reply.Body).RootElement;

    private static void AssertRefusal(SessionPipelineHost.Reply reply)
    {
        Assert.Equal(HttpStatusCode.BadGateway, reply.Status);
        Assert.Empty(reply.Cookies);
        Assert.DoesNotContain("injected-secret-source-text", reply.Body);
        Assert.DoesNotContain("skein:session:", reply.Body);
    }

    [RedisFact]
    public async Task Login_GetsProblemDetailsWithoutAnErrorMember()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, _, _) = await host.SignInAsync(Alice);
        FailReads(host);

        var reply = await host.SendAsync("/api/auth/login", cookie, HttpMethod.Post);

        AssertRefusal(reply);
        Assert.EndsWith("/upstream-unavailable", Json(reply).GetProperty("type").GetString());
        Assert.False(Json(reply).TryGetProperty("error", out _));
    }

    [RedisTheory]
    [InlineData("/api/auth/signup")]
    [InlineData("/api/auth/invitations/t/signup")]
    [InlineData("/api/auth/password-reset/t")]
    public async Task TheOtherExplicitOperations_GetProblemDetailsWithTheErrorCode(string path)
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, _, _) = await host.SignInAsync(Alice);
        FailReads(host);

        var reply = await host.SendAsync(path, cookie, HttpMethod.Post);

        AssertRefusal(reply);
        Assert.EndsWith("/upstream-unavailable", Json(reply).GetProperty("type").GetString());
        Assert.Equal("upstream_unavailable", Json(reply).GetProperty("error").GetString());
    }

    [RedisFact]
    public async Task ATrustedSsoRequest_ThatIsNotAnExplicitOperation_GetsTheSsoForm()
    {
        await using var host = await SessionPipelineHost.StartAsync(apiAuthMode: "keycloak", trustLoopback: true);
        var (cookie, _, _) = await host.SignInAsync(Alice);
        FailReads(host);

        var reply = await host.SendAsync("/api/auth/other", cookie, null,
            ("X-Auth-Request-User", "alice"), ("X-Auth-Request-Email", "alice@example.com"));

        AssertRefusal(reply);
        Assert.Equal("sso_unavailable", Json(reply).GetProperty("error").GetString());
    }

    [RedisFact]
    public async Task EverythingElse_GetsTheCommonForm()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, _, _) = await host.SignInAsync(Alice);
        FailReads(host);

        var reply = await host.SendAsync("/api/auth/other", cookie);

        AssertRefusal(reply);
        Assert.Equal("upstream_unavailable", Json(reply).GetProperty("error").GetString());
    }

    [RedisFact]
    public async Task AnExplicitOperation_KeepsItsOwnForm_EvenFromATrustedSsoPeer()
    {
        await using var host = await SessionPipelineHost.StartAsync(apiAuthMode: "keycloak", trustLoopback: true);
        var (cookie, _, _) = await host.SignInAsync(Alice);
        FailReads(host);

        var reply = await host.SendAsync("/api/auth/login", cookie, HttpMethod.Post, ("X-Auth-Request-User", "alice"), ("X-Auth-Request-Email", "alice@example.com"));

        AssertRefusal(reply);
        Assert.False(Json(reply).TryGetProperty("error", out _));
    }

    [RedisFact]
    public async Task ARowOfTheFormerFormat_AndGarbage_AreNoSession_NotAFailure()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, key, _) = await host.SignInAsync(Alice);

        await host.Db.KeyDeleteAsync(key);
        await host.Db.HashSetAsync(key, [new HashEntry("data", 1)]);
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.SendAsync("/test/me", cookie)).Status);

        await host.Db.KeyDeleteAsync(key);
        await host.Db.StringSetAsync(key, new byte[] { 1, 2, 3 });
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.SendAsync("/test/me", cookie)).Status);
    }

    [RedisFact]
    public async Task ATechnicalFailureToRemoveAnExpiredTicket_IsARefusal()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, key, _) = await host.SignInAsync(Alice);
        host.Time.Advance(host.Timeouts.Absolute + TimeSpan.FromSeconds(1)); // the session has ended by the stand's clock
        host.Faults.Before = (name, args) => name == nameof(IDatabase.KeyDeleteAsync)
            ? new InvalidOperationException("injected-secret-source-text")
            : null;

        var reply = await host.SendAsync("/test/me", cookie);

        AssertRefusal(reply);
        Assert.True(await host.Db.KeyExistsAsync(key)); // the refusal came from the failed DEL of that row
    }

    [RedisFact]
    public async Task ATechnicalFailureOfTheLifetimeWriteOfALiveTicket_IsARefusal()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, _, _) = await host.SignInAsync(Alice);
        host.Faults.Before = (name, args) => DbProxy.IsScript(name, args, StoreScripts.Read)
            ? new InvalidOperationException("injected-secret-source-text")
            : null;

        var reply = await host.SendAsync("/test/me", cookie);

        AssertRefusal(reply);
    }

    [RedisFact]
    public async Task Control_WithoutACookie_IsUnauthorizedNotARefusal()
    {
        await using var host = await SessionPipelineHost.StartAsync();

        var reply = await host.SendAsync("/test/me");

        Assert.Equal(HttpStatusCode.Unauthorized, reply.Status);
        Assert.Empty(reply.SessionWrites());
    }

    [RedisFact]
    public async Task Control_WithAHealthyRedis_TheSameCookieGivesOk()
    {
        await using var host = await SessionPipelineHost.StartAsync();
        var (cookie, _, _) = await host.SignInAsync(Alice);

        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync("/test/me", cookie)).Status);
    }
}
