using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using SkeinWeb.Auth;
using SkeinWeb.Tests.Auth;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Controllers;

/// <summary>
/// The native OIDC callback on the real <see cref="OpenIdConnectHandler"/> against a local provider
/// (a static configuration, an id_token signed with a test key, a stub token endpoint), the real
/// issuer and a real Redis: a new key for every kind of incoming cookie, the redirect, the cookies
/// that must and must not be counted, the refusals in the existing text form, and the sign-out.
/// </summary>
[Trait("Category", "Integration")]
[Collection("session-surfaces")]
public sealed class OidcCallbackSessionIntegrationTest
{
    private const string Realm = "https://idp.test/realms/skein";
    private const string ClientId = "skein";
    private static readonly Guid A = SurfacesApi.UserA;

    /// <summary>The local provider: signs id_tokens with its key and answers the token endpoint.</summary>
    private sealed class FakeIdp : HttpMessageHandler
    {
        private readonly SymmetricSecurityKey _key = new(Encoding.UTF8.GetBytes("0123456789abcdef0123456789abcdef"));

        public string? Nonce { get; set; }

        public SecurityKey SigningKey => _key;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
            {
                Issuer = Realm,
                Audience = ClientId,
                Expires = DateTime.UtcNow.AddMinutes(5),
                SigningCredentials = new SigningCredentials(_key, SecurityAlgorithms.HmacSha256),
                Claims = new Dictionary<string, object>
                {
                    ["sub"] = "idp-user-1",
                    ["nonce"] = Nonce!,
                    ["preferred_username"] = "alice",
                    ["email"] = "a@x.io",
                    ["groups"] = new[] { "/skein-users" },
                },
            });
            var body = JsonSerializer.Serialize(new { id_token = token, access_token = "at", token_type = "Bearer", expires_in = 3600 });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            });
        }
    }

    private static async Task<(SurfacesHost Host, FakeIdp Idp)> StartAsync(
        Action<IServiceCollection>? extra = null, bool useTokenLifetime = false,
        Action<Microsoft.AspNetCore.Authentication.AuthenticationProperties?>? onTicket = null)
    {
        var idp = new FakeIdp();
        var sso = new SsoOptions();
        sso.Oidc.Authority = Realm;
        sso.Oidc.ClientId = ClientId;
        sso.Oidc.ClientSecret = "secret";
        sso.Oidc.AllowedGroup = "skein-users";
        var host = await SurfacesHost.StartAsync(WebAuthMode.FromApi("keycloak", Realm), sso, services =>
        {
            extra?.Invoke(services);
            services.PostConfigure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
            {
                // On: the handler puts the token's lifetime into the properties it hands the issuer.
                options.UseTokenLifetime = useTokenLifetime;
                if (onTicket is not null)
                {
                    // Sees the properties the handler hands on, then lets the service's own event run.
                    var issue = options.Events.OnTicketReceived;
                    options.Events.OnTicketReceived = ctx =>
                    {
                        onTicket(ctx.Properties);
                        return issue(ctx);
                    };
                }
                options.Backchannel = new HttpClient(idp);
                options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(new OpenIdConnectConfiguration
                {
                    Issuer = Realm,
                    AuthorizationEndpoint = Realm + "/protocol/openid-connect/auth",
                    TokenEndpoint = Realm + "/protocol/openid-connect/token",
                    EndSessionEndpoint = Realm + "/protocol/openid-connect/logout",
                    SigningKeys = { idp.SigningKey },
                });
            });
        });
        return (host, idp);
    }

    /// <summary>Runs the challenge and returns the callback path with the cookies a browser would send there.</summary>
    private static async Task<(string Path, string Cookies, string Nonce)> ChallengeAsync(SurfacesHost host, string returnUri)
    {
        var start = await host.SendAsync(HttpMethod.Get, "/oauth2/start?rd=" + Uri.EscapeDataString(returnUri));
        Assert.Equal(HttpStatusCode.Redirect, start.Status);
        // The redirect to the provider is in the Location header, which the reply type does not keep.
        using var request = new HttpRequestMessage(HttpMethod.Get, "/oauth2/start?rd=" + Uri.EscapeDataString(returnUri));
        using var http = new HttpClient(new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false })
        {
            BaseAddress = host.Services.GetRequiredService<Microsoft.AspNetCore.Hosting.Server.IServer>()
                .Features.Get<Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>()!.Addresses.Select(a => new Uri(a)).First(),
        };
        using var response = await http.SendAsync(request);
        var location = response.Headers.Location!;
        var query = QueryHelpers.ParseQuery(location.Query);
        var cookies = string.Join("; ", response.Headers.GetValues("Set-Cookie")
            .Select(SessionPipelineHost.SetCookie.Parse)
            .Where(c => !c.IsDeletion)
            .Select(c => $"{c.Name}={c.Value}"));
        var redirectUri = new Uri(query["redirect_uri"].ToString());
        return (redirectUri.AbsolutePath + "?code=c&state=" + Uri.EscapeDataString(query["state"].ToString()), cookies, query["nonce"].ToString());
    }

    private static async Task<(SessionPipelineHost.Reply Reply, string? Location)> CallbackAsync(
        SurfacesHost host, FakeIdp idp, string returnUri, string? incoming)
    {
        var (path, cookies, nonce) = await ChallengeAsync(host, returnUri);
        idp.Nonce = nonce;
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.TryAddWithoutValidation("Cookie", incoming is null ? cookies : cookies + "; " + incoming);
        using var http = new HttpClient(new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false })
        {
            BaseAddress = host.Services.GetRequiredService<Microsoft.AspNetCore.Hosting.Server.IServer>()
                .Features.Get<Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>()!.Addresses.Select(a => new Uri(a)).First(),
        };
        using var response = await http.SendAsync(request);
        var set = response.Headers.TryGetValues("Set-Cookie", out var values)
            ? values.Select(SessionPipelineHost.SetCookie.Parse).ToList()
            : [];
        return (new SessionPipelineHost.Reply(response.StatusCode, await response.Content.ReadAsStringAsync(), set),
            response.Headers.Location?.OriginalString);
    }

    private static void AssertChallengeCookiesDeleted(SessionPipelineHost.Reply reply)
    {
        Assert.Contains(reply.Cookies, c => c.IsDeletion && c.Name.StartsWith(".AspNetCore.Correlation.", StringComparison.Ordinal));
        Assert.Contains(reply.Cookies, c => c.IsDeletion && c.Name.StartsWith(".AspNetCore.OpenIdConnect.Nonce.", StringComparison.Ordinal));
    }

    [RedisTheory]
    [InlineData("another-users-live", "/after")]
    [InlineData("own-live", "/after")]
    [InlineData("expired", "/after")]
    [InlineData("arbitrary", "/after")]
    [InlineData("own-live", "")]
    public async Task Callback_IssuesANewKey_RedirectsAndClosesTheOldHubConnection(string kind, string returnUri)
    {
        var (host, idp) = await StartAsync();
        await using var _ = host;
        // The sessions of the stand are made by a local-mode login route of the same host.
        var (cookie, old) = await SignInByTicketAsync(host, kind);
        var other = await StoreAsync(host, A);
        var connection = old == "-" || !await host.Db.KeyExistsAsync(old) ? null : await OpenHubAsync(host, cookie);

        var (reply, location) = await CallbackAsync(host, idp, returnUri, cookie);

        Assert.Equal(HttpStatusCode.Redirect, reply.Status);
        Assert.Equal(returnUri.Length == 0 ? "/" : returnUri, location);
        var set = Assert.Single(reply.Sessions(host.CookieName)); // the correlation and nonce deletions are not session cookies
        AssertChallengeCookiesDeleted(reply);
        Assert.DoesNotContain("expires=", set.Raw, StringComparison.OrdinalIgnoreCase); // a browser-session cookie, as the challenge made it
        var fresh = host.KeyOf(set);
        Assert.NotEqual(old, fresh);
        Assert.True(await host.Db.KeyExistsAsync(fresh));
        var ticket = await host.Services.GetRequiredService<RedisTicketStore>()
            .RetrieveAsync(fresh, new Microsoft.AspNetCore.Http.DefaultHttpContext(), CancellationToken.None);
        Assert.Equal("3", ticket!.Principal.FindFirst(SessionPrincipal.SessionEpochClaim)!.Value); // the epoch of the provisioning answer
        Assert.True(await host.Db.KeyExistsAsync(other)); // another key of the same user is untouched
        if (old != "-")
        {
            Assert.False(await host.Db.KeyExistsAsync(old));
            Assert.Equal(HttpStatusCode.Unauthorized, (await host.SendAsync(HttpMethod.Get, "/test/me", cookie: cookie)).Status);
        }
        if (connection is not null)
        {
            Assert.Contains(connection, host.Replica.Aborted);
        }
    }

    [RedisTheory]
    [InlineData("delete")]
    [InlineData("write")]
    public async Task Callback_WhenTheIssueFails_AnswersTheExistingTextBadGateway_WithNoCookie(string failing)
    {
        var (host, idp) = await StartAsync();
        await using var _ = host;
        var (cookie, old) = await SignInByTicketAsync(host, "own-live");
        var method = failing == "delete" ? nameof(IDatabase.ScriptEvaluateAsync) : nameof(IDatabase.StringSetAsync);
        var injected = false;
        host.Faults.Before = (name, _) =>
        {
            if (name == method)
            {
                injected = true;
                return new InvalidOperationException("injected");
            }
            return null;
        };

        var (reply, _) = await CallbackAsync(host, idp, "/after", cookie);

        host.Faults.Before = null;
        Assert.True(injected);
        Assert.Equal(HttpStatusCode.BadGateway, reply.Status);
        Assert.Equal("OIDC sign-in failed. Contact your administrator.", reply.Body);
        Assert.Empty(reply.Sessions(host.CookieName));
        AssertChallengeCookiesDeleted(reply); // the one-time cookies of the challenge go even when the issue fails
        Assert.Equal(failing == "write", !await host.Db.KeyExistsAsync(old)); // delete failed → alive; write failed after delete → dead
    }

    [RedisFact]
    public async Task RemoteSignOutFromTheProvider_RemovesTheServerRowOfTheCurrentSession()
    {
        var (host, _) = await StartAsync();
        await using var __ = host;
        var (cookie, key) = await SignInByTicketAsync(host, "own-live");

        // The provider's front-channel sign-out request: the handler signs out of SignOutScheme (Main).
        var reply = await host.SendAsync(HttpMethod.Get, "/signout-oidc", cookie: cookie);

        Assert.True((int)reply.Status < 500, reply.Body);
        Assert.False(await host.Db.KeyExistsAsync(key));
    }

    // ---- the window of an OIDC session (INV-7, E-9, SC-007) ---------------------------------------

    private const int AbsoluteHours = 11;

    private static Task<(SurfacesHost Host, FakeIdp Idp)> StartWithClockAsync(
        Microsoft.Extensions.Time.Testing.FakeTimeProvider clock, bool useTokenLifetime,
        Action<Microsoft.AspNetCore.Authentication.AuthenticationProperties?>? onTicket = null) =>
        StartAsync(services =>
        {
            services.AddSingleton<TimeProvider>(clock);
            services.AddSingleton(new SessionTimeouts(120, AbsoluteHours));
        }, useTokenLifetime, onTicket);

    private static Microsoft.Extensions.Time.Testing.FakeTimeProvider WholeSecondClock() =>
        new(DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds()));

    private static async Task<Microsoft.AspNetCore.Authentication.AuthenticationProperties> RowPropertiesAsync(SurfacesHost host, string key) =>
        (await host.Services.GetRequiredService<RedisTicketStore>()
            .RetrieveAsync(key, new Microsoft.AspNetCore.Http.DefaultHttpContext(), CancellationToken.None))!.Properties;

    // The token's own lifetime (exp, expires_in) never becomes the window, whether or not the
    // handler copies it into the properties; the cookie stays a browser-session one.
    [RedisTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Callback_SetsABrowserSessionCookie_AndAWindowFromTheSettings_WhateverTheProviderProperties(bool useTokenLifetime)
    {
        var clock = WholeSecondClock();
        DateTimeOffset? handedExpiry = null;
        var (host, idp) = await StartWithClockAsync(clock, useTokenLifetime, p => handedExpiry = p?.ExpiresUtc);
        await using var _ = host;
        var issuedAt = clock.GetUtcNow();

        var before = DateTimeOffset.UtcNow;
        var (reply, _) = await CallbackAsync(host, idp, "/after", incoming: null);
        var after = DateTimeOffset.UtcNow;

        Assert.Equal(HttpStatusCode.Redirect, reply.Status);
        // Precondition of the arm: with the token lifetime on, the handler hands the issuer the
        // token's exp (5 min after it is made, whole seconds); off, it does not.
        var tokenExpiry = handedExpiry is { } h
            && h >= before.AddMinutes(5).AddSeconds(-1) && h <= after.AddMinutes(5).AddSeconds(1);
        Assert.Equal(useTokenLifetime, tokenExpiry);
        var set = Assert.Single(reply.Sessions(host.CookieName));
        Assert.Null(SessionPipelineIntegrationTest.ExpiresOf(set));
        Assert.Null(SessionPipelineIntegrationTest.AttributeOf(set, "max-age"));
        var row = await RowPropertiesAsync(host, host.KeyOf(set));
        Assert.Equal(issuedAt, row.IssuedUtc);
        Assert.Equal(issuedAt.AddHours(AbsoluteHours), row.ExpiresUtc);
        Assert.False(row.IsPersistent);
    }

    [RedisFact]
    public async Task ARepeatedCallback_OverALiveOldSession_StartsANewWindowUnderANewKey()
    {
        var clock = WholeSecondClock();
        var (host, idp) = await StartWithClockAsync(clock, useTokenLifetime: false);
        await using var _ = host;
        // The old session's window: earlier than the new one and still live under the stand's limit.
        var twoHoursAgo = clock.GetUtcNow().AddHours(-2);
        var principal = SessionPrincipal.Create(
            new UserDto(A.ToString(), "a@x.io", "alice", "alice", "user", null, null, false), 3);
        var old = await host.Services.GetRequiredService<RedisTicketStore>().StoreAsync(
            new Microsoft.AspNetCore.Authentication.AuthenticationTicket(principal,
                new Microsoft.AspNetCore.Authentication.AuthenticationProperties { IssuedUtc = twoHoursAgo, ExpiresUtc = twoHoursAgo.AddHours(AbsoluteHours) },
                SessionSchemes.Issue),
            new Microsoft.AspNetCore.Http.DefaultHttpContext(), CancellationToken.None);
        var cookie = CookieFor(host, old);
        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync(HttpMethod.Get, "/test/me", cookie: cookie)).Status); // control: it is live
        clock.Advance(TimeSpan.FromMinutes(5));
        var callbackAt = clock.GetUtcNow();

        var (reply, _) = await CallbackAsync(host, idp, "/after", cookie);

        var set = Assert.Single(reply.Sessions(host.CookieName));
        var fresh = host.KeyOf(set);
        Assert.NotEqual(old, fresh);
        var row = await RowPropertiesAsync(host, fresh);
        Assert.Equal(callbackAt, row.IssuedUtc);
        Assert.Equal(callbackAt.AddHours(AbsoluteHours), row.ExpiresUtc);
        Assert.False(await host.Db.KeyExistsAsync(old));
    }

    // ---- helpers: sessions are written straight through the store, as the issuer would ----------

    private static async Task<string> StoreAsync(SurfacesHost host, Guid user, long epoch = 3)
    {
        var principal = SessionPrincipal.Create(
            new UserDto(user.ToString(), "a@x.io", "alice", "alice", "user", null, null, false), epoch);
        return await host.Services.GetRequiredService<RedisTicketStore>().StoreAsync(
            new Microsoft.AspNetCore.Authentication.AuthenticationTicket(principal, new Microsoft.AspNetCore.Authentication.AuthenticationProperties(), SessionSchemes.Issue),
            new Microsoft.AspNetCore.Http.DefaultHttpContext(), CancellationToken.None);
    }

    private static string CookieFor(SurfacesHost host, string key) =>
        $"{host.CookieName}={Uri.EscapeDataString(host.Services.GetRequiredService<Microsoft.AspNetCore.Authentication.TicketDataFormat>().Protect(new Microsoft.AspNetCore.Authentication.AuthenticationTicket(new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity([new System.Security.Claims.Claim("Microsoft.AspNetCore.Authentication.Cookies-SessionId", key)], "Cookies")), "Cookies")))}";

    private static async Task<(string Cookie, string Key)> SignInByTicketAsync(SurfacesHost host, string kind)
    {
        var otherUser = SurfacesApi.UserB;
        switch (kind)
        {
            case "another-users-live":
            {
                var key = await StoreAsync(host, otherUser);
                return (CookieFor(host, key), key);
            }
            case "own-live":
            {
                var key = await StoreAsync(host, A);
                return (CookieFor(host, key), key);
            }
            case "expired":
            {
                var key = await StoreAsync(host, A);
                var cookie = CookieFor(host, key);
                await host.Db.KeyDeleteAsync(key);
                return (cookie, key); // known, so the new key is told from it
            }
            default:
                return ($"{host.CookieName}=not-a-session-value", "-");
        }
    }

    private static async Task<string> OpenHubAsync(SurfacesHost host, string cookie) =>
        JsonDocument.Parse((await host.SendAsync(HttpMethod.Get, "/test/hub", cookie: cookie)).Body).RootElement.GetProperty("connection").GetString()!;
}
