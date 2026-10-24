using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SkeinWeb.Auth;
using SkeinWeb.Middleware;

namespace SkeinWeb.Tests.Middleware;

/// <summary>
/// Unit-level pins on the <see cref="SsoSessionMiddleware"/> control
/// flow (trust-headers org pattern: oauth2-proxy at the ingress edge
/// owns auth; the BFF only reads <c>X-Auth-Request-User</c> and
/// <c>X-Auth-Request-Email</c>).
///
/// Invariants pinned:
///   - The mode comes from the installation settings (skein-api's authMode
///     mapped by <see cref="WebAuthMode.FromApi"/>), not
///     from web configuration.
///   - Local mode, and native OIDC: the middleware never resolves
///     <see cref="SkeinApiClient"/>.
///   - Keycloak mode + missing trust headers: same no-op (the
///     downstream auth gates own the 401 response).
///   - Keycloak mode + already-authenticated principal with a FRESH
///     <c>urn:skein:refreshed-at</c> claim: pass through without
///     calling the upstream provisioning endpoint.
///   - Keycloak mode + authenticated principal but no trust headers
///     (e.g. internal probe): pass through without provisioning (the
///     TTL-refresh path is silent when oauth2-proxy didn't sit in front).
///   - Keycloak mode + bypass path: short-circuit even with headers set.
///
/// The happy path (and the TTL-refresh-DOES-fire branch) requires a live
/// skein-api on the other side and is covered by the integration suite,
/// not here.
/// </summary>
public class SsoSessionMiddlewareTest
{
    private const string RefreshedAtClaim = "urn:skein:refreshed-at";

    private static Claim FreshRefreshedAtClaim() => new(
        RefreshedAtClaim,
        DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));
    private const string Authority = "https://keycloak.example.com/realms/skein";

    // sk-674.18 (D-7): the mode is the installation's —
    // skein-api's authMode mapped with the configured OIDC authority (K-13) — not a web
    // setting. The trust-headers flow runs for an SSO mode
    // WITHOUT an OIDC authority (keycloak or hybrid).
    private static readonly WebAuthMode KeycloakMode = WebAuthMode.FromApi("keycloak", null);

    [Theory]
    [InlineData("local", null)]
    [InlineData("local", Authority)]
    [InlineData("keycloak", Authority)]   // native OIDC: the BFF itself is the RP
    [InlineData("hybrid", Authority)]
    public async Task LocalMode_NoOp_DoesNotResolveSkeinApiClient(string apiAuthMode, string? authority)
    {
        // Arrange: build an IServiceProvider that THROWS if anyone asks
        // for SkeinApiClient — proving the middleware never reaches DI
        // in local mode.
        var services = new ServiceCollection();
        services.AddSingleton<SkeinApiClient>(_ =>
        {
            throw new InvalidOperationException("SkeinApiClient must not be resolved in local mode");
        });
        var sp = services.BuildServiceProvider();

        var mw = new SsoSessionMiddleware(
            WebAuthMode.FromApi(apiAuthMode, authority),
            sp,
            NullLogger<SsoSessionMiddleware>.Instance);

        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/";
        // Even with trust headers set the middleware should ignore them
        // entirely — local mode is a hard short-circuit.
        ctx.Request.Headers["X-Auth-Request-Email"] = "u@example.com";
        ctx.Request.Headers["X-Auth-Request-User"] = "u";

        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        // Act
        await mw.InvokeAsync(ctx, next);

        // Assert
        Assert.True(nextCalled, "next() must be invoked in local mode");
        Assert.Equal(200, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task KeycloakMode_NoTrustHeaders_PassesThrough()
    {
        // Arrange: keycloak mode, but the inbound request never went
        // through oauth2-proxy so neither trust header is present. The
        // middleware must defer to downstream auth gates rather than
        // 401ing on its own.
        var services = new ServiceCollection();
        services.AddSingleton<SkeinApiClient>(_ =>
        {
            throw new InvalidOperationException("SkeinApiClient must not be resolved without trust headers");
        });
        var sp = services.BuildServiceProvider();

        var mw = new SsoSessionMiddleware(
            KeycloakMode,
            sp,
            NullLogger<SsoSessionMiddleware>.Instance);

        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/some/page";
        // No trust headers. No cookie principal either.

        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        // Act
        await mw.InvokeAsync(ctx, next);

        // Assert
        Assert.True(nextCalled, "next() must be invoked when no SSO headers are present");
        Assert.Equal(200, ctx.Response.StatusCode);
    }

    [Theory]
    [InlineData("keycloak")]
    [InlineData("hybrid")]
    public async Task KeycloakMode_FromInstallationSettings_ProvisionsFromTrustHeaders(string apiAuthMode)
    {
        // An SSO mode of skein-api with no OIDC authority in web is the
        // trust-headers flow: with both headers present the middleware turns
        // to skein-api to provision (observed as the resolution of the client).
        var resolved = false;
        var services = new ServiceCollection();
        services.AddSingleton<SkeinApiClient>(_ =>
        {
            resolved = true;
            throw new InvalidOperationException("stop here: provisioning reached");
        });
        var mw = new SsoSessionMiddleware(
            WebAuthMode.FromApi(apiAuthMode, null),
            services.BuildServiceProvider(),
            NullLogger<SsoSessionMiddleware>.Instance);
        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/";
        ctx.Request.Headers["X-Auth-Request-Email"] = "u@example.com";
        ctx.Request.Headers["X-Auth-Request-User"] = "u";
        ctx.Response.Body = new MemoryStream();

        await mw.InvokeAsync(ctx, _ => Task.CompletedTask);

        Assert.True(resolved, $"{apiAuthMode} without an OIDC authority must run the trust-headers flow");
    }

    [Fact]
    public async Task KeycloakMode_OnlyOneTrustHeader_PassesThrough()
    {
        // Arrange: keycloak mode and ONLY one of the trust headers is
        // set. The middleware requires BOTH email + user; partial
        // presence should not trigger provisioning (could indicate a
        // misconfigured upstream or header tampering).
        var services = new ServiceCollection();
        services.AddSingleton<SkeinApiClient>(_ =>
        {
            throw new InvalidOperationException("SkeinApiClient must not be resolved on partial trust headers");
        });
        var sp = services.BuildServiceProvider();

        var mw = new SsoSessionMiddleware(
            KeycloakMode,
            sp,
            NullLogger<SsoSessionMiddleware>.Instance);

        // Only email, no user.
        var ctx1 = new DefaultHttpContext();
        ctx1.Request.Path = "/";
        ctx1.Request.Headers["X-Auth-Request-Email"] = "u@example.com";
        var called1 = false;
        await mw.InvokeAsync(ctx1, _ => { called1 = true; return Task.CompletedTask; });
        Assert.True(called1);

        // Only user, no email.
        var ctx2 = new DefaultHttpContext();
        ctx2.Request.Path = "/";
        ctx2.Request.Headers["X-Auth-Request-User"] = "u";
        var called2 = false;
        await mw.InvokeAsync(ctx2, _ => { called2 = true; return Task.CompletedTask; });
        Assert.True(called2);
    }

    [Fact]
    public async Task KeycloakMode_AlreadyAuthenticated_WithFreshRefreshTimestamp_PassesThrough()
    {
        // Arrange: keycloak mode + cookie principal carrying a recent
        // urn:skein:refreshed-at claim (within the 5-min TTL). The SSO
        // middleware must NOT re-provision on every request — it
        // short-circuits the TTL-refresh path when the timestamp is
        // fresh.
        var services = new ServiceCollection();
        services.AddSingleton<SkeinApiClient>(_ =>
        {
            throw new InvalidOperationException(
                "SkeinApiClient must not be resolved when the refresh timestamp is fresh");
        });
        var sp = services.BuildServiceProvider();

        var mw = new SsoSessionMiddleware(
            KeycloakMode,
            sp,
            NullLogger<SsoSessionMiddleware>.Instance);

        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/";
        ctx.Request.Headers["X-Auth-Request-Email"] = "u@example.com";
        ctx.Request.Headers["X-Auth-Request-User"] = "u";
        ctx.User = new ClaimsPrincipal(
            new ClaimsIdentity(
                new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
                    FreshRefreshedAtClaim(),
                },
                authenticationType: "Cookies"));

        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        // Act
        await mw.InvokeAsync(ctx, next);

        // Assert
        Assert.True(nextCalled);
        Assert.Equal(200, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task KeycloakMode_AlreadyAuthenticated_NoTrustHeaders_SkipsRefresh()
    {
        // Arrange: keycloak mode + authenticated principal but NO trust
        // headers on this request (e.g. an internal probe or a request
        // that bypassed oauth2-proxy). The TTL-refresh path requires
        // headers to call OidcProvisionAsync, so it must silently
        // skip — the existing cookie keeps working.
        var services = new ServiceCollection();
        services.AddSingleton<SkeinApiClient>(_ =>
        {
            throw new InvalidOperationException(
                "SkeinApiClient must not be resolved without trust headers");
        });
        var sp = services.BuildServiceProvider();

        var mw = new SsoSessionMiddleware(
            KeycloakMode,
            sp,
            NullLogger<SsoSessionMiddleware>.Instance);

        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/";
        // No trust headers. The principal has NO refreshed-at claim
        // either — refresh would be due, but the missing headers force
        // a skip.
        ctx.User = new ClaimsPrincipal(
            new ClaimsIdentity(
                new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
                },
                authenticationType: "Cookies"));

        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        // Act
        await mw.InvokeAsync(ctx, next);

        // Assert
        Assert.True(nextCalled);
        Assert.Equal(200, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task KeycloakMode_BypassPaths_DoNotTouchSso()
    {
        // Arrange: paths that must NEVER trigger provisioning even in
        // keycloak mode (health checks, metrics, MCP, auth/config).
        var services = new ServiceCollection();
        services.AddSingleton<SkeinApiClient>(_ =>
        {
            throw new InvalidOperationException("SkeinApiClient must not be resolved on bypass paths");
        });
        var sp = services.BuildServiceProvider();

        var mw = new SsoSessionMiddleware(
            KeycloakMode,
            sp,
            NullLogger<SsoSessionMiddleware>.Instance);

        foreach (var path in new[] { "/healthz", "/ready", "/metrics", "/mcp", "/api/auth/config" })
        {
            var ctx = new DefaultHttpContext();
            ctx.Request.Path = path;
            // Even with trust headers, bypass paths short-circuit
            // before reaching the upstream.
            ctx.Request.Headers["X-Auth-Request-Email"] = "u@example.com";
            ctx.Request.Headers["X-Auth-Request-User"] = "u";

            var called = false;
            await mw.InvokeAsync(ctx, _ => { called = true; return Task.CompletedTask; });
            Assert.True(called, $"next() must be invoked for bypass path {path}");
        }
    }

    // ---- K-16: a TTL refresh never raises the epoch ----

    private sealed class ProvisionApi(long sessionEpoch) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(
                    "{\"id\":\"0199a1b2-0000-7000-8000-000000000001\",\"email\":\"u@example.com\"," +
                    "\"username\":\"u\",\"name\":\"u\",\"role\":\"user\",\"isExternal\":false," +
                    "\"sessionEpoch\":" + sessionEpoch + "}",
                    System.Text.Encoding.UTF8, "application/json"),
            });
    }

    private sealed record RefreshRun(DefaultHttpContext Ctx, List<ClaimsPrincipal> SignIns, List<string?> SignOuts, bool NextCalled);

    /// <summary>
    /// A cookie session issued with epoch 3 whose refresh is due (stale
    /// timestamp), trust headers present, and skein-api now reporting
    /// <paramref name="apiEpoch"/>.
    /// </summary>
    private static async Task<RefreshRun> RefreshWithApiEpoch(long apiEpoch)
    {
        var signIns = new List<ClaimsPrincipal>();
        var signOuts = new List<string?>();
        var auth = new Moq.Mock<Microsoft.AspNetCore.Authentication.IAuthenticationService>();
        auth.Setup(a => a.SignInAsync(Moq.It.IsAny<HttpContext>(), Moq.It.IsAny<string>(),
                Moq.It.IsAny<ClaimsPrincipal>(), Moq.It.IsAny<Microsoft.AspNetCore.Authentication.AuthenticationProperties>()))
            .Callback((HttpContext _, string _, ClaimsPrincipal p, Microsoft.AspNetCore.Authentication.AuthenticationProperties _) => signIns.Add(p))
            .Returns(Task.CompletedTask);
        auth.Setup(a => a.SignOutAsync(Moq.It.IsAny<HttpContext>(), Moq.It.IsAny<string?>(),
                Moq.It.IsAny<Microsoft.AspNetCore.Authentication.AuthenticationProperties?>()))
            .Callback((HttpContext _, string? scheme, Microsoft.AspNetCore.Authentication.AuthenticationProperties? _) => signOuts.Add(scheme))
            .Returns(Task.CompletedTask);
        var services = new ServiceCollection();
        services.AddSingleton(auth.Object);
        services.AddSingleton(new SkeinApiClient(
            new HttpClient(new ProvisionApi(apiEpoch)) { BaseAddress = new Uri("http://skein-api.test/") },
            NullLogger<SkeinApiClient>.Instance));
        var sp = services.BuildServiceProvider();

        var ctx = new DefaultHttpContext { RequestServices = sp };
        ctx.Request.Path = "/";
        ctx.Request.Headers["X-Auth-Request-Email"] = "u@example.com";
        ctx.Request.Headers["X-Auth-Request-User"] = "u";
        var stale = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        ctx.User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "0199a1b2-0000-7000-8000-000000000001"),
                new Claim(ClaimTypes.Email, "u@example.com"),
                new Claim("username", "u"),
                new Claim(ClaimTypes.Name, "u"),
                new Claim(ClaimTypes.Role, "user"),
                new Claim("is_external", "false"),
                new Claim(SessionPrincipal.SessionEpochClaim, "3"),
                new Claim(RefreshedAtClaim, stale),
            ],
            authenticationType: "Cookies"));

        var nextCalled = false;
        var mw = new SsoSessionMiddleware(KeycloakMode, sp, NullLogger<SsoSessionMiddleware>.Instance);
        await mw.InvokeAsync(ctx, _ => { nextCalled = true; return Task.CompletedTask; });
        return new RefreshRun(ctx, signIns, signOuts, nextCalled);
    }

    [Fact]
    public async Task KeycloakMode_TtlRefresh_EpochChanged_EndsTheSession_NeverRaisesIt()
    {
        var run = await RefreshWithApiEpoch(4);

        Assert.Empty(run.SignIns);
        Assert.Equal(["Cookies"], run.SignOuts);
        Assert.False(run.Ctx.User.Identity?.IsAuthenticated ?? false);
        Assert.True(run.NextCalled);
    }

    [Fact]
    public async Task KeycloakMode_TtlRefresh_SameEpoch_ReissuesWithThatEpoch()
    {
        var run = await RefreshWithApiEpoch(3);

        var reissued = Assert.Single(run.SignIns);
        Assert.Equal("3", reissued.FindFirstValue(SessionPrincipal.SessionEpochClaim));
        Assert.Empty(run.SignOuts);
    }
}
