using System.Globalization;
using System.Net;
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
///   - Keycloak mode + already-authenticated principal: passes through without
///     provisioning when there are no trust headers, or when the pair of the
///     request equals the pair remembered in the ticket and the refresh is not due
///     (the matching-pair case is covered by the integration suite, which has the store).
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

    // Trust headers count only from a trusted transport peer (US-4): every
    // request here comes from a peer in the list, so the flows below are the
    // ones the peer check lets through.
    private static readonly TrustedProxyConfig TrustedProxies = TrustedProxyConfig.FromEntries(["10.0.0.1"]);

    private static void WithTrustedPeer(HttpContext ctx) =>
        ctx.Features.Set(new EdgeSnapshot(IPAddress.Parse("10.0.0.1"), AmbiguousForwardedHost: false));

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
            TrustedProxies,
            sp,
            NullLogger<SsoSessionMiddleware>.Instance);

        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/";
        WithTrustedPeer(ctx);
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
            TrustedProxies,
            sp,
            NullLogger<SsoSessionMiddleware>.Instance);

        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/some/page";
        WithTrustedPeer(ctx);
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
            TrustedProxies,
            services.BuildServiceProvider(),
            NullLogger<SsoSessionMiddleware>.Instance);
        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/";
        WithTrustedPeer(ctx);
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
            TrustedProxies,
            sp,
            NullLogger<SsoSessionMiddleware>.Instance);

        // Only email, no user.
        var ctx1 = new DefaultHttpContext();
        ctx1.Request.Path = "/";
        WithTrustedPeer(ctx1);
        ctx1.Request.Headers["X-Auth-Request-Email"] = "u@example.com";
        var called1 = false;
        await mw.InvokeAsync(ctx1, _ => { called1 = true; return Task.CompletedTask; });
        Assert.True(called1);

        // Only user, no email.
        var ctx2 = new DefaultHttpContext();
        ctx2.Request.Path = "/";
        WithTrustedPeer(ctx2);
        ctx2.Request.Headers["X-Auth-Request-User"] = "u";
        var called2 = false;
        await mw.InvokeAsync(ctx2, _ => { called2 = true; return Task.CompletedTask; });
        Assert.True(called2);
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
            TrustedProxies,
            sp,
            NullLogger<SsoSessionMiddleware>.Instance);

        var ctx = new DefaultHttpContext();
        ctx.Request.Path = "/";
        WithTrustedPeer(ctx);
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
            TrustedProxies,
            sp,
            NullLogger<SsoSessionMiddleware>.Instance);

        foreach (var path in new[] { "/healthz", "/ready", "/metrics", "/mcp", "/api/auth/config" })
        {
            var ctx = new DefaultHttpContext();
            ctx.Request.Path = path;
            WithTrustedPeer(ctx);
            // Even with trust headers, bypass paths short-circuit
            // before reaching the upstream.
            ctx.Request.Headers["X-Auth-Request-Email"] = "u@example.com";
            ctx.Request.Headers["X-Auth-Request-User"] = "u";

            var called = false;
            await mw.InvokeAsync(ctx, _ => { called = true; return Task.CompletedTask; });
            Assert.True(called, $"next() must be invoked for bypass path {path}");
        }
    }

    // ---- R56: the trust boundary and the classification, without a store ----------------------------

    private static SsoSessionMiddleware Throwing(out List<string> touched)
    {
        var seen = new List<string>();
        touched = seen;
        var services = new ServiceCollection();
        services.AddSingleton<SkeinApiClient>(_ =>
        {
            seen.Add("api");
            throw new InvalidOperationException("skein-api must not be reached");
        });
        services.AddSingleton<SessionIssuer>(_ =>
        {
            seen.Add("issuer");
            throw new InvalidOperationException("the issuer must not be reached");
        });
        return new SsoSessionMiddleware(
            KeycloakMode, TrustedProxies, services.BuildServiceProvider(), NullLogger<SsoSessionMiddleware>.Instance);
    }

    private static DefaultHttpContext RequestWith(string path, string peer, bool email = true, bool user = true, bool session = false)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Path = path;
        ctx.Features.Set(new EdgeSnapshot(IPAddress.Parse(peer), AmbiguousForwardedHost: false));
        if (email)
        {
            ctx.Request.Headers["X-Auth-Request-Email"] = "b@example.com";
        }
        if (user)
        {
            ctx.Request.Headers["X-Auth-Request-User"] = "b";
        }
        if (session)
        {
            ctx.User = new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim(ClaimTypes.NameIdentifier, "0199a1b2-0000-7000-8000-00000000000a"), FreshRefreshedAtClaim()],
                authenticationType: "Cookies"));
        }
        return ctx;
    }

    [Theory]
    [InlineData("198.51.100.9", true, true, true, "/")]   // an untrusted peer with a live session
    [InlineData("198.51.100.9", true, true, false, "/")]  // an untrusted peer, no session
    [InlineData("10.0.0.1", true, false, true, "/")]      // an incomplete pair: no username
    [InlineData("10.0.0.1", false, true, true, "/")]      // an incomplete pair: no email
    [InlineData("10.0.0.1", true, true, true, "/healthz")]
    [InlineData("10.0.0.1", true, true, true, "/ready")]
    [InlineData("10.0.0.1", true, true, true, "/metrics")]
    [InlineData("10.0.0.1", true, true, true, "/api/auth/config")]
    [InlineData("10.0.0.1", true, true, true, "/mcp")]
    public async Task OutsideTheTrustBoundary_NeitherSkeinApiNorTheIssuerIsReached_AndNextRuns(
        string peer, bool email, bool user, bool session, string path)
    {
        var mw = Throwing(out var touched);
        var ctx = RequestWith(path, peer, email, user, session);

        var nextCalled = false;
        await mw.InvokeAsync(ctx, _ => { nextCalled = true; return Task.CompletedTask; });

        Assert.True(nextCalled);
        Assert.Empty(touched);
        Assert.Equal(200, ctx.Response.StatusCode);
    }

    [Theory]
    [InlineData(Surface.Login)]
    [InlineData(Surface.Signup)]
    [InlineData(Surface.InvitationSignup)]
    [InlineData(Surface.PasswordResetComplete)]
    public async Task AnExplicitSignInOperation_WithAnotherUsersHeaders_IsLeftAlone(Surface surface)
    {
        var mw = Throwing(out var touched);
        var ctx = RequestWith("/api/auth/anything", "10.0.0.1", session: true);
        ctx.SetEndpoint(new Endpoint(null, new EndpointMetadataCollection(new ExplicitSignInAttribute(surface)), surface.ToString()));

        var nextCalled = false;
        await mw.InvokeAsync(ctx, _ => { nextCalled = true; return Task.CompletedTask; });

        Assert.True(nextCalled);
        Assert.Empty(touched);
    }
}
