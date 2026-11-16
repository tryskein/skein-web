using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using SkeinWeb.Auth;
using SkeinWeb.Middleware;

namespace SkeinWeb.Tests.Middleware;

/// <summary>
/// The host check of <see cref="HostAllowlistMiddleware"/> (US-5, INV-6, INV-7):
/// with a non-empty <c>SKEIN_ALLOWED_HOSTS</c> a host outside the list, a
/// request without a host and an ambiguous <c>X-Forwarded-Host</c> of a trusted
/// peer answer 400 <c>invalid_host</c> and stop there; the comparison ignores
/// case, port, a trailing dot and IPv6 brackets. <c>/healthz</c>, <c>/ready</c>
/// and <c>/metrics</c> skip it (per segment). An empty list checks nothing.
/// </summary>
public class HostAllowlistMiddlewareTest
{
    private sealed record Outcome(int Status, bool NextCalled, string? Error);

    private static async Task<Outcome> Run(
        string allowedHosts, string? host, string path = "/projects",
        string protocol = "HTTP/1.1", bool ambiguousForwardedHost = false)
    {
        var nextCalled = false;
        var middleware = new HostAllowlistMiddleware(
            _ => { nextCalled = true; return Task.CompletedTask; },
            AllowedHostsConfig.Parse(allowedHosts));

        var ctx = new DefaultHttpContext();
        ctx.Request.Protocol = protocol;
        ctx.Request.Path = path;
        if (host is not null)
        {
            ctx.Request.Host = new HostString(host);
        }
        ctx.Features.Set(new EdgeSnapshot(IPAddress.Parse("10.0.0.1"), ambiguousForwardedHost));
        ctx.Response.Body = new MemoryStream();

        await middleware.InvokeAsync(ctx);

        string? error = null;
        if (ctx.Response.Body.Length > 0)
        {
            ctx.Response.Body.Position = 0;
            using var doc = await JsonDocument.ParseAsync(ctx.Response.Body);
            error = doc.RootElement.GetProperty("error").GetString();
        }
        return new Outcome(ctx.Response.StatusCode, nextCalled, error);
    }

    private const string List = "skein.example.com, [2001:db8::1], [::ffff:192.0.2.1]";

    [Fact]
    public async Task HostOutsideTheList_Is400InvalidHost_AndStops()
    {
        var outcome = await Run(List, "evil.example");

        Assert.Equal(StatusCodes.Status400BadRequest, outcome.Status);
        Assert.Equal("invalid_host", outcome.Error);
        Assert.False(outcome.NextCalled);
    }

    [Theory]
    [InlineData("SKEIN.example.com")]
    [InlineData("skein.example.com:8443")]
    [InlineData("skein.example.com.")]
    [InlineData("[2001:db8::1]:8080")]
    // The listed bracketed IPv6 address, written without brackets.
    [InlineData("2001:db8::1")]
    // The listed IPv4-mapped address, as plain IPv4.
    [InlineData("192.0.2.1")]
    public async Task ListedHost_IgnoringCasePortTrailingDotAndBrackets_GoesOn(string host)
    {
        var outcome = await Run(List, host);

        Assert.True(outcome.NextCalled);
        Assert.Equal(StatusCodes.Status200OK, outcome.Status);
    }

    [Fact]
    public async Task Http10RequestWithoutHost_Is400InvalidHost()
    {
        var outcome = await Run(List, host: null, protocol: "HTTP/1.0");

        Assert.Equal(StatusCodes.Status400BadRequest, outcome.Status);
        Assert.Equal("invalid_host", outcome.Error);
        Assert.False(outcome.NextCalled);
    }

    [Theory]
    [InlineData("/healthz")]
    [InlineData("/ready")]
    [InlineData("/metrics")]
    public async Task ProbePath_SkipsTheCheck(string path)
    {
        var outcome = await Run(List, "10.244.1.7", path);

        Assert.True(outcome.NextCalled);
        Assert.Equal(StatusCodes.Status200OK, outcome.Status);
    }

    [Theory]
    [InlineData("/healthzx")]
    [InlineData("/readyz")]
    [InlineData("/metrics2")]
    public async Task PathOnlyStartingLikeAProbePath_IsChecked(string path)
    {
        var outcome = await Run(List, "10.244.1.7", path);

        Assert.Equal(StatusCodes.Status400BadRequest, outcome.Status);
        Assert.Equal("invalid_host", outcome.Error);
        Assert.False(outcome.NextCalled);
    }

    [Theory]
    [InlineData("evil.example", "HTTP/1.1", false)]
    [InlineData(null, "HTTP/1.0", false)]
    [InlineData("skein.example.com", "HTTP/1.1", true)]
    public async Task EmptyList_ChecksNothing(string? host, string protocol, bool ambiguousForwardedHost)
    {
        var outcome = await Run("", host, protocol: protocol, ambiguousForwardedHost: ambiguousForwardedHost);

        Assert.True(outcome.NextCalled);
        Assert.Equal(StatusCodes.Status200OK, outcome.Status);
    }
}
