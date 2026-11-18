using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using SkeinWeb.Auth;
using SkeinWeb.Middleware;

namespace SkeinWeb.Tests.Middleware;

/// <summary>A refusal that comes late, after an upstream answer was copied onto the response, replaces it whole.</summary>
public class SessionStoreFailureLateRefusalTest
{
    [Fact]
    public async Task LateRefusal_DropsCopiedHeaders_AndWritesAConsistentBadGateway()
    {
        var middleware = new SessionStoreFailureMiddleware(
            WebAuthMode.FromApi("local", null), TrustedProxyConfig.FromEntries([]), NullLogger<SessionStoreFailureMiddleware>.Instance);
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();

        await middleware.InvokeAsync(ctx, c =>
        {
            c.Response.StatusCode = StatusCodes.Status401Unauthorized;
            c.Response.ContentLength = 31; // the length of the upstream body that will not be sent
            c.Response.Headers.SetCookie = "skein.sid=old; path=/";
            c.Response.Headers["X-Upstream"] = "1";
            throw new SessionStoreUnavailableException();
        });

        Assert.Equal(StatusCodes.Status502BadGateway, ctx.Response.StatusCode);
        Assert.Equal(0, ctx.Response.Headers.SetCookie.Count);
        Assert.False(ctx.Response.Headers.ContainsKey("X-Upstream"));
        Assert.Null(ctx.Response.ContentLength);
        Assert.True(SessionRequestState.Of(ctx).SuppressMainWrite);
        ctx.Response.Body.Position = 0;
        Assert.Contains("upstream_unavailable", Encoding.UTF8.GetString(((MemoryStream)ctx.Response.Body).ToArray()));
    }
}
