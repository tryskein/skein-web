using Microsoft.AspNetCore.Http;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// How the stands tell a deletion from a live session cookie in a Set-Cookie header
/// (<see cref="SessionPipelineHost.SetCookie.IsDeletionHeader"/>), on headers ASP.NET Core writes itself.
/// </summary>
public class SetCookieDeletionTest
{
    private static string Written(Action<IResponseCookies> write)
    {
        var ctx = new DefaultHttpContext();
        write(ctx.Response.Cookies);
        return Assert.Single(ctx.Response.Headers.SetCookie)!;
    }

    [Fact]
    public void ADeletion_IsADeletion()
    {
        var raw = Written(c => c.Delete("skein.sid", new CookieOptions { Path = "/" }));

        Assert.True(SessionPipelineHost.SetCookie.IsDeletionHeader(raw));
        Assert.True(SessionPipelineHost.SetCookie.Parse(raw).IsDeletion);
    }

    [Theory]
    [InlineData("CfDJ8_1970pUX")]
    [InlineData("1970")]
    [InlineData("a19701970b")]
    public void ALiveCookie_WhoseValueCarries1970_IsNotADeletion(string value)
    {
        var raw = Written(c => c.Append("skein.sid", value, new CookieOptions
        {
            Path = "/",
            HttpOnly = true,
            Expires = DateTimeOffset.UtcNow.AddHours(720),
        }));

        Assert.Contains("1970", raw, StringComparison.Ordinal); // the value carries it
        Assert.False(SessionPipelineHost.SetCookie.IsDeletionHeader(raw));
        Assert.Single(new SessionPipelineHost.Reply(System.Net.HttpStatusCode.OK, "", [SessionPipelineHost.SetCookie.Parse(raw)])
            .Sessions("skein.sid"));
    }

    [Fact]
    public void ALiveCookieWithoutExpires_IsNotADeletion()
    {
        Assert.False(SessionPipelineHost.SetCookie.IsDeletionHeader(Written(c => c.Append("skein.sid", "v1970"))));
    }
}
