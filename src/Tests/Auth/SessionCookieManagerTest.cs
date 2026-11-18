using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using SkeinWeb.Auth;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// The two cookie managers (US-1 incoming session, US-3 renewal): Main reads only the cookie of the
/// name it is asked for and may decline a late write; Issue never reads.
/// </summary>
public class SessionCookieManagerTest
{
    private const string Mode = "__Host-skein.sid";
    private const string Other = "skein.sid";

    private static DefaultHttpContext Context(string cookieHeader)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Headers.Cookie = cookieHeader;
        return ctx;
    }

    [Fact]
    public void Main_WithBothNames_ReadsTheNameOfTheMode()
    {
        var manager = new SessionCookieManager(new ChunkingCookieManager());
        var ctx = Context($"{Other}=old; {Mode}=current");

        Assert.Equal("current", manager.GetRequestCookie(ctx, Mode));
    }

    [Fact]
    public void Main_WithOnlyAnotherName_ReadsNothing()
    {
        var manager = new SessionCookieManager(new ChunkingCookieManager());

        Assert.Null(manager.GetRequestCookie(Context($"{Other}=old"), Mode));
    }

    [Fact]
    public void Issue_NeverReadsTheIncomingCookie()
    {
        var manager = new IssueCookieManager(new ChunkingCookieManager());

        Assert.Null(manager.GetRequestCookie(Context($"{Mode}=valid"), Mode));
    }

    private static int SetCookies(HttpContext ctx) => ctx.Response.Headers.SetCookie.Count;

    [Fact]
    public void Main_WithNoRenewOutcome_WritesTheCookie()
    {
        var manager = new SessionCookieManager(new ChunkingCookieManager());
        var ctx = new DefaultHttpContext();

        manager.AppendResponseCookie(ctx, Mode, "v", new CookieOptions());

        Assert.Equal(1, SetCookies(ctx));
    }

    [Fact]
    public void Main_WithRenewOutcomeWritten_WritesTheCookie()
    {
        var manager = new SessionCookieManager(new ChunkingCookieManager());
        var ctx = new DefaultHttpContext();
        SessionRequestState.Of(ctx).RenewOutcome = RenewOutcome.Written;

        manager.AppendResponseCookie(ctx, Mode, "v", new CookieOptions());

        Assert.Equal(1, SetCookies(ctx));
    }

    [Theory]
    [InlineData(RenewOutcome.KeyAbsent)]
    [InlineData(RenewOutcome.CasExhausted)]
    [InlineData(RenewOutcome.OwnerMismatch)]
    [InlineData(RenewOutcome.Suppressed)]
    [InlineData(RenewOutcome.TechnicalFailure)]
    public void Main_WithAnyOtherRenewOutcome_WritesNoCookie(RenewOutcome outcome)
    {
        var manager = new SessionCookieManager(new ChunkingCookieManager());
        var ctx = new DefaultHttpContext();
        SessionRequestState.Of(ctx).RenewOutcome = outcome;

        manager.AppendResponseCookie(ctx, Mode, "v", new CookieOptions());

        Assert.Equal(0, SetCookies(ctx));
    }

    [Fact]
    public void Main_WithSuppressedWrite_WritesNoCookie_ButStillDeletes()
    {
        var manager = new SessionCookieManager(new ChunkingCookieManager());
        var ctx = new DefaultHttpContext();
        SessionRequestState.Of(ctx).SuppressMainWrite = true;

        manager.AppendResponseCookie(ctx, Mode, "v", new CookieOptions());
        Assert.Equal(0, SetCookies(ctx));

        manager.DeleteCookie(ctx, Mode, new CookieOptions());
        Assert.Equal(1, SetCookies(ctx));
        Assert.Contains("1970", ctx.Response.Headers.SetCookie.ToString());
    }

    [Fact]
    public void Issue_WritesTheCookie_EvenWhenMainWouldBeSuppressed()
    {
        var manager = new IssueCookieManager(new ChunkingCookieManager());
        var ctx = new DefaultHttpContext();
        SessionRequestState.Of(ctx).SuppressMainWrite = true;

        manager.AppendResponseCookie(ctx, Mode, "v", new CookieOptions());

        Assert.Equal(1, SetCookies(ctx));
    }
}
