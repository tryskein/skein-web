using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Time.Testing;
using SkeinWeb.Auth;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// <see cref="SessionWindow"/>, the single definition of the window of a session, its validity,
/// the end of a session and the lifetime a write gives the session row (spec terms «Окно сессии»,
/// «Корректное окно», «Срок сессии», «Срок бездействия»; D-2, E-1, E-2, E-10; the plan decision
/// «SessionWindow»: the row lifetime is either «ended» or a whole number of milliseconds ≥ 1,
/// the time left rounded down).
/// </summary>
public class SessionWindowTest
{
    private static readonly DateTimeOffset SignIn = new(2026, 3, 1, 8, 0, 0, TimeSpan.Zero);

    private static readonly SessionTimeouts Defaults = new(120, 720);

    // The window a sign-in at SignIn under the default limits started.
    private static readonly SessionWindow DefaultWindow = new(SignIn, SignIn.AddHours(720));

    [Fact]
    public void ASignIn_StartsTheWindow_NowToNowPlusTheAbsoluteLimit()
    {
        var clock = new FakeTimeProvider(SignIn);
        clock.Advance(TimeSpan.FromMinutes(17));

        var window = SessionWindow.ForSignIn(new SessionTimeouts(120, 11), clock.GetUtcNow());

        Assert.Equal(new DateTimeOffset(2026, 3, 1, 8, 17, 0, TimeSpan.Zero), window.IssuedUtc);
        Assert.Equal(new DateTimeOffset(2026, 3, 1, 19, 17, 0, TimeSpan.Zero), window.ExpiresUtc);
    }

    public static TheoryData<string, AuthenticationProperties, bool> Windows() => new()
    {
        { "both times, issued before expiry", Props(SignIn, SignIn.AddHours(720)), true },
        // The properties keep times to the second, so a second is the smallest gap a ticket can carry.
        { "both times, one second apart", Props(SignIn, SignIn.AddSeconds(1)), true },
        { "no issue time", Props(null, SignIn.AddHours(720)), false },
        { "no expiry time", Props(SignIn, null), false },
        { "neither time", Props(null, null), false },
        { "issued equals expiry", Props(SignIn, SignIn), false },
        { "issued after expiry", Props(SignIn.AddHours(1), SignIn), false },
        { "issue time not parsable", Unparsable(".issued"), false },
        { "expiry time not parsable", Unparsable(".expires"), false },
    };

    [Theory]
    [MemberData(nameof(Windows))]
    public void AWindowIsValid_OnlyWithBothTimes_AndTheIssueEarlierThanTheExpiry(
        string _, AuthenticationProperties properties, bool valid)
    {
        var read = SessionWindow.TryRead(properties, out var window);

        Assert.Equal(valid, read);
        if (valid)
        {
            Assert.Equal(properties.IssuedUtc, window.IssuedUtc);
            Assert.Equal(properties.ExpiresUtc, window.ExpiresUtc);
        }
    }

    [Theory]
    // Limit unchanged: sign-in plus the absolute limit.
    [InlineData(720, 720)]
    // Lowered to 11 h: earlier than the written window.
    [InlineData(11, 11)]
    // Raised to 1000 h: never past the written window.
    [InlineData(1000, 720)]
    public void TheEndOfASession_IsTheEarlierOfSignInPlusTheCurrentLimit_AndTheWrittenExpiry(
        int currentAbsoluteHours, int expectedHoursAfterSignIn)
    {
        var end = DefaultWindow.SessionEnd(new SessionTimeouts(120, currentAbsoluteHours));

        Assert.Equal(SignIn.AddHours(expectedHoursAfterSignIn), end);
    }

    [Fact]
    public void ALimitLoweredAndRaisedAgain_WithoutARequest_IsJudgedByTheLimitOfTheNextRequest()
    {
        var lowered = new SessionTimeouts(120, 11);
        var raisedBack = new SessionTimeouts(120, 720);
        var at = SignIn.AddHours(30);

        // Under the lowered limit the session would have ended by then …
        Assert.True(DefaultWindow.HasEnded(lowered, at));
        // … but its next request comes after the limit was raised back, and that limit decides.
        Assert.False(DefaultWindow.HasEnded(raisedBack, at));
        Assert.Equal(SignIn.AddHours(720), DefaultWindow.SessionEnd(raisedBack));
    }

    public static TheoryData<string, SessionTimeouts, TimeSpan, long?> RowLifetimes() => new()
    {
        // Time left larger than the idle limit: the idle limit.
        { "time left above the idle limit", Defaults, TimeSpan.Zero, 120L * 3_600_000 },
        // Time left shorter than the idle limit: the time left, in whole milliseconds rounded down.
        { "time left below the idle limit", Defaults, TimeSpan.FromHours(715) - TimeSpan.FromTicks(4_000), 5L * 3_600_000 },
        { "1.9 ms left", Defaults, TimeSpan.FromHours(720) - TimeSpan.FromTicks(19_000), 1L },
        { "0.9 ms left", Defaults, TimeSpan.FromHours(720) - TimeSpan.FromTicks(9_000), null },
        { "nothing left", Defaults, TimeSpan.FromHours(720), null },
        { "past the end", Defaults, TimeSpan.FromHours(720) + TimeSpan.FromMilliseconds(1), null },
        // Idle limit at or above the absolute one: the time left.
        { "idle above absolute, at sign-in", new SessionTimeouts(720, 24), TimeSpan.Zero, 24L * 3_600_000 },
        { "idle equal to absolute, later", new SessionTimeouts(24, 24), TimeSpan.FromHours(10), 14L * 3_600_000 },
    };

    [Theory]
    [MemberData(nameof(RowLifetimes))]
    public void TheRowLifetime_IsTheIdleLimitOrTheTimeLeft_InWholeMillisecondsRoundedDown_OrEnded(
        string _, SessionTimeouts timeouts, TimeSpan sinceSignIn, long? expectedMilliseconds)
    {
        var window = SessionWindow.ForSignIn(timeouts, SignIn);

        var alive = window.TryGetRowLifetime(timeouts, SignIn + sinceSignIn, out var lifetime);

        if (expectedMilliseconds is { } ms)
        {
            Assert.True(alive);
            Assert.Equal(TimeSpan.FromMilliseconds(ms), lifetime);
        }
        else
        {
            Assert.False(alive);
        }
    }

    [Theory]
    // The absolute limit in effect at sign-in.
    [InlineData(720)]
    // A lowered absolute limit applied to the session issued under 720 h.
    [InlineData(11)]
    public void AroundTheEnd_ASecondBeforeIsAlive_AndTheEndAndASecondAfterAreEnded(int currentAbsoluteHours)
    {
        var timeouts = new SessionTimeouts(120, currentAbsoluteHours);
        var end = SignIn.AddHours(currentAbsoluteHours);

        Assert.False(DefaultWindow.HasEnded(timeouts, end.AddSeconds(-1)));
        Assert.True(DefaultWindow.TryGetRowLifetime(timeouts, end.AddSeconds(-1), out var lifetime));
        Assert.Equal(TimeSpan.FromMilliseconds(1000), lifetime);

        foreach (var at in new[] { end, end.AddSeconds(1) })
        {
            Assert.True(DefaultWindow.HasEnded(timeouts, at));
            Assert.False(DefaultWindow.TryGetRowLifetime(timeouts, at, out _));
        }
    }

    private static AuthenticationProperties Props(DateTimeOffset? issued, DateTimeOffset? expires) =>
        new() { IssuedUtc = issued, ExpiresUtc = expires };

    private static AuthenticationProperties Unparsable(string item)
    {
        var properties = Props(SignIn, SignIn.AddHours(720));
        properties.Items[item] = "not a date";
        return properties;
    }
}
