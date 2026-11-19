using Microsoft.Extensions.Configuration;
using SkeinWeb.Auth;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// The two session limits read at startup (FR-001, SC-005, US-3): an unset setting takes its
/// default (120 h idle, 720 h absolute), a set one must be a whole number of hours in 1–8760, and
/// a set but invalid one stops the start with an <see cref="InvalidOperationException"/> naming
/// that setting.
/// </summary>
public class SessionTimeoutsTest
{
    private const string Idle = "SKEIN_SESSION_IDLE_TIMEOUT_HOURS";
    private const string Absolute = "SKEIN_SESSION_ABSOLUTE_TIMEOUT_HOURS";

    private static SessionTimeouts Parse(params (string Key, string? Value)[] settings) =>
        SessionTimeouts.Parse(new ConfigurationBuilder()
            .AddInMemoryCollection(settings.Select(s => new KeyValuePair<string, string?>(s.Key, s.Value)))
            .Build());

    [Fact]
    public void WithoutEitherSetting_TheLimitsAre120And720Hours()
    {
        var timeouts = Parse();

        Assert.Equal(TimeSpan.FromHours(120), timeouts.Idle);
        Assert.Equal(TimeSpan.FromHours(720), timeouts.Absolute);
    }

    [Theory]
    [InlineData("1", "1", 1, 1)]
    [InlineData("8760", "8760", 8760, 8760)]
    [InlineData("7", "13", 7, 13)]
    [InlineData("13", "7", 13, 7)]
    [InlineData("1", "8760", 1, 8760)]
    [InlineData("8760", "1", 8760, 1)]
    public void AValidValueOfEachSetting_IsTakenAsGiven_IndependentlyOfTheOther(
        string idle, string absolute, int expectedIdleHours, int expectedAbsoluteHours)
    {
        var timeouts = Parse((Idle, idle), (Absolute, absolute));

        Assert.Equal(TimeSpan.FromHours(expectedIdleHours), timeouts.Idle);
        Assert.Equal(TimeSpan.FromHours(expectedAbsoluteHours), timeouts.Absolute);
    }

    [Theory]
    [InlineData(Idle, "48", 48, 720)]
    [InlineData(Absolute, "48", 120, 48)]
    public void OneSettingAlone_LeavesTheOtherAtItsDefault(
        string setting, string value, int expectedIdleHours, int expectedAbsoluteHours)
    {
        var timeouts = Parse((setting, value));

        Assert.Equal(TimeSpan.FromHours(expectedIdleHours), timeouts.Idle);
        Assert.Equal(TimeSpan.FromHours(expectedAbsoluteHours), timeouts.Absolute);
    }

    public static TheoryData<string, string, string> InvalidValues()
    {
        var data = new TheoryData<string, string, string>();
        foreach (var (setting, other) in new[] { (Idle, Absolute), (Absolute, Idle) })
        {
            foreach (var value in new[] { "", "   ", "1.5", "12h", "abc", "0", "8761", "-1", "2147483648", "99999999999" })
            {
                data.Add(setting, other, value);
            }
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(InvalidValues))]
    public void AnInvalidValue_StopsTheStart_NamingThatSettingAndNotTheOther(string setting, string other, string value)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => Parse((setting, value), (other, "24")));

        Assert.Contains(setting, ex.Message);
        Assert.DoesNotContain(other, ex.Message);
    }

    [Theory]
    [InlineData("720", "24", 720, 24)]
    [InlineData("8760", "1", 8760, 1)]
    [InlineData("24", "24", 24, 24)]
    public void AnIdleLimitLargerThanOrEqualToTheAbsoluteOne_IsAccepted(
        string idle, string absolute, int expectedIdleHours, int expectedAbsoluteHours)
    {
        var timeouts = Parse((Idle, idle), (Absolute, absolute));

        Assert.Equal(TimeSpan.FromHours(expectedIdleHours), timeouts.Idle);
        Assert.Equal(TimeSpan.FromHours(expectedAbsoluteHours), timeouts.Absolute);
    }
}
