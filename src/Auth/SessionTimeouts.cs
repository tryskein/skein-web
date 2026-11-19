using System.Globalization;

namespace SkeinWeb.Auth;

/// <summary>
/// The two limits of a browser session, read once at startup from
/// <see cref="IdleTimeoutSetting"/> and <see cref="AbsoluteTimeoutSetting"/>
/// (see <c>docs/env-reference.md</c>, section «Authentication»).
/// <list type="bullet">
///   <item><see cref="Idle"/> — how long a session lives without a request that
///         reads its ticket;</item>
///   <item><see cref="Absolute"/> — how long a session lives from its sign-in,
///         whatever its activity.</item>
/// </list>
/// The cookie handler, the session store and the per-user index take their
/// lifetimes from this one object; no other session lifetime exists in code.
/// An idle limit larger than the absolute one is a valid configuration: the
/// session then ends at the absolute limit.
/// </summary>
public sealed class SessionTimeouts
{
    /// <summary>Setting that carries the idle limit, in whole hours.</summary>
    public const string IdleTimeoutSetting = "SKEIN_SESSION_IDLE_TIMEOUT_HOURS";

    /// <summary>Setting that carries the absolute limit, in whole hours.</summary>
    public const string AbsoluteTimeoutSetting = "SKEIN_SESSION_ABSOLUTE_TIMEOUT_HOURS";

    /// <summary>Idle limit when <see cref="IdleTimeoutSetting"/> is not set: 120 h (5 days).</summary>
    public const int DefaultIdleTimeoutHours = 120;

    /// <summary>Absolute limit when <see cref="AbsoluteTimeoutSetting"/> is not set: 720 h (30 days).</summary>
    public const int DefaultAbsoluteTimeoutHours = 720;

    /// <summary>Lowest accepted value of either setting, in hours.</summary>
    public const int MinHours = 1;

    /// <summary>Highest accepted value of either setting, in hours (365 days).</summary>
    public const int MaxHours = 8760;

    /// <summary>
    /// Creates the limits from whole hours, each in
    /// [<see cref="MinHours"/>, <see cref="MaxHours"/>].
    /// </summary>
    /// <param name="idleHours">Idle limit, in hours.</param>
    /// <param name="absoluteHours">Absolute limit, in hours.</param>
    /// <exception cref="ArgumentOutOfRangeException">A value is outside the accepted range.</exception>
    public SessionTimeouts(int idleHours, int absoluteHours)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(idleHours, MinHours);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(idleHours, MaxHours);
        ArgumentOutOfRangeException.ThrowIfLessThan(absoluteHours, MinHours);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(absoluteHours, MaxHours);
        IdleHours = idleHours;
        AbsoluteHours = absoluteHours;
    }

    /// <summary>Idle limit, in whole hours.</summary>
    public int IdleHours { get; }

    /// <summary>Absolute limit, in whole hours.</summary>
    public int AbsoluteHours { get; }

    /// <summary>Idle limit: how long a session lives without a request that reads its ticket.</summary>
    public TimeSpan Idle => TimeSpan.FromHours(IdleHours);

    /// <summary>Absolute limit: how long a session lives from its sign-in.</summary>
    public TimeSpan Absolute => TimeSpan.FromHours(AbsoluteHours);

    /// <summary>
    /// Reads both settings. A setting that is not present yields its default;
    /// a present one must be a whole number of hours in
    /// [<see cref="MinHours"/>, <see cref="MaxHours"/>]. The two are read
    /// independently of each other.
    /// </summary>
    /// <param name="configuration">The application configuration.</param>
    /// <returns>The limits in effect for this process.</returns>
    /// <exception cref="InvalidOperationException">A setting is present but empty,
    /// not a whole number, or out of range; the message names that setting. A typo
    /// must stop the start rather than run with a session lifetime nobody chose.</exception>
    public static SessionTimeouts Parse(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var idle = ParseHours(configuration[IdleTimeoutSetting], IdleTimeoutSetting, DefaultIdleTimeoutHours);
        var absolute = ParseHours(configuration[AbsoluteTimeoutSetting], AbsoluteTimeoutSetting, DefaultAbsoluteTimeoutHours);
        return new SessionTimeouts(idle, absolute);
    }

    private static int ParseHours(string? raw, string setting, int defaultHours)
    {
        if (raw is null)
        {
            return defaultHours;
        }
        if (!int.TryParse(raw.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var hours)
            || hours < MinHours
            || hours > MaxHours)
        {
            throw new InvalidOperationException(
                $"{setting} must be a whole number of hours between {MinHours} and {MaxHours}, got '{raw}'");
        }
        return hours;
    }
}
