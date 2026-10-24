using System.Globalization;

namespace SkeinWeb.Hubs;

/// <summary>
/// Settings of the addressed project-event delivery of <see cref="SkeinHub"/>
/// (spec sk-622.21 US-9). Built once in <c>Program.cs</c> from the
/// environment and registered as a singleton; the hub reads the same object.
/// </summary>
public sealed class HubDeliveryOptions
{
    /// <summary>Environment variable of <see cref="MaxProjectsPerConnection"/>.</summary>
    public const string MaxProjectsPerConnectionEnvVar = "HUB_MAX_PROJECTS_PER_CONNECTION";

    /// <summary>Default <see cref="MaxProjectsPerConnection"/>: 50 (spec US-9).</summary>
    public const int DefaultMaxProjectsPerConnection = 50;

    /// <summary>
    /// Most projects one hub connection may have declared at a time. Ids past
    /// it, in declaration order, are rejected with <c>limit</c>. The "all
    /// visible" mode is not subject to it.
    /// </summary>
    public int MaxProjectsPerConnection { get; init; } = DefaultMaxProjectsPerConnection;

    /// <summary>
    /// Turns the raw value of <see cref="MaxProjectsPerConnectionEnvVar"/> into
    /// <see cref="MaxProjectsPerConnection"/>. <c>null</c> (variable not set)
    /// yields <see cref="DefaultMaxProjectsPerConnection"/>; anything else must
    /// be a positive whole number.
    /// </summary>
    /// <exception cref="InvalidOperationException">The value is set but empty,
    /// not an integer, or not positive — startup must stop rather than run
    /// with a limit nobody chose (spec edge 17).</exception>
    public static int ParseMaxProjectsPerConnection(string? raw)
    {
        if (raw is null)
        {
            return DefaultMaxProjectsPerConnection;
        }
        if (!int.TryParse(raw.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var value)
            || value <= 0)
        {
            throw new InvalidOperationException(
                $"{MaxProjectsPerConnectionEnvVar} must be a positive whole number, got '{raw}'");
        }
        return value;
    }
}
