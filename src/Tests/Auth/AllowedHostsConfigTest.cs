using Microsoft.Extensions.Logging;
using SkeinWeb.Auth;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// The grammar of <c>SKEIN_ALLOWED_HOSTS</c> (FR-005): a comma-separated list
/// of host names (DNS names or IP literals, IPv6 in brackets), spaces around
/// entries and empty entries ignored. A scheme, port, path, wildcard or invalid
/// character, or a non-empty value without a single entry, stops the start with
/// an error naming the setting and the entry; unset or empty is the empty list,
/// which logs a startup Warning naming the setting.
/// </summary>
public class AllowedHostsConfigTest
{
    [Theory]
    [InlineData("skein.example.com,skein.internal.example.com")]
    [InlineData("  skein.example.com ,  skein.internal.example.com  ")]
    [InlineData("a.example.com,,b.example.com")]
    [InlineData("10.0.0.5")]
    [InlineData("[2001:db8::1]")]
    [InlineData("Skein.Example.COM.")]
    public void ValidValue_IsAccepted_AsANonEmptyList(string raw)
    {
        var config = AllowedHostsConfig.Parse(raw);

        Assert.False(config.IsEmpty);
    }

    [Theory]
    [InlineData("https://skein.example.com", "https://skein.example.com")]
    [InlineData("skein.example.com:443", "skein.example.com:443")]
    [InlineData("skein.example.com/x", "skein.example.com/x")]
    [InlineData("*", "*")]
    [InlineData("*.example.com", "*.example.com")]
    [InlineData("exa mple.com", "exa mple.com")]
    [InlineData(",,", ",,")]
    [InlineData(" , ", " , ")]
    // A bracketed entry that is not a bracketed IPv6 literal.
    [InlineData("[::1", "[::1")]
    [InlineData("[example]", "[example]")]
    [InlineData("[1.2.3.4]", "[1.2.3.4]")]
    [InlineData("[fe80::1%2]", "[fe80::1%2]")]
    public void InvalidValue_StopsTheStart_NamingTheSettingAndTheEntry(string raw, string entry)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => AllowedHostsConfig.Parse(raw));

        Assert.Contains("SKEIN_ALLOWED_HOSTS", ex.Message, StringComparison.Ordinal);
        Assert.Contains(entry, ex.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A DNS name built from labels of <paramref name="labelLengths"/> letters
    /// each, joined by dots: <c>[63, 63, 63, 61]</c> is 253 characters.
    /// </summary>
    private static string Name(params int[] labelLengths) =>
        string.Join('.', labelLengths.Select(n => new string('a', n)));

    // RFC 1035 limits (FR-005: an entry is a DNS name or an IP literal): a
    // label is 1-63 characters and does not start or end with '-'; a name is
    // at most 253 characters without the trailing dot. Four dot-separated
    // labels that are not all numeric are a name, not an IPv4 literal.
    public static TheoryData<string> NamesAtTheLimits => new()
    {
        Name(63),
        Name(63, 63, 63, 61),
        "1.a.b.c",
        "1a.2.3.4",
        "1234.5.6.7",
        "a-b.example.com",
    };

    [Theory]
    [MemberData(nameof(NamesAtTheLimits))]
    public void NameAtTheLimit_IsAccepted_AndAllowed(string name)
    {
        var config = AllowedHostsConfig.Parse(name);

        Assert.True(config.Allows(name));
        Assert.False(config.Allows("other.example.com"));
    }

    // Past the limits, or a dotted quad that is not an IPv4 address.
    public static TheoryData<string> EntriesPastTheLimits => new()
    {
        Name(64),
        Name(64, 3),
        Name(63, 63, 63, 62),
        "-a.example.com",
        "a-.example.com",
        "256.0.0.1",
        "1.2.3.999",
        "999.1.1.1",
    };

    [Theory]
    [MemberData(nameof(EntriesPastTheLimits))]
    public void EntryPastTheLimit_StopsTheStart_NamingTheSettingAndTheEntry(string entry)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => AllowedHostsConfig.Parse(entry));

        Assert.Contains("SKEIN_ALLOWED_HOSTS", ex.Message, StringComparison.Ordinal);
        Assert.Contains(entry, ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void UnsetOrEmptyValue_IsTheEmptyList(string? raw)
    {
        var config = AllowedHostsConfig.Parse(raw);

        Assert.True(config.IsEmpty);
    }

    // FR-005: an empty list allows any host, including a missing or malformed one.
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("anything.example.com")]
    [InlineData("exa mple.com")]
    public void EmptyList_AllowsEveryHost(string? host)
    {
        Assert.True(AllowedHostsConfig.Parse(null).Allows(host));
        Assert.True(AllowedHostsConfig.Parse("").Allows(host));
    }

    // With a non-empty list, a missing, empty or malformed host is never listed.
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("exa mple.com")]
    [InlineData("*.example.com")]
    [InlineData("[::1")]
    [InlineData("[example]")]
    [InlineData("[1.2.3.4]")]
    [InlineData("[fe80::1%2]")]
    [InlineData("999.1.1.1")]
    public void NonEmptyList_DoesNotAllow_AMissingOrMalformedHost(string? host)
    {
        var config = AllowedHostsConfig.Parse("skein.example.com");

        Assert.True(config.Allows("skein.example.com"));
        Assert.False(config.Allows(host));
    }

    [Fact]
    public void NonEmptyList_DoesNotAllow_ANameOverTheLengthLimit()
    {
        var config = AllowedHostsConfig.Parse("skein.example.com");

        Assert.False(config.Allows(Name(63, 63, 63, 62)));
    }

    /// <summary>Records level and formatted message of every entry.</summary>
    private sealed class RecordingLogger : ILogger
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }

    /// <remarks>
    /// The Warning does not depend on the authentication mode: the method takes
    /// no mode, so "in every mode" holds by construction and the cases vary the
    /// value only.
    /// </remarks>
    [Theory]
    [InlineData(null, true)]
    [InlineData("", true)]
    [InlineData("skein.example.com", false)]
    public void StartupWarning_EmptyList_NamesTheSetting(string? raw, bool expected)
    {
        var logger = new RecordingLogger();

        AllowedHostsConfig.Parse(raw).WarnIfEmpty(logger);

        Assert.Equal(expected, logger.Entries.Any(e =>
            e.Level == LogLevel.Warning && e.Message.Contains("SKEIN_ALLOWED_HOSTS", StringComparison.Ordinal)));
    }
}
