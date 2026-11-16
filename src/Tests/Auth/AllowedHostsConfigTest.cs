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
    public void InvalidValue_StopsTheStart_NamingTheSettingAndTheEntry(string raw, string entry)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => AllowedHostsConfig.Parse(raw));

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
