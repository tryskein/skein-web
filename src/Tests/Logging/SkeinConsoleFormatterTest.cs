using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SkeinWeb.Logging;

namespace SkeinWeb.Tests.Logging;

/// <summary>
/// Pins the console contract of <see cref="SkeinConsoleFormatter"/>: logfmt
/// below Error, a JSON object for Error and Critical with the error context,
/// and secret-named fields masked in both forms — the field itself, its
/// placeholder in the message and the request path of the ASP.NET Core scope.
/// </summary>
public class SkeinConsoleFormatterTest
{
    private const string Secret = "fixturesecretvalue";
    private const string LinkToken = "linktokenfixturelinktokenfixturelinktokenfi";

    /// <summary>
    /// Renders one log call through a real <see cref="ILogger"/> so the state is
    /// the framework's own structured-message object, as in production.
    /// </summary>
    private static string Render(
        LogLevel level,
        Exception? exception,
        string template,
        object?[] args,
        IReadOnlyDictionary<string, object?>? scope = null)
    {
        var capture = new CapturingProvider();
        using (var factory = LoggerFactory.Create(b => b.SetMinimumLevel(LogLevel.Trace).AddProvider(capture)))
        {
            var logger = factory.CreateLogger("SkeinWeb.Test");
            using (scope is null ? null : logger.BeginScope(scope))
            {
#pragma warning disable CA2254 // the template is the subject of the test
                logger.Log(level, exception, template, args);
#pragma warning restore CA2254
            }
        }
        return capture.Output.ToString();
    }

    /// <summary>Feeds every log call to the formatter under test.</summary>
    private sealed class CapturingProvider : ILoggerProvider, ISupportExternalScope
    {
        private readonly SkeinConsoleFormatter _formatter = new();
        private IExternalScopeProvider _scopes = new LoggerExternalScopeProvider();
        public StringWriter Output { get; } = new();

        public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);
        public void SetScopeProvider(IExternalScopeProvider scopeProvider) => _scopes = scopeProvider;
        public void Dispose() { }

        private sealed class Logger(CapturingProvider owner, string category) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull =>
                owner._scopes.Push(state);
            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter) =>
                owner._formatter.Write(
                    new LogEntry<TState>(logLevel, category, eventId, state, exception, formatter),
                    owner._scopes,
                    owner.Output);
        }
    }

    [Fact]
    public void Error_is_one_json_object_with_the_error_context()
    {
        var output = Render(
            LogLevel.Error,
            new InvalidOperationException("boom"),
            "Failed to create {Thing} for {UserId}",
            ["container", "u-42"],
            new Dictionary<string, object?> { ["projectId"] = "p-15", ["attempt"] = 2 });

        var lines = output.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
        var line = Assert.Single(lines);
        using var json = JsonDocument.Parse(line);
        var root = json.RootElement;
        Assert.Equal("error", root.GetProperty("level").GetString());
        Assert.Equal("Failed to create container for u-42", root.GetProperty("message").GetString());
        Assert.Equal("skein-web", root.GetProperty("service").GetString());
        Assert.Equal("boom", root.GetProperty("error").GetString());
        Assert.Contains(nameof(InvalidOperationException), root.GetProperty("stackTrace").GetString());
        Assert.Equal("u-42", root.GetProperty("UserId").GetString());
        Assert.Equal("p-15", root.GetProperty("projectId").GetString());
        Assert.Equal(2, root.GetProperty("attempt").GetInt32());
        Assert.True(DateTimeOffset.TryParse(root.GetProperty("timestamp").GetString(), out var at));
        Assert.Equal(TimeSpan.Zero, at.Offset);
    }

    [Fact]
    public void Critical_is_json_with_level_fatal()
    {
        var output = Render(LogLevel.Critical, null, "cannot start", []);

        using var json = JsonDocument.Parse(output.Trim());
        Assert.Equal("fatal", json.RootElement.GetProperty("level").GetString());
    }

    [Theory]
    [InlineData(LogLevel.Debug, "debug")]
    [InlineData(LogLevel.Information, "info")]
    [InlineData(LogLevel.Warning, "warn")]
    public void Below_error_is_one_logfmt_line(LogLevel level, string name)
    {
        var output = Render(level, null, "Service started port={Port}", [5100]);

        var line = Assert.Single(output.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries));
        Assert.DoesNotContain("{", line);
        Assert.Contains($" level={name} ", line);
        Assert.Contains(" msg=\"Service started port=5100\"", line);
        Assert.EndsWith(" Port=5100", line);
    }

    [Theory]
    [InlineData("apiKey")]
    [InlineData("X-Skein-Api-Key")]
    [InlineData("password")]
    [InlineData("accessToken")]
    [InlineData("internalSecret")]
    [InlineData("Credential")]
    [InlineData("authorizationHeader")]
    [InlineData("api_key")]
    public void Secret_named_scope_field_is_masked_in_json_and_logfmt(string field)
    {
        var scope = new Dictionary<string, object?> { [field] = Secret };

        var json = Render(LogLevel.Error, null, "failed", [], scope);
        var logfmt = Render(LogLevel.Information, null, "done", [], scope);

        Assert.DoesNotContain(Secret, json);
        Assert.DoesNotContain(Secret, logfmt);
        using var doc = JsonDocument.Parse(json.Trim());
        Assert.Equal("***", doc.RootElement.GetProperty(field).GetString());
        Assert.Contains($" {field}=***", logfmt);
    }

    [Theory]
    [InlineData(LogLevel.Information)]
    [InlineData(LogLevel.Error)]
    public void Secret_named_placeholder_is_masked_in_the_message(LogLevel level)
    {
        var output = Render(level, null, "issued {Token} to {UserId}", [Secret, "u-42"]);

        Assert.DoesNotContain(Secret, output);
        Assert.Contains("issued *** to u-42", output);
    }

    [Fact]
    public void Request_path_of_the_request_scope_is_masked()
    {
        var scope = new Dictionary<string, object?> { ["RequestPath"] = "/api/v1/invitations/" + LinkToken };

        var output = Render(LogLevel.Error, null, "failed", [], scope);

        Assert.DoesNotContain(LinkToken, output);
        using var doc = JsonDocument.Parse(output.Trim());
        Assert.Equal("/api/v1/invitations/{redacted}", doc.RootElement.GetProperty("RequestPath").GetString());
    }

    [Fact]
    public void Logfmt_value_with_quotes_and_newline_stays_on_one_line()
    {
        var output = Render(LogLevel.Warning, null, "upstream said {Body}", ["a \"b\"\nc"]);

        var line = Assert.Single(output.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries));
        Assert.EndsWith(" Body=\"a \\\"b\\\"\\nc\"", line);
    }
}
