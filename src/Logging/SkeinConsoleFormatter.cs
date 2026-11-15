using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Console;

namespace SkeinWeb.Logging;

/// <summary>
/// Console formatter of the service: one logfmt line for Trace…Warning, one
/// JSON object for Error and Critical, with secret-bearing fields masked in
/// both forms.
/// </summary>
/// <remarks>
/// Fields are the structured values of the message template and the key/value
/// pairs of every active scope (<c>logger.BeginScope(new Dictionary…)</c>, the
/// ASP.NET Core request scope), so the context of an error reaches its JSON
/// line without each call site repeating it. A field whose name contains
/// <c>password</c>, <c>token</c>, <c>secret</c>, <c>key</c>, <c>credential</c>,
/// <c>authorization</c>, <c>apikey</c> or <c>api_key</c> (case-insensitive) is
/// written as <see cref="Masked"/>, and so is its placeholder in the rendered
/// message. The request scope's <c>RequestPath</c> passes through
/// <see cref="LoggablePath"/>, because proxied paths carry link tokens.
/// Timestamps are UTC, ISO 8601.
/// </remarks>
public sealed class SkeinConsoleFormatter : ConsoleFormatter
{
    /// <summary>Formatter name to set as <c>ConsoleLoggerOptions.FormatterName</c>.</summary>
    public const string FormatterName = "skein";

    /// <summary>Written in place of a secret-bearing value.</summary>
    public const string Masked = "***";

    /// <summary>Value of the <c>service</c> field on every JSON line.</summary>
    public const string ServiceName = "skein-web";

    private const string OriginalFormatKey = "{OriginalFormat}";
    private const string RequestPathKey = "RequestPath";

    private static readonly string[] SecretNameParts =
        ["password", "token", "secret", "key", "credential", "authorization", "apikey", "api_key"];

    /// <summary>Creates the formatter. The format is fixed and takes no options.</summary>
    public SkeinConsoleFormatter()
        : base(FormatterName)
    {
    }

    /// <summary>Adds the console logger with this formatter to <paramref name="logging"/>.</summary>
    /// <param name="logging">The logging builder of the host or of a bootstrap factory.</param>
    public static ILoggingBuilder AddTo(ILoggingBuilder logging) =>
        logging
            .AddConsole(o => o.FormatterName = FormatterName)
            .AddConsoleFormatter<SkeinConsoleFormatter, ConsoleFormatterOptions>();

    /// <summary>Whether a field of this name carries a secret and must be masked.</summary>
    /// <param name="name">Field name.</param>
    public static bool IsSecretName(string name)
    {
        foreach (var part in SecretNameParts)
        {
            if (name.Contains(part, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    /// <inheritdoc />
    public override void Write<TState>(
        in LogEntry<TState> logEntry,
        IExternalScopeProvider? scopeProvider,
        TextWriter textWriter)
    {
        var fields = new List<KeyValuePair<string, object?>>();
        string? template = null;
        if (logEntry.State is IEnumerable<KeyValuePair<string, object?>> stateValues)
        {
            foreach (var (name, value) in stateValues)
            {
                if (name == OriginalFormatKey)
                {
                    template = value as string;
                    continue;
                }
                AddField(fields, name, value);
            }
        }
        scopeProvider?.ForEachScope(static (scope, list) =>
        {
            if (scope is IEnumerable<KeyValuePair<string, object?>> scopeValues)
            {
                foreach (var (name, value) in scopeValues)
                {
                    if (name != OriginalFormatKey)
                    {
                        AddField(list, name, value);
                    }
                }
            }
        }, fields);

        var message = RenderMessage(logEntry, template);
        var timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);
        var exception = logEntry.Exception;

        if (logEntry.LogLevel >= LogLevel.Error)
        {
            WriteJson(textWriter, timestamp, logEntry.LogLevel, logEntry.Category, message, exception, fields);
        }
        else
        {
            WriteLogfmt(textWriter, timestamp, logEntry.LogLevel, logEntry.Category, message, exception, fields);
        }
    }

    private static void AddField(List<KeyValuePair<string, object?>> fields, string name, object? value)
    {
        object? safe = IsSecretName(name)
            ? Masked
            : name == RequestPathKey ? LoggablePath.From(value?.ToString()) : value;
        fields.Add(new(name, safe));
    }

    /// <summary>
    /// The rendered message. When a template placeholder names a secret the
    /// message is rebuilt from the template with that placeholder masked;
    /// otherwise the logger's own formatter renders it.
    /// </summary>
    private static string RenderMessage<TState>(in LogEntry<TState> logEntry, string? template)
    {
        if (template is null ||
            logEntry.State is not IReadOnlyList<KeyValuePair<string, object?>> values ||
            !values.Any(v => v.Key != OriginalFormatKey && IsSecretName(v.Key)))
        {
            return logEntry.Formatter(logEntry.State, logEntry.Exception) ?? string.Empty;
        }

        // Placeholders bind to the state values by position.
        var builder = new StringBuilder(template.Length);
        var index = 0;
        for (var i = 0; i < template.Length; i++)
        {
            var c = template[i];
            if ((c == '{' || c == '}') && i + 1 < template.Length && template[i + 1] == c)
            {
                builder.Append(c);
                i++;
                continue;
            }
            if (c != '{')
            {
                builder.Append(c);
                continue;
            }
            var end = template.IndexOf('}', i + 1);
            if (end < 0)
            {
                builder.Append(template, i, template.Length - i);
                break;
            }
            var value = index < values.Count ? values[index] : default;
            index++;
            builder.Append(value.Key is null
                ? template.AsSpan(i, end - i + 1).ToString()
                : IsSecretName(value.Key) ? Masked : Convert.ToString(value.Value, CultureInfo.InvariantCulture));
            i = end;
        }
        return builder.ToString();
    }

    private static void WriteJson(
        TextWriter writer,
        string timestamp,
        LogLevel level,
        string category,
        string message,
        Exception? exception,
        List<KeyValuePair<string, object?>> fields)
    {
        using var buffer = new MemoryStream();
        using (var json = new Utf8JsonWriter(buffer))
        {
            json.WriteStartObject();
            json.WriteString("level", LevelName(level));
            json.WriteString("message", message);
            json.WriteString("service", ServiceName);
            json.WriteString("category", category);
            json.WriteString("timestamp", timestamp);
            if (exception is not null)
            {
                json.WriteString("error", exception.Message);
                json.WriteString("stackTrace", exception.ToString());
            }
            var written = new HashSet<string>(StringComparer.Ordinal)
            {
                "level", "message", "service", "category", "timestamp", "error", "stackTrace",
            };
            foreach (var (name, value) in fields)
            {
                if (written.Add(name))
                {
                    json.WritePropertyName(name);
                    WriteJsonValue(json, value);
                }
            }
            json.WriteEndObject();
        }
        writer.Write(Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length));
        writer.Write(Environment.NewLine);
    }

    private static void WriteJsonValue(Utf8JsonWriter json, object? value)
    {
        switch (value)
        {
            case null:
                json.WriteNullValue();
                break;
            case bool b:
                json.WriteBooleanValue(b);
                break;
            case double d when !double.IsFinite(d):
            case float f when !float.IsFinite(f):
                json.WriteStringValue(Convert.ToString(value, CultureInfo.InvariantCulture));
                break;
            case int or long or short or byte or uint or ulong or ushort or sbyte or double or float or decimal:
                json.WriteRawValue(Convert.ToString(value, CultureInfo.InvariantCulture)!);
                break;
            default:
                json.WriteStringValue(Convert.ToString(value, CultureInfo.InvariantCulture));
                break;
        }
    }

    private static void WriteLogfmt(
        TextWriter writer,
        string timestamp,
        LogLevel level,
        string category,
        string message,
        Exception? exception,
        List<KeyValuePair<string, object?>> fields)
    {
        var line = new StringBuilder();
        line.Append("time=").Append(timestamp);
        line.Append(" level=").Append(LevelName(level));
        line.Append(" category=");
        AppendLogfmtValue(line, category);
        line.Append(" msg=");
        AppendLogfmtValue(line, message);
        var written = new HashSet<string>(StringComparer.Ordinal) { "time", "level", "category", "msg", "error" };
        foreach (var (name, value) in fields)
        {
            if (written.Add(name))
            {
                line.Append(' ').Append(name).Append('=');
                AppendLogfmtValue(line, Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty);
            }
        }
        if (exception is not null)
        {
            line.Append(" error=");
            AppendLogfmtValue(line, $"{exception.GetType().FullName}: {exception.Message}");
        }
        writer.Write(line.ToString());
        writer.Write(Environment.NewLine);
    }

    private static void AppendLogfmtValue(StringBuilder line, string value)
    {
        var quote = value.Length == 0 || value.Any(c => c is ' ' or '=' or '"' or '\\' || char.IsControl(c));
        if (!quote)
        {
            line.Append(value);
            return;
        }
        line.Append('"');
        foreach (var c in value)
        {
            switch (c)
            {
                case '"': line.Append("\\\""); break;
                case '\\': line.Append("\\\\"); break;
                case '\n': line.Append("\\n"); break;
                case '\r': line.Append("\\r"); break;
                case '\t': line.Append("\\t"); break;
                default:
                    if (char.IsControl(c))
                    {
                        line.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        line.Append(c);
                    }
                    break;
            }
        }
        line.Append('"');
    }

    private static string LevelName(LogLevel level) => level switch
    {
        LogLevel.Trace => "trace",
        LogLevel.Debug => "debug",
        LogLevel.Information => "info",
        LogLevel.Warning => "warn",
        LogLevel.Error => "error",
        LogLevel.Critical => "fatal",
        _ => "none",
    };
}
