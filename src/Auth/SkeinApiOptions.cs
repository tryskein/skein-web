using System.Globalization;

namespace SkeinWeb.Auth;

/// <summary>
/// Strongly-typed configuration for the BFF -> skein-api channel.
/// Populated from environment variables in Program.cs (no fallbacks).
/// </summary>
public sealed class SkeinApiOptions
{
    /// <summary>
    /// Base URL of the upstream skein-api, e.g. <c>http://skein-api:5100</c>.
    /// Used as <see cref="System.Net.Http.HttpClient.BaseAddress"/> for the
    /// typed SkeinApiClient and the reverse-proxy named client.
    /// </summary>
    public string Url { get; set; } = "";

    /// <summary>
    /// Shared secret on the X-Skein-Internal-Secret header. Must match the
    /// SKEIN_INTERNAL_SECRET configured on the skein-api side.
    /// </summary>
    public string InternalSecret { get; set; } = "";

    /// <summary>
    /// Whether a trusted proxy chain is configured (sk-163 S9), i.e.
    /// <c>SKEIN_TRUSTED_PROXIES</c> is non-empty. Gates the per-IP login
    /// throttle and the <c>X-Skein-Client-Ip</c> forward: BOTH are meaningful
    /// only when <c>Connection.RemoteIpAddress</c> reflects the real client,
    /// which requires at least one trusted proxy to honour X-Forwarded-For.
    ///
    /// When FALSE (the default, behind an ingress with no trusted-proxy config)
    /// RemoteIpAddress is the constant ingress/peer IP for EVERY user, so a
    /// per-IP bucket keyed on it would lump all logins into one bucket — an
    /// attacker could lock out the whole org with ~30 garbage POSTs/min. We
    /// therefore DISABLE the per-IP bucket (and skip the IP forward) in that
    /// state; the per-email throttle and the API in-memory backstop still run.
    /// Set automatically in Program.cs from SKEIN_TRUSTED_PROXIES; never an env
    /// var of its own.
    /// </summary>
    public bool ClientIpTrusted { get; set; }

    /// <summary>
    /// Environment variable that overrides <see cref="McpUpstreamHeadersTimeout"/>
    /// (sk-608). Whole seconds, see <see cref="ParseMcpUpstreamHeadersTimeout"/>.
    /// </summary>
    public const string McpUpstreamHeadersTimeoutEnvVar = "SKEIN_MCP_UPSTREAM_HEADERS_TIMEOUT_SECONDS";

    /// <summary>
    /// Default <see cref="McpUpstreamHeadersTimeout"/>: 120 s.
    /// <para>Why not the former 30 s: MCP calls observed in production ran
    /// for 30 s and more, the proxy cut them at 30 s, and the writes they carried
    /// had already been committed — the caller saw a 504, retried, and duplicated
    /// them (sk-608). The window has to cover the slowest legitimate call, not the
    /// typical one.</para>
    /// <para>skein-api's batch tools stop their own loop at 20 s
    /// (<c>batchLoopDeadline</c> in <c>internal/mcp/tools/batch_deadline.go</c>),
    /// sized to land inside this window. 120 s keeps it well inside, so that
    /// stop-and-report path still works; raising the window only widens the
    /// margin. The ceiling is <see cref="MaxMcpUpstreamHeadersTimeoutSeconds"/>.</para>
    /// </summary>
    public static readonly TimeSpan DefaultMcpUpstreamHeadersTimeout = TimeSpan.FromSeconds(120);

    /// <summary>
    /// Lowest accepted override, in seconds. A window shorter than skein-api's
    /// 20 s batch-loop deadline plus its measured pre-handler overhead would cut
    /// a batch call before it can report which rows it wrote — the silent
    /// partial write that deadline exists to prevent.
    /// </summary>
    public const int MinMcpUpstreamHeadersTimeoutSeconds = 30;

    /// <summary>
    /// Highest accepted override, in seconds: the <c>proxy_read_timeout</c> of
    /// the <c>/mcp</c> location in skein-frontend's nginx (3600 s). A larger
    /// value could never fire — nginx would cut the request first with its own
    /// error page instead of this proxy's JSON body.
    /// </summary>
    public const int MaxMcpUpstreamHeadersTimeoutSeconds = 3600;

    /// <summary>
    /// How long <c>McpProxyMiddleware</c> waits for skein-api to send response
    /// headers on a <c>/mcp</c> request before answering 504
    /// <c>upstream_timeout</c>. Bounds only the connect/headers phase; a
    /// streaming (SSE) body is not limited by it. Set in Program.cs from
    /// <see cref="McpUpstreamHeadersTimeoutEnvVar"/>.
    /// </summary>
    public TimeSpan McpUpstreamHeadersTimeout { get; set; } = DefaultMcpUpstreamHeadersTimeout;

    /// <summary>
    /// Turns the raw value of <see cref="McpUpstreamHeadersTimeoutEnvVar"/> into
    /// the timeout. <c>null</c> (variable not set) yields
    /// <see cref="DefaultMcpUpstreamHeadersTimeout"/>; anything else must be a
    /// whole number of seconds in
    /// [<see cref="MinMcpUpstreamHeadersTimeoutSeconds"/>,
    /// <see cref="MaxMcpUpstreamHeadersTimeoutSeconds"/>].
    /// </summary>
    /// <exception cref="InvalidOperationException">The value is set but is empty,
    /// not an integer, or out of range — a typo must stop startup rather than
    /// silently run with a timeout nobody chose.</exception>
    public static TimeSpan ParseMcpUpstreamHeadersTimeout(string? raw)
    {
        if (raw is null)
        {
            return DefaultMcpUpstreamHeadersTimeout;
        }
        if (!int.TryParse(raw.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)
            || seconds < MinMcpUpstreamHeadersTimeoutSeconds
            || seconds > MaxMcpUpstreamHeadersTimeoutSeconds)
        {
            throw new InvalidOperationException(
                $"{McpUpstreamHeadersTimeoutEnvVar} must be a whole number of seconds between " +
                $"{MinMcpUpstreamHeadersTimeoutSeconds} and {MaxMcpUpstreamHeadersTimeoutSeconds}, got '{raw}'");
        }
        return TimeSpan.FromSeconds(seconds);
    }
}
