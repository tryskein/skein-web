using System.Net;
using System.Globalization;
using System.Net.Http.Json;
using System.Text.Json;

namespace SkeinWeb.Auth;

/// <summary>
/// 200 body of skein-api <c>GET /api/v1/internal/instance-config</c> — the
/// installation settings skein-web takes from skein-api instead of keeping
/// copies (D-7, US-18). Mirrors <c>internal/accounts/contract.go#InstanceConfig</c>
/// (T012): every key is always present, null means "not configured". Read with
/// the web JSON defaults (camelCase). Every member is <c>required</c>, so a body
/// missing a key fails to deserialize instead of yielding a silent default.
/// </summary>
public sealed record InstanceConfig
{
    /// <summary><c>SKEIN_AUTH_MODE</c>: <c>local</c> | <c>keycloak</c> | <c>hybrid</c>
    /// (see <see cref="HasKnownAuthMode"/>).</summary>
    public required string? AuthMode { get; init; }

    /// <summary><c>SKEIN_SIGNUP_ENABLED</c>: self-service registration is open.</summary>
    public required bool SignupEnabled { get; init; }

    /// <summary><c>SKEIN_EMAIL_ENABLED</c>: outgoing mail works (password reset,
    /// email confirmation, invitation emails).</summary>
    public required bool EmailEnabled { get; init; }

    /// <summary><c>SKEIN_TURNSTILE_SITE_KEY</c>, the public Turnstile key; null = no captcha.</summary>
    public required string? TurnstileSiteKey { get; init; }

    /// <summary><c>SKEIN_PROJECT_PREFIX_MIN_LENGTH</c>; null = no minimum.</summary>
    public required int? ProjectPrefixMinLength { get; init; }

    /// <summary><c>SKEIN_TERMS_URL</c>, linked from the consent checkbox; null = no link.</summary>
    public required string? TermsUrl { get; init; }

    /// <summary><c>SKEIN_PRIVACY_URL</c>, linked from the consent checkbox; null = no link.</summary>
    public required string? PrivacyUrl { get; init; }

    /// <summary><c>SKEIN_INSTANCE_ADMIN_ENABLED</c>: the instance admin role exists.</summary>
    public required bool InstanceAdminEnabled { get; init; }

    /// <summary><see cref="AuthMode"/> is one of the three contract values. A
    /// body failing this is a contract violation, not something to read as
    /// <c>local</c>.</summary>
    public bool HasKnownAuthMode =>
        AuthMode is WebAuthMode.ApiLocal or WebAuthMode.ApiKeycloak or WebAuthMode.ApiHybrid;
}

/// <summary>
/// skein-api did not hand out the installation settings inside the startup
/// window, or handed out ones skein-web cannot run with. The process must not
/// start (E-13): there is no web-side default for the authentication mode.
/// </summary>
public sealed class InstanceConfigUnavailableException : Exception
{
    /// <summary>Creates the exception with the operator-facing reason.</summary>
    public InstanceConfigUnavailableException(string message, Exception? inner = null)
        : base(message, inner)
    {
    }
}

/// <summary>
/// Reads the installation settings from skein-api before the web host is built
/// (plan K-12, D-7, E-13): the authentication scheme is chosen from
/// <see cref="InstanceConfig.AuthMode"/>, and <c>AddAuthentication</c> must see
/// every scheme up front, so this runs synchronously in <c>Program.cs</c> ahead
/// of <c>builder.Build()</c>.
/// </summary>
/// <remarks>
/// <para>
/// Algorithm: <c>GET /api/v1/internal/instance-config</c> with
/// <c>X-Skein-Internal-Secret</c> only (no identity). A connection failure, a
/// per-attempt timeout or a non-2xx status other than 401/404 is treated as
/// "not yet" — skein-api may still be starting next to us — and retried with exponential backoff
/// (<see cref="FirstRetryDelay"/> doubling up to <see cref="MaxRetryDelay"/>)
/// until the startup window runs out; then the load fails. A 401 (wrong
/// secret), a 404 (wrong address or route) and a 200 whose body is not the
/// contract (unparseable, or an <c>authMode</c> outside the three values) fail
/// at once: retrying would only get the same answer.
/// </para>
/// <para>
/// All waiting goes through the injected <see cref="TimeProvider"/>, so the
/// window and the backoff are observable with a fake clock.
/// </para>
/// </remarks>
public static class InstanceConfigBootstrap
{
    /// <summary>skein-api route of the installation settings (T012).</summary>
    public const string Path = "/api/v1/internal/instance-config";

    /// <summary>
    /// Environment variable bounding the whole load, in whole seconds.
    /// </summary>
    public const string StartupTimeoutEnvVar = "SKEIN_API_STARTUP_TIMEOUT_SECONDS";

    /// <summary>Default startup window: 60 s (plan K-12).</summary>
    public static readonly TimeSpan DefaultStartupTimeout = TimeSpan.FromSeconds(60);

    /// <summary>Highest accepted override, in seconds (one hour) — a window
    /// longer than that is a typo, not a deployment choice.</summary>
    public const int MaxStartupTimeoutSeconds = 3600;

    /// <summary>Delay before the second attempt; doubles per attempt.</summary>
    public static readonly TimeSpan FirstRetryDelay = TimeSpan.FromMilliseconds(500);

    /// <summary>Upper bound of the delay between attempts.</summary>
    public static readonly TimeSpan MaxRetryDelay = TimeSpan.FromSeconds(5);

    /// <summary>Upper bound of one attempt — a hung connection must not eat the
    /// whole window in a single try.</summary>
    public static readonly TimeSpan AttemptTimeout = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Turns the raw value of <see cref="StartupTimeoutEnvVar"/> into the window.
    /// <c>null</c> (not set) yields <see cref="DefaultStartupTimeout"/>; anything
    /// else must be a whole number of seconds in [1, <see cref="MaxStartupTimeoutSeconds"/>].
    /// </summary>
    /// <exception cref="InvalidOperationException">The value is set but is empty,
    /// not an integer, or out of range — a typo must stop startup rather than
    /// silently run with a window nobody chose.</exception>
    public static TimeSpan ParseStartupTimeout(string? raw)
    {
        if (raw is null)
        {
            return DefaultStartupTimeout;
        }
        if (!int.TryParse(raw.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)
            || seconds < 1
            || seconds > MaxStartupTimeoutSeconds)
        {
            throw new InvalidOperationException(
                $"{StartupTimeoutEnvVar} must be a whole number of seconds between 1 and " +
                $"{MaxStartupTimeoutSeconds}, got '{raw}'");
        }
        return TimeSpan.FromSeconds(seconds);
    }

    /// <summary>
    /// Loads the installation settings, retrying until <paramref name="window"/>
    /// runs out (see the type remarks for the algorithm).
    /// </summary>
    /// <param name="http">Client whose base address is skein-api and which sends
    /// <c>X-Skein-Internal-Secret</c> (see <see cref="CreateHttpClient"/>).</param>
    /// <param name="window">Total time allowed, measured on <paramref name="time"/>; must be positive.</param>
    /// <param name="time">Clock for the window, the per-attempt timeout and the backoff.</param>
    /// <param name="logger">Receives one warning per failed attempt.</param>
    /// <param name="ct">Process shutdown.</param>
    /// <returns>Settings whose <see cref="InstanceConfig.AuthMode"/> is one of the contract values.</returns>
    /// <exception cref="InstanceConfigUnavailableException">No valid answer inside the window,
    /// or a 200 that is not the contract.</exception>
    public static async Task<InstanceConfig> LoadAsync(
        HttpClient http,
        TimeSpan window,
        TimeProvider time,
        ILogger logger,
        CancellationToken ct)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(window, TimeSpan.Zero);

        var started = time.GetTimestamp();
        var delay = FirstRetryDelay;
        string lastFailure = "no attempt made";

        for (var attempt = 1; ; attempt++)
        {
            var remaining = window - time.GetElapsedTime(started);
            if (remaining <= TimeSpan.Zero)
            {
                break;
            }

            var attemptBudget = remaining < AttemptTimeout ? remaining : AttemptTimeout;
            using (var attemptCts = new CancellationTokenSource(attemptBudget, time))
            using (var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, attemptCts.Token))
            {
                try
                {
                    using var response = await http.GetAsync(Path, linked.Token);
                    if (response.IsSuccessStatusCode)
                    {
                        return await ReadContractAsync(response, linked.Token);
                    }
                    if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.NotFound)
                    {
                        // Deterministic: a wrong secret or a wrong address/route
                        // is not fixed by waiting — fail now, naming the cause.
                        throw new InstanceConfigUnavailableException(
                            $"skein-api answered {Path} with HTTP {(int)response.StatusCode} — " +
                            (response.StatusCode == HttpStatusCode.Unauthorized
                                ? "SKEIN_INTERNAL_SECRET does not match skein-api's value."
                                : "check SKEIN_API_URL and that skein-api serves the installation settings (T012)."));
                    }
                    lastFailure = $"HTTP {(int)response.StatusCode}";
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    lastFailure = $"no answer within {attemptBudget.TotalMilliseconds:0} ms";
                }
                catch (HttpRequestException ex)
                {
                    lastFailure = ex.Message;
                }
            }

            logger.LogWarning(
                "instance-config: attempt {Attempt} failed ({Failure}); retrying until the startup window ends",
                attempt, lastFailure);

            var left = window - time.GetElapsedTime(started);
            if (left <= TimeSpan.Zero)
            {
                break;
            }
            await Task.Delay(delay < left ? delay : left, time, ct);
            delay = delay * 2 < MaxRetryDelay ? delay * 2 : MaxRetryDelay;
        }

        throw new InstanceConfigUnavailableException(
            $"skein-api did not return the installation settings ({Path}) within " +
            $"{window.TotalSeconds:0.###} s ({StartupTimeoutEnvVar}); last failure: {lastFailure}. " +
            "skein-web takes its authentication mode from skein-api and does not start without it.");
    }

    /// <summary>
    /// Builds the bootstrap client: skein-api base address, the channel secret,
    /// no Polly (the retry and its window are <see cref="LoadAsync"/>'s) and no
    /// client-level timeout (each attempt carries its own).
    /// </summary>
    /// <param name="skeinApiUrl"><c>SKEIN_API_URL</c>.</param>
    /// <param name="internalSecret"><c>SKEIN_INTERNAL_SECRET</c>.</param>
    public static HttpClient CreateHttpClient(string skeinApiUrl, string internalSecret)
    {
        var http = new HttpClient
        {
            BaseAddress = new Uri(skeinApiUrl),
            Timeout = Timeout.InfiniteTimeSpan,
        };
        http.DefaultRequestHeaders.Add(SkeinHeaders.InternalSecret, internalSecret);
        return http;
    }

    private static async Task<InstanceConfig> ReadContractAsync(HttpResponseMessage response, CancellationToken ct)
    {
        InstanceConfig? config;
        try
        {
            config = await response.Content.ReadFromJsonAsync<InstanceConfig>(ct);
        }
        catch (JsonException ex)
        {
            throw new InstanceConfigUnavailableException(
                $"skein-api answered {Path} with a body that is not the InstanceConfig contract.", ex);
        }

        if (config is null)
        {
            throw new InstanceConfigUnavailableException(
                $"skein-api answered {Path} with an empty body.");
        }
        if (!config.HasKnownAuthMode)
        {
            throw new InstanceConfigUnavailableException(
                $"skein-api reported authMode '{config.AuthMode}' on {Path}, expected one of " +
                $"'{WebAuthMode.ApiLocal}', '{WebAuthMode.ApiKeycloak}', '{WebAuthMode.ApiHybrid}'.");
        }
        return config;
    }
}
