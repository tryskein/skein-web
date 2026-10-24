using Microsoft.Extensions.DependencyInjection.Extensions;

namespace SkeinWeb.Auth;

/// <summary>
/// DI registration of <see cref="SkeinServiceApiClient"/> — the single
/// composition of the service-to-service pipeline, shared by
/// <c>Program.cs</c> and the tests that observe it.
/// </summary>
public static class SkeinServiceApiClientRegistration
{
    /// <summary>
    /// Registers the typed <see cref="SkeinServiceApiClient"/>: base address
    /// skein-api, <see cref="SkeinApiRetryPolicy"/> (three retries), the
    /// <c>X-Skein-Internal-Secret</c> header redacted from HttpClient logging,
    /// and NO <see cref="InternalApiHandler"/> — that handler forwards the
    /// identity of an ambient <see cref="HttpContext"/>, and a service call
    /// must carry no user identity (the client sets only the service secret).
    /// </summary>
    /// <remarks>
    /// <see cref="HttpClient.Timeout"/> is infinite on purpose: the call
    /// budget <see cref="SkeinServiceApiClient.CallBudget"/> is enforced by the
    /// client itself and covers every attempt, the retry pauses and the
    /// response body read — which <see cref="HttpClient.Timeout"/> does not
    /// cover under <see cref="HttpCompletionOption.ResponseHeadersRead"/>.
    /// Registers <see cref="TimeProvider.System"/> unless a
    /// <see cref="TimeProvider"/> is already registered.
    /// </remarks>
    /// <param name="services">Service collection.</param>
    /// <param name="skeinApiUrl">skein-api base URL.</param>
    /// <returns>The client builder, for further configuration.</returns>
    public static IHttpClientBuilder AddSkeinServiceApiClient(this IServiceCollection services, string skeinApiUrl)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrEmpty(skeinApiUrl);

        services.TryAddSingleton(TimeProvider.System);

        return services.AddHttpClient<SkeinServiceApiClient>(client =>
            {
                client.BaseAddress = new Uri(skeinApiUrl);
                client.Timeout = Timeout.InfiniteTimeSpan;
            })
            .RedactLoggedHeaders([SkeinHeaders.InternalSecret])
            .AddPolicyHandler(SkeinApiRetryPolicy.Create());
    }
}
