using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SkeinWeb.Auth;
using SkeinWeb.Middleware;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// Regression (critical): the default request logging of
/// <see cref="IHttpClientFactory"/> writes the full request URI, and the URIs
/// of the public account routes and of proxied <c>/api/v1</c> calls carry
/// secrets — reset, confirmation and invitation tokens in the path, the email
/// in the username-suggestions query (a log must not carry secrets). With
/// the production registrations and every log level enabled, no log entry may
/// contain them.
/// </summary>
public class HttpClientSecretLoggingTest
{
    private const string Token = "tok-aaaaaaaaaaaa";
    private const string Email = "secret.person@client.io";

    /// <summary>Captures every formatted message and its structured values, at every level.</summary>
    private sealed class CaptureLog : ILoggerProvider, ILogger
    {
        public List<string> Entries { get; } = [];
        public ILogger CreateLogger(string categoryName) => this;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var values = state is IEnumerable<KeyValuePair<string, object?>> pairs
                ? string.Join(" ", pairs.Select(p => $"{p.Key}={p.Value}"))
                : "";
            Entries.Add($"{formatter(state, exception)} {values}");
        }

        public void Dispose() { }
    }

    private sealed class Ok : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));
    }

    private static (ServiceProvider Provider, CaptureLog Log) Compose(Action<IServiceCollection> register)
    {
        var log = new CaptureLog();
        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.Trace).AddProvider(log));
        services.Configure<SkeinApiOptions>(o =>
        {
            o.Url = "http://skein-api.test";
            o.InternalSecret = "svc-secret";
        });
        register(services);
        return (services.BuildServiceProvider(), log);
    }

    [Fact]
    public async Task PublicAccountRoutes_TokensAndEmailNeverReachTheLog()
    {
        var (provider, log) = Compose(services =>
            SkeinAccountsApiClient.Register(services, "http://skein-api.test/")
                .ConfigurePrimaryHttpMessageHandler(() => new Ok()));
        await using var _ = provider;
        var client = provider.GetRequiredService<SkeinAccountsApiClient>();

        await client.ConfirmEmailAsync(Token, clientIp: null, CancellationToken.None);
        await client.InvitationPreviewAsync(Token, clientIp: null, CancellationToken.None);
        await client.PasswordResetCompleteAsync(Token, new PasswordResetCompleteRequest("pw"), clientIp: null, CancellationToken.None);
        await client.UsernameSuggestionsAsync(Email, clientIp: null, CancellationToken.None);

        Assert.DoesNotContain(log.Entries, e => e.Contains(Token, StringComparison.Ordinal));
        Assert.DoesNotContain(log.Entries, e =>
            e.Contains(Email, StringComparison.OrdinalIgnoreCase) ||
            e.Contains(Uri.EscapeDataString(Email), StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ProxyClient_TokenInAProxiedPathNeverReachesTheLog()
    {
        var (provider, log) = Compose(services =>
        {
            services.AddSingleton<IHttpContextAccessor>(new HttpContextAccessor { HttpContext = new DefaultHttpContext() });
            services.AddTransient<InternalApiHandler>();
            ApiProxyMiddleware.AddProxyHttpClient(services, "http://skein-api.test/")
                .ConfigurePrimaryHttpMessageHandler(() => new Ok());
        });
        await using var _ = provider;
        var client = provider.GetRequiredService<IHttpClientFactory>().CreateClient(ApiProxyMiddleware.ProxyClientName);

        await client.GetAsync($"/api/v1/invitations/{Token}");

        Assert.DoesNotContain(log.Entries, e => e.Contains(Token, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Control_DefaultFactoryLogging_WouldWriteTheToken()
    {
        // Positive control of the capture above: a client registered with the
        // factory's default handlers does log the URI, token included — so
        // the two assertions above can fail.
        var (provider, log) = Compose(services =>
            services.AddHttpClient("control").ConfigurePrimaryHttpMessageHandler(() => new Ok()));
        await using var _ = provider;

        await provider.GetRequiredService<IHttpClientFactory>().CreateClient("control")
            .GetAsync($"http://skein-api.test/api/v1/invitations/{Token}");

        Assert.Contains(log.Entries, e => e.Contains(Token, StringComparison.Ordinal));
    }
}
