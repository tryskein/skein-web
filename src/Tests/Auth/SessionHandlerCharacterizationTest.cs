using System.Collections.Concurrent;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// Characterization of the stock ASP.NET Core cookie handler against the session mechanism
/// the plan builds on (spike, questions Q1 and Q3–Q6). The handler is the real
/// <see cref="CookieAuthenticationHandler"/> running in Kestrel on a loopback port, so
/// <c>OnStarting</c> runs exactly as in production; only the
/// ticket store and the request-level decision (<see cref="SpikeRequestState"/>) are in-memory
/// stand-ins for the product pieces that do not exist yet. The expectations come from the
/// plan (new key on issue, deletion of the cookie without the store, sign-out removing the row),
/// not from what the stand returned when the test was written. The product no longer relies on
/// the handler's sliding renewal: that no ticket is written without a sign-in, and that a failed
/// renewal sets no cookie, is checked on the product's own pipeline.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SessionHandlerCharacterizationTest(ITestOutputHelper output)
{
    private const string Main = CookieAuthenticationDefaults.AuthenticationScheme;
    private const string Issue = "Skein.Issue";
    private const string Fake = "Fake.Remote";

    // The claim the stock handler puts into the cookie when a server-side store is used.
    // It is internal to the handler; the spike reads it to learn which key a cookie carries.
    private const string SessionIdClaim = "Microsoft.AspNetCore.Authentication.Cookies-SessionId";

    private const string DefaultCookieName = "__Host-skein.sid";

    // ---- Versions ---------------------------------------------------------------------------

    [Fact]
    public void Versions_AreRecordedAndTheFrameworkMajorIsTen()
    {
        var cookies = typeof(CookieAuthenticationHandler).Assembly;
        var cookiesVersion = cookies.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        var aspNetCore = typeof(WebApplication).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;

        output.WriteLine($"FrameworkDescription = {RuntimeInformation.FrameworkDescription}");
        output.WriteLine($"Environment.Version = {Environment.Version}");
        output.WriteLine($"{cookies.GetName().Name} informational version = {cookiesVersion}");
        output.WriteLine($"Microsoft.AspNetCore (WebApplication assembly) informational version = {aspNetCore}");

        Assert.Equal(10, Environment.Version.Major);
        Assert.NotNull(cookiesVersion);
        Assert.StartsWith("10.", cookiesVersion);
    }

    // ---- Q1: the Issue scheme gives a new key while the old one is live ---------------------

    [Fact]
    public async Task Q1_IssueScheme_IssuesANewKeyWhileTheOldKeyIsLive()
    {
        await using var stand = await Stand.StartAsync();
        var (cookie, oldKey) = await stand.SeedAsync();
        stand.Store.ResetCounters();

        var reply = await stand.GetAsync($"/signin/{Issue}", cookie);

        var set = Assert.Single(reply.SessionCookies(stand.CookieName));
        var newKey = stand.KeyOf(set);
        Assert.NotEqual(oldKey, newKey);
        Assert.Equal(1, stand.Store.StoreCalls);
        Assert.DoesNotContain(oldKey, stand.Store.RenewedKeys);
        Assert.True(stand.Store.Rows.ContainsKey(newKey));
    }

    [Fact]
    public async Task Q1_Control_MainSchemeReadsTheIncomingCookieAndReusesTheKey()
    {
        await using var stand = await Stand.StartAsync();
        var (cookie, oldKey) = await stand.SeedAsync();
        stand.Store.ResetCounters();

        var reply = await stand.GetAsync($"/signin/{Main}", cookie);

        var set = Assert.Single(reply.SessionCookies(stand.CookieName));
        Assert.Equal(oldKey, stand.KeyOf(set));
        Assert.Equal(0, stand.Store.StoreCalls);
        Assert.Contains(oldKey, stand.Store.RenewedKeys);
    }

    [Fact]
    public async Task Q1_SecondIssueInOneRequest_ReusesTheKeyOfTheFirstOne()
    {
        await using var stand = await Stand.StartAsync();
        var (cookie, oldKey) = await stand.SeedAsync();
        stand.Store.ResetCounters();

        var reply = await stand.GetAsync($"/signin-twice/{Issue}", cookie);

        var keys = reply.SessionCookies(stand.CookieName).Select(stand.KeyOf).Distinct().ToList();
        output.WriteLine($"Set-Cookie of the session in the response: {reply.SessionCookies(stand.CookieName).Count}");
        var newKey = Assert.Single(keys);
        Assert.NotEqual(oldKey, newKey);
        Assert.Equal(1, stand.Store.StoreCalls);
    }

    // ---- Q3: a new purpose rejects cookies of the previous one ------------------------------

    [Theory]
    [InlineData("__Host-skein.sid")]
    [InlineData("skein.sid")]
    public async Task Q3_CookieOfThePreviousPurpose_IsRejectedUnderEitherName(string cookieName)
    {
        await using var stand = await Stand.StartAsync(cookieName);
        var (_, key) = await stand.SeedAsync();
        var sessionTicket = Stand.SessionTicket(key);

        var oldFormat = new TicketDataFormat(stand.Provider.CreateProtector(
            "Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware", Main, "v2"));
        var oldCookie = $"{cookieName}={Uri.EscapeDataString(oldFormat.Protect(sessionTicket))}";
        var newCookie = $"{cookieName}={Uri.EscapeDataString(stand.Format.Protect(sessionTicket))}";

        var withOld = await stand.GetAsync("/me", oldCookie);
        var withNew = await stand.GetAsync("/me", newCookie);

        Assert.Equal("auth=False", withOld.Body);
        Assert.Equal("auth=True", withNew.Body); // control: the same row, the current purpose
    }

    // ---- Q4: deletion of the cookie and sign-out ---------------------------------------------

    [Fact]
    public async Task Q4_DeletingTheCookieThroughTheMainManager_NeedsNoStoreCall()
    {
        await using var stand = await Stand.StartAsync();
        stand.Store.ResetCounters();

        var reply = await stand.GetAsync("/delete-cookie", cookie: null);

        var deleted = Assert.Single(reply.Cookies, c => c.Name == stand.CookieName);
        Assert.True(deleted.IsDeletion);
        Assert.Equal(0, stand.Store.TotalCalls);
    }

    [Fact]
    public async Task Q4_Control_SignOutOfMain_RemovesTheServerRow()
    {
        await using var stand = await Stand.StartAsync();
        var (cookie, key) = await stand.SeedAsync();
        stand.Store.ResetCounters();

        var reply = await stand.GetAsync("/signout", cookie);

        Assert.Contains(reply.Cookies, c => c.Name == stand.CookieName && c.IsDeletion);
        Assert.False(stand.Store.Rows.ContainsKey(key));
        Assert.True(stand.Store.RemoveCalls >= 1);
    }

    // ---- Q5: a remote (OIDC-shaped) callback ------------------------------------------------

    [Theory]
    [InlineData("/after", "/after")]
    [InlineData("", "/")]
    public async Task Q5_Callback_IssuesTheSessionAndRedirects(string returnUri, string expectedLocation)
    {
        await using var stand = await Stand.StartAsync();
        var (callbackPath, challengeCookies) = await stand.ChallengeAsync(returnUri);

        var reply = await stand.GetAsync(callbackPath, challengeCookies);

        Assert.Equal(HttpStatusCode.Redirect, reply.Status);
        Assert.Equal(expectedLocation, reply.Location);
        var set = Assert.Single(reply.SessionCookies(stand.CookieName));
        Assert.True(stand.Store.Rows.ContainsKey(stand.KeyOf(set)));
        Assert.Contains(reply.Cookies, c => c.Name.StartsWith(".AspNetCore.Correlation.", StringComparison.Ordinal) && c.IsDeletion);
        Assert.Contains(reply.Cookies, c => c.Name == Stand.NonceCookie && c.IsDeletion);
    }

    [Fact]
    public async Task Q5_Callback_WhenTheSessionCannotBeIssued_AnswersTextBadGatewayWithoutASessionCookie()
    {
        await using var stand = await Stand.StartAsync();
        var (callbackPath, challengeCookies) = await stand.ChallengeAsync("/after");
        stand.Store.FailStore = true;

        var reply = await stand.GetAsync(callbackPath, challengeCookies);

        Assert.Equal(HttpStatusCode.BadGateway, reply.Status);
        Assert.Equal("bad gateway", reply.Body);
        Assert.Empty(reply.SessionCookies(stand.CookieName));
        Assert.Contains(reply.Cookies, c => c.Name.StartsWith(".AspNetCore.Correlation.", StringComparison.Ordinal) && c.IsDeletion);
        Assert.Empty(stand.Errors);
    }

    [Fact]
    public async Task Q5_RemoteSignOut_WithSignOutSchemeMain_RemovesTheServerRow()
    {
        await using var stand = await Stand.StartAsync();
        var (cookie, key) = await stand.SeedAsync();

        var reply = await stand.GetAsync("/remote-signout", cookie);

        Assert.Equal(HttpStatusCode.OK, reply.Status);
        Assert.False(stand.Store.Rows.ContainsKey(key));
        Assert.Contains(reply.Cookies, c => c.Name == stand.CookieName && c.IsDeletion);
    }

    // ---- Q6: a technical read failure escapes the authentication middleware ------------------

    [Fact]
    public async Task Q6_TechnicalFailureOfRetrieve_EscapesTheAuthenticationMiddleware()
    {
        await using var stand = await Stand.StartAsync();
        var (cookie, _) = await stand.SeedAsync();
        stand.Store.FailRetrieve = true;

        var reply = await stand.TryGetAsync("/me", cookie);

        Assert.Equal(HttpStatusCode.InternalServerError, reply.Status);
        Assert.Contains(stand.Errors, e => e.ChainContains("redis down (retrieve)"));
    }

    // =========================================================================================
    // Stand
    // =========================================================================================

    public enum RenewOutcome { Written, KeyAbsent, CasExhausted, OwnerMismatch, Suppressed, TechnicalFailure }

    public enum RenewFailure { None, CaughtInStore, Unhandled }

    /// <summary>The request-level decision both schemes read: stand-in for the product's request state.</summary>
    public sealed class SpikeRequestState
    {
        public bool SuppressMainWrite { get; set; }
        public RenewOutcome? RenewOutcome { get; set; }
    }

    private static SpikeRequestState StateOf(HttpContext ctx)
    {
        const string key = "spike.request-state";
        if (ctx.Items[key] is not SpikeRequestState state)
        {
            state = new SpikeRequestState();
            ctx.Items[key] = state;
        }
        return state;
    }

    /// <summary>In-memory <see cref="ITicketStore"/> with the call counters and failure switches the questions need.</summary>
    public sealed class SpikeTicketStore : ITicketStore
    {
        public ConcurrentDictionary<string, AuthenticationTicket> Rows { get; } = new();
        public List<string> RenewedKeys { get; } = [];
        public int StoreCalls { get; private set; }
        public int RenewCalls { get; private set; }
        public int RetrieveCalls { get; private set; }
        public int RemoveCalls { get; private set; }
        public int WrittenRenewals { get; private set; }
        public int ContextOverloadCalls { get; private set; }
        public int TotalCalls => StoreCalls + RenewCalls + RetrieveCalls + RemoveCalls;

        public bool FailStore { get; set; }
        public bool FailRetrieve { get; set; }
        public RenewFailure RenewFailure { get; set; }
        public RenewOutcome? SimulatedRenewOutcome { get; set; }

        public void ResetCounters()
        {
            StoreCalls = RenewCalls = RetrieveCalls = RemoveCalls = WrittenRenewals = ContextOverloadCalls = 0;
            RenewedKeys.Clear();
        }

        public void RevokeRow(string key) => Rows.TryRemove(key, out _);

        public Task<string> StoreAsync(AuthenticationTicket ticket) => StoreCore(ticket);

        public Task<string> StoreAsync(AuthenticationTicket ticket, HttpContext httpContext, CancellationToken cancellationToken)
        {
            ContextOverloadCalls++;
            return StoreCore(ticket);
        }

        private Task<string> StoreCore(AuthenticationTicket ticket)
        {
            StoreCalls++;
            if (FailStore)
            {
                throw new InvalidOperationException("redis down (store)");
            }
            var key = Guid.NewGuid().ToString("N");
            Rows[key] = ticket;
            return Task.FromResult(key);
        }

        public Task RenewAsync(string key, AuthenticationTicket ticket) => RenewCore(key, ticket, null);

        public Task RenewAsync(string key, AuthenticationTicket ticket, HttpContext httpContext, CancellationToken cancellationToken)
        {
            ContextOverloadCalls++;
            return RenewCore(key, ticket, StateOf(httpContext));
        }

        private Task RenewCore(string key, AuthenticationTicket ticket, SpikeRequestState? state)
        {
            RenewCalls++;
            RenewedKeys.Add(key);
            if (RenewFailure == RenewFailure.Unhandled)
            {
                throw new InvalidOperationException("redis down (renew)");
            }
            if (state is { SuppressMainWrite: true })
            {
                state.RenewOutcome = Spike_RenewOutcome.Suppressed;
                return Task.CompletedTask;
            }
            if (RenewFailure == RenewFailure.CaughtInStore)
            {
                try
                {
                    throw new InvalidOperationException("redis down (renew, caught)");
                }
                catch (InvalidOperationException)
                {
                    if (state is not null)
                    {
                        state.RenewOutcome = Spike_RenewOutcome.TechnicalFailure;
                    }
                    return Task.CompletedTask;
                }
            }
            if (SimulatedRenewOutcome is { } simulated)
            {
                if (state is not null)
                {
                    state.RenewOutcome = simulated;
                }
                return Task.CompletedTask;
            }
            if (!Rows.ContainsKey(key))
            {
                if (state is not null)
                {
                    state.RenewOutcome = Spike_RenewOutcome.KeyAbsent;
                }
                return Task.CompletedTask;
            }
            Rows[key] = ticket;
            WrittenRenewals++;
            if (state is not null)
            {
                state.RenewOutcome = Spike_RenewOutcome.Written;
            }
            return Task.CompletedTask;
        }

        public Task<AuthenticationTicket?> RetrieveAsync(string key) => RetrieveCore(key);

        public Task<AuthenticationTicket?> RetrieveAsync(string key, HttpContext httpContext, CancellationToken cancellationToken)
        {
            ContextOverloadCalls++;
            return RetrieveCore(key);
        }

        private Task<AuthenticationTicket?> RetrieveCore(string key)
        {
            RetrieveCalls++;
            if (FailRetrieve)
            {
                throw new InvalidOperationException("redis down (retrieve)");
            }
            return Task.FromResult(Rows.TryGetValue(key, out var ticket) ? ticket : null);
        }

        public Task RemoveAsync(string key) => RemoveCore(key);

        public Task RemoveAsync(string key, HttpContext httpContext, CancellationToken cancellationToken)
        {
            ContextOverloadCalls++;
            return RemoveCore(key);
        }

        private Task RemoveCore(string key)
        {
            RemoveCalls++;
            Rows.TryRemove(key, out _);
            return Task.CompletedTask;
        }
    }

    // Spike_RenewOutcome only exists to keep the store's body readable next to the property of the same name.
    private static class Spike_RenewOutcome
    {
        public const RenewOutcome Written = RenewOutcome.Written;
        public const RenewOutcome KeyAbsent = RenewOutcome.KeyAbsent;
        public const RenewOutcome Suppressed = RenewOutcome.Suppressed;
        public const RenewOutcome TechnicalFailure = RenewOutcome.TechnicalFailure;
    }

    /// <summary>Cookie manager of Main: reads normally, writes unless the request decision forbids it.</summary>
    private sealed class MainCookieManager(ICookieManager inner) : ICookieManager
    {
        public string? GetRequestCookie(HttpContext context, string key) => inner.GetRequestCookie(context, key);

        public void AppendResponseCookie(HttpContext context, string key, string? value, CookieOptions options)
        {
            var state = StateOf(context);
            if (state.SuppressMainWrite || (state.RenewOutcome is { } outcome && outcome != RenewOutcome.Written))
            {
                return;
            }
            inner.AppendResponseCookie(context, key, value, options);
        }

        public void DeleteCookie(HttpContext context, string key, CookieOptions options) =>
            inner.DeleteCookie(context, key, options);
    }

    /// <summary>Cookie manager of the Issue scheme: never reads the incoming cookie.</summary>
    private sealed class IssueCookieManager(ICookieManager inner) : ICookieManager
    {
        public string? GetRequestCookie(HttpContext context, string key) => null;

        public void AppendResponseCookie(HttpContext context, string key, string? value, CookieOptions options) =>
            inner.AppendResponseCookie(context, key, value, options);

        public void DeleteCookie(HttpContext context, string key, CookieOptions options) =>
            inner.DeleteCookie(context, key, options);
    }

    private sealed class FakeRemoteOptions : RemoteAuthenticationOptions
    {
        public string? SignOutScheme { get; set; }

        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; } = null!;

        public FakeRemoteOptions()
        {
            CallbackPath = "/signin-fake";
        }
    }

    /// <summary>
    /// A remote handler shaped like the OpenID Connect one for the parts the question is about:
    /// correlation cookie, a second (nonce) cookie deleted on the callback, the base ticket-received
    /// pipeline and a sign-out that forwards to <see cref="FakeRemoteOptions.SignOutScheme"/>.
    /// </summary>
    private sealed class FakeRemoteHandler(
        IOptionsMonitor<FakeRemoteOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : RemoteAuthenticationHandler<FakeRemoteOptions>(options, logger, encoder), IAuthenticationSignOutHandler
    {
        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            GenerateCorrelationId(properties);
            Response.Cookies.Append(Stand.NonceCookie, "nonce");
            var state = Options.StateDataFormat.Protect(properties);
            Response.Redirect($"{Options.CallbackPath}?state={Uri.EscapeDataString(state)}");
            return Task.CompletedTask;
        }

        protected override Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            var properties = Options.StateDataFormat.Unprotect(Request.Query["state"]);
            if (properties is null)
            {
                return Task.FromResult(HandleRequestResult.Fail("state is invalid"));
            }
            if (!ValidateCorrelationId(properties))
            {
                return Task.FromResult(HandleRequestResult.Fail("correlation failed", properties));
            }
            Response.Cookies.Delete(Stand.NonceCookie);
            var principal = Stand.PrincipalOf("remote-user");
            return Task.FromResult(HandleRequestResult.Success(new AuthenticationTicket(principal, properties, Scheme.Name)));
        }

        public Task SignOutAsync(AuthenticationProperties? properties) =>
            Context.SignOutAsync(Options.SignOutScheme!);
    }

    private sealed record SetCookie(string Name, string Value, string Raw)
    {
        public bool IsDeletion => SessionPipelineHost.SetCookie.IsDeletionHeader(Raw);

        public static SetCookie Parse(string raw)
        {
            var pair = raw.Split(';', 2)[0];
            var eq = pair.IndexOf('=');
            return new SetCookie(pair[..eq], Uri.UnescapeDataString(pair[(eq + 1)..]), raw);
        }
    }

    private sealed record Reply(HttpStatusCode Status, string Body, string? Location, IReadOnlyList<SetCookie> Cookies)
    {
        public IReadOnlyList<SetCookie> SessionCookies(string name) =>
            Cookies.Where(c => c.Name == name && !c.IsDeletion).ToList();
    }

    private sealed class ErrorCapture(List<Exception> errors) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => new CaptureLogger(errors);

        public void Dispose()
        {
        }

        private sealed class CaptureLogger(List<Exception> errors) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Error;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                if (logLevel >= LogLevel.Error)
                {
                    lock (errors)
                    {
                        errors.Add(exception ?? new InvalidOperationException(formatter(state, null)));
                    }
                }
            }
        }
    }

    private sealed class Stand : IAsyncDisposable
    {
        public const string NonceCookie = ".spike.nonce";

        private readonly WebApplication _app;
        private readonly HttpClient _client;
        private readonly List<Exception> _errors;

        private Stand(WebApplication app, HttpClient client, List<Exception> errors, string cookieName,
            IDataProtectionProvider provider, TicketDataFormat format, SpikeTicketStore store, FakeTimeProvider time)
        {
            _app = app;
            _client = client;
            _errors = errors;
            CookieName = cookieName;
            Provider = provider;
            Format = format;
            Store = store;
            Time = time;
        }

        public string CookieName { get; }
        public IDataProtectionProvider Provider { get; }
        public TicketDataFormat Format { get; }
        public SpikeTicketStore Store { get; }
        public FakeTimeProvider Time { get; }

        public IReadOnlyList<Exception> Errors
        {
            get
            {
                lock (_errors)
                {
                    return _errors.ToList();
                }
            }
        }

        public static ClaimsPrincipal PrincipalOf(string name) =>
            new(new ClaimsIdentity([new Claim(ClaimTypes.Name, name)], "spike", ClaimTypes.Name, ClaimTypes.Role));

        public static AuthenticationTicket SessionTicket(string key) =>
            new(new ClaimsPrincipal(new ClaimsIdentity([new Claim(SessionIdClaim, key)], Main)), Main);

        public static async Task<Stand> StartAsync(string cookieName = DefaultCookieName)
        {
            var errors = new List<Exception>();
            var time = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
            var store = new SpikeTicketStore();
            var provider = new EphemeralDataProtectionProvider();
            var format = new TicketDataFormat(provider.CreateProtector("Skein.Session.Cookie", "v3"));

            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = Environments.Production });
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            builder.Logging.ClearProviders();
            builder.Logging.AddProvider(new ErrorCapture(errors));

            void ConfigureCookie(CookieAuthenticationOptions o, Func<ICookieManager, ICookieManager> manager)
            {
                o.Cookie.Name = cookieName;
                o.Cookie.Path = "/";
                o.Cookie.HttpOnly = true;
                o.Cookie.SameSite = SameSiteMode.Lax;
                o.ExpireTimeSpan = TimeSpan.FromHours(24);
                o.SlidingExpiration = true;
                o.SessionStore = store;
                o.TicketDataFormat = format;
                o.TimeProvider = time;
                o.CookieManager = manager(new ChunkingCookieManager());
            }

            builder.Services
                .AddAuthentication(Main)
                .AddCookie(Main, o => ConfigureCookie(o, m => new MainCookieManager(m)))
                .AddCookie(Issue, o => ConfigureCookie(o, m => new IssueCookieManager(m)))
                .AddRemoteScheme<FakeRemoteOptions, FakeRemoteHandler>(Fake, Fake, o =>
                {
                    o.SignInScheme = Issue;
                    o.SignOutScheme = Main;
                    o.TimeProvider = time;
                    o.StateDataFormat = new PropertiesDataFormat(provider.CreateProtector("spike.state"));
                    o.Events = new RemoteAuthenticationEvents();
                    o.Events.OnTicketReceived = async ctx =>
                    {
                        ctx.HandleResponse();
                        try
                        {
                            await ctx.HttpContext.SignInAsync(Issue, ctx.Principal!, ctx.Properties);
                            ctx.Response.Redirect(string.IsNullOrEmpty(ctx.ReturnUri) ? "/" : ctx.ReturnUri);
                        }
                        catch (InvalidOperationException)
                        {
                            ctx.Response.StatusCode = StatusCodes.Status502BadGateway;
                            ctx.Response.ContentType = "text/plain";
                            await ctx.Response.WriteAsync("bad gateway");
                        }
                    };
                });
            builder.Services.AddAuthorization();

            var app = builder.Build();
            app.UseAuthentication();

            app.MapGet("/me", (HttpContext ctx) => Results.Text($"auth={ctx.User.Identity?.IsAuthenticated == true}"));

            app.MapGet("/me-suppressed", (HttpContext ctx) =>
            {
                StateOf(ctx).SuppressMainWrite = true;
                return Results.Text($"auth={ctx.User.Identity?.IsAuthenticated == true}");
            });

            app.MapGet("/signin/{scheme}", async (HttpContext ctx, string scheme) =>
            {
                await ctx.SignInAsync(scheme, PrincipalOf("alice"));
                return Results.Text("signed-in");
            });

            app.MapGet("/signin-twice/{scheme}", async (HttpContext ctx, string scheme) =>
            {
                await ctx.SignInAsync(scheme, PrincipalOf("alice"));
                await ctx.SignInAsync(scheme, PrincipalOf("bob"));
                return Results.Text("signed-in-twice");
            });

            app.MapGet("/rotate", async (HttpContext ctx, bool revoke, bool suppress) =>
            {
                if (suppress)
                {
                    StateOf(ctx).SuppressMainWrite = true;
                }
                if (revoke)
                {
                    var incoming = format.Unprotect(Uri.UnescapeDataString(
                        ctx.Request.Cookies[cookieName] ?? string.Empty))?.Principal.FindFirst(SessionIdClaim)?.Value;
                    if (incoming is not null)
                    {
                        store.RevokeRow(incoming);
                    }
                }
                await ctx.SignInAsync(Issue, PrincipalOf("alice"));
                return Results.Text("rotated");
            });

            app.MapGet("/delete-cookie", (HttpContext ctx, IOptionsMonitor<CookieAuthenticationOptions> options) =>
            {
                var main = options.Get(Main);
                main.CookieManager!.DeleteCookie(ctx, cookieName, main.Cookie.Build(ctx));
                return Results.Text("deleted");
            });

            app.MapGet("/signout", async (HttpContext ctx) =>
            {
                await ctx.SignOutAsync(Main);
                return Results.Text("signed-out");
            });

            app.MapGet("/remote-signout", async (HttpContext ctx) =>
            {
                await ctx.SignOutAsync(Fake);
                return Results.Text("remote-signed-out");
            });

            app.MapGet("/challenge", async (HttpContext ctx, string returnUri) =>
            {
                await ctx.ChallengeAsync(Fake, new AuthenticationProperties { RedirectUri = returnUri });
            });

            await app.StartAsync();
            var address = app.Urls.First();
            var client = new HttpClient(new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false })
            {
                BaseAddress = new Uri(address),
            };
            return new Stand(app, client, errors, cookieName, provider, format, store, time);
        }

        public string KeyOf(SetCookie cookie) =>
            Format.Unprotect(cookie.Value)?.Principal.FindFirst(SessionIdClaim)?.Value
            ?? throw new InvalidOperationException("the cookie carries no session key");

        /// <summary>Signs in through the Issue scheme without a cookie and returns the cookie header and the key.</summary>
        public async Task<(string Cookie, string Key)> SeedAsync()
        {
            var reply = await GetAsync($"/signin/{Issue}", cookie: null);
            var set = reply.SessionCookies(CookieName).SingleOrDefault()
                ?? throw new InvalidOperationException(
                    $"seed: status {reply.Status}, body '{reply.Body}', Set-Cookie [{string.Join(" | ", reply.Cookies.Select(c => c.Raw))}], " +
                    $"errors [{string.Join(" | ", Errors.Select(e => e.ToString()))}]");
            return ($"{CookieName}={Uri.EscapeDataString(set.Value)}", KeyOf(set));
        }

        /// <summary>Runs the challenge and returns the callback path and the cookies the browser would send there.</summary>
        public async Task<(string CallbackPath, string Cookies)> ChallengeAsync(string returnUri)
        {
            var reply = await GetAsync($"/challenge?returnUri={Uri.EscapeDataString(returnUri)}", cookie: null);
            var cookies = string.Join("; ", reply.Cookies
                .Where(c => !c.IsDeletion)
                .Select(c => $"{c.Name}={Uri.EscapeDataString(c.Value)}"));
            return (reply.Location!, cookies);
        }

        public async Task<Reply> GetAsync(string path, string? cookie)
        {
            var reply = await TryGetAsync(path, cookie);
            return reply;
        }

        public async Task<Reply> TryGetAsync(string path, string? cookie)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, path);
            if (cookie is not null)
            {
                request.Headers.TryAddWithoutValidation("Cookie", cookie);
            }
            using var response = await _client.SendAsync(request);
            var body = await response.Content.ReadAsStringAsync();
            var cookies = response.Headers.TryGetValues("Set-Cookie", out var values)
                ? values.Select(SetCookie.Parse).ToList()
                : [];
            return new Reply(response.StatusCode, body, response.Headers.Location?.OriginalString, cookies);
        }

        public async ValueTask DisposeAsync()
        {
            _client.Dispose();
            await _app.StopAsync();
            await _app.DisposeAsync();
        }
    }
}

internal static class ExceptionChainExtensions
{
    public static bool ChainContains(this Exception exception, string text)
    {
        for (var e = exception; e is not null; e = e.InnerException)
        {
            if (e.Message.Contains(text, StringComparison.Ordinal))
            {
                return true;
            }
        }
        return false;
    }
}
