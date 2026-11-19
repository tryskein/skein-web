using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using SkeinWeb.Auth;
using StackExchange.Redis;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// The session cookie policy (US-4, US-5): the name and Secure come from the setting and the
/// environment alone, and both cookie schemes carry them. Expectations follow the spec table,
/// not the implementation.
/// </summary>
public class SessionCookiePolicyTest
{
    private static SessionCookiePolicy Resolve(string environment, string? setting)
    {
        var values = new Dictionary<string, string?>();
        if (setting is not null)
        {
            values[SessionCookiePolicy.SettingName] = setting;
        }
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();
        var host = new Mock<IHostEnvironment>();
        host.SetupGet(h => h.EnvironmentName).Returns(environment);
        return SessionCookiePolicy.Resolve(configuration, host.Object);
    }

    [Theory]
    [InlineData("Development", null)]
    [InlineData("Development", "false")]
    [InlineData("Production", null)]
    [InlineData("Production", "false")]
    [InlineData("Staging", null)]
    [InlineData("", null)]
    public void NormalMode_IsHostPrefixedAndSecure(string environment, string? setting)
    {
        var policy = Resolve(environment, setting);

        Assert.Equal("__Host-skein.sid", policy.CookieName);
        Assert.True(policy.Secure);
    }

    [Fact]
    public void Development_WithTheSettingOn_IsPlainNameWithoutSecure()
    {
        var policy = Resolve("Development", "true");

        Assert.Equal("skein.sid", policy.CookieName);
        Assert.False(policy.Secure);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("")]
    public void SettingOnOutsideDevelopment_IsRefusedByName(string environment)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => Resolve(environment, "true"));

        Assert.Contains("SKEIN_ALLOW_INSECURE_HTTP", ex.Message);
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Production")]
    public void NonBooleanSetting_IsABinderError(string environment)
    {
        Assert.Throws<InvalidOperationException>(() => Resolve(environment, "maybe"));
    }

    [Theory]
    [InlineData(false, "__Host-skein.sid", CookieSecurePolicy.Always)]
    [InlineData(true, "skein.sid", CookieSecurePolicy.None)]
    public void BothSchemes_CarryTheNameAndTheAttributesOfThePolicy(bool insecure, string name, CookieSecurePolicy secure)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection();
        services.AddSingleton(new SessionCookiePolicy(insecure));
        services.AddSingleton(new RedisTicketStore(new Mock<IConnectionMultiplexer>().Object, NullLogger<RedisTicketStore>.Instance));
        services.AddSingleton(new SessionTimeouts(SessionTimeouts.DefaultIdleTimeoutHours, SessionTimeouts.DefaultAbsoluteTimeoutHours));
        services.AddSkeinAuthentication(WebAuthMode.FromApi("local", null), new SsoOptions());
        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>();

        foreach (var scheme in new[] { SessionSchemes.Main, SessionSchemes.Issue })
        {
            var o = options.Get(scheme);
            Assert.Equal(name, o.Cookie.Name);
            Assert.Equal(secure, o.Cookie.SecurePolicy);
            Assert.True(o.Cookie.HttpOnly);
            Assert.Equal(SameSiteMode.Lax, o.Cookie.SameSite);
            Assert.Equal("/", o.Cookie.Path);
            Assert.Null(o.Cookie.Domain);
            Assert.Equal(TimeSpan.FromHours(24), o.ExpireTimeSpan);
        }
    }
}
