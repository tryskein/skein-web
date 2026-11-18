namespace SkeinWeb.Auth;

/// <summary>
/// The session cookie's name and attributes for this process, resolved once at
/// startup from <c>SKEIN_ALLOW_INSECURE_HTTP</c> and the hosting environment.
/// This type is the only place the cookie name literals live; every other part of
/// the service reads <see cref="CookieName"/> instead of repeating a string.
/// </summary>
/// <remarks>
/// Two shapes exist and nothing else:
/// <list type="bullet">
///   <item><description>Normal mode: <c>__Host-skein.sid</c>, <c>Secure</c>, <c>HttpOnly</c>,
///   <c>Path=/</c>, no <c>Domain</c>, <c>SameSite=Lax</c>. The attributes do not depend on the
///   request scheme, on <c>X-Forwarded-Proto</c> or on proxy trust.</description></item>
///   <item><description>Insecure-http mode (Development only, opted in by
///   <c>SKEIN_ALLOW_INSECURE_HTTP=true</c>): <c>skein.sid</c> with the same attributes
///   except <c>Secure</c>, whatever the scheme or <c>X-Forwarded-Proto</c>.</description></item>
/// </list>
/// A self-signed HTTPS certificate does not enable the insecure mode.
/// </remarks>
/// <param name="AllowInsecureHttp">True only in Development with the setting switched on.</param>
public sealed record SessionCookiePolicy(bool AllowInsecureHttp)
{
    /// <summary>Name of the setting that switches the insecure-http mode on.</summary>
    public const string SettingName = "SKEIN_ALLOW_INSECURE_HTTP";

    /// <summary>Cookie name in the normal mode (the <c>__Host-</c> prefix needs <c>Secure</c>, <c>Path=/</c> and no <c>Domain</c>).</summary>
    public const string SecureCookieName = "__Host-skein.sid";

    /// <summary>Cookie name in the insecure-http mode.</summary>
    public const string InsecureCookieName = "skein.sid";

    /// <summary>Name of the session cookie for this process.</summary>
    public string CookieName => AllowInsecureHttp ? InsecureCookieName : SecureCookieName;

    /// <summary>Whether the session cookie carries <c>Secure</c>; false only in the insecure-http mode.</summary>
    public bool Secure => !AllowInsecureHttp;

    /// <summary>
    /// Reads <c>SKEIN_ALLOW_INSECURE_HTTP</c> (boolean, parsed by the configuration binder;
    /// not set means off) and returns the policy for this process.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The setting is <c>true</c> outside the Development environment. The message names the
    /// setting. Call this first at startup so the process never binds a port in that state.
    /// </exception>
    public static SessionCookiePolicy Resolve(IConfiguration configuration, IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(environment);

        var allow = configuration.GetValue<bool>(SettingName);
        if (allow && !environment.IsDevelopment())
        {
            throw new InvalidOperationException(
                $"{SettingName}=true is allowed only in the Development environment " +
                $"(current environment: '{environment.EnvironmentName}'). Unset {SettingName}; " +
                "a deployment that terminates TLS in front of this service needs no insecure-http mode.");
        }

        return new SessionCookiePolicy(allow);
    }
}
