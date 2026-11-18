namespace SkeinWeb.Auth;

/// <summary>The four operations that establish a session from credentials the request itself carries.</summary>
public enum Surface
{
    /// <summary>Password login (<c>POST /api/auth/login</c>).</summary>
    Login,

    /// <summary>Registration (<c>POST /api/auth/signup</c>).</summary>
    Signup,

    /// <summary>Registration by invitation (<c>POST /api/auth/invitations/{token}/signup</c>).</summary>
    InvitationSignup,

    /// <summary>Completion of a password reset (<c>POST /api/auth/password-reset/{token}</c>).</summary>
    PasswordResetComplete,
}

/// <summary>
/// Marks an endpoint as an explicit sign-in operation: the response carries one identity,
/// the identity of that operation, and it is a new authentication. A request to such an
/// endpoint is never treated as a trusted SSO request, whatever trust headers it carries: the code
/// that classifies requests (<see cref="SkeinWeb.Middleware.SessionStoreFailureMiddleware"/> and, later,
/// the SSO middleware) checks this marker in the endpoint metadata first and only then asks
/// <see cref="TrustedSsoRequest"/>, which does not look at endpoints. The marker itself changes no behavior.
/// </summary>
/// <param name="surface">Which of the four operations the endpoint is.</param>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false, Inherited = false)]
public sealed class ExplicitSignInAttribute(Surface surface) : Attribute
{
    /// <summary>Which of the four operations the endpoint is.</summary>
    public Surface Surface { get; } = surface;
}
