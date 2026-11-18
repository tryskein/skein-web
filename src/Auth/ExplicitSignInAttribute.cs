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
/// endpoint is never classified as a trusted SSO request (see <see cref="TrustedSsoRequest"/>),
/// whatever trust headers it carries. The marker itself changes no behavior; code that needs
/// the classification reads it from the endpoint metadata.
/// </summary>
/// <param name="surface">Which of the four operations the endpoint is.</param>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false, Inherited = false)]
public sealed class ExplicitSignInAttribute(Surface surface) : Attribute
{
    /// <summary>Which of the four operations the endpoint is.</summary>
    public Surface Surface { get; } = surface;
}
