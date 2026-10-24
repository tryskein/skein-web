namespace SkeinWeb.Auth;

/// <summary>
/// Thrown by <see cref="SkeinApiClient.OidcProvisionAsync"/> when
/// skein-api rejects a provisioning request with a structured business
/// error (HTTP 403 / 422 / 409 from
/// <c>POST /api/v1/auth/oidc/provision</c>).
/// </summary>
/// <remarks>
/// The <see cref="ErrorCode"/> is the machine-readable code in the
/// upstream JSON body (<c>user_not_provisioned</c>,
/// <c>missing_claims</c>, <c>username_conflict</c>) — middleware
/// branches on it to choose the surface response. The
/// <see cref="StatusCode"/> mirrors the upstream HTTP status verbatim
/// for callers that prefer to switch on the status rather than the code.
/// </remarks>
public sealed class SsoProvisioningException : Exception
{
    /// <summary>Upstream HTTP status code (403, 422, 409, …).</summary>
    public int StatusCode { get; }

    /// <summary>
    /// Stable upstream <c>error</c> code from the response body. Empty
    /// when the response body did not parse (defensive fallback).
    /// </summary>
    public string ErrorCode { get; }

    public SsoProvisioningException(int statusCode, string errorCode, string message)
        : base(message)
    {
        StatusCode = statusCode;
        ErrorCode = errorCode;
    }
}
