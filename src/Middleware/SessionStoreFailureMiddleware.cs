using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using SkeinWeb.Auth;

namespace SkeinWeb.Middleware;

/// <summary>
/// Early refusal when the session store (Redis) fails technically while the session is read: the
/// request is answered 502, without Set-Cookie and before skein-api is called. A missing, expired
/// or unusable session is not a failure — the store answers it as "no session" — so only a store
/// that cannot be reached ends here.
/// </summary>
/// <remarks>
/// <para>
/// Sits between <c>UseRouting</c> and <c>UseAuthentication</c>, so the endpoint metadata is
/// available and the cookie handler's first read happens inside <c>next</c>. It catches
/// <see cref="SessionStoreUnavailableException"/> only, and only while the response has not
/// started; the exception carries no text of its source.
/// </para>
/// <para>
/// The form of the answer follows the request:
/// <list type="number">
///   <item><description>an endpoint marked <see cref="ExplicitSignInAttribute"/>: for
///   <see cref="Surface.Login"/> a ProblemDetails 502 of type
///   <c>https://skein.local/errors/upstream-unavailable</c> without an <c>error</c> member; for the
///   other three the same with <c>error = upstream_unavailable</c>;</description></item>
///   <item><description>a trusted SSO request (<see cref="TrustedSsoRequest"/>) that is not an
///   explicit sign-in: JSON 502 <c>{"error":"sso_unavailable","message":…}</c>, the form
///   <see cref="SsoSessionMiddleware"/> uses for an unreachable authentication service;</description></item>
///   <item><description>everything else: ProblemDetails 502 of the same type with
///   <c>error = upstream_unavailable</c>.</description></item>
/// </list>
/// </para>
/// </remarks>
public sealed class SessionStoreFailureMiddleware(
    WebAuthMode mode,
    TrustedProxyConfig trustedProxies,
    ILogger<SessionStoreFailureMiddleware> logger) : IMiddleware
{
    private const string UpstreamUnavailableType = "https://skein.local/errors/upstream-unavailable";

    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    /// <inheritdoc />
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        try
        {
            await next(context);
        }
        catch (SessionStoreUnavailableException) when (!context.Response.HasStarted)
        {
            logger.LogWarning("session store unavailable while reading the session; answering 502");
            await WriteRefusalAsync(context);
        }
    }

    private async Task WriteRefusalAsync(HttpContext context)
    {
        // Nothing the failed request had prepared goes out with the refusal.
        context.Response.Headers.Remove("Set-Cookie");

        var explicitSignIn = context.GetEndpoint()?.Metadata.GetMetadata<ExplicitSignInAttribute>();
        if (explicitSignIn is null && TrustedSsoRequest.Matches(context, mode, trustedProxies))
        {
            context.Response.StatusCode = StatusCodes.Status502BadGateway;
            context.Response.ContentType = "application/json";
            await JsonSerializer.SerializeAsync(
                context.Response.Body,
                new
                {
                    error = "sso_unavailable",
                    message = "Authentication service is temporarily unavailable.",
                },
                JsonOpts,
                context.RequestAborted);
            return;
        }

        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status502BadGateway,
            Type = UpstreamUnavailableType,
            Title = explicitSignIn?.Surface == Surface.Login
                ? "Authentication service unavailable"
                : "Session service unavailable",
            Detail = "The session store is temporarily unavailable. Try again in a moment.",
        };
        if (explicitSignIn?.Surface != Surface.Login)
        {
            problem.Extensions["error"] = "upstream_unavailable";
        }

        context.Response.StatusCode = StatusCodes.Status502BadGateway;
        context.Response.ContentType = "application/problem+json";
        await JsonSerializer.SerializeAsync(context.Response.Body, problem, JsonOpts, context.RequestAborted);
    }
}
