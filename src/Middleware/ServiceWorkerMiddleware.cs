namespace SkeinWeb.Middleware;

/// <summary>
/// Serves the frontend service worker at root scope (<c>GET /sw.js</c>) with
/// the headers a service worker registration requires.
/// </summary>
/// <remarks>
/// <para>
/// A service worker can only control pages at or below the path it is served
/// from, so the SW file MUST live at the site root (<c>/sw.js</c>) to control
/// the whole app. We additionally emit <c>Service-Worker-Allowed: /</c> so the
/// browser permits a root registration scope even if the registration call
/// passes an explicit <c>scope</c>, and <c>Cache-Control: no-cache</c> so a new
/// SW deploy is picked up on the next navigation rather than being pinned by an
/// intermediary cache.
/// </para>
/// <para>
/// <b>Deployment reality (dev/prod split).</b> As of May 2026 skein-web no
/// longer serves the React SPA — the public entrypoint is the sibling
/// <c>skein-frontend</c> nginx image, which serves <c>/sw.js</c> from its
/// static bundle (and whose nginx.conf carries the equivalent
/// <c>Service-Worker-Allowed</c> / no-cache rule). In that topology this
/// middleware never fires for <c>/sw.js</c> because nginx answers it before the
/// request ever reaches the BFF. This middleware is the correct serving rule
/// for any deployment where skein-web DOES host the bundle (a <c>wwwroot/sw.js</c>
/// is present): it reads the file from the web-root content provider and, when
/// the file is absent (the default in this image and in local dev where the
/// frontend runs under Vite on its own port), it falls through to the next
/// middleware so the request 404s exactly as any other unmatched path does.
/// No blanket caching policy is applied to the rest of the static tree — this
/// handler is keyed on the single <c>/sw.js</c> path.
/// </para>
/// </remarks>
public sealed class ServiceWorkerMiddleware : IMiddleware
{
    /// <summary>Root-scoped path the browser fetches the service worker from.</summary>
    private const string ServiceWorkerPath = "/sw.js";

    private readonly IWebHostEnvironment _env;
    private readonly ILogger<ServiceWorkerMiddleware> _logger;

    public ServiceWorkerMiddleware(
        IWebHostEnvironment env,
        ILogger<ServiceWorkerMiddleware> logger)
    {
        _env = env;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        if (!context.Request.Path.Equals(ServiceWorkerPath, StringComparison.OrdinalIgnoreCase))
        {
            await next(context);
            return;
        }

        // Only GET/HEAD make sense for a static asset.
        if (!HttpMethods.IsGet(context.Request.Method) &&
            !HttpMethods.IsHead(context.Request.Method))
        {
            await next(context);
            return;
        }

        // Resolve sw.js from the web-root file provider (wwwroot). When the
        // bundle is not co-hosted (the default — the SPA lives in the
        // skein-frontend nginx image), the file is absent and we fall through
        // so the path 404s like any other unmatched route.
        var file = _env.WebRootFileProvider.GetFileInfo(ServiceWorkerPath);
        if (!file.Exists || file.IsDirectory)
        {
            await next(context);
            return;
        }

        // Service-worker serving rules:
        //  - Content-Type must be a JavaScript MIME or the browser refuses
        //    to register the worker.
        //  - Service-Worker-Allowed: / lets the worker claim root scope.
        //  - no-cache so a redeploy propagates on next navigation; we do NOT
        //    touch caching for any other path.
        context.Response.ContentType = "text/javascript";
        context.Response.Headers["Service-Worker-Allowed"] = "/";
        context.Response.Headers.CacheControl = "no-cache";

        if (HttpMethods.IsHead(context.Request.Method))
        {
            context.Response.ContentLength = file.Length;
            return;
        }

        _logger.LogDebug("serving co-hosted service worker from {Path}", file.PhysicalPath ?? ServiceWorkerPath);
        await context.Response.SendFileAsync(file, context.RequestAborted);
    }
}
