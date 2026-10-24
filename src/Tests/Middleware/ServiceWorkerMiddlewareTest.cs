using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging.Abstractions;
using SkeinWeb.Middleware;

namespace SkeinWeb.Tests.Middleware;

/// <summary>
/// Pins the <see cref="ServiceWorkerMiddleware"/> serving contract for
/// <c>/sw.js</c>: when a co-hosted bundle is present the file is served at
/// root scope with the headers a service-worker registration needs
/// (JavaScript MIME, <c>Service-Worker-Allowed: /</c>, <c>Cache-Control:
/// no-cache</c>); when the bundle is absent (the default in this image — the
/// SPA lives in the skein-frontend nginx image) the middleware falls through
/// so the path 404s like any other unmatched route; every non-<c>/sw.js</c>
/// path passes straight through untouched.
/// </summary>
public class ServiceWorkerMiddlewareTest
{
    /// <summary>
    /// Builds an env whose WebRootFileProvider is rooted at a temp directory.
    /// When <paramref name="swContents"/> is non-null an <c>sw.js</c> is
    /// written into it; otherwise the directory is empty (file absent).
    /// </summary>
    private static (ServiceWorkerMiddleware mw, string dir) BuildMiddleware(string? swContents)
    {
        var dir = Path.Combine(Path.GetTempPath(), "skein-sw-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        if (swContents is not null)
        {
            File.WriteAllText(Path.Combine(dir, "sw.js"), swContents);
        }

        var env = new StubWebHostEnvironment
        {
            WebRootPath = dir,
            WebRootFileProvider = new PhysicalFileProvider(dir),
        };
        var mw = new ServiceWorkerMiddleware(env, NullLogger<ServiceWorkerMiddleware>.Instance);
        return (mw, dir);
    }

    [Fact]
    public async Task SwJs_WhenFilePresent_ServedWithServiceWorkerHeaders()
    {
        var (mw, dir) = BuildMiddleware("self.addEventListener('push', () => {});");
        try
        {
            var ctx = new DefaultHttpContext();
            ctx.Request.Method = HttpMethods.Get;
            ctx.Request.Path = "/sw.js";
            var body = new MemoryStream();
            ctx.Response.Body = body;

            var nextCalled = false;
            await mw.InvokeAsync(ctx, _ => { nextCalled = true; return Task.CompletedTask; });

            Assert.False(nextCalled, "next() must NOT run when sw.js is served");
            Assert.Equal("text/javascript", ctx.Response.ContentType);
            Assert.Equal("/", ctx.Response.Headers["Service-Worker-Allowed"]);
            Assert.Equal("no-cache", ctx.Response.Headers.CacheControl);
            Assert.True(body.Length > 0, "sw.js body must be written");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task SwJs_WhenFileAbsent_FallsThroughToNext()
    {
        // Default deployment: SPA served by skein-frontend nginx, no
        // co-hosted wwwroot/sw.js → middleware defers so the request 404s
        // exactly like any other unmatched path.
        var (mw, dir) = BuildMiddleware(swContents: null);
        try
        {
            var ctx = new DefaultHttpContext();
            ctx.Request.Method = HttpMethods.Get;
            ctx.Request.Path = "/sw.js";

            var nextCalled = false;
            await mw.InvokeAsync(ctx, _ => { nextCalled = true; return Task.CompletedTask; });

            Assert.True(nextCalled, "next() must run when sw.js is not co-hosted");
            Assert.True(ctx.Response.Headers["Service-Worker-Allowed"].Count == 0,
                "no SW header should be set on the fall-through path");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task NonSwPath_PassesThroughUntouched()
    {
        var (mw, dir) = BuildMiddleware("self.addEventListener('push', () => {});");
        try
        {
            var ctx = new DefaultHttpContext();
            ctx.Request.Method = HttpMethods.Get;
            ctx.Request.Path = "/index.html";

            var nextCalled = false;
            await mw.InvokeAsync(ctx, _ => { nextCalled = true; return Task.CompletedTask; });

            Assert.True(nextCalled, "next() must run for non-/sw.js paths");
            Assert.True(ctx.Response.Headers["Service-Worker-Allowed"].Count == 0);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task SwJs_NonGetVerb_FallsThrough()
    {
        // A POST to /sw.js is nonsensical for a static asset — defer rather
        // than serve, so the request is handled by the normal pipeline.
        var (mw, dir) = BuildMiddleware("self.addEventListener('push', () => {});");
        try
        {
            var ctx = new DefaultHttpContext();
            ctx.Request.Method = HttpMethods.Post;
            ctx.Request.Path = "/sw.js";

            var nextCalled = false;
            await mw.InvokeAsync(ctx, _ => { nextCalled = true; return Task.CompletedTask; });

            Assert.True(nextCalled);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>Minimal IWebHostEnvironment for driving the middleware in isolation.</summary>
    private sealed class StubWebHostEnvironment : IWebHostEnvironment
    {
        public string WebRootPath { get; set; } = "";
        public IFileProvider WebRootFileProvider { get; set; } = new NullFileProvider();
        public string ApplicationName { get; set; } = "SkeinWeb.Tests";
        public string ContentRootPath { get; set; } = Path.GetTempPath();
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
        public string EnvironmentName { get; set; } = "Development";
    }
}
