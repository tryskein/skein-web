using System.Net;
using System.Text.Json;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// The form of the early 502 that the OpenAPI document declares equals the form the running
/// application gives, for every operation of the document, by class (INV-9, contract of the cookie
/// task). The expected form per class is the table below, not the product's own classifier.
/// </summary>
[Trait("Category", "Integration")]
[Collection("startup-stand")]
public sealed class SwaggerEarlyFailureDocumentationTest
{
    private enum Class { Two, Common, Login, Explicit }

    private static Class ClassOf(string method, string path) => (method, path) switch
    {
        ("post", "/api/auth/login") => Class.Login,
        ("post", "/api/auth/signup") or ("post", "/api/auth/invitations/{token}/signup")
            or ("post", "/api/auth/password-reset/{token}") => Class.Explicit,
        ("get", "/api/auth/config") or ("get", "/healthz") or ("get", "/ready") => Class.Common,
        _ => Class.Two,
    };

    [StartupFact]
    public async Task EveryOperation_DeclaresTheFormItGets()
    {
        await using var stand = await StartupStand.StartAsync(authMode: "keycloak", trusted: "127.0.0.1");
        Assert.True(await stand.App.WaitForHealthAsync(TimeSpan.FromSeconds(60)), stand.App.Output);
        var signIn = await stand.SendAsync("/api/auth/me", null, null, ("X-Auth-Request-User", "alice"), ("X-Auth-Request-Email", "alice@example.com"));
        var cookie = signIn.SetCookies.Single(c => c.StartsWith("skein.sid=", StringComparison.Ordinal)).Split(';')[0];
        var document = JsonDocument.Parse((await stand.SendAsync("/swagger/v1/swagger.json")).Body).RootElement;

        var operations = new List<(string Method, string Path, JsonElement Operation)>();
        foreach (var path in document.GetProperty("paths").EnumerateObject())
        {
            foreach (var op in path.Value.EnumerateObject())
            {
                operations.Add((op.Name, path.Name, op.Value));
            }
        }

        // Control: the document holds routes of every class.
        foreach (var (method, path) in new[]
        {
            ("get", "/api/auth/me"), ("post", "/api/auth/logout"), ("get", "/oauth2/start"), ("get", "/api/auth/config"),
            ("get", "/healthz"), ("get", "/ready"), ("post", "/api/auth/login"), ("post", "/api/auth/signup"),
            ("post", "/api/auth/invitations/{token}/signup"), ("post", "/api/auth/password-reset/{token}"),
        })
        {
            Assert.Contains(operations, o => o.Method == method && o.Path == path);
        }

        stand.Proxy.Cut();
        foreach (var (method, path, operation) in operations)
        {
            var @class = ClassOf(method, path);
            // The declaration is the 502 response text and the operation text together: a controller
            // action carries it in the response, a route of Program.cs in the operation description.
            var declared = (operation.GetProperty("responses").TryGetProperty("502", out var r)
                ? r.GetProperty("description").GetString() ?? "" : "")
                + " " + (operation.TryGetProperty("description", out var d) ? d.GetString() ?? "" : "");
            Assert.True(operation.GetProperty("responses").TryGetProperty("502", out _), $"{method} {path} declares no 502");
            switch (@class)
            {
                case Class.Two:
                    Assert.Contains("sso_unavailable", declared);
                    Assert.Contains("upstream_unavailable", declared);
                    break;
                case Class.Common or Class.Explicit:
                    Assert.Contains("upstream_unavailable", declared);
                    Assert.DoesNotContain("sso_unavailable", declared);
                    break;
                default:
                    Assert.DoesNotContain("sso_unavailable", declared);
                    Assert.Contains("member", declared);
                    break;
            }

            // The machine contract: every operation declares the common problem schema for its 502.
            // The SSO form cannot be declared next to it by attributes (one schema per status code
            // survives in the generated document), so its declaration is the text checked above.
            var schemas = string.Join(' ', operation.GetProperty("responses").GetProperty("502").GetProperty("content")
                .EnumerateObject().Select(c => c.Value.GetRawText()));
            Assert.Contains("ProblemDetails", schemas);

            var url = path.Replace("{token}", "t").Replace("{", "").Replace("}", "");
            var http = new HttpMethod(method.ToUpperInvariant());
            var plain = await stand.SendAsync(url, cookie, http);
            Assert.Equal(HttpStatusCode.BadGateway, plain.Status);
            Assert.Empty(plain.SetCookies);
            var body = JsonDocument.Parse(plain.Body).RootElement;
            Assert.Equal(@class != Class.Login, body.TryGetProperty("error", out var error) && error.GetString() == "upstream_unavailable");

            if (@class == Class.Two)
            {
                var sso = await stand.SendAsync(url, cookie, http, ("X-Auth-Request-User", "alice"), ("X-Auth-Request-Email", "alice@example.com"));
                Assert.Equal("sso_unavailable", JsonDocument.Parse(sso.Body).RootElement.GetProperty("error").GetString());
            }
        }
    }
}
