using System.ComponentModel.DataAnnotations;
using SkeinWeb.Auth;

namespace SkeinWeb.Tests.Auth;

/// <summary>
/// sk-303.42 — <see cref="ClientRuntimeOptions.Validate"/>. The MCP address
/// is copy-pasted by users into an agent config; a malformed value produces a
/// snippet that fails somewhere else entirely, so it is rejected at startup.
/// </summary>
public class ClientRuntimeOptionsTest
{
    private static void Validate(string url) =>
        new ClientRuntimeOptions { McpUrl = url }.Validate();

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public void Unset_IsAccepted(string url)
    {
        // Unset means "MCP is same-origin" — the common single-host shape.
        Validate(url);
    }

    [Theory]
    [InlineData("https://skein-mcp.example.com/mcp")]
    [InlineData("http://localhost:8080/mcp")]
    public void AbsoluteHttpUrl_IsAccepted(string url) => Validate(url);

    [Theory]
    [InlineData("/mcp")]
    [InlineData("//skein-mcp.example.com/mcp")]
    [InlineData("skein-mcp.example.com/mcp")]
    [InlineData("ftp://example.com/mcp")]
    public void NonAbsoluteHttpUrl_Throws(string url)
    {
        var ex = Assert.Throws<ValidationException>(() => Validate(url));
        Assert.Contains("SKEIN_MCP_URL", ex.Message);
    }
}
