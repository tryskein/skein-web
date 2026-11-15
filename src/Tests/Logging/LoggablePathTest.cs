using SkeinWeb.Logging;

namespace SkeinWeb.Tests.Logging;

/// <summary>
/// Pins the masking rule of <see cref="LoggablePath"/>: a segment that may be a
/// link token (20+ base64url characters, not a GUID) becomes
/// <c>{redacted}</c>; ids, GUIDs and words stay readable.
/// </summary>
public class LoggablePathTest
{
    // A link token as skein-api mints it: 32 random bytes, base64url, 43 characters.
    private const string LinkToken = "linktokenfixturelinktokenfixturelinktokenfi";

    [Theory]
    [InlineData("/ui/v1/invitations/" + LinkToken, "/ui/v1/invitations/{redacted}")]
    [InlineData("/ui/v1/invitations/" + LinkToken + "/accept", "/ui/v1/invitations/{redacted}/accept")]
    [InlineData("/ui/v1/auth/password-reset/" + LinkToken, "/ui/v1/auth/password-reset/{redacted}")]
    [InlineData("/agent/v1/" + LinkToken, "/agent/v1/{redacted}")]
    public void Token_segment_is_redacted(string path, string expected)
    {
        Assert.Equal(expected, LoggablePath.From(path));
    }

    [Theory]
    [InlineData("/ui/v1/issues/demo-42.1")]
    [InlineData("/ui/v1/projects/3f2b8c1e-5a4d-4e7f-9b6a-0c1d2e3f4a5b/issues")]
    [InlineData("/ui/v1/projects/3f2b8c1e5a4d4e7f9b6a0c1d2e3f4a5b")]
    [InlineData("/ui/v1/notifications/unread")]
    [InlineData("/mcp")]
    [InlineData("/")]
    public void Readable_path_is_unchanged(string path)
    {
        Assert.Equal(path, LoggablePath.From(path));
    }

    [Fact]
    public void Nineteen_character_segment_is_kept_and_twenty_is_redacted()
    {
        Assert.Equal("/x/abcdefghijklmnopqrs", LoggablePath.From("/x/abcdefghijklmnopqrs"));
        Assert.Equal("/x/{redacted}", LoggablePath.From("/x/abcdefghijklmnopqrst"));
    }

    [Fact]
    public void Empty_path_is_empty()
    {
        Assert.Equal(string.Empty, LoggablePath.From(null));
        Assert.Equal(string.Empty, LoggablePath.From(string.Empty));
    }
}
