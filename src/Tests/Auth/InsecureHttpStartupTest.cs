namespace SkeinWeb.Tests.Auth;

/// <summary>SC-005 on a real start: the insecure-http mode outside Development stops the process before it listens (INV-7, INV-11).</summary>
[Trait("Category", "Integration")]
[Collection("startup-stand")]
public sealed class InsecureHttpStartupTest
{
    [StartupFact]
    public async Task OutsideDevelopment_TheProcessExitsNamingTheSetting_AndNeverAcceptsAConnection()
    {
        await using var stand = await StartupStand.StartAsync(environment: "Production", insecure: "true");

        var accepted = false;
        for (var i = 0; i < 1500 && !stand.App.HasExited; i++)
        {
            accepted |= await stand.App.AcceptsConnectionAsync();
            await Task.Delay(10);
        }

        Assert.True(await stand.App.WaitForExitAsync(TimeSpan.FromSeconds(30)), stand.App.Output);
        Assert.NotEqual(0, stand.App.ExitCode);
        Assert.False(accepted);
        Assert.Contains("SKEIN_ALLOW_INSECURE_HTTP", stand.App.Output);
    }

    [StartupFact]
    public async Task Control_InDevelopment_TheSameSetOfDependenciesStartsAndAnswersHealthz()
    {
        await using var stand = await StartupStand.StartAsync(environment: "Development", insecure: "true");

        Assert.True(await stand.App.WaitForHealthAsync(TimeSpan.FromSeconds(60)), stand.App.Output);
    }

    // The error of the policy comes before the error of a missing required setting.
    [Fact]
    public async Task OutsideDevelopment_WithoutTheRequiredSettings_TheErrorNamesThePolicyNotTheMissingSetting()
    {
        using var app = AppProcess.Start(new Dictionary<string, string?>
        {
            ["ASPNETCORE_ENVIRONMENT"] = "Production",
            ["SKEIN_ALLOW_INSECURE_HTTP"] = "true",
            ["SKEIN_API_URL"] = null,
            ["SKEIN_INTERNAL_SECRET"] = null,
            ["REDIS_URL"] = null,
            ["NATS_URL"] = null,
        });

        Assert.True(await app.WaitForExitAsync(TimeSpan.FromSeconds(60)), app.Output);
        Assert.NotEqual(0, app.ExitCode);
        Assert.Contains("SKEIN_ALLOW_INSECURE_HTTP", app.Output);
        Assert.DoesNotContain("SKEIN_API_URL is not set", app.Output);
    }
}
