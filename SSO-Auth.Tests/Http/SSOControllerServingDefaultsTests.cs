// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// What the SSO sign-in surface answers while the stored configuration could not be read (#1543). A
/// default configuration holds no provider, so without this the flows would each answer that the provider
/// is unknown - a true sentence about the wrong thing, which sends an operator hunting a deleted provider
/// instead of a damaged file. Every sign-in route says 503 and points at the log instead, and the state is
/// cleared by an administrator supplying a configuration and by nothing else.
/// </summary>
[Collection("SSOController")]
public class SSOControllerServingDefaultsTests
{
    [Fact]
    public async Task OidChallenge_WhileServingDefaults_Is503()
    {
        var harness = ServingDefaults();

        var result = await harness.Controller.OidChallenge("keycloak");

        AssertUnavailable(result);
    }

    [Fact]
    public async Task OidCallback_WhileServingDefaults_Is503()
    {
        var harness = ServingDefaults();

        var result = await harness.Controller.OidCallback("keycloak", "state");

        AssertUnavailable(result);
    }

    [Fact]
    public async Task OidAuth_WhileServingDefaults_Is503()
    {
        var harness = ServingDefaults();

        var result = await harness.Controller.OidAuth("keycloak", new AuthResponse());

        Assert.Equal(503, Assert.IsAssignableFrom<ObjectResult>(result).StatusCode);
    }

    [Fact]
    public void SamlChallenge_WhileServingDefaults_Is503()
    {
        var harness = ServingDefaults();

        var result = harness.Controller.SamlChallenge("adfs");

        AssertUnavailable(result);
    }

    [Fact]
    public async Task SamlCallback_WhileServingDefaults_Is503()
    {
        var harness = ServingDefaults();

        var result = await harness.Controller.SamlCallback("adfs");

        AssertUnavailable(result);
    }

    [Fact]
    public async Task SamlAuth_WhileServingDefaults_Is503()
    {
        var harness = ServingDefaults();

        var result = await harness.Controller.SamlAuth("adfs", new AuthResponse());

        Assert.Equal(503, Assert.IsAssignableFrom<ObjectResult>(result).StatusCode);
    }

    [Fact]
    public async Task AReadableConfiguration_LeavesTheSignInSurfaceAlone()
    {
        // The falsifier: the same call on a plugin whose configuration read back is refused for its own
        // reasons - an unknown provider - and never with the 503 this state answers.
        var harness = new SsoControllerHarness();

        var result = await harness.Controller.OidChallenge("keycloak");

        AssertNotUnavailable(result);
    }

    [Fact]
    public async Task AnAdministratorSavingAConfiguration_EndsTheRefusal()
    {
        // The way out, and the reason local Jellyfin sign-in is deliberately untouched: an administrator
        // has to be able to get in to make this call.
        var harness = ServingDefaults();
        Assert.True(SSOPlugin.Instance.ServingDefaultConfiguration);

        SSOPlugin.Instance.UpdateConfiguration(new PluginConfiguration());

        Assert.False(SSOPlugin.Instance.ServingDefaultConfiguration);
        var result = await harness.Controller.OidChallenge("keycloak");
        AssertNotUnavailable(result);
    }

    [Fact]
    public void AnAdministratorImportingAConfiguration_EndsTheRefusal()
    {
        var harness = ServingDefaults();

        var imported = harness.Controller.ImportConfig(new ConfigExportDocument
        {
            FormatVersion = ConfigExport.FormatVersion,
            Configuration = new PluginConfiguration(),
        });

        Assert.IsType<NoContentResult>(imported);
        Assert.False(SSOPlugin.Instance.ServingDefaultConfiguration);
    }

    [Fact]
    public void ARejectedImport_LeavesTheRefusalStanding()
    {
        // Only a configuration that actually landed ends the state. A document the import refuses changed
        // nothing, so the server is still serving defaults and must still say so.
        var harness = ServingDefaults();

        var imported = harness.Controller.ImportConfig(new ConfigExportDocument
        {
            FormatVersion = ConfigExport.FormatVersion + 99,
            Configuration = new PluginConfiguration(),
        });

        Assert.IsType<BadRequestObjectResult>(imported);
        Assert.True(SSOPlugin.Instance.ServingDefaultConfiguration);
    }

    private static SsoControllerHarness ServingDefaults() => new(unreadableConfiguration: true);

    private static void AssertUnavailable(ActionResult result) => Assert.Equal(503, Status(result));

    private static void AssertNotUnavailable(ActionResult result) => Assert.NotEqual(503, Status(result));

    // A refusal on the sign-in surface arrives either as the plain result or as the restyled error page a
    // browser-navigated route wraps it in, and the two are different result types. The status is the same
    // fact in both, so it is what these read.
    private static int? Status(ActionResult result) => result switch
    {
        ObjectResult objectResult => objectResult.StatusCode,
        ContentResult contentResult => contentResult.StatusCode,
        StatusCodeResult statusCodeResult => statusCodeResult.StatusCode,
        _ => null,
    };
}
