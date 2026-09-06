// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
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
            Configuration = Restored(),
        });

        Assert.IsType<NoContentResult>(imported);
        Assert.False(SSOPlugin.Instance.ServingDefaultConfiguration);
    }

    [Fact]
    public void AnEmptyImport_DoesNotEndTheRefusal()
    {
        // What ends it is a configuration ARRIVING, not a request being accepted. A document that merges
        // nothing leaves the server on the same defaults it was refusing for, and flipping the answer from
        // an accurate 503 to "no matching provider" would hand the operator back the confusion this
        // exists to end.
        var harness = ServingDefaults();

        var imported = harness.Controller.ImportConfig(new ConfigExportDocument
        {
            FormatVersion = ConfigExport.FormatVersion,
            Configuration = new PluginConfiguration(),
        });

        Assert.IsType<NoContentResult>(imported);
        Assert.True(SSOPlugin.Instance.ServingDefaultConfiguration);
    }

    [Fact]
    public void AnAdministratorSavingAProviderOnTheSettingsPage_EndsTheRefusal()
    {
        // THE DOCUMENTED RECOVERY, and it does not go through the plugin-configuration door: the settings
        // page saves a provider through MutateConfiguration, which never enters UpdateConfiguration. A rule
        // written at that override alone left a server that had done exactly what the banner told it to do
        // refusing every SSO sign-in for good.
        var harness = ServingDefaults();

        harness.Controller.OidAdd("keycloak", new OidConfig { OidEndpoint = "https://idp.example", OidClientId = "client" });

        Assert.False(SSOPlugin.Instance.ServingDefaultConfiguration);
    }

    [Fact]
    public void AConfigurationArrivingFromADeclarativeSource_EndsTheRefusal()
    {
        // The deployment style that can repair itself without a person: a mounted document or a set of
        // environment variables is applied through the same MutateConfiguration the page save uses. A
        // server whose operator declared its providers must not come up holding exactly those providers
        // and refusing every sign-in until somebody clicks something.
        var harness = ServingDefaults();

        SSOPlugin.Instance.MutateConfiguration(configuration => configuration.OidConfigs["declared"] = new OidConfig());

        Assert.False(SSOPlugin.Instance.ServingDefaultConfiguration);
    }

    [Fact]
    public void ASaveWhoseWriteFails_DoesNotEndTheRefusal()
    {
        // The falsifier for the ordering. The full disk this whole area is about is exactly the case where
        // a save does not reach the file, and a server that answered logins with "no matching provider" for
        // the rest of the process on the strength of a write that never landed would be reporting a repair
        // that did not happen.
        var harness = ServingDefaults();

        // The lazy load first, so what fails below is the SAVE and not the host writing its own defaults.
        // Without this the write throws before the persist bridge is ever reached and the assertion holds
        // for a reason that has nothing to do with the ordering under examination.
        _ = SSOPlugin.Instance.Configuration;
        harness.Xml.When(x => x.SerializeToFile(Arg.Any<object>(), Arg.Any<string>())).Do(_ => throw new IOException("no space left on device"));

        Assert.Throws<IOException>(() => harness.Controller.OidAdd("keycloak", new OidConfig()));

        Assert.True(SSOPlugin.Instance.ServingDefaultConfiguration);
    }

    private static PluginConfiguration Restored()
    {
        var configuration = new PluginConfiguration();
        configuration.OidConfigs["keycloak"] = new OidConfig();
        return configuration;
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

    [Fact]
    public void TheConfigurationCheck_ReportsTheState()
    {
        // The page reads it from here, and this is the report whose empty provider list would otherwise
        // read as "nothing configured" on a server whose providers are on disk in a file it refused.
        var harness = ServingDefaults();

        var report = Assert.IsType<ProviderCheckDocument>(Assert.IsType<OkObjectResult>(harness.Controller.CheckProviders().Result).Value);

        Assert.True(report.ConfigurationUnreadable);
    }

    [Fact]
    public void TheConfigurationCheck_OnAHealthyServer_ReportsNothing()
    {
        // The falsifier: one thing changes - the stored configuration reads back - and the same report says
        // so, which is what stops the banner from being permanently on.
        var harness = new SsoControllerHarness();

        var report = Assert.IsType<ProviderCheckDocument>(Assert.IsType<OkObjectResult>(harness.Controller.CheckProviders().Result).Value);

        Assert.False(report.ConfigurationUnreadable);
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

        // Never null. A null would make Assert.NotEqual(503, …) pass for any result shape this does not
        // know, which is a falsifier that cannot fail - the negative assertions below would then hold for
        // a redirect, an empty result, or anything else a refactor produced.
        _ => throw new InvalidOperationException($"Unhandled result type in a sign-in assertion: {result.GetType().Name}"),
    };
}
