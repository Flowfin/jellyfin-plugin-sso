// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Text.Json;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of <c>GET sso/Config/Managed</c> (#1102) through <see cref="SsoControllerHarness"/>, so
/// the report the admin page will consume (#1104) is read off the real store rather than a stand-in. What is
/// pinned here is the contract a browser depends on: both protocols reported, an empty answer rather than an
/// error where nothing is managed, and names only on the wire.
/// </summary>
[Collection("SSOController")]
public class SSOControllerManagedProvidersTests
{
    private static ManagedProviderSetDocument Reported(SsoControllerHarness harness) =>
        Assert.IsType<ManagedProviderSetDocument>(Assert.IsType<OkObjectResult>(harness.Controller.ManagedProviders().Result).Value);

    [Fact]
    public void NoDeclarativeSource_ReportsAnEmptySet_RatherThanFailing()
    {
        // The answer every installation that mounts nothing gets, which is most of them. An error here would
        // make the config page treat "nothing is managed" as "the server is broken" and is the difference
        // between a feature nobody notices and one that breaks the settings page for everybody.
        var harness = new SsoControllerHarness(c => c.OidConfigs["hand-made"] = new OidConfig { OidClientId = "client-1" });

        var reported = Reported(harness);

        Assert.Empty(reported.OidConfigs);
        Assert.Empty(reported.SamlConfigs);
    }

    [Fact]
    public void TheManagedSet_IsReportedForBothProtocols()
    {
        var harness = new SsoControllerHarness(c =>
        {
            c.OidConfigs["keycloak"] = new OidConfig { OidClientId = "client-1" };
            c.OidConfigs["hand-made"] = new OidConfig { OidClientId = "client-2" };
            c.SamlConfigs["adfs"] = new SamlConfig { SamlEndpoint = "https://adfs.example.invalid/sso" };
        });

        var declared = new PluginConfiguration();
        declared.OidConfigs["keycloak"] = new OidConfig { OidClientId = "client-1" };
        declared.SamlConfigs["adfs"] = new SamlConfig { SamlEndpoint = "https://adfs.example.invalid/sso" };
        SSOPlugin.Instance.ConfigStore.RecordDeclarativelyManaged(declared, "/config/sso.json");

        var reported = Reported(harness);

        Assert.Equal(new[] { "keycloak" }, reported.OidConfigs);
        Assert.Equal(new[] { "adfs" }, reported.SamlConfigs);
    }

    [Fact]
    public void TheSerializedReport_CarriesNamesAndNothingElse()
    {
        // The report is built to be rendered in a browser. A field value reaching it would widen what the
        // config page holds, and a secret reaching it would be a disclosure through the one door that exists
        // to describe a provider rather than to reveal it.
        var harness = new SsoControllerHarness(c => c.OidConfigs["keycloak"] = new OidConfig
        {
            OidEndpoint = "https://idp.example.invalid/.well-known/openid-configuration",
            OidClientId = "client-1",
            OidSecret = "PLAINTEXT-OIDC-SECRET",
        });

        var declared = new PluginConfiguration();
        declared.OidConfigs["keycloak"] = new OidConfig { OidClientId = "client-1" };
        SSOPlugin.Instance.ConfigStore.RecordDeclarativelyManaged(declared, "/config/sso.json");

        var json = JsonSerializer.Serialize(Reported(harness));

        Assert.Contains("keycloak", json, StringComparison.Ordinal);
        Assert.DoesNotContain("PLAINTEXT-OIDC-SECRET", json, StringComparison.Ordinal);
        Assert.DoesNotContain("ssoenc:", json, StringComparison.Ordinal);
        Assert.DoesNotContain("client-1", json, StringComparison.Ordinal);
        Assert.DoesNotContain("idp.example.invalid", json, StringComparison.Ordinal);
    }
}
