// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Linq;
using System.Text.Json;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of <c>GET sso/Config/Check</c> (#1084) through <see cref="SsoControllerHarness"/>, so
/// the report the settings page consumes is read off the real store rather than a stand-in. What is pinned
/// here is the contract a browser depends on: the route answers over the live configuration, both protocols
/// appear in one list, and no field value rides along with the verdict.
/// </summary>
[Collection("SSOController")]
public class SSOControllerProviderCheckTests
{
    private static ProviderCheckDocument Reported(SsoControllerHarness harness) =>
        Assert.IsType<ProviderCheckDocument>(Assert.IsType<OkObjectResult>(harness.Controller.CheckProviders().Result).Value);

    [Fact]
    public void TheRoute_AnswersOverBothProtocols_InOneList()
    {
        var harness = new SsoControllerHarness(c =>
        {
            c.OidConfigs["keycloak"] = new OidConfig
            {
                Enabled = true,
                OidEndpoint = "https://idp.example.invalid/.well-known/openid-configuration",
                OidClientId = "client-1",
            };
            c.SamlConfigs["adfs"] = new SamlConfig
            {
                Enabled = true,
                SamlEndpoint = "https://adfs.example.invalid/sso",
                SamlClientId = "sp-1",
            };
        });

        var reported = Reported(harness);

        Assert.Equal(new[] { "keycloak", "adfs" }, reported.Providers.Select(r => r.Provider));
        Assert.Equal(new[] { "OpenID", "SAML" }, reported.Providers.Select(r => r.Protocol));
        Assert.True(reported.Providers.Single(r => r.Provider == "keycloak").Ready);
        Assert.False(reported.Providers.Single(r => r.Provider == "adfs").Ready);
    }

    [Fact]
    public void AnInstallationWithNoProviders_GetsAnEmptyReport_NotAnError()
    {
        var harness = new SsoControllerHarness(_ => { });

        Assert.Empty(Reported(harness).Providers);
    }

    [Fact]
    public void TheSerializedReport_CarriesNoProviderSecretOrEndpointValue()
    {
        // The report exists to describe a provider, not to reveal it. A row carries the provider's name,
        // which of its required settings are EMPTY by property name, and the refusal the save path would
        // give - none of which is a stored value. A secret arriving here would be a disclosure through the
        // one route on this page an administrator is most likely to run and then paste into a bug report.
        var harness = new SsoControllerHarness(c => c.OidConfigs["keycloak"] = new OidConfig
        {
            Enabled = true,
            OidEndpoint = "https://idp.example.invalid/.well-known/openid-configuration",
            OidClientId = "client-1",
            OidSecret = "PLAINTEXT-OIDC-SECRET",
        });

        var json = JsonSerializer.Serialize(Reported(harness));

        Assert.Contains("keycloak", json, StringComparison.Ordinal);
        Assert.DoesNotContain("PLAINTEXT-OIDC-SECRET", json, StringComparison.Ordinal);
        Assert.DoesNotContain("ssoenc:", json, StringComparison.Ordinal);
        Assert.DoesNotContain("client-1", json, StringComparison.Ordinal);
        Assert.DoesNotContain("idp.example.invalid", json, StringComparison.Ordinal);
    }
}
