// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Linq;
using System.Text.Json;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The aggregate configuration check (#1084) against the three things its acceptance asks of it: it names
/// exactly the provider that would fail and why, it answers an empty configuration as a report rather than
/// as an error, and it changes nothing while doing either.
/// </summary>
/// <remarks>
/// These run against <see cref="ProviderCheck"/> directly rather than through a browser, which is where the
/// button lives. That is deliberate: the evaluation was put on the server precisely so it could be executed
/// by a test, and the alternative shape - reading each provider's readiness out of the settings page's own
/// DOM - is unreachable from any suite here and would have left every clause below unproven.
/// </remarks>
public class ProviderCheckTests
{
    private static PluginConfiguration TwoProviders()
    {
        var config = new PluginConfiguration();
        config.OidConfigs["complete"] = new OidConfig
        {
            Enabled = true,
            OidEndpoint = "https://idp.example.invalid/.well-known/openid-configuration",
            OidClientId = "client-1",
        };
        config.OidConfigs["half-filled"] = new OidConfig
        {
            Enabled = true,
            OidEndpoint = "https://idp.example.invalid/.well-known/openid-configuration",
        };
        return config;
    }

    private static ProviderCheckResult Row(ProviderCheckDocument report, string provider)
        => Assert.Single(report.Providers, r => r.Provider == provider);

    [Fact]
    public void OneCompleteAndOneIncompleteProvider_NamesExactlyTheIncompleteOneAndTheReason()
    {
        // The first acceptance clause. "Exactly" is the load-bearing word: a check that flagged the complete
        // provider too would be as useless as one that flagged neither, because an administrator learns to
        // ignore a list that is always half red.
        var report = ProviderCheck.Build(TwoProviders());

        Assert.Equal(new[] { "complete", "half-filled" }, report.Providers.Select(r => r.Provider));
        Assert.True(Row(report, "complete").Ready);

        var incomplete = Row(report, "half-filled");
        Assert.False(incomplete.Ready);
        Assert.Equal(new[] { "OidClientId" }, incomplete.MissingFields);
        Assert.Null(incomplete.Problem);
    }

    [Fact]
    public void NoProvidersConfigured_ReportsAnEmptyList_RatherThanFailing()
    {
        // The second clause, and the state of every fresh installation. An exception here would make the
        // action look broken on the one page an administrator opens before they have configured anything.
        var report = ProviderCheck.Build(new PluginConfiguration());

        Assert.Empty(report.Providers);
    }

    [Fact]
    public void RunningTheCheck_LeavesEveryProviderFieldUnchanged()
    {
        // The third clause, at the only layer that can hold it: the check is a pure read, so nothing it does
        // could reach a stored value. Pinning it here means a later version that "repaired" a provider while
        // reporting on it - the obvious next feature - reddens instead of quietly editing configuration from
        // a button labelled Check. Compared through the export document because that is the whole
        // configuration rendered as bytes, so a change to any provider field shows up rather than only the
        // ones a hand-written assertion thought to name.
        var config = TwoProviders();
        config.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = false,
            SamlEndpoint = "https://adfs.example.invalid/sso",
            SamlClientId = "sp-1",
            SamlCertificate = "not-a-certificate",
        };
        var before = JsonSerializer.Serialize(ConfigExport.Build(config));

        ProviderCheck.Build(config);

        Assert.Equal(before, JsonSerializer.Serialize(ConfigExport.Build(config)));
    }

    [Fact]
    public void AnInvalidValue_IsReportedWithTheMessageTheSavePathWouldRefuseItWith()
    {
        // The reason text is TAKEN from the save gate rather than composed here, so the report and the
        // rejected save cannot say different things about one provider. Pinned against the gate's own output
        // rather than against a literal, so a reworded refusal moves both together.
        var config = new PluginConfiguration();
        config.OidConfigs["kc"] = new OidConfig
        {
            OidEndpoint = "https://idp.example.invalid/.well-known/openid-configuration",
            OidClientId = "client-1",
            BaseUrlOverride = "not-a-url",
        };

        var expected = Assert.Throws<ArgumentException>(
            () => ProviderConfigValidator.ValidateBaseUrlOverride("OpenID", "kc", "not-a-url"));

        var row = Row(ProviderCheck.Build(config), "kc");
        Assert.False(row.Ready);

        // Byte-identical, tail and all. Trimming the message here - the "(Parameter 'baseUrlOverride')" the
        // runtime appends is the obvious candidate - would make the check and the refused save say different
        // things about one provider, which is the disagreement this report exists to prevent.
        Assert.Equal(expected.Message, row.Problem);
    }

    [Fact]
    public void ADisabledButCompleteProvider_IsReportedAsReady_AndAsSwitchedOff()
    {
        // A provider an administrator turned off is not misconfigured. Reporting it as needing attention
        // would put a permanent false alarm on every deployment that keeps a provider parked, which is the
        // fastest way to make the whole list unread. The state is still REPORTED, so the page can say it.
        var config = new PluginConfiguration();
        config.SamlConfigs["parked"] = new SamlConfig
        {
            Enabled = false,
            SamlEndpoint = "https://adfs.example.invalid/sso",
            SamlClientId = "sp-1",
            SamlCertificate = SamlTestFactory.Create().CertificateBase64,
        };

        var row = Row(ProviderCheck.Build(config), "parked");

        Assert.True(row.Ready);
        Assert.False(row.Enabled);
    }

    [Fact]
    public void ASamlProviderMissingItsCertificate_NamesTheCertificate_NotTheEndpoint()
    {
        // The SAML required set is its own; a check that reported the OpenID one against a SAML provider
        // would name fields that provider does not have.
        var config = new PluginConfiguration();
        config.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlEndpoint = "https://adfs.example.invalid/sso",
            SamlClientId = "sp-1",
        };

        var row = Row(ProviderCheck.Build(config), "adfs");

        Assert.False(row.Ready);
        Assert.Equal(new[] { "SamlCertificate" }, row.MissingFields);
    }

    [Fact]
    public void AProviderNamingAnUndefinedProfile_IsReported_AndItsNeighbourIsNot()
    {
        // The check asks the whole-config validator about a snapshot holding ONE provider, which is what lets
        // a per-provider rule be reported per provider at all. Widen that snapshot to the whole configuration
        // and every provider inherits its neighbour's refusal, so the second assertion here is the one that
        // fails if the isolation is lost.
        var config = new PluginConfiguration();
        config.OidConfigs["kc"] = new OidConfig
        {
            OidEndpoint = "https://idp.example.invalid/.well-known/openid-configuration",
            OidClientId = "client-1",
            ProvisioningProfile = "no-such-profile",
        };
        config.OidConfigs["clean"] = new OidConfig
        {
            OidEndpoint = "https://idp.example.invalid/.well-known/openid-configuration",
            OidClientId = "client-2",
        };

        var report = ProviderCheck.Build(config);

        Assert.False(Row(report, "kc").Ready);
        Assert.Contains("no-such-profile", Row(report, "kc").Problem!, StringComparison.Ordinal);
        Assert.True(Row(report, "clean").Ready);
    }

    [Fact]
    public void EveryDeclaredRequiredField_ResolvesToAStringSettingOnItsProviderType()
    {
        // The required-field lists are read by reflection, so a name that resolves to nothing would throw at
        // the moment an administrator pressed the button - the one place a report about broken configuration
        // must not itself break. Misspell a name and this reddens instead.
        foreach (var field in ProviderCheck.OidRequiredFields)
        {
            var property = typeof(OidConfig).GetProperty(field);
            Assert.True(property is not null, "OidConfig declares no '" + field + "' property.");
            Assert.Equal(typeof(string), property!.PropertyType);
        }

        foreach (var field in ProviderCheck.SamlRequiredFields)
        {
            var property = typeof(SamlConfig).GetProperty(field);
            Assert.True(property is not null, "SamlConfig declares no '" + field + "' property.");
            Assert.Equal(typeof(string), property!.PropertyType);
        }
    }
}
