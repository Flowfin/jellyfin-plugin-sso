// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the elevated write doors that reach a provider WITHOUT going through the config-page
/// save (#1415), via <see cref="SsoControllerHarness"/>. The freeze #1102 landed sits in
/// <c>ProviderConfigStore.Save</c>, which only the settings page writes through; these five routes persist
/// through <c>MutateConfiguration</c> or through <c>ConfigImport</c> and so walked straight past it.
/// </summary>
/// <remarks>
/// <para>
/// What is pinned here is one property per door, in both directions. A declaratively managed provider is
/// refused and nothing is written; a provider no source named still adds and deletes exactly as it did
/// before, which is the half that would otherwise be broken in silence for every installation that mounts
/// no document at all.
/// </para>
/// <para>
/// The refusal has to name the SOURCE. Without it an administrator is told the change was refused and given
/// nowhere to make it instead, and the two sources - a mounted file and the environment - are edited in
/// different places on different machines.
/// </para>
/// </remarks>
[Collection("SSOController")]
public class SSOControllerManagedWriteDoorTests
{
    private const string Source = "/run/secrets/sso-providers.json";

    // The store is process state on the plugin singleton the harness rebuilds per test, so declaring a set
    // here cannot leak into the next test. Declared AFTER the harness is constructed for the same reason.
    private static void Manage(Action<PluginConfiguration> declare)
    {
        var declared = new PluginConfiguration();
        declare(declared);
        SSOPlugin.Instance.ConfigStore.RecordDeclarativelyManaged(declared, Source);
    }

    private static SsoControllerHarness ManagedKeycloakAndAdfs()
    {
        var harness = new SsoControllerHarness(c =>
        {
            c.OidConfigs["keycloak"] = new OidConfig { OidClientId = "declared-client" };
            c.OidConfigs["hand-made"] = new OidConfig { OidClientId = "typed-client" };
            c.SamlConfigs["adfs"] = new SamlConfig { SamlEndpoint = "https://adfs.example.invalid/sso" };
            c.SamlConfigs["shib"] = new SamlConfig { SamlEndpoint = "https://shib.example.invalid/sso" };
        });

        Manage(declared =>
        {
            declared.OidConfigs["keycloak"] = new OidConfig { OidClientId = "declared-client" };
            declared.SamlConfigs["adfs"] = new SamlConfig { SamlEndpoint = "https://adfs.example.invalid/sso" };
        });

        return harness;
    }

    private static void AssertNamesTheSource(SsoControllerHarness harness, string message, string provider)
    {
        Assert.Contains(Source, message, StringComparison.Ordinal);
        Assert.Contains(provider, message, StringComparison.Ordinal);

        // The operator half: a refusal an administrator meets in a browser is also an audit line, or the
        // server keeps no record of an elevated write it declined.
        var audited = Assert.Single(
            harness.ControllerLog.Entries,
            e => e.Message.Contains("[SSO Audit]", StringComparison.Ordinal)
                 && e.Message.Contains(Source, StringComparison.Ordinal));
        Assert.Contains(provider, audited.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void OidAdd_ManagedProvider_Throws_AndLeavesTheDeclaredValueStored()
    {
        var harness = ManagedKeycloakAndAdfs();

        var ex = Assert.Throws<ArgumentException>(
            () => harness.Controller.OidAdd("keycloak", new OidConfig { OidClientId = "attacker-client" }));

        AssertNamesTheSource(harness, ex.Message, "keycloak");
        Assert.Equal("declared-client", SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].OidClientId));
    }

    [Fact]
    public void SamlAdd_ManagedProvider_Throws_AndLeavesTheDeclaredValueStored()
    {
        var harness = ManagedKeycloakAndAdfs();

        var ex = Assert.Throws<ArgumentException>(
            () => harness.Controller.SamlAdd("adfs", new SamlConfig { SamlEndpoint = "https://attacker.example.invalid/sso" }));

        AssertNamesTheSource(harness, ex.Message, "adfs");
        Assert.Equal(
            "https://adfs.example.invalid/sso",
            SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs["adfs"].SamlEndpoint));
    }

    [Fact]
    public void OidDel_ManagedProvider_Throws_AndTheProviderSurvives()
    {
        // The availability half of this issue. Deleting a managed provider fails every login against it
        // until the next start puts it back, and nothing in the log said why.
        var harness = ManagedKeycloakAndAdfs();

        var ex = Assert.Throws<ArgumentException>(() => harness.Controller.OidDel("keycloak"));

        AssertNamesTheSource(harness, ex.Message, "keycloak");
        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs.ContainsKey("keycloak")));
    }

    [Fact]
    public void SamlDel_ManagedProvider_Throws_AndTheProviderSurvives()
    {
        var harness = ManagedKeycloakAndAdfs();

        var ex = Assert.Throws<ArgumentException>(() => harness.Controller.SamlDel("adfs"));

        AssertNamesTheSource(harness, ex.Message, "adfs");
        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs.ContainsKey("adfs")));
    }

    [Fact]
    public void OidAdd_UnmanagedProvider_StillStores_WhileAnotherProviderIsManaged()
    {
        var harness = ManagedKeycloakAndAdfs();

        harness.Controller.OidAdd("hand-made", new OidConfig { OidClientId = "re-typed-client" });

        Assert.Equal("re-typed-client", SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["hand-made"].OidClientId));
    }

    [Fact]
    public void SamlAdd_UnmanagedProvider_StillStores_WhileAnotherProviderIsManaged()
    {
        var harness = ManagedKeycloakAndAdfs();

        harness.Controller.SamlAdd("shib", new SamlConfig { SamlEndpoint = "https://shib2.example.invalid/sso" });

        Assert.Equal(
            "https://shib2.example.invalid/sso",
            SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs["shib"].SamlEndpoint));
    }

    [Fact]
    public void OidDel_UnmanagedProvider_StillDeletes_WhileAnotherProviderIsManaged()
    {
        var harness = ManagedKeycloakAndAdfs();

        harness.Controller.OidDel("hand-made");

        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs.ContainsKey("hand-made")));
    }

    [Fact]
    public void SamlDel_UnmanagedProvider_StillDeletes_WhileAnotherProviderIsManaged()
    {
        var harness = ManagedKeycloakAndAdfs();

        harness.Controller.SamlDel("shib");

        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs.ContainsKey("shib")));
    }

    [Fact]
    public void NoDeclarativeSource_LeavesAllFourDoorsExactlyAsTheyWere()
    {
        // Most installations mount nothing. If the guard read an empty set as "everything is managed" the
        // settings page would still work (it writes through Save) while the API doors all refused, which is
        // the regression a test of the refusal alone would not catch.
        var harness = new SsoControllerHarness(c =>
        {
            c.OidConfigs["keycloak"] = new OidConfig { OidClientId = "client-1" };
            c.SamlConfigs["adfs"] = new SamlConfig { SamlEndpoint = "https://adfs.example.invalid/sso" };
        });

        harness.Controller.OidAdd("keycloak", new OidConfig { OidClientId = "client-2" });
        harness.Controller.SamlAdd("adfs", new SamlConfig { SamlEndpoint = "https://adfs2.example.invalid/sso" });
        harness.Controller.OidDel("keycloak");
        harness.Controller.SamlDel("adfs");

        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs.ContainsKey("keycloak")));
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs.ContainsKey("adfs")));
        Assert.DoesNotContain(harness.ControllerLog.Entries, e => e.Message.Contains("refused", StringComparison.Ordinal));
    }

    [Fact]
    public void ImportConfig_DocumentNamingAManagedProvider_RefusesTheWholeDocument()
    {
        // The stated answer for the fifth door: the whole import is refused, not the managed entries
        // silently dropped. An administrator restoring a backup is told which providers stopped it, and the
        // provider the document did NOT own is not applied either - a half-applied restore is the state
        // nobody can see.
        var harness = ManagedKeycloakAndAdfs();

        var imported = new PluginConfiguration();
        imported.OidConfigs["keycloak"] = new OidConfig { OidClientId = "from-the-backup" };
        imported.OidConfigs["from-elsewhere"] = new OidConfig { OidClientId = "unrelated-client" };
        var document = new ConfigExportDocument { FormatVersion = ConfigExport.FormatVersion, Configuration = imported };

        var refusal = Assert.IsType<BadRequestObjectResult>(harness.Controller.ImportConfig(document));

        var message = Assert.IsType<string>(refusal.Value);
        AssertNamesTheSource(harness, message, "keycloak");
        Assert.Equal("declared-client", SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].OidClientId));
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs.ContainsKey("from-elsewhere")));
    }

    [Fact]
    public void ImportConfig_DocumentNamingNoManagedProvider_StillMerges()
    {
        var harness = ManagedKeycloakAndAdfs();

        var imported = new PluginConfiguration();
        imported.OidConfigs["from-elsewhere"] = new OidConfig { OidClientId = "unrelated-client" };
        var document = new ConfigExportDocument { FormatVersion = ConfigExport.FormatVersion, Configuration = imported };

        Assert.IsType<NoContentResult>(harness.Controller.ImportConfig(document));

        Assert.Equal(
            "unrelated-client",
            SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["from-elsewhere"].OidClientId));
    }

    [Fact]
    public void ImportConfig_RefusalNamesEveryManagedProviderItFound()
    {
        // The count is what makes the refusal actionable: an administrator editing the document out of the
        // first name only, and re-importing into the same refusal, is the loop a single name would create.
        var harness = ManagedKeycloakAndAdfs();

        var imported = new PluginConfiguration();
        imported.OidConfigs["keycloak"] = new OidConfig { OidClientId = "from-the-backup" };
        imported.SamlConfigs["adfs"] = new SamlConfig { SamlEndpoint = "https://backup.example.invalid/sso" };
        var document = new ConfigExportDocument { FormatVersion = ConfigExport.FormatVersion, Configuration = imported };

        var refusal = Assert.IsType<BadRequestObjectResult>(harness.Controller.ImportConfig(document));

        Assert.Contains("2 declaratively managed provider", Assert.IsType<string>(refusal.Value), StringComparison.Ordinal);
        Assert.Equal(
            2,
            harness.ControllerLog.Entries.Count(e => e.Message.Contains("Config/Import refused", StringComparison.Ordinal)));
    }

    [Fact]
    public void ImportConfig_RefusalIsSingleLine_SoItCannotSplitALogLine()
    {
        // The source is read from the environment or from a path an operator supplies, so it is not trusted
        // to be one line. The echoed body is the place a line ending would reach a log through a caller.
        var harness = new SsoControllerHarness(c => c.OidConfigs["keycloak"] = new OidConfig { OidClientId = "declared-client" });
        var declared = new PluginConfiguration();
        declared.OidConfigs["keycloak"] = new OidConfig { OidClientId = "declared-client" };
        SSOPlugin.Instance.ConfigStore.RecordDeclarativelyManaged(declared, "/mnt/sso.json\nINJECTED audit line");

        var imported = new PluginConfiguration();
        imported.OidConfigs["keycloak"] = new OidConfig { OidClientId = "from-the-backup" };
        var refusal = Assert.IsType<BadRequestObjectResult>(harness.Controller.ImportConfig(
            new ConfigExportDocument { FormatVersion = ConfigExport.FormatVersion, Configuration = imported }));

        var message = Assert.IsType<string>(refusal.Value);
        Assert.DoesNotContain('\n', message);
        Assert.DoesNotContain('\r', message);
    }
}
