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

    [Fact]
    public void ImportConfig_DocumentRedefiningAManagedProfile_RefusesTheWholeDocument()
    {
        // The sixth door, one object over from the fifth. A managed provider writes its named provisioning
        // profile onto every account it creates, so a document that names NO provider and only redefines that
        // profile changes what the managed provider grants - past a refusal that reads provider names only.
        var harness = new SsoControllerHarness(c =>
        {
            c.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 1 };
            c.OidConfigs["keycloak"] = new OidConfig { OidClientId = "declared-client", ProvisioningProfile = "guest" };
        });

        Manage(declared =>
        {
            declared.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 1 };
            declared.OidConfigs["keycloak"] = new OidConfig { OidClientId = "declared-client", ProvisioningProfile = "guest" };
        });

        var imported = new PluginConfiguration();
        imported.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 999 };
        imported.ProvisioningProfiles["from-elsewhere"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 5 };
        var document = new ConfigExportDocument { FormatVersion = ConfigExport.FormatVersion, Configuration = imported };

        var refusal = Assert.IsType<BadRequestObjectResult>(harness.Controller.ImportConfig(document));

        AssertNamesTheSource(harness, Assert.IsType<string>(refusal.Value), "guest");
        Assert.Equal(1, SSOPlugin.Instance.ReadConfiguration(c => c.ProvisioningProfiles["guest"].MaxActiveSessions));

        // Nothing of the document was applied, which is the whole-document half of the refusal.
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.ProvisioningProfiles.ContainsKey("from-elsewhere")));
    }

    [Fact]
    public void ImportConfig_DocumentRedefiningNoManagedProfile_StillMerges()
    {
        // The half that would otherwise break in silence for every installation that defines a profile by
        // hand: a document carrying a profile no source declared must still import.
        var harness = new SsoControllerHarness(c =>
            c.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 1 });

        Manage(declared =>
            declared.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 1 });

        var imported = new PluginConfiguration();
        imported.ProvisioningProfiles["from-elsewhere"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 5 };
        var document = new ConfigExportDocument { FormatVersion = ConfigExport.FormatVersion, Configuration = imported };

        Assert.IsType<NoContentResult>(harness.Controller.ImportConfig(document));

        Assert.Equal(5, SSOPlugin.Instance.ReadConfiguration(c => c.ProvisioningProfiles["from-elsewhere"].MaxActiveSessions));
        Assert.Equal(1, SSOPlugin.Instance.ReadConfiguration(c => c.ProvisioningProfiles["guest"].MaxActiveSessions));
    }

    [Fact]
    public void ImportConfig_ProfileRefusalIsSingleLine_SoItCannotSplitALogLine()
    {
        // The source is a path an operator supplies, so it is not trusted to be one line, and the echoed
        // body is the place a line ending would reach a log through a caller.
        var harness = new SsoControllerHarness(c =>
            c.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 1 });

        var declared = new PluginConfiguration();
        declared.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 1 };
        SSOPlugin.Instance.ConfigStore.RecordDeclarativelyManaged(declared, "/mnt/sso.json\nINJECTED audit line");

        var imported = new PluginConfiguration();
        imported.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 999 };
        var refusal = Assert.IsType<BadRequestObjectResult>(harness.Controller.ImportConfig(
            new ConfigExportDocument { FormatVersion = ConfigExport.FormatVersion, Configuration = imported }));

        var message = Assert.IsType<string>(refusal.Value);
        Assert.DoesNotContain('\n', message);
        Assert.DoesNotContain('\r', message);
    }
}
