// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json.Serialization;
using System.Xml.Serialization;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Model.Plugins;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="DeclarativeEnvironmentConfig"/> - the environment half of the declarative provider
/// configuration (#1097). The merge itself belongs to <see cref="ConfigImport"/> and the atomicity to
/// <see cref="DeclarativeProviderConfig"/>, both already pinned elsewhere; what is pinned here is what this
/// source adds: the naming scheme and its type handling, that no field of the model is silently
/// unconfigurable, that anything under the prefix this source cannot place refuses the whole environment
/// rather than half-configuring a provider, and the silent no-op when nothing is set. The store is driven
/// with local delegates and a supplied variable map, so no plugin instance and no process environment are
/// involved.
/// </summary>
public class DeclarativeEnvironmentConfigTests
{
    private const string Endpoint = "https://idp.example.invalid/.well-known/openid-configuration";
    private const string ClientId = "the-client";

    private static (ProviderConfigStore Store, PluginConfiguration Live, List<BasePluginConfiguration> Persisted) CreateStore()
    {
        var live = new PluginConfiguration();
        var persisted = new List<BasePluginConfiguration>();
        return (new ProviderConfigStore(() => live, persisted.Add, new CapturingLogger()), live, persisted);
    }

    private static string Xml(PluginConfiguration configuration)
    {
        using var writer = new StringWriter(CultureInfo.InvariantCulture);
        new XmlSerializer(typeof(PluginConfiguration)).Serialize(writer, configuration);
        return writer.ToString();
    }

    private static Dictionary<string, string?> Variables(params (string Name, string? Value)[] entries)
    {
        var map = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            // A variable this source does not own, present in every case, so "reads only its own prefix" is
            // exercised by every test rather than by one.
            ["PATH"] = "/usr/bin",
            [DeclarativeProviderConfig.SourcePathVariable] = "/run/secrets/sso.json",
        };

        foreach (var (name, value) in entries)
        {
            map[name] = value;
        }

        return map;
    }

    private static (string Name, string? Value) Oid(string provider, string field, string? value) =>
        ($"{DeclarativeEnvironmentConfig.Prefix}OidConfigs__{provider}__{field}", value);

    private static DeclarativeLoadOutcome Load(
        ProviderConfigStore store,
        Dictionary<string, string?> variables,
        CapturingLogger? logger = null) =>
        DeclarativeEnvironmentConfig.Apply(store, variables, logger);

    // A provider the validator accepts, spelled entirely in variables.
    private static (string Name, string? Value)[] AWorkingProvider(string provider = "keycloak") =>
    [
        Oid(provider, "OidEndpoint", Endpoint),
        Oid(provider, "OidClientId", ClientId),
        Oid(provider, "Enabled", "true"),
    ];

    [Fact]
    public void NoVariableUnderThePrefix_ReadsNothing_WritesNothing_AndSaysSo()
    {
        // The pin the whole feature rests on. An installation that sets none of these must behave exactly as
        // one built before this existed, and the neighbouring variable named by the FILE source must not be
        // mistaken for one of ours - its name starts with the same letters.
        var (store, live, persisted) = CreateStore();
        var before = Xml(live);

        Assert.Equal(DeclarativeLoadOutcome.NotConfigured, Load(store, Variables()));

        Assert.Empty(persisted);
        Assert.Equal(before, Xml(live));
    }

    [Fact]
    public void AProviderSpelledInVariables_IsApplied()
    {
        var (store, live, persisted) = CreateStore();

        Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, Variables(AWorkingProvider())));

        var applied = Assert.IsType<PluginConfiguration>(Assert.Single(persisted));
        Assert.Equal(Endpoint, applied.OidConfigs["keycloak"].OidEndpoint);
        Assert.Equal(ClientId, applied.OidConfigs["keycloak"].OidClientId);
        Assert.True(applied.OidConfigs["keycloak"].Enabled);
        Assert.Equal(Endpoint, live.OidConfigs["keycloak"].OidEndpoint);
    }

    [Fact]
    public void AProviderNobodyDeclared_IsLeftExactlyAsItIs()
    {
        // The precedence is a MERGE, inherited from the import the file source already goes through. A
        // deployment that declares one provider from the environment does not lose the ones it configured on
        // the settings page.
        var (store, live, _) = CreateStore();
        live.OidConfigs["already-there"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = "kept", Enabled = true };

        Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, Variables(AWorkingProvider())));

        Assert.Equal("kept", live.OidConfigs["already-there"].OidClientId);
        Assert.Equal(ClientId, live.OidConfigs["keycloak"].OidClientId);
    }

    [Theory]
    [InlineData("EnableRateLimit", "false")]
    [InlineData("RateLimitMaxAttempts", "7")]
    [InlineData("DisablePasswordLogin", "true")]
    [InlineData("BreakGlassAdminUsername", "root")]
    public void ASettingTheApplyDoesNotReach_IsRefusedRatherThanDropped(string field, string value)
    {
        // These four are deliberately not applied by ConfigImport: instance-local operational tuning with no
        // blank-means-keep signal, and a mode that needs a user manager to prove a surviving password door.
        // Accepting a variable for one of them would write it into the document and let the apply drop it,
        // which is a configuration that reads as applied and changed nothing - the exact failure the
        // hard-error rule exists against. Delete the DeclaredSurface check and this goes red, because the
        // variable would be accepted and the setting would still not move.
        var (store, live, persisted) = CreateStore();
        var before = Xml(live);

        Assert.Equal(
            DeclarativeLoadOutcome.Rejected,
            Load(store, Variables(($"{DeclarativeEnvironmentConfig.Prefix}{field}", value))));

        Assert.Empty(persisted);
        Assert.Equal(before, Xml(live));
    }

    [Fact]
    public void AWholeNumberOnAProvider_IsRead()
    {
        var (store, live, _) = CreateStore();

        Assert.Equal(
            DeclarativeLoadOutcome.Applied,
            Load(store, Variables([.. AWorkingProvider(), Oid("keycloak", "MaxAge", "300")])));

        Assert.Equal(300, live.OidConfigs["keycloak"].MaxAge);
    }

    [Fact]
    public void AListIsAddressedByIndexFromZero()
    {
        var (store, live, _) = CreateStore();
        var variables = Variables(
            [
                .. AWorkingProvider(),
                Oid("keycloak", "Roles__0", "media"),
                Oid("keycloak", "Roles__1", "staff"),
            ]);

        Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, variables));

        Assert.Equal(new[] { "media", "staff" }, live.OidConfigs["keycloak"].Roles);
    }

    [Fact]
    public void AListOfObjects_IsAddressedByIndexThenField()
    {
        // The role maps are lists of objects, which is the shape a table of environment variables is worst
        // at. It is reachable under the same rule as everything else rather than under a special case.
        var (store, live, _) = CreateStore();
        var variables = Variables(
            [
                .. AWorkingProvider(),
                Oid("keycloak", "EnableFolderRoles", "true"),
                Oid("keycloak", "FolderRoleMapping__0__Role", "staff"),
                Oid("keycloak", "FolderRoleMapping__0__Folders__0", "library-a"),
            ]);

        Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, variables));

        var mapping = Assert.Single(live.OidConfigs["keycloak"].FolderRoleMapping!);
        Assert.Equal("staff", mapping.Role);
        Assert.Equal(new[] { "library-a" }, mapping.Folders);
    }

    [Fact]
    public void AVariableSpelledInAnotherCase_ReachesTheSameField()
    {
        // The mounted file matches a member without regard to case because it is hand-written as often as it
        // is exported. A variable is hand-written every time, so it holds the same rule.
        var (store, live, _) = CreateStore();
        var variables = Variables(
            [
                .. AWorkingProvider(),
                Oid("keycloak", "hideloginbutton", "true"),
            ]);

        Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, variables));

        Assert.True(live.OidConfigs["keycloak"].HideLoginButton);
    }

    [Fact]
    public void AProviderNameIsTakenVerbatim()
    {
        // A key names a provider the operator chose. Matching it against anything, or normalising its case,
        // would make the environment address a different provider from the one the settings page shows.
        var (store, live, _) = CreateStore();

        Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, Variables(AWorkingProvider("KeyCloak-Prod"))));

        Assert.True(live.OidConfigs.ContainsKey("KeyCloak-Prod"));
        Assert.False(live.OidConfigs.ContainsKey("keycloak-prod"));
    }

    [Fact]
    public void ASecretIsSetDirectly()
    {
        // #1096 refuses a spelled-out secret in the mounted FILE and takes a reference, and one of the two
        // reference forms it accepts is an environment variable. This is that variable, so a value here is
        // the same disclosure the file's reference form already points at.
        var (store, live, _) = CreateStore();
        var variables = Variables([.. AWorkingProvider(), Oid("keycloak", "OidSecret", "s3cret")]);

        Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, variables));

        Assert.False(string.IsNullOrEmpty(live.OidConfigs["keycloak"].OidSecret));
    }

    [Fact]
    public void AnUnrecognisedVariableUnderThePrefix_RefusesEverything()
    {
        // The load-bearing refusal. A typo in one variable must not leave the other nine applied: a provider
        // carrying most of what a deployment asked for is a provider whose remaining fields silently hold
        // whatever was there before, which is the failure this whole source exists to remove. Delete the
        // refusal in TryResolveStep and this test goes red on the second assertion, because the good
        // variables would apply around the bad one.
        var (store, live, persisted) = CreateStore();
        var logger = new CapturingLogger();
        var before = Xml(live);
        var variables = Variables(
            [
                .. AWorkingProvider(),
                Oid("keycloak", "OidClientld", "typo-in-the-field-name"),
            ]);

        Assert.Equal(DeclarativeLoadOutcome.Rejected, Load(store, variables, logger));

        Assert.Empty(persisted);
        Assert.Equal(before, Xml(live));
        Assert.False(live.OidConfigs.ContainsKey("keycloak"));
    }

    [Theory]
    [InlineData("Enabled", "yes")]
    [InlineData("Enabled", "1")]
    [InlineData("MaxAge", "soon")]
    [InlineData("MaxAge", "1.5")]
    public void AValueThatIsNotTheFieldsType_RefusesEverything(string field, string value)
    {
        var (store, live, persisted) = CreateStore();
        var variables = Variables([.. AWorkingProvider(), Oid("keycloak", field, value)]);

        Assert.Equal(DeclarativeLoadOutcome.Rejected, Load(store, variables));

        Assert.Empty(persisted);
        Assert.False(live.OidConfigs.ContainsKey("keycloak"));
    }

    [Fact]
    public void AListWithAHoleInIt_RefusesEverything()
    {
        // Index 1 without index 0 deserializes to a list whose first entry is null, which is a different
        // configuration from the one that was written and reads downstream as an empty role rather than as a
        // mistake. Refused rather than closed up, because closing it up would silently renumber what the
        // operator wrote.
        var (store, live, persisted) = CreateStore();
        var variables = Variables([.. AWorkingProvider(), Oid("keycloak", "Roles__1", "staff")]);

        Assert.Equal(DeclarativeLoadOutcome.Rejected, Load(store, variables));

        Assert.Empty(persisted);
        Assert.False(live.OidConfigs.ContainsKey("keycloak"));
    }

    [Theory]
    [InlineData("CanonicalLinkIssuers__somebody", "https://idp.example.invalid/")]
    [InlineData("CanonicalLinks__somebody", "00000000-0000-0000-0000-000000000001")]
    public void AServerManagedFieldCannotBeSet(string field, string value)
    {
        // The link maps and the issuer bindings are withheld from the JSON boundary and re-injected on every
        // write, so a variable aimed at one would be accepted, written into the document and then dropped by
        // the deserializer - a configuration that looks applied and is not. They are refused by name instead.
        //
        // The first case is the one that proves the refusal rather than something else: its value type is a
        // plain string, so with the JsonIgnore check deleted the variable is placed happily and the whole
        // environment applies while that field stays empty. Delete the check and this case goes red.
        var (store, live, persisted) = CreateStore();
        var variables = Variables([.. AWorkingProvider(), Oid("keycloak", field, value)]);

        Assert.Equal(DeclarativeLoadOutcome.Rejected, Load(store, variables));

        Assert.Empty(persisted);
        Assert.False(live.OidConfigs.ContainsKey("keycloak"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("OidConfigs__")]
    [InlineData("OidConfigs____keycloak")]
    public void APathThatIsNotOne_RefusesEverything(string path)
    {
        var (store, _, persisted) = CreateStore();

        Assert.Equal(
            DeclarativeLoadOutcome.Rejected,
            Load(store, Variables(($"{DeclarativeEnvironmentConfig.Prefix}{path}", "x"))));

        Assert.Empty(persisted);
    }

    [Fact]
    public void AProviderTheValidatorRefuses_LeavesTheStoredConfigurationByteIdentical()
    {
        // The refusal comes from the same validator every other write path uses, reached through the same
        // apply, so this pins the reach rather than the rule: a base-URL override that is not an absolute
        // http(s) origin is refused on the settings page and on an import, and it is refused here too. What
        // matters is that reaching it from the environment leaves nothing behind.
        var (store, live, persisted) = CreateStore();
        var before = Xml(live);
        var variables = Variables([.. AWorkingProvider(), Oid("keycloak", "BaseUrlOverride", "not-an-absolute-url")]);

        Assert.Equal(DeclarativeLoadOutcome.Rejected, Load(store, variables));

        Assert.Empty(persisted);
        Assert.Equal(before, Xml(live));
        Assert.False(live.OidConfigs.ContainsKey("keycloak"));
    }

    [Fact]
    public void TheSameEnvironmentAppliedTwice_WritesNothingTheSecondTime()
    {
        // A container restarts with the same variables every time. If that rewrote config.xml on every boot,
        // the feature would churn the file it is meant to describe.
        var (store, _, persisted) = CreateStore();
        var variables = Variables(AWorkingProvider());

        Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, variables));
        Assert.Single(persisted);

        Assert.Equal(DeclarativeLoadOutcome.AlreadyCurrent, Load(store, variables));
        Assert.Single(persisted);
    }

    [Fact]
    public void TheEnvironmentWinsOverAMountedFile_AndOverWhatIsStored()
    {
        // The precedence rule, asserted across both sources rather than described. The two are applied in the
        // order the plugin's constructor applies them: the file first, the environment second. The unit of
        // precedence is a PROVIDER, because the apply merges by provider - so the environment declares the
        // provider whole, exactly as the file does.
        var (store, live, _) = CreateStore();
        live.OidConfigs["untouched"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = "stored", Enabled = true };

        var file = new PluginConfiguration();
        file.OidConfigs["keycloak"] = new OidConfig
        {
            OidEndpoint = Endpoint,
            OidClientId = "from-the-file",
            Enabled = true,
        };

        Assert.Equal(
            DeclarativeLoadOutcome.Applied,
            DeclarativeProviderConfig.Apply(
                store,
                "/run/secrets/sso.json",
                _ => true,
                _ => System.Text.Json.JsonSerializer.Serialize(new ConfigExportDocument
                {
                    FormatVersion = ConfigExport.FormatVersion,
                    Configuration = file,
                }),
                null));

        Assert.Equal("from-the-file", live.OidConfigs["keycloak"].OidClientId);

        Assert.Equal(
            DeclarativeLoadOutcome.Applied,
            Load(store, Variables(
                Oid("keycloak", "OidEndpoint", Endpoint),
                Oid("keycloak", "OidClientId", "from-the-environment"),
                Oid("keycloak", "Enabled", "true"))));

        Assert.Equal("from-the-environment", live.OidConfigs["keycloak"].OidClientId);
        Assert.Equal(Endpoint, live.OidConfigs["keycloak"].OidEndpoint);

        // Neither source named this one, so neither touched it.
        Assert.Equal("stored", live.OidConfigs["untouched"].OidClientId);
    }

    [Fact]
    public void NamingOneFieldOfAnExistingProvider_LeavesTheRestAtItsDefaults()
    {
        // The trap worth pinning rather than only documenting: the apply merges by provider, so a partial
        // declaration is a whole provider whose other fields are defaults - and on an OpenID provider a
        // blanked client id is a repoint, which clears that provider's links. A deployment declares every
        // field of a provider it owns from the environment.
        var (store, live, _) = CreateStore();
        live.OidConfigs["keycloak"] = new OidConfig
        {
            OidEndpoint = Endpoint,
            OidClientId = "was-here",
            Enabled = true,
            HideLoginButton = true,
        };

        Assert.Equal(
            DeclarativeLoadOutcome.Applied,
            Load(store, Variables(Oid("keycloak", "OidEndpoint", Endpoint))));

        Assert.Equal(Endpoint, live.OidConfigs["keycloak"].OidEndpoint);
        Assert.Equal(string.Empty, live.OidConfigs["keycloak"].OidClientId);
        Assert.False(live.OidConfigs["keycloak"].HideLoginButton);
    }

    [Fact]
    public void EveryProviderFieldTheModelCarries_IsReachableFromTheEnvironment()
    {
        // The guard behind the whole naming scheme, and the reason the scheme is resolved against the model
        // instead of against a table somebody maintains. It walks the configuration types and asserts that
        // every settable property is addressable and lands on a leaf kind this source can write, so a field
        // added tomorrow is either reachable or fails the build - never silently unconfigurable.
        //
        // A property withheld from the JSON boundary is deliberately NOT expected to be reachable: it is
        // server-managed, and refusing it is the behaviour AServerManagedFieldCannotBeSet pins.
        var unreachable = new List<string>();
        Walk(typeof(OidConfig), $"{DeclarativeEnvironmentConfig.Prefix}OidConfigs__[provider]", unreachable, []);
        Walk(typeof(SamlConfig), $"{DeclarativeEnvironmentConfig.Prefix}SamlConfigs__[provider]", unreachable, []);

        Assert.Empty(unreachable);
    }

    [Fact]
    public void TheReachabilityWalkActuallyWalksSomething()
    {
        // A walk that visited nothing would pass the test above while proving nothing, which is the way an
        // emptiness assertion usually goes wrong. Pin the population instead of trusting it.
        var visited = new List<string>();
        WalkNames(typeof(OidConfig), visited, []);
        WalkNames(typeof(SamlConfig), visited, []);

        Assert.Contains($"{nameof(OidConfig)}.{nameof(OidConfig.OidClientId)}", visited);
        Assert.Contains($"{nameof(SamlConfig)}.{nameof(SamlConfig.SamlEndpoint)}", visited);
        Assert.Contains($"{nameof(FolderRoleMap)}.{nameof(FolderRoleMap.Folders)}", visited);
        Assert.Contains($"{nameof(ProvisioningPolicyTemplate)}.{nameof(ProvisioningPolicyTemplate.SubtitleMode)}", visited);
        Assert.True(visited.Count > 60, $"the walk reached only {visited.Count} properties");
    }

    private static void WalkNames(Type type, List<string> visited, HashSet<Type> seen)
    {
        if (!seen.Add(type))
        {
            return;
        }

        foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (property.SetMethod is null
                || !property.SetMethod.IsPublic
                || property.GetCustomAttribute<JsonIgnoreAttribute>() is not null)
            {
                continue;
            }

            visited.Add($"{type.Name}.{property.Name}");
            var slot = Nullable.GetUnderlyingType(property.PropertyType) ?? property.PropertyType;
            while (DeclarativeEnvironmentConfig.TryResolveStep(slot, "0", out var inner, out _, out _) && inner != slot)
            {
                slot = inner;
            }

            if (slot != typeof(string) && slot != typeof(bool) && slot != typeof(int) && slot.IsClass)
            {
                WalkNames(slot, visited, seen);
            }
        }
    }

    private static void Walk(Type type, string path, List<string> unreachable, HashSet<Type> seen)
    {
        if (!seen.Add(type))
        {
            return;
        }

        foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (property.SetMethod is null
                || !property.SetMethod.IsPublic
                || property.GetCustomAttribute<JsonIgnoreAttribute>() is not null)
            {
                continue;
            }

            var here = $"{path}__{property.Name}";
            if (!DeclarativeEnvironmentConfig.TryResolveStep(type, property.Name, out var addressed, out _, out var rejection))
            {
                unreachable.Add($"{here}: {rejection}");
                continue;
            }

            WalkSlot(addressed, here, unreachable, seen);
        }
    }

    private static void WalkSlot(Type slot, string path, List<string> unreachable, HashSet<Type> seen)
    {
        if (slot == typeof(string) || slot == typeof(bool) || slot == typeof(int))
        {
            return;
        }

        // A dictionary or a list is one more step, and the step after it is the value's own surface. Driven
        // through the same resolver the loader uses, so what the test walks is what the loader would walk.
        if (DeclarativeEnvironmentConfig.TryResolveStep(slot, "0", out var inner, out _, out _)
            && inner != slot)
        {
            WalkSlot(inner, $"{path}__0", unreachable, seen);
            return;
        }

        if (slot.IsClass)
        {
            Walk(slot, path, unreachable, seen);
            return;
        }

        unreachable.Add($"{path}: a {slot.Name} cannot be written as a single variable");
    }
}
