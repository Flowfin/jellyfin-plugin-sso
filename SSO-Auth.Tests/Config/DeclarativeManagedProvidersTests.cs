// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Model.Plugins;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for the declarative freeze (#1102): a provider a mounted document or the environment decided is not
/// alterable through the config-page save, and the save that tried says so in the audit trail. The merge
/// rules the freeze rests on belong to <see cref="ConfigImport"/> and the loader's own behaviour to
/// <see cref="DeclarativeProviderConfigTests"/>; what is pinned here is the part an operator's deployment
/// depends on and cannot see - which providers end up managed, what a save to one does, and what a save to
/// an unmanaged provider on the same page still does.
/// </summary>
/// <remarks>
/// The unit is the PROVIDER rather than the field because the merge replaces a named provider whole (a field
/// the document omits comes back at its default at the next start), so a per-field freeze would promise a
/// granularity the loader does not have. <see cref="AFieldTheDocumentOmits_ComesBackAtItsDefault"/> is the
/// measurement that decides it, and it is a test rather than a sentence so the day the merge changes, this
/// reddens instead of the promise quietly becoming false.
/// </remarks>
public class DeclarativeManagedProvidersTests
{
    private const string Endpoint = "https://idp.example.invalid/.well-known/openid-configuration";

    private static (ProviderConfigStore Store, PluginConfiguration Live, List<BasePluginConfiguration> Persisted, CapturingLogger Log) CreateStore()
    {
        var live = new PluginConfiguration();
        var persisted = new List<BasePluginConfiguration>();
        var log = new CapturingLogger();
        return (new ProviderConfigStore(() => live, persisted.Add, log), live, persisted, log);
    }

    private static string Document(PluginConfiguration configuration) =>
        JsonSerializer.Serialize(new ConfigExportDocument
        {
            FormatVersion = ConfigExport.FormatVersion,
            Configuration = configuration,
        });

    private static DeclarativeLoadOutcome Load(ProviderConfigStore store, PluginConfiguration document, CapturingLogger? logger = null) =>
        DeclarativeProviderConfig.Apply(store, "/run/secrets/sso.json", _ => true, _ => Document(document), logger);

    // The shape a config-page save arrives in: a FRESH configuration object built from the page's snapshot,
    // never the live one. That is what makes ProviderConfigStore.Save run its pipeline at all.
    private static PluginConfiguration PostedFrom(PluginConfiguration live)
    {
        var posted = live.DetachedCopy();

        // The JSON boundary withholds the write-only secrets, so a real page save carries them blank. Blanked
        // here too, because a freeze that only looked right against a posted secret would be a test of the
        // wrong document.
        foreach (var kvp in posted.OidConfigs)
        {
            kvp.Value.OidSecret = null;
        }

        foreach (var kvp in posted.SamlConfigs)
        {
            kvp.Value.SamlSigningKeyPfx = null;
            kvp.Value.SamlRolloverSigningKeyPfx = null;
        }

        return posted;
    }

    private static IReadOnlyList<string> IgnoredWrites(CapturingLogger log) =>
        log.Entries
            .Where(e => e.Message.Contains("Configuration save ignored", StringComparison.Ordinal))
            .Select(e => e.Message)
            .ToList();

    [Fact]
    public void NoDeclarativeSource_ManagesNothing_AndASaveIsUnchanged()
    {
        // The pin the whole feature rests on: an installation that mounts nothing must save exactly as one
        // built before this existed. If the empty set ever froze anything, every deployment on earth would
        // stop being able to edit its providers, which is the worst failure this change could have.
        var (store, live, persisted, log) = CreateStore();
        live.OidConfigs["keycloak"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = "before" };

        var posted = PostedFrom(live);
        posted.OidConfigs["keycloak"].OidClientId = "after";
        store.Save(posted);

        Assert.True(store.ManagedProviders.IsEmpty);
        Assert.Equal("after", ((PluginConfiguration)persisted.Single()).OidConfigs["keycloak"].OidClientId);
        Assert.Empty(IgnoredWrites(log));
    }

    [Fact]
    public void ASaveToAManagedProvider_PersistsTheDeclarativeValue_AndAuditsTheIgnoredWrite()
    {
        // The first Done-when clause of #1102. An admin editing a file-managed provider on the settings page
        // is editing something the file wins back at the next start; without this the edit appears to hold
        // for as long as the server runs, which is the silent fight this issue exists to end.
        var (store, live, persisted, log) = CreateStore();
        var document = new PluginConfiguration();
        document.OidConfigs["keycloak"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = "from-the-file" };
        Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, document));

        var posted = PostedFrom(live);
        posted.OidConfigs["keycloak"].OidClientId = "typed-into-the-page";
        posted.OidConfigs["keycloak"].EnableAuthorization = true;
        store.Save(posted);

        var saved = (PluginConfiguration)persisted.Last();
        Assert.Equal("from-the-file", saved.OidConfigs["keycloak"].OidClientId);
        Assert.False(saved.OidConfigs["keycloak"].EnableAuthorization);

        var ignored = Assert.Single(IgnoredWrites(log));
        Assert.Contains("keycloak", ignored, StringComparison.Ordinal);
        Assert.Contains("OpenID", ignored, StringComparison.Ordinal);

        // The audit names WHICH provider, never what was posted to it: a rejected client id is still a value
        // an operator chose and the audit trail is read by more people than the settings page is.
        Assert.DoesNotContain("typed-into-the-page", ignored, StringComparison.Ordinal);
    }

    [Fact]
    public void ASaveToAnUnmanagedProviderOnTheSamePage_StillSavesNormally()
    {
        // The freeze is scoped to the providers a source NAMED. A deployment that manages one provider from a
        // file and adds a second through the page must keep the second editable, or config-as-code becomes
        // all-or-nothing and the feature is unusable for anyone migrating onto it.
        var (store, live, persisted, log) = CreateStore();
        live.OidConfigs["hand-made"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = "before" };

        var document = new PluginConfiguration();
        document.OidConfigs["keycloak"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = "from-the-file" };
        Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, document));

        var posted = PostedFrom(live);
        posted.OidConfigs["hand-made"].OidClientId = "after";
        store.Save(posted);

        var saved = (PluginConfiguration)persisted.Last();
        Assert.Equal("after", saved.OidConfigs["hand-made"].OidClientId);
        Assert.Equal("from-the-file", saved.OidConfigs["keycloak"].OidClientId);
        Assert.Empty(IgnoredWrites(log));
    }

    [Fact]
    public void ASaveThatDropsAManagedProvider_PutsItBack()
    {
        // Deleting a managed provider on the page would break every login against it until the next start, at
        // which point the source puts it back - so the deletion is never durable, only disruptive. Availability
        // rather than confidentiality: the failure is a working SSO login that stops answering.
        var (store, live, persisted, log) = CreateStore();
        var document = new PluginConfiguration();
        document.OidConfigs["keycloak"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = "from-the-file" };
        document.SamlConfigs["adfs"] = new SamlConfig { SamlEndpoint = "https://adfs.example.invalid/sso" };
        Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, document));

        var posted = PostedFrom(live);
        posted.OidConfigs.Remove("keycloak");
        posted.SamlConfigs.Remove("adfs");
        store.Save(posted);

        var saved = (PluginConfiguration)persisted.Last();
        Assert.Equal("from-the-file", saved.OidConfigs["keycloak"].OidClientId);
        Assert.True(saved.SamlConfigs.ContainsKey("adfs"));
        Assert.Equal(2, IgnoredWrites(log).Count);
    }

    [Fact]
    public void ASaveThatChangesNothingOnAManagedProvider_AuditsNothing()
    {
        // The noise guard, and the reason the freeze runs AFTER ServerManagedFields.Preserve. A page save
        // posts the whole configuration with the write-only secrets blank, so a comparison made before that
        // re-injection would call every unrelated settings change an ignored write - and an audit line that
        // fires on every save is one nobody reads on the save that mattered.
        var (store, live, persisted, log) = CreateStore();

        // The secret is seeded into the store rather than written into the document, because the document is
        // JSON and the JSON boundary withholds a secret in both directions (#189/#1096). The document names
        // the same provider identity and carries no secret, so blank-means-keep leaves this one stored - which
        // is exactly the state a real deployment is in after a secret reference resolved to what it already
        // had.
        live.OidConfigs["keycloak"] = new OidConfig
        {
            OidEndpoint = Endpoint,
            OidClientId = "from-the-file",
            OidSecret = "a-secret-the-page-never-sees",
        };

        var document = new PluginConfiguration();
        document.OidConfigs["keycloak"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = "from-the-file" };
        Assert.Equal(DeclarativeLoadOutcome.AlreadyCurrent, Load(store, document));

        var posted = PostedFrom(live);
        posted.EnableRateLimit = !posted.EnableRateLimit;
        store.Save(posted);

        Assert.Empty(IgnoredWrites(log));
        Assert.Equal("a-secret-the-page-never-sees", ((PluginConfiguration)persisted.Last()).OidConfigs["keycloak"].OidSecret);
    }

    [Fact]
    public void ADocumentRefusedBeforeItIsRead_ManagesNothing()
    {
        // Fail-closed in the direction that matters here: a document the loader refused changed nothing, so
        // freezing the providers it happened to name would hand a broken file authority over a configuration
        // it never applied - and leave an admin unable to repair it from the page. This is the arm refused by
        // the repeated-member screen, before the document is ever deserialized.
        var (store, _, _, _) = CreateStore();
        var log = new CapturingLogger();

        var outcome = DeclarativeProviderConfig.Apply(
            store,
            "/run/secrets/sso.json",
            _ => true,
            _ => "{\"FormatVersion\":1,\"Configuration\":{\"OidConfigs\":{\"keycloak\":{},\"keycloak\":{}}}}",
            log);

        Assert.Equal(DeclarativeLoadOutcome.Rejected, outcome);
        Assert.True(store.ManagedProviders.IsEmpty);
    }

    [Fact]
    public void ADocumentRefusedByTheMerge_ManagesNothing()
    {
        // The OTHER rejection arm, and the one the test above cannot reach. A document that parses, names a
        // provider and is then refused while being applied gets as far as the code that records the managed
        // set, so this is where "recorded before it was accepted" would hide. Written after a falsifier proved
        // the repeated-member case above passes with the recording moved AHEAD of the refusal - it never
        // reaches that line, so on its own it pins nothing about this order.
        var (store, live, persisted, _) = CreateStore();
        var document = new PluginConfiguration();

        // A provider name new to this instance carrying a URI-reserved character is refused by
        // ProviderConfigValidator inside ConfigImport (#336/#360), which is a refusal raised by the merge
        // rather than by the reader.
        document.OidConfigs["bad/name"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = "from-the-file" };

        Assert.Equal(DeclarativeLoadOutcome.Rejected, Load(store, document));
        Assert.True(store.ManagedProviders.IsEmpty);
        Assert.Empty(persisted);
        Assert.Empty(live.OidConfigs);
    }

    [Fact]
    public void ADocumentThatChangedNothing_StillManagesItsProviders()
    {
        // A restart that finds the mount already applied reports AlreadyCurrent. The providers are no less
        // decided by the file for it, and a freeze that depended on whether anything moved would release them
        // on exactly the boot an operator is least likely to notice: the ordinary one.
        var (store, _, _, _) = CreateStore();
        var document = new PluginConfiguration();
        document.OidConfigs["keycloak"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = "from-the-file" };

        Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, document));
        Assert.Equal(DeclarativeLoadOutcome.AlreadyCurrent, Load(store, document));

        Assert.Equal(new[] { "keycloak" }, store.ManagedProviders.OidConfigs);
    }

    [Fact]
    public void ASecondSourceDoesNotReleaseTheFirstSourcesProviders()
    {
        // The file applies first and the environment second (SSOPlugin's constructor). Each manages what it
        // named, so the set is a union: a deployment that mounts a file and sets one variable must not find
        // the file's providers editable again because the variable said nothing about them.
        var (store, _, _, _) = CreateStore();

        var fromFile = new PluginConfiguration();
        fromFile.OidConfigs["keycloak"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = "from-the-file" };
        Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, fromFile));

        var fromEnvironment = new PluginConfiguration();
        fromEnvironment.SamlConfigs["adfs"] = new SamlConfig { SamlEndpoint = "https://adfs.example.invalid/sso" };
        Assert.Equal(
            DeclarativeLoadOutcome.Applied,
            DeclarativeProviderConfig.ApplyDocument(
                store,
                new ConfigExportDocument { FormatVersion = ConfigExport.FormatVersion, Configuration = fromEnvironment },
                "JELLYFIN_SSO_CONFIG__",
                new CapturingLogger(),
                null));

        Assert.Equal(new[] { "keycloak" }, store.ManagedProviders.OidConfigs);
        Assert.Equal(new[] { "adfs" }, store.ManagedProviders.SamlConfigs);
    }

    [Fact]
    public void AFieldTheDocumentOmits_ComesBackAtItsDefault()
    {
        // The measurement the provider-level granularity rests on, kept as a test rather than as a sentence.
        // A document naming a provider decides ALL of it: an admin-set field the document is silent about is
        // gone at the next start, so a surface that froze three fields and left the rest editable would tell
        // the admin the opposite of what happens. The day the merge becomes per field, this reddens.
        var (store, live, _, _) = CreateStore();
        live.OidConfigs["keycloak"] = new OidConfig
        {
            OidEndpoint = Endpoint,
            OidClientId = "from-the-file",
            EnableAuthorization = true,
            DefaultProvider = "set-by-the-admin",
        };

        var document = new PluginConfiguration();
        document.OidConfigs["keycloak"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = "from-the-file" };
        Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, document));

        Assert.False(live.OidConfigs["keycloak"].EnableAuthorization);
        Assert.Null(live.OidConfigs["keycloak"].DefaultProvider);
    }

    [Fact]
    public void TheReportedSetIsNamesOnly_AndCarriesNoValue()
    {
        // What the admin surface is allowed to be told. The set exists to be rendered in a browser, so a
        // field value reaching it would widen what a config page holds - and a secret reaching it would be a
        // disclosure through the one door that was built to describe rather than to reveal.
        var (store, _, _, _) = CreateStore();
        var document = new PluginConfiguration();
        document.OidConfigs["keycloak"] = new OidConfig
        {
            OidEndpoint = Endpoint,
            OidClientId = "from-the-file",
            OidSecret = "PLAINTEXT-OIDC-SECRET",
        };
        Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, document));

        var json = JsonSerializer.Serialize(new ManagedProviderSetDocument
        {
            OidConfigs = store.ManagedProviders.OidConfigs,
            SamlConfigs = store.ManagedProviders.SamlConfigs,
        });

        Assert.Contains("keycloak", json, StringComparison.Ordinal);
        Assert.DoesNotContain("PLAINTEXT-OIDC-SECRET", json, StringComparison.Ordinal);
        Assert.DoesNotContain("ssoenc:", json, StringComparison.Ordinal);
        Assert.DoesNotContain(Endpoint, json, StringComparison.Ordinal);
    }

    [Fact]
    public void ThePersistedProviderIsWhatTheComparisonReads()
    {
        // A rotated client secret is withheld at the JSON boundary, so a JSON comparison would call the save
        // an unchanged provider and let the rotation through the freeze silently. The comparison is the XML
        // persisted form for that reason, and this is the case that separates the two.
        var (store, live, persisted, log) = CreateStore();
        live.OidConfigs["keycloak"] = new OidConfig
        {
            OidEndpoint = Endpoint,
            OidClientId = "from-the-file",
            OidSecret = "the-declared-secret",
        };

        var document = new PluginConfiguration();
        document.OidConfigs["keycloak"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = "from-the-file" };
        Assert.Equal(DeclarativeLoadOutcome.AlreadyCurrent, Load(store, document));

        var posted = PostedFrom(live);
        posted.OidConfigs["keycloak"].OidSecret = "rotated-through-the-page";
        store.Save(posted);

        Assert.Equal("the-declared-secret", ((PluginConfiguration)persisted.Last()).OidConfigs["keycloak"].OidSecret);
        Assert.Single(IgnoredWrites(log));
    }

    [Fact]
    public void AManagedProviderKeepsTheLinksALoginWroteAfterTheApply()
    {
        // The freeze re-injects the STORED provider, not a retained copy of the document, and this is what
        // that buys: a canonical link written by a login after the apply survives the next page save. Freezing
        // against the document instead would unlink every account on a managed provider on the first save.
        var (store, live, persisted, _) = CreateStore();
        var document = new PluginConfiguration();
        document.OidConfigs["keycloak"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = "from-the-file" };
        Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, document));

        var linked = Guid.Parse("55555555-5555-5555-5555-555555555555");
        store.Mutate(c => c.OidConfigs["keycloak"].CanonicalLinks["sub-1"] = linked);

        var posted = PostedFrom(live);
        posted.OidConfigs["keycloak"].OidClientId = "typed-into-the-page";
        store.Save(posted);

        Assert.Equal(linked, ((PluginConfiguration)persisted.Last()).OidConfigs["keycloak"].CanonicalLinks["sub-1"]);
    }

    [Fact]
    public void AFileDeclaredProvider_CarriesThePathAsItsSource()
    {
        // #1415: a write door that refuses has to say WHERE the change belongs, and the two sources are
        // edited in different places. Pinned on the loader rather than only at the door, so the attribution
        // is proven at the point it is recorded instead of at a point a test could hand-feed it.
        var (store, _, _, _) = CreateStore();
        var document = new PluginConfiguration();
        document.OidConfigs["keycloak"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = "from-the-file" };
        Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, document));

        Assert.Equal("/run/secrets/sso.json", store.ManagedProviders.OidSource("keycloak"));
        Assert.Null(store.ManagedProviders.OidSource("never-declared"));
        Assert.Null(store.ManagedProviders.SamlSource("keycloak"));
    }

    [Fact]
    public void AnEnvironmentDeclaredProvider_CarriesTheVariablePrefixAsItsSource()
    {
        // The other source, and the reason the attribution is not a path: an operator told to edit
        // "/run/secrets/sso.json" for a provider that came out of the environment would look at a file that
        // does not name it.
        var (store, _, _, _) = CreateStore();
        var variables = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            [DeclarativeEnvironmentConfig.Prefix + "OidConfigs__keycloak__OidEndpoint"] = Endpoint,
            [DeclarativeEnvironmentConfig.Prefix + "OidConfigs__keycloak__OidClientId"] = "from-the-environment",
        };

        Assert.Equal(DeclarativeLoadOutcome.Applied, DeclarativeEnvironmentConfig.Apply(store, variables, null));

        Assert.Equal(DeclarativeEnvironmentConfig.Prefix, store.ManagedProviders.OidSource("keycloak"));
    }

    [Fact]
    public void WhereBothSourcesNameOneProvider_TheAttributionIsTheOneThatAppliedLast()
    {
        // The sources apply in sequence and the environment is applied second, so the stored provider is the
        // environment's. Attributing it to the file would send an operator to edit a value the next start
        // would overwrite again, which is a worse answer than no attribution at all.
        var (store, _, _, _) = CreateStore();
        var document = new PluginConfiguration();
        document.OidConfigs["keycloak"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = "from-the-file" };
        Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, document));

        var variables = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            [DeclarativeEnvironmentConfig.Prefix + "OidConfigs__keycloak__OidEndpoint"] = Endpoint,
            [DeclarativeEnvironmentConfig.Prefix + "OidConfigs__keycloak__OidClientId"] = "from-the-environment",
        };
        Assert.Equal(DeclarativeLoadOutcome.Applied, DeclarativeEnvironmentConfig.Apply(store, variables, null));

        Assert.Equal(DeclarativeEnvironmentConfig.Prefix, store.ManagedProviders.OidSource("keycloak"));
    }

    [Fact]
    public void ASecondSourceThatNamesNothing_ReleasesNothingTheFirstOneDeclared()
    {
        // The union rule the set already carried, re-asserted now that each name also carries a value: a
        // dictionary rebuild that dropped the earlier entries would silently reopen every write door on a
        // provider the file owns.
        var (store, _, _, _) = CreateStore();
        var document = new PluginConfiguration();
        document.OidConfigs["keycloak"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = "from-the-file" };
        Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, document));

        Assert.Equal(
            DeclarativeLoadOutcome.NotConfigured,
            DeclarativeEnvironmentConfig.Apply(store, new Dictionary<string, string?>(StringComparer.Ordinal), null));

        Assert.Equal("/run/secrets/sso.json", store.ManagedProviders.OidSource("keycloak"));
    }
}
