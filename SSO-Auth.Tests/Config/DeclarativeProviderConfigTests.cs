// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Xml.Serialization;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Model.Plugins;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="DeclarativeProviderConfig"/> - the startup loader that applies a mounted provider
/// document over the stored configuration (#1095). The merge rules themselves belong to
/// <see cref="ConfigImport"/> and are pinned by <see cref="ConfigExportImportTests"/>; what is pinned here
/// is what the loader adds on top of them and what a deployment depends on: the silent no-op when no source
/// is configured, that every rejection leaves the stored configuration byte-identical, that the precedence
/// is a merge rather than a replace, and that re-applying an unchanged document writes nothing so a restart
/// loop cannot churn <c>config.xml</c>. The store is driven directly with local delegates, so no plugin
/// instance and no filesystem are involved.
/// </summary>
public class DeclarativeProviderConfigTests
{
    private static readonly Guid Linked = Guid.Parse("55555555-5555-5555-5555-555555555555");

    private const string Endpoint = "https://idp.example.invalid/.well-known/openid-configuration";
    private const string ClientId = "the-client";

    private static (ProviderConfigStore Store, PluginConfiguration Live, List<BasePluginConfiguration> Persisted) CreateStore()
    {
        var live = new PluginConfiguration();
        var persisted = new List<BasePluginConfiguration>();
        return (new ProviderConfigStore(() => live, persisted.Add, new CapturingLogger()), live, persisted);
    }

    // The document a deployment mounts: the same shape the admin export produces, serialized the same way.
    private static string Document(PluginConfiguration configuration, int? formatVersion = null) =>
        JsonSerializer.Serialize(new ConfigExportDocument
        {
            FormatVersion = formatVersion ?? ConfigExport.FormatVersion,
            Configuration = configuration,
        });

    private static string Xml(PluginConfiguration configuration)
    {
        using var writer = new StringWriter(CultureInfo.InvariantCulture);
        new XmlSerializer(typeof(PluginConfiguration)).Serialize(writer, configuration);
        return writer.ToString();
    }

    private static DeclarativeLoadOutcome Load(ProviderConfigStore store, string text, CapturingLogger? logger = null) =>
        DeclarativeProviderConfig.Apply(store, "/run/secrets/sso.json", _ => true, _ => text, logger);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void NoSourcePath_ReadsNothing_WritesNothing_AndSaysSo(string? sourcePath)
    {
        // The no-op is the pin the whole feature rests on: an installation that never sets the variable must
        // behave exactly as one built before this existed. Reading the file or persisting the configuration
        // would both be visible here, and the delegates fail the test loudly rather than being ignored.
        var (store, live, persisted) = CreateStore();
        var before = Xml(live);

        var outcome = DeclarativeProviderConfig.Apply(
            store,
            sourcePath,
            _ => throw new Xunit.Sdk.XunitException("An unconfigured source must not be probed on disk."),
            _ => throw new Xunit.Sdk.XunitException("An unconfigured source must not be read."),
            new CapturingLogger());

        Assert.Equal(DeclarativeLoadOutcome.NotConfigured, outcome);
        Assert.Empty(persisted);
        Assert.Equal(before, Xml(live));
    }

    [Fact]
    public void MissingFile_IsRejected_AndTheStoredConfigurationIsUntouched()
    {
        // A path that names nothing is a misconfiguration, not a licence to carry on quietly: the operator
        // asked for a file to decide the providers and the server is about to run on something else.
        var (store, live, persisted) = CreateStore();
        live.OidConfigs["kept"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = ClientId };
        var before = Xml(live);
        var logger = new CapturingLogger();

        var outcome = DeclarativeProviderConfig.Apply(
            store,
            "/run/secrets/absent.json",
            _ => false,
            _ => throw new Xunit.Sdk.XunitException("A file that does not exist must not be read."),
            logger);

        Assert.Equal(DeclarativeLoadOutcome.Rejected, outcome);
        Assert.Empty(persisted);
        Assert.Equal(before, Xml(live));
        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Error);
    }

    [Fact]
    public void UnparseableDocument_IsRejected_AndTheStoredConfigurationIsByteIdentical()
    {
        var (store, live, persisted) = CreateStore();
        live.OidConfigs["kept"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = ClientId };
        var before = Xml(live);
        var logger = new CapturingLogger();

        Assert.Equal(DeclarativeLoadOutcome.Rejected, Load(store, "{ this is not json", logger));

        Assert.Empty(persisted);
        Assert.Equal(before, Xml(live));
        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Error);
    }

    [Fact]
    public void DocumentNamingAMemberTwice_IsRejected_RatherThanLettingTheParserChoose()
    {
        // A repeated member makes the document say two things, and which of them wins is the deserializer's
        // decision rather than the operator's. On this surface that decision is a client id, an endpoint or
        // a secret, so the document is refused before it is deserialized at all.
        var (store, live, persisted) = CreateStore();
        var before = Xml(live);
        var logger = new CapturingLogger();

        const string Twice = """
            {
              "FormatVersion": 1,
              "Configuration": {
                "OidConfigs": {
                  "kc": { "OidClientId": "first", "OidClientId": "second" }
                }
              }
            }
            """;

        Assert.Equal(DeclarativeLoadOutcome.Rejected, Load(store, Twice, logger));

        Assert.Empty(persisted);
        Assert.Equal(before, Xml(live));
        Assert.Contains(
            logger.Entries,
            entry => entry.Level == LogLevel.Error && entry.Message.Contains("twice", StringComparison.Ordinal));
    }

    [Fact]
    public void UnsupportedFormatVersion_IsRejected_AndTheStoredConfigurationIsByteIdentical()
    {
        // A shape this plugin does not understand is refused whole rather than half-applied, which is
        // ConfigImport's rule reached through the loader: the version gate has to fire before the merge, not
        // after part of it.
        var (store, live, persisted) = CreateStore();
        live.OidConfigs["kept"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = ClientId };
        var before = Xml(live);

        var incoming = new PluginConfiguration();
        incoming.OidConfigs["arriving"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = "other" };

        Assert.Equal(
            DeclarativeLoadOutcome.Rejected,
            Load(store, Document(incoming, ConfigExport.FormatVersion + 1)));

        Assert.Empty(persisted);
        Assert.Equal(before, Xml(live));
        Assert.False(live.OidConfigs.ContainsKey("arriving"));
    }

    [Fact]
    public void OneInvalidProvider_RejectsTheWholeDocument_IncludingItsValidProviders()
    {
        // Fail-closed as a UNIT. A document that is right about one provider and wrong about another applies
        // neither, because a partly-applied provider set is a server whose login behaviour matches no
        // document anybody holds. The invalid entry is the zero-hour guest duration ProviderConfigValidator
        // already refuses (ProviderConfigValidatorTests).
        var (store, live, persisted) = CreateStore();
        var before = Xml(live);

        var incoming = new PluginConfiguration();
        incoming.OidConfigs["good"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = ClientId };
        incoming.OidConfigs["bad"] = new OidConfig
        {
            OidEndpoint = Endpoint,
            OidClientId = "second",
            GuestAccessDurationRoleMappings = new List<GuestAccessDurationRoleMap>
            {
                new GuestAccessDurationRoleMap { DurationHours = 0, Roles = new[] { "guest" } },
            },
        };

        Assert.Equal(DeclarativeLoadOutcome.Rejected, Load(store, Document(incoming)));

        Assert.Empty(persisted);
        Assert.Equal(before, Xml(live));
        Assert.False(live.OidConfigs.ContainsKey("good"));
        Assert.False(live.OidConfigs.ContainsKey("bad"));
    }

    [Fact]
    public void DocumentAssertingSsoOnlyLogin_IsRejected_BecauseNoSafeAdminCanBeProven()
    {
        // The loader runs while the plugin is being constructed, where there is no user manager to resolve a
        // break-glass admin with, so the SSO-only guard cannot be satisfied and refuses. That is deliberate
        // rather than incidental: turning off password login for a whole server is an elevated, audited act
        // on the SSO-Only endpoints, and a file dropped into a mount is not that.
        var (store, live, persisted) = CreateStore();
        var before = Xml(live);

        var incoming = new PluginConfiguration { DisablePasswordLogin = true, BreakGlassAdminUsername = "rescue" };
        incoming.OidConfigs["arriving"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = ClientId };

        Assert.Equal(DeclarativeLoadOutcome.Rejected, Load(store, Document(incoming)));

        Assert.Empty(persisted);
        Assert.Equal(before, Xml(live));
        Assert.False(live.DisablePasswordLogin);
    }

    [Fact]
    public void ProviderArrivingWithASecurityCheckDisabled_IsAudited_LikeASaveAndAnImport()
    {
        // A mounted file that turns off a default-on protection has to leave the same [SSO Audit] trace the
        // form save and the config import leave (#140/#672). Without this the quietest way to disable a
        // protection on this server would be the one route that wrote nothing about it, and the file applies
        // at boot, when nobody is looking at the surface it came from.
        var (store, live, persisted) = CreateStore();
        var logger = new CapturingLogger();

        var incoming = new PluginConfiguration();
        incoming.OidConfigs["lax"] = new OidConfig
        {
            OidEndpoint = Endpoint,
            OidClientId = ClientId,
            DoNotValidateEndpoints = true,
        };

        Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, Document(incoming), logger));

        Assert.Single(persisted);
        Assert.Contains(
            logger.Entries,
            entry => entry.Message.Contains("[SSO Audit]", StringComparison.Ordinal)
                && entry.Message.Contains(nameof(OidConfig.DoNotValidateEndpoints), StringComparison.Ordinal));
    }

    [Fact]
    public void Precedence_TheDocumentWinsForWhatItNames_LeavesWhatItDoesNot_AndKeepsTheServerManagedLinks()
    {
        // The whole precedence rule in one assertion set, because the three halves are only meaningful
        // together: a named provider is taken from the document, an unnamed one is not touched, and the link
        // map the server owns survives - it is in no document, so a replace instead of a merge would silently
        // unlink every account on that provider.
        var (store, live, persisted) = CreateStore();
        var managed = new OidConfig { OidEndpoint = Endpoint, OidClientId = ClientId, Enabled = false };
        managed.CanonicalLinks["subject-1"] = Linked;
        live.OidConfigs["managed"] = managed;
        live.OidConfigs["local-only"] = new OidConfig { OidEndpoint = "https://other.example.invalid/.well-known/openid-configuration", OidClientId = "local" };

        var incoming = new PluginConfiguration();
        incoming.OidConfigs["managed"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = ClientId, Enabled = true };

        Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, Document(incoming)));

        Assert.Same(live, Assert.Single(persisted));
        Assert.True(live.OidConfigs["managed"].Enabled);
        Assert.Equal(Linked, live.OidConfigs["managed"].CanonicalLinks["subject-1"]);
        Assert.Equal("local", live.OidConfigs["local-only"].OidClientId);
    }

    [Fact]
    public void ReapplyingTheSameDocument_PersistsNothingTheSecondTime()
    {
        // The restart-loop pin. A container that boots with an unchanged mount must not rewrite config.xml
        // every time, so the second load has to reach AlreadyCurrent without the persist delegate firing.
        var (store, live, persisted) = CreateStore();
        live.OidConfigs["managed"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = ClientId, Enabled = false };

        var incoming = new PluginConfiguration();
        incoming.OidConfigs["managed"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = ClientId, Enabled = true };
        var document = Document(incoming);

        Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, document));
        var afterFirst = Xml(live);
        Assert.Single(persisted);

        Assert.Equal(DeclarativeLoadOutcome.AlreadyCurrent, Load(store, document));

        Assert.Single(persisted);
        Assert.Equal(afterFirst, Xml(live));
    }
}
