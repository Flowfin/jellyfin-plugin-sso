// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Xml.Serialization;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Secrets;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Model.Plugins;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for the secret-reference form of the declarative provider document (#1096): a secret is named by
/// the environment variable or the file that holds it, never written into the document, and every way of
/// failing to resolve one refuses the whole load.
/// </summary>
/// <remarks>
/// The tests are driven through <see cref="DeclarativeProviderConfig.Apply(ProviderConfigStore, string, System.Func{string, bool}, System.Func{string, string}, ILogger, System.Func{string, string}, System.Func{string, string}, System.Func{string, string})"/>
/// rather than against the resolver alone, because what has to hold is a property of the LOAD: a document
/// this pass refuses must leave the stored configuration byte-identical, and a resolver returning false
/// proves that only if the loader acts on it. The environment and the filesystem are supplied as delegates,
/// so no test reads a real variable or a real file and one test cannot leak a secret into another.
/// </remarks>
public class DeclarativeSecretReferenceTests
{
    private const string Endpoint = "https://idp.example.invalid/.well-known/openid-configuration";
    private const string ClientId = "the-client";
    private const string Secret = "correct-horse-battery-staple";

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

    private static DeclarativeLoadOutcome Load(
        ProviderConfigStore store,
        string text,
        CapturingLogger? logger = null,
        IReadOnlyDictionary<string, string>? environment = null,
        IReadOnlyDictionary<string, string>? files = null,
        Func<string?, string?>? reveal = null) =>
        DeclarativeProviderConfig.Apply(
            store,
            "/run/secrets/sso.json",
            _ => true,
            _ => text,
            logger,
            name => environment is not null && environment.TryGetValue(name, out var value) ? value : null,
            path => files is not null && files.TryGetValue(path, out var content) ? content : null,
            reveal);

    // The document as an operator writes it: a provider object with whatever members the test is about.
    private static string Document(string map, string provider, string members) => $$"""
        {
          "FormatVersion": 1,
          "Configuration": {
            "{{map}}": {
              "{{provider}}": { {{members}} }
            }
          }
        }
        """;

    private static string OidDocument(string members) =>
        Document("OidConfigs", "kc", $"""
            "OidEndpoint": "{Endpoint}", "OidClientId": "{ClientId}", {members}
            """);

    private static void AssertRejected(
        DeclarativeLoadOutcome outcome,
        List<BasePluginConfiguration> persisted,
        PluginConfiguration live,
        string before,
        CapturingLogger logger,
        string namesThis)
    {
        Assert.Equal(DeclarativeLoadOutcome.Rejected, outcome);
        Assert.Empty(persisted);
        Assert.Equal(before, Xml(live));
        Assert.Contains(
            logger.Entries,
            entry => entry.Level == LogLevel.Error && entry.Message.Contains(namesThis, StringComparison.Ordinal));
        AssertNoEntryCarriesTheSecret(logger);
    }

    // Every rejection path is checked for this, not just the ones about logging: the reason a reference form
    // exists at all is that the secret should not be in reach of a place people read, and a log is such a
    // place. A message naming a variable or a path is the whole of what a rejection may say.
    private static void AssertNoEntryCarriesTheSecret(CapturingLogger logger)
    {
        Assert.DoesNotContain(
            logger.Records,
            record => record.Message.Contains(Secret, StringComparison.Ordinal)
                || record.Exception?.ToString().Contains(Secret, StringComparison.Ordinal) == true);
    }

    [Fact]
    public void EnvironmentReference_SuppliesTheSecret_AndTheDocumentNeverCarriesIt()
    {
        // The first form. What is in the document is the NAME of a variable, and what reaches the provider is
        // what that variable held, so the file an operator commits carries neither.
        var (store, live, persisted) = CreateStore();
        var logger = new CapturingLogger();

        var outcome = Load(
            store,
            OidDocument("\"OidSecretEnv\": \"SSO_KC_SECRET\""),
            logger,
            environment: new Dictionary<string, string> { ["SSO_KC_SECRET"] = Secret });

        Assert.Equal(DeclarativeLoadOutcome.Applied, outcome);
        Assert.Single(persisted);
        Assert.Equal(Secret, live.OidConfigs["kc"].OidSecret);
        AssertNoEntryCarriesTheSecret(logger);
    }

    [Fact]
    public void FileReference_SuppliesTheSecret_AndItsTrailingNewlineIsNotPartOfIt()
    {
        // The second form, and the trailing newline is the point rather than a detail: a container secret is
        // written by something that ends the line, and a client secret carrying one fails at the token
        // endpoint with an error nobody traces back to the file.
        var (store, live, persisted) = CreateStore();
        var logger = new CapturingLogger();

        var outcome = Load(
            store,
            OidDocument("\"OidSecretFile\": \"/run/secrets/kc\""),
            logger,
            files: new Dictionary<string, string> { ["/run/secrets/kc"] = Secret + "\n" });

        Assert.Equal(DeclarativeLoadOutcome.Applied, outcome);
        Assert.Single(persisted);
        Assert.Equal(Secret, live.OidConfigs["kc"].OidSecret);
        AssertNoEntryCarriesTheSecret(logger);
    }

    [Fact]
    public void InlineSecret_IsRejected_AndTheMessageNamesBothReferenceForms()
    {
        // The refusal the whole feature rests on. A secret written into the document is a secret in whatever
        // holds the document - a repository, a backup, an image layer - and none of those is reachable by the
        // plugin's at-rest encryption, so accepting it with a warning would be accepting it.
        var (store, live, persisted) = CreateStore();
        live.OidConfigs["kc"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = ClientId };
        var before = Xml(live);
        var logger = new CapturingLogger();

        var outcome = Load(store, OidDocument($"\"OidSecret\": \"{Secret}\""), logger);

        AssertRejected(outcome, persisted, live, before, logger, "OidSecretEnv");
        Assert.Contains(
            logger.Entries,
            entry => entry.Message.Contains("OidSecretFile", StringComparison.Ordinal));
    }

    [Fact]
    public void InlineSecretSpelledInAnotherCase_IsRejectedToo()
    {
        // The deserializer that reads this document matches property names case-insensitively, so a member
        // spelled 'oidsecret' fills the same field. A refusal that compared names exactly would be a refusal
        // with a documented way round it.
        var (store, live, persisted) = CreateStore();
        var before = Xml(live);
        var logger = new CapturingLogger();

        var outcome = Load(store, OidDocument($"\"oidsecret\": \"{Secret}\""), logger);

        AssertRejected(outcome, persisted, live, before, logger, "OidSecretEnv");
    }

    [Fact]
    public void SecretMemberSpelledTwiceInDifferentCases_IsRejected_RatherThanLettingTheParserChoose()
    {
        // Two members that differ only in case are not a repeat the document-level screen can see, and both
        // are candidates for one field. Which of them the deserializer takes would decide the secret, so the
        // document is refused rather than one of them being picked here.
        var (store, live, persisted) = CreateStore();
        var before = Xml(live);
        var logger = new CapturingLogger();

        var outcome = Load(
            store,
            OidDocument("\"OidSecretEnv\": \"FIRST\", \"oidsecretenv\": \"SECOND\""),
            logger,
            environment: new Dictionary<string, string> { ["FIRST"] = Secret, ["SECOND"] = "other" });

        AssertRejected(outcome, persisted, live, before, logger, "case");
    }

    [Fact]
    public void BothReferenceFormsOnOneField_IsRejected()
    {
        // Mutually exclusive per field. Picking one silently would make the document's meaning depend on this
        // code's preference rather than on what the operator wrote.
        var (store, live, persisted) = CreateStore();
        var before = Xml(live);
        var logger = new CapturingLogger();

        var outcome = Load(
            store,
            OidDocument("\"OidSecretEnv\": \"SSO_KC_SECRET\", \"OidSecretFile\": \"/run/secrets/kc\""),
            logger,
            environment: new Dictionary<string, string> { ["SSO_KC_SECRET"] = Secret },
            files: new Dictionary<string, string> { ["/run/secrets/kc"] = "other" });

        AssertRejected(outcome, persisted, live, before, logger, "undecided");
    }

    [Fact]
    public void UnsetEnvironmentVariable_RejectsTheLoad_AndNamesTheVariable()
    {
        // Fail-closed, and the alternative is what makes it matter: resolving to blank would be KEPT rather
        // than applied, so the server would run on its previous secret and the log would say nothing at all.
        var (store, live, persisted) = CreateStore();
        live.OidConfigs["kc"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = ClientId, OidSecret = "the-old-one" };
        var before = Xml(live);
        var logger = new CapturingLogger();

        var outcome = Load(store, OidDocument("\"OidSecretEnv\": \"SSO_KC_SECRET\""), logger);

        AssertRejected(outcome, persisted, live, before, logger, "SSO_KC_SECRET");
        Assert.Equal("the-old-one", live.OidConfigs["kc"].OidSecret);
    }

    [Fact]
    public void EnvironmentVariableHoldingOnlyWhitespace_RejectsTheLoad()
    {
        // A variable declared and left empty is the ordinary compose mistake, and it arrives as a value
        // rather than as an absence. It is the same refusal, because it supplies the same nothing.
        var (store, live, persisted) = CreateStore();
        var before = Xml(live);
        var logger = new CapturingLogger();

        var outcome = Load(
            store,
            OidDocument("\"OidSecretEnv\": \"SSO_KC_SECRET\""),
            logger,
            environment: new Dictionary<string, string> { ["SSO_KC_SECRET"] = "   " });

        AssertRejected(outcome, persisted, live, before, logger, "SSO_KC_SECRET");
    }

    [Fact]
    public void UnreadableFile_RejectsTheLoad_AndNamesThePath()
    {
        // A mount that did not arrive, or arrived without the permission to read it, is the failure this form
        // meets most often, and the path is the one thing a diagnosis needs.
        var (store, live, persisted) = CreateStore();
        var before = Xml(live);
        var logger = new CapturingLogger();

        var outcome = Load(store, OidDocument("\"OidSecretFile\": \"/run/secrets/kc\""), logger);

        AssertRejected(outcome, persisted, live, before, logger, "/run/secrets/kc");
    }

    [Fact]
    public void EmptyFile_RejectsTheLoad()
    {
        // A file that exists and holds nothing is the shape a half-finished mount produces, and it is not a
        // secret. Reading it as one would set an empty client secret on the next apply.
        var (store, live, persisted) = CreateStore();
        var before = Xml(live);
        var logger = new CapturingLogger();

        var outcome = Load(
            store,
            OidDocument("\"OidSecretFile\": \"/run/secrets/kc\""),
            logger,
            files: new Dictionary<string, string> { ["/run/secrets/kc"] = "\n  \n" });

        AssertRejected(outcome, persisted, live, before, logger, "/run/secrets/kc");
    }

    [Fact]
    public void ReferenceNamingNothing_RejectsTheLoad()
    {
        // A reference member present but blank says a secret is being supplied and supplies none. Treating it
        // as absent would be the fail-open reading of exactly the member that exists to close it.
        var (store, live, persisted) = CreateStore();
        var before = Xml(live);
        var logger = new CapturingLogger();

        var outcome = Load(store, OidDocument("\"OidSecretEnv\": \"\""), logger);

        AssertRejected(outcome, persisted, live, before, logger, "OidSecretEnv");
    }

    [Fact]
    public void ReferenceForTheOtherProtocolsSecret_RejectsTheLoad()
    {
        // An unknown member elsewhere in this document is a silent no-op, which the loader discloses. This one
        // may not be: the operator who wrote it believes a secret has been supplied, and the provider would
        // come up on whatever was stored before - working, and not from the file being read.
        var (store, live, persisted) = CreateStore();
        var before = Xml(live);
        var logger = new CapturingLogger();

        var outcome = Load(
            store,
            OidDocument("\"SamlSigningKeyPfxEnv\": \"SSO_KC_KEY\""),
            logger,
            environment: new Dictionary<string, string> { ["SSO_KC_KEY"] = Secret });

        AssertRejected(outcome, persisted, live, before, logger, "SamlSigningKeyPfxEnv");
    }

    [Fact]
    public void TheOtherProtocolsSecretWrittenOutInFull_RejectsTheLoad_EvenThoughItWouldDoNothing()
    {
        // A member the deserializer would drop, carrying a real secret. The value never reaches a provider,
        // so nothing here is about what the server would do with it - it is about the document, which is the
        // artefact this whole form exists to keep secrets out of. Ignoring it quietly would leave the secret
        // in the file and the operator with no sign that anything was wrong.
        var (store, live, persisted) = CreateStore();
        var before = Xml(live);
        var logger = new CapturingLogger();

        var outcome = Load(store, OidDocument($"\"SamlSigningKeyPfx\": \"{Secret}\""), logger);

        AssertRejected(outcome, persisted, live, before, logger, "SamlSigningKeyPfx");
    }

    [Fact]
    public void SamlSigningKeys_TakeReferencesToo_IncludingTheRolloverKey()
    {
        // Both SAML keys are private keys and both are withheld at the JSON boundary, so both are secrets a
        // document may not carry. The rollover key is named explicitly because it is the one that gets
        // forgotten: it exists only during an overlap window, which is exactly when a document is edited.
        var (store, live, persisted) = CreateStore();
        var logger = new CapturingLogger();

        // Real keys, because the validator this load runs through refuses a SAML signing key that is not a
        // loadable PKCS#12 blob - so a placeholder would prove the refusal rather than the reference form.
        var primary = SamlSigningKeyFactory.CreatePfxBase64();
        var rollover = SamlSigningKeyFactory.CreatePfxBase64();

        var document = Document("SamlConfigs", "adfs", """
            "SamlEndpoint": "https://idp.example.invalid/sso", "SamlClientId": "sp",
            "SamlSigningKeyPfxEnv": "SSO_PRIMARY", "SamlRolloverSigningKeyPfxFile": "/run/secrets/rollover"
            """);

        var outcome = Load(
            store,
            document,
            logger,
            environment: new Dictionary<string, string> { ["SSO_PRIMARY"] = primary },
            files: new Dictionary<string, string> { ["/run/secrets/rollover"] = rollover + "\n" });

        Assert.Equal(DeclarativeLoadOutcome.Applied, outcome);
        Assert.Single(persisted);
        Assert.Equal(primary, live.SamlConfigs["adfs"].SamlSigningKeyPfx);
        Assert.Equal(rollover, live.SamlConfigs["adfs"].SamlRolloverSigningKeyPfx);
        Assert.DoesNotContain(logger.Records, record => record.Message.Contains(primary, StringComparison.Ordinal));
    }

    [Fact]
    public void ADocumentWithNoSecretAtAll_StillLoads()
    {
        // The reference form is not a requirement to name a secret. A document that names none leaves the
        // stored one alone, which is the blank-means-keep rule the merge already carries, and this pins that
        // the new pass did not turn an absence into a refusal.
        var (store, live, persisted) = CreateStore();
        live.OidConfigs["kc"] = new OidConfig { OidEndpoint = Endpoint, OidClientId = ClientId, OidSecret = "the-stored-one" };
        var logger = new CapturingLogger();

        var outcome = Load(store, OidDocument("\"Enabled\": true"), logger);

        Assert.Equal(DeclarativeLoadOutcome.Applied, outcome);
        Assert.Equal("the-stored-one", live.OidConfigs["kc"].OidSecret);
    }

    [Fact]
    public void AResolvedSecretIsEncryptedAtRest_AndTheExportStillCarriesNothing()
    {
        // The three places a resolved secret must not appear, asserted on the same value in one test because
        // they are one claim: the reference form is worth nothing if the secret it delivers then leaks out of
        // the config XML, out of the admin export, or out of the log.
        var (store, live, persisted) = CreateStore();
        var logger = new CapturingLogger();
        var keyPath = SuiteTempFiles.Path("sso-declref");

        try
        {
            Assert.Equal(
                DeclarativeLoadOutcome.Applied,
                Load(
                    store,
                    OidDocument("\"OidSecretEnv\": \"SSO_KC_SECRET\""),
                    logger,
                    environment: new Dictionary<string, string> { ["SSO_KC_SECRET"] = Secret }));

            // What the plugin's persistence boundary does on the way to disk, reached the same way it is
            // reached in production rather than asserted about.
            var secrets = new SecretStore(keyPath);
            ConfigSecretProtection.ProtectAll(Assert.IsType<PluginConfiguration>(Assert.Single(persisted)), secrets);

            var xml = Xml(live);
            Assert.DoesNotContain(Secret, xml, StringComparison.Ordinal);
            Assert.True(SecretEnvelope.IsProtected(live.OidConfigs["kc"].OidSecret));
            Assert.Equal(Secret, secrets.Reveal(live.OidConfigs["kc"].OidSecret));

            var exported = JsonSerializer.Serialize(ConfigExport.Build(live));
            Assert.DoesNotContain(Secret, exported, StringComparison.Ordinal);

            AssertNoEntryCarriesTheSecret(logger);
        }
        finally
        {
            if (File.Exists(keyPath))
            {
                File.Delete(keyPath);
            }
        }
    }

    [Fact]
    public void ReapplyingADocumentWhoseReferenceHasNotMoved_PersistsNothingTheSecondTime()
    {
        // The restart-loop pin, re-run over a reference. What is stored is an envelope and what the reference
        // resolves to is the plaintext inside it, so without the comparison against the revealed value the two
        // never look equal and every boot rewrites config.xml with a freshly nonced envelope.
        var (store, live, persisted) = CreateStore();
        var logger = new CapturingLogger();
        var keyPath = SuiteTempFiles.Path("sso-declref-loop");
        var environment = new Dictionary<string, string> { ["SSO_KC_SECRET"] = Secret };
        var document = OidDocument("\"OidSecretEnv\": \"SSO_KC_SECRET\"");

        try
        {
            var secrets = new SecretStore(keyPath);

            Assert.Equal(DeclarativeLoadOutcome.Applied, Load(store, document, logger, environment, reveal: secrets.Reveal));
            ConfigSecretProtection.ProtectAll(live, secrets);
            var afterFirst = Xml(live);
            Assert.Single(persisted);

            Assert.Equal(
                DeclarativeLoadOutcome.AlreadyCurrent,
                Load(store, document, logger, environment, reveal: secrets.Reveal));

            Assert.Single(persisted);
            Assert.Equal(afterFirst, Xml(live));
        }
        finally
        {
            if (File.Exists(keyPath))
            {
                File.Delete(keyPath);
            }
        }
    }

    [Fact]
    public void AReferenceThatNowResolvesToADifferentSecret_IsAppliedRatherThanKept()
    {
        // The other half of the comparison above, and the one that would fail silently if it were wrong: a
        // rotated secret must still reach the provider. A comparison that answered "already stored" too
        // eagerly would leave the server authenticating with the retired value.
        var (store, live, persisted) = CreateStore();
        var logger = new CapturingLogger();
        var keyPath = SuiteTempFiles.Path("sso-declref-rotate");
        var document = OidDocument("\"OidSecretEnv\": \"SSO_KC_SECRET\"");

        try
        {
            var secrets = new SecretStore(keyPath);

            Assert.Equal(
                DeclarativeLoadOutcome.Applied,
                Load(store, document, logger, new Dictionary<string, string> { ["SSO_KC_SECRET"] = Secret }, reveal: secrets.Reveal));
            ConfigSecretProtection.ProtectAll(live, secrets);

            Assert.Equal(
                DeclarativeLoadOutcome.Applied,
                Load(store, document, logger, new Dictionary<string, string> { ["SSO_KC_SECRET"] = "the-rotated-one" }, reveal: secrets.Reveal));

            Assert.Equal(2, persisted.Count);
            Assert.Equal("the-rotated-one", live.OidConfigs["kc"].OidSecret);
        }
        finally
        {
            if (File.Exists(keyPath))
            {
                File.Delete(keyPath);
            }
        }
    }
}
