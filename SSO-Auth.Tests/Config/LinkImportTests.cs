// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests the restore half of the portable account-link snapshot (#1129). The document exists to survive a
/// user-database rebuild, so the property that decides whether it means anything is the round trip: links
/// exported against one server's ids come back bound to the ids the target holds today.
///
/// The rest is fail-closed, and every refusal is tested twice - that it refuses, and that the stored link
/// table is byte-identical afterwards. A half-applied restore is the worst outcome this code can produce,
/// because it looks restored and silently is not, so a refusal that wrote three of five links would be a
/// worse failure than one that wrote none.
/// </summary>
public class LinkImportTests
{
    // The SOURCE server's ids, as the export was taken against them.
    private static readonly Guid SourceAlice = Guid.Parse("a11ce000-0000-0000-0000-000000000001");
    private static readonly Guid SourceBob = Guid.Parse("b0b00000-0000-0000-0000-000000000002");

    // The TARGET server's ids for the same two usernames. Deliberately different from the source's: a
    // rebuilt user database issues new ids, and an import that quietly reused the document's ids would
    // pass a test whose two sides shared them.
    private static readonly Guid TargetAlice = Guid.Parse("7a19e700-0000-0000-0000-00000000000a");
    private static readonly Guid TargetBob = Guid.Parse("7a19e700-0000-0000-0000-00000000000b");
    private static readonly Guid TargetMallory = Guid.Parse("7a19e700-0000-0000-0000-00000000000c");

    // The four refusal messages `docs/SERVER-MIGRATION.md` and `docs/ACCOUNT-MANAGEMENT-API.md` quote to an
    // operator, held here in full rather than as the prefixes these assertions carried before #1514. The tail
    // is the half that tells the operator what to do: `; unlink it first` is the instruction, and `for that
    // protocol on this instance` is what separates a provider that is missing from one that is named
    // differently. Nothing outside those two pages held those tails, so editing one left the build, the suite
    // and every gate green while both pages went on quoting a sentence the plugin no longer emits.
    private const string NoSuchProvider =
        "no provider of that name is configured for that protocol on this instance";
    private const string NoSuchAccount = "no Jellyfin account is named 'nobody' on this instance";
    private const string AlreadyLinkedElsewhere =
        "this instance already links that identity to a different account; unlink it first";
    private const string AlreadyBoundToAnotherIssuer =
        "this instance already binds that link to a different issuer; unlink it first";

    [Fact]
    public void ExportOnOneServer_ImportsOntoAnother_ReboundToTheTargetsOwnIds()
    {
        var document = LinkExport.Build(SourceConfiguration(), SourceDirectory);
        var target = TargetConfiguration();

        var restored = LinkImport.Apply(target, document, TargetDirectory);

        Assert.Equal(TargetAlice, target.OidConfigs["idp"].CanonicalLinks["sub-alice"]);
        Assert.Equal(TargetBob, target.OidConfigs["idp"].CanonicalLinks["sub-bob"]);
        Assert.Equal(TargetAlice, target.SamlConfigs["adfs"].CanonicalLinks["nameid-alice"]);

        // The source ids are what the rebuild destroyed. Any of them surviving into the target means the
        // import copied the document's own bookkeeping instead of resolving the username.
        Assert.DoesNotContain(SourceAlice, target.OidConfigs["idp"].CanonicalLinks.Values);
        Assert.DoesNotContain(SourceBob, target.OidConfigs["idp"].CanonicalLinks.Values);
        Assert.DoesNotContain(SourceAlice, target.SamlConfigs["adfs"].CanonicalLinks.Values);

        Assert.Equal(
            new[] { "OpenID/idp:2", "SAML/adfs:1" },
            restored.Select(count => $"{count.Protocol}/{count.Provider}:{count.Links}").ToArray());
    }

    [Fact]
    public void TheIssuerBinding_IsRestoredWithTheLinkItBinds()
    {
        // Without this the restored link arrives unbound, and the first login after a migration stamps
        // whatever issuer answered (trust on first use) - which is precisely the repoint #186 exists to
        // refuse. A restore that silently relaxes a binding is a downgrade dressed as a recovery.
        var document = LinkExport.Build(SourceConfiguration(), SourceDirectory);
        var target = TargetConfiguration();

        LinkImport.Apply(target, document, TargetDirectory);

        Assert.Equal("https://idp.example.test", target.OidConfigs["idp"].CanonicalLinkIssuers["sub-alice"]);
    }

    [Fact]
    public void ALinkWithNoBinding_RestoresWithoutInventingOne()
    {
        var document = LinkExport.Build(SourceConfiguration(), SourceDirectory);
        var target = TargetConfiguration();

        LinkImport.Apply(target, document, TargetDirectory);

        Assert.False(target.OidConfigs["idp"].CanonicalLinkIssuers.ContainsKey("sub-bob"));
    }

    [Fact]
    public void AnIssuerOnASamlEntry_IsNotWrittenAnywhere()
    {
        // SAML has no issuer binding at all. A hand-edited document carrying one on a SAML entry must not
        // conjure a map for a protocol that does not use it.
        var target = TargetConfiguration();

        LinkImport.Apply(target, Document(Entry("SAML", "adfs", "nameid-alice", "alice", "https://forged.example.test")), TargetDirectory);

        Assert.Equal(TargetAlice, target.SamlConfigs["adfs"].CanonicalLinks["nameid-alice"]);
        Assert.IsNotType<OidConfig>(target.SamlConfigs["adfs"]);
    }

    [Fact]
    public void AnUnknownFormatVersion_IsRefusedAndNothingIsWritten()
    {
        var target = TargetConfiguration();
        var document = Document(Entry("OpenID", "idp", "sub-alice", "alice"));
        document.FormatVersion = LinkExport.FormatVersion + 1;

        var refusal = Assert.Throws<ArgumentException>(() => LinkImport.Apply(target, document, TargetDirectory));

        Assert.Contains("Unsupported link export format version", refusal.Message, StringComparison.Ordinal);
        AssertNoLinksWereWritten(target);
    }

    [Fact]
    public void AProviderThisInstanceDoesNotHold_RefusesTheWholeDocument()
    {
        var target = TargetConfiguration();

        var refusal = Assert.Throws<ArgumentException>(() =>
            LinkImport.Apply(target, Document(Entry("OpenID", "some-other-idp", "sub-alice", "alice")), TargetDirectory));

        Assert.Contains(NoSuchProvider, refusal.Message, StringComparison.Ordinal);
        AssertNoLinksWereWritten(target);
    }

    [Fact]
    public void AProviderNamedUnderTheWrongProtocol_IsNotFoundOnTheOtherMap()
    {
        // The two protocols keep separate provider namespaces, so "adfs" existing as a SAML provider must
        // not make an OpenID entry naming it restorable. Matching across the maps would restore a link onto
        // a provider no login of that protocol ever reads.
        var target = TargetConfiguration();

        Assert.Throws<ArgumentException>(() =>
            LinkImport.Apply(target, Document(Entry("OpenID", "adfs", "sub-alice", "alice")), TargetDirectory));

        AssertNoLinksWereWritten(target);
    }

    [Fact]
    public void AUsernameThisInstanceDoesNotHold_RefusesTheWholeDocument()
    {
        // The import never creates an account. A backup file that could bring principals into existence is
        // a much larger primitive than one restoring links between things that both sides already hold.
        var target = TargetConfiguration();

        var refusal = Assert.Throws<ArgumentException>(() =>
            LinkImport.Apply(target, Document(Entry("OpenID", "idp", "sub-alice", "nobody")), TargetDirectory));

        Assert.Contains(NoSuchAccount, refusal.Message, StringComparison.Ordinal);
        AssertNoLinksWereWritten(target);
    }

    [Fact]
    public void AnIdentityAlreadyLinkedToADifferentAccount_IsRefusedRatherThanRepointed()
    {
        // THE RULE THIS WHOLE ENDPOINT LIVES OR DIES BY. Without it a crafted backup file remaps an
        // identity-provider subject onto any account on the server, an administrator's included, and the
        // remap arrives through a route whose whole framing is "restore what was there".
        var target = TargetConfiguration();
        target.OidConfigs["idp"].CanonicalLinks["sub-alice"] = TargetMallory;

        var refusal = Assert.Throws<ArgumentException>(() =>
            LinkImport.Apply(target, Document(Entry("OpenID", "idp", "sub-alice", "alice")), TargetDirectory));

        Assert.Contains(AlreadyLinkedElsewhere, refusal.Message, StringComparison.Ordinal);
        Assert.Equal(TargetMallory, target.OidConfigs["idp"].CanonicalLinks["sub-alice"]);
    }

    [Fact]
    public void AlinkThisInstanceBindsToADifferentIssuer_IsRefusedRatherThanRebound()
    {
        // The same rule one level down (#186). Overwriting a stored binding would rewrite a security
        // decision as a side effect of a restore. Its immediate consequence is only fail-closed, since the
        // rebound link's next login is refused for a mismatch, but the shape is the repoint above.
        var target = TargetConfiguration();
        target.OidConfigs["idp"].CanonicalLinks["sub-alice"] = TargetAlice;
        target.OidConfigs["idp"].CanonicalLinkIssuers["sub-alice"] = "https://idp.example.test";

        var refusal = Assert.Throws<ArgumentException>(() => LinkImport.Apply(
            target,
            Document(Entry("OpenID", "idp", "sub-alice", "alice", "https://forged.example.test")),
            TargetDirectory));

        Assert.Contains(AlreadyBoundToAnotherIssuer, refusal.Message, StringComparison.Ordinal);
        Assert.Equal("https://idp.example.test", target.OidConfigs["idp"].CanonicalLinkIssuers["sub-alice"]);
    }

    [Fact]
    public void AnEntryWithNoIssuer_RestoresAgainstABoundLinkWithoutRelaxingIt()
    {
        // A backup taken before the binding existed carries no issuer. Restoring it must not clear the
        // binding the target already holds, which would silently drop the link back to trust on first use.
        var target = TargetConfiguration();
        target.OidConfigs["idp"].CanonicalLinks["sub-alice"] = TargetAlice;
        target.OidConfigs["idp"].CanonicalLinkIssuers["sub-alice"] = "https://idp.example.test";

        LinkImport.Apply(target, Document(Entry("OpenID", "idp", "sub-alice", "alice")), TargetDirectory);

        Assert.Equal("https://idp.example.test", target.OidConfigs["idp"].CanonicalLinkIssuers["sub-alice"]);
    }

    [Fact]
    public void ReimportingAMappingThisInstanceAlreadyHolds_IsNotARepointAndSucceeds()
    {
        // A migration is retried. An import that refused every link it had already restored would make the
        // second attempt after a partial failure impossible, and the rule above is about repointing rather
        // than about writing the same thing twice.
        var target = TargetConfiguration();
        target.OidConfigs["idp"].CanonicalLinks["sub-alice"] = TargetAlice;

        var restored = LinkImport.Apply(target, Document(Entry("OpenID", "idp", "sub-alice", "alice")), TargetDirectory);

        Assert.Equal(TargetAlice, target.OidConfigs["idp"].CanonicalLinks["sub-alice"]);
        Assert.Equal(1, restored.Single().Links);
    }

    [Fact]
    public void ADocumentMappingOneIdentityToTwoAccounts_IsRefused()
    {
        // Which entry wins would otherwise be decided by the document's own order, silently, in exactly the
        // case where getting it wrong hands somebody else's identity to an account.
        var target = TargetConfiguration();

        var refusal = Assert.Throws<ArgumentException>(() => LinkImport.Apply(
            target,
            Document(Entry("OpenID", "idp", "sub-alice", "alice"), Entry("OpenID", "idp", "sub-alice", "bob")),
            TargetDirectory));

        Assert.Contains("maps this identity to two different accounts", refusal.Message, StringComparison.Ordinal);
        AssertNoLinksWereWritten(target);
    }

    [Fact]
    public void OneBadEntryLateInTheDocument_LeavesEveryEarlierLinkUnwritten()
    {
        // The atomicity clause, and the one worth deleting the guard to check: move the write above the
        // validation and this is the test that reds. Two good entries precede the bad one, so a validator
        // that wrote as it went would leave them behind.
        var target = TargetConfiguration();

        Assert.Throws<ArgumentException>(() => LinkImport.Apply(
            target,
            Document(
                Entry("OpenID", "idp", "sub-alice", "alice"),
                Entry("SAML", "adfs", "nameid-alice", "alice"),
                Entry("OpenID", "idp", "sub-bob", "nobody")),
            TargetDirectory));

        AssertNoLinksWereWritten(target);
    }

    [Fact]
    public void ARefusal_NamesTheEntryAndNeverTheCanonicalSubject()
    {
        // The subject is the one field in the document that identifies a real person at the identity
        // provider, and the audit trail already carries no raw subject value (T-I1). The index into the
        // document the operator is holding is what they need to find the entry.
        var target = TargetConfiguration();

        var refusal = Assert.Throws<ArgumentException>(() =>
            LinkImport.Apply(target, Document(Entry("OpenID", "idp", "sub-alice", "nobody")), TargetDirectory));

        Assert.Contains("entry #0 (OpenID/idp)", refusal.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("sub-alice", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnEntryWithNoCanonicalName_IsRefused()
    {
        var target = TargetConfiguration();

        Assert.Throws<ArgumentException>(() =>
            LinkImport.Apply(target, Document(Entry("OpenID", "idp", "   ", "alice")), TargetDirectory));

        AssertNoLinksWereWritten(target);
    }

    [Fact]
    public void AProviderStoredWithNoConfigObject_IsTreatedAsAbsentRatherThanDereferenced()
    {
        // A null-bodied add (#350) can leave a provider whose config object is null. The write side fails
        // closed on it the way every read of these maps does, rather than throwing a NullReference out of a
        // config mutation.
        var target = TargetConfiguration();
        target.OidConfigs["broken"] = null!;

        var refusal = Assert.Throws<ArgumentException>(() =>
            LinkImport.Apply(target, Document(Entry("OpenID", "broken", "sub-alice", "alice")), TargetDirectory));

        Assert.Contains(NoSuchProvider, refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnEmptyDocument_RestoresNothingAndReportsZero()
    {
        // Applied rather than refused: it contradicts nothing and leaves nothing half-done. The count is
        // what tells an operator who applied the wrong file that nothing came back.
        var target = TargetConfiguration();

        var restored = LinkImport.Apply(target, Document(), TargetDirectory);

        Assert.Empty(restored);
        AssertNoLinksWereWritten(target);
    }

    [Fact]
    public void TheProtocolNameIsMatchedLoosely_AndTheProviderNameExactly()
    {
        // The protocol is a two-value vocabulary the plugin writes itself, so a lower-case spelling costs
        // nothing to accept. The provider name is a key the rest of the plugin looks up ordinally, so
        // accepting a different casing here would restore links onto a provider no login resolves.
        var target = TargetConfiguration();

        LinkImport.Apply(target, Document(Entry("openid", "idp", "sub-alice", "alice")), TargetDirectory);
        Assert.Equal(TargetAlice, target.OidConfigs["idp"].CanonicalLinks["sub-alice"]);

        Assert.Throws<ArgumentException>(() =>
            LinkImport.Apply(target, Document(Entry("OpenID", "IDP", "sub-bob", "bob")), TargetDirectory));
    }

    // --- helpers ---

    private static void AssertNoLinksWereWritten(PluginConfiguration target)
    {
        Assert.Empty(target.OidConfigs["idp"].CanonicalLinks);
        Assert.Empty(target.OidConfigs["idp"].CanonicalLinkIssuers);
        Assert.Empty(target.SamlConfigs["adfs"].CanonicalLinks);
    }

    private static PluginConfiguration SourceConfiguration()
    {
        var configuration = new PluginConfiguration();
        configuration.OidConfigs["idp"] = new OidConfig
        {
            Enabled = true,
            OidEndpoint = "https://idp.example.test",
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-alice"] = SourceAlice, ["sub-bob"] = SourceBob },
            CanonicalLinkIssuers = new SerializableDictionary<string, string> { ["sub-alice"] = "https://idp.example.test" },
        };
        configuration.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["nameid-alice"] = SourceAlice },
        };
        return configuration;
    }

    // The rebuilt server: the same two providers, the same two usernames, and no links at all.
    private static PluginConfiguration TargetConfiguration()
    {
        var configuration = new PluginConfiguration();
        configuration.OidConfigs["idp"] = new OidConfig { Enabled = true, OidEndpoint = "https://idp.example.test" };
        configuration.SamlConfigs["adfs"] = new SamlConfig { Enabled = true };
        return configuration;
    }

    private static LinkExportDocument Document(params LinkExportEntry[] entries)
    {
        var document = new LinkExportDocument { FormatVersion = LinkExport.FormatVersion };
        foreach (var entry in entries)
        {
            document.Links.Add(entry);
        }

        return document;
    }

    private static LinkExportEntry Entry(string protocol, string provider, string canonicalName, string username, string? issuer = null) =>
        new LinkExportEntry
        {
            Protocol = protocol,
            Provider = provider,
            CanonicalName = canonicalName,
            Username = username,
            Issuer = issuer,
        };

    private static string? SourceDirectory(Guid userId) =>
        userId == SourceAlice ? "alice" : userId == SourceBob ? "bob" : null;

    private static Guid? TargetDirectory(string username) => username switch
    {
        "alice" => TargetAlice,
        "bob" => TargetBob,
        "mallory" => TargetMallory,
        _ => null,
    };
}
