// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests the portable account-link snapshot (#1126). The document exists to survive a user-database
/// rebuild, so the properties worth pinning are the ones that decide whether it still means anything on
/// the other side of one: the username replaces the id, the #186 issuer binding travels with the link it
/// binds, and a link pointing at an account that no longer exists is absent rather than dangling.
/// </summary>
public class LinkExportTests
{
    private static readonly Guid Alice = Guid.Parse("a11ce000-0000-0000-0000-000000000001");
    private static readonly Guid Bob = Guid.Parse("b0b00000-0000-0000-0000-000000000002");
    private static readonly Guid Ghost = Guid.Parse("9057c000-0000-0000-0000-000000000003");

    [Fact]
    public void EveryLinkAcrossBothProtocols_IsExportedWithItsProviderNameAndUsername()
    {
        var document = LinkExport.Build(Configuration(), Directory);

        Assert.Equal(LinkExport.FormatVersion, document.FormatVersion);
        Assert.Equal(
            new[] { "OpenID/idp/sub-alice/alice", "OpenID/idp/sub-bob/bob", "SAML/adfs/nameid-alice/alice" },
            document.Links.Select(Describe).OrderBy(d => d, StringComparer.Ordinal));
    }

    [Fact]
    public void AnOpenIdLinksIssuerBinding_TravelsWithTheLinkItBinds()
    {
        // The binding is per link, not per provider (#186). Exporting the provider's configured issuer
        // instead would restore a binding the link never had, which is a relaxation dressed as a restore.
        var document = LinkExport.Build(Configuration(), Directory);

        Assert.Equal("https://idp.example.test", Link(document, "sub-alice").Issuer);
    }

    [Fact]
    public void AnOpenIdLinkWithNoBinding_ExportsNoIssuer()
    {
        // A link written before the binding existed has no entry in the issuer map, and null is the honest
        // answer for it. Substituting the provider's current issuer is the failure this pins against.
        var document = LinkExport.Build(Configuration(), Directory);

        Assert.Null(Link(document, "sub-bob").Issuer);
    }

    [Fact]
    public void ASamlLink_CarriesNoIssuer()
    {
        // SAML links have no issuer binding at all; the field is not merely unset for them, there is no
        // source it could come from.
        var document = LinkExport.Build(Configuration(), Directory);

        Assert.Null(Link(document, "nameid-alice").Issuer);
    }

    [Fact]
    public void ALinkWhoseAccountIsGone_IsDroppedRatherThanExportedDangling()
    {
        var configuration = Configuration();
        configuration.OidConfigs["idp"].CanonicalLinks["sub-ghost"] = Ghost;
        configuration.SamlConfigs["adfs"].CanonicalLinks["nameid-ghost"] = Ghost;

        var document = LinkExport.Build(configuration, Directory);

        Assert.DoesNotContain(document.Links, link => link.CanonicalName!.EndsWith("ghost", StringComparison.Ordinal));
        Assert.Equal(3, document.Links.Count);
    }

    [Fact]
    public void AProviderStoredWithNoConfigObject_IsSkippedRatherThanDereferenced()
    {
        // A null-bodied add (#350) can leave a provider whose config object is null. The read side treats it
        // the way the link listings do: skipped, never a 500.
        var configuration = Configuration();
        configuration.OidConfigs["broken"] = null!;
        configuration.SamlConfigs["broken"] = null!;

        var document = LinkExport.Build(configuration, Directory);

        Assert.Equal(3, document.Links.Count);
    }

    [Fact]
    public void TheSerializedDocument_CarriesNoSecretNoEnvelopeAndNoUserId()
    {
        // The user id is the value the whole document exists to replace, and a provider secret is the value
        // whose escape would matter most. Neither can reach the output, because nothing copies the provider
        // configuration into it; the assertion is on the bytes rather than on that argument.
        var configuration = Configuration();
        configuration.OidConfigs["idp"].OidSecret = "ssoenc:v1:not-a-real-envelope";
        configuration.SamlConfigs["adfs"].SamlSigningKeyPfx = "ssoenc:v1:also-not-a-real-envelope";

        var json = JsonSerializer.Serialize(LinkExport.Build(configuration, Directory));

        Assert.DoesNotContain("ssoenc:", json, StringComparison.Ordinal);
        Assert.DoesNotContain(Alice.ToString(), json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Bob.ToString(), json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("alice", json, StringComparison.Ordinal);
    }

    // --- helpers ---

    private static PluginConfiguration Configuration()
    {
        var configuration = new PluginConfiguration();
        configuration.OidConfigs["idp"] = new OidConfig
        {
            Enabled = true,
            OidEndpoint = "https://idp.example.test",
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-alice"] = Alice, ["sub-bob"] = Bob },
            CanonicalLinkIssuers = new SerializableDictionary<string, string> { ["sub-alice"] = "https://idp.example.test" },
        };
        configuration.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["nameid-alice"] = Alice },
        };
        return configuration;
    }

    private static string? Directory(Guid userId) => userId == Alice ? "alice" : userId == Bob ? "bob" : null;

    private static string Describe(LinkExportEntry entry) =>
        string.Join('/', entry.Protocol, entry.Provider, entry.CanonicalName, entry.Username);

    private static LinkExportEntry Link(LinkExportDocument document, string canonicalName) =>
        document.Links.Single(entry => string.Equals(entry.CanonicalName, canonicalName, StringComparison.Ordinal));
}
