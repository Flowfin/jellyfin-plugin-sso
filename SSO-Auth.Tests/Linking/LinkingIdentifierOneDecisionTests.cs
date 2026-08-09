// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The provider-side canonical name reaches one comparison decision wherever it arrives (#1165), so a
/// name that can be linked is the same name that can be unlinked and neither route can be shadowed by a
/// variant the other accepts.
/// <para>
/// In this tree that decision is not spread across the add path, the remove path and login-time
/// resolution: the identifier is never normalised, and all three index ONE map - the per-provider
/// <c>CanonicalLinks</c> dictionary - so the comparison is the dictionary's own comparer and there is
/// exactly one of it. That makes the property a fact about the map rather than about three call sites,
/// which is what the rules below assert: the comparer is the ordinal default on every provider kind and
/// survives a persistence round trip, and the end-to-end behaviour that follows from it holds on the
/// routes an administrator actually drives.
/// </para>
/// <para>
/// The failure this exists against is a later edit giving one of these maps a case- or culture-folding
/// comparer to be helpful. That would make <c>Alice</c> and <c>alice</c> one link for whichever paths
/// read the folded map and two for whichever did not - and the half that folds is a login-time identity
/// collapse, not a convenience.
/// </para>
/// </summary>
[Collection("SSOController")]
public class LinkingIdentifierOneDecisionTests
{
    private static readonly Guid Target = Guid.Parse("55555555-5555-5555-5555-555555555555");

    // Every map the canonical name is a KEY of, on a freshly constructed configuration. Derived from the
    // config objects rather than named as literals, so a provider kind added later is covered.
    private static IEnumerable<(string Where, IEqualityComparer<string> Comparer)> IdentifierKeyedMaps()
    {
        var oid = new OidConfig();
        var saml = new SamlConfig();

        yield return ("OidConfig.CanonicalLinks", oid.CanonicalLinks.Comparer);
        yield return ("OidConfig.CanonicalLinkIssuers", oid.CanonicalLinkIssuers.Comparer);
        yield return ("SamlConfig.CanonicalLinks", saml.CanonicalLinks.Comparer);
    }

    [Fact]
    public void EveryIdentifierKeyedMap_ComparesOrdinally()
    {
        // The rule. One comparer, and it is the ordinal default: no case folding, no culture, nothing that
        // could make two different subjects the same key on one path and different keys on another.
        foreach (var (where, comparer) in IdentifierKeyedMaps())
        {
            Assert.True(
                IsOrdinal(comparer),
                $"{where} no longer compares its keys ordinally. The canonical name is an identity, so folding it here silently merges two provider subjects into one link on whichever paths read this map (#1165).");
        }
    }

    [Fact]
    public void TheRule_RefusesAFoldingComparer()
    {
        // Must-catch fixture. The comparers a helpful edit would reach for are refused by the same
        // predicate the rule uses, so the rule above is a statement and not a tautology.
        Assert.False(IsOrdinal(new Dictionary<string, Guid>(StringComparer.OrdinalIgnoreCase).Comparer));
        Assert.False(IsOrdinal(new Dictionary<string, Guid>(StringComparer.InvariantCulture).Comparer));
        Assert.False(IsOrdinal(new Dictionary<string, Guid>(StringComparer.InvariantCultureIgnoreCase).Comparer));

        // And it accepts both spellings of the thing it is asserting, so a later refactor writing the
        // comparer out explicitly does not read as a regression.
        Assert.True(IsOrdinal(new Dictionary<string, Guid>().Comparer));
        Assert.True(IsOrdinal(new Dictionary<string, Guid>(StringComparer.Ordinal).Comparer));
    }

    [Fact]
    public void TheComparer_SurvivesThePersistenceRoundTrip()
    {
        // The map login-time resolution reads is the DESERIALIZED one, not the one a constructor made. A
        // round trip that dropped the comparer would leave the rule above true of a map nothing reads.
        var config = new PluginConfiguration();
        config.OidConfigs["keycloak"] = new OidConfig { CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-Alice"] = Target } };

        var restored = RoundTrip(config);

        Assert.True(IsOrdinal(restored.OidConfigs["keycloak"].CanonicalLinks.Comparer));
        Assert.True(restored.OidConfigs["keycloak"].CanonicalLinks.ContainsKey("sub-Alice"));
        Assert.False(restored.OidConfigs["keycloak"].CanonicalLinks.ContainsKey("sub-alice"));
    }

    [Fact]
    public async Task ACaseVariantOfALinkedName_IsRefusedByTheDeleteRouteAndTheExactNameStillRemovesIt()
    {
        // End to end on the routes an administrator drives. The shadow this closes is
        // linkable-but-not-unlinkable: a variant the DELETE route accepted while the stored key stayed
        // behind would leave a live link no operator could revoke.
        var harness = ForCaller(c => c.OidConfigs["keycloak"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-Alice"] = Target },
        });

        Assert.IsType<NotFoundObjectResult>(await harness.Controller.DeleteCanonicalLink("oid", "keycloak", Target, "sub-alice"));
        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].CanonicalLinks.ContainsKey("sub-Alice")));

        Assert.IsNotType<NotFoundObjectResult>(await harness.Controller.DeleteCanonicalLink("oid", "keycloak", Target, "sub-Alice"));
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].CanonicalLinks.ContainsKey("sub-Alice")));
    }

    [Fact]
    public async Task AWhitespaceVariantOfALinkedName_IsRefusedRatherThanTrimmedIntoAMatch()
    {
        // The other half of "never normalised". Trimming on the way in would let " sub-1" unlink "sub-1",
        // which is the same shadow read from the opposite side: a name nobody stored resolving to a link.
        var harness = ForCaller(c => c.OidConfigs["keycloak"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-1"] = Target },
        });

        Assert.IsType<NotFoundObjectResult>(await harness.Controller.DeleteCanonicalLink("oid", "keycloak", Target, " sub-1"));
        Assert.IsType<NotFoundObjectResult>(await harness.Controller.DeleteCanonicalLink("oid", "keycloak", Target, "sub-1 "));
        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].CanonicalLinks.ContainsKey("sub-1")));
    }

    [Fact]
    public async Task TheSamlLinkMap_HoldsTheSameDecision()
    {
        // The identifier is the SAML NameID on this side and the OpenID sub on the other, and both are
        // keys of the same kind of map. Asserted on both so a divergence cannot land on one protocol.
        var harness = ForCaller(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["Alice@example.test"] = Target },
        });

        Assert.IsType<NotFoundObjectResult>(await harness.Controller.DeleteCanonicalLink("saml", "adfs", Target, "alice@example.test"));
        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs["adfs"].CanonicalLinks.ContainsKey("Alice@example.test")));

        Assert.IsNotType<NotFoundObjectResult>(await harness.Controller.DeleteCanonicalLink("saml", "adfs", Target, "Alice@example.test"));
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs["adfs"].CanonicalLinks.ContainsKey("Alice@example.test")));
    }

    [Fact]
    public void TheIdentifierEntryPointSet_IsNonEmpty()
    {
        // Sentinel. The route segment is the one medium the identifier arrives on as a parameter - on the
        // add route it travels inside the redeemed identity and on the login path it is a persisted key,
        // neither of which a parameter walk can see. If this ever reads zero the behavioural proofs above
        // are driving a method no URL reaches any more.
        var carrying = EntryPointInventory.OfThePlugin()
            .Where(e => e.Parameters.Any(p => string.Equals(p.Name, "canonicalName", StringComparison.Ordinal)))
            .Select(e => e.Template)
            .ToList();

        Assert.NotEmpty(carrying);
        Assert.All(carrying, t => Assert.Contains("Link", t, StringComparison.Ordinal));
    }

    // The identifier is an opaque identity, so the only comparer that is right for it is the ordinal one,
    // and this is deliberately an identity check rather than a behavioural sniff. A culture comparer agrees
    // with ordinal on ASCII and diverges on inputs no fixture would think to try, which is exactly the kind
    // of near-miss a behavioural probe passes. The case leg stays as a second bar so a custom comparer
    // handed back in place of one of these instances still has to behave.
    private static bool IsOrdinal(IEqualityComparer<string> comparer) =>
        (ReferenceEquals(comparer, EqualityComparer<string>.Default) || ReferenceEquals(comparer, StringComparer.Ordinal))
        && !comparer.Equals("a", "A")
        && comparer.Equals("sub-1", "sub-1");

    // A persistence round trip through the same XML serializer the plugin stores its configuration with.
    private static PluginConfiguration RoundTrip(PluginConfiguration configuration)
    {
        var serializer = new System.Xml.Serialization.XmlSerializer(typeof(PluginConfiguration));
        using var buffer = new System.IO.MemoryStream();
        serializer.Serialize(buffer, configuration);
        buffer.Position = 0;

        // Read back with DTD processing off and no resolver, the same posture the plugin's own XML reads
        // take - a test fixture is not a reason to open one.
        using var reader = System.Xml.XmlReader.Create(buffer, new System.Xml.XmlReaderSettings
        {
            DtdProcessing = System.Xml.DtdProcessing.Prohibit,
            XmlResolver = null,
        });
        return (PluginConfiguration)serializer.Deserialize(reader)!;
    }

    // An administrator acting on their own account, which is what both link routes gate on before the
    // identifier is compared at all.
    private static SsoControllerHarness ForCaller(Action<PluginConfiguration> configure)
    {
        var harness = new SsoControllerHarness(configure);

        var user = new User("caller", "SSO-Auth", "Default") { Id = Target, EnableUserPreferenceAccess = true };
        user.SetPermission(PermissionKind.IsAdministrator, true);
        harness.AuthContext.GetAuthorizationInfo(Arg.Any<HttpRequest>()).Returns(Task.FromResult(new AuthorizationInfo { User = user }));
        return harness;
    }
}
