// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Text.Json;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Both discovery flag readers state a total contract - <see cref="PkceDiscovery.SupportsS256(string?)"/>
/// answers <c>false</c> on anything unexpected, <see cref="OidcResponseIssuer"/>'s flag fails tolerant - and
/// neither said it throws. Both did (#1340), on a document naming a member with an unpaired surrogate escape:
/// <c>JsonElement.TryGetProperty</c> unescapes every candidate whose raw name is longer than the name being
/// looked for, and a lone high surrogate has no completion, so the decoder raises
/// <c>InvalidOperationException</c> out of the lookup.
///
/// The padding is what selected which reader fell over, which is why every case here is built from the
/// reader's OWN property-name length rather than from one hand-written document. Measured on the unfixed
/// readers: the throw begins at 27 filler characters for <c>code_challenge_methods_supported</c> (32 bytes)
/// and at 41 for <c>authorization_response_iss_parameter_supported</c> (46 bytes) - the first padding at
/// which the six-byte escape makes the raw name longer than the name being matched. A repair to one reader
/// that leaves the other therefore reddens the other reader's sweep here rather than passing.
/// </summary>
public class DiscoveryMemberNameSurrogateTests
{
    private const string PkceName = "code_challenge_methods_supported";

    private const string ResponseIssuerName = "authorization_response_iss_parameter_supported";

    [Fact]
    public void SupportsS256_MemberNameCarryingALoneSurrogateEscape_AnswersFalseRatherThanThrowing()
    {
        // Swept rather than pinned at the one measured length, because the boundary is arithmetic on the
        // property name and a sweep past it cannot be made vacuous by a later rename.
        for (var filler = 0; filler <= PkceName.Length + 8; filler++)
        {
            var json = UndecodableNameOnly(filler);
            Assert.False(PkceDiscovery.SupportsS256(json));
            Assert.False(PkceDiscovery.SupportsS256(Root(json)));
        }
    }

    [Fact]
    public void DiscoveryAdvertisesResponseIssuer_MemberNameCarryingALoneSurrogateEscape_AnswersFalseRatherThanThrowing()
    {
        for (var filler = 0; filler <= ResponseIssuerName.Length + 8; filler++)
        {
            var json = UndecodableNameOnly(filler);
            Assert.False(OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer(json));
            Assert.False(OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer(Root(json)));
        }
    }

    [Fact]
    public void SupportsS256_UndecodableNameBesideTheRealMember_StillReadsS256()
    {
        // The availability half, and the reason the repair skips the member instead of answering "absent"
        // for the document. False here refuses every login wherever RequirePkce is on, so one member name
        // the decoder cannot complete must not be able to take a provider that does advertise S256 offline.
        var json = "{" + UndecodableMember(PkceName.Length - 5)
            + ",\"" + PkceName + "\":[\"S256\"]}";

        Assert.True(PkceDiscovery.SupportsS256(json));
        Assert.True(PkceDiscovery.SupportsS256(Root(json)));
    }

    [Fact]
    public void DiscoveryAdvertisesResponseIssuer_UndecodableNameBesideTheFlag_StillReadsTrue()
    {
        var json = "{" + UndecodableMember(ResponseIssuerName.Length - 5)
            + ",\"" + ResponseIssuerName + "\":true}";

        Assert.True(OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer(json));
        Assert.True(OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer(Root(json)));
    }

    [Fact]
    public void UndecodableNameAtTheOtherReadersLength_LeavesEachReadersOwnAnswerIntact()
    {
        // The issue's table, kept as a test: padding to one reader's name length is what used to decide which
        // reader fell over, so a document carrying both paddings has to leave both facts readable.
        var json = "{" + UndecodableMember(PkceName.Length - 5)
            + "," + UndecodableMember(ResponseIssuerName.Length - 5)
            + ",\"" + PkceName + "\":[\"S256\"]"
            + ",\"" + ResponseIssuerName + "\":true}";

        Assert.True(PkceDiscovery.SupportsS256(json));
        Assert.True(OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer(json));
    }

    [Theory]
    [InlineData("{\"\\ud800aaaaaaaaaaaaaaaaaaaaaaaaaaa\":1,\"code_challenge_methods_supported\":[\"S256\"]}", PkceName)]
    [InlineData("{\"\\ud800aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\":1,\"authorization_response_iss_parameter_supported\":true}", ResponseIssuerName)]
    public void CommittedFuzzSeedsCarryThePaddingThatReachesTheArm(string seed, string name)
    {
        // The two seeds in SSO-Auth.Fuzz/corpus/discovery/ are what makes the smoke gate replay this arm, and
        // a seed whose filler is one character short reaches nothing while still parsing and still passing a
        // "it did not throw" assertion. So the padding is compared rather than trusted: each literal is the
        // committed seed body, and has to open with the undecodable member this file builds for that
        // reader's own name length.
        Assert.StartsWith("{" + UndecodableMember(name.Length - 5) + ",\"" + name + "\":", seed, StringComparison.Ordinal);
    }

    // A document whose ONLY member is the undecodable name, so neither fact is present and the honest answer
    // is false for both readers - which is also the answer a throw was hiding.
    private static string UndecodableNameOnly(int filler) => "{" + UndecodableMember(filler) + "}";

    // `\ud800` is a high surrogate with no low surrogate after it: six raw characters that no unescape can
    // complete. The filler pads the name so the raw member name outruns the name being looked for, which is
    // the only reason the lookup tries to unescape it at all.
    private static string UndecodableMember(int filler) => "\"\\ud800" + new string('a', filler) + "\":1";

    private static JsonElement? Root(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.Clone();
    }
}
