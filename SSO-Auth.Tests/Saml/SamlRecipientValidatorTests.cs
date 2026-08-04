// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SamlRecipientValidator"/> - the pure endpoint-binding check (#156): the
/// signed Recipient (required) and the Response Destination (when present) must match one of this
/// service provider's assertion-consumer URLs.
/// </summary>
public class SamlRecipientValidatorTests
{
    private static readonly string[] AcsUrls =
    {
        "https://jf.example/sso/SAML/post/idp",
        "https://jf.example/sso/SAML/p/idp",
    };

    [Fact]
    public void RecipientMatchingAcs_NoDestination_IsBound()
    {
        Assert.True(SamlRecipientValidator.IsBound("https://jf.example/sso/SAML/post/idp", null, AcsUrls));
    }

    [Fact]
    public void RecipientMatchingLegacyPathForm_IsBound()
    {
        // Either advertised path spelling (post/p) is accepted - the NewPath-flip robustness.
        Assert.True(SamlRecipientValidator.IsBound("https://jf.example/sso/SAML/p/idp", null, AcsUrls));
    }

    [Fact]
    public void RecipientWithSurroundingWhitespace_IsTrimmedAndBound()
    {
        Assert.True(SamlRecipientValidator.IsBound("  https://jf.example/sso/SAML/post/idp  ", null, AcsUrls));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("https://evil.example/sso/SAML/post/idp")]
    public void MissingOrMismatchedRecipient_FailsClosed(string? recipient)
    {
        Assert.False(SamlRecipientValidator.IsBound(recipient!, null, AcsUrls));
    }

    /// <summary>
    /// The near-miss families (#1182), each spelled against the "post" ACS URL above. Every one of them is a
    /// string an identity provider - or somebody who controls one, or who registered a neighbouring host -
    /// can echo back, and every one of them would be accepted by a comparison somebody could reach for
    /// instead of the exact one: a prefix or "starts with" match takes the first two, a host-suffix match
    /// takes the parent-domain pair, a registrable-domain match takes the subdomain, and a case-insensitive
    /// match takes the last. The set membership must refuse all of them, on both legs.
    /// </summary>
    /// <returns>The family name (for the failure message and the test display name) and the near-miss URL.</returns>
    public static TheoryData<string, string> NearMissAcsUrls()
    {
        var data = new TheoryData<string, string>
        {
            // prefix: the expected URL is a prefix of the echo. A provider name that merely starts with
            // another provider's name must not bind that other provider's assertion.
            { "prefix: longer provider name", "https://jf.example/sso/SAML/post/idpX" },
            { "prefix: extra path segment", "https://jf.example/sso/SAML/post/idp/extra" },

            // suffix / parent-domain: the expected host is a prefix of a longer registrable name, and the
            // expected authority sits inside a longer one. Both are hosts an attacker can register.
            { "suffix: expected host as a parent domain", "https://jf.example.evil/sso/SAML/post/idp" },
            { "suffix: label prepended to the expected host", "https://evil.jf.example/sso/SAML/post/idp" },

            // subdomain: a name below the expected host, which anybody holding the zone can create.
            { "subdomain: label below the expected host", "https://a.jf.example/sso/SAML/post/idp" },

            // case: the host differs only in case, and DNS host names are case-insensitive, so this is the
            // one row here that is NOT an attack - it is a well-behaved identity provider that normalised or
            // re-cased the host in its echo, and it is refused.
            //
            // That refusal is deliberate and it is an interop decision, not an accident of the comparer. The
            // contract this predicate enforces is an exact echo of the bytes this service provider emitted in
            // AssertionConsumerServiceURL (see SamlAcsUrlBuilder, which concatenates and never re-encodes for
            // exactly this reason), so an ordinal comparison is the whole check. Refusing a re-cased host is
            // the fail-closed side of that contract: the cost is that such an identity provider cannot use
            // the opt-in ValidateRecipient binding until it echoes the URL unchanged.
            //
            // Do not "fix" this row by moving the comparison to StringComparer.OrdinalIgnoreCase. Case
            // insensitivity cannot be applied to the host alone here - the compared value is one string, so
            // the same change also makes the PATH case-insensitive, and the provider segment is
            // route-decoded, attacker-influenced input. Loosening it would let "post/IdP" bind "post/idp".
            // Accepting a re-cased host means normalising the host before the compare, which is a production
            // change with its own issue, not an edit to the comparer here.
            { "case: host in a different case", "https://JF.EXAMPLE/sso/SAML/post/idp" },
        };

        return data;
    }

    [Theory]
    [MemberData(nameof(NearMissAcsUrls))]
    public void RecipientNearMissOfAcs_NoDestination_FailsClosed(string family, string recipient)
    {
        Assert.False(SamlRecipientValidator.IsBound(recipient, null, AcsUrls), family);
    }

    [Theory]
    [MemberData(nameof(NearMissAcsUrls))]
    public void DestinationNearMissOfAcs_OnValidRecipient_FailsClosed(string family, string destination)
    {
        // The Recipient leg is valid here, so the Destination alone decides: the Response-level echo is held
        // to the same boundary as the signed one, or an unsigned Destination would be the weaker of the two.
        Assert.False(
            SamlRecipientValidator.IsBound("https://jf.example/sso/SAML/post/idp", destination, AcsUrls),
            family);
    }

    [Fact]
    public void DestinationPresentAndMatching_IsBound()
    {
        Assert.True(SamlRecipientValidator.IsBound(
            "https://jf.example/sso/SAML/post/idp",
            "https://jf.example/sso/SAML/post/idp",
            AcsUrls));
    }

    [Fact]
    public void DestinationPresentButMismatched_IsRejected()
    {
        // A Response-level Destination that is present must still match (defense in depth), even
        // though the Recipient itself is valid.
        Assert.False(SamlRecipientValidator.IsBound(
            "https://jf.example/sso/SAML/post/idp",
            "https://evil.example/sso/SAML/post/idp",
            AcsUrls));
    }
}
