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
    /// The near-miss families (#1182), each spelled against the "post" ACS URL above. Every row is a string
    /// an identity provider - or somebody who controls one, or who registered a neighbouring host - can echo
    /// back, and the set membership must refuse all of them on both legs.
    /// <para>
    /// The prefix and suffix families run in BOTH directions on purpose, because each direction falsifies a
    /// different weakening. The rows where the echo is longer kill a match written as
    /// <c>echo.StartsWith(expected)</c> or <c>echo.EndsWith(expected)</c>; the rows where the echo is shorter
    /// kill <c>expected.StartsWith(echo)</c>, <c>expected.EndsWith(echo)</c> and <c>expected.Contains(echo)</c>.
    /// A table that only grows the echo leaves those three passing, so it would let a truncated echo, or the
    /// bare origin, bind an assertion.
    /// </para>
    /// </summary>
    /// <returns>The family name (for the failure message and the test display name) and the near-miss URL.</returns>
    public static TheoryData<string, string> NearMissAcsUrls()
    {
        var data = new TheoryData<string, string>
        {
            // prefix, echo shorter: the echo is a prefix of an expected URL. The first row is also the exact
            // ACS URL of a provider literally named "id", so accepting it would bind one provider's assertion
            // to another's endpoint; the second drops the provider segment altogether.
            { "prefix: echo truncated inside the provider name", "https://jf.example/sso/SAML/post/id" },
            { "prefix: echo without the provider segment", "https://jf.example/sso/SAML/post" },

            // prefix, echo longer: an expected URL is a prefix of the echo. A provider name that merely
            // starts with another provider's name must not bind that other provider's assertion.
            { "prefix: echo extends the provider name", "https://jf.example/sso/SAML/post/idpX" },
            { "prefix: echo appends a path segment", "https://jf.example/sso/SAML/post/idp/extra" },

            // suffix, echo longer: an expected URL sits at the end of the echo, or inside it as a parameter.
            // Both are strings an attacker can serve from a host they own.
            { "suffix: expected URL at the end of a longer string", "xhttps://jf.example/sso/SAML/post/idp" },
            { "suffix: expected URL carried in a query", "https://evil.example/r?u=https://jf.example/sso/SAML/post/idp" },

            // suffix, echo shorter: the echo is a suffix of an expected URL, here with the scheme stripped.
            { "suffix: echo is the expected URL without its scheme", "jf.example/sso/SAML/post/idp" },

            // neighbouring registrable name: the expected host is a string prefix of a longer name that
            // somebody else can register. #1182 files it under parent domain; it is not the parent of the
            // expected host, so the label says what it is rather than repeating that.
            { "neighbouring name: expected host extended by a label", "https://jf.example.evil/sso/SAML/post/idp" },

            // subdomain: a name below the expected host, which anybody holding the zone can create. #1182
            // lists these two under different bullets and they are the same shape, one extra label. Both are
            // kept because it names both, and the labels differ so a failure says which row broke.
            { "subdomain: hostile label below the expected host", "https://evil.jf.example/sso/SAML/post/idp" },
            { "subdomain: ordinary label below the expected host", "https://a.jf.example/sso/SAML/post/idp" },

            // scheme: the same host and path over plaintext. Nothing in #1182 names this family, and it is
            // the one row here with a direct consequence beyond binding: it aims the assertion POST at a
            // cleartext endpoint. The scheme is a per-provider knob (SchemeOverride, and the request scheme
            // when no BaseUrlOverride is set), so both spellings of one host really can be in play.
            { "scheme: http where https was published", "http://jf.example/sso/SAML/post/idp" },

            // authority: the expected host parked in the userinfo of somebody else's authority. This is what
            // a comparison anchored on "the expected host appears after the scheme" would accept.
            { "authority: expected host as userinfo", "https://jf.example@evil.example/sso/SAML/post/idp" },

            // url equivalence: strings a URL parser treats as the expected URL, or nearly so, and an ordinal
            // compare refuses. The likeliest future loosening of this predicate is parsing both sides as Uri
            // instead of comparing bytes, so these rows exist to make that change visible. Measured rather
            // than assumed, because the folding is narrower than it looks: under Uri equality the default
            // port, the dot segment, the percent-encoded segment and the host case all bind, and the trailing
            // slash does NOT, since Uri keeps a trailing path slash. The slash row is carried anyway as the
            // shortest echo-longer-by-one-character case there is.
            { "url equivalence: trailing slash", "https://jf.example/sso/SAML/post/idp/" },
            { "url equivalence: explicit default port", "https://jf.example:443/sso/SAML/post/idp" },
            { "url equivalence: dot segment", "https://jf.example/sso/SAML/post/../post/idp" },
            { "url equivalence: percent-encoded provider segment", "https://jf.example/sso/SAML/post/%69dp" },

            // case, and this is the family that carries a decision rather than an attack. The three rows are
            // below this block, in the order host, path segment, provider segment.
            //
            // Only the provider row is a plain security refusal. The provider segment is route-decoded input
            // that keys a byte-exact dictionary, so "idp" and "IDP" are two different providers with
            // independent role and admin mappings, and binding an assertion across that boundary is what this
            // predicate exists to stop.
            //
            // The host row and the path row are the deliberate ones, and they are the same decision. DNS host
            // names are case-insensitive and ASP.NET attribute routing is case-insensitive, so
            // "https://JF.EXAMPLE/sso/SAML/post/idp" and "https://jf.example/sso/saml/post/idp" both name the
            // endpoint the assertion was meant for. Refusing them refuses a well-behaved identity provider,
            // usually one whose ACS URL was typed into a console rather than echoed from the AuthnRequest.
            // Both are refused anyway, fail closed, and these rows pin that as intended.
            //
            // What a reader meeting this cold needs to know before "fixing" it:
            //
            // 1. Moving the comparison to StringComparer.OrdinalIgnoreCase is the wrong repair. The compared
            //    value is one string, so the same edit also case-folds the provider segment, and the provider
            //    row below would go red for a reason. Accepting a re-cased host or path means normalising
            //    those parts alone before the compare, which is a production change and its own issue.
            // 2. For an operator whose whole SAML userbase is locked out, in order: turn ValidateRecipient
            //    off, which restores logins immediately because the binding is opt-in and off by default;
            //    then pin BaseUrlOverride (#139); then re-register the ACS URL at the identity provider in
            //    the exact spelling this server publishes, which after step two is a lowercase host.
            // 3. Why step two is not enough on its own. The expected bytes are not a constant. With
            //    BaseUrlOverride set, CanonicalBaseUrl.Resolve puts the value through Uri, which lowercases
            //    the host, so the expected set is stable AND lowercase; an identity provider echoing an
            //    uppercase host stays refused, which is what step three is for. With no override the base URL
            //    is built by UriBuilder from the request Host header, which keeps whatever case the proxy
            //    forwarded, so the expected host case can differ between the challenge and the callback, and
            //    the same header is the one CanonicalBaseUrl documents as influenceable through an unfiltered
            //    X-Forwarded-Host. Pinning the override is therefore the fix for the expected side of this,
            //    not a nicety.
            { "case: host in a different case", "https://JF.EXAMPLE/sso/SAML/post/idp" },
            { "case: path segment in a different case", "https://jf.example/sso/saml/post/idp" },
            { "case: provider segment in a different case", "https://jf.example/sso/SAML/post/IDP" },
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
        // The Recipient leg is valid here, so a PRESENT Destination alone decides. The two legs are not
        // otherwise symmetric: a Destination that is absent, or blank once trimmed, is skipped rather than
        // refused - see BlankDestination_IsTreatedAsAbsent for why that is intended.
        Assert.False(
            SamlRecipientValidator.IsBound("https://jf.example/sso/SAML/post/idp", destination, AcsUrls),
            family);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t")]
    [InlineData("\u00A0")]
    public void BlankDestination_IsTreatedAsAbsent(string destination)
    {
        // Characterization, and the asymmetry is deliberate. Destination is a Response-level attribute, so it
        // is only signature-covered when the whole Response is signed; anyone able to rewrite it can delete
        // it instead, which is why the check runs only when a value is present and why the signed Recipient
        // is what actually carries the binding. Blanking it therefore buys an attacker nothing that deleting
        // it does not already buy. SamlResponse.GetDestination maps only the EMPTY attribute to null, so a
        // whitespace-only Destination does reach here verbatim and is trimmed to blank at this point.
        Assert.True(
            SamlRecipientValidator.IsBound("https://jf.example/sso/SAML/post/idp", destination, AcsUrls));
    }

    [Theory]
    [InlineData("\t")]
    [InlineData("\r\n")]
    [InlineData("\u00A0")]
    public void RecipientWithNonSpaceWhitespace_IsTrimmedAndBound(string pad)
    {
        // Where the trimming stops, pinned because #1182's boundary is a byte comparison and Trim() is the
        // one thing that runs before it. Trim() strips every Unicode whitespace category, not just spaces,
        // so a tab, a CRLF or a no-break space around the echo still binds. Each of these normalises to the
        // exact expected URL, so none of them binds a DIFFERENT endpoint.
        //
        // The asymmetry is worth knowing and cannot be pinned from here: only the ECHO is trimmed, never the
        // expected set, and provider names may legally carry leading or trailing whitespace because
        // ProviderNameValidator permits it and SamlAcsUrlBuilder appends the name raw. So a provider named
        // with edge whitespace publishes an ACS URL this predicate can never match once the identity provider
        // echoes it back, and in the other direction two providers whose names differ only by edge whitespace
        // are not told apart. Both are production questions, reported on #1182 rather than repaired here.
        Assert.True(SamlRecipientValidator.IsBound(pad + "https://jf.example/sso/SAML/post/idp" + pad, null, AcsUrls));
    }

    [Fact]
    public void RecipientWithZeroWidthSpace_FailsClosed()
    {
        // The other side of the line above: U+200B is not a whitespace category, so Trim() leaves it and the
        // comparison refuses. A future normalisation step that strips "invisible" characters more broadly
        // would turn this row red, which is the point of having it.
        Assert.False(SamlRecipientValidator.IsBound("https://jf.example/sso/SAML/post/idp\u200B", null, AcsUrls));
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
