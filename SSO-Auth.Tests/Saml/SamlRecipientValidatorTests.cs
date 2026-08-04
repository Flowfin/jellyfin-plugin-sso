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

            // parent domain: the expected host is a string prefix of a longer registrable name that somebody
            // else can register. It is not the parent domain of the expected host, it is a different one.
            { "parent domain: expected host extended by a label", "https://jf.example.evil/sso/SAML/post/idp" },

            // subdomain: a name below the expected host, which anybody holding the zone can create. #1182
            // lists these two under different bullets, but they are one shape (one extra label) and no
            // comparison can accept one and refuse the other. Both are kept because both are named there.
            { "subdomain: label below the expected host", "https://evil.jf.example/sso/SAML/post/idp" },
            { "subdomain: label below the expected host", "https://a.jf.example/sso/SAML/post/idp" },

            // case, and this is the family that carries a decision rather than an attack.
            //
            // The comparison is StringComparer.Ordinal, so all three rows are refused. For the path and the
            // provider segment that is plainly right: ASP.NET routing is case-insensitive, so
            // "/sso/saml/post/idp" is a working POST target, and the provider segment is route-decoded input
            // that keys a byte-exact provider dictionary, in which "idp" and "IDP" are two different
            // providers with independent role and admin mappings. Binding an assertion across that boundary
            // is exactly what this predicate exists to stop.
            //
            // The host row is the deliberate one. DNS host names are case-insensitive, so a host echoed back
            // in a different case is the same endpoint, and refusing it refuses a well-behaved identity
            // provider. It is refused anyway, fail closed, and this row pins that as intended.
            //
            // What a reader meeting this cold needs to know before "fixing" it:
            //
            // 1. Moving the comparison to StringComparer.OrdinalIgnoreCase is the wrong repair. The compared
            //    value is one string, so the same edit also case-folds the path and the provider segment, and
            //    the two rows above it would go red for a reason. Accepting a re-cased host means normalising
            //    the host alone before the compare, which is a production change and its own issue.
            // 2. The expected bytes are not a constant, so this is not only about the identity provider. With
            //    BaseUrlOverride set, CanonicalBaseUrl.Resolve runs the value through Uri, which lowercases
            //    the host, so the expected set is stable. With no override (the default) the base URL is
            //    built by UriBuilder from the request Host header, which preserves whatever case the proxy
            //    forwarded, so the expected host case can differ between the challenge and the callback.
            // 3. So the operator-facing remedy for a deployment locked out by this is to pin BaseUrlOverride
            //    (#139), which makes the emitted bytes stable, and only then to look at the identity
            //    provider, which may be echoing a console-registered string rather than the
            //    AssertionConsumerServiceURL it was sent.
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
