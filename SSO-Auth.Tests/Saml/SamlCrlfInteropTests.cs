// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>Interop regression tests pinning that a conformantly signed, pretty-printed SAML response, the shape production signing stacks emit, still validates through <see cref="SamlResponse"/> (#120).</summary>
/// <remarks>
/// The hardened reader normalizes line endings to LF per XML 1.0 before building the DOM, and the rest of the
/// suite uses compact single-line fixtures, so a regression to a non-normalizing parser would break interop
/// while passing every existing test. Three cases make the pin non-vacuous: raw CRLF on the wire validates
/// against a signature computed over the LF form, altering the whitespace content is a digest mismatch, which
/// proves the whitespace is signature-covered, and the same ending written as a character reference also
/// validates, which is why the positive case encodes raw wire bytes and asserts the wire carries them.
/// </remarks>
public class SamlCrlfInteropTests
{
    [Fact]
    public void IsValid_WireWithRawCrlfBetweenElements_NormalizesAndValidates()
    {
        var fixture = SamlTestFactory.CreateIndented();

        // The signed document serializes to an LF baseline with no stray CR - confirm that before
        // reshaping it, so the CRLF on the wire below is introduced here, not already present.
        var lfBaseline = fixture.Document.OuterXml;
        Assert.Contains("\n", lfBaseline);
        Assert.DoesNotContain("\r", lfBaseline);
        Assert.DoesNotContain("&#xD;", lfBaseline);

        // Put RAW CRLF bytes on the wire between elements - the shape a conformant IdP emits - and
        // encode those bytes directly (never via OuterXml, which would escape CR to &#xD;). The reader
        // normalizes CRLF -> LF to reproduce the signed form, so the signature verifies.
        var wire = lfBaseline.Replace("\n", "\r\n");
        Assert.Contains("\r\n", wire);
        Assert.DoesNotContain("&#xD;", wire); // raw CR bytes on the wire, not the OuterXml escape

        var response = new SamlResponse(fixture.CertificateBase64, SamlFixture.Encode(wire));

        Assert.True(response.IsValid());
        Assert.Equal("alice", response.GetNameID()); // end-to-end read-through, not just the signature
    }

    [Fact]
    public void IsValid_InterElementWhitespaceAltered_FailsClosed()
    {
        // Vacuity guard for the raw-CRLF case: the inter-element whitespace is signature-covered, so
        // changing its CONTENT - here one extra indentation space the IdP never signed - is a digest
        // mismatch and is rejected. This is what makes the raw-CRLF acceptance meaningful: it is
        // specifically line-ending normalization (CRLF ≡ LF), not the parser ignoring whitespace.
        var fixture = SamlTestFactory.CreateIndented();
        var altered = fixture.Document.OuterXml.Replace("\n", "\r\n "); // CRLF plus an extra space per break

        var response = new SamlResponse(fixture.CertificateBase64, SamlFixture.Encode(altered));

        Assert.False(response.IsValid());
    }

    [Fact]
    public void IsValid_LineEndingCrAsCharacterReference_StillValidates()
    {
        // The OuterXml-escaping pitfall, pinned: the CR of the line ending expressed as a &#xD; character
        // reference (exactly what serializing a CR-bearing DOM via OuterXml produces) is exempt from XML
        // 1.0 §2.11 normalization, yet .NET's C14N normalizes line-ending CR as well, so this validates
        // too. A "CRLF" test built via OuterXml would thus pass while shipping &#xD; rather than raw
        // CRLF - passing for the wrong reason; the positive test encodes raw bytes precisely to avoid it.
        var fixture = SamlTestFactory.CreateIndented();
        var charRefWire = fixture.Document.OuterXml.Replace("\n", "&#xD;\n");
        Assert.Contains("&#xD;", charRefWire);

        var response = new SamlResponse(fixture.CertificateBase64, SamlFixture.Encode(charRefWire));

        Assert.True(response.IsValid());
    }
}
