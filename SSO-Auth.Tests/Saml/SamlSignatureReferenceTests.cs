// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The reference-URI rule both signature validators share (#1003): a same-document <c>#id</c> shorthand
/// pointer whose fragment is an XML <c>NCName</c>, and nothing else. Owning this rule here (rather than
/// leaning on .NET's own NCName guard inside <c>DefaultGetIdElement</c>, which is documented as
/// compatibility-switchable and sits above an XPath predicate that interpolates the fragment unescaped) is
/// what makes the rejection a property of this plugin instead of a property of the host's configuration.
/// </summary>
public class SamlSignatureReferenceTests
{
    [Theory]
    [InlineData("#_a1b2c3")] // the shape every conformant identity provider emits
    [InlineData("#assertion")]
    [InlineData("#_")]
    [InlineData("#a.b-c_d")] // dots, hyphens and underscores are all NCName characters
    public void TryGetSameDocumentId_ShorthandPointerWithNcNameFragment_ReturnsTheFragment(string referenceUri)
    {
        Assert.True(SamlSignatureReference.TryGetSameDocumentId(referenceUri, out var id));
        Assert.Equal(referenceUri.Substring(1), id);
    }

    [Theory]
    [InlineData(null)] // no reference at all
    [InlineData("")] // the whole-document form: covers content the readers do not bind to
    [InlineData("#")] // a pointer to nothing
    [InlineData("https://idp.example.com/doc#a")] // an external reference
    [InlineData("cid:attachment")] // a non-fragment scheme
    [InlineData("#xpointer(/)")] // resolved by .NET as the whole document, not the shorthand SAML mandates
    [InlineData("#xpointer(id('_a'))")] // unwrapped by .NET to the plain id, same
    [InlineData("#0leading")] // an NCName may not start with a digit
    [InlineData("#ns:name")] // a colon makes it a QName, not an NCName
    [InlineData("#has space")]
    public void TryGetSameDocumentId_AnythingElse_ReturnsFalse(string? referenceUri)
    {
        Assert.False(SamlSignatureReference.TryGetSameDocumentId(referenceUri, out var id));
        Assert.Null(id);
    }

    [Theory]
    [InlineData("#_a\" or \"1\"=\"1")] // closes the quoted XPath literal
    [InlineData("#_a\"]|//*[@x=\"")] // closes the predicate and appends another step
    [InlineData("#_a']|//*[@x='")] // the single-quoted variant
    public void TryGetSameDocumentId_FragmentCarryingXPathMetacharacters_ReturnsFalse(string referenceUri)
    {
        // The reason the NCName rule is enforced here rather than borrowed. Below .NET's own guard,
        // GetSingleReferenceTarget builds its lookup as "//*[@Id=\"" + idValue + "\"]" with the value
        // interpolated UNESCAPED; so a fragment carrying a quote is XPath injection inside reference
        // resolution on any host where that guard is relaxed by a compatibility switch. No quote, bracket or
        // pipe is an NCName character, so every such fragment is refused before it can reach the lookup.
        Assert.False(SamlSignatureReference.TryGetSameDocumentId(referenceUri, out var id));
        Assert.Null(id);
    }
}
