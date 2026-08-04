// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The logout/SLO twin of <see cref="SamlAttackShapeTests"/> (#1003). <c>SamlLogoutRequest</c> runs its OWN
/// <see cref="System.Security.Cryptography.Xml.SignedXml"/> verification against a different document shape
/// (the signed element is the <c>samlp:LogoutRequest</c> root; there is no assertion, no bearer confirmation,
/// no audience), so the login path's hardening is not automatically the logout path's hardening - the two can
/// drift silently. This battery re-runs the 2025/26 vectors against it so a divergence fails here rather than
/// on an unauthenticated, session-destructive endpoint: void canonicalization, whole-document / detached
/// digest, signed-element-is-not-the-processed-element, Id/ID resolution pollution and namespace confusion.
///
/// Every shape must be REJECTED - either at parse (<c>TryParse</c> false) or at validation
/// (<c>IsValid</c> false) - and the honest baseline ACCEPTED, all against the real signature-validation path,
/// never a mock of the crypto.
/// </summary>
public class SamlLogoutAttackShapeTests
{
    private const string SamlNs = "urn:oasis:names:tc:SAML:2.0:assertion";
    private const string SamlpNs = "urn:oasis:names:tc:SAML:2.0:protocol";
    private const string DsNs = "http://www.w3.org/2000/09/xmldsig#";

    [Fact]
    public void IsValid_HonestBaseline_ReturnsTrue()
    {
        // The honest, correctly-signed LogoutRequest is accepted - the control every negative case below is
        // measured against, so a rejection there is attributable to the injected shape, not the setup.
        var fixture = SamlLogoutTestFactory.Create();

        Assert.True(SamlLogoutRequest.TryParse(fixture.CertificateBase64, null, fixture.EncodeRequest(), out var request));
        Assert.True(request.IsValid());
    }

    [Fact]
    public void IsValid_ReferenceUriIsUnresolvedRelativeUri_ReturnsFalse()
    {
        // Void canonicalization on the logout path: the Reference names an ID that resolves to nothing and the
        // DigestValue is the digest of the EMPTY octet stream, so a canonicalizer that emits an empty string
        // for an unresolved same-document reference finds exactly the digest the attacker wrote down. The
        // SignedInfo is genuinely signed with the fixture key; only the binding is hostile. Rejected because
        // the reference resolves to no element.
        var fixture = SamlCraftedSignatureFactory.CreateLogoutRequestWithCraftedReference("#_absent");

        Assert.True(SamlLogoutRequest.TryParse(fixture.CertificateBase64, null, fixture.EncodeRequest(), out var request));
        Assert.False(request.IsValid());
    }

    [Fact]
    public void IsValid_ReferenceUriIsEmptyStringWithDetachedDigest_ReturnsFalse()
    {
        // The whole-document reference form of the same trick: URI="" with a digest over the empty octet
        // stream rather than over the request. Only a same-document "#id" reference is accepted, so the
        // attacker cannot fall back to the form whose covered content is implicit rather than named.
        var fixture = SamlCraftedSignatureFactory.CreateLogoutRequestWithCraftedReference(string.Empty);

        Assert.True(SamlLogoutRequest.TryParse(fixture.CertificateBase64, null, fixture.EncodeRequest(), out var request));
        Assert.False(request.IsValid());
    }

    [Theory]
    [InlineData(SamlReferenceForm.WholeDocument)]
    [InlineData(SamlReferenceForm.XPointerWholeDocument)]
    [InlineData(SamlReferenceForm.XPointerId)]
    public void IsValid_HonestSignatureUnderANonShorthandReferenceForm_ReturnsFalse(SamlReferenceForm form)
    {
        // The reference spellings that are NOT the SAML shorthand pointer but which .NET resolves and signs
        // correctly: the empty whole-document URI, "#xpointer(/)", and "#xpointer(id('...'))". Every one is
        // accepted by CheckSignature - the control below proves it - and on this path the XPointer id() form
        // names the request ROOT, the very element whose NameID and SessionIndexes decide which sessions are
        // destroyed. Nothing cryptographic rejects them; only the "#id"-shorthand-only rule does, and that
        // rule currently rests on GetIdElement not understanding XPointer. Pinned so it stays a decision.
        var fixture = SamlCraftedSignatureFactory.CreateLogoutRequestWithHonestReference(form);

        Assert.True(SamlLogoutRequest.TryParse(fixture.CertificateBase64, null, fixture.EncodeRequest(), out var request));
        Assert.False(request.IsValid());
    }

    [Theory]
    [InlineData(SamlReferenceForm.WholeDocument)]
    [InlineData(SamlReferenceForm.XPointerWholeDocument)]
    [InlineData(SamlReferenceForm.XPointerId)]
    public void HonestReferenceForm_IsAcceptedByTheBclSignatureCheck(SamlReferenceForm form)
    {
        // The control that makes the rejections above evidence rather than decoration: each of these logout
        // requests carries a signature the BCL verifier accepts outright, so a rejection cannot be blamed on a
        // malformed fixture. The response-path twin lives in SamlAttackShapeTests.
        var fixture = SamlCraftedSignatureFactory.CreateLogoutRequestWithHonestReference(form);
        using var certificate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(fixture.CertificateBase64));

        var verifier = new SignedXml(fixture.Document);
        verifier.LoadXml((XmlElement)fixture.Document.GetElementsByTagName("Signature", DsNs)[0]!);

        Assert.True(verifier.CheckSignature(certificate, true));
    }

    [Theory]
    [InlineData("#_absent")]
    [InlineData("")]
    public void CraftedSignature_IsCryptographicallySoundOverItsSignedInfo(string referenceUri)
    {
        // The logout twin of the response-path control: it verifies with the identity provider's own public
        // key that the hand-assembled SignatureValue really is an RSA-SHA256 signature over the exclusive-C14N
        // canonical form of its SignedInfo. Without it the two crafted logout rejections would rest on
        // inference from the response path - and "no test passes for the wrong reason" is exactly this
        // control's job, so it does not get to be inherited.
        var fixture = SamlCraftedSignatureFactory.CreateLogoutRequestWithCraftedReference(referenceUri);
        var signature = (XmlElement)fixture.Document.GetElementsByTagName("Signature", DsNs)[0]!;
        var signedInfo = (XmlElement)signature.GetElementsByTagName("SignedInfo", DsNs)[0]!;
        var signatureValue = Convert.FromBase64String(signature.GetElementsByTagName("SignatureValue", DsNs)[0]!.InnerText.Trim());

        var standalone = new XmlDocument { PreserveWhitespace = true };
        standalone.LoadXml("<ds:SignedInfo xmlns:ds=\"" + DsNs + "\">" + signedInfo.InnerXml + "</ds:SignedInfo>");
        var transform = new XmlDsigExcC14NTransform();
        transform.LoadInput(standalone);
        using var canonical = new MemoryStream();
        ((Stream)transform.GetOutput(typeof(Stream))).CopyTo(canonical);

        using var certificate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(fixture.CertificateBase64));
        using var publicKey = certificate.GetRSAPublicKey()!;

        Assert.True(publicKey.VerifyData(canonical.ToArray(), signatureValue, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Theory]
    [InlineData("#_a\" or \"1\"=\"1")]
    [InlineData("#_a\"]|//*[@x=\"")]
    public void IsValid_ReferenceFragmentCarriesXPathMetacharacters_ReturnsFalse(string referenceUri)
    {
        // The logout twin: the shared reference rule refuses a non-NCName fragment on this path too, so the
        // unauthenticated, session-destructive endpoint does not depend on the host's compatibility
        // configuration to keep a crafted XPath payload out of reference resolution either.
        var fixture = SamlCraftedSignatureFactory.CreateLogoutRequestWithCraftedReference(referenceUri);

        Assert.True(SamlLogoutRequest.TryParse(fixture.CertificateBase64, null, fixture.EncodeRequest(), out var request));
        Assert.False(request.IsValid());
    }

    [Fact]
    public void IsValid_SignedElementIsNotTheProcessedElement_ReturnsFalse()
    {
        // Processing is bound to the SIGNED element by reference: here the identity provider's key genuinely
        // signs the saml:Issuer element - a real, verifying signature at the position-bound root location -
        // while the NameID and SessionIndexes that decide WHOSE sessions are destroyed sit in the unsigned
        // remainder of the request. Rejected because the reference covers something other than the root.
        var fixture = SamlCraftedSignatureFactory.CreateLogoutRequestSigningTheIssuerOnly();

        Assert.True(SamlLogoutRequest.TryParse(fixture.CertificateBase64, null, fixture.EncodeRequest(), out var request));
        Assert.False(request.IsValid());
    }

    [Fact]
    public void IsValid_IdAttributeCaseVariantDecoy_ReturnsFalse()
    {
        // Attribute pollution that steers reference resolution: the signed root carries ID="x" and an
        // added decoy carries Id="x" - a different attribute name, so the document stays well-formed and the
        // root's signature stays intact, but .NET resolves "Id" BEFORE "ID" and "#x" now names the decoy.
        // Rejected because the resolved element is not the LogoutRequest root.
        var fixture = SamlLogoutTestFactory.Create();
        var decoy = fixture.Document.CreateElement("samlp", "Extensions", SamlpNs);
        decoy.SetAttribute("Id", fixture.RequestId);
        fixture.Document.DocumentElement!.PrependChild(decoy);

        Assert.True(SamlLogoutRequest.TryParse(fixture.CertificateBase64, null, fixture.EncodeRequest(), out var request));
        Assert.False(request.IsValid());
    }

    [Fact]
    public void IsValid_ForeignNamespacedIdDecoy_ReturnsFalse()
    {
        // The same pollution in a foreign namespace: the decoy carries the signed root's ID value through
        // evil:ID. On the LOGIN path the equivalent decoy is inert (it can sit outside the signed assertion,
        // and the namespace-aware resolver simply never sees it - see
        // SamlAttackShapeTests.IsValid_ForeignNamespacedIdOutsideSignedContent_IsInert_HonestAssertionStillValidates).
        // Here the signature covers the LogoutRequest ROOT, so there is no unsigned region for a decoy to hide
        // in at all: anything injected is inside the signed content and the digest rejects it. Pinned as its
        // own case because that asymmetry is a property of the logout document shape, not an accident - a
        // future change that narrowed the logout signature to some inner element would open exactly the
        // unsigned region this path currently does not have, and this test would flip.
        var fixture = SamlLogoutTestFactory.Create();
        var document = fixture.Document;
        var decoy = document.CreateElement("samlp", "Extensions", SamlpNs);
        var polluted = document.CreateAttribute("evil", "ID", "urn:evil");
        polluted.Value = fixture.RequestId;
        decoy.SetAttributeNode(polluted);
        document.DocumentElement!.PrependChild(decoy);

        Assert.True(SamlLogoutRequest.TryParse(fixture.CertificateBase64, null, fixture.EncodeRequest(), out var request));
        Assert.False(request.IsValid());
    }

    [Theory]
    [InlineData("xmlns:xml=\"urn:evil\"")] // the reserved "xml" prefix rebound to an attacker namespace
    [InlineData("xmlns:ev=\"http://www.w3.org/XML/1998/namespace\"")] // the reserved XML namespace bound to an ordinary prefix
    [InlineData("xmlns:xmlns=\"urn:evil\"")] // the reserved "xmlns" prefix declared as an ordinary one
    public void TryParse_ReservedXmlAttributeUsedAsOrdinaryAttribute_ReturnsFalse(string reservedDeclaration)
    {
        // Namespace confusion through the reserved XML namespace machinery, on the unauthenticated,
        // session-destructive endpoint: all three forms violate the namespace constraints, so the hardened
        // reader refuses the document and TryParse fails closed to a clean rejection rather than handing back
        // a half-interpreted DOM.
        var xml =
            "<samlp:LogoutRequest xmlns:samlp=\"" + SamlpNs + "\" xmlns:saml=\"" + SamlNs + "\" " + reservedDeclaration + " ID=\"_r\" Version=\"2.0\">" +
                "<saml:NameID>attacker</saml:NameID>" +
            "</samlp:LogoutRequest>";

        Assert.False(SamlLogoutRequest.TryParse(SamlFixture.ForeignCertificateBase64(), null, SamlLogoutTestFactory.Encode(xml), out var request));
        Assert.Null(request);
    }

    [Fact]
    public void IsValid_NamespaceConfusedDecoySignature_ReturnsFalse()
    {
        // Namespace confusion aimed at the position-bound signature selection: the honest signature is
        // replaced by one whose element is named "Signature" in a FOREIGN namespace, the shape a
        // namespace-agnostic GetElementsByTagName("Signature") would happily pick up and hand to the
        // verifier. The namespace-bound XPath selects nothing, so the request reads as UNSIGNED and is
        // rejected - a request whose only "signature" is a look-alike must never be treated as signed.
        var fixture = SamlLogoutTestFactory.Create();
        var document = fixture.Document;
        var signature = document.GetElementsByTagName("Signature", DsNs)[0]!;
        var lookAlike = document.CreateElement("ds", "Signature", "urn:evil:xmldsig");
        lookAlike.InnerXml = signature.InnerXml;
        signature.ParentNode!.ReplaceChild(lookAlike, signature);

        Assert.True(SamlLogoutRequest.TryParse(fixture.CertificateBase64, null, fixture.EncodeRequest(), out var request));
        Assert.False(request.IsValid());
    }
}
