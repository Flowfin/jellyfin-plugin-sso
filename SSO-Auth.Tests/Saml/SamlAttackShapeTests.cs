// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Characterization/regression tests pinning the SAML core's defenses against the known
/// 2025-2026 SAML attack shapes (#153). They complement <see cref="SamlResponseTests"/>
/// (which already pins SHA-1 downgrade, DOCTYPE/XXE, missing time-bounds, audience/recipient
/// confusion, plain two-assertion wrapping and relocated-signature) by adding the shapes that
/// were not yet pinned:
///
/// <list type="bullet">
///   <item>comment-truncation of NameID (CVE-2017-11428 — https://nvd.nist.gov/vuln/detail/CVE-2017-11428),</item>
///   <item>an unsigned assertion injected BEFORE the signed one,</item>
///   <item>duplicate and foreign-namespaced ID-attribute pollution (PortSwigger 'The Fragile Lock', 2025 —
///         https://portswigger.net/research/the-fragile-lock; GHSL-2024-329/330),</item>
///   <item>a ds:Signature relocated into a decoy wrapper outside the element its Reference covers,</item>
///   <item>assertion/advice confusion (a decoy assertion smuggled into saml:Advice).</item>
/// </list>
///
/// #1003 adds the three families published in December 2025 (PortSwigger, 'The Fragile Lock',
/// https://portswigger.net/research/the-fragile-lock; the ruby-saml chain CVE-2025-25291/25292 and its
/// incomplete fixes CVE-2025-66567/66568; samlify CVE-2025-47949; authentik CVE-2026-47201), each mapped to
/// the test that pins it:
///
/// <list type="bullet">
///   <item>VOID CANONICALIZATION — <see cref="IsValid_ReferenceUriIsUnresolvedRelativeUri_ReturnsFalse"/>,
///         <see cref="IsValid_ReferenceUriIsEmptyStringWithDetachedDigest_ReturnsFalse"/>,
///         <see cref="IsValid_ReferenceUriIsWholeDocument_ReturnsFalse"/>,
///         <see cref="IsValid_ReferenceUriIsAnXPointer_ReturnsFalse"/>.</item>
///   <item>REFERENCE / ID CONFUSION — <see cref="IsValid_SignedElementIsNotTheProcessedElement_ReturnsFalse"/>,
///         <see cref="IsValid_MoreThanOneAssertionInResponse_ReturnsFalse"/>,
///         <see cref="IsValid_IdAttributeCaseVariantDecoy_ReturnsFalse"/>.</item>
///   <item>ATTRIBUTE POLLUTION — <see cref="IsValid_AttributePollutionSameLocalNameDifferentNamespace_ReturnsFalse"/>,
///         <see cref="GetCustomAttributes_AttributePollutionOnAttributeName_ReadsSignedValueOnly"/>,
///         <see cref="IsValid_ForeignNamespacedIdOutsideSignedContent_IsInert_HonestAssertionStillValidates"/>.</item>
///   <item>NAMESPACE CONFUSION — <see cref="IsValid_ReservedXmlAttributeUsedAsOrdinaryAttribute_ReturnsFalse"/>,
///         <see cref="IsValid_NamespaceConfusedDecoySignature_ReturnsFalse"/>,
///         <see cref="IsValid_NamespaceConfusedDecoyAssertion_IsInert_ReadsSignedAssertionOnly"/>.</item>
/// </list>
///
/// Two controls keep the negatives honest, because a fixture that is merely broken would make them pass for
/// the wrong reason forever: <see cref="CraftedSignature_IsCryptographicallySoundOverItsSignedInfo"/> proves
/// the hand-assembled signatures really do sign their own canonical SignedInfo, and
/// <see cref="HonestReferenceForm_IsAcceptedByTheBclSignatureCheck"/> proves the non-shorthand reference
/// forms are accepted by the BCL verifier outright — so those rejections are the repo's rule, not the
/// platform's.
///
/// Two of those vectors are INERT rather than rejected (the two named ..._IsInert_...): a foreign-namespaced
/// ID outside the signed content, and a decoy Assertion in a foreign namespace, are both invisible to a
/// namespace-aware resolver, so the honest response keeps validating and every reader keeps returning the
/// SIGNED values. That is the correct outcome, not a gap — rejecting spec-legal foreign-namespace content
/// would be an availability regression with no security gain — and each is pinned with the signed value it
/// must still read, so it flips to red the day a namespace-agnostic lookup is introduced. The structural
/// counterpart is <c>ArchitectureConformanceTests.SamlSignaturePath_UsesOneXmlStackEndToEnd</c> /
/// <c>SamlSignaturePath_ParsesOnlyThroughTheHardenedReader</c> /
/// <c>SamlSignaturePath_ResolvesElementsNamespaceAware</c>, which forbid the second XML stack, the
/// unhardened parse seam, and the namespace-agnostic lookup that would turn these inert shapes into live
/// ones. The logout/SLO twin of this
/// battery lives in <see cref="SamlLogoutAttackShapeTests"/>.
///
/// Every malicious shape must be REJECTED (or, for comment-truncation, must NOT be truncatable)
/// and the honest baseline ACCEPTED — all against the real signature-validation path in
/// <see cref="SamlResponse"/>, never a mock of the crypto. These are TESTS ONLY: they pin existing
/// fail-closed behavior; no production change is expected while that behavior holds. A shape that
/// turns out to be ACCEPTED is a real defect to be filed as its own security finding, not papered
/// over here.
/// </summary>
public class SamlAttackShapeTests
{
    private const string SamlNs = "urn:oasis:names:tc:SAML:2.0:assertion";
    private const string DsNs = "http://www.w3.org/2000/09/xmldsig#";

    private static SamlResponse Load(SamlFixture fixture, string? certificateBase64 = null)
        => new SamlResponse(certificateBase64 ?? fixture.CertificateBase64, fixture.EncodeResponse());

    [Fact]
    public void IsValid_HonestBaseline_ReturnsTrue()
    {
        // The honest, correctly-signed response is accepted — the control every negative case below
        // is measured against, so a rejection there is attributable to the injected shape, not the setup.
        Assert.True(Load(SamlTestFactory.Create()).IsValid());
    }

    // --- Comment truncation (CVE-2017-11428) ---

    [Fact]
    public void GetNameID_CommentSplitNameId_IsNotTruncated_AndSignatureStaysValid()
    {
        // CVE-2017-11428: the IdP signs NameID = "admin@attacker.example" (the attacker's real
        // account). The attacker then splits it around an XML comment — "admin<!--x-->@attacker.example"
        // — WITHOUT changing the comment-free canonical text, so exclusive C14N (comment-free) strips
        // the comment and the signature still verifies. An SP that reads only the first text node
        // (FirstChild.Value) would truncate to "admin" and grant the privileged account. The plugin
        // reads XmlNode.InnerText, which concatenates across the comment, so the value is NOT
        // truncatable. This pins that: a refactor to FirstChild.Value/InnerXml would flip it and
        // silently reintroduce the CVE.
        var fixture = SamlTestFactory.Create(nameId: "admin@attacker.example", scope: SamlTestFactory.SignatureScope.Assertion);
        var doc = fixture.Document;
        var nameId = doc.GetElementsByTagName("NameID", SamlNs)[0]!;
        nameId.RemoveAll();
        nameId.AppendChild(doc.CreateTextNode("admin"));
        nameId.AppendChild(doc.CreateComment("x"));
        nameId.AppendChild(doc.CreateTextNode("@attacker.example"));

        var response = Load(fixture);

        // The comment does not alter the comment-free canonical form, so the signature remains valid...
        Assert.True(response.IsValid());
        // ...and the extracted identity is the FULL address, never the truncated "admin".
        Assert.Equal("admin@attacker.example", response.GetNameID());
        Assert.NotEqual("admin", response.GetNameID());
    }

    [Fact]
    public void GetCustomAttributes_CommentSplitAttributeValue_IsNotTruncated()
    {
        // The same truncation trick applied to a Role AttributeValue: an SP that truncated at the
        // comment could read "jellyfin-" instead of "jellyfin-users" (or drop a suffix that gates a
        // role match). InnerText concatenates, so the full value survives.
        var fixture = SamlTestFactory.Create(role: "jellyfin-users", scope: SamlTestFactory.SignatureScope.Assertion);
        var doc = fixture.Document;
        var attributeValue = doc.GetElementsByTagName("AttributeValue", SamlNs)[0]!;
        attributeValue.RemoveAll();
        attributeValue.AppendChild(doc.CreateTextNode("jellyfin-"));
        attributeValue.AppendChild(doc.CreateComment("x"));
        attributeValue.AppendChild(doc.CreateTextNode("users"));

        var response = Load(fixture);

        Assert.True(response.IsValid());
        Assert.Equal(new List<string> { "jellyfin-users" }, response.GetCustomAttributes("Role"));
    }

    // --- Assertion injected before the signed one ---

    [Fact]
    public void IsValid_UnsignedAssertionPrependedToResponseScopeSignature_ReturnsFalse()
    {
        // The whole SamlResponse is signed; the attacker prepends an unsigned assertion carrying a
        // different identity as the FIRST assertion (the one every reader consumes as Assertion[1]).
        // Rejected twice over: the single-assertion invariant now counts two direct-child assertions,
        // and prepending also perturbs the signed SamlResponse so the digest no longer matches.
        var fixture = SamlTestFactory.Create(nameId: "alice", scope: SamlTestFactory.SignatureScope.Response);
        var doc = fixture.Document;
        doc.DocumentElement!.PrependChild(BuildEvilAssertion(doc, "attacker"));

        Assert.False(Load(fixture).IsValid());
    }

    [Fact]
    public void IsValid_UnsignedAssertionPrependedToAssertionScopeSignature_ReturnsFalse()
    {
        // Only the honest assertion is signed; the attacker prepends an unsigned assertion so that
        // Assertion[1] is theirs while the signature reference still resolves to the honest, second
        // assertion. The single-assertion invariant rejects the response before any reader can be
        // pointed at the attacker's node.
        var fixture = SamlTestFactory.Create(nameId: "alice", scope: SamlTestFactory.SignatureScope.Assertion);
        var doc = fixture.Document;
        doc.DocumentElement!.PrependChild(BuildEvilAssertion(doc, "attacker"));

        Assert.False(Load(fixture).IsValid());
    }

    // --- Duplicate / namespaced ID-attribute pollution (GHSL-2024-329/330, 'The Fragile Lock') ---

    [Fact]
    public void IsValid_DecoyElementReusesSignedAssertionId_ReturnsFalse()
    {
        // ID pollution: a decoy element (not an assertion, so the single-assertion count stays one)
        // is given the SAME plain ID as the signed assertion. ID resolution over the untrusted
        // document is now ambiguous; the validator must fail closed rather than let the attacker steer
        // which element the "#id" reference resolves to.
        var fixture = SamlTestFactory.Create(scope: SamlTestFactory.SignatureScope.Assertion);
        var doc = fixture.Document;
        var decoy = doc.CreateElement("saml", "AuthnStatement", SamlNs);
        decoy.SetAttribute("ID", fixture.AssertionId);
        doc.DocumentElement!.PrependChild(decoy);

        Assert.False(Load(fixture).IsValid());
    }

    [Fact]
    public void IsValid_ForeignNamespacedIdDecoy_IsInert_HonestAssertionStillValidates()
    {
        // 'Fragile Lock' foreign-namespace ID pollution: a decoy element carries the signed
        // assertion's ID value only through a FOREIGN-namespace attribute (xml:id), the kind some
        // parsers resolve inconsistently. It is deliberately NOT a second saml:Assertion, so the
        // single-assertion invariant is not what does the work — this isolates ID resolution itself.
        // The enveloped-signature "#id" reference must keep binding to the real assertion (whose plain
        // ID it names): .NET's GetIdElement resolves only unprefixed Id/ID/id, so the xml:id decoy is
        // invisible and the pollution is inert — the honest signature still validates and extraction
        // still reads the signed "alice". If a change ever let the xml:id target the signature, the
        // reference would resolve to the decoy, the digest would no longer match, and this would flip
        // to a rejection — which the assertions below would catch.
        var fixture = SamlTestFactory.Create(nameId: "alice", scope: SamlTestFactory.SignatureScope.Assertion);
        var doc = fixture.Document;
        var decoy = doc.CreateElement("saml", "AuthnStatement", SamlNs);
        var xmlId = doc.CreateAttribute("xml", "id", "http://www.w3.org/XML/1998/namespace");
        xmlId.Value = fixture.AssertionId;
        decoy.SetAttributeNode(xmlId);
        doc.DocumentElement!.PrependChild(decoy);

        var response = Load(fixture);

        Assert.True(response.IsValid());
        Assert.Equal("alice", response.GetNameID());
    }

    // --- Signature relocated into a decoy wrapper outside the covered element ---

    [Fact]
    public void IsValid_SignatureRelocatedIntoDecoyWrapper_ReturnsFalse()
    {
        // The enveloped signature is lifted out of the assertion it covers and re-parented under a
        // decoy wrapper element hung off the SamlResponse. The reference still names the assertion ID, but
        // the position-bound signature selection only accepts a ds:Signature that is a direct child of
        // the SamlResponse or the Assertion — a signature buried in a wrapper is not selected at all, so
        // the response reads as unsigned and is rejected.
        var fixture = SamlTestFactory.Create(scope: SamlTestFactory.SignatureScope.Assertion);
        var doc = fixture.Document;
        var signature = doc.GetElementsByTagName("Signature", DsNs)[0]!;
        signature.ParentNode!.RemoveChild(signature);
        var wrapper = doc.CreateElement("saml", "Advice", SamlNs);
        wrapper.AppendChild(signature);
        doc.DocumentElement!.AppendChild(wrapper);

        Assert.False(Load(fixture).IsValid());
    }

    // --- Assertion / Advice confusion ---

    [Fact]
    public void GetNameID_DecoyAssertionInsideAdvice_ReadsSignedSubjectNotAdvice()
    {
        // A decoy assertion carrying "attacker" is smuggled into the honest assertion's saml:Advice.
        // Because it is added AFTER signing it is not part of the signed content, yet saml:Advice is a
        // spec-legal container so the response must not be rejected merely for its presence — instead
        // the readers, scoped to the SamlResponse's direct-child Assertion[1]/Subject, must ignore the
        // nested decoy and continue to read the signed "alice". This pins assertion/advice confusion
        // resistance: the advice subject never shadows the real one.
        var fixture = SamlTestFactory.Create(nameId: "alice", scope: SamlTestFactory.SignatureScope.Response);
        var doc = fixture.Document;
        var assertion = (XmlElement)doc.GetElementsByTagName("Assertion", SamlNs)[0]!;
        var advice = doc.CreateElement("saml", "Advice", SamlNs);
        advice.AppendChild(BuildEvilAssertion(doc, "attacker"));
        // Advice must precede Subject per the SAML schema; prepend keeps the document schema-shaped.
        assertion.PrependChild(advice);

        var response = Load(fixture);

        // Adding the (unsigned) advice perturbs the signed SamlResponse, so IsValid is false; the
        // load-bearing assertion is that identity extraction never returns the advice's "attacker".
        Assert.False(response.IsValid());
        Assert.NotEqual("attacker", response.GetNameID());
        Assert.Equal("alice", response.GetNameID());
    }

    // --- Strict-conformance shapes (#238): single signature, per-restriction audience, bearer method ---

    [Fact]
    public void IsValid_HonestlySignedOnBothResponseAndAssertion_ReturnsTrue()
    {
        // #238 (1): the Web Browser SSO profile permits signing BOTH the Response and the Assertion
        // (Keycloak "Sign Documents" + "Sign Assertions", Azure AD "Sign response and assertion", ADFS
        // MessageAndAssertion), so a doubly-signed honest response must be ACCEPTED — every position-bound
        // signature validates, which is what the validator now requires.
        Assert.True(Load(SamlTestFactory.CreateDoublySigned()).IsValid());
    }

    [Fact]
    public void IsValid_DoublySignedButOneSignatureInvalid_ReturnsFalse()
    {
        // #238 (1): with two position-bound signatures EVERY one must validate — not just the first in
        // document order. The Assertion-level signature stays honest (it is first in document order, so a
        // first-wins reading would accept the response), but the Response-level signature is corrupted, so
        // the response is rejected. This pins "validate all, not first-wins" and closes the ambiguity of
        // multiple signatures without rejecting the honest doubly-signed case above.
        var fixture = SamlTestFactory.CreateDoublySigned();
        var doc = fixture.Document;
        foreach (XmlElement signature in doc.GetElementsByTagName("Signature", DsNs))
        {
            // The Response-level signature is the one whose parent is the Response root (the
            // Assertion-level one's parent is the Assertion). Corrupt only its SignatureValue.
            if (signature.ParentNode == doc.DocumentElement)
            {
                var signatureValue = (XmlElement)signature.GetElementsByTagName("SignatureValue", DsNs)[0]!;
                // Flip one signature byte and re-encode: still valid base64 (so it is not rejected merely
                // as malformed at load time) but a wrong signature, so the Response-level signature fails
                // the actual cryptographic CheckSignature against the pinned cert.
                var bytes = Convert.FromBase64String(signatureValue.InnerText.Trim());
                bytes[0] ^= 0xFF;
                signatureValue.InnerText = Convert.ToBase64String(bytes);
                break;
            }
        }

        Assert.False(Load(fixture).IsValid());
    }

    [Fact]
    public void IsValidAudience_PresentInEveryRestriction_ReturnsTrue()
    {
        // Positive control for #238 (2): SAML 2.0 allows multiple <AudienceRestriction> blocks; the SP is
        // addressed when it appears in EVERY one. Our audience is in both, so the response is accepted.
        var fixture = SamlTestFactory.Create(
            scope: SamlTestFactory.SignatureScope.Response,
            audienceRestrictions: new[] { new[] { "https://sp.example.com" }, new[] { "https://sp.example.com", "https://other.example.com" } });

        Assert.True(Load(fixture).IsValid("https://sp.example.com"));
    }

    [Fact]
    public void IsValidAudience_PresentInOnlyOneOfTwoRestrictions_ReturnsFalse()
    {
        // #238 (2): the first <AudienceRestriction> names ANOTHER SP and only the second names us. SAML
        // 2.0 requires the SP in every restriction (AND across blocks), so this is not strictly addressed
        // to us; the old OR-over-the-union accepted it, the AND rejects it.
        var fixture = SamlTestFactory.Create(
            scope: SamlTestFactory.SignatureScope.Response,
            audienceRestrictions: new[] { new[] { "https://other.example.com" }, new[] { "https://sp.example.com" } });

        Assert.False(Load(fixture).IsValid("https://sp.example.com"));
    }

    [Fact]
    public void IsValid_NonBearerSubjectConfirmationMethod_ReturnsFalse()
    {
        // #238 (3): a holder-of-key confirmation carries no bearer token (its key-possession proof is not
        // verified here). The Web Browser SSO profile is a bearer profile, so an assertion offering only a
        // non-bearer confirmation is rejected. A Conditions upper bound is set so the time check is not
        // what rejects — this isolates the bearer-method check.
        var fixture = SamlTestFactory.Create(
            subjectConfirmationMethod: "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key",
            conditionsNotOnOrAfter: DateTime.UtcNow.AddMinutes(5));

        Assert.False(Load(fixture).IsValid());
    }

    [Fact]
    public void IsValid_SubjectConfirmationWithNoMethod_ReturnsFalse()
    {
        // A SubjectConfirmation with no Method at all is likewise not a bearer confirmation. Same
        // Conditions-bound isolation as above.
        var fixture = SamlTestFactory.Create(
            subjectConfirmationMethod: null,
            conditionsNotOnOrAfter: DateTime.UtcNow.AddMinutes(5));

        Assert.False(Load(fixture).IsValid());
    }

    [Fact]
    public void IsValid_BearerConfirmationWithConditionsBound_ReturnsTrue()
    {
        // Positive control isolating the bearer-method check: identical to the two rejects above except
        // the confirmation Method IS bearer, so the response is accepted — proving the method value is
        // what flips those cases, not the time bound or another guard.
        var fixture = SamlTestFactory.Create(conditionsNotOnOrAfter: DateTime.UtcNow.AddMinutes(5));

        Assert.True(Load(fixture).IsValid());
    }

    // --- Void canonicalization and reference/ID confusion (#1003, 'The Fragile Lock' 2025-12) ---

    [Theory]
    [InlineData("#_absent")]
    [InlineData("")]
    public void CraftedSignature_IsCryptographicallySoundOverItsSignedInfo(string referenceUri)
    {
        // The control for the two crafted-reference cases below, and the reason they are evidence rather than
        // decoration: it verifies, with the identity provider's own public key, that the crafted SignatureValue
        // really is an RSA-SHA256 signature over the exclusive-C14N canonical form of that SignedInfo. So the
        // rejections below are attributable to the REFERENCE BINDING — the digest covers nothing, or names
        // nothing — and not to a forgery that happens to be malformed. Without this control a broken crafted
        // signature would make those tests pass for the wrong reason forever.
        var fixture = SamlCraftedSignatureFactory.CreateResponseWithCraftedReference(referenceUri);
        var signature = (XmlElement)fixture.Document.GetElementsByTagName("Signature", DsNs)[0]!;
        var signedInfo = (XmlElement)signature.GetElementsByTagName("SignedInfo", DsNs)[0]!;
        var signatureValue = Convert.FromBase64String(signature.GetElementsByTagName("SignatureValue", DsNs)[0]!.InnerText.Trim());

        // Exclusive C14N renders only visibly-utilized prefixes, so canonicalizing the SignedInfo with its ds
        // declaration restored reproduces exactly the octets a verifier canonicalizes it to in place.
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

    [Fact]
    public void IsValid_ReferenceUriIsUnresolvedRelativeUri_ReturnsFalse()
    {
        // Void canonicalization: the Reference names an ID ("#_absent") that resolves to NOTHING, and the
        // DigestValue is the digest of the EMPTY octet stream — so a canonicalizer that silently emits an
        // empty string for an unresolved same-document reference computes exactly the digest the attacker
        // wrote down, and the reference "verifies" while the assertion actually consumed was never signed.
        // The SignedInfo is real: it is exclusive-C14N canonicalized and signed with the fixture key, so the
        // signature itself is cryptographically sound and only the binding is hostile. The validator must
        // reject because the reference resolves to no element at all.
        var fixture = SamlCraftedSignatureFactory.CreateResponseWithCraftedReference("#_absent");

        Assert.False(Load(fixture).IsValid());
    }

    [Fact]
    public void IsValid_ReferenceUriIsEmptyStringWithDetachedDigest_ReturnsFalse()
    {
        // The same void-canonicalization trick through the whole-document reference form: URI="" with a
        // DigestValue over the empty octet stream rather than over the document. SAML 2.0 requires the
        // reference to name the signed element's ID, so an empty (or any non-"#id") URI is rejected before a
        // digest is ever compared — the attacker cannot fall back to the form whose covered content is
        // implicit rather than named.
        var fixture = SamlCraftedSignatureFactory.CreateResponseWithCraftedReference(string.Empty);

        Assert.False(Load(fixture).IsValid());
    }

    [Fact]
    public void IsValid_ReferenceUriIsWholeDocument_ReturnsFalse()
    {
        // The strictly harder twin of the case above: a CRYPTOGRAPHICALLY COMPLETE whole-document signature
        // (URI="" with an honestly computed digest, emitted by SignedXml itself), so nothing about the
        // cryptography is wrong and CheckSignature would accept it. Only the "the reference must name the
        // Response or the Assertion by ID" binding can reject it, which makes this the sharpest probe of that
        // binding: the day it is relaxed, this test — not a crypto failure — is what turns red.
        var fixture = SamlCraftedSignatureFactory.CreateResponseWithWholeDocumentReference();

        Assert.False(Load(fixture).IsValid());
    }

    [Theory]
    [InlineData(SamlReferenceForm.XPointerWholeDocument)]
    [InlineData(SamlReferenceForm.XPointerId)]
    public void IsValid_ReferenceUriIsAnXPointer_ReturnsFalse(SamlReferenceForm form)
    {
        // The one reference spelling that gets PAST the "#..." gate and that .NET genuinely honours. Its
        // resolver understands two XPointer forms beyond the SAML shorthand pointer: "#xpointer(/)" is the
        // whole document, and "#xpointer(id('x'))" is unwrapped to the plain id "x". Both are signed correctly
        // by SignedXml and accepted by CheckSignature — the id() form covers the very assertion the readers
        // consume — so nothing cryptographic rejects them.
        //
        // What rejects them today is that the validator hands GetIdElement the RAW remainder after the "#",
        // which is not an ID, so the lookup returns null. That is an implicit BCL behaviour, not a rule this
        // repo states: a future BCL change, or any replacement of the ID lookup with something that unwraps
        // XPointer the way Reference.CalculateHashValue does, would open it silently. SAML 2.0 mandates the
        // shorthand "#id" form, so rejecting these is the fail-closed posture — pinned here so it stays a
        // decision rather than an accident. The companion control asserts CheckSignature really does accept
        // them, so this cannot pass because the fixture is broken.
        var fixture = SamlCraftedSignatureFactory.CreateResponseWithHonestReference(form);

        Assert.False(Load(fixture).IsValid());
    }

    [Theory]
    [InlineData(SamlReferenceForm.WholeDocument)]
    [InlineData(SamlReferenceForm.XPointerWholeDocument)]
    [InlineData(SamlReferenceForm.XPointerId)]
    public void HonestReferenceForm_IsAcceptedByTheBclSignatureCheck(SamlReferenceForm form)
    {
        // The control that makes the two rejection tests above (and the whole-document one below) evidence:
        // every one of these documents carries a signature the BCL verifier accepts outright. If a fixture
        // were subtly malformed, the rejections would be attributable to the forgery rather than to the
        // reference-form binding, and this control is what would catch that.
        var fixture = SamlCraftedSignatureFactory.CreateResponseWithHonestReference(form);
        using var certificate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(fixture.CertificateBase64));

        var verifier = new SignedXml(fixture.Document);
        verifier.LoadXml((XmlElement)fixture.Document.GetElementsByTagName("Signature", DsNs)[0]!);

        Assert.True(verifier.CheckSignature(certificate, true));
    }

    [Fact]
    public void IsValid_SignedElementIsNotTheProcessedElement_ReturnsFalse()
    {
        // Processing must be bound to the SIGNED element by reference, not merely to "a valid signature is
        // present somewhere". The identity provider's key here genuinely signs the saml:Issuer element — a
        // real, verifying signature, sitting at the position-bound direct-child-of-Response location — while
        // the Subject/NameID/attributes the plugin actually reads live in an entirely unsigned assertion.
        // Rejected because the reference covers neither the Response root nor the Assertion.
        var fixture = SamlCraftedSignatureFactory.CreateResponseSigningTheIssuerOnly();

        Assert.False(Load(fixture).IsValid());
    }

    [Fact]
    public void IsValid_MoreThanOneAssertionInResponse_ReturnsFalse()
    {
        // Two direct-child assertions, each INDEPENDENTLY and honestly signed by the identity provider's key,
        // so every signature verifies and no digest is broken: the exactly-one-assertion invariant is the sole
        // control. It must reject the response outright rather than pick one — "pick the first" would consume
        // the attacker's, "pick the signed one" is undecidable when both are signed. This is the shape the
        // pre-existing prepended-unsigned-assertion tests cannot reach, because there a broken digest also
        // rejects; here nothing but the count does.
        var fixture = SamlCraftedSignatureFactory.CreateResponseWithTwoSignedAssertions(firstNameId: "attacker", secondNameId: "alice");

        Assert.False(Load(fixture).IsValid());
        Assert.False(Load(fixture).IsValid("https://sp.example.com"));
    }

    // --- Attribute pollution (#1003) ---

    [Fact]
    public void IsValid_AttributePollutionSameLocalNameDifferentNamespace_ReturnsFalse()
    {
        // Attribute pollution: a SECOND attribute whose local name is also "ID" but in a foreign namespace is
        // added to the signed assertion, so a resolver that matched attributes by local name (ignoring the
        // namespace) would resolve the reference to the attacker's value while the namespace-aware one
        // resolves the real ID. Because the polluted attribute has to sit ON the signed element to be
        // reachable that way, it is inside the signed content and the digest no longer matches — pollution
        // cannot be smuggled into a signed element. Rejected.
        var fixture = SamlTestFactory.Create(nameId: "alice", scope: SamlTestFactory.SignatureScope.Assertion);
        var doc = fixture.Document;
        var assertion = (XmlElement)doc.GetElementsByTagName("Assertion", SamlNs)[0]!;
        var polluted = doc.CreateAttribute("evil", "ID", "urn:evil");
        polluted.Value = "_evil";
        assertion.SetAttributeNode(polluted);

        Assert.False(Load(fixture).IsValid());
    }

    [Fact]
    public void IsValid_IdAttributeCaseVariantDecoy_ReturnsFalse()
    {
        // The attribute-pollution variant that actually steers resolution: the honest assertion carries
        // ID="x" (the SAML spelling), and a decoy element carries Id="x" — a DIFFERENT attribute name, so the
        // document stays well-formed and the assertion's signature stays intact. .NET's reference resolver
        // tries "Id" BEFORE "ID", so "#x" resolves to the decoy, not to the assertion the readers consume:
        // exactly the parser-differential shape behind the ruby-saml chain, reproduced inside one stack.
        // Rejected because the resolved element is neither the Response root nor the Assertion.
        var fixture = SamlTestFactory.Create(nameId: "alice", scope: SamlTestFactory.SignatureScope.Assertion);
        var doc = fixture.Document;
        var decoy = doc.CreateElement("saml", "AuthnStatement", SamlNs);
        decoy.SetAttribute("Id", fixture.AssertionId);
        doc.DocumentElement!.PrependChild(decoy);

        Assert.False(Load(fixture).IsValid());
    }

    [Fact]
    public void IsValid_ForeignNamespacedIdOutsideSignedContent_IsInert_HonestAssertionStillValidates()
    {
        // Pins the BCL's ID-resolution semantics, which the whole reference binding rests on: .NET tries the
        // unprefixed Id, then id, then ID, and each probe is an XPath attribute test in the NULL namespace. A
        // decoy sibling carrying the signed assertion's ID value through a foreign-namespaced evil:ID is
        // therefore invisible to all three probes — the reference keeps binding to the real assertion and the
        // honest login still succeeds. It sits outside the signed content, so no digest is what makes this
        // pass; only the resolution semantics do.
        //
        // The load-bearing assertions are the SIGNED values that survive: the subject, and GetAssertionId(),
        // which is what the one-time replay key is derived from. If a .NET upgrade ever made a namespaced
        // attribute a resolution candidate, GetIdElement would see two matches and throw, or bind to the
        // decoy — either way this flips, and the replay key would be the first thing to move.
        var fixture = SamlTestFactory.Create(nameId: "alice", scope: SamlTestFactory.SignatureScope.Assertion);
        var doc = fixture.Document;
        var decoy = doc.CreateElement("saml", "AuthnStatement", SamlNs);
        var polluted = doc.CreateAttribute("evil", "ID", "urn:evil");
        polluted.Value = fixture.AssertionId;
        decoy.SetAttributeNode(polluted);
        doc.DocumentElement!.PrependChild(decoy);

        var response = Load(fixture);

        Assert.True(response.IsValid());
        Assert.Equal("alice", response.GetNameID());
        Assert.Equal(fixture.AssertionId, response.GetAssertionId());
    }

    [Fact]
    public void IsValid_NamespaceConfusedDecoySignature_ReturnsFalse()
    {
        // Namespace confusion aimed at the position-bound signature selection: the honest signature is
        // replaced by one whose element is named "Signature" in a FOREIGN namespace — the look-alike a
        // namespace-agnostic GetElementsByTagName("Signature") would happily pick up and hand to the verifier.
        // The namespace-bound XPath selects nothing, so signatureNodes.Count is zero, the response reads as
        // UNSIGNED and is rejected. The logout twin is SamlLogoutAttackShapeTests with the same name.
        var fixture = SamlTestFactory.Create(nameId: "alice", scope: SamlTestFactory.SignatureScope.Assertion);
        var doc = fixture.Document;
        var signature = doc.GetElementsByTagName("Signature", DsNs)[0]!;
        var lookAlike = doc.CreateElement("ds", "Signature", "urn:evil:xmldsig");
        lookAlike.InnerXml = signature.InnerXml;
        signature.ParentNode!.ReplaceChild(lookAlike, signature);

        Assert.False(Load(fixture).IsValid());
    }

    [Fact]
    public void GetCustomAttributes_AttributePollutionOnAttributeName_ReadsSignedValueOnly()
    {
        // Attribute pollution aimed at the ROLE reader rather than at the signature: a decoy saml:Attribute
        // declares its name through a foreign-namespaced evil:Name="Role" and carries a privileged value.
        // GetCustomAttributes matches the unprefixed Name attribute, so the decoy contributes nothing and the
        // only role returned is the signed one. The decoy also perturbs the signed assertion, so IsValid is
        // false; the load-bearing assertion is that the reader never surfaces the injected role — a reader
        // that matched by local name would hand the caller "jellyfin-admins".
        var fixture = SamlTestFactory.Create(nameId: "alice", role: "jellyfin-users", scope: SamlTestFactory.SignatureScope.Assertion);
        var doc = fixture.Document;
        var statement = (XmlElement)doc.GetElementsByTagName("AttributeStatement", SamlNs)[0]!;
        var decoy = doc.CreateElement("saml", "Attribute", SamlNs);
        var pollutedName = doc.CreateAttribute("evil", "Name", "urn:evil");
        pollutedName.Value = "Role";
        decoy.SetAttributeNode(pollutedName);
        var value = doc.CreateElement("saml", "AttributeValue", SamlNs);
        value.InnerText = "jellyfin-admins";
        decoy.AppendChild(value);
        statement.PrependChild(decoy);

        var response = Load(fixture);

        Assert.False(response.IsValid());
        Assert.Equal(new List<string> { "jellyfin-users" }, response.GetCustomAttributes("Role"));
    }

    // --- Namespace confusion (#1003) ---

    [Theory]
    [InlineData("xmlns:xml=\"urn:evil\"")] // the reserved "xml" prefix rebound to an attacker namespace
    [InlineData("xmlns:ev=\"http://www.w3.org/XML/1998/namespace\"")] // the reserved XML namespace bound to an ordinary prefix
    [InlineData("xmlns:xmlns=\"urn:evil\"")] // the reserved "xmlns" prefix declared as an ordinary one
    public void IsValid_ReservedXmlAttributeUsedAsOrdinaryAttribute_ReturnsFalse(string reservedDeclaration)
    {
        // Namespace confusion through the reserved XML namespace machinery: rebinding the "xml"/"xmlns"
        // prefixes, or binding the reserved XML namespace URI to an ordinary prefix, makes one parser see a
        // prefixed name in one namespace and another parser see it in a different one — the way a "same"
        // element or attribute can mean two things to two stacks. All three forms are namespace-constraint
        // violations, so the hardened reader refuses the document outright and TryParse fails closed to a
        // clean rejection rather than handing back a half-interpreted DOM (or escaping as a 500).
        var xml =
            "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"" + SamlNs + "\" " + reservedDeclaration + " ID=\"_r\" Version=\"2.0\">" +
                "<saml:Assertion ID=\"_a\" Version=\"2.0\"><saml:Subject><saml:NameID>attacker</saml:NameID></saml:Subject></saml:Assertion>" +
            "</samlp:Response>";

        Assert.False(SamlResponseLoader.TryParse(SamlFixture.ForeignCertificateBase64(), SamlFixture.Encode(xml), out var response));
        Assert.Null(response);
    }

    [Fact]
    public void IsValid_NamespaceConfusedDecoyAssertion_IsInert_ReadsSignedAssertionOnly()
    {
        // Namespace confusion aimed at the exactly-one-assertion count: a decoy element named "Assertion" —
        // but in a FOREIGN namespace — is prepended as a sibling of the honest assertion, outside the signed
        // content so no digest breaks. Every lookup on this path is namespace-bound, so the decoy is neither
        // counted as a second assertion nor readable as one, and the honest login still returns the SIGNED
        // subject. A namespace-agnostic GetElementsByTagName("Assertion") would instead have counted two (a
        // spurious rejection of every such response) or, worse, read the decoy's subject — which is why
        // SamlSignaturePath_ResolvesElementsNamespaceAware bans that lookup shape outright.
        var fixture = SamlTestFactory.Create(nameId: "alice", scope: SamlTestFactory.SignatureScope.Assertion);
        var doc = fixture.Document;
        const string EvilNs = "urn:evil:assertion";
        var decoy = doc.CreateElement("evil", "Assertion", EvilNs);
        var subject = doc.CreateElement("evil", "Subject", EvilNs);
        var nameId = doc.CreateElement("evil", "NameID", EvilNs);
        nameId.InnerText = "attacker";
        subject.AppendChild(nameId);
        decoy.AppendChild(subject);
        doc.DocumentElement!.PrependChild(decoy);

        var response = Load(fixture);

        Assert.True(response.IsValid());
        Assert.Equal("alice", response.GetNameID());
    }

    // Builds an unsigned attacker-controlled assertion with the given NameID, shaped like a real one
    // (ID/Version/Subject/NameID) so injection tests exercise the count/reference/position checks
    // rather than tripping on malformed XML.
    private static XmlElement BuildEvilAssertion(XmlDocument doc, string nameId)
    {
        var evil = doc.CreateElement("saml", "Assertion", SamlNs);
        evil.SetAttribute("ID", "_evil");
        evil.SetAttribute("Version", "2.0");
        var subject = doc.CreateElement("saml", "Subject", SamlNs);
        var name = doc.CreateElement("saml", "NameID", SamlNs);
        name.InnerText = nameId;
        subject.AppendChild(name);
        evil.AppendChild(subject);
        return evil;
    }
}
