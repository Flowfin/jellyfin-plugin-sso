// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Globalization;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Builds SAML documents whose <c>ds:Signature</c> is CRAFTED rather than produced by
/// <see cref="SignedXml.ComputeSignature"/> — the shapes the .NET signer refuses to emit but an attacker
/// can hand-assemble (#1003): a <c>Reference</c> naming an ID that resolves to nothing, a whole-document
/// (<c>URI=""</c>) reference carrying a digest over a different octet stream, and a reference covering an
/// element other than the one the readers consume.
///
/// The crafted signatures are REAL cryptography, never mocks: the <c>SignedInfo</c> is exclusive-C14N
/// canonicalized and signed with the fixture's RSA key, so <c>SignedXml.CheckSignature</c> would accept the
/// signature itself. Only the reference binding is hostile — which is precisely the property the validator's
/// reference checks must reject on, so a test built on these documents fails the moment those checks are
/// weakened.
/// </summary>
internal static class SamlCraftedSignatureFactory
{
    private const string SamlNs = "urn:oasis:names:tc:SAML:2.0:assertion";
    private const string SamlpNs = "urn:oasis:names:tc:SAML:2.0:protocol";
    private const string DsNs = "http://www.w3.org/2000/09/xmldsig#";
    private const string TimeFormat = "yyyy-MM-ddTHH:mm:ssZ";

    /// <summary>
    /// Produces a SAML response whose single, position-bound <c>ds:Signature</c> (a direct child of the
    /// Response root) carries the given <c>Reference URI</c> and a <c>DigestValue</c> computed over
    /// <paramref name="digestedOctets"/> — empty by default, the "void canonicalization" shape where the
    /// digest covers nothing at all.
    /// </summary>
    /// <param name="referenceUri">The literal <c>Reference/@URI</c> value to emit (e.g. <c>#_absent</c> or the empty string).</param>
    /// <param name="digestedOctets">The octets the DigestValue is computed over; null means the empty octet stream.</param>
    /// <param name="nameId">The value placed in saml:NameID.</param>
    /// <returns>A fixture whose document carries the crafted signature.</returns>
    internal static SamlFixture CreateResponseWithCraftedReference(string referenceUri, byte[]? digestedOctets = null, string nameId = "attacker")
    {
        var responseId = "_" + Guid.NewGuid().ToString("N");
        var assertionId = "_" + Guid.NewGuid().ToString("N");
        var document = LoadResponse(BuildResponseXml(responseId, assertionId, nameId));

        using var rsa = RSA.Create(2048);
        var certificate = SelfSign(rsa);
        var signature = BuildSignature(document, rsa, certificate, referenceUri, digestedOctets ?? Array.Empty<byte>());
        document.DocumentElement!.AppendChild(signature);

        return new SamlFixture(certificate, document, responseId, assertionId);
    }

    /// <summary>
    /// Produces a SAML response carrying a CRYPTOGRAPHICALLY COMPLETE whole-document signature: a
    /// <c>Reference URI=""</c> with an honestly computed digest, produced by <see cref="SignedXml"/> itself.
    /// Nothing about the cryptography is wrong — <c>CheckSignature</c> accepts it — so the only thing that can
    /// reject it is the same-document-ID-reference requirement, which makes it the strongest available probe
    /// of that binding (the strictly harder twin of the detached-digest <c>URI=""</c> shape).
    /// </summary>
    /// <param name="nameId">The value placed in saml:NameID.</param>
    /// <returns>A fixture whose document carries a valid whole-document signature.</returns>
    internal static SamlFixture CreateResponseWithWholeDocumentReference(string nameId = "attacker")
    {
        var responseId = "_" + Guid.NewGuid().ToString("N");
        var assertionId = "_" + Guid.NewGuid().ToString("N");
        var document = LoadResponse(BuildResponseXml(responseId, assertionId, nameId));

        using var rsa = RSA.Create(2048);
        var certificate = SelfSign(rsa);

        var signedXml = new SignedXml(document) { SigningKey = rsa };
        var reference = new Reference(string.Empty) { DigestMethod = SignedXml.XmlDsigSHA256Url };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(reference);
        signedXml.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(certificate));
        signedXml.KeyInfo = keyInfo;
        signedXml.ComputeSignature();

        document.DocumentElement!.AppendChild(document.ImportNode(signedXml.GetXml(), true));

        return new SamlFixture(certificate, document, responseId, assertionId);
    }

    /// <summary>
    /// Produces a SAML response whose signature honestly covers the <c>saml:Issuer</c> element (given its own
    /// ID and genuinely digested) rather than the Response root or the Assertion the readers consume — the
    /// "signed element is not the processed element" shape. The signature sits at the position-bound root
    /// location, so only the reference-covers-{root|assertion} binding can reject it.
    /// </summary>
    /// <param name="nameId">The value placed in saml:NameID.</param>
    /// <returns>A fixture whose document carries a valid signature over the wrong element.</returns>
    internal static SamlFixture CreateResponseSigningTheIssuerOnly(string nameId = "attacker")
    {
        var responseId = "_" + Guid.NewGuid().ToString("N");
        var assertionId = "_" + Guid.NewGuid().ToString("N");
        var issuerId = "_" + Guid.NewGuid().ToString("N");
        var document = LoadResponse(BuildResponseXml(responseId, assertionId, nameId, issuerId));

        using var rsa = RSA.Create(2048);
        var certificate = SelfSign(rsa);

        var signedXml = new SignedXml(document) { SigningKey = rsa };
        var reference = new Reference("#" + issuerId) { DigestMethod = SignedXml.XmlDsigSHA256Url };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(reference);
        signedXml.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(certificate));
        signedXml.KeyInfo = keyInfo;
        signedXml.ComputeSignature();

        // Placed at the position-bound root location: the selection and enveloped-within checks must not be
        // what rejects it — the reference-covers-{root|assertion} binding must.
        document.DocumentElement!.AppendChild(document.ImportNode(signedXml.GetXml(), true));

        return new SamlFixture(certificate, document, responseId, assertionId);
    }

    /// <summary>
    /// Produces a SAML response carrying TWO direct-child assertions, each INDEPENDENTLY and honestly signed
    /// by the same key — so every signature verifies and only the exactly-one-assertion invariant can reject
    /// the document. The second assertion names a different subject.
    /// </summary>
    /// <param name="firstNameId">The subject of the first (document-order) assertion.</param>
    /// <param name="secondNameId">The subject of the second assertion.</param>
    /// <returns>A fixture whose document carries two individually valid signed assertions.</returns>
    internal static SamlFixture CreateResponseWithTwoSignedAssertions(string firstNameId = "attacker", string secondNameId = "alice")
    {
        var responseId = "_" + Guid.NewGuid().ToString("N");
        var firstId = "_" + Guid.NewGuid().ToString("N");
        var secondId = "_" + Guid.NewGuid().ToString("N");
        var notOnOrAfter = DateTime.UtcNow.AddMinutes(5).ToString(TimeFormat, CultureInfo.InvariantCulture);

        var xml =
            "<samlp:Response xmlns:samlp=\"" + SamlpNs + "\" xmlns:saml=\"" + SamlNs + "\" ID=\"" + responseId + "\" Version=\"2.0\">" +
                Assertion(firstId, firstNameId, notOnOrAfter) +
                Assertion(secondId, secondNameId, notOnOrAfter) +
            "</samlp:Response>";

        var document = LoadResponse(xml);
        using var rsa = RSA.Create(2048);
        var certificate = SelfSign(rsa);
        SignEnveloped(document, firstId, rsa, certificate);
        SignEnveloped(document, secondId, rsa, certificate);

        return new SamlFixture(certificate, document, responseId, firstId);
    }

    /// <summary>
    /// Produces a signed <c>samlp:LogoutRequest</c> whose position-bound signature carries the given
    /// <c>Reference URI</c> and a digest over <paramref name="digestedOctets"/> — the logout-path twin of
    /// <see cref="CreateResponseWithCraftedReference"/>.
    /// </summary>
    /// <param name="referenceUri">The literal <c>Reference/@URI</c> value to emit.</param>
    /// <param name="digestedOctets">The octets the DigestValue is computed over; null means the empty octet stream.</param>
    /// <returns>A fixture whose LogoutRequest carries the crafted signature.</returns>
    internal static SamlLogoutFixture CreateLogoutRequestWithCraftedReference(string referenceUri, byte[]? digestedOctets = null)
    {
        var requestId = "_" + Guid.NewGuid().ToString("N");
        var document = LoadResponse(BuildLogoutRequestXml(requestId));

        using var rsa = RSA.Create(2048);
        var certificate = SelfSign(rsa);
        var signature = BuildSignature(document, rsa, certificate, referenceUri, digestedOctets ?? Array.Empty<byte>());
        document.DocumentElement!.AppendChild(signature);

        return new SamlLogoutFixture(certificate, document, requestId);
    }

    /// <summary>
    /// Produces a signed <c>samlp:LogoutRequest</c> whose signature honestly covers the <c>saml:Issuer</c>
    /// element instead of the request root whose NameID/SessionIndex the caller consumes.
    /// </summary>
    /// <returns>A fixture whose LogoutRequest carries a valid signature over the wrong element.</returns>
    internal static SamlLogoutFixture CreateLogoutRequestSigningTheIssuerOnly()
    {
        var requestId = "_" + Guid.NewGuid().ToString("N");
        var issuerId = "_" + Guid.NewGuid().ToString("N");
        var document = LoadResponse(BuildLogoutRequestXml(requestId, issuerId));

        using var rsa = RSA.Create(2048);
        var certificate = SelfSign(rsa);

        var signedXml = new SignedXml(document) { SigningKey = rsa };
        var reference = new Reference("#" + issuerId) { DigestMethod = SignedXml.XmlDsigSHA256Url };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(reference);
        signedXml.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(certificate));
        signedXml.KeyInfo = keyInfo;
        signedXml.ComputeSignature();
        document.DocumentElement!.AppendChild(document.ImportNode(signedXml.GetXml(), true));

        return new SamlLogoutFixture(certificate, document, requestId);
    }

    // Hand-assembles a ds:Signature whose SignedInfo names the given reference URI and digest, then signs the
    // exclusive-C14N canonical form of that SignedInfo with the fixture key — a signature .NET's signer would
    // refuse to produce (it resolves the reference eagerly), yet cryptographically sound over SignedInfo.
    private static XmlNode BuildSignature(XmlDocument document, RSA key, X509Certificate2 certificate, string referenceUri, byte[] digestedOctets)
    {
        var digestValue = Convert.ToBase64String(SHA256.HashData(digestedOctets));
        var signedInfoXml =
            "<ds:SignedInfo xmlns:ds=\"" + DsNs + "\">" +
                "<ds:CanonicalizationMethod Algorithm=\"" + SignedXml.XmlDsigExcC14NTransformUrl + "\" />" +
                "<ds:SignatureMethod Algorithm=\"" + SignedXml.XmlDsigRSASHA256Url + "\" />" +
                "<ds:Reference URI=\"" + SecurityElement.Escape(referenceUri) + "\">" +
                    "<ds:Transforms>" +
                        "<ds:Transform Algorithm=\"" + SignedXml.XmlDsigEnvelopedSignatureTransformUrl + "\" />" +
                        "<ds:Transform Algorithm=\"" + SignedXml.XmlDsigExcC14NTransformUrl + "\" />" +
                    "</ds:Transforms>" +
                    "<ds:DigestMethod Algorithm=\"" + SignedXml.XmlDsigSHA256Url + "\" />" +
                    "<ds:DigestValue>" + digestValue + "</ds:DigestValue>" +
                "</ds:Reference>" +
            "</ds:SignedInfo>";

        var signatureValue = Convert.ToBase64String(key.SignData(Canonicalize(signedInfoXml), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

        var signatureXml =
            "<ds:Signature xmlns:ds=\"" + DsNs + "\">" +
                signedInfoXml.Replace(" xmlns:ds=\"" + DsNs + "\"", string.Empty, StringComparison.Ordinal) +
                "<ds:SignatureValue>" + signatureValue + "</ds:SignatureValue>" +
                "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>" + Convert.ToBase64String(certificate.Export(X509ContentType.Cert)) + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>" +
            "</ds:Signature>";

        var fragment = new XmlDocument { PreserveWhitespace = true };
        fragment.LoadXml(signatureXml);
        return document.ImportNode(fragment.DocumentElement!, true);
    }

    // Exclusive-C14N canonical octets of a standalone SignedInfo fragment. Exclusive canonicalization emits
    // only visibly-utilized prefixes, so the bytes are identical whether the ds prefix is declared on the
    // SignedInfo (here) or inherited from the enclosing ds:Signature (in the assembled document) — which is
    // what makes the crafted SignatureValue verify in place.
    private static byte[] Canonicalize(string signedInfoXml)
    {
        var fragment = new XmlDocument { PreserveWhitespace = true };
        fragment.LoadXml(signedInfoXml);
        var transform = new XmlDsigExcC14NTransform();
        transform.LoadInput(fragment);
        using var output = (Stream)transform.GetOutput(typeof(Stream));
        using var buffer = new MemoryStream();
        output.CopyTo(buffer);
        return buffer.ToArray();
    }

    private static void SignEnveloped(XmlDocument document, string referenceId, RSA key, X509Certificate2 certificate)
    {
        var signedXml = new SignedXml(document) { SigningKey = key };
        var reference = new Reference("#" + referenceId) { DigestMethod = SignedXml.XmlDsigSHA256Url };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(reference);
        signedXml.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(certificate));
        signedXml.KeyInfo = keyInfo;
        signedXml.ComputeSignature();

        var target = (XmlElement)signedXml.GetIdElement(document, referenceId)!;
        target.AppendChild(document.ImportNode(signedXml.GetXml(), true));
    }

    private static X509Certificate2 SelfSign(RSA key)
    {
        var request = new CertificateRequest("CN=Test SAML IdP", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
    }

    private static XmlDocument LoadResponse(string xml)
    {
        var document = new XmlDocument { PreserveWhitespace = true };
        document.LoadXml(xml);
        return document;
    }

    private static string BuildResponseXml(string responseId, string assertionId, string nameId, string? issuerId = null)
    {
        var notOnOrAfter = DateTime.UtcNow.AddMinutes(5).ToString(TimeFormat, CultureInfo.InvariantCulture);
        var issuerIdAttribute = issuerId == null ? string.Empty : " ID=\"" + issuerId + "\"";
        return
            "<samlp:Response xmlns:samlp=\"" + SamlpNs + "\" xmlns:saml=\"" + SamlNs + "\" ID=\"" + responseId + "\" Version=\"2.0\">" +
                "<saml:Issuer" + issuerIdAttribute + ">https://idp.example.com</saml:Issuer>" +
                Assertion(assertionId, nameId, notOnOrAfter) +
            "</samlp:Response>";
    }

    private static string BuildLogoutRequestXml(string requestId, string? issuerId = null)
    {
        var issueInstant = DateTime.UtcNow.ToString(TimeFormat, CultureInfo.InvariantCulture);
        var issuerIdAttribute = issuerId == null ? string.Empty : " ID=\"" + issuerId + "\"";
        return
            "<samlp:LogoutRequest xmlns:samlp=\"" + SamlpNs + "\" xmlns:saml=\"" + SamlNs + "\" ID=\"" + requestId + "\" Version=\"2.0\" IssueInstant=\"" + issueInstant + "\">" +
                "<saml:Issuer" + issuerIdAttribute + ">https://idp.example.com</saml:Issuer>" +
                "<saml:NameID>alice</saml:NameID>" +
            "</samlp:LogoutRequest>";
    }

    private static string Assertion(string id, string nameId, string notOnOrAfter) =>
        "<saml:Assertion ID=\"" + id + "\" Version=\"2.0\">" +
            "<saml:Issuer>https://idp.example.com</saml:Issuer>" +
            "<saml:Subject>" +
                "<saml:NameID>" + SecurityElement.Escape(nameId) + "</saml:NameID>" +
                "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" +
                    "<saml:SubjectConfirmationData NotOnOrAfter=\"" + notOnOrAfter + "\" />" +
                "</saml:SubjectConfirmation>" +
            "</saml:Subject>" +
            "<saml:AttributeStatement>" +
                "<saml:Attribute Name=\"Role\"><saml:AttributeValue>jellyfin-users</saml:AttributeValue></saml:Attribute>" +
            "</saml:AttributeStatement>" +
        "</saml:Assertion>";
}
