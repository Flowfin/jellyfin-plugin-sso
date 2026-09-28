// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.IO;
using System.Text;
using System.Xml;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>Builds SAML 2.0 service-provider metadata an administrator can hand to an identity provider, so it registers this service provider by URL instead of by hand (#162).</summary>
/// <remarks>
/// Pure and request-free: it emits the entity id, the HTTP-POST assertion-consumer URLs and, only where
/// request signing is on, the public signing certificates it is given. Both accepted assertion-consumer
/// spellings are advertised where a legacy one is supplied, the new one staying the default, and during a
/// signing-key rollover both public certificates are advertised (#491). It touches no private key and never
/// reads the request host, because the caller resolves every URL from the configured canonical base URL
/// (#139), so a spoofed host cannot poison the endpoint assertions are posted to.
/// </remarks>
internal static class SamlSpMetadataBuilder
{
    private const string MetadataNamespace = "urn:oasis:names:tc:SAML:2.0:metadata";
    private const string ProtocolNamespace = "urn:oasis:names:tc:SAML:2.0:protocol";
    private const string DsigNamespace = "http://www.w3.org/2000/09/xmldsig#";
    private const string HttpPostBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

    /// <summary>Renders the service-provider metadata document.</summary>
    /// <param name="entityId">The service-provider entity id, the same value sent as the AuthnRequest issuer, so the identity provider correlates the two.</param>
    /// <param name="assertionConsumerServiceUrl">The absolute HTTP-POST assertion-consumer URL in the new-path spelling, built from the canonical base URL and advertised as the default.</param>
    /// <param name="signingCertificateBase64">The Base64 public signing certificate to advertise where request signing is on, or null to advertise none; never a private key.</param>
    /// <param name="rolloverSigningCertificateBase64">The optional Base64 public rollover certificate (#491), advertised second so either is trusted during an overlap; null, or a null primary, emits one.</param>
    /// <param name="legacyAssertionConsumerServiceUrl">The optional assertion-consumer URL in the legacy spelling, advertised second and non-default; null, or a value equal to the new spelling, emits one. Last, so positional callers stay source-compatible.</param>
    /// <returns>The metadata document as an XML string.</returns>
    internal static string Build(string entityId, string assertionConsumerServiceUrl, string? signingCertificateBase64, string? rolloverSigningCertificateBase64 = null, string? legacyAssertionConsumerServiceUrl = null)
    {
        // A StringWriter is UTF-16 internally, which would make XmlWriter stamp encoding="utf-16" into the
        // XML declaration even though the bytes are served as UTF-8; report UTF-8 so the declaration matches
        // the wire encoding a strict metadata consumer validates.
        using var writer = new Utf8StringWriter();
        var settings = new XmlWriterSettings
        {
            Indent = true,
            Encoding = Encoding.UTF8,
        };

        using (var xml = XmlWriter.Create(writer, settings))
        {
            xml.WriteStartElement("md", "EntityDescriptor", MetadataNamespace);
            xml.WriteAttributeString("entityID", entityId);

            xml.WriteStartElement("md", "SPSSODescriptor", MetadataNamespace);

            // Advertise request signing exactly as it is configured, and always require signed assertions:
            // this SP rejects an unsigned assertion (Saml.cs verifies the signature on every response), so
            // WantAssertionsSigned="true" is a truthful statement of what the IdP must send.
            xml.WriteAttributeString("AuthnRequestsSigned", signingCertificateBase64 is null ? "false" : "true");
            xml.WriteAttributeString("WantAssertionsSigned", "true");
            xml.WriteAttributeString("protocolSupportEnumeration", ProtocolNamespace);

            if (signingCertificateBase64 is not null)
            {
                WriteSigningKeyDescriptor(xml, signingCertificateBase64);

                // The rollover certificate (#491) is a SECOND signing KeyDescriptor during the overlap
                // window. It is only meaningful alongside a primary (signing must be on), so it is nested
                // under the primary guard; a null rollover leaves the single-descriptor output unchanged.
                if (rolloverSigningCertificateBase64 is not null)
                {
                    WriteSigningKeyDescriptor(xml, rolloverSigningCertificateBase64);
                }
            }

            xml.WriteStartElement("md", "AssertionConsumerService", MetadataNamespace);
            xml.WriteAttributeString("Binding", HttpPostBinding);
            xml.WriteAttributeString("Location", assertionConsumerServiceUrl);
            xml.WriteAttributeString("index", "0");
            xml.WriteAttributeString("isDefault", "true");
            xml.WriteEndElement(); // md:AssertionConsumerService

            // The SP accepts either ACS spelling on the way back (SamlAcsUrlBuilder.ExpectedAcsUrls), so when a
            // distinct legacy spelling is supplied the metadata lists it too - a SECOND, non-default endpoint at
            // index="1". The new spelling above stays the default (index="0", isDefault="true"), so an identity
            // provider that honours isDefault keeps posting to it; the legacy entry only widens what the IdP may
            // pick to a URL this SP already honours. A null (the default) or duplicate legacy URL leaves the
            // single-ACS output unchanged.
            if (legacyAssertionConsumerServiceUrl is not null
                && !string.Equals(legacyAssertionConsumerServiceUrl, assertionConsumerServiceUrl, System.StringComparison.Ordinal))
            {
                xml.WriteStartElement("md", "AssertionConsumerService", MetadataNamespace);
                xml.WriteAttributeString("Binding", HttpPostBinding);
                xml.WriteAttributeString("Location", legacyAssertionConsumerServiceUrl);
                xml.WriteAttributeString("index", "1");
                xml.WriteAttributeString("isDefault", "false");
                xml.WriteEndElement(); // md:AssertionConsumerService
            }

            xml.WriteEndElement(); // md:SPSSODescriptor
            xml.WriteEndElement(); // md:EntityDescriptor
        }

        return writer.ToString();
    }

    // Writes one <md:KeyDescriptor use="signing"> wrapping the given PUBLIC certificate DER. The caller
    // passes only the public certificate (certificate.RawData); no private-key material ever reaches here.
    private static void WriteSigningKeyDescriptor(XmlWriter xml, string signingCertificateBase64)
    {
        xml.WriteStartElement("md", "KeyDescriptor", MetadataNamespace);
        xml.WriteAttributeString("use", "signing");
        xml.WriteStartElement("ds", "KeyInfo", DsigNamespace);
        xml.WriteStartElement("ds", "X509Data", DsigNamespace);
        xml.WriteStartElement("ds", "X509Certificate", DsigNamespace);
        xml.WriteString(signingCertificateBase64);
        xml.WriteEndElement(); // ds:X509Certificate
        xml.WriteEndElement(); // ds:X509Data
        xml.WriteEndElement(); // ds:KeyInfo
        xml.WriteEndElement(); // md:KeyDescriptor
    }

    // A StringWriter that reports UTF-8 so XmlWriter emits encoding="utf-8" in the XML declaration (the
    // default StringWriter reports UTF-16, which would mislabel the served UTF-8 document).
    private sealed class Utf8StringWriter : StringWriter
    {
        /// <inheritdoc/>
        public override Encoding Encoding => Encoding.UTF8;
    }
}
