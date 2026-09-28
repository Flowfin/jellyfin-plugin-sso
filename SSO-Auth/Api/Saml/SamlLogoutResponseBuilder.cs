// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>Builds the outbound SAML LogoutResponse for the HTTP-Redirect binding (#727), the signed answer of this service provider to a validated inbound <see cref="SamlLogoutRequest"/>.</summary>
/// <remarks>
/// It reuses the shared <see cref="SamlRedirectSigner"/> under the SAMLResponse parameter, so the
/// key-derived, allowlist-checked signing policy is not re-implemented. It is emitted only after the inbound
/// request passed full validation and at least one session was revoked, and it always reports success, so no
/// rejection cause leaks through this channel while the endpoint keeps its uniform 400. The document pins the
/// InResponseTo and the Destination, so a captured response cannot be replayed to a different endpoint.
/// </remarks>
internal sealed class SamlLogoutResponseBuilder
{
    private const string SuccessStatusCode = "urn:oasis:names:tc:SAML:2.0:status:Success";

    private readonly string _id;
    private readonly string _issueInstant;

    private readonly string _issuer;
    private readonly string _inResponseTo;
    private readonly string _destination;

    /// <summary>
    /// Initializes a new instance of the <see cref="SamlLogoutResponseBuilder"/> class.
    /// </summary>
    /// <param name="issuer">The SP entity id (the same value the LogoutRequest sends as its Issuer).</param>
    /// <param name="inResponseTo">The validated inbound <c>LogoutRequest</c> ID this response answers.</param>
    /// <param name="destination">The IdP Single-Logout endpoint the response is sent to (its <c>Destination</c>).</param>
    public SamlLogoutResponseBuilder(string issuer, string inResponseTo, string destination)
    {
        _id = "_" + Guid.NewGuid().ToString();
        _issueInstant = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);

        _issuer = issuer;
        _inResponseTo = inResponseTo;
        _destination = destination;
    }

    /// <summary>
    /// Gets the response's unique <c>ID</c> (the value sent as the LogoutResponse ID).
    /// </summary>
    public string Id => _id;

    /// <summary>
    /// Builds the <c>LogoutResponse</c> as a Base64-encoded, DEFLATE-compressed string. The DEFLATE/encoding
    /// approach is copied verbatim from <see cref="SamlLogoutRequestBuilder.GetRequest"/> so both outbound
    /// redirect-binding messages encode identically.
    /// </summary>
    /// <returns>The response as a Base64-encoded, DEFLATE-compressed string.</returns>
    public string GetResponse()
    {
        using var sw = new StringWriter(CultureInfo.InvariantCulture);
        var xws = new XmlWriterSettings();
        xws.OmitXmlDeclaration = true;

        using (var xw = XmlWriter.Create(sw, xws))
        {
            xw.WriteStartElement("samlp", "LogoutResponse", "urn:oasis:names:tc:SAML:2.0:protocol");
            xw.WriteAttributeString("ID", _id);
            xw.WriteAttributeString("Version", "2.0");
            xw.WriteAttributeString("IssueInstant", _issueInstant);
            xw.WriteAttributeString("InResponseTo", _inResponseTo);
            xw.WriteAttributeString("Destination", _destination);

            xw.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
            xw.WriteString(_issuer);
            xw.WriteEndElement();

            // Status is REQUIRED (SAML core §3.7.2) and always Success: the SP answers only a request it
            // already validated and acted on, and never encodes a rejection reason here (the endpoint keeps a
            // uniform 400 for every failure, so this channel carries no cause oracle).
            xw.WriteStartElement("samlp", "Status", "urn:oasis:names:tc:SAML:2.0:protocol");
            xw.WriteStartElement("samlp", "StatusCode", "urn:oasis:names:tc:SAML:2.0:protocol");
            xw.WriteAttributeString("Value", SuccessStatusCode);
            xw.WriteEndElement();
            xw.WriteEndElement();

            xw.WriteEndElement();
        }

        // The exact DEFLATE + Base64 approach SamlLogoutRequestBuilder.GetRequest uses for the HTTP-Redirect
        // binding.
        var memoryStream = new MemoryStream();
        var writer = new StreamWriter(new DeflateStream(memoryStream, CompressionMode.Compress, true), new UTF8Encoding(false));
        writer.Write(sw.ToString());
        writer.Close();
        return Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)memoryStream.Length, Base64FormattingOptions.None);
    }

    /// <summary>Gets the redirect URL to the Single-Logout endpoint of the identity provider with the LogoutResponse signed for the HTTP-Redirect binding, delegating to the shared <see cref="SamlRedirectSigner"/>.</summary>
    /// <param name="sloEndpoint">The Single-Logout endpoint URL, which is the response Destination.</param>
    /// <param name="relayState">The relay state echoed from the inbound request, omitted when null or empty.</param>
    /// <param name="signingKey">The service-provider private key, RSA or ECDSA.</param>
    /// <returns>The signed redirect URL.</returns>
    public string GetSignedRedirectUrl(string sloEndpoint, string? relayState, AsymmetricAlgorithm signingKey)
    {
        ArgumentNullException.ThrowIfNull(sloEndpoint);

        return SamlRedirectSigner.BuildSignedRedirectUrl(sloEndpoint, "SAMLResponse", GetResponse(), relayState, signingKey);
    }
}
