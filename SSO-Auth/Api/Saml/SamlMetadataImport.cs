// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>The values extracted from the SAML metadata of an identity provider (#735), which the importer only ever pre-fills for an administrator to review and save through the normal validated write path.</summary>
/// <remarks>
/// <see cref="EntityId"/> is the own entity id of the identity provider, the issuer of its assertions,
/// rather than the service-provider client id sent as the AuthnRequest issuer and used as the expected
/// audience. It is surfaced for reference only and deliberately not mapped onto that field.
/// </remarks>
/// <param name="EntityId">The entity id of the identity provider, for reference.</param>
/// <param name="Endpoint">The SingleSignOnService location the browser is redirected to.</param>
/// <param name="PrimaryCertificate">The primary Base64 signing certificate.</param>
/// <param name="SecondaryCertificate">The optional secondary signing certificate, or null.</param>
internal sealed record SamlMetadataImport(
    string EntityId,
    string Endpoint,
    string PrimaryCertificate,
    string? SecondaryCertificate);

/// <summary>
/// Thrown when SAML metadata cannot be parsed into a usable provider configuration (#735) - malformed or
/// oversized XML, a prohibited DOCTYPE/DTD, a missing <c>IDPSSODescriptor</c>/entityID/endpoint, or no usable
/// signing certificate. The message is admin-facing and free of internal detail; the import applies nothing
/// on failure (never a partial result).
/// </summary>
internal sealed class SamlMetadataException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SamlMetadataException"/> class with an admin-facing
    /// message.
    /// </summary>
    /// <param name="message">The admin-facing failure message, free of internal detail.</param>
    internal SamlMetadataException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SamlMetadataException"/> class wrapping the underlying
    /// parse failure.
    /// </summary>
    /// <param name="message">The admin-facing failure message, free of internal detail.</param>
    /// <param name="innerException">The underlying exception that caused the failure.</param>
    internal SamlMetadataException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
