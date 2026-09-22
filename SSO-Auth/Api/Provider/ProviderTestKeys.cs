// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Api.Provider;

/// <summary>
/// The catalogue keys a provider Test-connection probe answers with (#1728): every verdict and every fact
/// line the probe can produce, named here and nowhere else. The probe returns a key rather than a sentence,
/// and the settings page renders it through the localization catalogue in the administrator's language, so
/// the English wording lives in <c>en.json</c> beside its German row instead of in C#. The <c>test.</c>
/// namespace is the server's: the conformance suite holds every constant here to a row in the English
/// catalogue and every <c>test.</c> row there to a constant here, and refuses a prose literal in the probe's
/// source, so a verdict cannot be added as a sentence the catalogue never sees.
/// </summary>
internal static class ProviderTestKeys
{
    /// <summary>OpenID verdict: no endpoint is stored, so nothing was fetched.</summary>
    internal const string OidcNoEndpoint = "test.oidc_no_endpoint";

    /// <summary>OpenID verdict: the stored endpoint is not an absolute URL, so nothing was fetched.</summary>
    internal const string OidcInvalidEndpoint = "test.oidc_invalid_endpoint";

    /// <summary>OpenID verdict: the discovery document named a JSON member twice and the screen refused it (#1064).</summary>
    internal const string OidcRefusedRepeatedMember = "test.oidc_refused_repeated_member";

    /// <summary>OpenID verdict: the discovery response could not be inspected as JSON and the screen refused it (#1064).</summary>
    internal const string OidcRefusedUninspectable = "test.oidc_refused_uninspectable";

    /// <summary>OpenID verdict: the discovery document could not be read, with no screened cause to name.</summary>
    internal const string OidcUnreadable = "test.oidc_unreadable";

    /// <summary>OpenID verdict: the document was read and the issuer it publishes is not the configured endpoint (#1837).</summary>
    internal const string OidcIssuerMismatch = "test.oidc_issuer_mismatch";

    /// <summary>Fact with a value: the OpenID endpoint as configured.</summary>
    internal const string ConfiguredEndpoint = "test.configured_endpoint";

    /// <summary>Fact with a value: the issuer the discovery document published.</summary>
    internal const string PublishedIssuer = "test.published_issuer";

    /// <summary>OpenID verdict: the discovery document was read under the login's policy.</summary>
    internal const string OidcDiscoveryRead = "test.oidc_discovery_read";

    /// <summary>Fact with a value: the issuer - the discovery document's, or the SAML signing certificate's.</summary>
    internal const string Issuer = "test.issuer";

    /// <summary>Fact with a value: the authorization endpoint.</summary>
    internal const string AuthorizationEndpoint = "test.authorization_endpoint";

    /// <summary>Fact with a value: the token endpoint.</summary>
    internal const string TokenEndpoint = "test.token_endpoint";

    /// <summary>Fact with a value: the UserInfo endpoint.</summary>
    internal const string UserInfoEndpoint = "test.userinfo_endpoint";

    /// <summary>Fact with a value: the JWKS was fetched, and the value is its key count.</summary>
    internal const string JwksReachable = "test.jwks_reachable";

    /// <summary>Fact without a value: the discovery document advertised no jwks_uri.</summary>
    internal const string JwksNotAdvertised = "test.jwks_not_advertised";

    /// <summary>Fact without a value: PKCE S256 is advertised.</summary>
    internal const string PkceAdvertised = "test.pkce_advertised";

    /// <summary>Fact without a value: PKCE S256 is not advertised.</summary>
    internal const string PkceNotAdvertised = "test.pkce_not_advertised";

    /// <summary>Fact without a value: the RFC 9207 response iss parameter is advertised.</summary>
    internal const string ResponseIssuerAdvertised = "test.response_iss_advertised";

    /// <summary>Fact without a value: the RFC 9207 response iss parameter is not advertised.</summary>
    internal const string ResponseIssuerNotAdvertised = "test.response_iss_not_advertised";

    /// <summary>SAML verdict: no signing certificate is stored, so nothing was parsed.</summary>
    internal const string SamlNoCertificate = "test.saml_no_certificate";

    /// <summary>SAML verdict: the stored signing certificate is not a Base64 DER X.509 certificate.</summary>
    internal const string SamlCertificateUnparsable = "test.saml_certificate_unparsable";

    /// <summary>SAML verdict: the stored signing certificate parsed.</summary>
    internal const string SamlCertificateParsed = "test.saml_certificate_parsed";

    /// <summary>Fact with a value: the certificate's subject.</summary>
    internal const string CertificateSubject = "test.certificate_subject";

    /// <summary>Fact with a value: the start of the certificate's validity, UTC.</summary>
    internal const string CertificateValidFrom = "test.certificate_valid_from";

    /// <summary>Fact with a value: the end of the certificate's validity, UTC.</summary>
    internal const string CertificateValidTo = "test.certificate_valid_to";

    /// <summary>Fact with a value: the certificate's SHA-256 thumbprint.</summary>
    internal const string CertificateThumbprint = "test.certificate_thumbprint";

    /// <summary>Fact without a value: today is outside the certificate's validity, so logins may fail.</summary>
    internal const string CertificateOutsideValidity = "test.certificate_outside_validity";

    /// <summary>
    /// The row the page renders in a fact's value slot when the fact carries no value - a document that did
    /// not advertise the endpoint. Referenced by the page rather than by the probe, and declared here so the
    /// two-way pin between this vocabulary and the catalogue covers it.
    /// </summary>
    internal const string NotAdvertised = "test.not_advertised";
}
