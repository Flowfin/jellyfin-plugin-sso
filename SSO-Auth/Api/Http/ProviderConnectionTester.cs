// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Http;

/// <summary>
/// Runs an admin-triggered Test-connection probe against a STORED provider configuration (#163) so an
/// administrator can confirm connectivity and basic config before a user hits the failure at first login.
/// The endpoints that call this are elevation-gated (see <see cref="SSOController"/>), and the probe fetches
/// only the already-stored provider URL - the exact URL the (rate-limited) anonymous login challenge already
/// fetches - so it adds no outbound-fetch surface beyond the login path.
///
/// OpenID: reads the discovery document through the SAME hardened reader the login uses
/// (<see cref="OidcDiscoveryReader"/> under the provider's <see cref="OidcDiscoveryOptions"/> discovery
/// policy - RequireHttps / ValidateIssuerName / ValidateEndpoints), and reports the issuer, endpoints and
/// JWKS reachability from that one response. It never reveals the client secret (discovery needs no
/// credential). SAML: parses the configured PUBLIC signing certificate and reports its non-secret facts;
/// there is no SAML metadata-URL field, so the SAML probe makes no network call. Neither path ever puts a
/// secret, signing key, or DEK into the <see cref="ProviderTestResult"/> or the log.
///
/// Every verdict and fact is a catalogue key from <see cref="ProviderTestKeys"/> (#1728), never a sentence:
/// the page renders them in the administrator's language, and the conformance suite refuses a prose literal
/// in this file so the next verdict cannot arrive as English the catalogue never sees.
/// </summary>
internal static class ProviderConnectionTester
{
    /// <summary>
    /// Probes a stored OpenID provider: reads its discovery document under the login's hardened discovery
    /// policy and reports the issuer, endpoints, JWKS reachability and the two discovery facts. Fail-closed
    /// and actionable - an unreadable document or an invalid endpoint returns a non-Ok result whose verdict
    /// names what to check, never a sensitive value, rather than throwing.
    /// </summary>
    /// <param name="config">The stored OpenID provider configuration.</param>
    /// <param name="provider">The provider name, for the reader's fail-closed warning only.</param>
    /// <param name="httpClientFactory">The shared HTTP client factory the hardened discovery fetch is built over.</param>
    /// <param name="logger">The logger the reader logs its fail-closed warning to (never a secret).</param>
    /// <param name="cancellationToken">The admin request's own lifetime, passed down to the discovery read (#1558).</param>
    /// <returns>The probe result, safe to return to an administrator.</returns>
    internal static async Task<ProviderTestResult> TestOidcAsync(OidConfig config, string provider, IHttpClientFactory httpClientFactory, ILogger logger, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(config.OidEndpoint))
        {
            return ProviderTestResult.Failure(ProviderTestKeys.OidcNoEndpoint);
        }

        OidcClientOptions options;
        try
        {
            // Same discovery policy the login builds (#163), so the probe's TLS/endpoint posture matches.
            options = OidcDiscoveryOptions.Build(config);
        }
        catch (Exception ex) when (ex is UriFormatException or ArgumentException)
        {
            return ProviderTestResult.Failure(ProviderTestKeys.OidcInvalidEndpoint);
        }

        // The probe uses the provider's own transport tier, so "Test connection" reports what the login will
        // actually do - an opted-in provider on the admin's LAN must not fail here and then succeed at login.
        var discovery = await OidcDiscoveryReader.ReadAsync(options, provider, httpClientFactory, logger, config.AllowPrivateNetworkAddresses, cancellationToken).ConfigureAwait(false);
        if (!discovery.Available)
        {
            // The reader already logged the fail-closed warning (with the library error, never a secret). The
            // verdict describes THIS failure (#1064): the probe is the one in-product diagnostic on the recovery
            // path, and a verdict that answers confidently and points somewhere else is worse than a vague one -
            // an admin whose provider serves a document the screen refuses would otherwise be sent to look at
            // reachability, the well-known path and TLS, none of which is wrong.
            //
            // The English rows of the two screened causes open with the SAME constant the server log carries
            // (RepeatedMemberScreen.RefusalReason / UninspectableReason), which the probe's suite pins, so an
            // admin matching the two on an English dashboard sees one wording rather than two paraphrases. On a
            // translated dashboard the log is the English side of that pairing: that is the price of the page
            // reading the administrator's language (#1728), paid on purpose. Neither row names the repeated
            // member. The surface is elevation-gated, so that is not the login path's disclosure question, but
            // the member name is a provider-authored string and every bound and filter it needs sits on the log
            // entry (#1068, #1194) and nowhere else; pointing at the log spends nothing and keeps one place
            // responsible for it.
            //
            // A refused issuer is the exception that names its values (#1837), because the value is the repair:
            // the field has to carry the published issuer, and no log line on the recovery path should be needed
            // to read it. Both facts are rendered inert by the page, like the issuer a successful read reports.
            if (discovery.Refusal == OidcDiscoveryRefusal.IssuerMismatch)
            {
                return ProviderTestResult.Failure(
                    ProviderTestKeys.OidcIssuerMismatch,
                    [Fact(ProviderTestKeys.ConfiguredEndpoint, options.Authority), Fact(ProviderTestKeys.PublishedIssuer, discovery.PublishedIssuer)]);
            }

            return ProviderTestResult.Failure(discovery.Refusal switch
            {
                OidcDiscoveryRefusal.RepeatedMember => ProviderTestKeys.OidcRefusedRepeatedMember,
                OidcDiscoveryRefusal.Uninspectable => ProviderTestKeys.OidcRefusedUninspectable,
                _ => ProviderTestKeys.OidcUnreadable,
            });
        }

        var info = discovery.ProviderInformation;
        var facts = new List<ProviderTestFact>
        {
            Fact(ProviderTestKeys.Issuer, info.IssuerName),
            Fact(ProviderTestKeys.AuthorizationEndpoint, info.AuthorizeEndpoint),
            Fact(ProviderTestKeys.TokenEndpoint, info.TokenEndpoint),
            Fact(ProviderTestKeys.UserInfoEndpoint, info.UserInfoEndpoint),
            info.KeySet is null
                ? new ProviderTestFact(ProviderTestKeys.JwksNotAdvertised, null)
                : new ProviderTestFact(ProviderTestKeys.JwksReachable, (info.KeySet.Keys?.Count ?? 0).ToString(CultureInfo.InvariantCulture)),
            Advertised(ProviderTestKeys.PkceAdvertised, ProviderTestKeys.PkceNotAdvertised, discovery.Facts.PkceS256),
            Advertised(ProviderTestKeys.ResponseIssuerAdvertised, ProviderTestKeys.ResponseIssuerNotAdvertised, discovery.Facts.ResponseIssuerAdvertised),
        };

        return ProviderTestResult.Success(ProviderTestKeys.OidcDiscoveryRead, facts);
    }

    /// <summary>
    /// Probes a stored SAML provider: parses the configured PUBLIC signing certificate and reports its
    /// non-secret facts (subject, issuer, validity window, SHA-256 thumbprint). No network call - there is
    /// no metadata-URL field - and never the service-provider signing key. A non-parsing certificate returns
    /// a non-Ok result whose verdict names what to paste instead.
    /// </summary>
    /// <param name="config">The stored SAML provider configuration.</param>
    /// <returns>The probe result, safe to return to an administrator.</returns>
    internal static ProviderTestResult TestSaml(SamlConfig config)
    {
        if (string.IsNullOrWhiteSpace(config.SamlCertificate))
        {
            return ProviderTestResult.Failure(ProviderTestKeys.SamlNoCertificate);
        }

        X509Certificate2 certificate;
        try
        {
            // The same parse SamlCertificate.IsInvalid performs (#206): Base64 (DER) X.509. The IdP signing
            // certificate carries only the PUBLIC key, so nothing secret is loaded or reported.
            certificate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(config.SamlCertificate));
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or ArgumentException)
        {
            return ProviderTestResult.Failure(ProviderTestKeys.SamlCertificateUnparsable);
        }

        using (certificate)
        {
            var notBefore = certificate.NotBefore.ToUniversalTime();
            var notAfter = certificate.NotAfter.ToUniversalTime();
            var now = DateTime.UtcNow;

            var facts = new List<ProviderTestFact>
            {
                Fact(ProviderTestKeys.CertificateSubject, certificate.Subject),
                Fact(ProviderTestKeys.Issuer, certificate.Issuer),
                new ProviderTestFact(ProviderTestKeys.CertificateValidFrom, notBefore.ToString("u", CultureInfo.InvariantCulture)),
                new ProviderTestFact(ProviderTestKeys.CertificateValidTo, notAfter.ToString("u", CultureInfo.InvariantCulture)),
                new ProviderTestFact(ProviderTestKeys.CertificateThumbprint, certificate.GetCertHashString(HashAlgorithmName.SHA256)),
            };

            if (now < notBefore || now > notAfter)
            {
                facts.Add(new ProviderTestFact(ProviderTestKeys.CertificateOutsideValidity, null));
            }

            return ProviderTestResult.Success(ProviderTestKeys.SamlCertificateParsed, facts);
        }
    }

    // A provider value the admin can eyeball. A document that did not advertise it sends NO value, and the page
    // renders the not-advertised row in the slot rather than an empty line, so a blank field reads as "not
    // advertised" in the administrator's language rather than as nothing.
    private static ProviderTestFact Fact(string key, string? value) =>
        new(key, string.IsNullOrWhiteSpace(value) ? null : value);

    // A fact the discovery document either advertises or does not: two whole rows rather than a yes/no word
    // handed to one, so each language writes the sentence its own way.
    private static ProviderTestFact Advertised(string advertised, string notAdvertised, bool value) =>
        new(value ? advertised : notAdvertised, null);
}
