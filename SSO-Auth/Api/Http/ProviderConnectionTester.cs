// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
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
/// </summary>
internal static class ProviderConnectionTester
{
    // How long the link import waits for ONE provider's issuer before giving up on it (#1518). Shorter than
    // the reader's own per-request timeout on purpose: a restore names several providers and an operator is
    // holding the request, so the sum has to stay a wait rather than a hang. Giving up refuses the entries
    // that needed the answer, which is the same fail-closed arm an unreachable provider takes.
    private static readonly TimeSpan IssuerReadBudget = TimeSpan.FromSeconds(8);

    /// <summary>
    /// Probes a stored OpenID provider: reads its discovery document under the login's hardened discovery
    /// policy and reports the issuer, endpoints, JWKS reachability and the two discovery facts. Fail-closed
    /// and actionable - an unreadable document or an invalid endpoint returns a non-Ok result with a
    /// generic, secret-free message rather than throwing.
    /// </summary>
    /// <param name="config">The stored OpenID provider configuration.</param>
    /// <param name="provider">The provider name, for the reader's fail-closed warning only.</param>
    /// <param name="httpClientFactory">The shared HTTP client factory the hardened discovery fetch is built over.</param>
    /// <param name="logger">The logger the reader logs its fail-closed warning to (never a secret).</param>
    /// <returns>The probe result, safe to return to an administrator.</returns>
    internal static async Task<ProviderTestResult> TestOidcAsync(OidConfig config, string provider, IHttpClientFactory httpClientFactory, ILogger logger)
    {
        if (string.IsNullOrWhiteSpace(config.OidEndpoint))
        {
            return ProviderTestResult.Failure("No OpenID endpoint is configured. Set the OpenID Endpoint, save the provider, then test again.");
        }

        OidcClientOptions options;
        try
        {
            // Same discovery policy the login builds (#163), so the probe's TLS/endpoint posture matches.
            options = OidcDiscoveryOptions.Build(config);
        }
        catch (Exception ex) when (ex is UriFormatException or ArgumentException)
        {
            return ProviderTestResult.Failure("The configured OpenID Endpoint is not a valid absolute URL (for example https://idp.example.com).");
        }

        // The probe uses the provider's own transport tier, so "Test connection" reports what the login will
        // actually do - an opted-in provider on the admin's LAN must not fail here and then succeed at login.
        var discovery = await OidcDiscoveryReader.ReadAsync(options, provider, httpClientFactory, logger, config.AllowPrivateNetworkAddresses).ConfigureAwait(false);
        if (!discovery.Available)
        {
            // The reader already logged the fail-closed warning (with the library error, never a secret).
            // The admin-facing message stays generic: it names what to check, not any sensitive value.
            return ProviderTestResult.Failure(CauseOf(discovery.Refusal));
        }

        var info = discovery.ProviderInformation;
        var jwksKeyCount = info.KeySet?.Keys?.Count ?? 0;
        var jwksReachable = info.KeySet is not null;

        var details = new List<string>
        {
            "Issuer: " + Describe(info.IssuerName),
            "Authorization endpoint: " + Describe(info.AuthorizeEndpoint),
            "Token endpoint: " + Describe(info.TokenEndpoint),
            "UserInfo endpoint: " + Describe(info.UserInfoEndpoint),
            jwksReachable
                ? $"JWKS: reachable ({jwksKeyCount} key(s))"
                : "JWKS: the discovery document advertised no jwks_uri",
            "PKCE (S256) advertised: " + YesNo(discovery.Facts.PkceS256),
            "RFC 9207 response-iss advertised: " + YesNo(discovery.Facts.ResponseIssuerAdvertised),
        };

        return ProviderTestResult.Success("The OpenID discovery document was read successfully.", details);
    }

    /// <summary>
    /// Reads what one stored OpenID provider is configured to issue, for the link import's issuer check
    /// (#1518). Same discovery read as the probe above and under the same hardened policy, reduced to the
    /// single fact the importer compares against - so the value a restore is judged by and the value a
    /// login is judged by come from the one document, and a later change to the discovery posture cannot
    /// leave this on a weaker one.
    /// </summary>
    /// <remarks>
    /// Every failure arm returns a FACT rather than throwing, and every one of them is a refusal at the
    /// importer: there is no arm here that answers "carry on unchecked", because an unchecked issuer
    /// written into a link table is the whole of what #1518 is about.
    /// </remarks>
    /// <param name="config">The stored OpenID provider configuration.</param>
    /// <param name="provider">The provider name, for the reader's fail-closed warning only.</param>
    /// <param name="httpClientFactory">The shared HTTP client factory the hardened discovery fetch is built over.</param>
    /// <param name="logger">The logger the reader logs its fail-closed warning to (never a secret).</param>
    /// <param name="cancellationToken">Abandons the read when the administrator's request goes away.</param>
    /// <returns>The issuer, or the reason it could not be read.</returns>
    internal static async Task<LinkImportIssuerFact> ReadConfiguredIssuerAsync(OidConfig config, string provider, IHttpClientFactory httpClientFactory, ILogger logger, CancellationToken cancellationToken = default)
    {
        var endpoint = config?.OidEndpoint?.Trim();
        if (string.IsNullOrWhiteSpace(endpoint))
        {
            return LinkImportIssuerFact.Failed("no OpenID endpoint is configured for it");
        }

        OidcClientOptions options;
        try
        {
            options = OidcDiscoveryOptions.Build(config!);
        }
        catch (Exception ex) when (ex is UriFormatException or ArgumentException)
        {
            return LinkImportIssuerFact.Failed("its configured OpenID Endpoint is not a valid absolute URL");
        }

        // THE ONE PLACE THIS READ IS DELIBERATELY NARROWER THAN THE LOGIN'S, and it is a relaxation on
        // purpose. The library's DiscoveryPolicy requires a key set by default, so an ordinary discovery
        // read also fetches jwks_uri - a provider-authored URL, often on a different host - and fails the
        // whole read when that second leg fails. The login needs those keys and must fail closed without
        // them; this read needs one string out of the first document and no key material, so a JWKS host
        // having a bad minute would otherwise refuse an operator's entire link restore for a value it never
        // touches. Nothing else in the posture moves: RequireHttps, ValidateIssuerName, ValidateEndpoints,
        // the SSRF transport tier and the repeated-member screen are all still the provider's own.
        options.Policy.Discovery.RequireKeySet = false;

        // The reader takes no cancellation token - adding one there would reach thirty test call sites in
        // files this change is not about - so the budget is applied HERE, around the whole read. The fetch
        // it abandons keeps running until its own timeout; what this bounds is how long an administrator
        // waits, not how long the socket lives. #1558 holds the token itself.
        OidcDiscoveryResult discovery;
        try
        {
            discovery = await OidcDiscoveryReader
                .ReadAsync(options, provider, httpClientFactory, logger, config!.AllowPrivateNetworkAddresses)
                .WaitAsync(IssuerReadBudget, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is TimeoutException or OperationCanceledException)
        {
            return LinkImportIssuerFact.Failed("reading its discovery document did not finish in time");
        }

        if (!discovery.Available)
        {
            return LinkImportIssuerFact.Failed(CauseOf(discovery.Refusal));
        }

        // A document that declares no issuer is a read that succeeded and produced nothing to compare
        // against, which is not the same as a read that failed and is reported as its own cause. The
        // importer refuses on both, and an operator who sees this one looks at the identity provider's
        // metadata rather than at the network.
        var issuer = discovery.ProviderInformation?.IssuerName;
        return string.IsNullOrWhiteSpace(issuer)
            ? LinkImportIssuerFact.Failed("its discovery document declares no issuer")
            : LinkImportIssuerFact.Read(issuer!, endpoint);
    }

    /// <summary>
    /// Probes a stored SAML provider: parses the configured PUBLIC signing certificate and reports its
    /// non-secret facts (subject, issuer, validity window, SHA-256 thumbprint). No network call - there is
    /// no metadata-URL field - and never the service-provider signing key. A non-parsing certificate returns
    /// a non-Ok result with an actionable, secret-free message.
    /// </summary>
    /// <param name="config">The stored SAML provider configuration.</param>
    /// <returns>The probe result, safe to return to an administrator.</returns>
    internal static ProviderTestResult TestSaml(SamlConfig config)
    {
        if (string.IsNullOrWhiteSpace(config.SamlCertificate))
        {
            return ProviderTestResult.Failure("No SAML signing certificate is configured. Paste the identity provider's Base64 (DER) X.509 signing certificate, save the provider, then test again.");
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
            return ProviderTestResult.Failure("The configured SAML signing certificate could not be parsed. It must be the identity provider's Base64-encoded (DER) X.509 PUBLIC signing certificate - not a PEM wrapper and not a private key.");
        }

        using (certificate)
        {
            var notBefore = certificate.NotBefore.ToUniversalTime();
            var notAfter = certificate.NotAfter.ToUniversalTime();
            var now = DateTime.UtcNow;

            var details = new List<string>
            {
                "Subject: " + Describe(certificate.Subject),
                "Issuer: " + Describe(certificate.Issuer),
                $"Valid from (UTC): {notBefore:u}",
                $"Valid to (UTC): {notAfter:u}",
                "SHA-256 thumbprint: " + certificate.GetCertHashString(HashAlgorithmName.SHA256),
            };

            if (now < notBefore || now > notAfter)
            {
                details.Add("Note: the certificate is outside its validity period - logins may fail until it is renewed.");
            }

            return ProviderTestResult.Success("The SAML signing certificate parsed successfully.", details);
        }
    }

    // Why the discovery read came back unavailable, in words that describe THIS failure (#1064). The probe is
    // the one in-product diagnostic on the recovery path, so a message that answers confidently and points
    // somewhere else is worse than a vague one: an admin whose provider serves a document the screen refuses
    // would otherwise be sent to look at reachability, the well-known path and TLS, none of which is wrong.
    //
    // Each screened cause opens with the SAME constant the server log carries, so an admin matching the two
    // sees one wording rather than two paraphrases of it. Neither names the repeated member. The surface is
    // elevation-gated, so that is not the login path's disclosure question, but the member name is a
    // provider-authored string and every bound and filter it needs sits on the log entry (#1068, #1194) and
    // nowhere else; pointing at the log spends nothing and keeps one place responsible for it.
    private static string CauseOf(OidcDiscoveryRefusal refusal) => refusal switch
    {
        OidcDiscoveryRefusal.RepeatedMember =>
            RepeatedMemberScreen.RefusalReason
            + ", so the OpenID discovery read was refused. The document was served and rejected before it was parsed, which is a defect to report to the identity provider - a document whose meaning depends on which reader parses it. The Jellyfin server log records which document and which member.",
        OidcDiscoveryRefusal.Uninspectable =>
            RepeatedMemberScreen.UninspectableReason
            + ", so the OpenID discovery read was refused. That is usually a truncated body or a Content-Type naming a character set this server cannot decode, rather than a connectivity problem. The Jellyfin server log records which document and the failure it hit.",
        _ =>
            "Could not read the OpenID discovery document. Check that the endpoint is reachable, serves /.well-known/openid-configuration, and - unless HTTPS discovery is disabled - is served over HTTPS.",
    };

    // A discovery value the admin can eyeball, or an explicit marker when the document did not advertise it,
    // so a blank field reads as "not advertised" rather than an empty line.
    private static string Describe(string value) =>
        string.IsNullOrWhiteSpace(value) ? "(not advertised)" : value;

    private static string YesNo(bool value) => value ? "yes" : "no";
}
