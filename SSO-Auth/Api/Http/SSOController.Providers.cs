// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Net.Mime;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Events;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Logout;
using Jellyfin.Plugin.SSO_Auth.Api.Metrics;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Api;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Events;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Net;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Jellyfin.Plugin.SSO_Auth.Api.Http;

/// <summary>The provider administration endpoints: add, delete, list and import a provider configuration.</summary>
public partial class SSOController
{
    /// <summary>
    /// Rejects a malformed canonical base-URL override at the OID/SAML Add endpoints (#139), the door that
    /// mirrors the config-page save-time check for the Add path that bypasses it. A blank override is valid.
    /// </summary>
    /// <param name="baseUrlOverride">The override value posted to the Add endpoint.</param>
    /// <exception cref="ArgumentException">The override is non-blank and not a valid absolute http(s) URL.</exception>
    internal static void RejectInvalidBaseUrlOverride(string? baseUrlOverride)
    {
        if (CanonicalBaseUrl.IsInvalidOverride(baseUrlOverride))
        {
            throw new ArgumentException("The Base URL override must be an absolute http(s) URL such as https://jellyfin.example.com, or left blank.", nameof(baseUrlOverride));
        }
    }

    // Rejects a non-loadable SAML signing certificate at the SAML/Add endpoint (#206), which persists
    // through MutateConfiguration and so bypasses the config-page save-time validation in
    // ProviderConfigValidator.Validate. Without this, a garbage certificate set via the Add API would be
    // persisted and then throw a CryptographicException on every callback (an unhandled 500). Blank is
    // valid (a half-configured provider).

    /// <summary>
    /// Rejects a non-loadable SAML signing certificate at the SAML/Add endpoint (#206), the Add-path
    /// counterpart to the config-page save-time certificate check. A blank certificate is valid.
    /// </summary>
    /// <param name="certificateStr">The Base64-encoded (DER) X.509 certificate posted to the Add endpoint.</param>
    /// <exception cref="ArgumentException">The certificate is non-blank and not loadable.</exception>
    internal static void RejectInvalidSamlCertificate(string? certificateStr)
    {
        if (SamlCertificate.IsInvalid(certificateStr))
        {
            throw new ArgumentException("The SAML signing certificate must be a Base64-encoded (DER) X.509 certificate, or left blank.", nameof(certificateStr));
        }
    }

    // Rejects a non-loadable inbound secondary verification certificate at the SAML/Add endpoint (#491),
    // the same fail-closed door as the primary certificate guard above and for the same reason: a garbage
    // secondary would persist and then throw a CryptographicException on every callback (an unhandled
    // 500). It is the identity provider's PUBLIC certificate, so it is validated exactly like the primary.
    // Blank is valid (no overlap window configured).

    /// <summary>
    /// Rejects a non-loadable inbound secondary verification certificate at the SAML/Add endpoint (#491) -
    /// the identity provider's public certificate for a key-overlap window, validated like the primary. A
    /// blank value is valid (no overlap window configured).
    /// </summary>
    /// <param name="certificateStr">The Base64-encoded (DER) X.509 certificate posted to the Add endpoint.</param>
    /// <exception cref="ArgumentException">The certificate is non-blank and not loadable.</exception>
    internal static void RejectInvalidSamlSecondaryCertificate(string? certificateStr)
    {
        if (SamlCertificate.IsInvalid(certificateStr))
        {
            throw new ArgumentException("The SAML secondary signing certificate must be a Base64-encoded (DER) X.509 certificate, or left blank.", nameof(certificateStr));
        }
    }

    // Rejects a non-loadable service-provider signing key at the SAML/Add endpoint (#167), the same
    // fail-closed door as the inbound certificate guard above: a garbage or private-key-less PKCS#12 set
    // here would persist and then fail every signed challenge. Blank is valid (signing simply stays off,
    // or the stored key is preserved on save).

    /// <summary>
    /// Rejects a non-loadable service-provider request signing key at the SAML/Add endpoint (#167). A blank
    /// key is valid (signing stays off, or the stored key is preserved on save).
    /// </summary>
    /// <param name="signingKeyPfx">The Base64-encoded PKCS#12 (PFX) signing key posted to the Add endpoint.</param>
    /// <exception cref="ArgumentException">The key is non-blank and not a loadable PFX with an RSA or ECDSA private key.</exception>
    internal static void RejectInvalidSamlSigningKey(string? signingKeyPfx)
    {
        if (SamlSigningKey.IsInvalid(signingKeyPfx))
        {
            throw new ArgumentException("The SAML request signing key must be a Base64-encoded, unencrypted PKCS#12 (PFX) blob containing an RSA or ECDSA private key, or left blank.", nameof(signingKeyPfx));
        }
    }

    // Rejects a malformed SAML SLO endpoint (#727, SLO-3c) at the SAML/Add endpoint, the door that mirrors
    // the config-page save-time SLO-endpoint check in ProviderConfigValidator for the Add path that
    // bypasses it. It must be an absolute https URL - the redirect carries a signed LogoutRequest naming the
    // subject, so it must not traverse plaintext http. Reuses the same CanonicalBaseUrl.TryNormalize
    // absolute-URL predicate the Base URL override guard uses, narrowed to https. Blank is valid (no
    // SP-initiated Single Logout). The message stays generic (never echoes the caller's endpoint back).

    /// <summary>
    /// Rejects a malformed SAML SLO endpoint at the SAML/Add endpoint (#727, SLO-3c), the Add-path
    /// counterpart to the config-page save-time SLO-endpoint check. A blank endpoint is valid.
    /// </summary>
    /// <param name="sloEndpoint">The SAML SLO endpoint posted to the Add endpoint.</param>
    /// <exception cref="ArgumentException">The endpoint is non-blank and not a valid absolute https URL.</exception>
    internal static void RejectInvalidSamlSloEndpoint(string? sloEndpoint)
    {
        if (!string.IsNullOrWhiteSpace(sloEndpoint)
            && (!CanonicalBaseUrl.TryNormalize(sloEndpoint, out var normalized)
                || !normalized.StartsWith("https://", StringComparison.Ordinal)))
        {
            throw new ArgumentException("The SAML SLO Endpoint must be an absolute https URL such as https://idp.example.com/slo, or left blank.", nameof(sloEndpoint));
        }
    }

    // Rejects a null provider body at the Add endpoints (#350). ASP.NET model binding hands a null
    // [FromBody] object for an empty or literal "null" JSON payload; storing it would put a null entry
    // in the config map that then NREs the config-page save (ServerManagedFields.Preserve). Reject at
    // the door so the store never holds a null provider - the same fail-closed posture as the other
    // Add-endpoint gates.

    /// <summary>
    /// Rejects a null provider body at the Add endpoints (#350), so a null or literal "null" JSON payload
    /// can never put a null entry in the config map that would later NRE the config-page save.
    /// </summary>
    /// <param name="config">The model-bound provider configuration body.</param>
    /// <exception cref="ArgumentException">The body is null.</exception>
    internal static void RejectNullProviderBody(object config)
    {
        if (config is null)
        {
            throw new ArgumentException("The provider configuration body must not be empty.", nameof(config));
        }
    }

    // Rejects a provider name containing URI-reserved or control characters when it would register a NEW
    // provider (#336, #360): the name is appended raw to the callback URLs handed to the identity provider
    // (the OIDC/SAML URL builders), so '%' breaks route decoding, '/' dead-ends the IdP redirect on a path no route
    // matches, control characters do not round-trip at all, and the other RFC 3986 delimiters invite
    // proxy/IdP misinterpretation. Updating an
    // EXISTING name stays allowed: its URL bytes are already registered at the IdP, and blocking the
    // update would strand the deployment behind a rename (encoding the built URLs instead is pinned
    // off by SsoUrlBuilderTests).

    /// <summary>
    /// Rejects a NEW provider name containing control characters, a backslash, or a URI-reserved character
    /// (#336, #360), because the name is appended raw to the callback URLs registered with the identity
    /// provider. Updating an existing name stays allowed so a deployment is not stranded behind a rename.
    /// </summary>
    /// <param name="provider">The provider name posted to the Add endpoint.</param>
    /// <param name="providerExists">Whether the name already names a registered provider; only new names are validated.</param>
    /// <exception cref="ArgumentException">The name is new and contains a forbidden character.</exception>
    internal static void RejectInvalidNewProviderName(string provider, bool providerExists)
    {
        if (!providerExists && ProviderNameValidator.IsInvalid(provider))
        {
            throw new ArgumentException("A new provider name must not contain control characters, a backslash, or any of % : / ? # [ ] @ ! $ & ' ( ) * + , ; = because the name becomes part of the callback URL registered with the identity provider.", nameof(provider));
        }
    }

    // Rejects a provisioning policy the configuration save would refuse (#1502) at the OID/SAML Add doors,
    // which persist through MutateConfiguration and so bypass the save-time Validate. Without this, a
    // template naming a permission that is not a PermissionKind, a subtitle mode that is not a
    // SubtitlePlaybackMode, a negative ceiling, or a home-screen section that is not a HomeSectionType was
    // stored as posted with a 200; every writer then skipped it fail-closed at provisioning, so the
    // template widened nothing and did nothing, with the reason visible only at the first login that
    // created an account. The three checks are the save's own, so both admin write paths refuse the same
    // policy with the same message. Runs under the config lock, because the profile checks resolve the
    // posted name against the LIVE profile set; it runs before any mutation, so a throw persists nothing.

    /// <summary>
    /// Rejects a provisioning template, profile reference, or role-to-profile row the configuration save
    /// would refuse (#1502), at the Add doors that bypass that save. Called inside the configuration
    /// mutation, before it changes anything, because the profile checks read the live profile set.
    /// </summary>
    /// <param name="protocol">The protocol label (<c>OpenID</c> or <c>SAML</c>) echoed in the rejection message.</param>
    /// <param name="provider">The provider name posted to the Add endpoint.</param>
    /// <param name="config">The provider body posted to the Add endpoint.</param>
    /// <param name="live">The live configuration, whose profile set a posted profile name must resolve in.</param>
    /// <exception cref="ArgumentException">The template, the profile reference, or a role-to-profile row is invalid.</exception>
    private static void RejectInvalidProvisioningPolicy(string protocol, string provider, ProviderConfigBase config, PluginConfiguration live)
    {
        ProviderConfigValidator.ValidateProvisioningTemplate(protocol, provider, config.ProvisioningPolicyTemplate);
        ProviderConfigValidator.ValidateProvisioningProfileReference(protocol, provider, config, live.ProvisioningProfiles);
        ProviderConfigValidator.ValidateProvisioningProfileRoleMappings(protocol, provider, config, live.ProvisioningProfiles);
    }

    // The refusal every elevated write door gives for a declaratively managed provider (#1415), defined once
    // so five doors and their tests cannot drift into five wordings. It names the source, because a refusal
    // that does not say where the change belongs leaves an administrator with nowhere to make it.
    private static string ManagedProviderRefusal(string protocol, string provider, string source) =>
        string.Create(
            CultureInfo.InvariantCulture,
            $"The {protocol} provider '{provider}' is managed by the declarative source {source}. Edit that source and restart the server; a change made here would be undone at the next start.");

    private static string ManagedProfileRefusal(string profile, string source) =>
        string.Create(
            CultureInfo.InvariantCulture,
            $"The provisioning profile '{profile}' is defined by the declarative source {source}. Edit that source and restart the server; a change made here would be undone at the next start.");

    /// <summary>Refuses an elevated single-provider write against a provider a declarative source decided (#1415), and audits the refusal so an operator sees why nothing changed.</summary>
    /// <remarks>Refuse rather than the config-page save's ignore-and-keep, because these doors carry a single-provider intent with no unrelated edit to protect, and honouring the call while doing nothing would report success for a change that did not happen; it runs before the body validators, because a managed provider's posted body is never applied.</remarks>
    /// <param name="door">The route being refused, for the audit line.</param>
    /// <param name="protocol">The protocol label, <c>OpenID</c> or <c>SAML</c>.</param>
    /// <param name="provider">The provider the caller named.</param>
    /// <param name="source">What names the owning source, or null when the provider is not managed and the call proceeds.</param>
    /// <exception cref="ArgumentException">The provider is declaratively managed.</exception>
    private void RejectManagedProviderWrite(string door, string protocol, string provider, string? source)
    {
        if (source is null)
        {
            return;
        }

        SsoAudit.DeclarativeWriteRefused(_logger, door, protocol, provider, source);
        throw new ArgumentException(ManagedProviderRefusal(protocol, provider, source), nameof(provider));
    }

    /// <summary>
    /// Adds an OpenID auth configuration. Requires administrator privileges. If the provider already exists, it will be removed and readded.
    /// </summary>
    /// <param name="provider">The name of the provider to add.</param>
    /// <param name="config">The OID configuration (deserialized from a JSON post).</param>
    /// <returns>Whether the save dropped the stored client secret, with the notice that goes with it (#1872).</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("OID/Add/{provider}")]
    public ActionResult<ProviderSaveResponse> OidAdd(string provider, [FromBody] OidConfig config)
    {
        RejectManagedProviderWrite("OID/Add", OpenIdProtocol, provider, SSOPlugin.Instance.ConfigStore.ManagedProviders.OidSource(provider));
        RejectNullProviderBody(config);
        RejectInvalidBaseUrlOverride(config.BaseUrlOverride);
        // Reject a malformed generic permission-role mapping (#164) at the door, exactly like the base-URL
        // and certificate guards above: the Add endpoints persist through MutateConfiguration and so bypass
        // the config-page save-time validation. Reuses the one shared validator so every admin write path
        // agrees on what a valid mapping is.
        ProviderConfigValidator.ValidatePermissionRoleMappings(OpenIdProtocol, provider, config.PermissionRoleMappings);
        // Reject an invalid parental-rating mapping (#736) at the door too (negative score / no roles), like
        // the permission-role guard above - the Add endpoints bypass the config-page save-time validation.
        ProviderConfigValidator.ValidateParentalRatingMappings(OpenIdProtocol, provider, config.ParentalRatingRoleMappings);
        // And an invalid SyncPlay-access mapping (#827): a level the resolver cannot parse would map nothing
        // at login, so it is refused at every write door rather than only at the config page.
        ProviderConfigValidator.ValidateSyncPlayAccessMappings(OpenIdProtocol, provider, config.SyncPlayAccessRoleMappings);
        // And an invalid access-duration mapping (#1146), for the same reason: a non-positive or out-of-range
        // duration reaching the login path would silently stamp nothing, so it is refused at every write door
        // rather than only at the config page.
        ProviderConfigValidator.ValidateGuestAccessDurations(OpenIdProtocol, provider, config.GuestAccessDurationRoleMappings);
        // Reject RequireAcr with no acr_values at the door too (#757): an empty allow-list would refuse every
        // login for the provider (a silent single-provider lockout). Mirrors the config-page/import validation
        // so this Add path - which persists through MutateConfiguration and bypasses the save-time Validate -
        // shares the same fail-closed guard.
        ProviderConfigValidator.ValidateAcrRequirement(provider, config);
        // And a post-logout return URL off the configured base (#727, SLO-4) at the door too (#1504): the
        // runtime drops such a URL at logout, so it would be stored with a 200 and never fire. Same predicate
        // and same skip as the save - without a determinate base the runtime allow-list stays the only check.
        ProviderConfigValidator.ValidatePostLogoutRedirectUri(OpenIdProtocol, provider, config.BaseUrlOverride, config.PostLogoutRedirectUri);
        var secretDropped = SSOPlugin.Instance.MutateConfiguration(configuration =>
        {
            // The name guard needs the under-lock existence check (#336) and runs before any mutation,
            // so a throw leaves the live configuration untouched and nothing is persisted.
            var providerExists = configuration.OidConfigs.TryGetValue(provider, out var existing);
            RejectInvalidNewProviderName(provider, providerExists);
            RejectInvalidProvisioningPolicy(OpenIdProtocol, provider, config, configuration);

            // THE FACT THIS SAVE DROPS THE STORED SECRET (#1872), read from the posted config against the
            // stored one. The rule stays as it is - a write-only secret must not follow a provider repointed
            // at another token endpoint - and the door answers with what it did, so the secret is asked for
            // now rather than found missing at the next login.
            var dropped = providerExists && ServerManagedFields.SecretDroppedByRepoint(config, existing);

            // Re-inject the server-managed fields this API cannot carry - CanonicalLinks ([JsonIgnore],
            // #157) and the write-only secret's blank-means-keep rule (#189) - through the one shared
            // ServerManagedFields.Preserve the config-page save also uses, so every write path agrees.
            if (providerExists)
            {
                ServerManagedFields.Preserve(config, existing);
            }

            configuration.OidConfigs[provider] = config;
            return dropped;
        });
        SsoAudit.ProviderConfigured(_logger, OpenIdProtocol, provider);

        // Audit any disabled security check (#140), so enabling an escape hatch (DisableHttps,
        // DoNotValidateIssuerName, DoNotValidateEndpoints) via this API leaves a trace too.
        var insecure = OidcInsecureToggles.Enabled(config);
        if (insecure.Count > 0)
        {
            SsoAudit.InsecureOptionsEnabled(_logger, OpenIdProtocol, provider, insecure);
        }

        return Ok(ProviderSaveResponse.For(secretDropped));
    }

    /// <summary>
    /// Deletes an OpenID provider.
    /// </summary>
    /// <param name="provider">Name of provider to delete.</param>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("OID/Del/{provider}")]
    public void OidDel(string provider)
    {
        RejectManagedProviderWrite("OID/Del", OpenIdProtocol, provider, SSOPlugin.Instance.ConfigStore.ManagedProviders.OidSource(provider));
        var removed = SSOPlugin.Instance.MutateConfiguration(configuration => configuration.OidConfigs.Remove(provider));
        if (removed)
        {
            SsoAudit.ProviderRemoved(_logger, OpenIdProtocol, provider);
        }
    }

    /// <summary>
    /// Lists the OpenID providers configured. Requires administrator privileges.
    /// </summary>
    /// <returns>The list of OpenID configurations.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("OID/Get")]
    public ActionResult OidProviders()
    {
        return Ok(SSOPlugin.Instance.ReadConfiguration(c => SnapshotConfigs(c.OidConfigs)));
    }

    /// <summary>
    /// Lists the names of the enabled OpenID providers only. Intentionally anonymous - see the
    /// in-body rationale (#540).
    /// </summary>
    /// <returns>The list of enabled OpenID provider names.</returns>
    [HttpGet("OID/GetNames")]
    public ActionResult OidProviderNames()
    {
        // Only enabled providers are offered (#344), because a disabled one cannot complete a link; the server-side
        // rejection stays the real gate. Materialized under the lock (#157) so the formatter never enumerates a live
        // view. No [Authorize] on purpose (#540): the linking page that calls this carries none either and renders
        // the same names to an anonymous visitor, so gating it would break that page's render for nobody's gain.
        return Ok(SSOPlugin.Instance.ReadConfiguration(c => EnabledProviderNames(c.OidConfigs)));
    }

    /// <summary>
    /// Lists the names of the enabled SAML providers only. Intentionally anonymous - see the
    /// in-body rationale (#540).
    /// </summary>
    /// <returns>The list of enabled SAML provider names.</returns>
    [HttpGet("SAML/GetNames")]
    public ActionResult SamlProviderNames()
    {
        // Enabled-only and materialized under the lock, as OID/GetNames does (#344, #157/F-10).
        // Anonymous by the same design as OID/GetNames above (#540) - same caller, same already-public
        // rendering, same rationale.
        return Ok(SSOPlugin.Instance.ReadConfiguration(c => EnabledProviderNames(c.SamlConfigs)));
    }

    /// <summary>
    /// Adds a SAML configuration. If the provider already exists, overwrite it.
    /// </summary>
    /// <param name="provider">The provider name to add.</param>
    /// <param name="newConfig">The SAML configuration object (deserialized) from JSON.</param>
    /// <returns>The success result.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("SAML/Add/{provider}")]
    public OkResult SamlAdd(string provider, [FromBody] SamlConfig newConfig)
    {
        RejectManagedProviderWrite("SAML/Add", SamlProtocol, provider, SSOPlugin.Instance.ConfigStore.ManagedProviders.SamlSource(provider));
        RejectNullProviderBody(newConfig);
        RejectInvalidBaseUrlOverride(newConfig.BaseUrlOverride);
        RejectInvalidSamlSloEndpoint(newConfig.SamlSloEndpoint);
        RejectInvalidSamlCertificate(newConfig.SamlCertificate);
        RejectInvalidSamlSecondaryCertificate(newConfig.SamlSecondaryCertificate);
        RejectInvalidSamlSigningKey(newConfig.SamlSigningKeyPfx);
        RejectInvalidSamlSigningKey(newConfig.SamlRolloverSigningKeyPfx);
        // Reject a malformed generic permission-role mapping (#164) at the door, as OidAdd does.
        ProviderConfigValidator.ValidatePermissionRoleMappings(SamlProtocol, provider, newConfig.PermissionRoleMappings);
        ProviderConfigValidator.ValidateParentalRatingMappings(SamlProtocol, provider, newConfig.ParentalRatingRoleMappings);
        ProviderConfigValidator.ValidateGuestAccessDurations(SamlProtocol, provider, newConfig.GuestAccessDurationRoleMappings);
        ProviderConfigValidator.ValidateSyncPlayAccessMappings(SamlProtocol, provider, newConfig.SyncPlayAccessRoleMappings);
        SSOPlugin.Instance.MutateConfiguration(configuration =>
        {
            // The name guard needs the under-lock existence check (#336) and runs before any mutation,
            // so a throw leaves the live configuration untouched and nothing is persisted.
            var providerExists = configuration.SamlConfigs.TryGetValue(provider, out var existing);
            RejectInvalidNewProviderName(provider, providerExists);
            RejectInvalidProvisioningPolicy(SamlProtocol, provider, newConfig, configuration);

            // Preserve the server-managed canonical links (#157), as OidAdd does, through the shared
            // ServerManagedFields.Preserve: the posted config never carries them ([JsonIgnore]), so
            // re-inject the live map before the wholesale replace so an API save cannot wipe links.
            if (providerExists)
            {
                ServerManagedFields.Preserve(newConfig, existing);
            }

            configuration.SamlConfigs[provider] = newConfig;
        });
        SsoAudit.ProviderConfigured(_logger, SamlProtocol, provider);

        // Mirror OidAdd (#140/#672): a SAML provider added with a default-on protection disabled
        // (DoNotValidateAudience) leaves the same auditable [SSO Audit] trace an OpenID escape hatch does.
        var insecure = SamlInsecureToggles.Enabled(newConfig);
        if (insecure.Count > 0)
        {
            SsoAudit.InsecureOptionsEnabled(_logger, SamlProtocol, provider, insecure);
        }

        return Ok();
    }

    /// <summary>
    /// Deletes a provider from the configuration with a given ID.
    /// </summary>
    /// <param name="provider">The ID of the provider to delete.</param>
    /// <returns>The success result.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("SAML/Del/{provider}")]
    public OkResult SamlDel(string provider)
    {
        RejectManagedProviderWrite("SAML/Del", SamlProtocol, provider, SSOPlugin.Instance.ConfigStore.ManagedProviders.SamlSource(provider));
        var removed = SSOPlugin.Instance.MutateConfiguration(configuration => configuration.SamlConfigs.Remove(provider));
        if (removed)
        {
            SsoAudit.ProviderRemoved(_logger, SamlProtocol, provider);
        }

        return Ok();
    }

    /// <summary>
    /// Returns a list of all SAML providers configured. Requires administrator privileges.
    /// </summary>
    /// <returns>A list of all of the Saml providers available.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("SAML/Get")]
    public ActionResult SamlProviders()
    {
        return Ok(SSOPlugin.Instance.ReadConfiguration(c => SnapshotConfigs(c.SamlConfigs)));
    }

    /// <summary>Parses SAML identity-provider metadata, from a server-fetched URL or pasted XML, into the SSO endpoint and signing certificates an administrator would otherwise hand-copy (#735), returning them for review and applying nothing.</summary>
    /// <remarks>Elevation-gated because the server fetches an admin-supplied URL, through the SSRF-hardened client that refuses a private address; the XML is parsed with no DTD and a size bound, the body is size-capped, and the endpoint is throttled after the elevation guard.</remarks>
    /// <param name="request">Exactly one of a metadata URL or pasted metadata XML.</param>
    /// <returns>The parsed import values, or 400 when the input or metadata is invalid.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("SAML/ImportMetadata")]
    [RequestSizeLimit(ConfigImportMaxBytes)]
    [Consumes(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> SamlImportMetadata([FromBody] SamlMetadataImportRequest request)
    {
        // Throttle after the elevation guard, before the outbound fetch (mirrors OidTest): the [Authorize]
        // filter rejects a non-elevated caller before the body runs, so an unauthorized request never reaches
        // the limiter or the fetch - no SSRF probe, no rate-limit oracle.
        if (RateLimitCheck(SsoRateLimitClass.Test) is { } throttled)
        {
            return throttled;
        }

        if (request is null)
        {
            return BadRequest("The metadata-import request is missing or is not valid JSON.");
        }

        try
        {
            var import = await SamlMetadataImporter.ImportAsync(_httpClientFactory, request.Url, request.Xml, HttpContext.RequestAborted).ConfigureAwait(false);
            return Ok(import);
        }
        catch (SamlMetadataException ex)
        {
            // The message is an admin-facing fixed string (no IdP/library detail); nothing was applied.
            return BadRequest(ex.Message);
        }
    }
}
