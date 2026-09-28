// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Linq;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>Rejects invalid provider configuration fail-closed before anything is persisted.</summary>
/// <remarks>
/// Every rule is one shared predicate the Add endpoints also delegate to; only the messages differ, because the
/// config-page messages name the provider and the Add-endpoint messages stay input-independent (#671).
/// </remarks>
internal static class ProviderConfigValidator
{
    /// <summary>Validates an entire incoming configuration before the config-page save persists it, throwing on the first invalid provider.</summary>
    /// <param name="incoming">The configuration about to be persisted.</param>
    /// <param name="live">The current live configuration, used to tell a newly added provider from an existing one.</param>
    /// <exception cref="ArgumentException">A provider fails any per-provider rule.</exception>
    internal static void Validate(PluginConfiguration incoming, PluginConfiguration live)
    {
        // The profile set first, because a provider's reference is only as good as the profile it names (#1105).
        ValidateProvisioningProfiles(incoming.ProvisioningProfiles);

        if (incoming.OidConfigs != null)
        {
            foreach (var kvp in incoming.OidConfigs)
            {
                ValidateProviderName("OpenID", kvp.Key, isNew: live?.OidConfigs?.ContainsKey(kvp.Key) != true);
                ValidateBaseUrlOverride("OpenID", kvp.Key, kvp.Value?.BaseUrlOverride);
                ValidatePostLogoutRedirectUri("OpenID", kvp.Key, kvp.Value?.BaseUrlOverride, kvp.Value?.PostLogoutRedirectUri);
                ValidatePermissionRoleMappings("OpenID", kvp.Key, kvp.Value?.PermissionRoleMappings);
                ValidateParentalRatingMappings("OpenID", kvp.Key, kvp.Value?.ParentalRatingRoleMappings);
                ValidateSyncPlayAccessMappings("OpenID", kvp.Key, kvp.Value?.SyncPlayAccessRoleMappings);
                ValidateGuestAccessDurations("OpenID", kvp.Key, kvp.Value?.GuestAccessDurationRoleMappings);
                ValidateProvisioningTemplate("OpenID", kvp.Key, kvp.Value?.ProvisioningPolicyTemplate);
                ValidateProvisioningProfileReference("OpenID", kvp.Key, kvp.Value, incoming.ProvisioningProfiles);
                ValidateProvisioningProfileRoleMappings("OpenID", kvp.Key, kvp.Value, incoming.ProvisioningProfiles);
                ValidateAcrRequirement(kvp.Key, kvp.Value);
            }
        }

        if (incoming.SamlConfigs != null)
        {
            foreach (var kvp in incoming.SamlConfigs)
            {
                ValidateProviderName("SAML", kvp.Key, isNew: live?.SamlConfigs?.ContainsKey(kvp.Key) != true);
                ValidateBaseUrlOverride("SAML", kvp.Key, kvp.Value?.BaseUrlOverride);
                ValidateSamlSloEndpoint(kvp.Key, kvp.Value?.SamlSloEndpoint);
                ValidateSamlCertificate(kvp.Key, kvp.Value?.SamlCertificate);
                ValidateSamlSecondaryCertificate(kvp.Key, kvp.Value?.SamlSecondaryCertificate);
                ValidateSamlSigningKey(kvp.Key, kvp.Value?.SamlSigningKeyPfx);
                ValidateSamlSigningKey(kvp.Key, kvp.Value?.SamlRolloverSigningKeyPfx);
                ValidatePermissionRoleMappings("SAML", kvp.Key, kvp.Value?.PermissionRoleMappings);
                ValidateParentalRatingMappings("SAML", kvp.Key, kvp.Value?.ParentalRatingRoleMappings);
                ValidateSyncPlayAccessMappings("SAML", kvp.Key, kvp.Value?.SyncPlayAccessRoleMappings);
                ValidateGuestAccessDurations("SAML", kvp.Key, kvp.Value?.GuestAccessDurationRoleMappings);
                ValidateProvisioningTemplate("SAML", kvp.Key, kvp.Value?.ProvisioningPolicyTemplate);
                ValidateProvisioningProfileReference("SAML", kvp.Key, kvp.Value, incoming.ProvisioningProfiles);
                ValidateProvisioningProfileRoleMappings("SAML", kvp.Key, kvp.Value, incoming.ProvisioningProfiles);
            }
        }
    }

    /// <summary>Rejects a new provider whose name would corrupt the callback URL it becomes part of (#336, #360).</summary>
    /// <remarks>An already-registered name is exempt, so a deployment is never stranded behind a rename.</remarks>
    /// <param name="protocol">The protocol label ("OpenID" or "SAML") echoed in the rejection message.</param>
    /// <param name="provider">The provider name to check.</param>
    /// <param name="isNew">Whether this name is absent from the live configuration; only new names are validated.</param>
    /// <exception cref="ArgumentException">The name is new and contains a forbidden character.</exception>
    internal static void ValidateProviderName(string protocol, string provider, bool isNew)
    {
        if (isNew && ProviderNameValidator.IsInvalid(provider))
        {
            // Every control character is stripped inline, then the two line separators char.IsControl misses (#360).
            var echoName = string.Concat((provider ?? string.Empty).Where(c => !char.IsControl(c))).ReplaceLineEndings(string.Empty);
            throw new ArgumentException(
                $"{protocol} provider '{echoName}' has a name with control characters, URI-reserved characters, or a backslash; the name becomes part of the callback URL registered with the identity provider, so a new name must not contain control characters, a backslash, or any of % : / ? # [ ] @ ! $ & ' ( ) * + , ; =.",
                nameof(provider));
        }
    }

    /// <summary>Rejects an OpenID provider that requires an ACR but supplies no acr_values, which would lock out every login for it (#757).</summary>
    /// <param name="provider">The provider name, echoed (line-ending-stripped) in the rejection message.</param>
    /// <param name="config">The OpenID provider configuration to check; a null config is tolerated.</param>
    /// <exception cref="ArgumentException">RequireAcr is set with blank AcrValues.</exception>
    internal static void ValidateAcrRequirement(string provider, OidConfig? config)
    {
        if (config?.RequireAcr == true && string.IsNullOrWhiteSpace(config.AcrValues))
        {
            throw new ArgumentException(
                $"OpenID provider '{provider?.ReplaceLineEndings(string.Empty)}' sets RequireAcr but no Acr Values; set the required acr_values (space-separated) the returned acr must match, or turn RequireAcr off.",
                nameof(config));
        }
    }

    /// <summary>Rejects a canonical base-URL override that is set but not an absolute http(s) URL, which would fall back to the request host at login (#139).</summary>
    /// <param name="protocol">The protocol label ("OpenID" or "SAML") echoed in the rejection message.</param>
    /// <param name="provider">The provider name, echoed (line-ending-stripped) in the rejection message.</param>
    /// <param name="baseUrlOverride">The override value to check.</param>
    /// <exception cref="ArgumentException">The override is non-blank and not a valid absolute http(s) URL.</exception>
    internal static void ValidateBaseUrlOverride(string protocol, string provider, string? baseUrlOverride)
    {
        if (CanonicalBaseUrl.IsInvalidOverride(baseUrlOverride))
        {
            throw new ArgumentException(
                $"{protocol} provider '{provider?.ReplaceLineEndings(string.Empty)}' has an invalid Base URL override; it must be an absolute http(s) URL such as https://jellyfin.example.com.",
                nameof(baseUrlOverride));
        }
    }

    /// <summary>Rejects a <c>post_logout_redirect_uri</c> the logout would silently drop, using the runtime's own allow-list predicate (#727).</summary>
    /// <remarks>Checked only where a Base URL override makes the canonical base determinate at save time; OpenID only, since only that logout path uses it.</remarks>
    /// <param name="protocol">The protocol label (always "OpenID") echoed in the rejection message.</param>
    /// <param name="provider">The provider name, echoed (line-ending-stripped) in the rejection message.</param>
    /// <param name="baseUrlOverride">The provider's canonical base-URL override; only a valid override makes the base determinate at save time.</param>
    /// <param name="postLogoutRedirectUri">The configured post-logout return URL to check.</param>
    /// <exception cref="ArgumentException">The value is non-blank, the base is determinate, and the value is not at/under it.</exception>
    internal static void ValidatePostLogoutRedirectUri(string protocol, string provider, string? baseUrlOverride, string? postLogoutRedirectUri)
    {
        if (string.IsNullOrWhiteSpace(postLogoutRedirectUri)
            || !CanonicalBaseUrl.TryNormalize(baseUrlOverride, out var canonicalBase))
        {
            return;
        }

        if (!OidcLogout.IsAllowedPostLogoutRedirect(postLogoutRedirectUri, canonicalBase, out _))
        {
            throw new ArgumentException(
                $"{protocol} provider '{provider?.ReplaceLineEndings(string.Empty)}' has a Post Logout Redirect URI that is not at or under the configured Base URL; it must be an absolute http(s) URL at or under this server's base URL, or it is ignored at logout. Leave it blank for no post-logout redirect.",
                nameof(postLogoutRedirectUri));
        }
    }

    /// <summary>Rejects a SAML single-logout endpoint that is set but not an absolute https URL, which would silently disable SP-initiated logout (#727).</summary>
    /// <remarks>https, because the redirect carries a signed request naming the subject.</remarks>
    /// <param name="provider">The provider name, echoed (line-ending-stripped) in the rejection message.</param>
    /// <param name="sloEndpoint">The SAML SLO endpoint to check.</param>
    /// <exception cref="ArgumentException">The endpoint is non-blank and not a valid absolute https URL.</exception>
    internal static void ValidateSamlSloEndpoint(string provider, string? sloEndpoint)
    {
        if (string.IsNullOrWhiteSpace(sloEndpoint))
        {
            return;
        }

        if (!CanonicalBaseUrl.TryNormalize(sloEndpoint, out var normalized)
            || !normalized.StartsWith("https://", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"SAML provider '{provider?.ReplaceLineEndings(string.Empty)}' has an invalid SAML SLO Endpoint; it must be an absolute https URL such as https://idp.example.com/slo, or left blank to disable SP-initiated Single Logout.",
                nameof(sloEndpoint));
        }
    }

    /// <summary>Rejects a SAML provider whose signing certificate is set but not a loadable X.509 certificate, which would throw on every callback (#206).</summary>
    /// <param name="provider">The provider name, echoed (line-ending-stripped) in the rejection message.</param>
    /// <param name="certificate">The Base64-encoded (DER) X.509 certificate to check.</param>
    /// <exception cref="ArgumentException">The certificate is non-blank and not loadable.</exception>
    internal static void ValidateSamlCertificate(string provider, string? certificate)
    {
        if (SamlCertificate.IsInvalid(certificate ?? string.Empty))
        {
            throw new ArgumentException(
                $"SAML provider '{provider?.ReplaceLineEndings(string.Empty)}' has an invalid signing certificate; it must be a Base64-encoded (DER) X.509 certificate.",
                nameof(certificate));
        }
    }

    /// <summary>Rejects a SAML provider whose secondary verification certificate is set but not loadable, validated exactly like the primary (#491).</summary>
    /// <param name="provider">The provider name, echoed (line-ending-stripped) in the rejection message.</param>
    /// <param name="certificate">The Base64-encoded (DER) X.509 certificate to check.</param>
    /// <exception cref="ArgumentException">The certificate is non-blank and not loadable.</exception>
    internal static void ValidateSamlSecondaryCertificate(string provider, string? certificate)
    {
        if (SamlCertificate.IsInvalid(certificate ?? string.Empty))
        {
            throw new ArgumentException(
                $"SAML provider '{provider?.ReplaceLineEndings(string.Empty)}' has an invalid secondary signing certificate; it must be a Base64-encoded (DER) X.509 certificate.",
                nameof(certificate));
        }
    }

    /// <summary>Rejects a permission-role mapping whose permission is empty, unknown, or one of the dedicated permissions with their own setting (#164).</summary>
    /// <remarks>A null collection or a null entry maps nothing and is tolerated.</remarks>
    /// <param name="protocol">The protocol label ("OpenID" or "SAML") echoed in the rejection message.</param>
    /// <param name="provider">The provider name, echoed (control-stripped) in the rejection message.</param>
    /// <param name="mappings">The permission-role mappings to check.</param>
    /// <exception cref="ArgumentException">An entry names an invalid or dedicated permission.</exception>
    internal static void ValidatePermissionRoleMappings(string protocol, string provider, System.Collections.Generic.IEnumerable<PermissionRoleMap>? mappings)
    {
        if (mappings == null)
        {
            return;
        }

        foreach (var mapping in mappings)
        {
            if (mapping == null)
            {
                continue;
            }

            var status = PermissionRolePolicy.Classify(mapping.Permission);
            if (status == PermissionRolePolicy.PermissionNameStatus.Valid)
            {
                continue;
            }

            var echoName = (provider ?? string.Empty).ReplaceLineEndings(string.Empty);
            var echoPerm = string.Concat((mapping.Permission ?? string.Empty).Where(c => !char.IsControl(c))).ReplaceLineEndings(string.Empty);
            var reason = status switch
            {
                PermissionRolePolicy.PermissionNameStatus.Empty => "has an empty permission name",
                PermissionRolePolicy.PermissionNameStatus.Dedicated => $"names '{echoPerm}', which is managed by its own dedicated setting (administrator, all-folders, or Live TV) or is barred from role mapping (account-disable) and may not be mapped here",
                _ => $"names '{echoPerm}', which is not a known Jellyfin permission",
            };
            throw new ArgumentException(
                $"{protocol} provider '{echoName}' has an invalid permission-role mapping: it {reason}. Each mapping's Permission must be the exact name of a Jellyfin PermissionKind (for example EnableContentDownloading) other than IsAdministrator, EnableAllFolders, EnableLiveTvAccess, EnableLiveTvManagement, or IsDisabled.",
                nameof(mappings));
        }
    }

    /// <summary>Rejects a provisioning template that names a permission the plugin may not write, or carries a value Jellyfin cannot mean (#1099).</summary>
    /// <param name="protocol">The protocol label ("OpenID" or "SAML") echoed in the rejection message.</param>
    /// <param name="provider">The provider name, echoed (control-stripped) in the rejection message.</param>
    /// <param name="template">The provisioning template to check.</param>
    /// <exception cref="ArgumentException">The template names an invalid or dedicated permission, or carries a negative number.</exception>
    internal static void ValidateProvisioningTemplate(string protocol, string provider, ProvisioningPolicyTemplate? template)
        => ValidateTemplateFields($"{protocol} provider '{(provider ?? string.Empty).ReplaceLineEndings(string.Empty)}'", template);

    // One implementation for the inline template and the named profile, so a profile cannot carry what the inline surface refuses (#1105).
    private static void ValidateTemplateFields(string subject, ProvisioningPolicyTemplate? template)
    {
        if (template == null)
        {
            return;
        }

        foreach (var entry in template.Permissions ?? new System.Collections.Generic.List<ProvisionedPermissionEntry>())
        {
            if (entry == null)
            {
                continue;
            }

            // The same classification the role mappings are validated against.
            var status = PermissionRolePolicy.Classify(entry.Permission);
            if (status == PermissionRolePolicy.PermissionNameStatus.Valid)
            {
                continue;
            }

            var echoPerm = string.Concat((entry.Permission ?? string.Empty).Where(c => !char.IsControl(c))).ReplaceLineEndings(string.Empty);
            var reason = status switch
            {
                PermissionRolePolicy.PermissionNameStatus.Empty => "has an entry with an empty permission name",
                PermissionRolePolicy.PermissionNameStatus.Dedicated => $"names '{echoPerm}', which is managed by its own dedicated setting (administrator, all-folders, or Live TV) or is barred from SSO writes (account-disable) and may not be templated",
                _ => $"names '{echoPerm}', which is not a known Jellyfin permission",
            };
            throw new ArgumentException(
                $"{subject} has an invalid provisioning template: it {reason}. Each entry's Permission must be the exact name of a Jellyfin PermissionKind (for example EnableContentDownloading) other than IsAdministrator, EnableAllFolders, EnableLiveTvAccess, EnableLiveTvManagement, or IsDisabled.",
                nameof(template));
        }

        // Zero is meaningful on both and null is unset; only a negative value is refused, and refused rather than clamped.
        if (template.RemoteClientBitrateLimit < 0)
        {
            throw new ArgumentException(
                $"{subject} has an invalid provisioning template: the remote-client bitrate limit must be zero or greater (zero means no limit; leave it unset to keep Jellyfin's default).",
                nameof(template));
        }

        if (template.MaxActiveSessions < 0)
        {
            throw new ArgumentException(
                $"{subject} has an invalid provisioning template: the maximum active sessions must be zero or greater (zero means unlimited; leave it unset to keep Jellyfin's default).",
                nameof(template));
        }

        // The same parse the writer uses, so the validator refuses exactly what the create arm would skip (#1100, #1482).
        if (template.SubtitleMode != null
            && !ProvisioningPolicy.TryParseSubtitleMode(template.SubtitleMode, out _))
        {
            var echoMode = string.Concat(template.SubtitleMode.Where(c => !char.IsControl(c))).ReplaceLineEndings(string.Empty);
            throw new ArgumentException(
                $"{subject} has an invalid provisioning template: it names subtitle mode '{echoMode}', which is not a known Jellyfin SubtitlePlaybackMode. Use the exact enum name (for example Default, Always, OnlyForced, or Smart), or leave it unset to keep Jellyfin's default.",
                nameof(template));
        }

        // Same parse as the writer, and a list longer than the web client renders is refused too (#1101).
        if (template.HomeSections != null
            && !HomeScreenPolicy.TryParseHomeSections(template.HomeSections, out _, out var refusedSection))
        {
            var reason = refusedSection is null
                ? $"lists {template.HomeSections.Count} home-screen sections, more than the {HomeScreenPolicy.SlotCount} slots the web client renders"
                : $"names home-screen section '{string.Concat(refusedSection.Where(c => !char.IsControl(c))).ReplaceLineEndings(string.Empty)}', which is not a known Jellyfin HomeSectionType";
            throw new ArgumentException(
                $"{subject} has an invalid provisioning template: it {reason}. Use the exact enum names (for example SmallLibraryTiles, Resume, NextUp, LatestMedia, or None), one per slot from the top and at most {HomeScreenPolicy.SlotCount}, or leave the list empty to keep Jellyfin's own layout.",
                nameof(template));
        }
    }

    /// <summary>Rejects a provisioning-profile set that carries an unnamed profile or one an inline template would be refused for (#1105).</summary>
    /// <param name="profiles">The profile set to check.</param>
    /// <exception cref="ArgumentException">A profile is unnamed, or its template fails the template checks.</exception>
    internal static void ValidateProvisioningProfiles(SerializableDictionary<string, ProvisioningPolicyTemplate>? profiles)
    {
        if (profiles == null)
        {
            return;
        }

        foreach (var kvp in profiles)
        {
            if (string.IsNullOrWhiteSpace(kvp.Key))
            {
                throw new ArgumentException(
                    "A provisioning profile has a blank name. Every profile needs a name, because a name is the only thing a provider can point at; an unnamed one could never be selected and would be persisted as dead configuration.",
                    nameof(profiles));
            }

            ValidateTemplateFields(
                $"Provisioning profile '{string.Concat(kvp.Key.Where(c => !char.IsControl(c))).ReplaceLineEndings(string.Empty)}'",
                kvp.Value);
        }
    }

    /// <summary>Rejects a provider that names a profile the configuration does not define, or names one beside its own inline template (#1105).</summary>
    /// <remarks>Both would be silent: the resolution at creation is fail-closed and does not fall back.</remarks>
    /// <param name="protocol">The protocol label ("OpenID" or "SAML") echoed in the rejection message.</param>
    /// <param name="provider">The provider name, echoed (control-stripped) in the rejection message.</param>
    /// <param name="config">The provider configuration to check; <see langword="null"/> names nothing.</param>
    /// <param name="profiles">The profile set the name must resolve in.</param>
    /// <exception cref="ArgumentException">The named profile is undefined, or the provider also carries an inline template.</exception>
    internal static void ValidateProvisioningProfileReference(
        string protocol,
        string provider,
        ProviderConfigBase? config,
        SerializableDictionary<string, ProvisioningPolicyTemplate>? profiles)
    {
        var profile = config?.ProvisioningProfile;
        if (string.IsNullOrWhiteSpace(profile))
        {
            return;
        }

        var echoName = (provider ?? string.Empty).ReplaceLineEndings(string.Empty);
        var echoProfile = string.Concat(profile.Where(c => !char.IsControl(c))).ReplaceLineEndings(string.Empty);

        if (config!.ProvisioningPolicyTemplate != null)
        {
            throw new ArgumentException(
                $"{protocol} provider '{echoName}' names the provisioning profile '{echoProfile}' and also carries its own inline provisioning template. A provider's new accounts get exactly one policy, so keep the profile and remove the inline template, or clear the profile name.",
                nameof(config));
        }

        if (profiles == null || !profiles.ContainsKey(profile))
        {
            throw new ArgumentException(
                $"{protocol} provider '{echoName}' names the provisioning profile '{echoProfile}', which this configuration does not define. Define the profile, or clear the name - a provider pointing at a missing profile provisions nothing rather than falling back.",
                nameof(config));
        }
    }

    /// <summary>Rejects a provider whose role-to-profile rows name no profile, list no roles, or name a profile the configuration does not define (#1106).</summary>
    /// <param name="protocol">The protocol label ("OpenID" or "SAML") echoed in the rejection message.</param>
    /// <param name="provider">The provider name, echoed (control-stripped) in the rejection message.</param>
    /// <param name="config">The provider configuration to check; <see langword="null"/> configures no rows.</param>
    /// <param name="profiles">The profile set every row's name must resolve in.</param>
    /// <exception cref="ArgumentException">A row names no profile, lists no roles, or names an undefined profile.</exception>
    internal static void ValidateProvisioningProfileRoleMappings(
        string protocol,
        string provider,
        ProviderConfigBase? config,
        SerializableDictionary<string, ProvisioningPolicyTemplate>? profiles)
    {
        var mappings = config?.ProvisioningProfileRoleMappings;
        if (mappings == null)
        {
            return;
        }

        var echoName = (provider ?? string.Empty).ReplaceLineEndings(string.Empty);

        foreach (var mapping in mappings)
        {
            if (mapping == null)
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(mapping.Profile))
            {
                throw new ArgumentException(
                    $"{protocol} provider '{echoName}' has a role-to-provisioning-profile row naming no profile. A row exists to send matching logins to a named profile, so a row without one could never select anything and would be persisted as dead configuration.",
                    nameof(config));
            }

            var echoProfile = string.Concat(mapping.Profile.Where(c => !char.IsControl(c))).ReplaceLineEndings(string.Empty);

            // A row with no role, or only blank ones the matcher skips (#935), would sit in the map selecting nothing.
            if (mapping.Roles == null || !mapping.Roles.Any(role => !string.IsNullOrWhiteSpace(role)))
            {
                throw new ArgumentException(
                    $"{protocol} provider '{echoName}' has a role-to-provisioning-profile row for '{echoProfile}' that lists no roles. A row with no roles can never match a login, so list the roles it is for or remove the row.",
                    nameof(config));
            }

            if (profiles == null || !profiles.ContainsKey(mapping.Profile.Trim()))
            {
                throw new ArgumentException(
                    $"{protocol} provider '{echoName}' has a role-to-provisioning-profile row naming '{echoProfile}', which this configuration does not define. Define the profile, or remove the row - a row pointing at a missing profile provisions nothing for the logins it matches rather than falling back to the provider default.",
                    nameof(config));
            }
        }
    }

    /// <summary>Rejects a parental-rating mapping with a negative score or no roles (#736).</summary>
    /// <param name="protocol">The protocol label ("OpenID" or "SAML") echoed in the rejection message.</param>
    /// <param name="provider">The provider name, echoed (line-ending-stripped) in the rejection message.</param>
    /// <param name="mappings">The parental-rating mappings to check.</param>
    /// <exception cref="ArgumentException">An entry has a negative score or lists no roles.</exception>
    internal static void ValidateParentalRatingMappings(string protocol, string provider, System.Collections.Generic.IEnumerable<ParentalRatingRoleMap>? mappings)
    {
        if (mappings == null)
        {
            return;
        }

        foreach (var mapping in mappings)
        {
            if (mapping == null)
            {
                continue;
            }

            var echoName = (provider ?? string.Empty).ReplaceLineEndings(string.Empty);
            if (mapping.Score < 0)
            {
                throw new ArgumentException(
                    $"{protocol} provider '{echoName}' has an invalid parental-rating mapping: the score must be zero or greater (a smaller value is more restrictive; null/unmapped leaves the ceiling untouched).",
                    nameof(mappings));
            }

            if (mapping.Roles == null || mapping.Roles.Length == 0)
            {
                throw new ArgumentException(
                    $"{protocol} provider '{echoName}' has a parental-rating mapping with no roles: each mapping must list at least one role the ceiling applies to.",
                    nameof(mappings));
            }
        }
    }

    /// <summary>Rejects a SyncPlay-access mapping whose level is not a declared member of Jellyfin's enum, or which lists no roles (#827).</summary>
    /// <param name="protocol">The protocol label ("OpenID" or "SAML") echoed in the rejection message.</param>
    /// <param name="provider">The provider name, echoed (line-ending-stripped) in the rejection message.</param>
    /// <param name="mappings">The SyncPlay-access mappings to check.</param>
    /// <exception cref="ArgumentException">An entry names an unknown level or lists no roles.</exception>
    internal static void ValidateSyncPlayAccessMappings(string protocol, string provider, System.Collections.Generic.IEnumerable<SyncPlayAccessRoleMap>? mappings)
    {
        if (mappings == null)
        {
            return;
        }

        foreach (var mapping in mappings)
        {
            if (mapping == null)
            {
                continue;
            }

            var echoName = (provider ?? string.Empty).ReplaceLineEndings(string.Empty);

            // The same parse the login path uses, so a saved mapping is one the mint can act on.
            if (!SyncPlayAccessPolicy.TryParseAccess(mapping.Access, out _))
            {
                var echoAccess = string.Concat((mapping.Access ?? string.Empty).Where(c => !char.IsControl(c))).ReplaceLineEndings(string.Empty);
                throw new ArgumentException(
                    $"{protocol} provider '{echoName}' has an invalid SyncPlay-access mapping: '{echoAccess}' is not a SyncPlay access level. Use the exact spelling CreateAndJoinGroups, JoinGroups or None.",
                    nameof(mappings));
            }

            if (mapping.Roles == null || mapping.Roles.Length == 0)
            {
                throw new ArgumentException(
                    $"{protocol} provider '{echoName}' has a SyncPlay-access mapping with no roles: each mapping must list at least one role the level applies to.",
                    nameof(mappings));
            }
        }
    }

    /// <summary>Rejects an access-duration mapping whose duration is not positive, exceeds <see cref="GuestAccessDurationRoleMap.MaxDurationHours"/>, or lists no roles (#1146).</summary>
    /// <param name="protocol">The protocol label ("OpenID" or "SAML") echoed in the rejection message.</param>
    /// <param name="provider">The provider name, echoed (line-ending-stripped) in the rejection message.</param>
    /// <param name="mappings">The access-duration mappings to check.</param>
    /// <exception cref="ArgumentException">An entry has a non-positive or out-of-range duration, or lists no roles.</exception>
    internal static void ValidateGuestAccessDurations(string protocol, string provider, System.Collections.Generic.IEnumerable<GuestAccessDurationRoleMap>? mappings)
    {
        if (mappings == null)
        {
            return;
        }

        foreach (var mapping in mappings)
        {
            if (mapping == null)
            {
                continue;
            }

            var echoName = (provider ?? string.Empty).ReplaceLineEndings(string.Empty);
            if (mapping.DurationHours <= 0)
            {
                throw new ArgumentException(
                    $"{protocol} provider '{echoName}' has an invalid access-duration mapping: the duration must be greater than zero hours (remove the mapping to leave access unlimited).",
                    nameof(mappings));
            }

            if (mapping.DurationHours > GuestAccessDurationRoleMap.MaxDurationHours)
            {
                throw new ArgumentException(
                    $"{protocol} provider '{echoName}' has an access-duration mapping above the {GuestAccessDurationRoleMap.MaxDurationHours}-hour maximum: a longer limit is not a time limit, so remove the mapping instead.",
                    nameof(mappings));
            }

            if (mapping.Roles == null || mapping.Roles.Length == 0)
            {
                throw new ArgumentException(
                    $"{protocol} provider '{echoName}' has an access-duration mapping with no roles: each mapping must list at least one role the duration applies to.",
                    nameof(mappings));
            }
        }
    }

    /// <summary>Rejects a service-provider signing key that is non-blank but not a loadable unencrypted PKCS#12 blob (#167, #491).</summary>
    /// <remarks>Blank is valid, because a config-page save withholds the key and the stored one is re-injected afterwards.</remarks>
    /// <param name="provider">The provider name, echoed (line-ending-stripped) in the rejection message.</param>
    /// <param name="signingKeyPfx">The Base64-encoded PKCS#12 (PFX) signing key to check.</param>
    /// <exception cref="ArgumentException">The key is non-blank and not a loadable PFX with an RSA or ECDSA private key.</exception>
    internal static void ValidateSamlSigningKey(string provider, string? signingKeyPfx)
    {
        if (SamlSigningKey.IsInvalid(signingKeyPfx ?? string.Empty))
        {
            throw new ArgumentException(
                $"SAML provider '{provider?.ReplaceLineEndings(string.Empty)}' has an invalid request signing key; it must be a Base64-encoded, unencrypted PKCS#12 (PFX) blob containing an RSA or ECDSA private key.",
                nameof(signingKeyPfx));
        }
    }
}
