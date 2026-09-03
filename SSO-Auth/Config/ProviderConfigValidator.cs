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

/// <summary>
/// Rejects invalid provider configuration fail-closed before anything is persisted. The whole-config
/// <see cref="Validate"/> gates the admin config-page save inside <see cref="ProviderConfigStore.Save"/>
/// by composing the per-provider checks below; those per-provider methods are also exercised directly,
/// one predicate at a time, by the unit tests (hence internal, not private). The single source of truth
/// is the underlying <see cref="CanonicalBaseUrl.IsInvalidOverride"/>,
/// <see cref="OidcLogout.IsAllowedPostLogoutRedirect"/> (the SAME allow-list the logout runtime enforces),
/// <see cref="SamlCertificate.IsInvalid"/>, <see cref="SamlSigningKey.IsInvalid"/>, and
/// <see cref="ProviderNameValidator.IsInvalid"/> predicates - the SAME ones the Add endpoints' own
/// guards (<c>SSOController.RejectInvalid*</c>) delegate to. The two admin write paths keep separate
/// throwing wrappers on purpose (#671): the config-page messages here embed the provider name and
/// protocol for the admin UI, whereas the Add-endpoint messages stay generic and input-independent (they
/// never echo the caller's provider name back), and <c>RejectInvalidNewProviderName</c> resolves
/// existence under the config lock. So a new provider-config rule is one shared base predicate plus the
/// two context-appropriate wrappers - the validation logic is not duplicated, only the messaging is
/// deliberately parallel.
/// </summary>
internal static class ProviderConfigValidator
{
    // Throws if any provider's canonical base-URL override (#139) is set but not a valid absolute
    // http/https base URL, any SAML provider's signing certificate (#206) is set but not a loadable
    // X.509 certificate, or any NEWLY registered provider name (#336/#360) contains control characters,
    // URI-reserved characters, or a backslash - rejecting the save fail-closed before anything is
    // persisted. A blank override or
    // certificate is valid (the override feature is off; a half-configured provider), and a name
    // already present in the live configuration is exempt from the name rule (see
    // ValidateProviderName). Only the admin config-page save path validates the whole config; the Add
    // endpoints validate their own incoming provider at the controller, and login-path writes reuse
    // the live object and are never revalidated.

    /// <summary>
    /// Validates an entire incoming provider configuration fail-closed before the config-page save
    /// persists it, throwing on the first invalid provider found. Composes the per-provider name,
    /// base-URL-override, certificate, signing-key, ACR, permission-role and parental-rating checks
    /// over every OpenID and SAML provider; a valid config returns without effect.
    /// </summary>
    /// <param name="incoming">The configuration about to be persisted.</param>
    /// <param name="live">The current live configuration, used to tell a newly added provider from an existing one.</param>
    /// <exception cref="ArgumentException">A provider fails any per-provider rule.</exception>
    internal static void Validate(PluginConfiguration incoming, PluginConfiguration live)
    {
        // The profile set first: a provider's reference below is only as good as the profile it names, and a
        // profile carrying a permission the plugin may not write must be refused whether or not any provider
        // points at it yet (#1105).
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
            // One pass runs all three checks per provider, so with several invalid providers the first
            // error reported follows map order rather than check kind; every invalid save is still
            // rejected fail-closed before anything is persisted.
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

    // A NEW provider name containing URI-reserved or control characters would be persisted and then break
    // the callback round-trip at login (#336, #360): the name is appended raw to the redirect_uri/ACS URL
    // (the OIDC/SAML URL builders) and matched back by route. Only a name absent from the live configuration is
    // rejected - an existing name, whose URL bytes the identity provider already has registered, must
    // keep saving unchanged or the deployment would be stranded behind a rename. The echoed name gets a
    // full control strip (stronger than the line-ending strip below - see the inline comment).

    /// <summary>
    /// Rejects a NEW provider whose name would corrupt the login callback URL it becomes part of: a name
    /// that is new to the live configuration and contains control characters, a backslash, or a
    /// URI-reserved character is refused. An already-registered name is exempt so a deployment is never
    /// stranded behind a rename.
    /// </summary>
    /// <param name="protocol">The protocol label ("OpenID" or "SAML") echoed in the rejection message.</param>
    /// <param name="provider">The provider name to check.</param>
    /// <param name="isNew">Whether this name is absent from the live configuration; only new names are validated.</param>
    /// <exception cref="ArgumentException">The name is new and contains a forbidden character.</exception>
    internal static void ValidateProviderName(string protocol, string provider, bool isNew)
    {
        if (isNew && ProviderNameValidator.IsInvalid(provider))
        {
            // Rejected names can now carry arbitrary control characters (#360), so line-ending stripping
            // alone would let e.g. ESC survive into the exception text and any log that captures it -
            // strip ALL controls inline here, then the two non-control line separators (U+2028/U+2029)
            // that ReplaceLineEndings covers and char.IsControl does not.
            var echoName = string.Concat((provider ?? string.Empty).Where(c => !char.IsControl(c))).ReplaceLineEndings(string.Empty);
            throw new ArgumentException(
                $"{protocol} provider '{echoName}' has a name with control characters, URI-reserved characters, or a backslash; the name becomes part of the callback URL registered with the identity provider, so a new name must not contain control characters, a backslash, or any of % : / ? # [ ] @ ! $ & ' ( ) * + , ; =.",
                nameof(provider));
        }
    }

    // RequireAcr with no acr_values would be persisted and then refuse EVERY login for the provider (the
    // allow-list is empty, so no returned acr can satisfy it) - a silent lockout (#757). Reject it at save so
    // the mis-set is caught before it takes effect, rather than failing open (a no-op) or locking out. The
    // provider name is line-ending-stripped inline in case it reaches a log through the thrown exception.

    /// <summary>
    /// Rejects an OpenID provider that requires an ACR but supplies no acr_values, which would otherwise
    /// persist and then silently lock out every login for that provider (the allow-list is empty, so no
    /// returned acr can satisfy it). Caught at save rather than failing open or locking out (#757).
    /// </summary>
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

    // A malformed override would be persisted and then silently fall back to the request Host at
    // login (#139). The provider name is line-ending-stripped inline in case it reaches a log through
    // the thrown exception.

    /// <summary>
    /// Rejects a canonical base-URL override that is set but is not a valid absolute http(s) base URL,
    /// which would otherwise persist and then silently fall back to the request Host at login (#139). A
    /// blank override is valid (the feature is off).
    /// </summary>
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

    // A post_logout_redirect_uri that is set but not at/under this server's canonical base is silently
    // dropped at logout (OidcLogout omits it and the logout completes with no redirect back), so the admin
    // gets no feedback that their configured return URL never fires (#727, SLO-4). Reject it at save so the
    // mis-set is caught instead of failing as a silent runtime no-op. The base is only DETERMINATE at save
    // time when it is pinned via the per-provider Base URL Override - without an override the runtime derives
    // it from the request Host, which does not exist at save time - so the check applies exactly when the
    // canonical base is knowable from the config alone, and it reuses the SAME allow-list predicate the
    // runtime enforces (OidcLogout.IsAllowedPostLogoutRedirect) rather than restating the URL rule. The
    // provider name is line-ending-stripped inline in case it reaches a log through the thrown exception, and
    // the candidate value is deliberately NOT echoed (RejectInvalid* message discipline). OpenID-only: only
    // the OpenID logout path consumes post_logout_redirect_uri, so Validate runs this only over OidConfigs
    // (the property lives on the shared base but no SAML runtime path honours it).

    /// <summary>
    /// Rejects a non-blank <c>post_logout_redirect_uri</c> (#727, SLO-4) that the runtime would silently drop
    /// - i.e. one that is not an absolute http(s) URL at or under this server's canonical base - so the admin
    /// gets feedback instead of a return URL that never fires. OpenID-only (only the OpenID logout path uses
    /// it). The base is taken from the provider's Base URL Override; when no override pins it (the base is
    /// request-derived and unknown at save time) the check is skipped, leaving the runtime allow-list as the
    /// sole check. A blank value is valid (no post-logout redirect). Reuses
    /// <see cref="OidcLogout.IsAllowedPostLogoutRedirect"/>, the one allow-list predicate.
    /// </summary>
    /// <param name="protocol">The protocol label (always "OpenID") echoed in the rejection message.</param>
    /// <param name="provider">The provider name, echoed (line-ending-stripped) in the rejection message.</param>
    /// <param name="baseUrlOverride">The provider's canonical base-URL override; only a valid override makes the base determinate at save time.</param>
    /// <param name="postLogoutRedirectUri">The configured post-logout return URL to check.</param>
    /// <exception cref="ArgumentException">The value is non-blank, the base is determinate, and the value is not at/under it.</exception>
    internal static void ValidatePostLogoutRedirectUri(string protocol, string provider, string? baseUrlOverride, string? postLogoutRedirectUri)
    {
        // Blank means no post-logout redirect - always valid. Without a determinate canonical base the
        // runtime's own allow-list stays the only check (the base is the request Host, unknown here).
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

    // A malformed SAML SLO endpoint (#727, SLO-3c) would be persisted and then silently disable SP-initiated
    // Single Logout (the logout route falls back to local-only), so the admin gets no feedback that the
    // endpoint they configured never fires. Reject it at save. It reuses the SAME absolute-URL predicate the
    // Base URL override validates through (CanonicalBaseUrl.TryNormalize - absolute http(s), no
    // query/fragment/userinfo) and then narrows to https: the redirect carries a signed LogoutRequest naming
    // the subject NameID, so it must not traverse plaintext http. Blank is valid (no SP-initiated SLO). The
    // provider name is line-ending-stripped inline in case it reaches a log through the thrown exception.

    /// <summary>
    /// Rejects a SAML Single-Logout (SLO) endpoint (#727, SLO-3c) that is set but is not a valid absolute
    /// https URL, which would otherwise persist and then silently disable SP-initiated Single Logout (the
    /// logout route falls back to local-only). Reuses <see cref="CanonicalBaseUrl.TryNormalize"/> - the same
    /// absolute-URL predicate the Base URL override validates through - and narrows to https so the signed
    /// LogoutRequest never traverses plaintext http. A blank endpoint is valid (no SP-initiated SLO).
    /// </summary>
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

    // A garbage certificate would be persisted and then throw a CryptographicException on every
    // callback - an unhandled 500 (#206). Same inline line-ending strip as above.

    /// <summary>
    /// Rejects a SAML provider whose signing certificate is set but is not a loadable X.509 certificate,
    /// which would otherwise persist and then throw on every callback (an unhandled 500, #206). A blank
    /// certificate is valid (a half-configured provider).
    /// </summary>
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

    // The optional inbound secondary verification certificate (#491) is the identity provider's PUBLIC
    // certificate - the exact same kind of value as the primary, and rejected the exact same way: a
    // set-but-unloadable value would be persisted and then throw a CryptographicException on every callback
    // (an unhandled 500, #206). Blank is valid (no overlap window configured). Same inline line-ending
    // strip as above.

    /// <summary>
    /// Rejects a SAML provider whose OPTIONAL secondary verification certificate (#491) is set but not
    /// loadable - the identity provider's public certificate for a key-overlap window, validated exactly
    /// like the primary. A blank value is valid (no overlap window configured).
    /// </summary>
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

    // A malformed generic permission-role mapping (#164) would be persisted and then silently grant
    // nothing for the offending entry at login (fail-closed at runtime), leaving the admin's intended
    // permission un-applied with no feedback. Reject it at the door instead: every entry's Permission must
    // name a known Jellyfin PermissionKind that is not one of the dedicated permissions managed by their
    // own fields (administrator, all-folders, Live TV access/management) - those have exactly one
    // authoritative source and may not be double-mapped here. A null entry maps nothing and is tolerated
    // (it grants nothing at runtime). Both the config-page save and the Add endpoints run this. The
    // provider name and the echoed permission are control-stripped in case they reach a log through the
    // thrown exception.

    /// <summary>
    /// Rejects a permission-role mapping (#164) whose Permission is empty, is not a known Jellyfin
    /// PermissionKind, or names one of the dedicated permissions owned by their own fields (administrator,
    /// all-folders, Live TV, account-disable). Such an entry would otherwise persist and silently grant
    /// nothing at login. A null mappings collection or a null entry maps nothing and is tolerated.
    /// </summary>
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

    /// <summary>
    /// Rejects a provisioning template (#1099) that names a permission the plugin may not write, or that
    /// carries a negative bitrate ceiling or session count. All three would be persisted and then silently do
    /// nothing at provisioning, or - for the numbers - be written as a value Jellyfin cannot mean. A null
    /// template, a null permission list or a null entry configures nothing and is tolerated.
    /// </summary>
    /// <param name="protocol">The protocol label ("OpenID" or "SAML") echoed in the rejection message.</param>
    /// <param name="provider">The provider name, echoed (control-stripped) in the rejection message.</param>
    /// <param name="template">The provisioning template to check.</param>
    /// <exception cref="ArgumentException">The template names an invalid or dedicated permission, or carries a negative number.</exception>
    internal static void ValidateProvisioningTemplate(string protocol, string provider, ProvisioningPolicyTemplate? template)
        => ValidateTemplateFields($"{protocol} provider '{(provider ?? string.Empty).ReplaceLineEndings(string.Empty)}'", template);

    // The template checks themselves, over whatever names the template being judged - a provider carrying an
    // inline one, or a named profile several providers share (#1105). One implementation, so a profile cannot
    // carry a permission the inline surface refuses.
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

            // The same classification the role mappings are validated against, so an administrator cannot
            // reach through a template what the mapping surface refuses by name: the dedicated four keep one
            // authoritative source each, and IsDisabled stays barred from every config-driven SSO write.
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

        // Zero is meaningful on both (Jellyfin reads it as "no limit" / "unlimited") and is distinct from
        // unset, which is null; only a negative value is nonsense, and it is refused rather than clamped so
        // the administrator finds out at save instead of wondering later which value took effect.
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

        // The subtitle mode (#1100) is the one playback preference with a closed vocabulary, so it is the one
        // that can be mis-set rather than merely unusual. Refused here rather than clamped: an unknown name
        // that fell through would land on the enum's zero value, which is itself a real mode, so the
        // administrator would get a setting they never chose and nothing would say so. The two language
        // fields are deliberately NOT checked against a list - Jellyfin stores what it is given, and a
        // plugin-side allow-list would drift against it and begin refusing codes Jellyfin accepts.
        // One parse for both sites (#1482), so the validator refuses exactly what the writer would skip:
        // a bare numeral walked through Enum.TryParse here and landed on the account as an undeclared
        // (SubtitlePlaybackMode)57, from a save that reported success.
        if (template.SubtitleMode != null
            && !ProvisioningPolicy.TryParseSubtitleMode(template.SubtitleMode, out _))
        {
            var echoMode = string.Concat(template.SubtitleMode.Where(c => !char.IsControl(c))).ReplaceLineEndings(string.Empty);
            throw new ArgumentException(
                $"{subject} has an invalid provisioning template: it names subtitle mode '{echoMode}', which is not a known Jellyfin SubtitlePlaybackMode. Use the exact enum name (for example Default, Always, OnlyForced, or Smart), or leave it unset to keep Jellyfin's default.",
                nameof(template));
        }

        // The home-screen layout (#1101) has a closed vocabulary too, and one more way to be wrong: a list
        // longer than the web client renders would be persisted in full and shown in part, with nothing
        // saying where the cut fell. Same parse as the writer (HomeScreenPolicy), so the save refuses
        // exactly the list the create arm would otherwise skip.
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

    /// <summary>
    /// Rejects a named provisioning-profile set (#1105) that carries an unnamed or invalid profile. Each
    /// profile is judged by exactly the checks an inline template gets, so a policy cannot reach through a
    /// profile what the inline surface refuses by name - the dedicated permissions and <c>IsDisabled</c>
    /// above all. A configuration that defines no profile configures nothing here and is tolerated.
    /// </summary>
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

    // A provider names the profile its new accounts get (#1105). Two states are refused rather than
    // tolerated, and both would otherwise be silent: a name no profile answers to would persist and then
    // provision NOTHING at the next first login (the resolution is fail-closed and does not fall back), and a
    // provider carrying a name AND an inline template would have two account-creation policies with nothing
    // saying which one won. The rule is cross-object, so it is checked here on the whole incoming
    // configuration rather than on the provider alone - the same reason the SSO-only guard is.

    /// <summary>
    /// Rejects a provider that names a provisioning profile the configuration does not define, or that names
    /// one while also carrying its own inline template (#1105). A provider naming no profile is untouched and
    /// keeps its inline template, which is every provider written before profiles existed.
    /// </summary>
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

    // A provider may also select the profile per login, from the roles the identity provider sent (#1106).
    // The rows are refused for the same two reasons the provider-level name is, and both would otherwise be
    // silent: a row naming no profile is dead configuration that can never select anything, and a row naming
    // a profile the configuration does not define would persist and then provision NOTHING for exactly the
    // group it was written for (the resolution is fail-closed and does not fall back). Cross-object like the
    // reference check above, so it is checked against the whole incoming configuration rather than the
    // provider alone. An unmatched login is not this check's business: it falls to the provider default,
    // which the check above already covers.

    /// <summary>
    /// Rejects a provider whose role-to-provisioning-profile rows (#1106) name no profile, list no roles, or
    /// name a profile the configuration does not define. A provider configuring no rows is untouched, which
    /// is every provider written before this existed.
    /// </summary>
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
            // A null entry selects nothing and is tolerated, the same way every other role map here tolerates
            // one: it contributes nothing at runtime and refusing it would fail a save over a stray element.
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

            // A row listing no role never matches, so it would sit in the map looking like a rule while
            // selecting nothing - the same failure ValidateParentalRatingMappings refuses for the same reason.
            // A row whose every entry is blank is the same state written differently, so both are refused
            // here: the runtime matcher skips blank entries (#935), which would make such a row dead too.
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

    // A parental-rating mapping (#736) with a negative score or no roles would be persisted and then either
    // never apply (no roles) or be a nonsensical ceiling - reject both fail-closed at save so a mis-set is
    // caught before it takes effect. A null entry maps nothing and is tolerated (it contributes nothing at
    // runtime). Both the config-page save and the Add endpoints run this. The provider name is control-
    // stripped in case it reaches a log through the thrown exception.

    /// <summary>
    /// Rejects a parental-rating mapping (#736) with a negative score or with no roles - the former is a
    /// nonsensical ceiling, the latter would never apply. Both are caught at save so a mis-set is found
    /// before it takes effect. A null mappings collection or a null entry maps nothing and is tolerated.
    /// </summary>
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

    /// <summary>
    /// Rejects a SyncPlay-access mapping (#827) whose level is not a declared member of Jellyfin's
    /// <c>SyncPlayUserAccessType</c> (spelled exactly), or which lists no roles - the former would silently
    /// map nothing at login, the latter would never apply. Both are caught at save so a mis-set is found
    /// before it takes effect. A null mappings collection or a null entry maps nothing and is tolerated.
    /// </summary>
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

            // One parse, shared with the login path: the validator refuses exactly what the resolver would
            // skip, so a saved mapping is one the mint can act on rather than one it silently drops.
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

    /// <summary>
    /// Rejects an access-duration mapping (#1146) whose duration is not positive, is longer than
    /// <see cref="GuestAccessDurationRoleMap.MaxDurationHours"/>, or which lists no roles. The upper bound is
    /// a guard rather than a policy: the duration is added to the provisioning instant on the login path and
    /// <see cref="DateTime.AddHours"/> throws past <see cref="DateTime.MaxValue"/>, so an unbounded value
    /// would turn every provisioning login for that provider into a 500. A null mappings collection or a null
    /// entry maps nothing and is tolerated.
    /// </summary>
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

    // A garbage service-provider signing key (#167) would be persisted and then fail every signed
    // challenge. On the config-page save the key is withheld from JSON so it arrives blank (valid) and the
    // stored one is re-injected afterwards; this rejects the case where a non-blank, unloadable key is
    // posted. Same inline line-ending strip as above.

    /// <summary>
    /// Rejects a service-provider request signing key (#167/#491) that is non-blank but not a loadable
    /// unencrypted PKCS#12 blob, which would otherwise persist and fail every signed challenge. A blank
    /// key is valid - a config-page save withholds the key from JSON, so it arrives blank and the stored
    /// one is re-injected afterwards.
    /// </summary>
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
