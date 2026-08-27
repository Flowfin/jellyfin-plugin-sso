// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api.Authz;

/// <summary>
/// Writes a provider's static provisioning template (#1099) onto a BRAND-NEW account, once, at creation.
/// </summary>
/// <remarks>
/// <para>
/// The one thing to hold on to is that this runs on the create arm and nowhere else. Every other policy the
/// plugin writes - <see cref="PermissionRolePolicy"/>, <see cref="RolePrivilegeMapper"/>,
/// <see cref="ParentalRatingPolicy"/> - is authoritative and re-asserted on every login, because a role the
/// identity provider withdrew has to withdraw its permission. A template is the opposite claim: it is a
/// starting point, so an administrator's later per-user edit has to survive. Re-applying it would undo that
/// edit on the user's next login with nothing in the log to explain it.
/// </para>
/// <para>
/// It writes only what the template NAMES. An unlisted permission and a null numeric field are left
/// untouched, so Jellyfin's own new-user default governs them and a provider that carries no template
/// provisions byte-identically to before this existed.
/// </para>
/// <para>
/// The permission vocabulary is <see cref="PermissionRolePolicy.Classify"/>'s, not a second one, so the
/// dedicated permissions (administrator, all-folders, Live TV) keep exactly one authoritative source each
/// and <c>IsDisabled</c> stays barred from every SSO-config-driven write. Save-time validation refuses those
/// names outright; this skips them again at write time so a config file edited by hand around the validator
/// still cannot use a template to grant administrator or to disable every account a provider creates.
/// </para>
/// </remarks>
internal static class ProvisioningPolicy
{
    /// <summary>
    /// Resolves which template a provider's brand-new accounts get, in one documented order (#1105, #1106):
    /// the profile the login's roles selected, else the named
    /// <see cref="PluginConfiguration.ProvisioningProfiles"/> entry the provider points at, else the
    /// provider's own inline <see cref="ProviderConfigBase.ProvisioningPolicyTemplate"/>.
    /// </summary>
    /// <remarks>
    /// A name that resolves to nothing writes NO policy, and deliberately does not fall back - not to the
    /// inline template, and not to the provider default when the name came from a role row. The save path
    /// refuses a dangling name on both surfaces, and refuses a provider carrying a name AND an inline
    /// template (<see cref="ProviderConfigValidator.ValidateProvisioningProfiles"/>), so neither state
    /// arrives through a validated write; what is left is a configuration file edited by hand around the
    /// validator, and there the fail-closed answer is to write nothing. Falling back would hand the new
    /// account the very permission set the administrator replaced when they pointed the provider elsewhere -
    /// and on a role row it would do it to precisely the group that was singled out for a narrower one.
    /// </remarks>
    /// <param name="configuration">The live plugin configuration, read for its profile set.</param>
    /// <param name="provider">The provider the account is being created for; <see langword="null"/> resolves to no template.</param>
    /// <param name="selectedProfile">
    /// The profile name the login's roles selected (#1106), or <see langword="null"/>/blank when the login
    /// matched no row. A selected name is authoritative: it never falls back to the provider's own default,
    /// for the reason in the remarks.
    /// </param>
    /// <returns>The template to apply, or <see langword="null"/> when the provider configures none.</returns>
    internal static ProvisioningPolicyTemplate? TemplateFor(PluginConfiguration configuration, ProviderConfigBase? provider, string? selectedProfile = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        if (provider is null)
        {
            return null;
        }

        // The role-selected profile (#1106) wins over the provider's own default, because that is the whole
        // point of the row: it names where THIS login goes instead of where the provider sends everyone else.
        // An unmatched login arrives here with null and the resolution below is byte-identical to #1105's.
        var profile = string.IsNullOrWhiteSpace(selectedProfile) ? provider.ProvisioningProfile : selectedProfile;
        if (string.IsNullOrWhiteSpace(profile))
        {
            return provider.ProvisioningPolicyTemplate;
        }

        return configuration.ProvisioningProfiles != null
            && configuration.ProvisioningProfiles.TryGetValue(profile, out var named)
                ? named
                : null;
    }

    /// <summary>
    /// Applies the provider's template to a freshly created user, in memory. The caller persists.
    /// </summary>
    /// <param name="user">The brand-new Jellyfin account.</param>
    /// <param name="template">The provider's template; <see langword="null"/> writes nothing at all.</param>
    /// <returns>The number of fields written, so the caller can stay silent when there was nothing to do.</returns>
    internal static int ApplyAtProvisioning(User user, ProvisioningPolicyTemplate? template)
    {
        ArgumentNullException.ThrowIfNull(user);

        if (template is null)
        {
            return 0;
        }

        var written = 0;
        foreach (var entry in template.Permissions ?? new List<ProvisionedPermissionEntry>())
        {
            // A null entry (a hand-edited config, a partial post) names no permission and writes nothing,
            // the same tolerance the role mappings give it. The resolver is the role mapping's own, so
            // "which names are writable" has one implementation and cannot come apart between the two.
            if (entry is not null && PermissionRolePolicy.TryResolvePermission(entry.Permission, out var kind))
            {
                user.SetPermission(kind, entry.Granted);
                written++;
            }
        }

        if (template.RemoteClientBitrateLimit is { } bitrate)
        {
            user.RemoteClientBitrateLimit = bitrate;
            written++;
        }

        if (template.MaxActiveSessions is { } sessions)
        {
            user.MaxActiveSessions = sessions;
            written++;
        }

        // The playback preferences (#1100). These are columns on the account itself, alongside the two
        // numbers above, so they are written here on the same create arm rather than through a second
        // persistence call - which also means they inherit "never re-applied" for free instead of needing
        // their own guard. They grant nothing: no field below can widen an account's access.
        if (template.AudioLanguagePreference is { } audioLanguage)
        {
            user.AudioLanguagePreference = audioLanguage;
            written++;
        }

        if (template.SubtitleLanguagePreference is { } subtitleLanguage)
        {
            user.SubtitleLanguagePreference = subtitleLanguage;
            written++;
        }

        // Parsed rather than cast, and skipped when it does not parse. Save-time validation already refuses
        // an unknown name; this is the same second refusal the permission entries get above, for the same
        // reason - a config file edited by hand around the validator still reaches this writer. Falling back
        // to the enum's zero value would quietly set a mode nobody asked for.
        if (Enum.TryParse<SubtitlePlaybackMode>(template.SubtitleMode, ignoreCase: false, out var subtitleMode))
        {
            user.SubtitleMode = subtitleMode;
            written++;
        }

        if (template.PlayDefaultAudioTrack is { } playDefaultAudioTrack)
        {
            user.PlayDefaultAudioTrack = playDefaultAudioTrack;
            written++;
        }

        if (template.RememberAudioSelections is { } rememberAudio)
        {
            user.RememberAudioSelections = rememberAudio;
            written++;
        }

        if (template.RememberSubtitleSelections is { } rememberSubtitles)
        {
            user.RememberSubtitleSelections = rememberSubtitles;
            written++;
        }

        return written;
    }
}
