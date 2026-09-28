// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api.Authz;

/// <summary>Writes a provider's static provisioning template (#1099) onto a brand-new account, once, at creation.</summary>
/// <remarks>
/// It runs on the create arm and nowhere else: every other policy is re-asserted on every login, but a template
/// is a starting point an administrator's later per-user edit has to survive. It writes only what the template
/// names, so an unlisted permission keeps Jellyfin's default. The vocabulary is
/// <see cref="PermissionRolePolicy.Classify"/>'s, so the dedicated permissions keep one source each and
/// <c>IsDisabled</c> stays barred even from a configuration edited by hand around the validator.
/// </remarks>
internal static class ProvisioningPolicy
{
    /// <summary>Resolves which template a provider's brand-new accounts get (#1105, #1106): the profile the login's roles selected, else the named <see cref="PluginConfiguration.ProvisioningProfiles"/> entry the provider points at, else the provider's inline <see cref="ProviderConfigBase.ProvisioningPolicyTemplate"/>.</summary>
    /// <remarks>A name that resolves to nothing writes no policy and does not fall back, because falling back would hand the account the very permission set the administrator replaced; the save path refuses a dangling name, so that state arrives only from a file edited by hand.</remarks>
    /// <param name="configuration">The live plugin configuration, read for its profile set.</param>
    /// <param name="provider">The provider the account is being created for; <see langword="null"/> resolves to no template.</param>
    /// <param name="selectedProfile">The profile name the login's roles selected (#1106), or <see langword="null"/> or blank when the login matched no row; a selected name never falls back to the provider default.</param>
    /// <returns>The template to apply and, when a configured name pointed at no profile, that name, so the caller can log it rather than provisioning silently.</returns>
    internal static ProvisioningTemplateResolution TemplateFor(PluginConfiguration configuration, ProviderConfigBase? provider, string? selectedProfile = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        if (provider is null)
        {
            return default;
        }

        // The role-selected profile (#1106) wins over the provider's own default, because that is the whole
        // point of the row: it names where THIS login goes instead of where the provider sends everyone else.
        // An unmatched login arrives here with null and the resolution below is byte-identical to #1105's.
        var selectedByRole = !string.IsNullOrWhiteSpace(selectedProfile);
        var profile = selectedByRole ? selectedProfile : provider.ProvisioningProfile;
        if (string.IsNullOrWhiteSpace(profile))
        {
            return new ProvisioningTemplateResolution(provider.ProvisioningPolicyTemplate, null, false);
        }

        return configuration.ProvisioningProfiles != null
            && configuration.ProvisioningProfiles.TryGetValue(profile, out var named)
                ? new ProvisioningTemplateResolution(named, null, selectedByRole)
                : new ProvisioningTemplateResolution(null, profile, selectedByRole);
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
        if (TryParseSubtitleMode(template.SubtitleMode, out var subtitleMode))
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

    /// <summary>
    /// Parses a configured subtitle-mode name, refusing anything that is not a DECLARED member of
    /// <see cref="SubtitlePlaybackMode"/> spelled exactly (#1482).
    /// </summary>
    /// <param name="mode">The configured mode name.</param>
    /// <param name="parsed">The parsed mode when the name is a declared member.</param>
    /// <returns>True when the name parsed to a declared member.</returns>
    internal static bool TryParseSubtitleMode(string? mode, out SubtitlePlaybackMode parsed)
    {
        // ignoreCase: false so a mis-cased spelling is reported rather than guessed at. The two checks after
        // it are what a MEASUREMENT added rather than reasoning, and they are the ones the permission
        // entries and SyncPlayAccessPolicy.TryParseAccess already carry: Enum.TryParse also accepts a bare
        // numeral, and the two arms fail differently. "57" parses to an undeclared (SubtitlePlaybackMode)57
        // - IsDefined refuses it. "1" parses to a declared member and IsDefined waves it through, so the
        // name round-trip is what refuses it: a numeral pins the stored preference to the ORDER upstream
        // happens to declare the enum in, and a reorder there would silently change what an administrator
        // configured. A mode is a NAME here, on both sites that read one.
        return Enum.TryParse(mode, ignoreCase: false, out parsed)
            && Enum.IsDefined(parsed)
            && string.Equals(parsed.ToString(), mode, StringComparison.Ordinal);
    }

    /// <summary>What <see cref="TemplateFor(PluginConfiguration, ProviderConfigBase, string)"/> decided: the template to write, and the profile name that pointed at nothing when one did.</summary>
    /// <remarks>The unresolved name is carried out rather than swallowed, because no policy is written either way and the caller, which alone knows this is the create arm, owns the log line that says which name did not resolve.</remarks>
    /// <param name="Template">The template to apply, or <see langword="null"/> when there is none to apply.</param>
    /// <param name="UnresolvedProfile">The configured profile name that resolved to nothing, or <see langword="null"/> when nothing was left unresolved.</param>
    /// <param name="SelectedByRole">Whether the name came from a role row (#1106) rather than from the provider's own default (#1105); false whenever <see cref="UnresolvedProfile"/> is null.</param>
    internal readonly record struct ProvisioningTemplateResolution(
        ProvisioningPolicyTemplate? Template,
        string? UnresolvedProfile,
        bool SelectedByRole);
}
