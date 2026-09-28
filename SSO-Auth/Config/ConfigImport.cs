// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>Applies a redacted export document onto the live configuration as a merge, through the same validation and preservation every save uses (#161).</summary>
/// <remarks>
/// The whole document is validated before anything is mutated, and a provider is merged through
/// <see cref="ServerManagedFields"/>, so a blank secret keeps the stored one and a repoint drops the links. See
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#configuration-export--import-admin"/>.
/// </remarks>
internal static class ConfigImport
{
    /// <summary>Validates and merges the export document into <paramref name="live"/>, throwing before any mutation on a document it cannot apply.</summary>
    /// <param name="live">The live configuration to merge into (mutated in place).</param>
    /// <param name="document">The import document.</param>
    /// <param name="resolveBreakGlass">Resolves a username to its <see cref="BreakGlassAdminState"/> for the SSO-only guard; null makes the guard fail closed (#165).</param>
    /// <exception cref="ArgumentException">The document is unsupported, empty, carries an invalid provider, or asserts SSO-only with no surviving admin login path.</exception>
    internal static void Apply(PluginConfiguration live, ConfigExportDocument document, Func<string, BreakGlassAdminState>? resolveBreakGlass = null)
    {
        ArgumentNullException.ThrowIfNull(live);
        ArgumentNullException.ThrowIfNull(document);

        if (document.FormatVersion != ConfigExport.FormatVersion)
        {
            throw new ArgumentException(
                $"Unsupported configuration export format version {document.FormatVersion}; this plugin imports version {ConfigExport.FormatVersion}.");
        }

        var imported = document.Configuration
            ?? throw new ArgumentException("The configuration import document has no configuration payload.");

        // The SSO-only assertion is validated fail-closed but never applied; the mode is enabled only through the elevated endpoints (#165).
        if (imported.DisablePasswordLogin)
        {
            var breakGlass = imported.BreakGlassAdminUsername ?? string.Empty;
            SsoOnlyLoginGuard.AssertCanActivate(breakGlass, resolveBreakGlass?.Invoke(breakGlass) ?? default);
        }

        ProviderConfigValidator.Validate(imported, live);

        // Profiles first, so the target never holds a provider naming a profile it has not got (#1105).
        MergeProfiles(live, imported);

        // The rate-limit scalars are not imported: a scalar has no blank-means-keep signal, so a partial document could silently disable the limiter.
        MergeProviders(live.OidConfigs, imported.OidConfigs, ServerManagedFields.Preserve);
        MergeProviders(live.SamlConfigs, imported.SamlConfigs, ServerManagedFields.Preserve);
    }

    // An upsert: a provider only the target holds is left alone, and a null-valued entry is skipped (#538).
    private static void MergeProviders<T>(
        SerializableDictionary<string, T> live,
        SerializableDictionary<string, T> imported,
        Action<T, T> preserve)
        where T : ProviderConfigBase
    {
        if (imported is null)
        {
            return;
        }

        foreach (var kvp in imported)
        {
            if (kvp.Value is null)
            {
                continue;
            }

            if (live.TryGetValue(kvp.Key, out var existing) && existing is not null)
            {
                preserve(kvp.Value, existing);

                // NewPath is runtime state meaningless across instances, so the target keeps its own.
                kvp.Value.NewPath = existing.NewPath;
            }

            live[kvp.Key] = kvp.Value;
        }
    }

    // An upsert, with a null-valued entry skipped rather than stored as a profile that resolves to no policy (#538).
    private static void MergeProfiles(PluginConfiguration live, PluginConfiguration imported)
    {
        if (imported.ProvisioningProfiles is null)
        {
            return;
        }

        live.ProvisioningProfiles ??= new SerializableDictionary<string, ProvisioningPolicyTemplate>();
        foreach (var kvp in imported.ProvisioningProfiles)
        {
            if (kvp.Value is null)
            {
                continue;
            }

            live.ProvisioningProfiles[kvp.Key] = kvp.Value;
        }
    }
}
