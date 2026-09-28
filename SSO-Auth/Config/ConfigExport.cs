// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>Builds the redacted, importable configuration export document (#161).</summary>
/// <remarks>
/// The redaction is the JSON boundary's own, so the snapshot is redacted by construction. See
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#the-export-is-redacted---secrets-never-leave-the-server"/>.
/// </remarks>
internal static class ConfigExport
{
    /// <summary>The current export document format version; the import rejects any other.</summary>
    internal const int FormatVersion = 1;

    /// <summary>Builds the export document from the live configuration; call it under the config lock.</summary>
    /// <param name="live">The live plugin configuration to snapshot.</param>
    /// <returns>The redacted export document.</returns>
    internal static ConfigExportDocument Build(PluginConfiguration live)
    {
        ArgumentNullException.ThrowIfNull(live);
        return new ConfigExportDocument
        {
            FormatVersion = FormatVersion,
            Configuration = Snapshot(live),
        };
    }

    // Shallow copies: the provider objects are shared, and the only in-place write on the login path is a scalar flip (#157).
    private static PluginConfiguration Snapshot(PluginConfiguration live) => new()
    {
        EnableRateLimit = live.EnableRateLimit,
        RateLimitMaxAttempts = live.RateLimitMaxAttempts,
        RateLimitWindowSeconds = live.RateLimitWindowSeconds,
        OidConfigs = ShallowCopy(live.OidConfigs),
        SamlConfigs = ShallowCopy(live.SamlConfigs),

        // The profiles travel with the providers that point at them, or the import would refuse the document (#1105).
        ProvisioningProfiles = ShallowCopy(live.ProvisioningProfiles),
    };

    private static SerializableDictionary<string, T> ShallowCopy<T>(SerializableDictionary<string, T> source)
    {
        var copy = new SerializableDictionary<string, T>();
        if (source is not null)
        {
            foreach (var kvp in source)
            {
                copy[kvp.Key] = kvp.Value;
            }
        }

        return copy;
    }
}
