// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api.Session;

/// <summary>
/// The folder merge behind <see cref="ProviderConfigBase.PreserveUnmanagedFolders"/> (#1846): the set of
/// folders a provider's configuration manages, and the list a login writes when the account's current
/// folders are merged with the login's grants instead of being replaced by them.
/// </summary>
/// <remarks>
/// A folder is managed when the configuration names it anywhere: in the provider's static
/// <see cref="ProviderConfigBase.EnabledFolders"/> or in any <see cref="FolderRoleMap.Folders"/>. Managed
/// folders are granted or revoked by the login exactly as before; a folder the configuration has never
/// mentioned is left as the administrator, or a tool holding the admin key, set it on the account. A
/// folder dropped from the configuration stops being managed on the next login and so stays on the
/// account; to revoke without deleting, keep it in a mapping no role carries, which is managed but not
/// granted. Comparison is ordinal: the values are Jellyfin item ids, not names.
/// </remarks>
internal static class UnmanagedFolderMerge
{
    /// <summary>
    /// Collects every folder the provider's configuration names, so the mint can tell a folder it owns
    /// from one it must leave alone.
    /// </summary>
    /// <param name="config">The provider configuration.</param>
    /// <returns>The distinct managed folder ids; empty when the configuration names none.</returns>
    internal static string[] ManagedBy(ProviderConfigBase config)
    {
        var managed = new List<string>();
        if (config.EnabledFolders is not null)
        {
            managed.AddRange(config.EnabledFolders);
        }

        if (config.FolderRoleMapping is not null)
        {
            foreach (var map in config.FolderRoleMapping)
            {
                if (map?.Folders is not null)
                {
                    managed.AddRange(map.Folders);
                }
            }
        }

        return managed.Where(f => !string.IsNullOrEmpty(f)).Distinct(StringComparer.Ordinal).ToArray();
    }

    /// <summary>
    /// Merges the account's current folders with a login's grants: everything the account has that the
    /// configuration does not manage survives, everything managed is replaced by what the login grants.
    /// </summary>
    /// <param name="current">The folders the account holds before the login.</param>
    /// <param name="managed">The folders the provider's configuration manages (<see cref="ManagedBy"/>).</param>
    /// <param name="granted">The folders this login grants.</param>
    /// <returns>The list to write: the unmanaged survivors first, then the grants, each folder once.</returns>
    internal static string[] Apply(IEnumerable<string>? current, IEnumerable<string> managed, IEnumerable<string> granted)
    {
        var managedSet = new HashSet<string>(managed, StringComparer.Ordinal);
        return (current ?? Array.Empty<string>())
            .Where(f => !string.IsNullOrEmpty(f) && !managedSet.Contains(f))
            .Concat(granted)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }
}
