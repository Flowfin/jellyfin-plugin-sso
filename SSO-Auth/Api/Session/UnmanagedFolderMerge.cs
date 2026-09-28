// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api.Session;

/// <summary>The folder merge behind <see cref="ProviderConfigBase.PreserveUnmanagedFolders"/>: the managed set, and the list a login writes (#1846).</summary>
/// <remarks>
/// A folder is managed when the configuration names it anywhere; comparison is ordinal on item ids. See
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#libraries-a-login-leaves-alone-preserveunmanagedfolders"/>.
/// </remarks>
internal static class UnmanagedFolderMerge
{
    /// <summary>Collects every folder the provider's configuration names, so the mint can tell a folder it owns from one it must leave alone.</summary>
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

    /// <summary>Merges the account's current folders with a login's grants: the unmanaged survive, the managed are replaced by the grants.</summary>
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
