// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.Loader;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>What <see cref="DuplicateInstall.Detect"/> found: whether a second copy is loaded, where the copies are, and where the configuration was kept.</summary>
/// <param name="IsDuplicated">Whether more than one copy of this assembly is live in this process.</param>
/// <param name="Locations">The file each loaded copy came from, one entry per copy.</param>
/// <param name="PreservedCopyPath">Where the configuration was copied, or <see langword="null"/> when it was not.</param>
internal readonly record struct DuplicateInstallState(
    bool IsDuplicated,
    ReadOnlyCollection<string> Locations,
    string? PreservedCopyPath);

/// <summary>Notices that a second copy of this plugin is loaded into the same server, and saves the configuration before that costs it (#1601).</summary>
/// <remarks>
/// A catalog downgrade leaves two copies loaded, and the host then overwrites the configuration with defaults; this
/// runs in the plugin constructor, ahead of that lazy load. See
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Troubleshooting"/>.
/// </remarks>
internal static class DuplicateInstall
{
    /// <summary>Marks a copy taken because a second install was found, distinct from the unreadable-configuration copies.</summary>
    internal const string CopySuffix = ".before-duplicate-";

    /// <summary>Reports whether a second copy of this plugin is loaded, and preserves the configuration when one is.</summary>
    /// <param name="configurationFilePath">The host's configuration file path for this plugin.</param>
    /// <param name="nowUtc">The clock, injected so the copy name is testable.</param>
    /// <returns>What was found, and what was done about it.</returns>
    internal static DuplicateInstallState Detect(string? configurationFilePath, DateTime nowUtc)
        => Decide(Locations(), configurationFilePath, nowUtc);

    /// <summary>Turns a list of loaded copies into the verdict, preserving the configuration when there is more than one.</summary>
    /// <param name="locations">One entry per loaded copy of this assembly; an entry may be empty.</param>
    /// <param name="configurationFilePath">The host's configuration file path for this plugin.</param>
    /// <param name="nowUtc">The clock, which names the copy.</param>
    /// <returns>What was found, and what was done about it.</returns>
    internal static DuplicateInstallState Decide(
        IReadOnlyList<string> locations,
        string? configurationFilePath,
        DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(locations);

        var seen = new ReadOnlyCollection<string>(locations.ToList());
        if (seen.Count < 2)
        {
            return new DuplicateInstallState(false, seen, null);
        }

        return new DuplicateInstallState(true, seen, Preserve(configurationFilePath, nowUtc));
    }

    /// <summary>Copies the configuration aside, once.</summary>
    /// <remarks>An existing copy is handed back rather than joined, because by the second boot the file on disk is already the empty one the host wrote.</remarks>
    /// <param name="configurationFilePath">The file to copy.</param>
    /// <param name="nowUtc">The clock, which names the copy.</param>
    /// <returns>The copy, an earlier copy if one exists, or <see langword="null"/> when none was made.</returns>
    internal static string? Preserve(string? configurationFilePath, DateTime nowUtc)
    {
        if (string.IsNullOrWhiteSpace(configurationFilePath))
        {
            return null;
        }

        try
        {
            var directory = Path.GetDirectoryName(configurationFilePath);
            if (string.IsNullOrEmpty(directory) || !File.Exists(configurationFilePath))
            {
                return null;
            }

            var earlier = Directory
                .EnumerateFiles(directory, Path.GetFileName(configurationFilePath) + CopySuffix + "*")
                .OrderBy(path => path, StringComparer.Ordinal)
                .FirstOrDefault();
            if (earlier is not null)
            {
                return earlier;
            }

            // Two instances compose the same name within a second; overwrite: false lets exactly one win.
            var copy = configurationFilePath + CopySuffix
                + nowUtc.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "Z";
            File.Copy(configurationFilePath, copy, overwrite: false);
            return copy;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>Says what was found, once.</summary>
    /// <param name="state">What <see cref="Detect"/> or <see cref="Decide"/> returned.</param>
    /// <param name="logger">The logger.</param>
    internal static void Announce(DuplicateInstallState state, ILogger logger)
    {
        if (!state.IsDuplicated)
        {
            return;
        }

        try
        {
            SsoAudit.DuplicateInstallFound(logger, Name(state.Locations), state.PreservedCopyPath);
        }
#pragma warning disable CA1031, RCS1075 // an announcement that cannot be made costs the line and never the load
        catch (Exception)
#pragma warning restore CA1031, RCS1075
        {
        }
    }

    /// <summary>Renders the loaded copies for the one line an operator acts on.</summary>
    /// <remarks>Deduplicated here and not in the verdict, because two copies loaded from one path are still two identities.</remarks>
    /// <param name="locations">One entry per loaded copy.</param>
    /// <returns>A single line naming the copies.</returns>
    internal static string Name(IReadOnlyList<string> locations)
    {
        ArgumentNullException.ThrowIfNull(locations);

        return string.Join(
            " AND ",
            locations
                .Select(path => string.IsNullOrEmpty(path) ? "(unnamed)" : path)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(path => path, StringComparer.Ordinal));
    }

    // Assembly instances are counted because the fault is two type identities; an enumeration that throws answers nothing found.
    private static IReadOnlyList<string> Locations()
    {
        try
        {
            var self = typeof(DuplicateInstall).Assembly.GetName().Name;
            return AssemblyLoadContext.All
                .SelectMany(context => context.Assemblies)
                .Where(assembly => string.Equals(assembly.GetName().Name, self, StringComparison.Ordinal))
                .Select(assembly => assembly.IsDynamic ? string.Empty : assembly.Location)
                .ToList();
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException)
        {
            return Array.Empty<string>();
        }
    }
}
