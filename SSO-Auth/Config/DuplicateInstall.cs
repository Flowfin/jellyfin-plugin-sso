// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// What <see cref="DuplicateInstall.Detect"/> found: whether a second copy of this plugin is loaded into
/// the same server, where the copies are, and where the configuration was put for safekeeping.
/// </summary>
/// <param name="IsDuplicated">Whether more than one copy of this assembly is live in this process.</param>
/// <param name="Locations">The file each loaded copy came from, in order, for the operator to act on.</param>
/// <param name="PreservedCopyPath">Where the configuration was copied, or <see langword="null"/> when it was not.</param>
internal readonly record struct DuplicateInstallState(
    bool IsDuplicated,
    ReadOnlyCollection<string> Locations,
    string? PreservedCopyPath);

/// <summary>
/// Notices that a second copy of this plugin is loaded into the same server, and saves the configuration
/// before that costs it (#1601).
/// </summary>
/// <remarks>
/// <para>
/// A downgrade through the plugin catalog does not replace the installed version. It adds a second
/// directory beside it, and Jellyfin 12.0 loads BOTH at the next start. Two copies of this assembly are
/// then live at once, and three things follow. Every route this plugin registers matches twice, so the
/// admin surface answers <c>AmbiguousMatchException</c> and shows nothing. The configuration type exists
/// twice, so a value produced by one copy cannot be cast to the other and the round-trip fails with
/// <c>InvalidCastException: PluginConfiguration cannot be cast to PluginConfiguration</c>. And the host,
/// unable to read a configuration back, hands out defaults and writes them over the file.
/// </para>
/// <para>
/// Measured on a live Jellyfin 12.0.0 with the published packages, downgrading and then going back up:
/// <c>SSO-Auth.xml</c> went 3576 bytes with a provider, to 601 bytes with none, to 38 bytes. The provider
/// data is destroyed on disk, and the copy the unreadable-configuration screen keeps (#1543) is taken
/// after the overwrite, because the file was readable at the moment it was read - it was simply replaced
/// afterwards.
/// </para>
/// <para>
/// Nothing in this plugin can stop the host loading two copies of it, and nothing here can intercept the
/// host's own write. What it CAN do is be early: this runs in the plugin constructor, before anything
/// touches <c>Configuration</c> and therefore before the lazy load that ends in the overwrite. So the copy
/// it takes is the last one made while the file still held the operator's providers.
/// </para>
/// <para>
/// It preserves at most ONE copy per configuration file, and the first one wins. A server left in this
/// state boots repeatedly, and each later boot would copy a file that is already empty; keeping the oldest
/// keeps the only one worth having.
/// </para>
/// </remarks>
internal static class DuplicateInstall
{
    /// <summary>Marks a copy taken because a second install was found, distinct from the #1543 copies.</summary>
    internal const string CopySuffix = ".before-duplicate-";

    // Bounded like the unreadable-configuration walk beside it: a directory holding this many taken names
    // already is one nobody is reading, and walking further is not the way to find that out.
    private const int MostCopyNamesToTry = 64;

    /// <summary>
    /// Reports whether a second copy of this plugin is loaded, and preserves the configuration when one is.
    /// </summary>
    /// <param name="configurationFilePath">The host's configuration file path for this plugin.</param>
    /// <param name="nowUtc">The clock, injected so the copy name is testable.</param>
    /// <returns>What was found, and what was done about it.</returns>
    internal static DuplicateInstallState Detect(string? configurationFilePath, DateTime nowUtc)
    {
        var locations = Locations();
        if (locations.Count < 2)
        {
            return new DuplicateInstallState(false, locations, null);
        }

        return new DuplicateInstallState(true, locations, Preserve(configurationFilePath, nowUtc));
    }

    /// <summary>
    /// The file each loaded copy of this assembly came from.
    /// </summary>
    /// <remarks>
    /// Counts ASSEMBLY INSTANCES rather than distinct paths, because the fault is two identities of the
    /// same types and two copies loaded from one path would still be two identities. The paths are then
    /// deduplicated for the log line only, where they are an instruction to the operator rather than the
    /// count. An enumeration that throws - contexts do load while this runs - answers "nothing found"
    /// rather than a guess: a false negative leaves the server exactly as it was, and a false positive
    /// would refuse every configuration write on a server with nothing wrong with it.
    /// </remarks>
    /// <returns>The distinct locations, empty when this could not be determined.</returns>
    private static ReadOnlyCollection<string> Locations()
    {
        try
        {
            var self = typeof(DuplicateInstall).Assembly.GetName().Name;
            var copies = AssemblyLoadContext.All
                .SelectMany(context => context.Assemblies)
                .Where(assembly => string.Equals(assembly.GetName().Name, self, StringComparison.Ordinal))
                .ToList();

            if (copies.Count < 2)
            {
                return new ReadOnlyCollection<string>(Array.Empty<string>());
            }

            var paths = copies
                .Select(Where)
                .Where(path => !string.IsNullOrEmpty(path))
                .Distinct(StringComparer.Ordinal)
                .OrderBy(path => path, StringComparer.Ordinal)
                .ToList();

            // The count is what decides, so it must survive locations that could not be named: a copy with
            // no file behind it still carries its own types. Two unnamed copies report as two empty slots
            // rather than as none.
            while (paths.Count < copies.Count)
            {
                paths.Add(string.Empty);
            }

            return new ReadOnlyCollection<string>(paths);
        }
        catch (Exception ex) when (ex is InvalidOperationException or ReflectionTypeLoadException or NotSupportedException)
        {
            return new ReadOnlyCollection<string>(Array.Empty<string>());
        }
    }

    private static string Where(Assembly assembly)
    {
        try
        {
            return assembly.Location;
        }
        catch (Exception ex) when (ex is NotSupportedException or InvalidOperationException)
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Copies the configuration aside, once.
    /// </summary>
    /// <remarks>
    /// <c>File.Copy</c> with <c>overwrite: false</c> is the whole guarantee: a name already taken is never
    /// written over, so a copy from an earlier boot - the one taken while the file still held providers -
    /// cannot be replaced by this boot's emptier version. Internal so the copy rule can be tested on its
    /// own: the branch that calls it needs a second copy of this assembly loaded, which a test process
    /// cannot arrange without becoming a test of the loader instead of a test of the rule.
    /// </remarks>
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
            if (!File.Exists(configurationFilePath))
            {
                return null;
            }

            if (AlreadyPreserved(configurationFilePath) is { } existing)
            {
                return existing;
            }

            var copy = FreeCopyName(configurationFilePath, nowUtc);
            File.Copy(configurationFilePath, copy, overwrite: false);
            return copy;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    private static string? AlreadyPreserved(string configurationFilePath)
    {
        var directory = Path.GetDirectoryName(configurationFilePath);
        if (string.IsNullOrEmpty(directory))
        {
            return null;
        }

        return Directory
            .EnumerateFiles(directory, Path.GetFileName(configurationFilePath) + CopySuffix + "*")
            .OrderBy(path => path, StringComparer.Ordinal)
            .FirstOrDefault();
    }

    private static string FreeCopyName(string configurationFilePath, DateTime nowUtc)
    {
        var stem = configurationFilePath + CopySuffix + nowUtc.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "Z";
        if (!File.Exists(stem))
        {
            return stem;
        }

        for (var attempt = 1; attempt < MostCopyNamesToTry; attempt++)
        {
            var candidate = stem + "-" + attempt.ToString(CultureInfo.InvariantCulture);
            if (!File.Exists(candidate))
            {
                return candidate;
            }
        }

        // Every name walked is taken. Hand back the stamped one and let File.Copy refuse it, so the failure
        // is reported by the code that reports the other copy failures rather than invented here.
        return stem;
    }

    /// <summary>
    /// Says what was found, once, at the volume the consequence deserves.
    /// </summary>
    /// <param name="state">What <see cref="Detect"/> returned.</param>
    /// <param name="logger">The logger.</param>
    internal static void Announce(DuplicateInstallState state, ILogger logger)
    {
        if (!state.IsDuplicated)
        {
            return;
        }

        try
        {
            SsoAudit.DuplicateInstallFound(
                logger,
                string.Join(" AND ", state.Locations.Select(path => string.IsNullOrEmpty(path) ? "(unnamed)" : path)),
                state.PreservedCopyPath);
        }
#pragma warning disable CA1031, RCS1075 // an announcement that cannot be made costs the line and never the load
        catch (Exception)
#pragma warning restore CA1031, RCS1075
        {
        }
    }
}
