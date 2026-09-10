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

/// <summary>
/// What <see cref="DuplicateInstall.Detect"/> found: whether a second copy of this plugin is loaded into
/// the same server, where the copies are, and where the configuration was put for safekeeping.
/// </summary>
/// <param name="IsDuplicated">Whether more than one copy of this assembly is live in this process.</param>
/// <param name="Locations">The file each loaded copy came from, one entry per copy.</param>
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
/// The DECISION is separated from the loader question on purpose (<see cref="Decide"/> against
/// <see cref="Detect"/>). Which assemblies are loaded cannot be arranged in a test process without the
/// test becoming a test of the loader, so that question is kept to a handful of lines and everything that
/// acts on its answer is exercised directly.
/// </para>
/// </remarks>
internal static class DuplicateInstall
{
    /// <summary>Marks a copy taken because a second install was found, distinct from the #1543 copies.</summary>
    internal const string CopySuffix = ".before-duplicate-";

    /// <summary>
    /// Reports whether a second copy of this plugin is loaded, and preserves the configuration when one is.
    /// </summary>
    /// <param name="configurationFilePath">The host's configuration file path for this plugin.</param>
    /// <param name="nowUtc">The clock, injected so the copy name is testable.</param>
    /// <returns>What was found, and what was done about it.</returns>
    internal static DuplicateInstallState Detect(string? configurationFilePath, DateTime nowUtc)
        => Decide(Locations(), configurationFilePath, nowUtc);

    /// <summary>
    /// Turns a list of loaded copies into the verdict, preserving the configuration when there is more
    /// than one.
    /// </summary>
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

    /// <summary>
    /// Copies the configuration aside, once.
    /// </summary>
    /// <remarks>
    /// An existing copy is handed back rather than joined by a second one, and that is the point rather
    /// than tidiness: a server in this state boots again and again, and by the second boot the file on disk
    /// is already the empty one the host wrote. The oldest copy is the only one worth having. Internal so
    /// the rule can be exercised without arranging a second loaded assembly.
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

            // overwrite: false is the guarantee. Two instances of this plugin in one process reach here
            // within the same second and compose the same name; one wins the copy and the other is refused
            // and answers null, which leaves exactly one copy either way.
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

    /// <summary>
    /// Says what was found, once, at the volume the consequence deserves.
    /// </summary>
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

    /// <summary>
    /// Renders the loaded copies for the one line an operator acts on.
    /// </summary>
    /// <remarks>
    /// Deduplicated HERE and not in the verdict: the count is what decides, and two copies loaded from one
    /// path are still two identities, so collapsing them earlier would hide the fault this exists to
    /// report. A copy with no file behind it is named as such rather than dropped, because a line listing
    /// one path for a fault about two would read as a different fault.
    /// </remarks>
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

    // The one question that can only be asked of the running process. Assembly INSTANCES are what is
    // counted, because the fault is two type identities; a dynamic assembly has no file and is named as an
    // empty entry rather than skipped, so the count still matches the copies. An enumeration that throws -
    // contexts do load while this runs - answers "nothing found" rather than guessing: a false negative
    // leaves the server as it was, and a false positive would refuse every configuration write on a server
    // with nothing wrong with it.
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
