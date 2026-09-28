// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Globalization;
using System.IO;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using MediaBrowser.Model.Serialization;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>What one comparison of the damaged configuration against a candidate copy came back with; the two ways of not knowing are answered differently (#1543).</summary>
internal enum Comparison
{
    /// <summary>The candidate holds exactly the damaged file's bytes.</summary>
    Same,

    /// <summary>It does not: a different length, different bytes, or a link rather than a copy.</summary>
    Different,

    /// <summary>The damaged file could not be read, so no copy could be written either and a standing record is kept.</summary>
    DamageUnreadable,

    /// <summary>The candidate could not be read, so a copy is attempted and a record naming this candidate is the last resort.</summary>
    CandidateUnreadable,
}

/// <summary>What one read of the stored file said: whether it came back, and whether it holds a configuration somebody put there (#1543).</summary>
/// <param name="Readable">Whether the file yielded a configuration.</param>
/// <param name="HoldsAProvider">Whether that configuration holds at least one provider, which is what makes it somebody's rather than a default.</param>
/// <param name="Judged">Whether the read happened at all; a third value, because an undecidable read must not read as the host's empty default.</param>
internal readonly record struct Restored(bool Readable, bool HoldsAProvider, bool Judged)
{
    /// <summary>Gets the answer for a file that is not there: a first start, judged by the carried-over arm like any file holding no provider.</summary>
    internal static Restored Nothing => new(true, false, true);

    /// <summary>Gets the answer for a read that could not be made at all, which decides nothing.</summary>
    internal static Restored Unknown => new(false, false, false);

    /// <summary>Gets the answer for a file that is there and does not come back.</summary>
    internal static Restored Damaged => new(false, false, true);
}

/// <summary>Whether the stored configuration could be read at start, and where the damaged file was kept (#1543).</summary>
/// <remarks>The default value is the healthy one, so a caller that forgets to assign this serves logins.</remarks>
/// <param name="IsUnreadable">Whether the stored configuration failed to deserialize, so the host is about to serve defaults over it.</param>
/// <param name="PreservedCopyPath">Where the damaged file was copied, or null when no copy is known; null does not weaken <paramref name="IsUnreadable"/>.</param>
internal readonly record struct UnreadableConfigurationState(bool IsUnreadable, string? PreservedCopyPath);

/// <summary>Keeps the evidence when the configuration file cannot be read, and says so (#1543).</summary>
/// <remarks>
/// The host replaces an unreadable configuration with defaults on its first lazy read, so this runs in the plugin
/// constructor, ahead of it, and reads the file itself. See
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Troubleshooting"/>.
/// </remarks>
internal static class UnreadableConfiguration
{
    /// <summary>The suffix a preserved copy is named with, before its UTC timestamp.</summary>
    internal const string CopySuffix = ".unreadable-";

    /// <summary>The suffix of the marker that keeps the state across a restart; its own file, because the configuration is what was lost.</summary>
    internal const string MarkerSuffix = ".unreadable";

    // The two records under the marker's sentence, so the next boot can tell this incident from a new one.
    private const string IncidentPrefix = "Damaged-file: ";
    private const string CopyPrefix = "Kept-copy: ";

    // A bound rather than a capacity: reaching it means a clock that does not advance.
    private const int CopyNameLimit = 100;

    // Small on purpose, so the comparison is bounded by nothing the host has to allocate in one block.
    private const int CompareBufferBytes = 64 * 1024;

    /// <summary>Screens the stored configuration before anything reads it, keeps the evidence when it cannot be read, and answers whether this server is about to serve defaults.</summary>
    /// <remarks>
    /// A file that could not be read at all decides nothing, because the host's own read a moment later may succeed;
    /// a marker beside the copy makes the refusal survive the restart that replaces the damaged file with a default.
    /// </remarks>
    /// <param name="configurationFilePath">The host's configuration file path for this plugin.</param>
    /// <param name="serializer">The host's XML serializer, asked the same question the host will ask it.</param>
    /// <param name="logger">The logger the refusal is announced on.</param>
    /// <param name="nowUtc">The instant a copy is named after.</param>
    /// <returns>The screened state: unreadable or not, and where the damaged file was kept.</returns>
    internal static UnreadableConfigurationState Preserve(string? configurationFilePath, IXmlSerializer serializer, ILogger logger, DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(serializer);

        if (string.IsNullOrWhiteSpace(configurationFilePath))
        {
            return default;
        }

        // No file at all is a first start, not damage.
        var stored = File.Exists(configurationFilePath) ? ReadsBack(configurationFilePath, serializer, logger) : Restored.Nothing;

        // A read that did not happen decides nothing, the marker arm included, or a momentary lock on a repaired server would refuse for the life of the process.
        if (!stored.Judged)
        {
            return default;
        }

        if (stored.Readable)
        {
            return CarriedOver(configurationFilePath, stored.HoldsAProvider, logger);
        }

        // One copy per incident, told apart by the damaged file's own identity rather than by the marker's existence.
        var incident = IncidentOf(configurationFilePath);
        var carried = ReadMarker(configurationFilePath);

        var sameIncident = incident is not null
            && carried?.Incident is { } previous
            && string.Equals(previous, incident, StringComparison.Ordinal);
        // The record inherits nothing from another incident, and it may not outrank the bytes: an existing copy an operator saved over is refuted by its length.
        var recordedCopy = sameIncident ? carried?.Kept : null;
        // No record at all is answered as Different, which reuses nothing and falls back to nothing.
        var verdict = recordedCopy is null ? Comparison.Different : Compare(configurationFilePath, recordedCopy);
        var preserved = verdict is Comparison.Same or Comparison.DamageUnreadable
            ? recordedCopy
            : Copy(configurationFilePath, nowUtc, logger) ?? (verdict is Comparison.CandidateUnreadable ? recordedCopy : null);
        Mark(configurationFilePath, incident, preserved, logger);
        Announce(() => SsoAudit.UnreadableConfigurationFound(logger, configurationFilePath, preserved));
        return new UnreadableConfigurationState(true, preserved);
    }

    /// <summary>Removes the marker once a configuration has been supplied; the preserved copies stay, because they are the evidence (#1543).</summary>
    /// <param name="configurationFilePath">The host's configuration file path for this plugin.</param>
    /// <param name="logger">The logger a failure to remove it is reported on.</param>
    internal static void ClearMarker(string? configurationFilePath, ILogger logger)
    {
        if (string.IsNullOrWhiteSpace(configurationFilePath))
        {
            return;
        }

        try
        {
            File.Delete(configurationFilePath + MarkerSuffix);
        }
#pragma warning disable CA1031 // a marker that cannot be removed must not turn a successful save into a failure
        catch (Exception ex)
#pragma warning restore CA1031
        {
            Announce(() => SsoAudit.UnreadableConfigurationMarkerNotCleared(logger, configurationFilePath + MarkerSuffix, ex));
        }
    }

    // A file that merely parses is the host's default; one that holds a provider is a repair this plugin never saw, and clears the marker.
    private static UnreadableConfigurationState CarriedOver(string configurationFilePath, bool holdsAProvider, ILogger logger)
    {
        if (!MarkerExists(configurationFilePath))
        {
            return default;
        }

        if (holdsAProvider)
        {
            ClearMarker(configurationFilePath, logger);
            Announce(() => SsoAudit.UnreadableConfigurationRepairedOnDisk(logger, configurationFilePath));
            return default;
        }

        // The marker's own record and nothing else; a directory search would name another incident's copy as this one's.
        var preserved = ReadMarker(configurationFilePath)?.Kept;
        Announce(() => SsoAudit.UnreadableConfigurationStillUnrepaired(logger, configurationFilePath, preserved));
        return new UnreadableConfigurationState(true, preserved);
    }

    // Copies the damaged file aside, never over an existing name; the boot-loop bound is the bytes already beside it, not the marker.
    private static string? Copy(string configurationFilePath, DateTime nowUtc, ILogger logger)
    {
        if (AlreadyCopied(configurationFilePath) is { } existing)
        {
            return existing;
        }

        var copy = FreeCopyName(configurationFilePath, nowUtc);
        try
        {
            File.Copy(configurationFilePath, copy, overwrite: false);
            return copy;
        }
#pragma warning disable CA1031 // the state is unreadable whether or not the copy succeeded, and saying so is what matters
        catch (Exception ex)
#pragma warning restore CA1031
        {
            Announce(() => SsoAudit.UnreadableConfigurationNotPreserved(logger, copy, ex));
            return null;
        }
    }

    // An occupied name belongs to another fault, so the name is disambiguated rather than the copy dropped; past the bound File.Copy refuses.
    private static string FreeCopyName(string configurationFilePath, DateTime nowUtc)
    {
        var stem = configurationFilePath + CopySuffix + nowUtc.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "Z";
        var name = stem;
        for (var attempt = 1; attempt <= CopyNameLimit && File.Exists(name); attempt++)
        {
            name = string.Create(CultureInfo.InvariantCulture, $"{stem}.{attempt}");
        }

        return name;
    }

    // Streamed, lengths first, and a link is not a copy: a link back at the configuration would compare equal and suppress the copy.
    private static Comparison Compare(string configurationFilePath, string candidate)
    {
        // Which side failed is the whole of the third answer, because only the damaged side's fault also stops a copy.
        var damagedSide = false;
        try
        {
            var kept = new FileInfo(candidate);
            if (kept.LinkTarget is not null)
            {
                return Comparison.Different;
            }

            damagedSide = true;
            var damagedLength = new FileInfo(configurationFilePath).Length;
            damagedSide = false;
            if (kept.Length != damagedLength)
            {
                return Comparison.Different;
            }

            damagedSide = true;
            using var damaged = File.OpenRead(configurationFilePath);
            damagedSide = false;
            using var copy = File.OpenRead(candidate);

            var fromDamaged = new byte[CompareBufferBytes];
            var fromCopy = new byte[CompareBufferBytes];
            while (true)
            {
                damagedSide = true;
                var read = damaged.ReadAtLeast(fromDamaged, CompareBufferBytes, throwOnEndOfStream: false);
                damagedSide = false;
                if (read == 0)
                {
                    return Comparison.Same;
                }

                copy.ReadExactly(fromCopy.AsSpan(0, read));
                if (!fromDamaged.AsSpan(0, read).SequenceEqual(fromCopy.AsSpan(0, read)))
                {
                    return Comparison.Different;
                }
            }
        }
#pragma warning disable CA1031 // which file could not be read is the answer; neither failure is a decision about the bytes
        catch (Exception)
#pragma warning restore CA1031
        {
            return damagedSide ? Comparison.DamageUnreadable : Comparison.CandidateUnreadable;
        }
    }

    // A logger that throws in the constructor would turn a decided refusal into a fail-open, so the announcement is contained.
    private static void Announce(Action say)
    {
        try
        {
            say();
        }
#pragma warning disable CA1031, RCS1075 // an announcement that cannot be made costs the line and never the decision
        catch (Exception)
#pragma warning restore CA1031, RCS1075
        {
        }
    }

    // Length and last-write instant: a boot loop meets the same pair and a new incident does not.
    private static string? IncidentOf(string configurationFilePath)
    {
        try
        {
            var file = new FileInfo(configurationFilePath);
            return string.Create(CultureInfo.InvariantCulture, $"{file.Length}:{file.LastWriteTimeUtc.Ticks}");
        }
#pragma warning disable CA1031 // an identity that cannot be read is answered as a new incident, which costs a copy and never the evidence
        catch (Exception)
#pragma warning restore CA1031
        {
            return null;
        }
    }

    private static Marker? ReadMarker(string configurationFilePath)
    {
        try
        {
            if (!File.Exists(configurationFilePath + MarkerSuffix))
            {
                return null;
            }

            string? incident = null;
            string? copy = null;
            foreach (var line in File.ReadAllLines(configurationFilePath + MarkerSuffix))
            {
                if (line.StartsWith(IncidentPrefix, StringComparison.Ordinal))
                {
                    incident = line[IncidentPrefix.Length..];
                }
                else if (line.StartsWith(CopyPrefix, StringComparison.Ordinal) && line.Length > CopyPrefix.Length)
                {
                    copy = line[CopyPrefix.Length..];
                }
            }

            return new Marker(incident, copy);
        }
#pragma warning disable CA1031 // a marker that cannot be read is the same answer as one that records nothing
        catch (Exception)
#pragma warning restore CA1031
        {
            return null;
        }
    }

    // A copy already beside the configuration holding exactly the damaged bytes, or null; not being able to look costs a copy, never the evidence.
    private static string? AlreadyCopied(string configurationFilePath)
    {
        string[] candidates;
        try
        {
            var directory = Path.GetDirectoryName(configurationFilePath);
            if (string.IsNullOrEmpty(directory))
            {
                return null;
            }

            candidates = Directory.GetFiles(directory, Path.GetFileName(configurationFilePath) + CopySuffix + "*");
        }
#pragma warning disable CA1031 // not being able to look at all is the same answer as there being no copy, which costs one copy
        catch (Exception)
#pragma warning restore CA1031
        {
            return null;
        }

        foreach (var candidate in candidates)
        {
            // Judged per candidate, so one unreadable file does not abandon the walk and reopen the copy loop.
            if (Compare(configurationFilePath, candidate) is Comparison.Same)
            {
                return candidate;
            }
        }

        return null;
    }

    // The sentence first for the operator who opens the file, the two records below it for the next boot.
    private static void Mark(string configurationFilePath, string? incident, string? preservedCopyPath, ILogger logger)
    {
        try
        {
            var text = "This server could not read its SSO configuration and is serving defaults. Save or import a configuration holding at least one provider to clear this. To clear it by hand instead, move the unreadable configuration file out of the way AND delete this file, then restart - deleting this file alone re-arms the refusal on the next start if the configuration file is still unreadable. The timestamped files beside it are the copies that were kept."
                + Environment.NewLine + IncidentPrefix + (incident ?? string.Empty)
                + Environment.NewLine + CopyPrefix + (preservedCopyPath ?? string.Empty);
            File.WriteAllText(configurationFilePath + MarkerSuffix, text);
        }
#pragma warning disable CA1031 // a marker that cannot be written costs only its survival across a restart
        catch (Exception ex)
#pragma warning restore CA1031
        {
            Announce(() => SsoAudit.UnreadableConfigurationMarkerNotWritten(logger, configurationFilePath + MarkerSuffix, ex));
        }
    }

    private static bool MarkerExists(string configurationFilePath)
    {
        try
        {
            return File.Exists(configurationFilePath + MarkerSuffix);
        }
#pragma warning disable CA1031 // not being able to look is the same answer as there being no marker
        catch (Exception)
#pragma warning restore CA1031
        {
            return false;
        }
    }

    // A failure about the content is damage, a null result is judged the same, and an IO failure decides nothing.
    private static Restored ReadsBack(string configurationFilePath, IXmlSerializer serializer, ILogger logger)
    {
        try
        {
            // Null-tolerant on both maps, or a null map would be reported as damage the host never rewrites.
            return serializer.DeserializeFromFile(typeof(PluginConfiguration), configurationFilePath) is PluginConfiguration configuration
                ? new Restored(true, configuration.OidConfigs?.Count > 0 || configuration.SamlConfigs?.Count > 0, true)
                : Restored.Damaged;
        }
#pragma warning disable CA1031 // the shape of the failure is the whole question, and it is asked below
        catch (Exception ex)
#pragma warning restore CA1031
        {
            // The serializer wraps a stream fault in an InvalidOperationException, so the chain is walked; an XmlException is never an IOException.
            for (var cause = ex; cause is not null; cause = cause.InnerException)
            {
                if (cause is IOException or UnauthorizedAccessException)
                {
                    Announce(() => SsoAudit.UnreadableConfigurationCheckSkipped(logger, configurationFilePath, ex));
                    return Restored.Unknown;
                }
            }

            return Restored.Damaged;
        }
    }

    // What a marker says: which damaged file it was written for and where that file was kept, either possibly absent.
    private readonly record struct Marker(string? Incident, string? CopyPath)
    {
        // The recorded copy only while it is still there; a path that does not exist helps nobody.
        internal string? Kept => CopyPath is { } path && File.Exists(path) ? path : null;
    }
}
