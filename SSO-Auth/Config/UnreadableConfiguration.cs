// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Globalization;
using System.IO;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using MediaBrowser.Model.Serialization;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// What one read of the stored file said (#1543): whether it came back at all, and whether what came
/// back is a configuration somebody put there rather than the empty default the host writes.
/// </summary>
/// <param name="Readable">Whether the file yielded a configuration, or could not be judged at all.</param>
/// <param name="HoldsAProvider">Whether that configuration holds at least one provider, which is what makes it somebody's rather than a default.</param>
internal readonly record struct Restored(bool Readable, bool HoldsAProvider)
{
    /// <summary>Gets the answer for a file that is not there: nothing to preserve and nothing to refuse.</summary>
    internal static Restored Nothing => new(true, false);

    /// <summary>Gets the answer for a read that could not be made at all, which decides nothing.</summary>
    internal static Restored Unknown => new(true, false);

    /// <summary>Gets the answer for a file that is there and does not come back.</summary>
    internal static Restored Damaged => new(false, false);
}

/// <summary>
/// Whether the stored configuration could be read at start, and where the damaged file was kept (#1543).
/// </summary>
/// <remarks>
/// The default value is the healthy one: a configuration that read back, and a first start with no file at
/// all, are both <c>IsUnreadable = false</c>. So a caller that forgets to assign this serves logins, which
/// is the right direction for a flag whose true value takes SSO offline.
/// </remarks>
/// <param name="IsUnreadable">Whether the stored configuration failed to deserialize, so the host is about to serve defaults over it.</param>
/// <param name="PreservedCopyPath">
/// Where the damaged file was copied, or <see langword="null"/> when the copy could not be written. Null
/// does NOT weaken <paramref name="IsUnreadable"/>: the evidence is gone, the refusal is not.
/// </param>
internal readonly record struct UnreadableConfigurationState(bool IsUnreadable, string? PreservedCopyPath);

/// <summary>
/// Keeps the evidence when <c>SSO-Auth.xml</c> cannot be read, and says so (#1543).
/// </summary>
/// <remarks>
/// <para>
/// WHAT THE HOST DOES, MEASURED RATHER THAN REASONED. <c>BasePlugin&lt;T&gt;.LoadConfiguration</c> catches
/// every exception, builds a default configuration and WRITES IT BACK over the file. So a damaged
/// <c>SSO-Auth.xml</c> - a write truncated by a full disk, a filesystem corruption, an interrupted restore,
/// a hand edit - is replaced by defaults on the next start, and the only artefact a repair could have
/// worked on is overwritten in the same act. Every provider, every canonical link and every at-rest secret
/// envelope goes with it.
/// </para>
/// <para>
/// WHY A WINDOW EXISTS AT ALL. The host's load is LAZY: after the plugin's constructor returns, the
/// serializer has been asked for nothing and the damaged file is byte-for-byte intact - the destruction
/// happens on the FIRST read of <c>Configuration</c>. That window belongs to this plugin, and this is what
/// it is spent on. The check is the plugin's own and touches no base-class member: it reads the file
/// itself, so nothing here can trigger the load it exists to get ahead of.
/// </para>
/// <para>
/// A write-side rename would not reach this. That repair publishes a complete file or none, which stops
/// the truncation - and leaves the load side exactly as it is for every other cause of an unreadable file
/// (#1532). The destructive act is the host's, on load, and no write-side change touches it.
/// </para>
/// </remarks>
internal static class UnreadableConfiguration
{
    /// <summary>The suffix a preserved copy is named with, before its UTC timestamp.</summary>
    internal const string CopySuffix = ".unreadable-";

    /// <summary>
    /// The suffix of the marker that keeps the state across a restart. Its own file rather than a flag in
    /// the configuration, because the configuration is the thing that was lost.
    /// </summary>
    internal const string MarkerSuffix = ".unreadable";

    /// <summary>
    /// Screens the stored configuration before anything reads it, keeps the evidence when it cannot be
    /// read, and answers whether this server is about to serve defaults.
    /// </summary>
    /// <remarks>
    /// THREE ANSWERS, NOT TWO, and the third is the one a fail-closed reading gets wrong. A file that
    /// deserializes is healthy. A file that fails to deserialize for a reason about its CONTENT is damage.
    /// A file that could not be READ AT ALL - locked by a virus scanner, a backup agent or a sync client at
    /// exactly the moment plugins load, an IO error on the volume - is neither: this check could not run,
    /// and the host's own read a moment later may well succeed. Latching the refusal on that would take SSO
    /// offline permanently on a server whose configuration is perfectly good and is live in memory, with a
    /// log line that is false in both halves, until somebody notices and presses Save. The refusal is
    /// worth having against real damage and is not worth that, so an IO failure says so and changes
    /// nothing - which leaves the behaviour exactly where it stood before this check existed.
    /// </remarks>
    /// <remarks>
    /// IT SURVIVES A RESTART, and it has to. By the next boot the host has already replaced the damaged
    /// file with a readable default, so the screen alone would report healthy - no banner, no line, no
    /// refusal - and every SSO sign-in would go back to answering that the provider is unknown, which is
    /// the confusion this exists to end. Restarting is also the first thing an operator does when told SSO
    /// is down. So a marker file is written beside the copy and outlives the process; only an administrator
    /// supplying a configuration removes it, and it is a marker rather than the copy, so the evidence is
    /// never what gets deleted.
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

        // No file at all is a first start: nothing to preserve and nothing to refuse. Treating it as damage
        // would take every new installation offline before it was ever configured.
        var stored = File.Exists(configurationFilePath) ? ReadsBack(configurationFilePath, serializer, logger) : Restored.Nothing;
        if (stored.Readable)
        {
            return CarriedOver(configurationFilePath, stored.HoldsAProvider, logger);
        }

        // One copy per INCIDENT, keyed on the marker rather than on whether some copy exists. A boot loop
        // on a damaged file must not write one full copy of it per restart into the directory the whole
        // server needs writable - but a second, unrelated incident months later is a different file, and
        // finding the first incident's copy must not make this one go uncopied while the log says it was
        // kept. The marker is cleared when the server is repaired; a stray copy is not.
        var preserved = MarkerExists(configurationFilePath)
            ? ExistingCopy(configurationFilePath) ?? Copy(configurationFilePath, nowUtc, logger)
            : Copy(configurationFilePath, nowUtc, logger);
        Mark(configurationFilePath, logger);
        SsoAudit.UnreadableConfigurationFound(logger, configurationFilePath, preserved);
        return new UnreadableConfigurationState(true, preserved);
    }

    /// <summary>
    /// Removes the marker, so a server that has been given a configuration stops serving defaults across
    /// restarts too (#1543). The preserved copies are deliberately left where they are: they are the
    /// evidence, and an operator may not have looked at them yet.
    /// </summary>
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
            SsoAudit.UnreadableConfigurationMarkerNotCleared(logger, configurationFilePath + MarkerSuffix, ex);
        }
    }

    // The state a previous boot left behind, judged against what the file now holds.
    //
    // A file that reads back is not yet a repair: the host replaces a damaged one with a DEFAULT, which
    // parses perfectly and holds nothing, so the marker has to be believed over the mere fact that it
    // parses. A file that reads back AND holds a provider is a different thing entirely - somebody put the
    // configuration back, and the two ways they will actually do it are restoring the backup over the file
    // and copying it in from elsewhere, neither of which is a write this plugin ever sees. Refusing on
    // through those would leave a server whose providers, links and secrets are all correct and live
    // answering 503 to every sign-in for good, with the log telling the operator that no configuration had
    // been supplied - and on a server whose administrators all arrived through SSO, nobody to fix it.
    private static UnreadableConfigurationState CarriedOver(string configurationFilePath, bool holdsAProvider, ILogger logger)
    {
        if (!MarkerExists(configurationFilePath))
        {
            return default;
        }

        if (holdsAProvider)
        {
            ClearMarker(configurationFilePath, logger);
            SsoAudit.UnreadableConfigurationRepairedOnDisk(logger, configurationFilePath);
            return default;
        }

        var preserved = ExistingCopy(configurationFilePath);
        SsoAudit.UnreadableConfigurationStillUnrepaired(logger, configurationFilePath, preserved);
        return new UnreadableConfigurationState(true, preserved);
    }

    // The oldest copy this incident produced, or null when none was written. Ordinal ordering over a fixed
    // UTC timestamp format is chronological, so "oldest" is the first entry.
    private static string? ExistingCopy(string configurationFilePath)
    {
        try
        {
            var directory = Path.GetDirectoryName(configurationFilePath);
            if (string.IsNullOrEmpty(directory))
            {
                return null;
            }

            var copies = Directory.GetFiles(directory, Path.GetFileName(configurationFilePath) + CopySuffix + "*");
            Array.Sort(copies, StringComparer.Ordinal);
            return copies.Length > 0 ? copies[0] : null;
        }
#pragma warning disable CA1031 // not being able to look is the same answer as there being nothing to find
        catch (Exception)
#pragma warning restore CA1031
        {
            return null;
        }
    }

    // Copies the damaged file aside, never over an existing name. A copy that cannot be written is reported
    // and does not soften the refusal: the state is unreadable either way, and losing the evidence is the
    // worse outcome rather than a reason to serve logins as though nothing had happened.
    private static string? Copy(string configurationFilePath, DateTime nowUtc, ILogger logger)
    {
        var copy = configurationFilePath + CopySuffix + nowUtc.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "Z";
        try
        {
            File.Copy(configurationFilePath, copy, overwrite: false);
            return copy;
        }
#pragma warning disable CA1031 // the state is unreadable whether or not the copy succeeded, and saying so is what matters
        catch (Exception ex)
#pragma warning restore CA1031
        {
            SsoAudit.UnreadableConfigurationNotPreserved(logger, copy, ex);
            return null;
        }
    }

    // Writes the marker that outlives the process. A marker that cannot be written costs the state its
    // survival across a restart and nothing else, so it is reported rather than thrown - this runs in a
    // plugin constructor, and a server that cannot start is a worse answer than one that forgets.
    private static void Mark(string configurationFilePath, ILogger logger)
    {
        try
        {
            File.WriteAllText(
                configurationFilePath + MarkerSuffix,
                "This server could not read its SSO configuration and is serving defaults. Import or save a configuration to clear this; the file beside it is the copy that was kept.");
        }
#pragma warning disable CA1031 // a marker that cannot be written costs only its survival across a restart
        catch (Exception ex)
#pragma warning restore CA1031
        {
            SsoAudit.UnreadableConfigurationMarkerNotWritten(logger, configurationFilePath + MarkerSuffix, ex);
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

    // Whether the host serializer can turn the stored bytes back into this plugin configuration type. A
    // failure ABOUT THE CONTENT is the condition being detected: the host catches it, hands out defaults and
    // persists them over the file, whatever its type, and a deserialize that returns null is the same
    // outcome under another name. An IO failure is not that: it means this check could not read the bytes
    // at all, the host's own read may still succeed, and latching a permanent refusal on a file somebody
    // else had open for a moment is a worse failure than the one being guarded. It says so and reports
    // readable, which leaves the server exactly where it stood before this check existed.
    private static Restored ReadsBack(string configurationFilePath, IXmlSerializer serializer, ILogger logger)
    {
        try
        {
            return serializer.DeserializeFromFile(typeof(PluginConfiguration), configurationFilePath) is PluginConfiguration configuration
                ? new Restored(true, configuration.OidConfigs.Count > 0 || configuration.SamlConfigs.Count > 0)
                : Restored.Damaged;
        }
#pragma warning disable CA1031 // the shape of the failure is the whole question, and it is asked below
        catch (Exception ex)
#pragma warning restore CA1031
        {
            // WRAPPED OR NOT, an IO failure is an IO failure. The serializer turns anything the stream
            // threw into an InvalidOperationException with the real cause inside, so matching only the
            // top-level type catches a file that would not OPEN and misses one that failed halfway
            // through - a network mount hiccupping, a device read error, a restore rewriting the file
            // under the read - and calls it damage. Nothing genuine is lost by looking inside: an
            // XmlException is a SystemException and is never an IOException, so real corruption still
            // lands on the damage arm.
            for (var cause = ex; cause is not null; cause = cause.InnerException)
            {
                if (cause is IOException or UnauthorizedAccessException)
                {
                    SsoAudit.UnreadableConfigurationCheckSkipped(logger, configurationFilePath, ex);
                    return Restored.Unknown;
                }
            }

            return Restored.Damaged;
        }
    }
}
