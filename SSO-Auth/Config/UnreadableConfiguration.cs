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
    /// Copies the configuration file aside when it cannot be deserialized, and answers with where it was
    /// kept, so the caller can say what is being served instead. Reports readable for a file that reads
    /// back and for no file at all - a first start has nothing to preserve and nothing to refuse, and
    /// treating it as damage would take every new installation offline before it was ever configured.
    /// </summary>
    /// <remarks>
    /// The readability question is answered with the SAME serializer the host will use, because the failure
    /// this guards is "the host's deserialize threw", not "the bytes are not well-formed XML": a document
    /// that parses as XML but not as this type produces defaults just as surely. That costs one extra parse
    /// per start, paid once, before any login can exist.
    /// <para>
    /// It never overwrites an existing copy. A server that keeps failing to start must not grind its own
    /// evidence away one boot at a time, so the timestamp makes each copy its own file and a collision
    /// leaves the older one standing. A copy that cannot be written is reported and does not stop the
    /// refusal: the state is unreadable either way, and the operator learning that from the log is worth
    /// more than the copy that failed.
    /// </para>
    /// </remarks>
    /// <param name="configurationFilePath">The host's configuration file path for this plugin.</param>
    /// <param name="serializer">The host's XML serializer, asked the same question the host will ask it.</param>
    /// <param name="logger">The logger the refusal is announced on.</param>
    /// <param name="nowUtc">The instant the copy is named after.</param>
    /// <returns>The screened state: unreadable or not, and where the damaged file was kept.</returns>
    internal static UnreadableConfigurationState Preserve(string? configurationFilePath, IXmlSerializer serializer, ILogger logger, DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(serializer);

        if (string.IsNullOrWhiteSpace(configurationFilePath) || !File.Exists(configurationFilePath))
        {
            return default;
        }

        if (ReadsBack(configurationFilePath, serializer))
        {
            return default;
        }

        var copy = configurationFilePath + CopySuffix + nowUtc.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "Z";
        string? preserved = null;
        try
        {
            File.Copy(configurationFilePath, copy, overwrite: false);
            preserved = copy;
        }
#pragma warning disable CA1031 // the state is unreadable whether or not the copy succeeded, and saying so is what matters
        catch (Exception ex)
#pragma warning restore CA1031
        {
            SsoAudit.UnreadableConfigurationNotPreserved(logger, copy, ex);
        }

        SsoAudit.UnreadableConfigurationFound(logger, configurationFilePath, preserved);
        return new UnreadableConfigurationState(true, preserved);
    }

    // Whether the host serializer can turn the stored bytes back into this plugin configuration type. Every
    // failure is one answer - no, fail closed - because every failure has one outcome downstream: the host
    // catches it, hands out defaults and persists them over the file. A null result counts as a failure for
    // the same reason: it is not a configuration, and serving it would be serving defaults under another name.
    private static bool ReadsBack(string configurationFilePath, IXmlSerializer serializer)
    {
        try
        {
            return serializer.DeserializeFromFile(typeof(PluginConfiguration), configurationFilePath) is PluginConfiguration;
        }
#pragma warning disable CA1031 // any failure to deserialize is the condition being detected, whatever its type
        catch (Exception)
#pragma warning restore CA1031
        {
            return false;
        }
    }
}
