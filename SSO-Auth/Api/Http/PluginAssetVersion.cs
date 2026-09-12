// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using Microsoft.Net.Http.Headers;

namespace Jellyfin.Plugin.SSO_Auth.Api.Http;

/// <summary>
/// The one answer to "how long may a browser keep one of this plugin's assets" (#1627), shared by the two
/// routes that serve them: the plugin's own <see cref="SSOViewsController"/>, and the host's
/// <c>web/ConfigurationPage</c> action through <see cref="PluginPageCacheFilter"/>.
/// </summary>
/// <remarks>
/// <para>
/// The assets are embedded in the assembly, so they change exactly when the assembly's bytes do, and the
/// tag is a digest of those bytes (#1705). It was the file version until that issue, on the reasoning that
/// the build stamps one per release; the build does not. The project pins the file version at the line's
/// three-part number and the build number lives in the package's <c>meta.json</c> only, so every build of
/// one line answered the same tag, a browser holding the previous build's script was told 304, and the
/// dashboard ran that script against the new build's markup with nothing on the page saying so. A digest
/// of the assembly cannot agree across two builds whose bytes differ, whatever any version field says.
/// One tag for every asset is still correct: a client sends the tag it cached for a URL, and the server
/// compares it against that URL's current tag.
/// </para>
/// <para>
/// <c>no-cache</c> rather than a lifetime: a browser may keep the asset but must ask before using it, and
/// with the tag the answer is a 304 until the plugin changes. Without the header a browser falls back to
/// heuristic freshness and can run the previous release's script for as long as it likes after an
/// upgrade, with nothing on the page saying so; a fixed lifetime would only bound that, not end it.
/// </para>
/// <para>
/// THE TAG NEVER FAILS TO EXIST. The digest needs the assembly's bytes from disk: an assembly loaded from
/// memory has no location, and a file can be unreadable at the moment the type initializes. In both
/// cases the tag falls back to the assembly's version, quoted, which is the static answer this replaces
/// and is still a valid validator. A type initializer that threw here would take both asset routes down
/// with it, so the read is injectable and the throwing case is driven by a test rather than reasoned.
/// </para>
/// </remarks>
internal static class PluginAssetVersion
{
    /// <summary>
    /// The <c>Cache-Control</c> value every plugin asset carries: keep it, but ask before using it.
    /// </summary>
    internal const string CacheControl = "no-cache";

    // Sixteen hex digits, 64 bits of the digest: enough that two builds of one line cannot collide by
    // accident, short enough to read in a response header.
    private const int TagDigits = 16;

    /// <summary>
    /// Gets the strong entity tag every plugin asset carries: a digest of this build of the assembly.
    /// </summary>
    internal static EntityTagHeaderValue ETag { get; } = TagOf(typeof(PluginAssetVersion).Assembly);

    /// <summary>
    /// The tag for one build of the assembly, from its bytes: the first sixteen hex digits of their
    /// SHA-256, quoted and strong.
    /// </summary>
    /// <param name="assembly">The bytes of the assembly file.</param>
    /// <returns>The tag those bytes answer.</returns>
    internal static EntityTagHeaderValue TagOf(ReadOnlySpan<byte> assembly) =>
        new("\"" + Convert.ToHexStringLower(SHA256.HashData(assembly))[..TagDigits] + "\"");

    /// <summary>
    /// The tag for a loaded assembly: a digest of its file on disk, or its version quoted where the
    /// file cannot be read.
    /// </summary>
    /// <param name="assembly">The loaded assembly.</param>
    /// <returns>The tag this build of it answers.</returns>
    internal static EntityTagHeaderValue TagOf(Assembly assembly)
    {
        ArgumentNullException.ThrowIfNull(assembly);
        return TagOf(assembly.Location, File.ReadAllBytes, assembly.GetName().Version);
    }

    /// <summary>
    /// The tag for an assembly at <paramref name="location"/> read through <paramref name="read"/>, or
    /// <paramref name="version"/> quoted where there is no location or the read fails.
    /// </summary>
    /// <param name="location">The assembly's path on disk, or empty for one that has none.</param>
    /// <param name="read">Reads the bytes at a path.</param>
    /// <param name="version">The assembly's version, the fallback.</param>
    /// <returns>The tag.</returns>
    internal static EntityTagHeaderValue TagOf(string? location, Func<string, byte[]> read, Version? version)
    {
        ArgumentNullException.ThrowIfNull(read);
        try
        {
            if (!string.IsNullOrEmpty(location))
            {
                return TagOf(read(location));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            // The version below: a tag that is static across builds beats no tag at all.
        }

        return new("\"" + (version?.ToString() ?? "0.0.0.0") + "\"");
    }
}
