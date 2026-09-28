// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using Microsoft.Net.Http.Headers;

namespace Jellyfin.Plugin.SSO_Auth.Api.Http;

/// <summary>The one answer to how long a browser may keep one of this plugin's assets (#1627), shared by <see cref="SSOViewsController"/> and the host's page action through <see cref="PluginPageCacheFilter"/>.</summary>
/// <remarks>
/// The tag is a digest of the assembly's bytes (#1705), because the file version is pinned per line and every
/// build of one line answered the same tag, so a browser holding the previous build's script was told 304.
/// <c>no-cache</c> rather than a lifetime: the browser may keep the asset but asks before using it, and the
/// answer is a 304 until the plugin changes. The tag never fails to exist: an assembly with no readable location
/// falls back to the quoted assembly version, and the read is injectable so the throwing case is driven by a test.
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
