// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Microsoft.Net.Http.Headers;

namespace Jellyfin.Plugin.SSO_Auth.Api.Http;

/// <summary>
/// The one answer to "how long may a browser keep one of this plugin's assets" (#1627), shared by the two
/// routes that serve them: the plugin's own <see cref="SSOViewsController"/>, and the host's
/// <c>web/ConfigurationPage</c> action through <see cref="PluginPageCacheFilter"/>.
/// </summary>
/// <remarks>
/// <para>
/// The assets are embedded in the assembly, so they change exactly when the plugin's file version does,
/// and the file version is what the build stamps per release; the assembly version can stay static across
/// releases and would then validate stale assets after an upgrade (#253). One tag for every asset is
/// correct: a client sends the tag it cached for a URL, and the server compares it against that URL's
/// current tag.
/// </para>
/// <para>
/// <c>no-cache</c> rather than a lifetime: a browser may keep the asset but must ask before using it, and
/// with the tag the answer is a 304 until the plugin changes. Without the header a browser falls back to
/// heuristic freshness and can run the previous release's script for as long as it likes after an
/// upgrade, with nothing on the page saying so; a fixed lifetime would only bound that, not end it.
/// </para>
/// </remarks>
internal static class PluginAssetVersion
{
    /// <summary>
    /// The <c>Cache-Control</c> value every plugin asset carries: keep it, but ask before using it.
    /// </summary>
    internal const string CacheControl = "no-cache";

    /// <summary>
    /// Gets the strong entity tag every plugin asset carries: the plugin's file version, quoted.
    /// </summary>
    internal static EntityTagHeaderValue ETag { get; } = new(
        "\"" + System.Diagnostics.FileVersionInfo.GetVersionInfo(typeof(PluginAssetVersion).Assembly.Location).FileVersion + "\"");
}
