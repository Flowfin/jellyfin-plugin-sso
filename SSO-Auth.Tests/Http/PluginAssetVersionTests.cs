// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Jellyfin.Plugin.SSO_Auth.Api.Http;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The one lifetime answer both asset routes give (#1627), pinned independently of either route: the tag is
/// the plugin's file version, which the release build stamps per release, and the header is the one that
/// makes a browser ask.
/// </summary>
public class PluginAssetVersionTests
{
    [Fact]
    public void TheTag_IsThePluginsFileVersion_Quoted_AndStrong()
    {
        // Recomputed here from the same source, the SSO-Auth assembly's FILE version, so a regression to
        // the assembly version (static across releases, #253) or to a weak tag is caught.
        var fileVersion = System.Diagnostics.FileVersionInfo.GetVersionInfo(typeof(SSOPlugin).Assembly.Location).FileVersion;

        Assert.Equal("\"" + fileVersion + "\"", PluginAssetVersion.ETag.ToString());
        Assert.False(PluginAssetVersion.ETag.IsWeak);
    }

    [Fact]
    public void TheHeader_MakesABrowserAsk_NotForget()
    {
        // no-cache keeps the asset and revalidates it; no-store would throw it away and re-download 300 KB
        // of core script on every page load, and a max-age would only bound the stale window.
        Assert.Equal("no-cache", PluginAssetVersion.CacheControl);
    }
}
