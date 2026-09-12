// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;
using System.Security.Cryptography;
using Jellyfin.Plugin.SSO_Auth.Api.Http;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The one lifetime answer both asset routes give (#1627), pinned independently of either route: the tag is
/// a digest of the build of the assembly that is serving (#1705), and the header is the one that makes a
/// browser ask.
/// </summary>
public class PluginAssetVersionTests
{
    [Fact]
    public void TheTag_IsADigestOfThisBuildOfTheAssembly_Quoted_AndStrong()
    {
        // Recomputed here from the same source, the bytes of the SSO-Auth assembly on disk, so a regression
        // to any version field - static across the builds of one line - is caught.
        var bytes = File.ReadAllBytes(typeof(SSOPlugin).Assembly.Location);
        var digest = Convert.ToHexStringLower(SHA256.HashData(bytes))[..16];

        Assert.Equal("\"" + digest + "\"", PluginAssetVersion.ETag.ToString());
        Assert.False(PluginAssetVersion.ETag.IsWeak);
    }

    [Fact]
    public void TheTag_IsNotTheFileVersion_WhichEveryBuildOfALineShares()
    {
        // The defect of #1705: the project pins the file version at the line's three-part number and the
        // build number lives in meta.json only, so a tag from the file version let a browser keep the
        // previous build's script after an upgrade.
        var fileVersion = System.Diagnostics.FileVersionInfo.GetVersionInfo(typeof(SSOPlugin).Assembly.Location).FileVersion;

        Assert.NotEqual("\"" + fileVersion + "\"", PluginAssetVersion.ETag.ToString());
    }

    [Fact]
    public void TwoBuildsWhoseBytesDiffer_AnswerDifferentTags_AndTheSameBytesTheSameTag()
    {
        var one = new byte[64];
        for (var i = 0; i < one.Length; i++)
        {
            one[i] = (byte)i;
        }

        var other = (byte[])one.Clone();
        other[40] ^= 1;

        Assert.NotEqual(PluginAssetVersion.TagOf(one).ToString(), PluginAssetVersion.TagOf(other).ToString());
        Assert.Equal(PluginAssetVersion.TagOf(one).ToString(), PluginAssetVersion.TagOf((byte[])one.Clone()).ToString());
        Assert.Matches("^\"[0-9a-f]{16}\"$", PluginAssetVersion.TagOf(one).ToString());
    }

    [Fact]
    public void AnAssemblyWithNoLocation_FallsBackToItsVersion_RatherThanNoTag()
    {
        // A dynamic assembly has no location, which is one of the two shapes the fallback exists for: the
        // tag is then the assembly's version, static across builds, and still a validator rather than a
        // failed type initializer that would take both asset routes down.
        var name = new AssemblyName("Jellyfin.Plugin.SSO_Auth.Tests.Fallback") { Version = new Version(9, 8, 7, 6) };
        var dynamic = AssemblyBuilder.DefineDynamicAssembly(name, AssemblyBuilderAccess.Run);

        Assert.Equal("\"9.8.7.6\"", PluginAssetVersion.TagOf(dynamic).ToString());
    }

    [Fact]
    public void AnAssemblyWhoseFileCannotBeRead_FallsBackToItsVersion_RatherThanThrowing()
    {
        // The other shape: a location that exists and a read that fails at the moment the type initializes.
        // Driven through the injectable read, because a file that cannot be read is not a state a test can
        // put the real assembly into.
        var tag = PluginAssetVersion.TagOf("C:/nowhere/SSO-Auth.dll", _ => throw new IOException("gone"), new Version(1, 2, 3, 4));

        Assert.Equal("\"1.2.3.4\"", tag.ToString());
    }

    [Fact]
    public void AReadThatSucceeds_IsTheDigest_NotTheVersion()
    {
        // The same seam the fallback is driven through, on its main arm: the version is ignored where the
        // bytes can be read, so a regression that always answered the version would be caught here and
        // not only by the real-assembly test above.
        var tag = PluginAssetVersion.TagOf("C:/somewhere/SSO-Auth.dll", _ => new byte[] { 1, 2, 3 }, new Version(1, 2, 3, 4));

        Assert.Equal(PluginAssetVersion.TagOf(new byte[] { 1, 2, 3 }).ToString(), tag.ToString());
    }

    [Fact]
    public void TheHeader_MakesABrowserAsk_NotForget()
    {
        // no-cache keeps the asset and revalidates it; no-store would throw it away and re-download 300 KB
        // of core script on every page load, and a max-age would only bound the stale window.
        Assert.Equal("no-cache", PluginAssetVersion.CacheControl);
    }
}
