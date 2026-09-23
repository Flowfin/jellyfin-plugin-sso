// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Direct tests of <see cref="UnmanagedFolderMerge"/> (#1846): which folders a configuration manages, and
/// what a merged login writes.
/// </summary>
public class UnmanagedFolderMergeTests
{
    [Fact]
    public void ManagedBy_CollectsTheStaticListAndEveryMapping_Once()
    {
        var config = new OidConfig
        {
            EnabledFolders = new[] { "lib-static", "lib-both" },
            FolderRoleMapping = new List<FolderRoleMap>
            {
                new() { Role = "family", Folders = new List<string> { "lib-both", "lib-family" } },
                new() { Role = "nobody", Folders = new List<string> { "lib-parked" } },
            },
        };

        var managed = UnmanagedFolderMerge.ManagedBy(config);

        Assert.Equal(new[] { "lib-static", "lib-both", "lib-family", "lib-parked" }, managed);
    }

    [Fact]
    public void ManagedBy_NullListsAndBlankEntries_ManageNothing()
    {
        // A config/deserialization edge: null lists and blank ids grant nothing elsewhere (#675) and manage
        // nothing here, so an empty configuration never claims a folder.
        var config = new OidConfig
        {
            EnabledFolders = null,
            FolderRoleMapping = new List<FolderRoleMap> { new() { Role = "family", Folders = null }, new() { Role = "x", Folders = new List<string> { string.Empty } } },
        };

        Assert.Empty(UnmanagedFolderMerge.ManagedBy(config));
        Assert.Empty(UnmanagedFolderMerge.ManagedBy(new OidConfig()));
    }

    [Fact]
    public void Apply_KeepsUnmanagedFolders_ReplacesManagedOnesWithTheGrants()
    {
        var written = UnmanagedFolderMerge.Apply(
            current: new[] { "lib-personal", "lib-mapped-old", "lib-1" },
            managed: new[] { "lib-mapped-old", "lib-1", "lib-2" },
            granted: new[] { "lib-2" });

        Assert.Equal(new[] { "lib-personal", "lib-2" }, written);
    }

    [Fact]
    public void Apply_AFolderDroppedFromTheConfiguration_IsNoLongerManaged_AndStaysOnTheAccount()
    {
        // The trade named on #1846: once the configuration stops naming a folder it is not the plugin's to
        // touch, so the account keeps it. Revoking without deleting is a mapping no role carries, which
        // keeps the folder managed (in the set) and not granted, and the merge removes it.
        var current = new[] { "lib-old" };

        Assert.Equal(new[] { "lib-old" }, UnmanagedFolderMerge.Apply(current, managed: Array.Empty<string>(), granted: Array.Empty<string>()));
        Assert.Empty(UnmanagedFolderMerge.Apply(current, managed: new[] { "lib-old" }, granted: Array.Empty<string>()));
    }

    [Fact]
    public void Apply_IsOrdinal_AndWritesEachFolderOnce()
    {
        // Folder ids are Jellyfin item ids, so case is significant, and a folder both kept and granted
        // appears once.
        var written = UnmanagedFolderMerge.Apply(
            current: new[] { "AbC", "abc", "lib-1" },
            managed: new[] { "abc" },
            granted: new[] { "lib-1", "lib-1" });

        Assert.Equal(new[] { "AbC", "lib-1" }, written);
    }

    [Fact]
    public void Apply_NullCurrent_WritesJustTheGrants()
    {
        Assert.Equal(new[] { "lib-1" }, UnmanagedFolderMerge.Apply(null, managed: new[] { "lib-1" }, granted: new[] { "lib-1" }));
    }
}
