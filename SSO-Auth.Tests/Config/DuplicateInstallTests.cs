// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Coverage for noticing a second copy of this plugin in the same server, and for the one copy of the
/// configuration that is taken before the host can overwrite it (#1601).
/// </summary>
public class DuplicateInstallTests
{
    private static readonly DateTime Noon = new(2026, 9, 10, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void InAProcessHoldingOneCopy_ItReportsNoDuplicate()
    {
        // The direction that matters. A missed duplicate leaves the server exactly as it was before this
        // check existed; a false positive refuses every configuration write on a healthy server, which is
        // an outage this check invented. So the ordinary case is asserted rather than assumed, in the one
        // process available to assert it in.
        WithConfigurationFile(path =>
        {
            var state = DuplicateInstall.Detect(path, Noon);

            Assert.False(state.IsDuplicated);
            Assert.Null(state.PreservedCopyPath);
            Assert.Empty(Copies(path));
        });
    }

    [Fact]
    public void ItCopiesTheConfigurationAside()
    {
        WithConfigurationFile(path =>
        {
            var copy = DuplicateInstall.Preserve(path, Noon);

            Assert.NotNull(copy);
            Assert.Equal(File.ReadAllText(path), File.ReadAllText(copy!));
            Assert.Contains(DuplicateInstall.CopySuffix, copy!, StringComparison.Ordinal);
            Assert.Single(Copies(path));
        });
    }

    [Fact]
    public void ASecondBootKeepsTheFirstCopyRatherThanTakingItsOwn()
    {
        // The property the whole file turns on. A server left in this state boots again and again, and by
        // the second boot the file on disk is already the empty one the host wrote. Copying again would
        // bury the only version worth having under a stack of empty ones, so the oldest copy is the answer
        // and later boots hand it back unchanged.
        WithConfigurationFile(path =>
        {
            var first = DuplicateInstall.Preserve(path, Noon);
            File.WriteAllText(path, "<PluginConfiguration />");

            var second = DuplicateInstall.Preserve(path, Noon.AddHours(1));

            Assert.Equal(first, second);
            Assert.Single(Copies(path));
            Assert.Contains("authentik", File.ReadAllText(first!), StringComparison.Ordinal);
        });
    }

    [Fact]
    public void WithNoConfigurationOnDisk_ItCopiesNothing()
    {
        WithConfigurationFile(path =>
        {
            File.Delete(path);

            Assert.Null(DuplicateInstall.Preserve(path, Noon));
            Assert.Empty(Copies(path));
        });
    }

    [Fact]
    public void WithNoConfigurationPath_ItCopiesNothing()
    {
        // The host hands out a path composed from the application paths, and a harness or an early boot
        // can leave it empty. An empty path must be a no-op rather than an exception out of a plugin
        // constructor, which would take every SSO login on the server offline.
        Assert.Null(DuplicateInstall.Preserve(null, Noon));
        Assert.Null(DuplicateInstall.Preserve(string.Empty, Noon));
        Assert.Null(DuplicateInstall.Preserve("   ", Noon));
    }

    private static string[] Copies(string configurationFilePath) =>
        Directory
            .EnumerateFiles(
                Path.GetDirectoryName(configurationFilePath)!,
                Path.GetFileName(configurationFilePath) + DuplicateInstall.CopySuffix + "*")
            .ToArray();

    private static void WithConfigurationFile(Action<string> test)
    {
        var directory = SuiteTempFiles.Path("sso-duplicate", string.Empty);
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "SSO-Auth.xml");
        File.WriteAllText(
            path,
            "<PluginConfiguration><OidConfigs><item><key>authentik</key></item></OidConfigs></PluginConfiguration>");
        try
        {
            test(path);
        }
        finally
        {
            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Best effort, as SuiteTempFiles does it: a directory that would not go must not turn a
                // green suite red on the way out.
            }
        }
    }
}
