// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Model.Serialization;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Cover for #1543: what happens to <c>SSO-Auth.xml</c> when it cannot be read. The host answers that by
/// building a default configuration and writing it back over the file, so every provider, canonical link
/// and at-rest secret envelope is gone AND the only artefact a repair could work on is overwritten in the
/// same act. What is pinned here is the window this plugin has before that: the file is copied aside, the
/// state is recorded, and it is recorded in the direction that refuses logins rather than serving them.
/// <para>
/// In the <c>SSOController</c> collection because constructing a plugin sets the static
/// <see cref="SSOPlugin.Instance"/> every other test in that collection reads.
/// </para>
/// </summary>
[Collection("SSOController")]
public class UnreadableConfigurationTests
{
    [Fact]
    public void AFileThatReadsBack_IsNotTouched()
    {
        var (path, serializer) = Stored("<PluginConfiguration />", readable: true);

        var state = UnreadableConfiguration.Preserve(path, serializer, Logger(), DateTime.UtcNow);

        Assert.False(state.IsUnreadable);
        Assert.Null(state.PreservedCopyPath);
        Assert.Empty(Copies(path));
    }

    [Fact]
    public void NoFileAtAll_IsAFirstStartRatherThanDamage()
    {
        // A fresh installation has nothing to preserve and nothing to refuse. Treating it as damage would
        // take every new installation offline before it was ever configured.
        var root = Path.Combine(Path.GetTempPath(), "sso-unreadable-" + Guid.NewGuid());
        Directory.CreateDirectory(root);

        var state = UnreadableConfiguration.Preserve(
            Path.Combine(root, "SSO-Auth.xml"),
            Substitute.For<IXmlSerializer>(),
            Logger(),
            DateTime.UtcNow);

        Assert.False(state.IsUnreadable);
    }

    [Fact]
    public void AFileThatDoesNotDeserialize_IsCopiedAsideAndReported()
    {
        var (path, serializer) = Stored("<PluginConfig", readable: false);

        var state = UnreadableConfiguration.Preserve(path, serializer, Logger(), new DateTime(2026, 9, 6, 1, 2, 3, DateTimeKind.Utc));

        Assert.True(state.IsUnreadable);
        Assert.Equal(path + ".unreadable-20260906-010203Z", state.PreservedCopyPath);
        Assert.Equal("<PluginConfig", File.ReadAllText(state.PreservedCopyPath!));

        // The original is still where the host expects it: this preserves the evidence, it does not move
        // the file out from under the load that is about to happen.
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void ADeserializeThatReturnsNull_CountsAsUnreadable()
    {
        // Not a configuration, so serving it would be serving defaults under another name. Every failure
        // has one outcome downstream and therefore one answer here.
        var root = Path.Combine(Path.GetTempPath(), "sso-unreadable-" + Guid.NewGuid());
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "SSO-Auth.xml");
        File.WriteAllText(path, "<PluginConfiguration />");

        var serializer = Substitute.For<IXmlSerializer>();
        serializer.DeserializeFromFile(Arg.Any<Type>(), Arg.Any<string>()).Returns((object?)null);

        Assert.True(UnreadableConfiguration.Preserve(path, serializer, Logger(), DateTime.UtcNow).IsUnreadable);
    }

    [Fact]
    public void AnExistingCopy_IsNeverOverwritten()
    {
        // A server that keeps failing to start must not grind its own evidence away one boot at a time.
        var (path, serializer) = Stored("second boot", readable: false);
        var at = new DateTime(2026, 9, 6, 1, 2, 3, DateTimeKind.Utc);
        File.WriteAllText(path + ".unreadable-20260906-010203Z", "first boot");

        var state = UnreadableConfiguration.Preserve(path, serializer, Logger(), at);

        Assert.True(state.IsUnreadable);
        Assert.Equal("first boot", File.ReadAllText(path + ".unreadable-20260906-010203Z"));
    }

    [Fact]
    public void ACopyThatCannotBeWritten_StillReportsUnreadable()
    {
        // The state is unreadable whether or not the copy succeeded, and the refusal must not depend on
        // the evidence: losing the copy is worse, not a reason to serve logins as though nothing happened.
        var (path, serializer) = Stored("truncated", readable: false);
        var at = new DateTime(2026, 9, 6, 1, 2, 3, DateTimeKind.Utc);

        // A DIRECTORY where the copy would go: File.Copy cannot write over it, on every platform.
        Directory.CreateDirectory(path + ".unreadable-20260906-010203Z");

        var state = UnreadableConfiguration.Preserve(path, serializer, Logger(), at);

        Assert.True(state.IsUnreadable);
        Assert.Null(state.PreservedCopyPath);
    }

    [Fact]
    public void TheLogSaysWhatIsBeingServedAndWhereTheFileWent()
    {
        // An operator can only act on this from the log, so the log carries both halves: that defaults are
        // in use, and where the old file is.
        var (path, serializer) = Stored("truncated", readable: false);
        var log = new CapturingLogger();

        var state = UnreadableConfiguration.Preserve(path, serializer, log, DateTime.UtcNow);

        var line = Assert.Single(log.Records, r => r.Level == LogLevel.Error);
        Assert.Contains("could not be read", line.Message, StringComparison.Ordinal);
        Assert.Contains("Default settings are being served", line.Message, StringComparison.Ordinal);
        Assert.Contains(state.PreservedCopyPath!, line.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void APluginConstructedOverAnUnreadableFile_ServesDefaultsAndKeepsTheEvidence()
    {
        // The whole road, through the real constructor: the screen runs before anything reads
        // Configuration, so the file it copies is the damaged one rather than the defaults the host is
        // about to write over it.
        var root = Path.Combine(Path.GetTempPath(), "sso-unreadable-" + Guid.NewGuid());
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "SSO-Auth.xml");
        File.WriteAllText(path, "<PluginConfig");

        var appPaths = Substitute.For<IApplicationPaths>();
        appPaths.PluginConfigurationsPath.Returns(root);
        appPaths.PluginsPath.Returns(Path.Combine(root, "plugins"));

        var serializer = Substitute.For<IXmlSerializer>();
        serializer.DeserializeFromFile(Arg.Any<Type>(), Arg.Any<string>()).Returns(_ => throw new InvalidOperationException("truncated"));

        var plugin = new SSOPlugin(appPaths, serializer, Substitute.For<ILogger<SSOPlugin>>());

        Assert.True(plugin.ServingDefaultConfiguration);
        var copy = Assert.Single(Copies(path));
        Assert.Equal("<PluginConfig", File.ReadAllText(copy));
    }

    [Fact]
    public void APluginConstructedOverAReadableFile_ServesIt()
    {
        // The falsifier for the test above: one thing changes - the serializer reads the file back - and
        // the same construction leaves the flag off and writes no copy.
        var root = Path.Combine(Path.GetTempPath(), "sso-unreadable-" + Guid.NewGuid());
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "SSO-Auth.xml");
        File.WriteAllText(path, "<PluginConfiguration />");

        var appPaths = Substitute.For<IApplicationPaths>();
        appPaths.PluginConfigurationsPath.Returns(root);
        appPaths.PluginsPath.Returns(Path.Combine(root, "plugins"));

        var serializer = Substitute.For<IXmlSerializer>();
        serializer.DeserializeFromFile(Arg.Any<Type>(), Arg.Any<string>()).Returns(new PluginConfiguration());

        var plugin = new SSOPlugin(appPaths, serializer, Substitute.For<ILogger<SSOPlugin>>());

        Assert.False(plugin.ServingDefaultConfiguration);
        Assert.Empty(Copies(path));
    }

    [Fact]
    public void AFileThatCouldNotBeOpenedAtAll_DecidesNothing()
    {
        // THE FAILURE THAT MUST NOT LATCH. A locked file - a virus scanner, a backup agent or a sync
        // client holding it at exactly the moment plugins load - is not damage: this check could not read
        // the bytes, and the server's own read a moment later may well succeed. Refusing on it would take
        // SSO offline permanently on a server whose configuration is perfectly good and live in memory,
        // with a log line false in both halves, until somebody noticed and pressed Save.
        var root = Path.Combine(Path.GetTempPath(), "sso-unreadable-" + Guid.NewGuid());
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "SSO-Auth.xml");
        File.WriteAllText(path, "<PluginConfiguration />");

        var serializer = Substitute.For<IXmlSerializer>();
        serializer.DeserializeFromFile(Arg.Any<Type>(), Arg.Any<string>()).Returns(_ => throw new IOException("the file is in use"));

        var state = UnreadableConfiguration.Preserve(path, serializer, Logger(), DateTime.UtcNow);

        Assert.False(state.IsUnreadable);
        Assert.Empty(Copies(path));
        Assert.False(File.Exists(path + UnreadableConfiguration.MarkerSuffix));
    }

    [Fact]
    public void AFileThatCannotBeAccessed_DecidesNothingEither()
    {
        // The same reading for the permission flavour of the same failure.
        var (path, _) = Stored("<PluginConfiguration />", readable: true);
        var serializer = Substitute.For<IXmlSerializer>();
        serializer.DeserializeFromFile(Arg.Any<Type>(), Arg.Any<string>()).Returns(_ => throw new UnauthorizedAccessException());

        Assert.False(UnreadableConfiguration.Preserve(path, serializer, Logger(), DateTime.UtcNow).IsUnreadable);
    }

    [Fact]
    public void TheStateSurvivesARestart()
    {
        // By the next start the server has replaced the damaged file with a readable default, so the screen
        // alone would report healthy - no line, no refusal - and SSO would go back to answering that the
        // provider is unknown, which is the confusion this exists to end. Restarting is also the first
        // thing an operator does when told SSO is down. The marker is what makes the second start agree
        // with the first.
        var (path, damaged) = Stored("<PluginConfig", readable: false);
        Assert.True(UnreadableConfiguration.Preserve(path, damaged, Logger(), DateTime.UtcNow).IsUnreadable);

        // The host has now written its defaults over the file, so a fresh screen reads it back.
        File.WriteAllText(path, "<PluginConfiguration />");
        var healthy = Substitute.For<IXmlSerializer>();
        healthy.DeserializeFromFile(Arg.Any<Type>(), Arg.Any<string>()).Returns(new PluginConfiguration());

        var second = UnreadableConfiguration.Preserve(path, healthy, Logger(), DateTime.UtcNow);

        Assert.True(second.IsUnreadable);
        Assert.Equal(Copies(path)[0], second.PreservedCopyPath);
    }

    [Fact]
    public void ClearingTheMarkerEndsIt_AndLeavesTheEvidence()
    {
        // The falsifier for the test above, and the property that keeps it from being a one-way door: what
        // an administrator supplying a configuration removes is the marker, never the copy.
        var (path, damaged) = Stored("<PluginConfig", readable: false);
        UnreadableConfiguration.Preserve(path, damaged, Logger(), DateTime.UtcNow);
        var copy = Copies(path)[0];

        UnreadableConfiguration.ClearMarker(path, Logger());

        File.WriteAllText(path, "<PluginConfiguration />");
        var healthy = Substitute.For<IXmlSerializer>();
        healthy.DeserializeFromFile(Arg.Any<Type>(), Arg.Any<string>()).Returns(new PluginConfiguration());

        Assert.False(UnreadableConfiguration.Preserve(path, healthy, Logger(), DateTime.UtcNow).IsUnreadable);
        Assert.True(File.Exists(copy));
    }

    [Fact]
    public void ASecondFailingStart_AddsNoSecondCopy()
    {
        // A server crash-looping before anything reads the configuration would otherwise write one full
        // copy of the file per restart into the directory the whole server needs writable. The evidence is
        // already kept, and the second copy would be the same bytes as the first.
        var (path, damaged) = Stored("<PluginConfig", readable: false);
        UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 9, 6, 1, 2, 3, DateTimeKind.Utc));

        var second = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 9, 6, 4, 5, 6, DateTimeKind.Utc));

        Assert.True(second.IsUnreadable);
        Assert.Single(Copies(path));
        Assert.Equal(path + UnreadableConfiguration.CopySuffix + "20260906-010203Z", second.PreservedCopyPath);
    }

    private static ILogger Logger() => Substitute.For<ILogger>();

    private static string[] Copies(string path)
        => Directory.GetFiles(Path.GetDirectoryName(path)!, Path.GetFileName(path) + UnreadableConfiguration.CopySuffix + "*");

    // A stored file plus a serializer that either reads it back or throws the way the host's own does.
    private static (string Path, IXmlSerializer Serializer) Stored(string content, bool readable)
    {
        var root = Path.Combine(Path.GetTempPath(), "sso-unreadable-" + Guid.NewGuid());
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "SSO-Auth.xml");
        File.WriteAllText(path, content);

        var serializer = Substitute.For<IXmlSerializer>();
        if (readable)
        {
            serializer.DeserializeFromFile(Arg.Any<Type>(), Arg.Any<string>()).Returns(new PluginConfiguration());
        }
        else
        {
            serializer.DeserializeFromFile(Arg.Any<Type>(), Arg.Any<string>()).Returns(_ => throw new InvalidOperationException("truncated"));
        }

        return (path, serializer);
    }
}
