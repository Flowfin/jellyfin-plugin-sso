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

    [Fact]
    public void AConfigurationRestoredOnDisk_EndsIt()
    {
        // THE REPAIR AN OPERATOR ACTUALLY PERFORMS, and the one the marker nearly broke. Restoring the
        // backup over the file is not a write this plugin ever sees, so a marker that only a persisted
        // write could clear would have left a server whose providers, links and secrets are all correct
        // and live answering 503 to every sign-in for good - and on a server whose administrators all
        // arrived through SSO, with nobody able to log in and clear it.
        var (path, damaged) = Stored("<PluginConfig", readable: false);
        Assert.True(UnreadableConfiguration.Preserve(path, damaged, Logger(), DateTime.UtcNow).IsUnreadable);

        var restored = Substitute.For<IXmlSerializer>();
        var configuration = new PluginConfiguration();
        configuration.OidConfigs["keycloak"] = new OidConfig();
        restored.DeserializeFromFile(Arg.Any<Type>(), Arg.Any<string>()).Returns(configuration);

        var second = UnreadableConfiguration.Preserve(path, restored, Logger(), DateTime.UtcNow);

        Assert.False(second.IsUnreadable);
        Assert.False(File.Exists(path + UnreadableConfiguration.MarkerSuffix));
        Assert.Single(Copies(path));
    }

    [Fact]
    public void ADefaultConfigurationOnDisk_DoesNotEndIt()
    {
        // The falsifier for the test above, and the reason the marker exists at all: the host replaces a
        // damaged file with a DEFAULT, which parses perfectly and holds nothing. If merely parsing counted
        // as a repair, the state would clear on the first restart and SSO would go back to answering that
        // the provider is unknown.
        var (path, damaged) = Stored("<PluginConfig", readable: false);
        UnreadableConfiguration.Preserve(path, damaged, Logger(), DateTime.UtcNow);

        var defaults = Substitute.For<IXmlSerializer>();
        defaults.DeserializeFromFile(Arg.Any<Type>(), Arg.Any<string>()).Returns(new PluginConfiguration());

        Assert.True(UnreadableConfiguration.Preserve(path, defaults, Logger(), DateTime.UtcNow).IsUnreadable);
    }

    [Fact]
    public void AnIoFailureTheSerializerWrapped_DecidesNothing()
    {
        // The serializer turns anything the stream threw into an InvalidOperationException with the real
        // cause inside, so matching only the top-level type catches a file that would not OPEN and misses
        // one that failed halfway through - a network mount hiccupping, a device read error, a restore
        // rewriting the file under the read - and would call it damage on a healthy server.
        var (path, _) = Stored("<PluginConfiguration />", readable: true);
        var serializer = Substitute.For<IXmlSerializer>();
        serializer.DeserializeFromFile(Arg.Any<Type>(), Arg.Any<string>())
            .Returns(_ => throw new InvalidOperationException("There is an error in XML document (1, 10).", new IOException("device error")));

        var state = UnreadableConfiguration.Preserve(path, serializer, Logger(), DateTime.UtcNow);

        Assert.False(state.IsUnreadable);
        Assert.Empty(Copies(path));
        Assert.False(File.Exists(path + UnreadableConfiguration.MarkerSuffix));
    }

    [Fact]
    public void ASecondIncidentAfterARepair_IsCopiedInItsOwnRight()
    {
        // The dedup is per INCIDENT, keyed on the marker. Keyed on "some copy exists" instead, a second
        // failure months later would go uncopied while the log said it had been kept, and the operator
        // would be pointed at a stale artefact from a different incident - the feature failing on exactly
        // its second occurrence.
        var (path, damaged) = Stored("<PluginConfig", readable: false);
        UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 9, 6, 1, 2, 3, DateTimeKind.Utc));
        UnreadableConfiguration.ClearMarker(path, Logger());

        File.WriteAllText(path, "<DifferentDamage");
        var second = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 12, 1, 4, 5, 6, DateTimeKind.Utc));

        Assert.True(second.IsUnreadable);
        Assert.Equal(2, Copies(path).Length);
        Assert.Equal("<DifferentDamage", File.ReadAllText(second.PreservedCopyPath!));
    }

    [Fact]
    public void AnUndecidableReadWhileAMarkerStands_DoesNotRefuse()
    {
        // THE BOOT THIS FEATURE'S OWN RECOVERY STORY ENDS ON. The operator restores the backup over the
        // file and restarts; the marker is by construction still there, because this is the boot that
        // clears it. If the read cannot be MADE at that moment - the backup agent that just finished is
        // still holding the file - the answer is "I could not look", and it used to be carried into the
        // arm that asks whether the file holds a provider. That arm has no answer for it, read "no", and
        // latched 503 on every SSO sign-in for the whole process on a server whose providers, links and
        // secrets are correct and live on disk.
        var (path, damaged) = Stored("<PluginConfig", readable: false);
        Assert.True(UnreadableConfiguration.Preserve(path, damaged, Logger(), DateTime.UtcNow).IsUnreadable);

        var locked = Substitute.For<IXmlSerializer>();
        locked.DeserializeFromFile(Arg.Any<Type>(), Arg.Any<string>()).Returns(_ => throw new IOException("the file is in use"));

        var second = UnreadableConfiguration.Preserve(path, locked, Logger(), DateTime.UtcNow);

        Assert.False(second.IsUnreadable);

        // And it decided NOTHING rather than deciding the other way: the marker and the copy are untouched,
        // so the next start judges the same file again with nothing lost.
        Assert.True(File.Exists(path + UnreadableConfiguration.MarkerSuffix));
        Assert.Single(Copies(path));
    }

    [Fact]
    public void ASecondIncidentAfterAMarkerDeleteFailed_IsStillCopied()
    {
        // The dedup used to key on the marker EXISTING, and ClearMarker swallows a delete that fails - a
        // backup agent holding that one file, an ACL, a read-only mount. So a marker could outlive its
        // incident, and the next incident months later was read as a restart of the first: its damaged
        // bytes were never copied, the host overwrote them moments later, and the log named the FIRST
        // incident's file as the only surviving copy of the providers, links and secrets. Both halves of
        // that sentence were then false. The marker records which file it was written for, so this is a
        // different incident whatever the marker's presence says.
        var (path, damaged) = Stored("<PluginConfig", readable: false);
        UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 9, 6, 1, 2, 3, DateTimeKind.Utc));

        // The repair happened and the marker delete did not, so the marker stands over a new incident.
        File.WriteAllText(path, "<DifferentDamage");
        var second = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 12, 1, 4, 5, 6, DateTimeKind.Utc));

        // WHAT IS PINNED IS THAT THE BYTES SURVIVE, which is what was lost: the second incident's file is
        // copied in its own right rather than skipped because a marker happened to be lying there. Which
        // of the two the log LEADS with is a separate question and is the earliest of the chain, because
        // nothing on disk tells a stale marker apart from a boot loop whose file the host has since
        // rewritten - so both are kept and the log says to keep both.
        Assert.True(second.IsUnreadable);
        Assert.Equal(2, Copies(path).Length);
        Assert.Contains(Copies(path), copy => File.ReadAllText(copy) == "<DifferentDamage");
    }

    [Fact]
    public void ALaterBootNamesThisIncidentsCopy_AndNotTheOldestInTheDirectory()
    {
        // The copies are deliberately never deleted, so a directory accumulates them across incidents. The
        // name to give an operator is the one THIS incident produced; the oldest in the directory is a
        // months-old artefact holding a different configuration, and telling somebody to recover from it -
        // and to protect it rather than the file that matters - is worse than saying nothing.
        var (path, damaged) = Stored("<PluginConfig", readable: false);
        UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 9, 6, 1, 2, 3, DateTimeKind.Utc));
        UnreadableConfiguration.ClearMarker(path, Logger());

        File.WriteAllText(path, "<DifferentDamage");
        var current = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 12, 1, 4, 5, 6, DateTimeKind.Utc));

        // The host has now written its defaults over the file, so the next boot reads it back and has only
        // the marker to go on.
        File.WriteAllText(path, "<PluginConfiguration />");
        var healthy = Substitute.For<IXmlSerializer>();
        healthy.DeserializeFromFile(Arg.Any<Type>(), Arg.Any<string>()).Returns(new PluginConfiguration());

        var later = UnreadableConfiguration.Preserve(path, healthy, Logger(), DateTime.UtcNow);

        Assert.True(later.IsUnreadable);
        Assert.Equal(current.PreservedCopyPath, later.PreservedCopyPath);
        Assert.NotEqual(Copies(path).OrderBy(name => name, StringComparer.Ordinal).First(), later.PreservedCopyPath);
    }

    [Fact]
    public void ACopyThatFailed_IsReportedAsNoneAndNeverAsAnEarlierIncidentsFile()
    {
        // THE BRANCH THE MARKER RECORD DID NOT REACH AT FIRST. A copy that cannot be written leaves a
        // marker recording the incident and NO copy, and reading that as "this marker records nothing"
        // sent the directory scan looking - which after an earlier, repaired incident finds THAT copy and
        // names it as the surviving copy of this one. The operator is then told to recover from, and to
        // protect, a months-old file holding different providers, different links and different secret
        // envelopes. Null is the truth here and the log says "not written".
        var (path, damaged) = Stored("<PluginConfig", readable: false);
        UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 9, 6, 1, 2, 3, DateTimeKind.Utc));
        UnreadableConfiguration.ClearMarker(path, Logger());

        // A second incident whose copy cannot be written: the name it would take is already occupied, and
        // the copy is never made over an existing file.
        File.WriteAllText(path, "<DifferentDamage");
        File.WriteAllText(path + UnreadableConfiguration.CopySuffix + "20261201-040506Z", "in the way");
        var incident = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 12, 1, 4, 5, 6, DateTimeKind.Utc));

        Assert.True(incident.IsUnreadable);
        Assert.Null(incident.PreservedCopyPath);

        // The host has now written its defaults over the file, so this boot has only the marker to go on.
        File.WriteAllText(path, "<PluginConfiguration />");
        var healthy = Substitute.For<IXmlSerializer>();
        healthy.DeserializeFromFile(Arg.Any<Type>(), Arg.Any<string>()).Returns(new PluginConfiguration());

        var later = UnreadableConfiguration.Preserve(path, healthy, Logger(), DateTime.UtcNow);

        Assert.True(later.IsUnreadable);
        Assert.Null(later.PreservedCopyPath);
    }

    [Fact]
    public void AFileMovedAsideWhileTheMarkerStands_StillServesDefaults()
    {
        // Half of the break-glass instruction. It says to move the unreadable file out of the way AND to
        // delete the marker; doing only the first leaves an unrepaired incident recorded over a server
        // that will be handed a default configuration the moment anything reads it. Refusing is the honest
        // answer, and this pins it rather than leaving it as a side effect of a missing file reading like
        // a first start.
        var (path, damaged) = Stored("<PluginConfig", readable: false);
        Assert.True(UnreadableConfiguration.Preserve(path, damaged, Logger(), DateTime.UtcNow).IsUnreadable);

        File.Delete(path);

        Assert.True(UnreadableConfiguration.Preserve(path, damaged, Logger(), DateTime.UtcNow).IsUnreadable);

        // And deleting the marker as well is what ends it, which is what the log and the page both say.
        UnreadableConfiguration.ClearMarker(path, Logger());
        Assert.False(UnreadableConfiguration.Preserve(path, damaged, Logger(), DateTime.UtcNow).IsUnreadable);
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
