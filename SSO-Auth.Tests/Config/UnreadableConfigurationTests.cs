// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Globalization;
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

        // AND THIS INCIDENT'S BYTES ARE STILL KEPT, which is the half this test did not assert until the
        // twelfth review. Never overwriting is one rule and abandoning the copy is another: the old code
        // composed one name, met it taken, and returned "no copy kept" - after which the host wrote its
        // defaults over the file and no later boot reached this arm again, because by then the file reads
        // back. The name is walked past instead.
        Assert.NotNull(state.PreservedCopyPath);
        Assert.Equal("second boot", File.ReadAllText(state.PreservedCopyPath!));
    }

    [Fact]
    public void ACopyNameTakenByAnotherIncident_IsDisambiguatedRatherThanAbandoned()
    {
        // The falsifier for the pair of assertions above, on the state that produces them: a host whose
        // wall clock repeats a second across boots - no RTC, a read-only rootfs, a snapshot restored again
        // and again - or two instances sharing one plugin-configuration directory. AlreadyCopied has
        // already said no file there holds THESE bytes, so the occupant is a different fault's file, and
        // the answer is another name rather than no copy at all.
        var (path, serializer) = Stored("<SecondDamage", readable: false);
        var at = new DateTime(2026, 9, 6, 1, 2, 3, DateTimeKind.Utc);
        File.WriteAllText(path + UnreadableConfiguration.CopySuffix + "20260906-010203Z", "<FirstDamage");

        var state = UnreadableConfiguration.Preserve(path, serializer, Logger(), at);

        Assert.Equal(path + UnreadableConfiguration.CopySuffix + "20260906-010203Z.1", state.PreservedCopyPath);
        Assert.Equal("<SecondDamage", File.ReadAllText(state.PreservedCopyPath!));
        Assert.Equal("<FirstDamage", File.ReadAllText(path + UnreadableConfiguration.CopySuffix + "20260906-010203Z"));
    }

    [Fact]
    public void AnAlteredRecordedCopy_IsTakenAgainRatherThanCountedAsKept()
    {
        // THE RECORD MAY NOT OUTRANK THE BYTES. The marker's Kept only proved the recorded copy still
        // EXISTS, and existence is the wrong question: the log invites an operator to work on the
        // timestamped copy, so the natural repair loop - open it, fix the truncated XML, save it back -
        // leaves a file that exists and no longer holds the damage. The same disk that truncated the
        // configuration can empty it too. On that boot the copy was reused, no second one was taken, and
        // the Error line said the bytes had been kept; then the host wrote defaults over the file and the
        // only artefact a repair could work on was gone. This is the sibling of
        // ARecordedCopyThatIsGone_IsTakenAgainRatherThanCountedAsKept with one verb changed.
        var (path, damaged) = Stored("<PluginConfig", readable: false);
        var first = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 9, 6, 1, 2, 3, DateTimeKind.Utc));
        Assert.NotNull(first.PreservedCopyPath);

        File.WriteAllText(first.PreservedCopyPath!, string.Empty);

        var second = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 9, 6, 4, 5, 6, DateTimeKind.Utc));

        Assert.True(second.IsUnreadable);
        Assert.Equal(path + UnreadableConfiguration.CopySuffix + "20260906-040506Z", second.PreservedCopyPath);
        Assert.Equal("<PluginConfig", File.ReadAllText(second.PreservedCopyPath!));
    }

    [Fact]
    public void ARepeatBootWhoseBytesCannotBeRead_KeepsTheRecordedCopyRatherThanLosingIt()
    {
        // A COMPARISON THAT COULD NOT BE MADE DECIDES NOTHING, which is the rule the undecidable-read arm
        // already states one level up. Verifying the recorded copy is right; answering "not the same" when
        // the files could not be compared AT ALL is not, and what it costs is the record: no second copy is
        // possible on that fault either, so rewriting the marker with an empty copy line only erases the
        // pointer to the copy that already exists, and the next boot tells an operator nothing was kept
        // while it sits beside the configuration.
        //
        // WHAT MAKES THIS UNDECIDABLE AND NOT MERELY UNREAD is that the lengths still match and it is the
        // DAMAGED file that cannot be opened; a length that differs is refused on its own, and a candidate
        // that is what cannot be opened is refused too, which the two tests below pin. A share-denying
        // handle on the configuration produces the pair here: the serializer reports damage about the
        // CONTENT while the file itself cannot be opened for the compare.
        var (path, damaged) = Stored("<PluginConfig", readable: false);
        var first = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 9, 6, 1, 2, 3, DateTimeKind.Utc));
        Assert.NotNull(first.PreservedCopyPath);

        using (File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            for (var boot = 0; boot < 3; boot++)
            {
                var state = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 12, 1, 0, 0, boot, DateTimeKind.Utc));

                Assert.True(state.IsUnreadable);
                Assert.Equal(first.PreservedCopyPath, state.PreservedCopyPath);
            }
        }

        // The marker still points at the copy, which is the half that was being erased. The copy COUNT is
        // deliberately not asserted here: the same handle that stops the compare stops File.Copy, so it
        // could not move in this fixture and asserting it would prove nothing.
        Assert.Contains(first.PreservedCopyPath!, File.ReadAllText(path + UnreadableConfiguration.MarkerSuffix), StringComparison.Ordinal);
    }

    [Fact]
    public void ARecordedCopyOfADifferentLength_IsRefusedEvenWhenTheDamageCannotBeRead()
    {
        // THE LENGTH DECIDES ON ITS OWN, and that is what keeps a decided "no" available on the boot the
        // bytes are unreachable. Believing the record whenever the comparison could not be made is
        // File.Exists again - the predicate the verification was added to replace - and the two shapes it
        // exists to catch both change the length: a copy emptied by the same full disk, and a copy an
        // operator opened and saved a repaired document over. A stat answers that without opening either
        // file, so the answer here is the truthful "no copy was kept" rather than a false one naming a
        // file that no longer holds the damage.
        var (path, damaged) = Stored("<PluginConfig", readable: false);
        var first = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 9, 6, 1, 2, 3, DateTimeKind.Utc));
        Assert.NotNull(first.PreservedCopyPath);
        File.WriteAllText(first.PreservedCopyPath!, string.Empty);

        using (File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            var state = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 12, 1, 0, 0, 0, DateTimeKind.Utc));

            Assert.True(state.IsUnreadable);
            Assert.Null(state.PreservedCopyPath);
        }
    }

    [Fact]
    public void ARecordedCopyThatCannotBeReadWhileTheDamageCan_IsTakenAgain()
    {
        // THE OTHER SIDE OF UNDECIDABLE, and the falsifier for the test above. There the DAMAGED file is
        // what cannot be opened, and believing the record costs nothing because no copy could have been
        // written either. Here the damage is readable and only the recorded copy is not - an ACL a restore
        // left behind, a bad block under the copy, the backup agent a restore just woke - so a copy IS
        // writable, and this is the one boot on which the bytes still exist before the host writes its
        // defaults over them. Treating the two the same left an unreadable file named as the copy that was
        // kept, with nothing behind it.
        var (path, damaged) = Stored("<PluginConfig", readable: false);
        var first = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 9, 6, 1, 2, 3, DateTimeKind.Utc));
        Assert.NotNull(first.PreservedCopyPath);

        using (File.Open(first.PreservedCopyPath!, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            var second = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 12, 1, 0, 0, 0, DateTimeKind.Utc));

            Assert.Equal(path + UnreadableConfiguration.CopySuffix + "20261201-000000Z", second.PreservedCopyPath);
            Assert.Equal("<PluginConfig", File.ReadAllText(second.PreservedCopyPath!));
            Assert.Equal(2, Copies(path).Length);
        }
    }

    [Fact]
    public void ARecordedCopyThatCannotBeRead_KeepsItsRecordWhenNoNewCopyCanBeWritten()
    {
        // THE PREMISE IS ABOUT WHAT CAN BE ATTEMPTED, NOT ABOUT WHAT SUCCEEDS. A candidate that cannot be
        // read means the damage is readable and a copy is writable, so one is taken - and on the full disk
        // this feature is named after, the attempt fails. Handing that failure on to the marker erased the
        // only pointer to a copy that still exists, still belongs to this incident and still has the
        // damaged file's length, on the boot after which the host overwrites the configuration; every later
        // boot then told the operator that no copy had been kept while it lay beside the file. The record
        // is the last resort HERE and only here: a decided "different" - the test above - must still not be
        // named as this damage.
        var (path, damaged) = Stored("<PluginConfig", readable: false);
        var first = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 9, 6, 1, 2, 3, DateTimeKind.Utc));
        Assert.NotNull(first.PreservedCopyPath);

        // A directory where this boot's copy would go, so File.Copy cannot write it.
        Directory.CreateDirectory(path + UnreadableConfiguration.CopySuffix + "20261201-000000Z");

        using (File.Open(first.PreservedCopyPath!, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            var second = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 12, 1, 0, 0, 0, DateTimeKind.Utc));

            Assert.True(second.IsUnreadable);
            Assert.Equal(first.PreservedCopyPath, second.PreservedCopyPath);
            Assert.Contains(first.PreservedCopyPath!, File.ReadAllText(path + UnreadableConfiguration.MarkerSuffix), StringComparison.Ordinal);
        }
    }

    [Fact]
    public void ACandidateCopyThatCannotBeRead_DoesNotAbandonTheWalk()
    {
        // THE BOUND IS PER CANDIDATE, NOT PER WALK. One try around the whole scan answered "no copy" for
        // the entire directory as soon as any candidate could not be read - and the candidate guaranteed
        // to be read is this incident's own copy, because a genuine copy has the damaged file's length by
        // construction. So one further fault, of the kind this module names everywhere else - an ACL a
        // restore left behind, a bad block on the disk that caused the damage, an agent holding the file -
        // took the bound off entirely and every later boot wrote another full copy of the configuration
        // into the directory the whole server needs writable.
        var (path, damaged) = Stored("<PluginConfig", readable: false);
        UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 9, 6, 1, 2, 3, DateTimeKind.Utc));

        // A second candidate of exactly the damaged file's length that cannot be read, and the marker gone
        // so the recorded-copy shortcut cannot answer instead of the walk.
        var unreadableCandidate = path + UnreadableConfiguration.CopySuffix + "20260101-000000Z";
        File.WriteAllText(unreadableCandidate, "<PluginConfig");
        UnreadableConfiguration.ClearMarker(path, Logger());

        using (File.Open(unreadableCandidate, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            for (var boot = 0; boot < 4; boot++)
            {
                var state = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 12, 1, 0, 0, boot, DateTimeKind.Utc));

                Assert.True(state.IsUnreadable);
                Assert.Equal(path + UnreadableConfiguration.CopySuffix + "20260906-010203Z", state.PreservedCopyPath);
                UnreadableConfiguration.ClearMarker(path, Logger());
            }
        }

        Assert.Equal(2, Copies(path).Length);
    }

    [Fact]
    public void APluginWhoseLogSinkThrows_StillRefuses()
    {
        // THE ANNOUNCEMENT MAY NOT UNDO THE DECISION. The trigger the constructor's own comment names is a
        // full disk that truncates the configuration AND takes the file log sink with it, so the Error
        // line this screen writes throws. The screen had already decided, copied and marked by then; an
        // exception escaping it reached the constructor's catch, whose answer is "not unreadable", and a
        // decided refusal became a server accepting every SSO sign-in and answering "no matching provider"
        // for the life of the process - while the marker on disk said the opposite and the next boot
        // refused again. Fail-open on a control whose whole posture is fail-closed.
        var root = Path.Combine(Path.GetTempPath(), "sso-unreadable-" + Guid.NewGuid());
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "SSO-Auth.xml");
        File.WriteAllText(path, "<PluginConfig");

        var appPaths = Substitute.For<IApplicationPaths>();
        appPaths.PluginConfigurationsPath.Returns(root);
        appPaths.PluginsPath.Returns(Path.Combine(root, "plugins"));

        var serializer = Substitute.For<IXmlSerializer>();
        serializer.DeserializeFromFile(Arg.Any<Type>(), Arg.Any<string>()).Returns(_ => throw new InvalidOperationException("truncated"));

        var logger = Substitute.For<ILogger<SSOPlugin>>();
        logger.IsEnabled(Arg.Any<LogLevel>()).Returns(true);
        logger
            .When(l => l.Log(Arg.Any<LogLevel>(), Arg.Any<EventId>(), Arg.Any<Arg.AnyType>(), Arg.Any<Exception?>(), Arg.Any<Func<Arg.AnyType, Exception?, string>>()))
            .Do(_ => throw new IOException("no space left on device"));

        var plugin = new SSOPlugin(appPaths, serializer, logger);

        Assert.True(plugin.ServingDefaultConfiguration);
        Assert.True(File.Exists(path + UnreadableConfiguration.MarkerSuffix));
        Assert.Equal("<PluginConfig", File.ReadAllText(Assert.Single(Copies(path))));
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

        // The bytes survive AND the log names them. A marker records the copy of ITS OWN incident and
        // inherits nothing from the one before it: inheriting looks tidy and names a months-old file
        // holding different providers as this incident's kept copy.
        Assert.True(second.IsUnreadable);
        Assert.Equal(2, Copies(path).Length);
        Assert.Equal("<DifferentDamage", File.ReadAllText(second.PreservedCopyPath!));
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

        // A second incident whose copy cannot be written. A DIRECTORY at the name, which File.Copy cannot
        // write over on any platform - and NOT a file at the name, which is a different thing entirely and
        // is what this fixture used to do: a taken name is now walked past rather than surrendered to, so
        // occupying it with a file no longer stops the copy and this test would have been proving that a
        // written copy is reported as none.
        File.WriteAllText(path, "<DifferentDamage");
        Directory.CreateDirectory(path + UnreadableConfiguration.CopySuffix + "20261201-040506Z");
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

    [Fact]
    public void ACopyThatFailedUnderAStaleMarker_IsRetriedOnTheNextBoot()
    {
        // The two failures of this area meeting at once: a marker whose delete failed after an earlier
        // repair, and a new damage whose first copy attempt fails - the full disk, which is the same disk
        // that caused the damage. What must NOT happen is the marker deciding that a copy is already kept,
        // because the only copy it knows is the earlier incident's: the retry stops, the host overwrites
        // the damaged file, and the bytes this whole screen exists to keep are gone while the log names
        // somebody else's configuration.
        var (path, damaged) = Stored("<PluginConfig", readable: false);
        UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 9, 6, 1, 2, 3, DateTimeKind.Utc));

        // Repaired, and the marker delete failed, so it stands over what follows.
        File.WriteAllText(path, "<DifferentDamage");

        // The first attempt of the new incident cannot write its copy: a directory stands where it would
        // go, which File.Copy cannot write over. A FILE at that name is not this case - a taken name is
        // walked past now, not surrendered to - and using one here would have pinned a copy that was
        // written as a copy that failed.
        Directory.CreateDirectory(path + UnreadableConfiguration.CopySuffix + "20261201-040506Z");
        var firstAttempt = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 12, 1, 4, 5, 6, DateTimeKind.Utc));

        Assert.True(firstAttempt.IsUnreadable);
        Assert.Null(firstAttempt.PreservedCopyPath);

        // Same file, next boot: the copy is attempted again, and this time its name is free.
        var retried = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 12, 1, 7, 8, 9, DateTimeKind.Utc));

        Assert.True(retried.IsUnreadable);
        Assert.Equal(path + UnreadableConfiguration.CopySuffix + "20261201-070809Z", retried.PreservedCopyPath);
        Assert.Equal("<DifferentDamage", File.ReadAllText(retried.PreservedCopyPath!));
    }

    [Fact]
    public void AConfigurationWhoseProviderMapsAreNull_IsNotDamage()
    {
        // THE SCREEN'S OWN FAULT MUST NOT BE REPORTED AS THE FILE'S. The two provider maps are read inside
        // the try whose catch means "the content is damaged", so a null map - which every other reader in
        // this plugin tolerates, and which the suite feeds through the save path on purpose - would be
        // announced as a damaged configuration, copied aside, marked, and answered with 503 on every SSO
        // sign-in. And it would not end: the host never touches these members, so it never rewrites the
        // file, so every boot repeats it until an administrator who can still sign in intervenes.
        var root = Path.Combine(Path.GetTempPath(), "sso-unreadable-" + Guid.NewGuid());
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "SSO-Auth.xml");
        File.WriteAllText(path, "<PluginConfiguration />");

        var serializer = Substitute.For<IXmlSerializer>();
        serializer.DeserializeFromFile(Arg.Any<Type>(), Arg.Any<string>())
            .Returns(new PluginConfiguration { OidConfigs = null!, SamlConfigs = null! });

        var state = UnreadableConfiguration.Preserve(path, serializer, Logger(), DateTime.UtcNow);

        Assert.False(state.IsUnreadable);
        Assert.Empty(Copies(path));
        Assert.False(File.Exists(path + UnreadableConfiguration.MarkerSuffix));
    }

    [Fact]
    public void ARecordedCopyThatIsGone_IsTakenAgainRatherThanCountedAsKept()
    {
        // The log invites an operator to keep the timestamped copy, and some of them will move it to a
        // workstation to look at it. If the marker's recorded name were believed without checking, the
        // next boot of the same incident would count a copy as already kept and never take another - so
        // moving the evidence somewhere safe would be what destroys it, since the host overwrites the
        // damaged file regardless.
        var (path, damaged) = Stored("<PluginConfig", readable: false);
        var first = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 9, 6, 1, 2, 3, DateTimeKind.Utc));
        Assert.NotNull(first.PreservedCopyPath);

        File.Delete(first.PreservedCopyPath!);

        var second = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 9, 6, 4, 5, 6, DateTimeKind.Utc));

        Assert.True(second.IsUnreadable);
        Assert.Equal(path + UnreadableConfiguration.CopySuffix + "20260906-040506Z", second.PreservedCopyPath);
        Assert.Equal("<PluginConfig", File.ReadAllText(second.PreservedCopyPath!));
    }

    [Fact]
    public void AMarkerThatCannotBeRead_StillCopiesOnceAndOnlyOnce()
    {
        // The only unbounded path this screen had, and the bound must not be "stop copying". A marker
        // that is THERE and cannot be read - held open by another process, an ACL a restore left behind,
        // an IO error on the volume - answers "no record", which is read everywhere else here as a new
        // incident, so every restart would take another full copy into the directory the whole server
        // needs writable, on the disk that caused the damage.
        //
        // Declining to copy would bound it and is the wrong trade: the conditions that stop a marker
        // being READ are the conditions that stop it being DELETED, so an unreadable marker and one that
        // outlived its incident are one fault - and on that fault a genuinely new damage would go
        // unpreserved for good. So the bound is asked of the copies instead: the same bytes are already
        // kept, whatever the marker can or cannot say.
        var (path, damaged) = Stored("<PluginConfig", readable: false);
        var first = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 9, 6, 1, 2, 3, DateTimeKind.Utc));
        Assert.Single(Copies(path));

        using (File.Open(path + UnreadableConfiguration.MarkerSuffix, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            for (var boot = 0; boot < 4; boot++)
            {
                var state = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 12, 1, 0, 0, boot, DateTimeKind.Utc));

                Assert.True(state.IsUnreadable);
                Assert.Equal(first.PreservedCopyPath, state.PreservedCopyPath);
            }
        }

        Assert.Single(Copies(path));
    }

    [Fact]
    public void AMarkerThatCannotBeRead_StillPreservesADifferentDamage()
    {
        // The other half, and the one the bound must not cost. On the same unreadable marker, a file that
        // is not the one already kept is a different incident whatever the marker can say, and its bytes
        // are the only copy of a configuration that is about to be overwritten with defaults.
        var (path, damaged) = Stored("<PluginConfig", readable: false);
        UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 9, 6, 1, 2, 3, DateTimeKind.Utc));

        using (File.Open(path + UnreadableConfiguration.MarkerSuffix, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            File.WriteAllText(path, "<DifferentDamage");
            var state = UnreadableConfiguration.Preserve(path, damaged, Logger(), new DateTime(2026, 12, 1, 4, 5, 6, DateTimeKind.Utc));

            Assert.True(state.IsUnreadable);
            Assert.Equal("<DifferentDamage", File.ReadAllText(state.PreservedCopyPath!));
        }

        Assert.Equal(2, Copies(path).Length);
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
