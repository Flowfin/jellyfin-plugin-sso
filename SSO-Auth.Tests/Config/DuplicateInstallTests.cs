// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Coverage for noticing a second copy of this plugin in the same server, and for the one copy of the
/// configuration that is taken before the host can overwrite it (#1601).
/// </summary>
public class DuplicateInstallTests
{
    private static readonly DateTime Noon = new(2026, 9, 10, 12, 0, 0, DateTimeKind.Utc);

    private static readonly string[] TwoCopies =
    {
        "/config/plugins/Community SSO for Jellyfin_5.0.0.75/SSO-Auth.dll",
        "/config/plugins/Community SSO for Jellyfin_5.0.0.81/SSO-Auth.dll",
    };

    [Fact]
    public void InAProcessHoldingOneCopy_ItReportsNoDuplicate()
    {
        // The direction that matters, asked of the real loader. A missed duplicate leaves the server
        // exactly as it was before this check existed; a false positive refuses every configuration write
        // on a healthy server, which is an outage this check invented.
        WithConfigurationFile(path =>
        {
            var state = DuplicateInstall.Detect(path, Noon);

            Assert.False(state.IsDuplicated);
            Assert.Null(state.PreservedCopyPath);
            Assert.Empty(Copies(path));
        });
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void BelowTwoCopies_ItDecidesNoDuplicateAndTouchesNothing(int copies)
    {
        // Zero is what a loader question that could not be answered returns, and it has to read as "no
        // duplicate" rather than as "no copies, so something is wrong": the safe answer is the one that
        // leaves the server alone.
        WithConfigurationFile(path =>
        {
            var state = DuplicateInstall.Decide(TwoCopies.Take(copies).ToList(), path, Noon);

            Assert.False(state.IsDuplicated);
            Assert.Null(state.PreservedCopyPath);
            Assert.Empty(Copies(path));
        });
    }

    [Fact]
    public void WithTwoCopies_ItDecidesDuplicateAndCopiesTheConfiguration()
    {
        WithConfigurationFile(path =>
        {
            var state = DuplicateInstall.Decide(TwoCopies, path, Noon);

            Assert.True(state.IsDuplicated);
            Assert.Equal(2, state.Locations.Count);
            Assert.NotNull(state.PreservedCopyPath);
            Assert.Equal(File.ReadAllText(path), File.ReadAllText(state.PreservedCopyPath!));
            Assert.Single(Copies(path));
        });
    }

    [Fact]
    public void ASecondBootKeepsTheFirstCopyRatherThanTakingItsOwn()
    {
        // The property the whole file turns on. A server left in this state boots again and again, and by
        // the second boot the file on disk is already the empty one the host wrote. Copying again would
        // bury the only version worth having under a stack of empty ones.
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

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("SSO-Auth.xml")]
    public void WithNoUsableConfigurationPath_ItCopiesNothing(string? path)
    {
        // The host composes this path from the application paths, and a harness or an early boot can leave
        // it empty or bare. Every shape of that must be a no-op rather than an exception out of a plugin
        // constructor, which would take every SSO login on the server offline.
        Assert.Null(DuplicateInstall.Preserve(path, Noon));
    }

    [Fact]
    public void WhenTheCopyCannotBeWritten_ItAnswersNothingRatherThanThrowing()
    {
        // The realistic trigger is a full or read-only volume, which is also when the operator can least
        // afford a plugin that fails to load. Arranged here by taking the copy's name with a directory,
        // which File.Copy refuses the same way.
        WithConfigurationFile(path =>
        {
            Directory.CreateDirectory(path + DuplicateInstall.CopySuffix + "20260910-120000Z");

            Assert.Null(DuplicateInstall.Preserve(path, Noon));
        });
    }

    [Fact]
    public void TheLineNamesBothCopiesAndCollapsesARepeatedPath()
    {
        var line = DuplicateInstall.Name(new[] { "/b/SSO-Auth.dll", "/a/SSO-Auth.dll", "/a/SSO-Auth.dll" });

        Assert.Equal("/a/SSO-Auth.dll AND /b/SSO-Auth.dll", line);
    }

    [Fact]
    public void TheLineNamesACopyWithNoFileBehindIt()
    {
        // A dynamic assembly has no location, and dropping it would leave a line about two copies naming
        // one path, which reads as a different fault than the one being reported.
        var line = DuplicateInstall.Name(new[] { "/a/SSO-Auth.dll", string.Empty });

        Assert.Equal("(unnamed) AND /a/SSO-Auth.dll", line);
    }

    [Fact]
    public void WithNoDuplicate_ItSaysNothing()
    {
        var logger = new CapturingLogger();

        DuplicateInstall.Announce(DuplicateInstall.Decide(Array.Empty<string>(), null, Noon), logger);

        Assert.Empty(logger.Entries);
    }

    [Fact]
    public void WithADuplicate_ItNamesBothDirectoriesAndTheCopy()
    {
        // The line IS the repair instruction: an admin told there are two copies but not where they are
        // has been told half of it, and one told nothing about the copy cannot restore from it.
        WithConfigurationFile(path =>
        {
            var logger = new CapturingLogger();
            var state = DuplicateInstall.Decide(TwoCopies, path, Noon);

            DuplicateInstall.Announce(state, logger);

            var entry = Assert.Single(logger.Entries);
            Assert.Equal(LogLevel.Error, entry.Level);
            Assert.Contains(TwoCopies[0], entry.Message, StringComparison.Ordinal);
            Assert.Contains(TwoCopies[1], entry.Message, StringComparison.Ordinal);
            Assert.Contains(state.PreservedCopyPath!, entry.Message, StringComparison.Ordinal);
        });
    }

    [Fact]
    public void WithADuplicateAndNoCopyTaken_ItSaysThatToo()
    {
        // The negative disclosure. An operator told a copy exists when none does looks for a file that is
        // not there, on the one path where the file is the only thing left.
        var logger = new CapturingLogger();

        DuplicateInstall.Announce(DuplicateInstall.Decide(TwoCopies, null, Noon), logger);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Error, entry.Level);
        Assert.Contains("NO copy of the configuration was kept", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void WithErrorLoggingOff_ItBuildsNoLine()
    {
        // The line is composed from paths, so it costs something to build, and it is written from a plugin
        // constructor on a server that may have the sink turned down. The level is asked before the
        // arguments are touched, and a sink that is off gets nothing rather than a formatted entry it
        // discards.
        var logger = new SilentLogger();

        DuplicateInstall.Announce(DuplicateInstall.Decide(TwoCopies, null, Noon), logger);

        Assert.Empty(logger.Records);
    }

    [Fact]
    public void ALoggerThatThrowsCostsTheLineAndNotTheLoad()
    {
        // This runs inside a plugin constructor. Anything that escapes it fails the plugin load and takes
        // every SSO login on the server offline, and the one failure realistic here is the log sink itself
        // going down with the same full disk that caused the fault.
        DuplicateInstall.Announce(DuplicateInstall.Decide(TwoCopies, null, Noon), new ThrowingLogger());
    }

    private sealed class SilentLogger : ILogger
    {
        internal List<string> Records { get; } = new();

        public IDisposable BeginScope<TState>(TState state)
            where TState : notnull => null!;

        public bool IsEnabled(LogLevel logLevel) => false;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Records.Add(formatter(state, exception));
    }

    private sealed class ThrowingLogger : ILogger
    {
        public IDisposable BeginScope<TState>(TState state)
            where TState : notnull => null!;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => throw new IOException("the sink is on the disk that just filled up");
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
