// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using Jellyfin.Plugin.SSO_Auth.Api.Routing;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Identity;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Model.Plugins;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <content>
/// Conformance rules for the source-file rules: the SPDX header on every file, and parse-surface assertions never reaching the shipped build.
/// </content>
public partial class ArchitectureConformanceTests
{
    [Fact]
    public void EverySourceFile_CarriesTheSpdxHeader()
    {
        // #747: every C# source file opens with the SPDX copyright + licence header, so the licence of any
        // one file is machine-readable at its top (REUSE / SPDX) and a new file cannot land without it.
        // GPL-3.0-only is the project's SPDX identifier - it matches the declared "GPL v3.0" exactly, with no
        // implicit "or later" broadening; the copyright line credits the authors collectively. This test is
        // the drift guard that keeps the headers complete: a file added without the two opening lines fails
        // CI here (the header must be the first two lines so it precedes the usings and the file-scoped
        // namespace, which SPDX/REUSE tooling expects).
        const string CopyrightLine = "// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors";
        const string LicenceLine = "// SPDX-License-Identifier: GPL-3.0-only";
        var roots = ProjectRoots();
        var sources = roots
            .SelectMany(root => Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories))
            .Where(src => !IsBuildOutput(src))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // The liveness floor. A derived root set can silently become empty - a rename, a project moved, a
        // repository root resolved one directory too high - and an empty scan reports no offenders, which
        // reads exactly like a tree where every file carries its header. Both halves are floored, and both
        // sit well under the real counts so an ordinary project or file being added or removed never moves
        // them; this must fail when the DERIVATION breaks, not when the tree changes shape. Two is the floor
        // rather than today's count because the non-shipping projects are the ones that come and go, while
        // the plugin and this test project cannot both leave without taking this rule with them.
        Assert.True(
            roots.Count >= 2,
            $"The SPDX root derivation found only {roots.Count} project directories; it has stopped seeing the tree, and this rule would now pass over the projects it no longer walks (#1270).");
        Assert.True(
            sources.Count >= 100,
            $"The SPDX scan found only {sources.Count} C# files under the derived roots; the walk has broken and a missing header would no longer be seen (#1270).");

        var offenders = new List<string>();
        foreach (var src in sources)
        {
            var firstLines = File.ReadLines(src).Take(2).ToList();
            if (firstLines.Count < 2
                || firstLines[0].Trim() != CopyrightLine
                || firstLines[1].Trim() != LicenceLine)
            {
                offenders.Add(Path.GetFileName(src));
            }
        }

        Assert.True(
            offenders.Count == 0,
            "Every C# source file must open with the SPDX copyright + GPL-3.0-only header (#747). Missing or incorrect in: " + string.Join(", ", offenders));
    }

    // Every directory in the tree that owns a C# project, derived from the project files themselves rather
    // than listed (#1270). A literal list is the defect and not the fix: adding a root is a step somebody
    // has to remember, and the project that lands while nobody remembers is the one carrying the unheaded
    // file. Deriving it means a new project of the same shape - non-shipping, outside the solution, ordinary
    // C# source - is covered on the day it lands, without this rule being edited.
    private static IReadOnlyList<string> ProjectRoots() =>
        Directory.EnumerateFiles(RepoTree.Root, "*.csproj", SearchOption.AllDirectories)
            .Where(project => !IsBuildOutput(project))
            .Select(project => Path.GetDirectoryName(project)!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(root => root, StringComparer.Ordinal)
            .ToList();

    [Fact]
    public void ParseSurfaceAssertions_NeverReachTheShippedBuild()
    {
        // #1082. The parse surface carries post-conditions so a silent mis-parse becomes a detectable fault
        // under an assertion-enabled fuzzing build. They are Debug.Assert, which the compiler removes from a
        // build without DEBUG, and that removal is the whole reason they are allowed on an authentication
        // path at all: a post-condition that fired in a running server would take a login down over a
        // condition the fail-closed paths already handle.
        //
        // WHAT THIS RULE DOES NOT DO, stated first because the name invites the wrong reading: it does not
        // re-prove that [Conditional("DEBUG")] strips a call. That is the compiler's contract, and the
        // evidence for it is the IL differential recorded on the issue, not a source scan. What this rule
        // holds are the two ways the tree itself could defeat that contract.
        var pluginSources = Directory
            .EnumerateFiles(Path.Combine(RepoTree.Root, "SSO-Auth"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path))
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            pluginSources.Count > 0,
            "No plugin source file was found under SSO-Auth - the project moved, so this rule would pass vacuously (#1082).");

        // The first way. Trace.Assert and Trace.Fail look like the same thing and are not: they are
        // [Conditional("TRACE")], and TRACE is defined in a Release build by default, so one of these written
        // by habit next to a Debug.Assert ships. It would then abort or dialog on whatever the fuzzer was
        // meant to catch quietly, on the unauthenticated callback, in production.
        var survivingAssertions = pluginSources
            .SelectMany(path => CodeLines(path)
                .Where(l => l.Text.Contains("Trace.Assert(", StringComparison.Ordinal)
                    || l.Text.Contains("Trace.Fail(", StringComparison.Ordinal))
                .Select(l => $"{Path.GetFileName(path)}:{l.Number}: {l.Text}"))
            .ToList();

        Assert.True(
            survivingAssertions.Count == 0,
            "Trace.Assert / Trace.Fail are [Conditional(\"TRACE\")] and TRACE is defined in Release, so they ship - use Debug.Assert for a parse-surface post-condition (#1082). Offending lines: " + string.Join(" | ", survivingAssertions));

        // The second way. Defining DEBUG for the shipping build carries every Debug.Assert into the shipped
        // assembly, and it is a one-word edit in a file nobody rereads. A DefineConstants that mentions DEBUG
        // is therefore refused outright here rather than parsed for its condition: the plugin's build files
        // define no constants at all today, so the honest rule is that they define none, and anyone who needs
        // one comes here to say why.
        var buildFiles = new[] { Path.Combine(RepoTree.Root, "Directory.Build.props"), Path.Combine(RepoTree.Root, "SSO-Auth", "SSO-Auth.csproj") }
            .Where(File.Exists)
            .ToList();

        Assert.Equal(2, buildFiles.Count);

        var debugDefiners = buildFiles
            .Where(path => File.ReadAllText(path).Contains("DefineConstants", StringComparison.Ordinal))
            .Select(Path.GetFileName)
            .ToList();

        Assert.True(
            debugDefiners.Count == 0,
            "The plugin's build files must define no compilation constants: a DEBUG among them carries every parse-surface Debug.Assert into the shipped assembly (#1082). Offending files: " + string.Join(", ", debugDefiners));

        // Sentinel against a vacuous pass. Both bans above guard something only while the post-conditions
        // exist. If they were deleted, the rule would keep passing over a plugin that asserts nothing, and
        // the fuzzing configuration that runs with assertions on would be running them against nothing.
        var assertionSites = pluginSources
            .SelectMany(path => CodeLines(path)
                .Where(l => l.Text.Contains("Debug.Assert(", StringComparison.Ordinal))
                .Select(l => $"{Path.GetFileName(path)}:{l.Number}"))
            .ToList();

        Assert.True(
            assertionSites.Count > 0,
            "No Debug.Assert remains in the plugin, so the assertion-enabled fuzzing configuration has nothing to check and the bans above guard nothing (#1082).");
    }
}
