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
/// Conformance rules for the repeated-member walk takes the duplicate decision itself and has one code path on both target frameworks, and every repo-root walk-up goes through the shared helper.
/// </content>
public partial class ArchitectureConformanceTests
{
    // The repeated-member walk, whose one claim is that ONE code path reaches the same verdict on both target
    // frameworks. Declared as a path rather than found by name so a rename has to come past this rule.
    private const string RepeatedMemberWalk = "SSO-Auth/Api/Oidc/StrictJson.cs";

    // Spellings that would move the duplicate-member decision off this walk and onto the System.Text.Json the
    // host binds (#1770). Each was checked to exist in the reference assemblies this repository restores
    // against rather than assumed, which is why JsonDuplicatePropertyHandling is absent: nothing implements
    // it, and a name nothing implements is dead weight in a denylist. All four compile on the one target, so
    // this rule is the only thing that refuses any of them.
    private static readonly string[] FrameworkDuplicatePolicies =
    {
        "AllowDuplicateProperties",
        "JsonSerializerOptions.Strict",
        "JsonSerializerDefaults.Strict",
        "DuplicatePropertyNameHandling",
    };

    /// <summary>The repeated-member walk decides duplicates itself and never delegates that decision to the JSON stack of the host (#1189).</summary>
    /// <remarks>
    /// With one target every spelling below compiles, so nothing but this rule stands between the walk and the
    /// duplicate policy of the host, and every test here loads its own System.Text.Json rather than that one,
    /// so a delegated verdict would be reported as the verdict of the runtime the suite ran on. #1043 measured
    /// the preset against the corpus of the walk and kept the walk, so the rule retires the day that
    /// measurement is re-taken and comes out the other way: see <c>StrictJsonTests</c>.
    /// </remarks>
    [Fact]
    public void TheRepeatedMemberWalk_TakesTheDuplicateDecisionItself()
    {
        var source = File.ReadAllText(WalkPath());

        var delegated = FrameworkDuplicatePolicies
            .Where(policy => SourceCallsInCode(source, policy))
            .ToList();

        Assert.True(
            delegated.Count == 0,
            $"{RepeatedMemberWalk} must reach its verdict without the host's duplicate policy (#1189); it names: " + string.Join(", ", delegated));
    }

    /// <summary>
    /// The walk carries no conditional compilation, which is the other half of "one code path" and the one
    /// an ordinary test cannot see - a per-target branch is invisible to a suite that runs each target
    /// separately and passes on both. One target is built today (#1770) and #1043 kept the walk, so the
    /// rule stays and a second target cannot bring a branch back unnoticed.
    /// </summary>
    [Fact]
    public void TheRepeatedMemberWalk_HasOneCodePathOnBothTargets()
    {
        var branches = File.ReadAllLines(WalkPath())
            .Select((text, index) => (Number: index + 1, Text: text.TrimStart()))
            .Where(l => l.Text.StartsWith("#if", StringComparison.Ordinal)
                || l.Text.StartsWith("#else", StringComparison.Ordinal)
                || l.Text.StartsWith("#elif", StringComparison.Ordinal))
            .Select(l => $"line {l.Number}: {l.Text}")
            .ToList();

        Assert.True(
            branches.Count == 0,
            $"{RepeatedMemberWalk} must compile to one code path on both target frameworks (#1189); it branches at: " + string.Join(" | ", branches));
    }

    [Fact]
    public void AWalkThatDelegatesTheDuplicateDecision_IsRejectedByTheScan()
    {
        // The must-catch half, over the predicate rather than over the tree, and deliberately the spelling
        // that compiled on both legs while two existed rather than the one the net9.0 compiler stopped. A
        // near-miss the build refuses anyway proves nothing about this rule; this one was applied to the
        // shipped walk, built clean, and reddened both this rule and its prose twin.
        const string Source = @"
internal static class StrictJson
{
    internal static Verdict Inspect(string json)
    {
        var settings = new JsonLoadSettings { DuplicatePropertyNameHandling = DuplicatePropertyNameHandling.Replace };
        return Verdict.Clean;
    }
}";

        Assert.Contains(FrameworkDuplicatePolicies, policy => SourceCallsInCode(Source, policy));
    }

    [Fact]
    public void TheWalksOwnProseAboutThePreset_IsNotFlaggedByTheScan()
    {
        // The must-not-catch twin, and it is not hypothetical: the shipped walk explains itself by naming
        // the preset it converges on and the issue that will replace it with one. Both mentions are in XML
        // documentation, and a rule built on a whole-file text search would refuse the file that satisfies
        // it. So the scan reading CODE lines is load-bearing here rather than incidental, and the two
        // assertions below are what say so - the raw text names the preset, the code does not.
        var source = File.ReadAllText(WalkPath());

        Assert.Contains("JsonSerializerOptions.Strict", source, StringComparison.Ordinal);
        Assert.DoesNotContain(FrameworkDuplicatePolicies, policy => SourceCallsInCode(source, policy));
    }

    [Fact]
    public void TheRepeatedMemberWalkScan_RefusesAVacuousPass()
    {
        // A scan over a file that is gone, renamed or empty reports the same all-clear as a scan that found
        // nothing wrong, and the walk is exactly the kind of file a refactor moves.
        var path = WalkPath();
        Assert.True(File.Exists(path), $"The declared repeated-member walk does not exist: {RepeatedMemberWalk}");
        Assert.NotEmpty(File.ReadAllText(path));
    }

    private static string WalkPath() =>
        Path.Combine(RepoTree.Root, RepeatedMemberWalk.Replace('/', Path.DirectorySeparatorChar));

    // The attribute the copied walk-ups were built on, spelled at run time instead of written out. A rule
    // that searches the test tree for a literal it also contains would name its own file every run, and the
    // repair for that - excluding this file from its own scan - would leave the hole where the sixth copy
    // actually lived. Derived from the type rather than from a string, so a framework rename moves with it.
    private static readonly string CallerPathMarker =
        "[" + nameof(CallerFilePathAttribute).Replace("Attribute", string.Empty, StringComparison.Ordinal) + "]";

    /// <summary>One repository-root resolver in the test project, in <c>_Support/RepoTree.cs</c> (#1189).</summary>
    /// <remarks>
    /// Six copies of a hand-rolled walk-up existed on the day this rule landed and the count had only ever
    /// gone up. They were not interchangeable, because each counted the levels to the root by hand, so a rule
    /// file moved between folders resolves a root one level off and scans a tree that is not the repository
    /// while reporting the all-clear. Deleting the copies is not enough on its own; this rule stops the
    /// seventh.
    /// </remarks>
    [Fact]
    public void EveryRepoRootWalkUp_GoesThroughTheSharedHelper()
    {
        var testsRoot = Path.Combine(RepoTree.Root, "SSO-Auth.Tests");
        var owner = Path.Combine("_Support", "RepoTree.cs");

        var resolvers = Directory.EnumerateFiles(testsRoot, "*.cs", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path))
            .Where(path => SourceCallsInCode(File.ReadAllText(path), CallerPathMarker))
            .Select(path => Path.GetRelativePath(testsRoot, path))
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToList();

        // Set equality both ways. "No new copy" alone would pass a build where the shared helper itself was
        // deleted and every rule silently fell back to something else - and it is also what proves the
        // assembled marker still spells the attribute: mis-assemble it and the list comes back empty rather
        // than naming the one file that genuinely uses it.
        Assert.Equal(new List<string> { owner }, resolvers);
    }

    [Fact]
    public void TheWalkUpScan_KeepsDeclarationsAndDropsProse()
    {
        // The must-catch and must-not-catch pair for the resolver scan, including the edit that defeats a
        // whole-file text search: removing the walk-up and describing the removal in a comment that still
        // names it (#1122). Every row is assembled from the marker rather than written out, for the reason
        // the marker itself is assembled - a fixture spelling the attribute would make this file the seventh
        // copy as far as the scan above is concerned.
        var declaration = "private static string RepoRoot(" + CallerPathMarker + " string p = \"\") =>";

        Assert.True(SourceCallsInCode("    " + declaration, CallerPathMarker));
        Assert.False(SourceCallsInCode("    // " + declaration, CallerPathMarker));
        Assert.False(SourceCallsInCode("    /// Replaced the old " + CallerPathMarker + " walk-up with the shared helper.", CallerPathMarker));
        Assert.False(SourceCallsInCode("        var root = RepoTree.Root;", CallerPathMarker));
    }
}
