// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Holds the parse-surface assertions to exactly one build: the weekly fuzz job (#1081).
/// <para>
/// The post-conditions #1082 put on the SAML and OpenID parsers are <c>Debug.Assert</c>, which the
/// compiler removes from any build that does not define <c>DEBUG</c>. That removal is what makes them
/// acceptable on an authentication path, and it is also what makes them useless to a fuzzer unless one
/// build asks for them back. <c>ParseSurfaceAssertions_NeverReachTheShippedBuild</c> refuses the constant
/// in <c>Directory.Build.props</c> and <c>SSO-Auth.csproj</c>, so the fuzz job passes it on the command
/// line instead - and a constant on a command line is exactly the kind of thing that gets dropped in an
/// unrelated edit to a workflow nobody rereads on a green week.
/// </para>
/// <para>
/// Both directions are the rule. Dropping the constant from the fuzz job leaves the weekly run driving a
/// surface that asserts nothing while every artefact still says it does; adding it to any other workflow
/// puts an abort-on-failure check into a build that can be published, where a fault the login path is
/// meant to reject becomes a process abort instead.
/// </para>
/// <para>
/// WHAT THIS DOES NOT DO. It reads workflow text, so it judges what the repository asks for and never
/// what a runner did with it: a job whose build step is skipped, or whose SDK ignores the property, looks
/// identical here. The evidence that the constant reaches the assembly is the differential recorded on
/// #1081, and the evidence that a failing assertion lands as a libFuzzer reproducer is the dispatch run
/// linked there. This rule keeps the configuration those two measurements were taken against.
/// </para>
/// </summary>
public class FuzzAssertionBuildTests
{
    // The workflow that is allowed to compile the assertions in. Named rather than discovered: the claim is
    // about one job, and a scan that took whichever workflow happened to build the harness would move with
    // the tree instead of pinning it.
    private const string FuzzWorkflow = "fuzz.yml";

    // The project the fuzz job builds. A build line that does not name it is some other build and is not
    // what this rule is about.
    private const string HarnessProject = "SSO-Auth.Fuzz/SSO-Auth.Fuzz.csproj";

    // The property spelling that carries the constant. Matched on the property NAME alone, so a rewrite of
    // the value (a third constant, a different separator escape) is read by the assertions below rather
    // than slipping past a match on the whole literal.
    private const string ConstantProperty = "-p:DefineConstants=";

    [Fact]
    public void OnlyTheFuzzWorkflow_CompilesTheParseSurfaceAssertions()
    {
        var workflows = Directory
            .EnumerateFiles(Path.Combine(RepoTree.Root, ".github", "workflows"), "*.yml", SearchOption.TopDirectoryOnly)
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            workflows.Count > 0,
            "No workflow file was found under .github/workflows - the directory moved, so this rule would pass vacuously (#1081).");

        var definers = workflows
            .Where(path => DefinesDebug(File.ReadAllText(path)))
            .Select(Path.GetFileName)
            .ToList();

        Assert.True(
            definers.Count == 1 && string.Equals(definers[0], FuzzWorkflow, StringComparison.Ordinal),
            $"DEBUG may be defined by {FuzzWorkflow} and by no other workflow: it carries every parse-surface Debug.Assert into the assembly that build produces, and outside the fuzz job that assembly can be published (#1081/#1082). Definers: "
                + (definers.Count == 0 ? "(none)" : string.Join(", ", definers)));
    }

    [Fact]
    public void TheFuzzWorkflow_BuildsTheHarnessWithTheAssertionsAndNothingElseDropped()
    {
        var buildLines = File
            .ReadAllLines(Path.Combine(RepoTree.Root, ".github", "workflows", FuzzWorkflow))
            .Select(line => line.Trim())
            .Where(line => !line.StartsWith('#')
                && line.Contains("dotnet build", StringComparison.Ordinal)
                && line.Contains(HarnessProject, StringComparison.Ordinal))
            .ToList();

        Assert.True(
            buildLines.Count == 1,
            $"Expected exactly one step in {FuzzWorkflow} building {HarnessProject}, so there is one place the constant can be read off; found {buildLines.Count} (#1081).");

        var build = buildLines[0];

        Assert.True(
            build.Contains(ConstantProperty, StringComparison.Ordinal),
            $"The fuzz build must pass {ConstantProperty}: without it the parse-surface post-conditions are compiled out and the weekly run asserts nothing (#1081). Line: {build}");

        var constants = Constants(build);

        Assert.Contains("DEBUG", constants, StringComparer.Ordinal);

        // TRACE is not decoration. The property REPLACES the default constant set rather than adding to it,
        // and Release defines TRACE, so a value naming DEBUG alone would silently make the fuzzed build
        // differ from Release in a second way that has nothing to do with assertions.
        Assert.Contains("TRACE", constants, StringComparer.Ordinal);

        // Release, because the assertions are meant to cost the fuzzer checks and not its optimized code:
        // -c Debug would buy the same constant and spend the run's -max_total_time budget on unoptimized IL.
        Assert.Contains("-c Release", build, StringComparison.Ordinal);
    }

    // Reads the value of the constant property off a command line and splits it into the constants it
    // names. %3B is MSBuild's escape for the separator and is what the fuzz job uses, so a value spelled
    // with a literal semicolon reads identically here rather than looking like one long constant.
    private static IReadOnlyList<string> Constants(string commandLine)
    {
        var start = commandLine.IndexOf(ConstantProperty, StringComparison.Ordinal) + ConstantProperty.Length;
        var value = commandLine[start..].Split(' ')[0].Trim('"', '\'');

        return value
            .Replace("%3B", ";", StringComparison.OrdinalIgnoreCase)
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    // A workflow defines DEBUG when a command line in it sets the constant property to a value naming it.
    // Comment lines are read too, deliberately: this file's own prose aside, a commented-out build step is
    // not what the rule is about, but a DEBUG sitting in a workflow's text is worth a reader's attention
    // either way, and treating the two the same keeps the check from depending on YAML structure.
    private static bool DefinesDebug(string workflow) =>
        workflow.Contains(ConstantProperty, StringComparison.Ordinal)
        && workflow
            .Split('\n')
            .Where(line => line.Contains(ConstantProperty, StringComparison.Ordinal))
            .Any(line => Constants(line).Contains("DEBUG", StringComparer.Ordinal));
}
