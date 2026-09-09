// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The gate tools this repository installs from PyPI are pinned to bytes, and each version is written
/// ONCE (#1595).
/// <para>
/// Before this, <c>zizmor</c> was installed with <c>uvx --no-build "zizmor@$&#123;ZIZMOR_VERSION&#125;"</c>:
/// what ran was whatever the index served that minute, and nothing in the tree recorded it. The
/// neighbouring <c>opengrep</c> workflow already fetched its binary against a committed SHA-256, so two
/// tools gated this repository and only one of them was reviewable.
/// </para>
/// <para>
/// The version is READ out of the requirements input rather than restated in the workflow, and that half
/// is not tidiness. Nothing writes a workflow <c>env:</c> value, so a version written in both places is
/// one a routine updater cannot finish moving: it changes the requirements files and leaves the third
/// place behind. A restated literal is therefore a finding here, and so is a workflow that names no
/// input - without that second half, deleting the <c>env:</c> and reading nothing would pass.
/// </para>
/// </summary>
public partial class ArchitectureConformanceTests
{
    /// <summary>Every tool installed from a committed closure, and where its three files live.</summary>
    private static readonly IReadOnlyList<(string Workflow, string EnvKey, string Package)> PinnedTools =
        new[] { (Workflow: "zizmor.yml", EnvKey: "ZIZMOR_VERSION:", Package: "zizmor") };

    [Fact]
    public void EveryPinnedTool_WritesItsVersionOnceAndTheWorkflowReadsIt()
    {
        var findings = new List<string>();

        foreach (var (workflowName, envKey, package) in PinnedTools)
        {
            var workflow = ReadRepositoryFile(Path.Combine(".github", "workflows", workflowName));
            var inputPath = "requirements/" + package + ".in";
            var input = ReadRepositoryFile(Path.Combine("requirements", package + ".in"));
            var compiled = ReadRepositoryFile(Path.Combine("requirements", package + ".txt"));

            var requested = PinnedVersion(input, package);
            var compiledTo = PinnedVersion(compiled, package);

            if (requested is null)
            {
                findings.Add($"{inputPath} names no version for {package}");
            }

            if (compiledTo is null)
            {
                findings.Add($"requirements/{package}.txt names no version for {package}");
            }

            if (requested is not null && !string.Equals(requested, compiledTo, StringComparison.Ordinal))
            {
                findings.Add(
                    $"{package}'s generated closure disagrees with its input: .in '{requested}', .txt '{compiledTo}'");
            }

            if (YamlCallsInCode(workflow, envKey))
            {
                findings.Add($"{workflowName} restates {envKey} instead of reading it from {inputPath}");
            }

            if (!workflow.Contains(inputPath, StringComparison.Ordinal))
            {
                findings.Add($"{workflowName} never names {inputPath}, so nothing there reads the pin");
            }

            if (YamlCallsInCode(workflow, "uvx "))
            {
                findings.Add(
                    $"{workflowName} resolves a tool with uvx, which reaches the index at run time rather than the committed closure");
            }
        }

        Assert.True(findings.Count == 0, string.Join("\n", findings));
    }

    [Fact]
    public void EveryPinnedTool_InstallsFromAHashPinnedClosure()
    {
        var findings = new List<string>();

        foreach (var (_, _, package) in PinnedTools)
        {
            var compiled = ReadRepositoryFile(Path.Combine("requirements", package + ".txt"));
            var unhashed = RequirementsWithoutAHash(compiled).ToList();

            if (unhashed.Count > 0)
            {
                findings.Add($"{package}.txt has requirements with no --hash=: {string.Join(", ", unhashed)}");
            }
        }

        Assert.True(findings.Count == 0, string.Join("\n", findings));
    }

    [Fact]
    public void ThePinnedToolScan_RefusesAVacuousPass()
    {
        // A scan over a file that is gone, renamed or empty reports the same all-clear as a scan that
        // found nothing wrong, and a requirements file is exactly the kind of file a refactor moves.
        foreach (var (workflowName, _, package) in PinnedTools)
        {
            foreach (var relative in new[]
                     {
                         Path.Combine(".github", "workflows", workflowName),
                         Path.Combine("requirements", package + ".in"),
                         Path.Combine("requirements", package + ".txt"),
                     })
            {
                var path = Path.Combine(RepoTree.Root, relative);
                Assert.True(File.Exists(path), $"a pinned tool's file does not exist: {relative}");
                Assert.NotEmpty(File.ReadAllText(path));
            }
        }
    }

    [Fact]
    public void ThePinnedToolScan_KeepsPinsAndDropsProse()
    {
        // The must-catch and must-not-catch pair. A version named in a comment sentence is prose; the
        // same figure on a code line is a restatement, and the difference is the whole point of reading
        // the pin out of the input.
        Assert.Equal("1.2.3", PinnedVersion("zizmor==1.2.3\n", "zizmor"));
        Assert.Null(PinnedVersion("# zizmor==1.2.3\n", "zizmor"));
        Assert.Null(PinnedVersion("zizmorplus==1.2.3\n", "zizmor"));

        Assert.Empty(RequirementsWithoutAHash("zizmor==1.2.3 \\\n    --hash=sha256:aa\n"));
        Assert.Equal(new[] { "zizmor" }, RequirementsWithoutAHash("zizmor==1.2.3\n"));

        // The YAML scan's own pair, and it is here because the rule failed on it once: a workflow that
        // EXPLAINS the call it removed must read as prose, while the call itself must not.
        Assert.True(YamlCallsInCode("        run: uvx --no-build tool\n", "uvx "));
        Assert.False(YamlCallsInCode("        # This replaces uvx --no-build tool.\n", "uvx "));
        Assert.False(YamlCallsInCode("# uvx resolves at run time\n", "uvx "));
    }

    /// <summary>
    /// Whether a YAML file names something on a line that is not a comment.
    /// <para>
    /// The shared <c>SourceCallsInCode</c> strips C# comments and leaves <c>#</c> alone, so pointing it at
    /// a workflow makes every explanatory comment read as code. The first version of this rule did exactly
    /// that and refused its own file for the sentence describing the <c>uvx</c> call it had just removed,
    /// which is the failure the comment-versus-code distinction exists to prevent, arriving from the other
    /// side.
    /// </para>
    /// <para>
    /// Only whole-line comments are dropped. A trailing <c>#</c> after code is not modelled, because these
    /// workflows put their reasoning on lines of its own and a quoted <c>#</c> inside a shell string would
    /// otherwise be mistaken for one.
    /// </para>
    /// </summary>
    private static bool YamlCallsInCode(string yaml, string needle) =>
        yaml
            .Split('\n')
            .Select(line => line.TrimEnd('\r'))
            .Where(line => !line.TrimStart().StartsWith('#'))
            .Any(line => line.Contains(needle, StringComparison.Ordinal));

    /// <summary>Reads a repository file, which is the tree rather than the assembly's output.</summary>
    private static string ReadRepositoryFile(string relative) =>
        File.ReadAllText(Path.Combine(RepoTree.Root, relative));

    /// <summary>
    /// The version a requirements file pins for one package, or null. Reads the pin rather than the
    /// generated header, which names the same package inside the command it records.
    /// </summary>
    private static string? PinnedVersion(string requirements, string package) =>
        requirements
            .Split('\n')
            .Select(line => line.TrimEnd('\r'))
            .Where(line => line.StartsWith(package + "==", StringComparison.Ordinal))
            .Select(line => line[(package.Length + 2)..].Split(' ')[0].Trim())
            .FirstOrDefault(version => version.Length > 0);

    /// <summary>
    /// The packages in a compiled closure that carry no digest. A requirement begins at column zero and
    /// owns every continuation line until the next one, so the hash is looked for in that block rather
    /// than on the first line alone.
    /// </summary>
    private static IEnumerable<string> RequirementsWithoutAHash(string compiled)
    {
        string? current = null;
        var hashed = false;

        foreach (var raw in compiled.Split('\n'))
        {
            var line = raw.TrimEnd('\r');

            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            if (!char.IsWhiteSpace(line[0]))
            {
                if (current is not null && !hashed)
                {
                    yield return current;
                }

                current = line.Split(new[] { "==", " ", "\\" }, StringSplitOptions.RemoveEmptyEntries)[0];
                hashed = line.Contains("--hash=", StringComparison.Ordinal);
                continue;
            }

            hashed |= line.Contains("--hash=", StringComparison.Ordinal);
        }

        if (current is not null && !hashed)
        {
            yield return current;
        }
    }
}
