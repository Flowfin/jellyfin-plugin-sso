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
/// Conformance rules for what the plugin ships: the host-ABI assemblies, the build-yaml artifact list against the publish closure, and the settled read the closure is taken through.
/// </content>
public partial class ArchitectureConformanceTests
{
    [Fact]
    public void SourceFilesDeclaring_MatchesRecordStructAndStructAlongsideClass()
    {
        // #542: the helper's regex used to be "\bclass\s+{Name}\b" only, so it silently returned an empty
        // file list for a record struct/struct type instead of finding its declaring file - a latent
        // false-negative for any future rule that scans one by name. RouteSuffix and DiscoveryFacts
        // ("internal readonly record struct ...") are real record structs already living in SSO-Auth/Api,
        // so this pins the fix against actual source rather than a synthetic fixture.
        var recordStructFiles = SourceFilesDeclaring(new[] { typeof(RouteSuffix), typeof(DiscoveryFacts) });
        Assert.True(
            recordStructFiles.Count == 2,
            "SourceFilesDeclaring must find the declaring file of a record struct type (RouteSuffix, DiscoveryFacts), not just a class.");

        // The class path must keep working too - the widened regex must not have narrowed the original
        // "class Name" match.
        var classFiles = SourceFilesDeclaring(new[] { typeof(AuthorizeSession) });
        Assert.True(
            classFiles.Count == 1,
            "SourceFilesDeclaring must still find the declaring file of an ordinary class (AuthorizeSession).");
    }

    [Fact]
    public void HostProvidedFrameworkAssemblies_StayOnTheHostAbi()
    {
        // Locked in by #590 (the 4.1.0.0 field regression) and generalized per target (#135). Each
        // Jellyfin generation the plugin targets provides the whole Microsoft.Extensions.* family from its
        // ASP.NET Core shared framework - host-provided, deliberately NOT in build.yaml's artifacts. .NET
        // rolls a host assembly reference FORWARD to a newer host but never DOWN a major version, so a
        // dependency dragging one of these ABOVE the target host's .NET major compiles and keeps
        // `dotnet test` green (both run against the full publish output, which carries the newer DLL) yet
        // throws FileNotFoundException the moment the host DI constructs the plugin against its own,
        // lower-versioned assembly - disabling it. That is exactly how OidcClient 7.x (which references
        // Logging.Abstractions 10.0.0.0) broke 4.1.0.0 on the .NET 9 host. The floor is the target's host
        // .NET major: 9 for net9.0 (Jellyfin 10.11), 10 for net10.0 (Jellyfin 12.0). When a net11 target
        // is added, turn this into an #elif chain (NET11_0_OR_GREATER → 11) - NET10_0_OR_GREATER is also
        // true on net11, so leaving it would pin the floor to 10 and spuriously fail the net11 build.
#if NET10_0_OR_GREATER
        const int hostAbiMajor = 10;
#else
        const int hostAbiMajor = 9;
#endif
        var references = typeof(SSOPlugin).Assembly.GetReferencedAssemblies();

        var overshoot = references
            .Where(a => a.Name is { } n && n.StartsWith("Microsoft.Extensions.", StringComparison.Ordinal))
            .Where(a => a.Version is { } v && v.Major > hostAbiMajor)
            .Select(a => $"{a.Name} {a.Version}")
            .ToList();

        Assert.True(
            overshoot.Count == 0,
            $"SSO-Auth references a host-provided Microsoft.Extensions.* assembly above the .NET {hostAbiMajor} host ABI; this target's Jellyfin host provides only {hostAbiMajor}.x and .NET does not roll a host assembly down, so the packaged plugin would throw FileNotFoundException at construction and be disabled (#590): " + string.Join(", ", overshoot));

        // Sentinel against a vacuous pass: the keystone that broke 4.1.0.0 is
        // Microsoft.Extensions.Logging.Abstractions - SSOPlugin's ILogger<> constructor dependency, the
        // very reference the host could not satisfy. It must remain referenced, or the scan above would
        // pass for the wrong reason (an empty match set).
        Assert.True(
            references.Any(a => a.Name == "Microsoft.Extensions.Logging.Abstractions"),
            "SSO-Auth no longer references Microsoft.Extensions.Logging.Abstractions; the #590 ABI-floor scan would pass vacuously - re-anchor it on the host-provided framework assembly the plugin actually uses.");
    }

    [Fact]
    public void BuildYamlArtifacts_EqualTheTfmPublishClosure()
    {
        // Locked in by #608, the drop-list-completeness partner of HostProvidedFrameworkAssemblies_StayOnTheHostAbi
        // above (which guards the OVER-reference direction - a host assembly pulled above the host ABI). JPRM
        // packages the shipped plugin zip from exactly the files named in the build yaml's `artifacts:` list, so
        // that hand-maintained list MUST equal the plugin's NON-HOST `dotnet publish` closure for the target
        // framework. Two failure modes it closes, previously guarded only by a comment (the #605 review finding):
        // a shipped runtime dependency MISSING from the list is dropped from the zip and throws
        // FileNotFoundException the moment the host loads the plugin (the #590 class of field regression); a
        // listed-but-unpublished file makes the JPRM package step fail on a missing artifact and is dead weight.
        //
        // The publish closure is read from SSO-Auth's own SSO-Auth.deps.json - the runtime-assembly manifest the
        // ORDINARY build emits, so the test needs no separate `dotnet publish` invocation. Its per-target
        // `runtime` set is exactly the set `dotnet publish -f <tfm>` copies: the whole package/reference closure
        // MINUS the .NET + ASP.NET Core shared framework the host supplies through the FrameworkReference (proven
        // byte-for-byte equal to the publish output when #608 was written). Subtracting the remaining
        // HOST-PROVIDED families Jellyfin itself ships - Jellyfin/Emby/MediaBrowser and the EF Core, Polly and
        // Unicode/text stacks they drag in, plus Microsoft.Extensions.* and Newtonsoft.Json - leaves precisely the
        // set that must travel in the plugin zip. Per target, mirroring the ABI-floor test's #if: net9.0 ->
        // build.yaml (Jellyfin 10.11, 11 DLLs), net10.0 -> build-jf12.yaml (Jellyfin 12.0, 8 DLLs - where the SAML
        // crypto assemblies are framework-provided on .NET 10 and correctly absent from both closure and list).
#if NET10_0_OR_GREATER
        const string targetFramework = "net10.0";
        const string buildYaml = "build-jf12.yaml";
#else
        const string targetFramework = "net9.0";
        const string buildYaml = "build.yaml";
#endif
#if DEBUG
        const string configuration = "Debug";
#else
        const string configuration = "Release";
#endif

        // SSO-Auth is a ProjectReference of this test project, so building the test for this configuration/target
        // builds the plugin into SSO-Auth/bin/<config>/<tfm>/ with its deps.json alongside. RepoTree.Root is the
        // same compile-time-anchored source root the source-scan rules use; the plugin build output lives under
        // it in CI (which builds and tests the one checkout).
        var depsPath = Path.Combine(RepoTree.Root, "SSO-Auth", "bin", configuration, targetFramework, "SSO-Auth.deps.json");

        // #1072. That input is the build output of ANOTHER project, and any build of the plugin rewrites it, so
        // the row's answer depended on what else was running. Both directions were open, and only one of them
        // was visible: a read that lands mid-write sees a partial or momentarily absent file and reds a correct
        // tree, and a read that lands on the PREVIOUS build's file compares the ship-list against a closure the
        // dependency graph has already moved past, and passes. The two checks below close one direction each.
        // A retry alone would have closed only the first and left the silent one, which is why there is not one.
        var settledDeps = ReadSettledText(() => SampleArtifact(depsPath), () => Thread.Sleep(ArtifactSettlePauseMs), ArtifactSettleAttempts);
        Assert.True(
            settledDeps is not null,
            File.Exists(depsPath)
                ? $"SSO-Auth.deps.json at {depsPath} never held still across {ArtifactSettleAttempts} samples, so a build was writing it while this row read it (#1072). The comparison was not made - re-run the suite without a concurrent build of SSO-Auth."
                : $"SSO-Auth.deps.json for {configuration}/{targetFramework} was not found at {depsPath}; the plugin build output carrying the publish closure is missing, so the ship-list cannot be computed - build SSO-Auth for this target before the test runs (#608).");

        // The closure's content is a function of the declared dependency set and nothing else, and that set
        // reaches the build through obj/project.assets.json. An artifact older than the restore graph therefore
        // predates the dependencies it claims to describe, whatever its bytes parse to. MSBuild takes the assets
        // file as an input of the target that writes deps.json, so any build refreshes the artifact past it, and
        // this can only be red when no build has run since the graph moved.
        var restoreGraphPath = Path.Combine(RepoTree.Root, "SSO-Auth", "obj", "project.assets.json");
        Assert.False(
            ArtifactPredatesRestoreGraph(depsPath, restoreGraphPath),
            $"SSO-Auth.deps.json at {depsPath} is older than the restore graph at {restoreGraphPath}, so the publish closure it carries predates the current dependency declaration and the ship-list would be compared against a set that no longer holds (#1072). Build SSO-Auth for {configuration}/{targetFramework} before the test runs.");

        var publishClosure = PublishClosureAssemblies(settledDeps!);

        // Liveness against a vacuous closure: the plugin's own assembly must be in it, proving the deps.json parse
        // found the real runtime set rather than an empty one that would make the set-equality below trivially true.
        Assert.True(
            publishClosure.Contains("SSO-Auth.dll"),
            "The computed publish closure does not contain the plugin's own SSO-Auth.dll; the deps.json parse found nothing real, so the comparison would pass vacuously (#608).");

        // Liveness against a vacuous FILTER: a keystone host-provided assembly Jellyfin ships (MediaBrowser.Common)
        // must be present in the raw closure AND be removed by the host filter. If the closure ever stopped
        // carrying it, or the filter stopped matching it, the host subtraction would be doing nothing and the
        // equality could pass for the wrong reason - re-anchor the filter on what publish actually drags in.
        Assert.True(
            publishClosure.Contains("MediaBrowser.Common.dll") && IsHostProvidedAssembly("MediaBrowser.Common.dll"),
            "The publish closure no longer carries the host-provided keystone MediaBrowser.Common.dll, or the host-provided filter stopped matching it; re-anchor HostProvidedAssemblyPrefixes on the plugin's real publish output (#608).");

        var shipped = publishClosure.Where(dll => !IsHostProvidedAssembly(dll)).ToHashSet(StringComparer.Ordinal);

        var declared = ParseBuildYamlArtifacts(Path.Combine(RepoTree.Root, buildYaml));
        Assert.True(
            declared.Count > 0,
            $"No artifacts were parsed from {buildYaml}; the `artifacts:` list is empty or the parse missed it, so the comparison would pass vacuously (#608).");

        var missingFromYaml = shipped.Except(declared).OrderBy(x => x, StringComparer.Ordinal).ToList();
        var extraInYaml = declared.Except(shipped).OrderBy(x => x, StringComparer.Ordinal).ToList();

        Assert.True(
            missingFromYaml.Count == 0 && extraInYaml.Count == 0,
            $"{buildYaml}'s `artifacts:` list must equal the non-host {targetFramework} publish closure (#608). "
            + $"Shipped but NOT listed (FileNotFoundException on plugin load): [{string.Join(", ", missingFromYaml)}]. "
            + $"Listed but NOT in the publish output (JPRM fails / dead artifact): [{string.Join(", ", extraInYaml)}]. "
            + "Reconcile the build yaml with `dotnet publish -f " + targetFramework + "`, or extend HostProvidedAssemblyPrefixes if a genuinely new host-provided family appeared.");
    }

    [Fact]
    public void SettledRead_ReturnsTheTextWhenNoWriterMovedAcrossTwoSamples()
    {
        // The ordinary case, and the positive control for every refusal below: a file nobody is writing is read
        // on the first pair of samples, so the guard costs the row nothing when it is not needed (#1072).
        var written = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var settled = SamplerOf(("{\"targets\":{}}", written, 14), ("{\"targets\":{}}", written, 14));

        Assert.Equal("{\"targets\":{}}", ReadSettledText(settled, NoPause, ArtifactSettleAttempts));
    }

    [Fact]
    public void SettledRead_ReturnsTheTextOnceTheWriterStopsInsideTheBudget()
    {
        // A build that finishes while the row is sampling. The whole point of sampling more than twice is that
        // this case ends in the comparison being made, not in a red the operator has to interpret.
        var written = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var settles = SamplerOf(
            ("{\"targ", written, 6),
            ("{\"targets\":{}}", written.AddSeconds(1), 14),
            ("{\"targets\":{}}", written.AddSeconds(1), 14));

        Assert.Equal("{\"targets\":{}}", ReadSettledText(settles, NoPause, ArtifactSettleAttempts));
    }

    [Fact]
    public void SettledRead_RefusesWhileAWriterKeepsMoving()
    {
        // The failure the issue reproduces with two concurrent builds. It has to end as null, and the caller
        // has to say the comparison was NOT MADE - a row that quietly used the last sample would be reading
        // whatever byte count the writer happened to have flushed.
        var written = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var moves = 0;
        (string Text, DateTime WrittenUtc, long Length)? NeverSettles() =>
            ("{\"targets\":{}}", written.AddSeconds(moves), 14 + moves++);

        Assert.Null(ReadSettledText(NeverSettles, NoPause, ArtifactSettleAttempts));
    }

    [Fact]
    public void SettledRead_RefusesAnArtifactNoSampleEverSaw()
    {
        // Two absences in a row are equal to each other, so an unguarded sample comparison would call a missing
        // file settled and hand the parser an empty string. Nothing was read, so nothing is returned.
        Assert.Null(ReadSettledText(() => null, NoPause, ArtifactSettleAttempts));
    }

    [Fact]
    public void SettledRead_RefusesTwoDifferentBodiesUnderOneStampAndLength()
    {
        // The near-miss worth spending the fixture on: a rewrite that lands inside the filesystem's timestamp
        // granularity and happens to keep the length. Comparing only the stat would accept the pair. The bytes
        // are part of the sample for this reason and no other. The budget is two here on purpose: the fixture
        // is about what one PAIR of samples decides, and a longer run would legitimately settle on the second
        // body once the writer stopped.
        var written = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var indistinguishableStats = SamplerOf(
            ("{\"targets\":{\"a\":{}}}", written, 20),
            ("{\"targets\":{\"b\":{}}}", written, 20));

        Assert.Null(ReadSettledText(indistinguishableStats, NoPause, 2));
    }

    [Theory]
    [InlineData(5, false)] // written after the graph, which is what a build leaves behind
    [InlineData(0, false)] // the same second: equal is not older, and a rebuild may not move a coarse stamp
    [InlineData(-5, true)] // the stale read the row used to pass on
    public void ArtifactPredatesRestoreGraph_JudgesByTheGraphsTimestamp(int artifactOffsetSeconds, bool expected)
    {
        // Fixtures for the staleness predicate itself. This is the direction that produced no red at all, so
        // the assertion in the row above is the only thing standing between a moved dependency graph and a
        // ship-list compared against a closure that no longer describes it (#1072).
        var root = Path.Combine(Path.GetTempPath(), "sso-deps-stale-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var artifact = Path.Combine(root, "SSO-Auth.deps.json");
            var graph = Path.Combine(root, "project.assets.json");
            File.WriteAllText(artifact, "{}");
            File.WriteAllText(graph, "{}");

            var graphWrittenUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            File.SetLastWriteTimeUtc(graph, graphWrittenUtc);
            File.SetLastWriteTimeUtc(artifact, graphWrittenUtc.AddSeconds(artifactOffsetSeconds));

            Assert.Equal(expected, ArtifactPredatesRestoreGraph(artifact, graph));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void ArtifactPredatesRestoreGraph_AnswersFalseWhenEitherFileIsAbsent()
    {
        // A checkout that has not restored, and a target that has not been built, are both states this
        // predicate cannot speak about. It says false rather than inventing a staleness verdict out of a
        // missing file; the absent artifact is reported by the settled read, which is where that belongs.
        var root = Path.Combine(Path.GetTempPath(), "sso-deps-absent-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var artifact = Path.Combine(root, "SSO-Auth.deps.json");
            var graph = Path.Combine(root, "project.assets.json");
            File.WriteAllText(artifact, "{}");

            Assert.False(ArtifactPredatesRestoreGraph(artifact, graph));
            Assert.False(ArtifactPredatesRestoreGraph(graph, artifact));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    // The fixtures below drive the settle loop through every branch, so they must not also spend the real
    // caller's wall time doing it: thirty seconds of sleeping would be paid on every green run of the suite.
    private static void NoPause()
    {
    }

    // Replays a fixed sequence of samples and then holds on the last one, so a fixture states exactly what the
    // filesystem did and nothing about how often the reader looked.
    private static Func<(string Text, DateTime WrittenUtc, long Length)?> SamplerOf(
        params (string Text, DateTime WrittenUtc, long Length)?[] samples)
    {
        var taken = 0;
        return () => samples[Math.Min(taken++, samples.Length - 1)];
    }

    // The assembly-name families the Jellyfin host provides at runtime and therefore must NOT ship in the plugin
    // zip, even though `dotnet publish` copies them into the plugin's own publish output (they are not part of the
    // .NET/ASP.NET Core shared framework, so publish does not strip them the way it strips the framework). Matched
    // on the assembly SIMPLE name so one entry covers a whole family: "Polly" -> Polly + Polly.Core, "ICU4N" ->
    // ICU4N + ICU4N.Transliterator, "Microsoft.EntityFrameworkCore" -> its .Abstractions/.Relational, etc. This is
    // the counterpart denylist to the build yaml's allow-list of shipped deps: a genuinely new host-provided family
    // must be added here (with justification) and a new shipped dependency must be added to the build yaml -
    // either way BuildYamlArtifacts_EqualTheTfmPublishClosure fails until the two agree (fail-closed). "Microsoft."
    // is deliberately NOT a blanket prefix: Microsoft.IdentityModel.* and Microsoft.Bcl.Cryptography DO ship, so
    // only the specific host-provided Microsoft families (Extensions, EntityFrameworkCore) are listed.
    private static readonly string[] HostProvidedAssemblyPrefixes =
    {
        "Jellyfin", "Emby", "MediaBrowser", "Microsoft.Extensions", "Microsoft.EntityFrameworkCore",
        "Newtonsoft", "Polly", "BitFaster", "Diacritics", "ICU4N", "J2N", "NEbml",
    };

    private static bool IsHostProvidedAssembly(string dllFileName)
    {
        var simpleName = dllFileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
            ? dllFileName[..^4]
            : dllFileName;
        return HostProvidedAssemblyPrefixes.Any(p =>
            simpleName.Equals(p, StringComparison.Ordinal)
            || simpleName.StartsWith(p + ".", StringComparison.Ordinal));
    }

    // The runtime-assembly filenames from SSO-Auth.deps.json's single build target - the exact set
    // `dotnet publish` copies for that framework (#608). A framework-dependent build has one target (the runtime
    // target); read every library's `runtime` map and take each entry's leaf filename, because deps.json keys
    // runtime items by their in-package path (e.g. "lib/net8.0/Duende.IdentityModel.dll"), not the bare name.
    // Takes the TEXT rather than the path, because whether that text was read off a file nobody was writing is
    // a separate question with its own answer (ReadSettledText, #1072) and the parse must not re-open the file
    // and get a different one.
    private static HashSet<string> PublishClosureAssemblies(string depsJson)
    {
        using var doc = JsonDocument.Parse(depsJson);
        var targets = doc.RootElement.GetProperty("targets");

        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (var target in targets.EnumerateObject())
        {
            foreach (var library in target.Value.EnumerateObject())
            {
                if (!library.Value.TryGetProperty("runtime", out var runtime))
                {
                    continue;
                }

                foreach (var asset in runtime.EnumerateObject())
                {
                    var leaf = asset.Name.Split('/', '\\').Last();
                    if (leaf.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    {
                        result.Add(leaf);
                    }
                }
            }
        }

        return result;
    }

    // The budget for waiting out a build that is writing the artifact this row reads. A tree nobody is
    // building settles on the first pair of samples and pays none of it, because the pause is taken only after
    // two samples disagreed. What the budget has to outlast is one full rebuild of the plugin project, which
    // deletes the artifact and writes it back seconds later, so it is measured in wall time rather than in
    // reads: 150 samples 200ms apart is thirty seconds, comfortably past a --no-incremental build of SSO-Auth
    // on this machine (measured at 4 to 20 seconds) and still bounded, so a genuinely stuck run ends in a
    // failure that says what happened instead of hanging (#1072).
    private const int ArtifactSettleAttempts = 150;
    private const int ArtifactSettlePauseMs = 200;

    // A build artifact, together with the identity of the write that produced the bytes: the stat is taken
    // AFTER the read, so a sample that agrees with its predecessor is one no writer moved across. Absent or
    // exclusively locked reads back as no sample at all rather than as an empty file, which is the shape a
    // concurrent build passes through and must not be mistaken for a real closure (#1072).
    private static (string Text, DateTime WrittenUtc, long Length)? SampleArtifact(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return null;
            }

            var text = File.ReadAllText(path);
            var info = new FileInfo(path);
            return info.Exists ? (text, info.LastWriteTimeUtc, info.Length) : null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    // The text of an artifact nobody was writing, or null when no two consecutive samples agreed inside the
    // budget. Sampling twice is what separates "the file says this" from "the file said this at the instant I
    // looked": a partial read differs from the settled one in its bytes, and a completed rewrite differs in its
    // stamp or length, so both are caught by comparing whole samples rather than any one field. The pause is a
    // parameter so the fixtures below can exercise every branch without spending the wall time the real caller
    // needs, and it is taken only between disagreeing samples.
    private static string? ReadSettledText(
        Func<(string Text, DateTime WrittenUtc, long Length)?> sample,
        Action pause,
        int attempts)
    {
        var previous = sample();
        for (var taken = 1; taken < attempts; taken++)
        {
            var current = sample();
            if (previous is { } settled && current == previous)
            {
                return settled.Text;
            }

            previous = current;
            pause();
        }

        return null;
    }

    // Whether a derived build artifact predates the restore graph it is derived from. An absent graph answers
    // false: the question cannot be decided, and inventing a red from a missing file would make the row fail on
    // a checkout that has not restored yet rather than on the condition it is about (#1072).
    private static bool ArtifactPredatesRestoreGraph(string artifactPath, string restoreGraphPath) =>
        File.Exists(artifactPath)
        && File.Exists(restoreGraphPath)
        && File.GetLastWriteTimeUtc(artifactPath) < File.GetLastWriteTimeUtc(restoreGraphPath);

    // The `.dll` names under the build yaml's `artifacts:` list. Minimal hand-parse (the test project takes no YAML
    // dependency): once at the `artifacts:` key, collect the `- "X.dll"` list items, skip the interleaved comments,
    // and stop at the next top-level key. build.yaml / build-jf12.yaml keep exactly one quoted dll per list item.
    private static HashSet<string> ParseBuildYamlArtifacts(string yamlPath)
    {
        var artifacts = new HashSet<string>(StringComparer.Ordinal);
        var inArtifacts = false;
        foreach (var line in File.ReadAllLines(yamlPath))
        {
            if (!inArtifacts)
            {
                if (Regex.IsMatch(line, @"^artifacts:\s*$"))
                {
                    inArtifacts = true;
                }

                continue;
            }

            // A new top-level key (unindented and not a list item) ends the artifacts block.
            if (line.Length > 0 && !char.IsWhiteSpace(line[0]) && !line.TrimStart().StartsWith('-'))
            {
                break;
            }

            var item = Regex.Match(line, "^\\s*-\\s*\"([^\"]+)\"\\s*$");
            if (item.Success)
            {
                artifacts.Add(item.Groups[1].Value);
            }
        }

        return artifacts;
    }
}
