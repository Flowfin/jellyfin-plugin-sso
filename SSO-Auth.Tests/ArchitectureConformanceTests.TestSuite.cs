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
/// Conformance rules for the test suite's own rules: a class opening a process-wide door runs in the non-parallel collection, and no test class declares a base class.
/// </content>
public partial class ArchitectureConformanceTests
{
    // The harness door, spelled as a construction rather than as a call: building the harness is what swaps
    // SSOPlugin.Instance and clears the flow caches.
    private const string HarnessDoor = "new SsoControllerHarness";

    // A door no test names because it sits behind another one: a production reset hook opens it, so every
    // test opening THAT door opens this one too. Keyed door -> the door that opens it. The rule proves both
    // halves rather than trusting the table, so an entry whose indirection is removed fails as loudly as a
    // door with no user at all. Without this, a per-door floor would redden on a door that is genuinely
    // reached, and the only way to quiet it would be the combined count this rule exists to remove.
    private static readonly Dictionary<string, string> DoorsOpenedThroughAnotherDoor = new(StringComparer.Ordinal)
    {
        // Opened by the flow service's own reset hook, so every test that resets the OpenID state also
        // reinstalls this gate.
        ["ChallengeNewPathResolver.ResetForTests"] = "OidcLoginService.ResetOidStateForTests",

        // Opened by the harness constructor, so every test that builds a harness clears the one-time
        // SAML outcome store; no test names it directly.
        ["SamlLoginService.ResetSamlOutcomesForTests"] = HarnessDoor,
    };

    /// <summary>
    /// Every test class that can reach a process-wide static sits in the serialized <c>SSOController</c>
    /// collection. What it stops: two test classes outside that collection clearing the same static under
    /// each other's one-time-use assertion, so a replay a validator must refuse is instead refused because a
    /// neighbouring class had just cleared the cache, or accepted because it had just repopulated it. That
    /// failure is intermittent, it lands on whichever class the runner happened to schedule alongside, and it
    /// reads as flakiness rather than as a lost guard (#928 U4, #1171).
    /// <para>
    /// The set of doors is DERIVED from the production tree - every <c>internal static ... ForTests(</c>
    /// declaration, keyed by the qualified name a call site spells, plus the harness type - so adding a hook
    /// under <c>SSO-Auth/</c> adds a door here with no edit to this rule. Keying on the qualified name is not
    /// cosmetic: three types declare <c>ResetReplaysForTests</c>, and a key of the bare method name would
    /// collapse them into one door whose floor clears on any one of the three.
    /// </para>
    /// <para>
    /// Each door carries its OWN floor. A single combined count is the conjunction defect this rule class
    /// keeps reproducing: it clears on one door's population while another door is blind. The scan reads
    /// <see cref="CodeLines(string)"/> only, so a door named in a comment is not a use, and it is sound to
    /// read each file alone only because a test class cannot inherit its setup -
    /// <see cref="NoTestClass_DeclaresABaseClass"/> is what holds that (#1172).
    /// </para>
    /// </summary>
    [Fact]
    public void EveryTestClassOpeningAProcessWideDoor_IsInTheNonParallelControllerCollection()
    {
        var doors = ProcessWideDoors();

        // Liveness on the derivation itself: the production tree carries the harness door plus a hook per
        // flow service, per replay cache and per one-time store. A derivation that stopped matching
        // declarations would otherwise report an empty door set and pass every file below vacuously.
        Assert.True(
            doors.Count >= 10,
            $"The door derivation found only {doors.Count} doors - the `internal static ... ForTests(` scan has been blinded (declaration shape changed, hooks moved out of SSO-Auth/); fix the derivation, do not lower this floor. Found: " + string.Join(", ", doors));

        var offenders = new List<string>();
        var users = doors.ToDictionary(door => door, _ => new List<string>(), StringComparer.Ordinal);
        foreach (var src in Directory.EnumerateFiles(Path.Combine(RepoTree.Root, "SSO-Auth.Tests"), "*.cs", SearchOption.AllDirectories))
        {
            // Skip this rule's OWN source: it carries the scanned names inside the rule itself, not as uses.
            // The rules are one partial class over several files (#1045), so the exemption follows the class
            // name and its per-surface suffixes rather than the single file name it used to be spelled as.
            if (IsBuildOutput(src) || Path.GetFileName(src).StartsWith(nameof(ArchitectureConformanceTests) + ".", StringComparison.Ordinal))
            {
                continue;
            }

            var source = File.ReadAllText(src);

            foreach (var door in DoorsNamedByTestBearingSource(source, doors))
            {
                users[door].Add(Path.GetFileName(src));
            }

            offenders.AddRange(DoorsOpenedUnserialized(source, doors)
                .Select(door => Path.GetFileName(src) + " opens " + door));
        }

        Assert.True(
            offenders.Count == 0,
            "A test class reaching a process-wide door must carry [Collection(\"SSOController\")], or it runs in parallel with another class clearing the same static: " + string.Join("; ", offenders));

        // Per-door floor: every derived door is named by at least one test-bearing file, unless it is
        // declared as reached only through another door and that indirection still holds.
        var blind = doors
            .Where(door => users[door].Count == 0 && !DoorsOpenedThroughAnotherDoor.ContainsKey(door))
            .ToList();

        Assert.True(
            blind.Count == 0,
            "These doors are named by no test-bearing file, so this rule is blind to them - a rename has outrun the scan, or the hook is unused and should go: " + string.Join(", ", blind));

        foreach (var (door, opener) in DoorsOpenedThroughAnotherDoor)
        {
            Assert.True(
                doors.Contains(door, StringComparer.Ordinal),
                $"'{door}' is declared as reached through another door but is no longer a derived door at all; drop the entry.");
            Assert.True(
                doors.Contains(opener, StringComparer.Ordinal) && users[opener].Count > 0,
                $"'{door}' is declared as reached through '{opener}', which is itself not a door with a test user; the indirection no longer holds.");
            Assert.True(
                OpenerOpens(opener, door),
                $"'{opener}' no longer calls '{door}', so the declared indirection is gone; the door needs a test user of its own or the hook needs removing.");
        }
    }

    /// <summary>
    /// The per-file decision of the rule above, fed synthetic source: one must-catch fixture and three
    /// must-not-catch twins, each a single edit away from it and each falsifying a DIFFERENT conjunct of
    /// the decision. Without the pair the rule is only ever observed passing on a clean tree, which is
    /// indistinguishable from a scan that has gone blind (#1173).
    /// <para>
    /// Which twin moves under which mutation is not symmetric, and it follows from what the decision does.
    /// It reports a file that is test-bearing, names a door, and is NOT serialized, so deleting the
    /// collection check can only make it report MORE files: the offender was reported before that deletion
    /// and still is, while the SERIALIZED twin goes from silent to reported. A mutation aimed at the
    /// offender row would therefore change nothing observable and read as if the check had been proved.
    /// </para>
    /// </summary>
    [Fact]
    public void NonParallelRule_PerFileDecision_ReportsTheOffenderAndSparesEachTwin()
    {
        var doors = ProcessWideDoors();
        const string Door = "OidcLoginService.ResetOidStateForTests";

        // Sentinel: these fixtures say nothing if that name is no longer a derived door. The pair would go
        // quiet for a reason unrelated to the conjuncts it exists to falsify, which is the failure a
        // fixture-fed rule is most able to hide.
        Assert.Contains(Door, doors, StringComparer.Ordinal);

        static string Fixture(string attributes, string body) => string.Join(
            "\n",
            attributes,
            "public sealed class DoorProbe",
            "{",
            "    public void Reset()",
            "    {",
            body,
            "    }",
            "}");

        var call = "        " + Door + "();";

        // Must-catch: test-bearing, names the door in code, no serializing attribute.
        Assert.Equal(new[] { Door }, DoorsOpenedUnserialized(Fixture("[Fact]", call), doors));

        // Twin 1, falsifying the code-line reader: the door named only in a comment. A whole-file text
        // search reports this file, and removing a call while documenting the removal in a comment that
        // names it is the edit that reads as diligence.
        Assert.Empty(DoorsOpenedUnserialized(Fixture("[Fact]", "        // " + Door + "();"), doors));

        // Twin 2, falsifying the collection check: the serializing attribute present, nothing else changed.
        Assert.Empty(DoorsOpenedUnserialized(Fixture("[Collection(\"SSOController\")]\n[Fact]", call), doors));

        // Twin 3, falsifying the test-bearing check: no [Fact]/[Theory] at all. This is what keeps the
        // harness support type off the offender list although it opens six doors.
        Assert.Empty(DoorsOpenedUnserialized(Fixture(string.Empty, call), doors));
    }

    // Every derived door a source names in CODE, or nothing at all when the source declares no test. A
    // support type is never scheduled by the runner, so it cannot race anything; the harness itself opens
    // six doors and would otherwise be a permanent offender.
    private static IReadOnlyList<string> DoorsNamedByTestBearingSource(string source, IEnumerable<string> doors) =>
        SourceCallsInCode(source, "[Fact]") || SourceCallsInCode(source, "[Theory]")
            ? doors.Where(door => SourceCallsInCode(source, door)).ToList()
            : Array.Empty<string>();

    // The rule's whole per-file decision: the doors a source opens without carrying the serializing
    // collection attribute. Takes source rather than a path so the pair above can be a string (#1173).
    private static IReadOnlyList<string> DoorsOpenedUnserialized(string source, IEnumerable<string> doors) =>
        SourceCallsInCode(source, "[Collection(\"SSOController\")]")
            ? Array.Empty<string>()
            : DoorsNamedByTestBearingSource(source, doors);

    // Every process-wide door a test can reach: the test-only hooks the production tree declares, keyed
    // Type.Method exactly as a call site spells them, plus the harness construction. Derived rather than
    // listed, so a new hook cannot create a door the rule above is blind to.
    private static IReadOnlyList<string> ProcessWideDoors()
    {
        var declaration = new Regex(@"\b(?:class|record|struct)\s+(?<type>[A-Za-z0-9_]+)");
        var hook = new Regex(@"\binternal\s+static\s+[^;=]*?\b(?<hook>[A-Za-z0-9_]+ForTests)\s*\(");
        var doors = new List<string> { HarnessDoor };

        foreach (var src in Directory.EnumerateFiles(Path.Combine(RepoTree.Root, "SSO-Auth"), "*.cs", SearchOption.AllDirectories))
        {
            if (IsBuildOutput(src))
            {
                continue;
            }

            var type = string.Empty;
            foreach (var line in CodeLines(src))
            {
                var declared = declaration.Match(line.Text);
                if (declared.Success)
                {
                    type = declared.Groups["type"].Value;
                }

                var found = hook.Match(line.Text);
                if (found.Success && type.Length > 0)
                {
                    doors.Add(type + "." + found.Groups["hook"].Value);
                }
            }
        }

        return doors;
    }

    // Whether the declared opener really opens the door, proved in the opener's own source rather than
    // anywhere in the tree: a call from some third place would leave the table's sentence false while the
    // assertion passed. The harness opener is proved in the harness file; a hook opener is proved in the
    // file that declares that hook. The door's own declaration is not a call, and the trailing paren keeps
    // it out.
    private static bool OpenerOpens(string opener, string door)
    {
        if (string.Equals(opener, HarnessDoor, StringComparison.Ordinal))
        {
            var harness = Path.Combine(RepoTree.Root, "SSO-Auth.Tests", "_Support", "SsoControllerHarness.cs");
            return File.Exists(harness) && CodeLines(harness).Any(l => l.Text.Contains(door + "(", StringComparison.Ordinal));
        }

        var hook = opener.Split('.')[^1];
        return Directory.EnumerateFiles(Path.Combine(RepoTree.Root, "SSO-Auth"), "*.cs", SearchOption.AllDirectories)
            .Where(src => !IsBuildOutput(src))
            .Select(src => CodeLines(src).Select(l => l.Text).ToList())
            .Where(lines => lines.Any(text => text.Contains("internal static", StringComparison.Ordinal) && text.Contains(hook + "(", StringComparison.Ordinal)))
            .Any(lines => lines.Any(text => text.Contains(door + "(", StringComparison.Ordinal)));
    }

    [Fact]
    public void NoTestClass_DeclaresABaseClass()
    {
        // #1172: the harness rule above reads each file's own code lines. That is sound only while a test
        // class cannot inherit its setup: `sealed class FooTests : SomeTestBase` where the base constructs
        // the harness or clears a static matches no literal in FooTests.cs, so the file would be scanned
        // clean and run in parallel with a class clearing the same statics. This rule closes that route by
        // construction rather than by scanning for spellings of it - a test-bearing type inherits nothing
        // but object, so whatever a test class does is in the file that declares it. Interfaces are not
        // base types in the CLR, so IDisposable, IClassFixture<T> and IAsyncLifetime are unaffected. It
        // also puts the Coding-Standards wiki rule "there are no test base classes" behind a build gate.
        var testBearing = typeof(ArchitectureConformanceTests).Assembly.GetTypes()
            .Where(t => !IsCompilerGenerated(t))
            .Where(t => t
                .GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)
                .Any(m => m.GetCustomAttributes(typeof(FactAttribute), inherit: true).Length > 0))
            .ToList();

        var offenders = testBearing
            .Where(t => t.BaseType is not null && t.BaseType != typeof(object))
            .Select(t => $"{TestSourceFileDeclaring(t)}: {SimpleName(t)} : {SimpleName(t.BaseType!)}")
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "A test class must not derive from a base class - the file-local test scans (harness collection, statics) would not see what the base does. Implement an interface, or put the shared code in a fixture the class holds. Offenders: " + string.Join(", ", offenders));

        // Liveness floor: the scan must actually reach the test classes. A reflection that stopped finding
        // [Fact]/[Theory] carriers would report zero offenders forever.
        Assert.True(
            testBearing.Count >= 120,
            $"The test-class reflection found only {testBearing.Count} types carrying [Fact]/[Theory] - the scan has been blinded (attribute renamed, tests moved out of this assembly); update this rule.");
    }

    // The test source file declaring a type, so an offender is reported as a file a reader can open rather
    // than as a type name they then have to find. Test-side counterpart of SourceFilesDeclaring, which
    // scans the plugin project.
    private static string TestSourceFileDeclaring(Type type)
    {
        var declaration = new Regex(
            $@"\b(?:{string.Join("|", TypeDeclarationKeywords)})\s+{Regex.Escape(SimpleName(type))}\b");

        return Directory
            .EnumerateFiles(Path.Combine(RepoTree.Root, "SSO-Auth.Tests"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path))
            .Where(path => declaration.IsMatch(File.ReadAllText(path)))
            .Select(Path.GetFileName)
            .FirstOrDefault() ?? SimpleName(type) + " (declaring file not found)";
    }
}
