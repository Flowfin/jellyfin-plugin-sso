// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Holds the shipped plugin's JSON parse sites to a declared list, so a new one cannot appear without a
/// decision about the bytes it reads (#1005, #1187). Every site under <c>SSO-Auth/</c> is named in exactly
/// one of three tables: the reads reached only through the repeated-member screen, the reads over bytes
/// the plugin itself owns, and the reads that are neither - untrusted input parsed with no screen in front
/// of it. That third table is the point of the rule. A scan that only asked "is this site allowlisted"
/// would let an unscreened untrusted read be written into the trusted list and disappear; here it has its
/// own table, its own name and the issue that owes the decision.
///
/// The scan reads CODE lines only. The likeliest edit that defeats a call-site rule is removing the call
/// and describing the removal in a comment that still names it, which reads as diligence and would keep a
/// whole-file text search green (#1122).
/// </summary>
public class UntrustedJsonConformanceTests
{
    // Every way this dependency set turns bytes into an object graph. Two parsers are in play - the
    // System.Text.Json the plugin binds from the host, and the Newtonsoft the identity library brings - and
    // the whole reason the rule exists is that they disagree about a document that names a member twice, so
    // a table naming only one of them would be a rule with a hole the shape of the other.
    //
    // "JsonSerializer.Deserialize" and not "JsonSerializer": the serialize direction writes bytes the
    // plugin authored and reads nothing, and WebResponse.cs alone holds ten of those calls.
    // "new Utf8JsonReader" and not "Utf8JsonReader": a converter takes one as a `ref` PARAMETER over a
    // document its caller already opened, which is a read of somebody else's parse rather than a parse.
    private static readonly string[] ParseCalls =
    {
        "JsonSerializer.Deserialize",
        "JsonDocument.Parse",
        "JsonNode.Parse",
        "JObject.Parse",
        "JArray.Parse",
        "JToken.Parse",
        "JsonConvert.DeserializeObject",
        "new Utf8JsonReader",
    };

    // Sites whose bytes reach them only after passing the screen, mapped to the file the screen is invoked
    // in. The mapping is a path rather than a type so the assertion below can read the gate's source and
    // see the call: a gate file that stops calling Inspect is the failure this pair exists to catch, and it
    // would leave every behaviour test green.
    //
    // The gate moved once already - PR #1032 wrote this mapping against OidcDiscoveryReader.cs, #1061 moved
    // the call into the transport handler, and the mapping is re-pointed here rather than carried (#1187).
    private static readonly SortedDictionary<string, string> GatedJsonReads = new(StringComparer.Ordinal)
    {
        // The discovery body parsed for the two challenge-time facts. It is the string
        // OidcDiscoveryReader.ReadAsync took off a response that came back through RepeatedMemberScreen, so
        // a document naming a member twice was already refused at the transport and never reaches here.
        ["SSO-Auth/Api/Oidc/DiscoveryJson.cs"] = "SSO-Auth/Api/Oidc/RepeatedMemberScreen.cs",
    };

    // Sites over bytes the plugin itself shipped or produced, each with the reason it is not provider
    // input. A reason is required rather than conventional: "trusted" with no stated source is how a read
    // of provider input gets filed here by the next person in a hurry.
    private static readonly SortedDictionary<string, string> TrustedJsonReads = new(StringComparer.Ordinal)
    {
        // A localization catalog read out of this assembly's own embedded resources. The bytes are built
        // into the plugin; an attacker who can change them has already replaced the plugin.
        ["SSO-Auth/Api/Localization/SsoLocalizer.cs"] = "an embedded resource shipped inside this assembly",

        // The screen's own walk. It is the thing the other sites are screened BY, and it is written against
        // hostile input by construction: a raw Utf8JsonReader under an explicit depth bound that reports a
        // repeat instead of resolving one.
        ["SSO-Auth/Api/Oidc/StrictJson.cs"] = "the screening walk itself, which is what the gated reads are gated by",
    };

    // Sites that read UNTRUSTED input with no screen in front of them. This table is a disclosure, not a
    // dispensation: every entry names the issue that owes the decision, and the rule below pins the table's
    // contents exactly, so closing one of these has to move the entry rather than leave it standing.
    private static readonly SortedDictionary<string, string> UnscreenedUntrustedReads = new(StringComparer.Ordinal)
    {
        // The role claim's value, straight off the id_token, parsed by Newtonsoft with no repeated-member
        // check. #1053 is open on exactly this: the screen's Unreadable verdict is fail-closed in the
        // discovery reader and fail-open here, and deciding what Unreadable MEANS on a privilege path comes
        // before any code. Until it is decided the site stays visible here rather than filed as trusted.
        ["SSO-Auth/Api/Oidc/OidcRoleExtractor.cs"] = "the id_token role claim value; the Unreadable-on-a-privilege-path decision is #1053",
    };

    [Fact]
    public void UntrustedJson_IsParsedOnlyThroughTheScreenedSeam()
    {
        // Set equality in both directions, and that is deliberate. "No unknown site" alone would pass a
        // build where a declared read was deleted or renamed, leaving a table entry pointing at nothing and
        // the rule quietly covering less than it says. A site that appears and a site that disappears are
        // both edits somebody has to look at.
        var found = ParseSites();
        var declared = GatedJsonReads.Keys
            .Concat(TrustedJsonReads.Keys)
            .Concat(UnscreenedUntrustedReads.Keys)
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToList();

        Assert.Equal(declared, found);
    }

    [Fact]
    public void EveryGatedRead_NamesAGateFileThatStillInvokesTheScreen()
    {
        // What makes a read "gated" is not the table saying so. The gate is a call, in a file, and this is
        // the assertion that the call is still there - a screen removed from the transport would otherwise
        // leave this whole rule asserting a fact about a comment.
        foreach (var (read, gate) in GatedJsonReads)
        {
            var gatePath = Path.Combine(RepoRoot(), gate.Replace('/', Path.DirectorySeparatorChar));
            Assert.True(File.Exists(gatePath), $"The gate file declared for {read} does not exist: {gate}");
            Assert.Contains(
                CodeLinesOf(File.ReadAllText(gatePath)),
                line => line.Contains("StrictJson.Inspect(", StringComparison.Ordinal));
        }
    }

    [Fact]
    public void TheScanRefusesAVacuousPass()
    {
        // The failure this catches: the plugin's directory layout changes, the scan walks a tree with no
        // .cs files in it, finds nothing, and a rule that now covers zero sites reports success. An empty
        // result is the one answer this scan may never treat as good news.
        Assert.NotEmpty(ParseSites());

        // And the mirror of it - a table entry naming a path that no longer exists. Set equality above
        // already reddens on it, but it reddens with a diff of two lists; this says which path is dangling.
        foreach (var declared in GatedJsonReads.Keys.Concat(TrustedJsonReads.Keys).Concat(UnscreenedUntrustedReads.Keys))
        {
            Assert.True(
                File.Exists(Path.Combine(RepoRoot(), declared.Replace('/', Path.DirectorySeparatorChar))),
                $"A declared JSON read names a file that does not exist: {declared}");
        }
    }

    [Fact]
    public void UnguardedJsonRead_IsRejectedByTheScan()
    {
        // The must-catch half of the pair, over the predicate rather than over the tree: a raw parse of a
        // response body, spelled the way somebody adding one would spell it.
        const string Source = @"
internal static class Whatever
{
    internal static void Read(string body)
    {
        using var document = JsonDocument.Parse(body);
    }
}";

        Assert.True(HoldsAParseCall(Source));
    }

    [Fact]
    public void NonReadingJsonUse_IsNotFlaggedByTheScan()
    {
        // The adjacent must-not-catch twin. Every line here NAMES a JSON type, and none of them parses
        // untrusted bytes: a serialize, a converter taking somebody else's reader by ref, an options
        // object, and prose describing the very call the rule looks for. Widen the predicate to "mentions
        // a JSON type" and this fixture goes red, which is what stops the rule being tightened into one
        // that flags the whole file set.
        const string Source = @"
internal sealed class Whatever : JsonConverter<string?>
{
    // Deliberately not JsonDocument.Parse - the caller already opened the document.
    public override string? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => reader.GetString();

    public override void Write(Utf8JsonWriter writer, string? value, JsonSerializerOptions options)
        => writer.WriteRawValue(JsonSerializer.Serialize(value));
}";

        Assert.False(HoldsAParseCall(Source));
    }

    [Theory]
    [InlineData("var d = JsonDocument.Parse(body);", true)]
    [InlineData("// var d = JsonDocument.Parse(body);", false)]
    [InlineData("/* JsonDocument.Parse(body) */", false)]
    [InlineData("* the JsonDocument.Parse this replaced", false)]
    [InlineData("/// Replaces the old JsonDocument.Parse call.", false)]
    [InlineData("    var d = JsonDocument.Parse(body); // was JObject.Parse", true)]
    public void TheCodeReaderKeepsCallsAndDropsProse(string line, bool expected)
    {
        // The reader's whole contract, and its bound: it judges what a trimmed line STARTS with, so a
        // comment opened part-way along a line does not hide the code before it (the last row). A rule
        // built on it inherits exactly that, which is why the bound is pinned here rather than assumed.
        Assert.Equal(expected, HoldsAParseCall(line));
    }

    // Every repo-relative path under SSO-Auth/ whose code calls a parser, forward slashes so the table
    // entries read the same on either platform. Exact paths rather than file names: two files can share a
    // name, and an allowlist keyed on the short one would admit the wrong one.
    private static IReadOnlyList<string> ParseSites()
    {
        var root = RepoRoot();
        var pluginRoot = Path.Combine(root, "SSO-Auth");

        return Directory.EnumerateFiles(pluginRoot, "*.cs", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path))
            .Where(path => HoldsAParseCall(File.ReadAllText(path)))
            .Select(path => Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/'))
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToList();
    }

    // Whether a source text calls a parser on a code line.
    private static bool HoldsAParseCall(string source) =>
        CodeLinesOf(source).Any(line => ParseCalls.Any(call => line.Contains(call, StringComparison.Ordinal)));

    // A source text's trimmed CODE lines: line comments, block-comment openers, block continuations and
    // XML-doc lines are dropped. On CRLF input the trailing \r survives the split and is removed by the
    // Trim, so what a line says does not depend on the checkout's line endings.
    private static IEnumerable<string> CodeLinesOf(string source) =>
        source.Split('\n')
            .Select(line => line.Trim())
            .Where(text => !text.StartsWith("//", StringComparison.Ordinal)
                && !text.StartsWith("/*", StringComparison.Ordinal)
                && !text.StartsWith("*", StringComparison.Ordinal));

    // obj/bin hold generated and compiled output; this scan reads hand-written source only.
    private static bool IsBuildOutput(string path) =>
        path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
        || path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal);

    // The repository root, derived from this test file's compile-time path
    // (<root>/SSO-Auth.Tests/Oidc/<file>). CallerFilePath is baked in at build and CI builds on the same
    // checkout it tests, so the source tree is present for the scan.
    private static string RepoRoot([CallerFilePath] string thisFilePath = "") =>
        Directory.GetParent(Directory.GetParent(Path.GetDirectoryName(thisFilePath)!)!.FullName)!.FullName;
}
