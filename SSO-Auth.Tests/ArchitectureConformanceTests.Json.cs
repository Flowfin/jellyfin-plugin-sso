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
/// Conformance rules for the JSON parse seam: untrusted bytes are read only through the screen, and every declared gate still invokes it.
/// </content>
public partial class ArchitectureConformanceTests
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
    // the call into the transport handler, and the mapping was re-pointed rather than carried (#1187).
    private static readonly SortedDictionary<string, string> GatedJsonReads = new(StringComparer.Ordinal)
    {
        // The discovery body parsed for the two challenge-time facts. It is the string
        // OidcDiscoveryReader.ReadAsync took off a response that came back through RepeatedMemberScreen, so
        // a document naming a member twice was already refused at the transport and never reaches here.
        ["SSO-Auth/Api/Oidc/DiscoveryJson.cs"] = "SSO-Auth/Api/Oidc/RepeatedMemberScreen.cs",

        // The id_token role claim's value. Here the gate is in the reading file itself rather than in a
        // transport ahead of it: the value arrives as a claim on an already-validated token, so there is no
        // response for a handler to sit in front of, and the screen runs on the string before Newtonsoft is
        // consulted at all (#1324).
        ["SSO-Auth/Api/Oidc/OidcRoleExtractor.cs"] = "SSO-Auth/Api/Oidc/OidcRoleExtractor.cs",

        // The account-expiry claim's value, walked to a scalar when the configured path is dotted (#1143).
        // Same shape as the role claim above and gated the same way: the value is a claim on an
        // already-validated token, so the screen runs in the reading file on the string, ahead of
        // Newtonsoft, over exactly the scopes the walk descends through.
        ["SSO-Auth/Api/Oidc/OidcAuthorizeStateBuilder.cs"] = "SSO-Auth/Api/Oidc/OidcAuthorizeStateBuilder.cs",

        // The declarative provider document read off a mounted path at startup (#1095). The gate is in the
        // reading file, like the two claim reads above and for the same reason: the bytes arrive as a file
        // rather than as a response, so there is no transport for a handler to sit in front of, and the
        // screen runs on the text before the deserializer is consulted. Every object scope is screened
        // rather than a named subset - this caller hands the whole document to a deserializer whose indexed
        // member set it does not control, which is the discovery posture rather than the claim-walk one. A
        // member named twice on this surface decides a client id, an endpoint or a secret, so it is refused
        // rather than resolved by whichever of the two parsers happens to read it.
        ["SSO-Auth/Config/DeclarativeProviderConfig.cs"] = "SSO-Auth/Config/DeclarativeProviderConfig.cs",

        // The same document, re-read as a node tree to resolve the secret references in it (#1096). The gate
        // is the loader rather than this file, and the ordering is what makes that true: the pass runs
        // between the screen and the deserializer, over bytes the screen has already cleared, so a document
        // naming a member twice never reaches it. It is named here rather than folded into the entry above
        // because what this read decides is the narrower and sharper half - which environment variable or
        // which file supplies a client secret or a signing key.
        ["SSO-Auth/Config/DeclarativeSecretReference.cs"] = "SSO-Auth/Config/DeclarativeProviderConfig.cs",
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
        // EMPTY, and that is a state this rule has to hold rather than a reason to delete the table. The one
        // entry it carried was the role claim's value, disclosed here while #1053 decided what an unreadable
        // document means on a privilege path; #1324 put the screen in front of it and the entry moved up to
        // the gated table. An empty disclosure is the honest reading of the tree today, and the next
        // unscreened read has a table to land in instead of a decision to re-open.
    };

    /// <summary>
    /// Holds the shipped plugin's JSON parse sites to a declared list, so a new one cannot appear without a
    /// decision about the bytes it reads (#1005, #1187). Every site under <c>SSO-Auth/</c> is named in
    /// exactly one of three tables: the reads reached only through the repeated-member screen, the reads
    /// over bytes the plugin itself owns, and the reads that are neither - untrusted input parsed with no
    /// screen in front of it. That third table is the point of the rule. A scan that only asked "is this
    /// site allowlisted" would let an unscreened untrusted read be written into the trusted list and
    /// disappear; here it has its own table, its own name and the issue that owes the decision.
    /// <para>
    /// The scan reads CODE lines only, through the same <see cref="CodeLinesOf"/> every other rule in this
    /// file uses. The likeliest edit that defeats a call-site rule is removing the call and describing the
    /// removal in a comment that still names it, which reads as diligence and would keep a whole-file text
    /// search green (#1122).
    /// </para>
    /// </summary>
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
            var gatePath = Path.Combine(RepoTree.Root, gate.Replace('/', Path.DirectorySeparatorChar));
            Assert.True(File.Exists(gatePath), $"The gate file declared for {read} does not exist: {gate}");
            Assert.True(
                SourceCallsInCode(File.ReadAllText(gatePath), "StrictJson.Inspect("),
                $"The gate file declared for {read} no longer calls the screen: {gate}");
        }
    }

    [Fact]
    public void TheJsonParseScanRefusesAVacuousPass()
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
                File.Exists(Path.Combine(RepoTree.Root, declared.Replace('/', Path.DirectorySeparatorChar))),
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

    // Every hand-written .cs file the shipped plugin is built from. Shared by the parse-site scan and the
    // request-body scan, so the two cannot drift apart on which tree they walk.
    private static IEnumerable<string> PluginSourceFiles() =>
        Directory.EnumerateFiles(Path.Combine(RepoTree.Root, "SSO-Auth"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path));

    // Every repo-relative path under SSO-Auth/ whose code calls a parser, forward slashes so the table
    // entries read the same on either platform. Exact paths rather than file names: two files can share a
    // name, and an allowlist keyed on the short one would admit the wrong one.
    private static IReadOnlyList<string> ParseSites() =>
        PluginSourceFiles()
            .Where(path => HoldsAParseCall(File.ReadAllText(path)))
            .Select(path => Path.GetRelativePath(RepoTree.Root, path).Replace(Path.DirectorySeparatorChar, '/'))
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToList();

    // Whether a source text calls a parser on a code line.
    private static bool HoldsAParseCall(string source) =>
        ParseCalls.Any(call => SourceCallsInCode(source, call));

    // obj/bin hold generated and compiled output; the source scans read hand-written source only.
    private static bool IsBuildOutput(string path) =>
        path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
        || path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal);
}
