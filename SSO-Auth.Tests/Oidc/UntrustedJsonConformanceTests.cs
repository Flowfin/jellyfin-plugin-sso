// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The structural half of #1005. The claim, stated at the width it is actually held: every JSON read seam
/// this scan's own predicate matches, in a file under <c>SSO-Auth/</c>, is DECLARED — as gated by a named
/// gate file, as reading trusted bytes, or as an untreated provider-supplied read with the issue that owns
/// deciding what to do about it. It is a call-level property no reflection over types can see, so it is a
/// source scan, in the shape the SAML hardened-reader ban already uses here — with the same must-catch /
/// adjacent-must-not-catch fixtures for the scan's own predicate, because a scan nobody has seen go red is
/// decorative.
///
/// What the scan does NOT see, so that nothing downstream reads more into a green run: a document parsed by
/// constructing a parser type directly (<c>new JsonWebToken(…)</c>, <c>new JsonWebKeySet(…)</c>) matches
/// none of its seams. That surface is covered instead by <c>DuplicateJsonKeyPostureTests</c>, which pins the
/// duplicate-key posture of those parsers and asserts that every reader of the id_token reaches one value.
///
/// This rule lives in its own file rather than in <c>ArchitectureConformanceTests</c> while #1030 is open on
/// that file; folding it in once #1030 has merged is #1037.
/// </summary>
public class UntrustedJsonConformanceTests
{
    // The provider-supplied JSON read seams that ARE screened, listed by the file they live in and the file
    // whose gate covers them. Both are pure readers of the discovery document and are gated at the boundary
    // that fetches it, not individually: the tolerant one would fail OPEN if it refused a document on its own
    // (its false means "do not require the RFC 9207 iss"), so the gate belongs where refusing means refusing
    // the login.
    //
    // A file, not a call, because a file is what a scan can identify — so an entry claims only that the JSON
    // read seams in the key file are covered by the gate in the value file. OidcResponseIssuer.cs also reads
    // an id_token, which is not a JSON read seam (it goes through JsonWebToken) and needs no gate of its own:
    // all five of its readers share one parser, which DuplicateJsonKeyPostureTests asserts rather than
    // assumes. A second document reached through a seam this scan DOES match would show up as its own
    // entry — there is no way to add one to a listed file without the list saying which gate covers it.
    private static readonly Dictionary<string, string> GatedJsonReads = new(StringComparer.Ordinal)
    {
        ["SSO-Auth/Api/Oidc/PkceDiscovery.cs"] = "SSO-Auth/Api/Oidc/OidcDiscoveryReader.cs",
        ["SSO-Auth/Api/Oidc/OidcResponseIssuer.cs"] = "SSO-Auth/Api/Oidc/OidcDiscoveryReader.cs",
    };

    // The provider-supplied reads that are deliberately NOT screened, each with the issue that owns deciding
    // what screening them should mean. This list is the honest half of the rule: without it the scan would
    // either have to claim a coverage it does not have, or force a screen onto a path whose failure mode is
    // still an open question. An entry here is a declaration, not an exemption — the issue is what closes it.
    //
    // The role claim reaches the extractor through a parser that accepts grammars the screen cannot read, and
    // what an UNREADABLE claim should mean on a path that decides privileges is a design question rather than
    // a patch: refusing costs every role of a provider that emits one of those grammars, proceeding disables
    // the screen on exactly the path that matters. #1053 settles that contract before any code.
    private static readonly Dictionary<string, string> UnscreenedJsonReads = new(StringComparer.Ordinal)
    {
        ["SSO-Auth/Api/Oidc/OidcRoleExtractor.cs"] = "#1053",
    };

    // The reads whose input is not provider-supplied, each by EXACT repo-relative path. A suffix match would
    // exempt any file of that name anywhere under SSO-Auth/, and an allowlist is the last place to be
    // approximate about identity.
    private static readonly HashSet<string> TrustedJsonReads = new(StringComparer.Ordinal)
    {
        "SSO-Auth/Api/Localization/SsoLocalizer.cs", // per-culture catalogues embedded in the assembly at build
        "SSO-Auth/Api/Oidc/StrictJson.cs", // the gate itself, which necessarily reads the document it screens
    };

    private const string GateCall = "StrictJson.Inspect";

    [Fact]
    public void UntrustedJson_IsParsedOnlyThroughTheStrictHelper()
    {
        var sources = Directory
            .EnumerateFiles(Path.Combine(RepoRoot(), "SSO-Auth"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path))
            .Select(path => (Path: path, Relative: Relative(path)))
            .ToList();

        // The sentinel. A moved repo root, a renamed project folder or a build-output filter that swallowed
        // the tree would leave every assertion below trivially satisfied; the rule has to prove it read
        // something first, and specifically that it read the files it claims to govern.
        Assert.True(sources.Count > 50, $"The scan found only {sources.Count} source files under SSO-Auth/ — it is not reading the tree it governs.");

        var seams = sources
            .Select(f => (f.Relative, Seams: JsonReadSeams(File.ReadAllText(f.Path))))
            .Where(f => f.Seams.Count > 0)
            .ToDictionary(f => f.Relative, f => f.Seams, StringComparer.Ordinal);

        foreach (var known in GatedJsonReads.Keys.Concat(UnscreenedJsonReads.Keys).Concat(TrustedJsonReads))
        {
            Assert.True(seams.ContainsKey(known), $"{known} is listed as a JSON read site but the scan found no read seam in it — the list has drifted from the code, so the rule is checking nothing there.");
        }

        var unlisted = seams.Keys
            .Where(relative => !GatedJsonReads.ContainsKey(relative) && !UnscreenedJsonReads.ContainsKey(relative) && !TrustedJsonReads.Contains(relative))
            .Select(relative => $"{relative} ({string.Join(", ", seams[relative])})")
            .ToList();

        Assert.True(
            unlisted.Count == 0,
            "A new JSON read site must declare itself: gated by a named gate file, reading trusted bytes, or unscreened with the issue that owns the decision (#1005). Undeclared: " + string.Join(" | ", unlisted));

        // Read as CODE, with the comments stripped — the same treatment the rule below gives the gate's own
        // source, and for the same reason: a gate file's prose names the call it makes, so a raw text match
        // is satisfied by a doc comment mentioning it. Under an assertion message that says a comment is not
        // a control, that is the exact failure the message describes.
        var ungated = GatedJsonReads
            .Where(entry => !CodeOf(File.ReadAllText(Path.Combine(RepoRoot(), entry.Value.Replace('/', Path.DirectorySeparatorChar)))).Contains(GateCall, StringComparison.Ordinal))
            .Select(entry => $"{entry.Key} is declared gated by {entry.Value}, which does not call {GateCall}")
            .ToList();

        Assert.True(ungated.Count == 0, "A declared gate that never calls the gate is a comment, not a control: " + string.Join(" | ", ungated));
    }

    [Theory]
    // The must-catch fixtures for the scan's own predicate. The first block is the spellings a list written
    // around JObject.Parse alone lets through — each a complete read seam naming none of the first two
    // tokens. The second is the same point one turn further: every one of these reads a whole document while
    // naming none of the spellings in the first block, and a rule anchored to exact verb names walks past all
    // of them while its own documentation claims it governs every read under SSO-Auth/.
    [InlineData("var o = JObject.Parse(body);")]
    [InlineData("var f = JsonConvert.DeserializeObject<Foo>(body);")]
    [InlineData("using var d = JsonDocument.Parse(body);")]
    [InlineData("var f = JsonSerializer.Deserialize<Foo>(body);")]
    [InlineData("var n = JsonNode.Parse(body);")]
    [InlineData("var t = JToken.Parse(body);")]
    [InlineData("var a = JArray.Parse(body);")]
    [InlineData("var r = new Utf8JsonReader(bytes);")]
    [InlineData("var f = await JsonSerializer.DeserializeAsync<Foo>(stream);")]
    [InlineData("using var d = await JsonDocument.ParseAsync(stream);")]
    [InlineData("var o = JObject.Load(reader);")]
    [InlineData("var t = JToken.ReadFrom(reader);")]
    [InlineData("JsonConvert.PopulateObject(body, target);")]
    [InlineData("var r = new JsonTextReader(new StringReader(body));")]
    [InlineData("var f = await response.Content.ReadFromJsonAsync<Foo>();")]
    public void UnguardedJsonRead_IsRejectedByTheScan(string statement)
    {
        Assert.NotEmpty(JsonReadSeams(statement));
    }

    [Theory]
    // The adjacent must-not-catch fixtures. The write side is the one that matters: the served auth pages
    // serialise a dozen localised strings through JsonSerializer.Serialize, and a predicate that matched the
    // type name rather than the read call would flag every one of them and be switched off within a week.
    [InlineData("var json = JsonSerializer.Serialize(value);")]
    [InlineData("[System.Text.Json.Serialization.JsonConverter(typeof(WriteOnlySecretConverter))]")]
    [InlineData("using Newtonsoft.Json.Linq;")]
    [InlineData("var o = new JObject();")]
    [InlineData("public override string? Read(ref Utf8JsonReader reader, Type t, JsonSerializerOptions o)")]
    public void NonReadingJsonUse_IsNotFlaggedByTheScan(string statement)
    {
        Assert.Empty(JsonReadSeams(statement));
    }

    [Fact]
    public void StrictJson_NeverDependsOnJsonSerializerOptions()
    {
        // The gate must reach the same decision on net9.0 and net10.0, and the System.Text.Json members that
        // would express it directly do not exist on both: referencing JsonSerializerOptions.Strict fails the
        // net9.0 build with CS0117, because the plugin binds the HOST's System.Text.Json — .NET 9's in the
        // Jellyfin 10.11 line. Writing the gate in terms of any of these would make one leg silently weaker,
        // and no test in this project could see it: this test process loads a 10.x System.Text.Json on BOTH
        // legs, so the assembly a test observes is never the one production binds.
        // Read as CODE, with the comments stripped. The gate's own documentation has to name the members it
        // refuses to use in order to explain why it does not use them, and a rule that cannot tell prose from
        // a call would force that reasoning out of the file to stay green.
        var gate = CodeOf(File.ReadAllText(Path.Combine(RepoRoot(), "SSO-Auth", "Api", "Oidc", "StrictJson.cs")));

        Assert.Contains("Utf8JsonReader", gate, StringComparison.Ordinal);
        foreach (var forbidden in new[] { "JsonSerializerOptions", "AllowDuplicateProperties", "JsonSerializer.Deserialize", "JsonDocument.Parse" })
        {
            Assert.DoesNotContain(forbidden, gate, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void TheCodeReaderKeepsCallsAndDropsProse()
    {
        // The must-catch / must-not-catch pair for the stripper the rule above depends on. Without it the
        // rule could be made green by a stripper that deleted everything, which would assert nothing at all —
        // and its Contains half would be the only thing standing in the way.
        var stripped = CodeOf("/// A doc comment naming JsonSerializerOptions.\nvar r = new Utf8JsonReader(b); // JsonDocument.Parse\n/* JsonSerializer.Deserialize */");

        Assert.Contains("new Utf8JsonReader(b);", stripped, StringComparison.Ordinal);
        Assert.DoesNotContain("JsonSerializerOptions", stripped, StringComparison.Ordinal);
        Assert.DoesNotContain("JsonDocument.Parse", stripped, StringComparison.Ordinal);
        Assert.DoesNotContain("JsonSerializer.Deserialize", stripped, StringComparison.Ordinal);
    }

    // The source with its comments removed, block comments before line comments so that a `//` inside a block
    // cannot end a line early. Adequate here because the gate holds no string literal carrying either marker,
    // which the pair above keeps honest.
    private static string CodeOf(string source) =>
        Regex.Replace(Regex.Replace(source, @"/\*.*?\*/", string.Empty, RegexOptions.Singleline), @"//[^\n]*", string.Empty);

    // The read seams, as calls rather than as type names: the write side of the very same types is used
    // throughout the served pages and must not be caught. Utf8JsonReader is included by construction because
    // a hand-rolled walk is a read of the whole document, gate or bypass depending on where it sits.
    //
    // Each verb ends in \w* rather than a word boundary. A boundary anchors the rule to the exact spellings
    // whoever wrote it happened to think of, and every reader here has an -Async twin one keystroke away:
    // `Deserialize` with a trailing \b does not match `DeserializeAsync`, so the whole rule walked past an
    // await. The suffix wildcard costs a hypothetical over-match — a method named for a listed verb, which
    // belongs on one of the two lists anyway — and buys coverage of spellings that do not exist yet.
    private static IReadOnlyList<string> JsonReadSeams(string source) =>
        Regex.Matches(
                source,
                @"(?:JObject|JArray|JToken|JsonDocument|JsonNode)\s*\.\s*(?:Parse|Load|ReadFrom)\w*"
                + @"|JsonConvert\s*\.\s*(?:Deserialize|Populate)\w*"
                + @"|JsonSerializer\s*\.\s*Deserialize\w*"
                + @"|\.\s*Read(?:FromJson|AsAsync)\w*"
                + @"|new\s+(?:Utf8JsonReader|JsonTextReader)\b")
            .Select(m => m.Value)
            .Distinct(StringComparer.Ordinal)
            .ToList();

    private static bool IsBuildOutput(string path) =>
        path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
        || path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal);

    private static string Relative(string path) =>
        Path.GetRelativePath(RepoRoot(), path).Replace(Path.DirectorySeparatorChar, '/');

    // The repository root, from this file's compile-time path (<root>/SSO-Auth.Tests/Oidc/<file>) — the
    // resolution every source rule in this repo uses, ArchitectureConformanceTests included. A source scan
    // needs the sources, which exist only in a checkout, and the sentinel above fires with its own message if
    // this ever resolves somewhere else.
    private static string RepoRoot([CallerFilePath] string thisFilePath = "") =>
        Directory.GetParent(Directory.GetParent(Path.GetDirectoryName(thisFilePath)!)!.FullName)!.FullName;
}
