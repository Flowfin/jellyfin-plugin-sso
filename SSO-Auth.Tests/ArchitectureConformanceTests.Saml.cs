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
/// Conformance rules for the SAML signature path: one XML stack end to end, parsing only through the hardened reader, and namespace-aware element resolution.
/// </content>
public partial class ArchitectureConformanceTests
{
    [Fact]
    public void SamlSignaturePath_UsesOneXmlStackEndToEnd()
    {
        // #1003. XML signature wrapping is a full authentication bypass, and it becomes reachable the same way
        // every time: the document that is verified and the document that is consumed stop being one object
        // graph. The surviving stack is System.Xml, because SignedXml resolves Reference/@URI against the very
        // XmlDocument instance it was constructed with, while XDocument, XPathDocument and XmlSerializer
        // cannot verify a signature at all and so force a second parse. This rule is the ratchet rather than a
        // proof of correctness, which the negative tests carry. The module scope holds because the only two
        // entry points are the two SAML validators and the linking round-trip re-enters the same one; a
        // future consumer that parses OuterXml elsewhere joins this surface.
        var samlSources = SamlModuleSourceFiles();

        // A comment can mention any of these without introducing anything, so comment/XML-doc lines are out of
        // scope - including this test's own prose were it ever moved into the module. "Regex" is banned here
        // but not by the out-of-module rule, which shares the type list: string-scraping a SAML document is a
        // second-view problem, whereas a regex elsewhere in the plugin is ordinary code.
        var stackOffenders = samlSources
            .SelectMany(path => XmlStackUsages(File.ReadAllText(path), SecondXmlStackTypes.Append("Regex"))
                .Select(offender => $"{Path.GetFileName(path)}:{offender}"))
            .ToList();

        Assert.True(
            stackOffenders.Count == 0,
            "The SAML module must read and navigate a SAML document through ONE XML stack (XmlDocument/XmlReader/XmlNamespaceManager + SignedXml). A second stack gives the verifier and the consumer different views of the same bytes - the 2025/26 SAML bypass wave's root cause (#1003). Offending lines: " + string.Join(" | ", stackOffenders));

        // The other way to grow a second view is string surgery on the markup instead of resolving through the
        // DOM. Scoped to the files that parse an inbound document, discovered by their XmlDocument
        // construction rather than hardcoded, so a new parser is covered the moment it is written and the
        // outbound builders are out of scope. Keying on the document rather than on the hardened-reader call
        // is what makes such a seam impossible to write without entering this scan.
        var inboundParsers = XmlDocumentConstructingFiles(samlSources);

        var stringOperations = new[] { "IndexOf(", "Substring(", "Contains(", "Split(", "Replace(", "StartsWith(", "EndsWith(" };
        var markupMarkers = new[] { "ID=", "URI=", "<saml", "<samlp", "<ds:", "Assertion", "Signature" };
        var scrapeOffenders = inboundParsers
            .SelectMany(path => CodeLines(path)
                .Where(l => stringOperations.Any(op => l.Text.Contains(op, StringComparison.Ordinal)))
                .Where(l => StringLiterals(l.Text).Any(literal => markupMarkers.Any(m => literal.Contains(m, StringComparison.Ordinal))))
                .Select(l => $"{Path.GetFileName(path)}:{l.Number}: {l.Text}"))
            .ToList();

        Assert.True(
            scrapeOffenders.Count == 0,
            "An inbound SAML parser must not extract an ID, a Reference URI, or an element name by string surgery on the markup - resolve it through the DOM, or the verified and the consumed document drift apart (#1003). Offending lines: " + string.Join(" | ", scrapeOffenders));

        // Sentinel against a vacuous pass: the bans above only mean something while the allowlisted stack is
        // still what the module uses. If the SAML core were rewritten onto something else entirely, every ban
        // would keep "passing" against a module that no longer parses XML this way - this is the assertion
        // that would catch it and force a conscious update of the rule.
        var moduleText = string.Concat(samlSources.Select(File.ReadAllText));
        var missing = AllowedXmlStackTypes
            .Where(marker => !moduleText.Contains(marker, StringComparison.Ordinal))
            .ToList();
        Assert.True(
            missing.Count == 0,
            "The allowlisted XML stack is no longer present in Api/Saml, so the second-stack bans would pass vacuously - update SamlSignaturePath_UsesOneXmlStackEndToEnd to the stack the module actually uses (#1003). Missing: " + string.Join(", ", missing));
    }

    [Fact]
    public void SamlSignaturePath_ParsesOnlyThroughTheHardenedReader()
    {
        // #1003. Staying on System.Xml is worth nothing if the document is loaded with the hardening switched
        // off, so each setting is required here: DtdProcessing.Prohibit, which is also the control behind the
        // standing CodeQL dismissal on this parser; XmlResolver null on both the document and the reader
        // settings; MaxCharactersInDocument, which bounds bulk where the DTD prohibition bounds only entities;
        // and PreserveWhitespace wherever a signature is verified, because exclusive canonicalization is
        // whitespace-sensitive. The seam itself is pinned: an XmlDocument here is populated only through
        // XmlReader.Create and Load(reader), and SignedXml.LoadXml is allowed because it parses no text.
        var samlSources = SamlModuleSourceFiles();
        var parsers = XmlDocumentConstructingFiles(samlSources);
        var offenders = new List<string>();

        foreach (var path in parsers)
        {
            var text = File.ReadAllText(path);
            var name = Path.GetFileName(path);
            var required = new (string Marker, string Description)[]
            {
                ("DtdProcessing = DtdProcessing.Prohibit", "DtdProcessing.Prohibit on the reader settings"),
                ("XmlResolver = null", "XmlResolver = null"),
                ("MaxCharactersInDocument", "a MaxCharactersInDocument bound"),
                ("XmlReader.Create(", "an XmlReader.Create parse seam"),
            };
            offenders.AddRange(required
                .Where(r => !text.Contains(r.Marker, StringComparison.Ordinal))
                .Select(r => $"{name}: missing {r.Description}"));

            // Whitespace fidelity matters only where a signature is verified over the document.
            if (text.Contains("SignedXml", StringComparison.Ordinal)
                && !text.Contains("PreserveWhitespace = true", StringComparison.Ordinal))
            {
                offenders.Add($"{name}: verifies signatures but does not set PreserveWhitespace = true");
            }
        }

        Assert.True(
            offenders.Count == 0,
            "Every SAML parser must load its untrusted document through the hardened reader (DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument, and PreserveWhitespace where signatures are verified) (#1003): " + string.Join(" | ", offenders));

        // The bypass ban, over the whole module rather than just the parsers: a NEW file could load a document
        // the unhardened way without constructing one in the shape the discovery recognises.
        // The bypass ban, over the whole module rather than just the parsers: a NEW file could load a document
        // the unhardened way without constructing one in the shape the discovery recognises. See
        // UnhardenedDocumentLoads for the two spellings this must catch and why a line regex could not.
        var bypasses = samlSources
            .SelectMany(path => UnhardenedDocumentLoads(File.ReadAllText(path))
                .Select(offender => $"{Path.GetFileName(path)}:{offender}"))
            .ToList();

        Assert.True(
            bypasses.Count == 0,
            "An XmlDocument in the SAML module may be populated only through XmlReader.Create + Load(reader) - LoadXml or Load on anything else skips the DTD/resolver/size hardening while still looking like the allowlisted stack (#1003): " + string.Join(" | ", bypasses));
    }

    [Theory]
    // The two spellings a line-level regex let through, and which a file-level "the settings appear somewhere"
    // check cannot catch either - a SECOND parse method added inside an existing hardened file would satisfy
    // every other arm of the rule while parsing with the reader's own defaults.
    [InlineData("xmlDoc.Load(new StringReader(xml));")] // "StringReader" contains "reader", so a substring carve-out admits it
    [InlineData("xmlDoc.Load(new StreamReader(stream));")] // same trick, other reader
    [InlineData("signedXmlDocument.LoadXml(raw);")] // a receiver whose NAME merely contains "signedXml"
    [InlineData("xmlDoc.Load(stream);")] // the plain unhardened load
    [InlineData("doc.Load(File.OpenText(path));")] // and via a factory call
    public void UnhardenedDocumentLoad_IsRejectedByTheHardenedReaderBan(string statement)
    {
        // Negative fixtures for the ban itself. The rule's own predicate is the thing under test here: a ban
        // whose failure message promises "only XmlReader.Create + Load(reader)" has to actually mean it, or a
        // future parse seam passes a rule written specifically to stop it.
        Assert.NotEmpty(UnhardenedDocumentLoads(statement));
    }

    [Theory]
    [InlineData("xmlDoc.Load(reader);")] // the hardened seam
    [InlineData("signedXml.LoadXml(signatureElement);")] // SignedXml's element overload - parses no text
    [InlineData("_signedXml.LoadXml(signatureElement);")] // the same, spelled as this repo's field convention
    public void HardenedDocumentLoad_IsAcceptedByTheHardenedReaderBan(string statement)
    {
        // The positive controls: the ban must not reject the two forms the module legitimately uses, or it
        // would be satisfied only by code that does not exist and would say nothing about code that does.
        Assert.Empty(UnhardenedDocumentLoads(statement));
    }

    [Fact]
    public void SamlDocumentParsing_HappensOnlyInsideTheSamlModule()
    {
        // #1003. The two rules above are scoped to Api/Saml, and that scope is sound only while nothing
        // outside the module can parse a SAML document, so no file under SSO-Auth outside Api/Saml may name
        // any XML document, reader or navigator type. The banned set is the shared list plus the stack the
        // module may use, rather than a hand-rolled subset: the first draft omitted XElement, and an XElement
        // parse in a flow service named none of its tokens. Two config files are allowlisted by exact
        // repo-relative path, because a suffix match would exempt any file of those names anywhere.
        var offenders = Directory
            .EnumerateFiles(Path.Combine(RepoTree.Root, "SSO-Auth"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path))
            .Select(path => (Path: path, Relative: Path.GetRelativePath(RepoTree.Root, path)))
            .Where(f => !f.Relative.StartsWith(SamlModuleRelativePath + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            .Where(f => !IsXmlConfigAllowlisted(f.Relative))
            .SelectMany(f => XmlStackUsages(File.ReadAllText(f.Path), SecondXmlStackTypes.Concat(AllowedXmlStackTypes))
                .Select(offender => $"{f.Relative}:{offender}"))
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "Only the SAML module may parse XML - a parse seam elsewhere would feed the signature path while sitting outside the scope of the one-stack and hardened-reader rules (#1003). Found: " + string.Join(" | ", offenders));
    }

    [Theory]
    // The spelling the hand-rolled banned list let through: a complete parse seam naming none of its tokens.
    [InlineData("using System.Xml.Linq;")]
    [InlineData("var assertion = XElement.Parse(samlResponse.Xml);")]
    [InlineData("var doc = XDocument.Parse(raw);")]
    [InlineData("var nav = new XPathDocument(reader).CreateNavigator();")]
    [InlineData("var s = new XmlSerializer(typeof(Foo));")]
    [InlineData("var d = new XmlDocument();")]
    public void SecondXmlStackSpelling_IsRejectedByTheStackScan(string statement)
    {
        // Negative fixtures for the shared type list itself. The out-of-module rule is only as good as this
        // list, and a rule that silently covers nothing is worse than no rule - it reads as protection.
        Assert.NotEmpty(XmlStackUsages(statement, SecondXmlStackTypes.Concat(AllowedXmlStackTypes)));
    }

    [Theory]
    [InlineData("var name = user.Name;")] // ordinary code
    [InlineData("// XElement.Parse would be a second stack")] // prose cannot introduce one
    [InlineData("private readonly IXmlSerializer _serializer;")] // the host's serializer abstraction, not a parser
    public void OrdinaryCode_IsAcceptedByTheStackScan(string statement)
    {
        // The positive controls: whole-word matching must not fire on prose or on IXmlSerializer, which is the
        // Jellyfin host abstraction the plugin is handed - not a parser it constructs.
        Assert.Empty(XmlStackUsages(statement, SecondXmlStackTypes.Concat(AllowedXmlStackTypes)));
    }

    [Theory]
    [InlineData("SSO-Auth/Config/PluginConfiguration.cs", true)]
    [InlineData("SSO-Auth/Config/SerializableDictionary.cs", true)]
    // The suffix-match evasions: same file NAME, different location. An allowlist matched by suffix would
    // exempt every one of these.
    [InlineData("SSO-Auth/Api/Flows/Config/PluginConfiguration.cs", false)]
    [InlineData("SSO-Auth/Api/Http/Config/SerializableDictionary.cs", false)]
    [InlineData("SSO-Auth/Config/PluginConfigurationExtra.cs", false)]
    public void XmlConfigAllowlist_MatchesByExactPathNotBySuffix(string relativePath, bool expected)
    {
        Assert.Equal(expected, IsXmlConfigAllowlisted(relativePath.Replace('/', Path.DirectorySeparatorChar)));
    }

    [Fact]
    public void BothSignatureValidators_ResolveTheirReferenceThroughTheSharedRule()
    {
        // #1003. The shared reference rule is only worth having while both validators actually CALL it. A
        // future edit that reinstated a local `uri[0] != '#'` check and dropped the call would leave the unit
        // tests green (the helper still behaves) and the end-to-end tests green (the platform's own guard
        // still rejects underneath) - the drift would be invisible to every other test in this PR. Same shape
        // as VerifiedIdentity_IsConstructedOnlyByProtocolValidators: pin the call sites, not just the callee.
        const string Invocation = "SamlSignatureReference.TryGetSameDocumentId(";

        // Sentinel: the rule's target must still exist under that name, so a rename fails HERE and forces a
        // conscious update rather than turning the scan into a no-op.
        Assert.True(
            typeof(SamlSignatureReference).GetMethod("TryGetSameDocumentId", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public) is not null,
            "SamlSignatureReference.TryGetSameDocumentId was renamed or removed; point this rule at the shared reference rule's new name (#1003).");

        var validators = SourceFilesDeclaring(new[] { typeof(SamlResponse), typeof(SamlLogoutRequest) });
        Assert.Equal(2, validators.Count);

        var missing = validators
            .Where(path => !SourceCallsInCode(File.ReadAllText(path), Invocation))
            .Select(Path.GetFileName)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "Both signature validators must resolve their Reference URI through the shared SamlSignatureReference rule - a local re-implementation is how the two paths drift on the question of WHAT a signature covers (#1003). Not calling it: " + string.Join(", ", missing));

        // And they must not carry a local re-implementation alongside it: the shared call has to be the whole
        // rule, not a first opinion the file then second-guesses.
        var localChecks = validators
            .SelectMany(path => CodeLines(path)
                .Where(l => Regex.IsMatch(l.Text, @"\[0\]\s*!=\s*'#'") || l.Text.Contains("referenceUri.Substring(1)", StringComparison.Ordinal))
                .Select(l => $"{Path.GetFileName(path)}:{l.Number}: {l.Text}"))
            .ToList();

        Assert.True(
            localChecks.Count == 0,
            "A signature validator must not re-implement the reference-URI rule locally alongside the shared one (#1003): " + string.Join(" | ", localChecks));
    }

    // The presence half of the rule above, fed synthetic source. A commented-out invocation is the shape that
    // defeats a whole-file text search, so it is pinned from both sides: every comment form the exclusion
    // knows about reads as absent, and a real call reads as present even when a comment names it too (#1122).
    [Theory]
    [InlineData("var id = SamlSignatureReference.TryGetSameDocumentId(uri);", true)]
    [InlineData("        var id = SamlSignatureReference.TryGetSameDocumentId(uri);", true)]
    [InlineData("// dropped: SamlSignatureReference.TryGetSameDocumentId( is no longer called here", false)]
    [InlineData("        // SamlSignatureReference.TryGetSameDocumentId(uri);", false)]
    [InlineData("/* SamlSignatureReference.TryGetSameDocumentId(uri); */", false)]
    [InlineData("     * SamlSignatureReference.TryGetSameDocumentId( - see the shared rule", false)]
    [InlineData("nothing here", false)]
    public void CallSitePresence_ReadsCodeLinesNotRawText(string line, bool expected)
    {
        Assert.Equal(expected, SourceCallsInCode(line, "SamlSignatureReference.TryGetSameDocumentId("));
    }

    [Fact]
    public void CallSitePresence_ACommentDoesNotStandInForARemovedCall()
    {
        var source = string.Join(
            "\n",
            "internal static bool Validate(string uri)",
            "{",
            "    // SamlSignatureReference.TryGetSameDocumentId( was inlined below; see #1003.",
            "    return uri.Length > 0 && uri[0] != '#';",
            "}");

        Assert.False(SourceCallsInCode(source, "SamlSignatureReference.TryGetSameDocumentId("));
        Assert.True(source.Contains("SamlSignatureReference.TryGetSameDocumentId(", StringComparison.Ordinal));
    }

    // The two comment exclusions in this file, asked the same question about the same line. The argument-level
    // scan (CallsTo, through IsOnACommentLine) reads the text ahead of a call; the line scan (CodeLinesOf)
    // reads whole lines; only a shared form list makes them agree, and they did NOT agree about a line opening
    // with /* until this row existed (#1214). Remove any form from OpensAComment and a row here goes red.
    //
    // The last row is the residual both of them carry: a comment opened part-way along a line hides nothing
    // from either scan. That is the honest state, not an oversight this row waves through - it is pinned so
    // that closing it later has to be a deliberate edit with a failing test in front of it.
    [Theory]
    [InlineData("document.Load(reader);", true)]
    [InlineData("        document.Load(reader);", true)]
    [InlineData("// document.Load(reader);", false)]
    [InlineData("        // document.Load(reader);", false)]
    [InlineData("/* document.Load(reader); */", false)]
    [InlineData("        /* document.Load(reader); */", false)]
    [InlineData("     * document.Load(reader); - the spelling before the hardened reader", false)]
    [InlineData("var settings = Harden(); // document.Load(reader);", true)]
    public void CommentExclusion_ReadsTheSameFormsForALineAndForACallSite(string line, bool isCode)
    {
        Assert.Equal(isCode, CallsTo(line, "Load").Any());
        Assert.Equal(isCode, CodeLinesOf(line).Any(l => l.Text.Contains("Load(", StringComparison.Ordinal)));
    }

    [Fact]
    public void SamlSignaturePath_ResolvesElementsNamespaceAware()
    {
        // #1003. Within one stack a namespace-agnostic lookup reintroduces the ambiguity a second parser would:
        // GetElementsByTagName matches any namespace, and an unprefixed XPath without a namespace manager
        // silently selects nothing in a namespaced document, which fails open into absent. Every such call
        // carries its namespace argument, checked by extracting the balanced argument list rather than by
        // matching line text. The single-argument GetAttribute is out of scope, because it matches the
        // qualified name, which SamlAttackShapeTests pins behaviourally.
        var samlSources = SamlModuleSourceFiles();
        var inspected = 0;
        var offenders = new List<string>();

        foreach (var path in samlSources)
        {
            var source = File.ReadAllText(path);
            foreach (var call in CallsTo(source, "GetElementsByTagName", "SelectNodes", "SelectSingleNode"))
            {
                inspected++;
                if (!HasTopLevelComma(call.Arguments))
                {
                    offenders.Add($"{Path.GetFileName(path)}:{call.Line}: {call.Method}({call.Arguments})");
                }
            }
        }

        Assert.True(
            offenders.Count == 0,
            "Every element lookup on a SAML document must be namespace-aware: pass the XmlNamespaceManager to SelectNodes/SelectSingleNode and the namespace URI to GetElementsByTagName (#1003). Namespace-agnostic lookups: " + string.Join(" | ", offenders));

        // Sentinel against a vacuous pass: the module resolves every element through these three calls, so a
        // scan that inspected almost none of them would mean the lookups moved somewhere this rule no longer
        // sees. The floor is deliberately well below today's count (24) so an honest refactor does not trip it,
        // while a wholesale move away from these APIs does.
        Assert.True(
            inspected >= 10,
            $"Only {inspected} element lookups were inspected in Api/Saml - the SAML core no longer resolves elements through GetElementsByTagName/SelectNodes/SelectSingleNode, so this rule is close to a no-op; point it at the lookup API the module actually uses (#1003).");
    }

    // The SAML module's location, as a repo-relative path, so the module-scope rules and the out-of-module
    // rule cannot disagree about where the boundary is.
    private static readonly string SamlModuleRelativePath = Path.Combine("SSO-Auth", "Api", "Saml");

    // Every XML stack that is NOT the one the SAML signature path is allowed to use (#1003). ONE list, shared
    // by the in-module ban and the out-of-module ban: a hand-rolled subset in either place is how a rule
    // silently stops covering the spelling it was written for - the out-of-module rule's first draft omitted
    // XElement, which is a complete parse seam on its own.
    private static readonly string[] SecondXmlStackTypes =
    {
        "System.Xml.Linq", "System.Xml.XPath", "System.Xml.Serialization",
        "XDocument", "XElement", "XAttribute", "XNamespace",
        "XPathDocument", "XPathNavigator", "XPathExpression", "CreateNavigator",
        "XmlSerializer", "DataContractSerializer", "XmlTextReader",
    };

    // The stack the SAML module IS allowed to use: banned everywhere else (only the SAML module parses SAML),
    // and required to still be present inside it (the vacuous-pass sentinel).
    private static readonly string[] AllowedXmlStackTypes =
    {
        "XmlDocument", "XmlReader", "XmlNamespaceManager", "SignedXml",
    };

    // The occurrences of any of the given XML-stack types in a source text, as "line: text". Whole-word
    // matching, so IXmlSerializer (the host abstraction the plugin is handed) does not match XmlSerializer,
    // and comment lines are excluded - prose can name a stack without introducing one.
    private static IEnumerable<string> XmlStackUsages(string source, IEnumerable<string> types)
    {
        var patterns = types.Select(t => new Regex(@"\b" + Regex.Escape(t) + @"\b")).ToList();
        return CodeLinesOf(source)
            .Where(l => patterns.Any(p => p.IsMatch(l.Text)))
            .Select(l => $"{l.Number}: {l.Text}");
    }

    // Whether a repo-relative path is one of the two XML-config files exempt from the out-of-module ban.
    // Compared by ORDINAL EQUALITY on the whole relative path: a suffix match would exempt any file with one
    // of these names in any Config/ directory anywhere in the tree, and an allowlist is the one place where
    // approximate identity is least acceptable.
    private static bool IsXmlConfigAllowlisted(string relativePath)
    {
        var allowlist = new[]
        {
            Path.Combine("SSO-Auth", "Config", "PluginConfiguration.cs"),
            Path.Combine("SSO-Auth", "Config", "SerializableDictionary.cs"),
        };

        return allowlist.Any(a => string.Equals(relativePath, a, StringComparison.Ordinal));
    }

    // The SAML module's hand-written sources, with the non-empty sentinel both #1003 rules depend on: a scan
    // over an empty file set would pass every ban vacuously.
    private static IReadOnlyList<string> SamlModuleSourceFiles()
    {
        var files = Directory
            .EnumerateFiles(Path.Combine(RepoTree.Root, SamlModuleRelativePath), "*.cs", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path))
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            files.Count > 0,
            "No source file was found under SSO-Auth/Api/Saml - the SAML module was renamed or moved, so the #1003 one-XML-stack rules would pass vacuously; point them at its new location.");
        return files;
    }

    // The SAML module's parse seams: the files that build an XmlDocument from untrusted input. Keyed on the
    // document construction, not on the reader call, so a parser written the unhardened way is still
    // discovered - and then failed by SamlSignaturePath_ParsesOnlyThroughTheHardenedReader. Carries the
    // non-empty sentinel both consumers need.
    private static IReadOnlyList<string> XmlDocumentConstructingFiles(IEnumerable<string> sources)
    {
        var files = sources
            .Where(path => CodeLines(path).Any(l => l.Text.Contains("new XmlDocument", StringComparison.Ordinal)))
            .ToList();

        Assert.True(
            files.Count > 0,
            "No SAML parse seam was found (nothing in Api/Saml constructs an XmlDocument any more), so the markup-scraping and hardened-reader scans would pass vacuously - point them at the new parse seam (#1003).");
        return files;
    }

    // Every unhardened way of populating an XmlDocument in a source text. Deliberately built on CallsTo +
    // BalancedArguments rather than on a line regex: a regex over the line cannot tell
    // `Load(new StringReader(xml))` from `Load(reader)` without excluding nested parentheses, and a substring
    // carve-out for "reader" ADMITS the former - "StringReader" contains "reader" - which is precisely the
    // most natural unhardened spelling, going through XmlDocument.Load(TextReader) with that reader's own
    // defaults instead of the hardened XmlReaderSettings. Likewise the LoadXml exemption is ordinal-EQUAL on
    // the receiver, not a substring: a variable merely NAMED signedXmlDocument is not a SignedXml.
    private static IEnumerable<string> UnhardenedDocumentLoads(string source)
    {
        foreach (var call in CallsTo(source, "Load", "LoadXml"))
        {
            if (call.Method == "LoadXml")
            {
                // The SignedXml overload takes an XmlElement already inside the verified DOM and parses no
                // text. On anything else, LoadXml means "build a document from a string" - the bypass. Both
                // the local and the field spelling of the receiver are accepted, because "_signedXml" is this
                // repo's own field convention and rejecting it would be a confusing false positive.
                if (!string.Equals(call.Receiver, "signedXml", StringComparison.Ordinal)
                    && !string.Equals(call.Receiver, "_signedXml", StringComparison.Ordinal))
                {
                    yield return $"{call.Line}: {call.Receiver}.LoadXml({call.Arguments})";
                }

                continue;
            }

            // Load is the hardened seam only when its argument IS the hardened reader - an identifier, not a
            // freshly constructed one, and not a factory call that returns some other reader or stream.
            var argument = call.Arguments.Trim();
            if (argument.Contains("new ", StringComparison.Ordinal)
                || argument.Contains('(', StringComparison.Ordinal)
                || !argument.Contains("reader", StringComparison.OrdinalIgnoreCase))
            {
                yield return $"{call.Line}: {call.Receiver}.Load({call.Arguments})";
            }
        }
    }
}
