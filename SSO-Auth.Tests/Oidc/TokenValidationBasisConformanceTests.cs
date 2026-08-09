// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Holds the shipped plugin to ONE hardened <c>TokenValidationParameters</c>, and pins what that one basis
/// is allowed to accept (#1004). Both halves are the rule. A second basis built somewhere else could omit
/// <c>ValidAlgorithms</c>, which lets the handler take the algorithm from the token header; and the one
/// basis that exists could have <c>HS256</c> added to its allowlist, which turns the client secret every
/// provider already holds into a token-signing key.
/// <para>
/// The property was true before this file existed and nothing refused a change to it.
/// <see cref="OidcSignatureKeys"/>' own summary says there is "provably no second, laxer verification
/// path"; until now the proof was a reader's grep, and a second builder would have landed green.
/// </para>
/// <para>
/// WHAT THIS SCAN CANNOT SEE, stated so the rule is not read as exhaustive. It judges which FILES name the
/// type on a code line, so a second construction added inside the file already on the table is invisible to
/// it - the standing limit of this rule family. It reads source, so it cannot see a returned basis being
/// mutated by its caller either; that window was a code change rather than a rule (#1176), and this scan
/// was named in that issue as the thing that could not catch it. And a caller that passes a target-typed
/// <c>new()</c> straight into a handler never names the type at all. Review owns all three.
/// </para>
/// </summary>
public class TokenValidationBasisConformanceTests
{
    // The type whose construction is being held to one place. Scanning for the NAME rather than for
    // "new TokenValidationParameters" is deliberate: C# target-typed construction spells a second builder
    // as `= new() { ... }`, which a scan for the longer phrase reads as absent.
    private const string TypeName = "TokenValidationParameters";

    // The construction spelling the one declared builder must still carry. Without this the file could
    // delegate to a helper elsewhere and the table above would go on naming it as the builder.
    private const string ConstructionCall = "new TokenValidationParameters";

    // The value that marks the ONE file allowed to build. Any other value is an ordinary reason a file
    // names the type without constructing one, and the assertion below reads it as exactly that.
    private const string Builder = "builds the one hardened basis";

    // Every plugin file whose CODE names the type, and what each one does with it. Exact repo-relative
    // paths, not file names: two files can share a short name and a table keyed on it would admit the
    // wrong one. A path here is a claim a reviewer has to agree with, which is the point - a new file
    // naming the type reddens the rule until somebody writes down what it does with it.
    private static readonly SortedDictionary<string, string> DeclaredFiles = new(StringComparer.Ordinal)
    {
        ["SSO-Auth/Api/Oidc/OidcSignatureKeys.cs"] = Builder,
    };

    /// <summary>
    /// The algorithm families in RFC 7518 whose verification key is PUBLIC. Anything outside them is either
    /// symmetric - verified with a secret the relying party and the provider both hold, so either party can
    /// mint a token this plugin would accept - or <c>none</c>, which is unauthenticated by definition.
    /// </summary>
    private static readonly string[] AsymmetricPrefixes = { "RS", "PS", "ES" };

    [Fact]
    public void EveryFileNamingTheValidationBasis_IsDeclared()
    {
        // Set equality, and the direction that is easy to skip is the one that matters here: "no unknown
        // file" alone keeps passing over a tree where the declared builder was deleted or renamed, leaving
        // a rule that asserts a fact about nothing.
        Assert.Equal(DeclaredFiles.Keys.ToList(), FilesNamingTheType());
    }

    [Fact]
    public void ExactlyOneDeclaredFile_ActuallyConstructsTheBasis()
    {
        // The table says which file builds; this reads the file and checks it still does. A builder that
        // quietly started delegating would leave the entry above standing and true-looking.
        var builders = DeclaredFiles
            .Where(entry => entry.Value == Builder)
            .Select(entry => entry.Key)
            .ToList();

        var constructing = DeclaredFiles.Keys
            .Where(path => HoldsAConstruction(File.ReadAllText(AbsolutePathOf(path))))
            .ToList();

        Assert.Equal(builders, constructing);
        Assert.Single(constructing);
    }

    [Fact]
    public void TheScanRefusesAVacuousPass()
    {
        // An empty result is the one answer this scan may never treat as good news: a renamed plugin root,
        // a layout change, a scan walking a tree with no .cs files in it. Set equality reddens on that too,
        // but it reddens with a diff of two lists; this says the scan itself found nothing.
        Assert.NotEmpty(FilesNamingTheType());

        foreach (var declared in DeclaredFiles.Keys)
        {
            Assert.True(
                File.Exists(AbsolutePathOf(declared)),
                $"A declared file names a path that does not exist: {declared}");
        }
    }

    [Fact]
    public void ASecondBasis_IsRejectedByTheScan_InBothSpellings()
    {
        // The must-catch half, over the predicate rather than over the tree. Two rows, because the second
        // is the one a scan for "new TokenValidationParameters" would wave through: target-typed
        // construction never writes the type name next to `new`.
        const string Explicit = @"
internal static class Whatever
{
    internal static TokenValidationParameters Build() => new TokenValidationParameters { RequireSignedTokens = true };
}";

        const string TargetTyped = @"
internal static class Whatever
{
    internal static TokenValidationParameters Build()
    {
        TokenValidationParameters basis = new() { RequireSignedTokens = false };
        return basis;
    }
}";

        Assert.True(NamesTheType(Explicit));
        Assert.True(NamesTheType(TargetTyped));

        // And the narrower predicate, the one that says which declared file BUILDS, reads both spellings
        // too. It has to: it is the check that would otherwise redden on a rewrite from one to the other,
        // which is a change to nobody's posture.
        Assert.True(HoldsAConstruction(Explicit));
        Assert.True(HoldsAConstruction(TargetTyped));
    }

    [Fact]
    public void ProseAboutTheBasis_IsNotFlaggedByTheScan()
    {
        // The adjacent must-not-catch twin, and it is a live shape rather than an invented one:
        // OidcLoginService.cs names the type in a comment today and in no code line. If the scan read raw
        // text, that file would have to be declared, and a rule that has to declare every file mentioning
        // a type in prose is one nobody keeps accurate.
        const string Source = @"
internal sealed class Whatever
{
    // Nothing here holds a TokenValidationParameters that could be weakened after the fact.
    /// <summary>Reads a basis built elsewhere; see TokenValidationParameters on the builder.</summary>
    internal static bool Signed() => true;
}";

        Assert.False(NamesTheType(Source));
    }

    [Theory]
    [InlineData("TokenValidationParameters basis = new();", true)]
    [InlineData("// TokenValidationParameters basis = new();", false)]
    [InlineData("/* TokenValidationParameters */", false)]
    [InlineData("* the TokenValidationParameters this replaced", false)]
    [InlineData("/// Replaces the old TokenValidationParameters basis.", false)]
    [InlineData("return Build(); // no TokenValidationParameters here", true)]
    public void TheCodeReaderKeepsCodeAndDropsProse(string line, bool expected)
    {
        // The reader's whole contract and its bound: it judges what a TRIMMED line starts with, so a
        // comment opened part-way along a line does not hide the code before it - and the last row shows
        // the cost of that, a trailing comment that makes an innocent line count. Erring toward declaring
        // a file is the safe direction for this rule; erring the other way hides a builder.
        Assert.Equal(expected, NamesTheType(line));
    }

    [Fact]
    public void TheAlgorithmAllowlist_AdmitsNoSymmetricAlgorithmAndNoNone()
    {
        // The half no site scan can reach. One builder is worth nothing if HS256 is added to what it
        // accepts: the client secret is a value the provider and this plugin both hold, so an HS* entry
        // makes every party to the OAuth exchange able to mint an id_token this plugin verifies.
        foreach (var algorithm in OidcSignatureKeys.AllowedSignatureAlgorithms)
        {
            Assert.DoesNotContain("HS", algorithm, StringComparison.OrdinalIgnoreCase);
            Assert.NotEqual("none", algorithm, StringComparer.OrdinalIgnoreCase);

            // Stated as an allowlist rather than as those two denials. "Not HS, not none" admits an entry
            // nobody has thought about yet - a future symmetric family, a vendor spelling - and this rule
            // exists to make a widening a thing somebody writes down here.
            Assert.Contains(
                AsymmetricPrefixes,
                prefix => algorithm.StartsWith(prefix, StringComparison.Ordinal));
        }
    }

    [Fact]
    public void TheAlgorithmAllowlist_CoversTheThreeAsymmetricFamilies()
    {
        // The bound from the OTHER side, and it is not decoration. Every assertion above is a per-entry
        // denial, so an allowlist tightened to nothing - or to one family - satisfies all of them
        // vacuously. That is the shape a stub takes, and #1068 records the same mistake made on a length
        // bound: pinned from the ceiling only, tightening it to two characters passed.
        //
        // This does not forbid tightening the shipped allowlist. It makes tightening reddens here, so it
        // is argued rather than absorbed - dropping a family an IdP in the field signs with is a lockout,
        // and that is the cost this side of the pin stands for.
        foreach (var prefix in AsymmetricPrefixes)
        {
            Assert.Contains(
                OidcSignatureKeys.AllowedSignatureAlgorithms,
                algorithm => algorithm.StartsWith(prefix, StringComparison.Ordinal));
        }
    }

    // Every repo-relative path under SSO-Auth/ whose CODE names the type, forward slashes so the comparison
    // reads the same on either platform.
    private static IReadOnlyList<string> FilesNamingTheType()
    {
        var root = RepoTree.Root;
        var pluginRoot = Path.Combine(root, "SSO-Auth");

        return Directory.EnumerateFiles(pluginRoot, "*.cs", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path))
            .Where(path => NamesTheType(File.ReadAllText(path)))
            .Select(path => Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/'))
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToList();
    }

    // Whether a source text names the type on a code line.
    private static bool NamesTheType(string source) =>
        CodeLinesOf(source).Any(line => line.Contains(TypeName, StringComparison.Ordinal));

    // Whether a source text constructs one, in either spelling C# offers: the type named next to new, or
    // a target-typed new on a line that names the type as the target. The second row is not hypothetical
    // tidiness - it is the ordinary way this construction gets rewritten, and a check that only knew the
    // first spelling would redden on a refactor that changed nothing about the posture.
    private static bool HoldsAConstruction(string source) =>
        CodeLinesOf(source).Any(line =>
            line.Contains(ConstructionCall, StringComparison.Ordinal)
            || (line.Contains(TypeName, StringComparison.Ordinal) && line.Contains("new(", StringComparison.Ordinal)));

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

    private static string AbsolutePathOf(string repoRelative) =>
        Path.Combine(RepoTree.Root, repoRelative.Replace('/', Path.DirectorySeparatorChar));
}
