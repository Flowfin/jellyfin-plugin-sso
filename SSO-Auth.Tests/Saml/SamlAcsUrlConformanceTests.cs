// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Pins that the AssertionConsumerServiceURL this service provider PUBLISHES in its metadata, the one it
/// SENDS in the AuthnRequest, and the set it ACCEPTS a signed Recipient against are all composed in one
/// place (#1163).
///
/// <para>
/// Why a structural rule and not a unit test. <see cref="SamlRecipientValidator.IsBound"/> compares the
/// signed Recipient and Destination against the expected set with <c>StringComparer.Ordinal</c>, and it
/// only ever sees the set it was handed. A site that published one URL and accepted another would be an
/// endpoint-binding bypass that every test of the validator passes, because the disagreement is between two
/// CALLERS and the validator is not one of them. The property has to be asserted over the composition
/// sites, which is what this does.
/// </para>
/// </summary>
public class SamlAcsUrlConformanceTests
{
    // The path this SP's ACS URL is composed from. It is the ordinal bytes the identity provider echoes
    // back in the signed Recipient, so a second site spelling the same path a different way is the defect,
    // not a style question.
    private const string AcsPath = "/sso/SAML/";

    private const string Builder = "SSO-Auth/Api/Saml/SamlAcsUrlBuilder.cs";
    private const string FlowService = "SSO-Auth/Api/Flows/SamlLoginService.cs";
    private const string AssertionValidator = "SSO-Auth/Api/Saml/SamlAssertionValidator.cs";

    // The surface the must-not-catch clause names: the endpoints that arrive through SAML/ImportMetadata
    // are the IDENTITY PROVIDER's SSO and SLO addresses, read out of its metadata document at runtime. They
    // are not this SP's ACS URLs and a rule that swept them in would be demanding they come from a builder
    // that composes this server's own routes.
    private const string MetadataImporter = "SSO-Auth/Api/Http/SamlMetadataImporter.cs";

    [Fact]
    public void TheAcsPathIsComposedInExactlyOnePlace()
    {
        // The whole property in one assertion. As long as the path appears on a code line in one file, no
        // second site can be publishing or accepting a differently-composed string, because there is
        // nowhere else the string is made.
        Assert.Equal(new List<string> { Builder }, FilesWhoseCodeHolds(AcsPath));
    }

    [Fact]
    public void ThePublishSendAndAcceptSitesAllTakeTheUrlFromTheBuilder()
    {
        // Two files call the builder, and between them they are the three sites. The flow service holds
        // both the metadata leg and the AuthnRequest leg; the assertion validator holds the accepted set.
        var callers = FilesWhoseCodeHolds("SamlAcsUrlBuilder.");
        Assert.Equal(new List<string> { FlowService, AssertionValidator }.OrderBy(p => p, StringComparer.Ordinal).ToList(), callers);

        // And the publishing site is one of them rather than a third file that composes its own. Metadata
        // is the document an administrator hands the identity provider, so a published URL the SP does not
        // accept is the mismatch this rule exists to prevent, arriving by configuration rather than attack.
        var publishers = FilesWhoseCodeHolds("SamlSpMetadataBuilder.Build(");
        Assert.Equal(new List<string> { FlowService }, publishers);
        Assert.Subset(callers.ToHashSet(StringComparer.Ordinal), publishers.ToHashSet(StringComparer.Ordinal));
    }

    [Fact]
    public void TheIdentityProvidersOwnEndpointsAreNotSweptIn()
    {
        // The must-not-catch surface, asserted where a reader will look for it rather than left implied by
        // the two set equalities above. The importer reads the IdP's SSO and SLO Locations out of its
        // metadata; it composes no URL of this server's and calls no builder, and the rule says nothing
        // about it.
        Assert.True(
            File.Exists(Path.Combine(RepoRoot(), MetadataImporter.Replace('/', Path.DirectorySeparatorChar))),
            $"The must-not-catch surface no longer exists at {MetadataImporter}; re-point this rule before trusting it.");
        Assert.DoesNotContain(MetadataImporter, FilesWhoseCodeHolds(AcsPath));
        Assert.DoesNotContain(MetadataImporter, FilesWhoseCodeHolds("SamlAcsUrlBuilder."));
    }

    [Fact]
    public void ASecondIndependentlyComposedAcsUrl_IsRejectedByTheScan()
    {
        // The must-catch fixture, over the predicate rather than over the tree: the natural way somebody
        // adds a second composition, reached for because the builder was not to hand.
        const string Source = @"
internal static class Elsewhere
{
    internal static string Acs(string baseUrl, string provider) =>
        baseUrl + ""/sso/SAML/post/"" + provider;
}";

        Assert.True(HoldsOnACodeLine(Source, AcsPath));
    }

    [Fact]
    public void ReadingAnIdentityProvidersEndpoint_IsNotFlaggedByTheScan()
    {
        // The adjacent must-not-catch twin, one edit from the fixture above: it handles a SAML endpoint URL
        // and composes none. Every URL here is a value read at runtime out of somebody else's document.
        //
        // The bound this states plainly: the predicate matches a LITERAL in source, so it cannot mistake a
        // runtime value for a composition, but it would flag source that quoted an ACS-shaped URL inside a
        // string. No production file does, and the set equality above is what would catch one that started.
        const string Source = @"
internal static class Importer
{
    private const string PostBinding = ""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"";

    internal static string? SsoEndpoint(XmlElement descriptor) =>
        descriptor.GetElementsByTagName(""SingleSignOnService"")
            .OfType<XmlElement>()
            .FirstOrDefault(e => e.GetAttribute(""Binding"") == PostBinding)
            ?.GetAttribute(""Location"");
}";

        Assert.False(HoldsOnACodeLine(Source, AcsPath));
    }

    [Theory]
    [InlineData(@"baseUrl + ""/sso/SAML/post/"" + provider;", true)]
    [InlineData(@"// baseUrl + ""/sso/SAML/post/"" + provider;", false)]
    [InlineData(@"/// The ACS is <c>/sso/SAML/post/{provider}</c>.", false)]
    [InlineData(@"* links to /sso/SAML/start/{name}", false)]
    public void TheCodeReaderKeepsCompositionsAndDropsProse(string line, bool expected)
    {
        // Prose may name the path at no cost, and it does: a login-button summary documents the SAML start
        // route in an XML-doc line. A whole-file text search would call that a second composition site and
        // the rule would have to be widened or waived to survive it.
        Assert.Equal(expected, HoldsOnACodeLine(line, AcsPath));
    }

    [Fact]
    public void TheBuilderAndTheBindingCheckArePinnedByReflection()
    {
        // The sentinel. Every assertion above is a string search over source, so a rename that emptied the
        // scans would leave them green on a tree where nothing composes an ACS URL at all. These four
        // members are what the rule is about; if one is gone the rule is stale rather than satisfied.
        Assert.NotNull(typeof(SamlAcsUrlBuilder).GetMethod("AcsUrl", BindingFlags.NonPublic | BindingFlags.Static));
        Assert.NotNull(typeof(SamlAcsUrlBuilder).GetMethod("ExpectedAcsUrls", BindingFlags.NonPublic | BindingFlags.Static));
        Assert.NotNull(typeof(SamlRecipientValidator).GetMethod("IsBound", BindingFlags.NonPublic | BindingFlags.Static));
        Assert.NotEmpty(FilesWhoseCodeHolds(AcsPath));
    }

    // Every repo-relative path under SSO-Auth/ whose CODE holds the token, forward slashes so the constants
    // above read the same on either platform.
    private static IReadOnlyList<string> FilesWhoseCodeHolds(string token)
    {
        var root = RepoRoot();

        return Directory.EnumerateFiles(Path.Combine(root, "SSO-Auth"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path))
            .Where(path => HoldsOnACodeLine(File.ReadAllText(path), token))
            .Select(path => Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/'))
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToList();
    }

    // Whether a source text holds the token on a line that is not a comment. Comment lines are dropped
    // because prose can name the ACS path without any site composing one, and one XML-doc line already
    // does.
    private static bool HoldsOnACodeLine(string source, string token) =>
        source.Split('\n')
            .Select(line => line.Trim())
            .Where(text => !text.StartsWith("//", StringComparison.Ordinal)
                && !text.StartsWith("/*", StringComparison.Ordinal)
                && !text.StartsWith("*", StringComparison.Ordinal))
            .Any(text => text.Contains(token, StringComparison.Ordinal));

    // obj/bin hold generated and compiled output; this scan reads hand-written source only.
    private static bool IsBuildOutput(string path) =>
        path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
        || path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal);

    // The repository root, derived from this test file's compile-time path
    // (<root>/SSO-Auth.Tests/Saml/<file>).
    private static string RepoRoot([CallerFilePath] string thisFilePath = "") =>
        Directory.GetParent(Directory.GetParent(Path.GetDirectoryName(thisFilePath)!)!.FullName)!.FullName;
}
