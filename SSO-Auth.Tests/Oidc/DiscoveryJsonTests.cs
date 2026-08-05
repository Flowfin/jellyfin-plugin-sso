// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="DiscoveryJson"/> - the single parse a discovery response gets, out of which both
/// challenge-time facts are read (#1170). Before this the two readers each walked the same body for one
/// boolean apiece. They pin: the parse answers null for every body that is not a JSON object rather than
/// throwing; one parsed root serves both facts; the fail-closed / fail-tolerant asymmetry between the two
/// readers survives the move, on the raw entry point and on the root one alike; and the plugin holds no
/// second parse site.
/// </summary>
public class DiscoveryJsonTests
{
    // Advertises both facts, so a reader that stopped reading its member would show up as a flipped answer
    // rather than as an answer that was already false.
    private const string BothFacts =
        "{\"code_challenge_methods_supported\":[\"S256\"],\"authorization_response_iss_parameter_supported\":true}";

    [Theory]
    [InlineData("{}")]
    [InlineData(BothFacts)]
    [InlineData("{\"issuer\":\"https://idp.example.com\"}")]
    public void AJsonObject_Parses(string discoveryJson)
    {
        Assert.NotNull(DiscoveryJson.TryParse(discoveryJson));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-json")]
    [InlineData("[1,2]")] // a JSON array is well-formed JSON and still not a discovery document
    [InlineData("42")]
    [InlineData("{\"a\":1} trailing")]
    [InlineData("{\"a\":1")]
    public void AnythingThatIsNotAJsonObject_IsNullRatherThanAThrow(string? discoveryJson)
    {
        // The readers below turn a null root into their own answer, and the two answers differ. Throwing
        // here instead would take that decision away from them and hand the whole read to
        // OidcDiscoveryReader's catch-all, which fails the login closed - including for the tolerant fact.
        Assert.Null(DiscoveryJson.TryParse(discoveryJson));
    }

    [Fact]
    public void OneParsedRoot_ServesBothFacts()
    {
        // What "parsed once" is observable as: both readers answer off the instance they were handed, so a
        // change made to that one instance moves both answers. A reader holding its own parse of the same
        // bytes could not see either removal.
        var root = DiscoveryJson.TryParse(BothFacts);

        Assert.NotNull(root);
        Assert.True(PkceDiscovery.SupportsS256(root));
        Assert.True(OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer(root));

        root.Remove("code_challenge_methods_supported");
        root.Remove("authorization_response_iss_parameter_supported");

        Assert.False(PkceDiscovery.SupportsS256(root));
        Assert.False(OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer(root));
    }

    [Fact]
    public void ANullRoot_KeepsTheAsymmetryBetweenTheTwoFacts()
    {
        // The one thing the shared parse must not quietly level out. PKCE support fails CLOSED on a
        // document that could not be read (#141); the RFC 9207 response-iss flag stays TOLERANT, because a
        // flag nobody could read must never lock out a provider that omits iss (#210). Both are false here,
        // and they are false for opposite reasons - the rows below are what keeps the pair from drifting
        // into one answer.
        Assert.False(PkceDiscovery.SupportsS256((JObject?)null));
        Assert.False(OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer((JObject?)null));

        // Tolerant means: an advertised flag on an otherwise empty document still reads true, and a
        // document that omits it reads false without the read having failed.
        var advertised = DiscoveryJson.TryParse("{\"authorization_response_iss_parameter_supported\":true}");
        Assert.True(OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer(advertised));
        Assert.False(PkceDiscovery.SupportsS256(advertised));
    }

    [Theory]
    [InlineData(BothFacts, true, true)]
    [InlineData("{\"code_challenge_methods_supported\":[\"S256\"]}", true, false)]
    [InlineData("{\"authorization_response_iss_parameter_supported\":true}", false, true)]
    [InlineData("{\"code_challenge_methods_supported\":[\"plain\"],\"authorization_response_iss_parameter_supported\":false}", false, false)]
    [InlineData("{\"code_challenge_methods_supported\":\"S256\",\"authorization_response_iss_parameter_supported\":\"true\"}", false, false)]
    [InlineData("{}", false, false)]
    [InlineData("not-json", false, false)]
    [InlineData("", false, false)]
    [InlineData(null, false, false)]
    public void TheSeamAgreesWithBothRawEntryPoints(string? discoveryJson, bool expectedPkce, bool expectedResponseIssuer)
    {
        // The behaviour bound on the refactor: what the challenge reads out of one parse is what the two
        // raw-JSON readers answered separately before it. The expectations are written out rather than
        // computed from the readers, so a change that moved BOTH sides at once would still be caught.
        var facts = OidcDiscoveryReader.FactsFrom(discoveryJson);

        Assert.Equal(expectedPkce, facts.PkceS256);
        Assert.Equal(expectedResponseIssuer, facts.ResponseIssuerAdvertised);
        Assert.Equal(PkceDiscovery.SupportsS256(discoveryJson), facts.PkceS256);
        Assert.Equal(OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer(discoveryJson), facts.ResponseIssuerAdvertised);
    }

    [Fact]
    public void TheShippedPluginHoldsOneParseSite()
    {
        // The rule the refactor is: one document, one parse. Nothing stops a later reader from adding its
        // own JObject.Parse next to the shared one, and nothing about that would fail a behaviour test -
        // both parses would agree. So the count is asserted directly.
        //
        // The scan is over raw file text, so a mention inside a comment counts as a site. That is
        // deliberate: it needs no agreement with anyone else's idea of what a comment is, and prose can say
        // "the shared parse" at no cost.
        var pluginRoot = Path.Combine(RepoRoot(), "SSO-Auth");
        var owner = Path.Combine("Api", "Oidc", "DiscoveryJson.cs");

        var sites = Directory.EnumerateFiles(pluginRoot, "*.cs", SearchOption.AllDirectories)
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                && !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(path => File.ReadAllText(path).Contains("JObject.Parse(", StringComparison.Ordinal))
            .Select(path => Path.GetRelativePath(pluginRoot, path))
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToList();

        Assert.Equal(new List<string> { owner }, sites);
    }

    // The repository root, derived from this test file's compile-time path
    // (<root>/SSO-Auth.Tests/Oidc/<file>).
    private static string RepoRoot([CallerFilePath] string thisFilePath = "") =>
        Directory.GetParent(Directory.GetParent(Path.GetDirectoryName(thisFilePath)!)!.FullName)!.FullName;
}
