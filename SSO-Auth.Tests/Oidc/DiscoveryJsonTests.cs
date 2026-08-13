// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="DiscoveryJson"/> - the single parse a discovery response gets, out of which both
/// challenge-time facts are read (#1170), taken by the same parser family the repeated-member screen walks
/// the body with (#1054). They pin: the parse answers null for every body that is not a JSON object rather
/// than throwing; one parsed root serves both facts, and the readers genuinely read off it; the fail-closed /
/// fail-tolerant asymmetry between the two readers survives the move, on the raw entry point and on the root
/// one alike; the plugin holds no second parse site; and the reader admits no document the screen refuses.
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
        using var document = DiscoveryJson.TryParse(discoveryJson);

        Assert.NotNull(document);
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
        using var document = DiscoveryJson.TryParse(discoveryJson);

        Assert.Null(document);
    }

    [Fact]
    public void OneParsedRoot_ServesBothFacts()
    {
        // What "parsed once" is observable as: both readers answer off the instance they were handed. The
        // document is disposed while the root they were given is still in hand, and a reader holding its own
        // parse of the same bytes could not notice - the disposal is the discriminator, and it is why this
        // is not written as two equal answers, which a second parse would also produce.
        var document = DiscoveryJson.TryParse(BothFacts);
        Assert.NotNull(document);
        var root = document.RootElement;

        Assert.True(PkceDiscovery.SupportsS256(root));
        Assert.True(OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer(root));

        document.Dispose();

        Assert.Throws<ObjectDisposedException>(() => PkceDiscovery.SupportsS256(root));
        Assert.Throws<ObjectDisposedException>(() => OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer(root));
    }

    [Fact]
    public void ANullRoot_KeepsTheAsymmetryBetweenTheTwoFacts()
    {
        // The one thing the shared parse must not quietly level out. PKCE support fails CLOSED on a
        // document that could not be read (#141); the RFC 9207 response-iss flag stays TOLERANT, because a
        // flag nobody could read must never lock out a provider that omits iss (#210). Both are false here,
        // and they are false for opposite reasons - the rows below are what keeps the pair from drifting
        // into one answer.
        Assert.False(PkceDiscovery.SupportsS256((JsonElement?)null));
        Assert.False(OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer((JsonElement?)null));

        // Tolerant means: an advertised flag on an otherwise empty document still reads true, and a
        // document that omits it reads false without the read having failed.
        using var advertised = DiscoveryJson.TryParse("{\"authorization_response_iss_parameter_supported\":true}");
        Assert.True(OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer(advertised?.RootElement));
        Assert.False(PkceDiscovery.SupportsS256(advertised?.RootElement));
    }

    [Fact]
    public void ARootThatIsNotAnObject_AnswersRatherThanThrowing()
    {
        // TryParse never hands one back, so this is about the overloads' own contract: an element that is
        // neither null nor an object - default(JsonElement), whose ValueKind is Undefined - reaches
        // TryGetProperty, which THROWS on it. A reader that let that escape would turn a caller's uninitialised
        // field into a 500 on the anonymous challenge endpoint rather than into a refusal.
        Assert.False(PkceDiscovery.SupportsS256(default(JsonElement)));
        Assert.False(OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer(default(JsonElement)));
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

    /// <param name="discoveryJson">A body some JSON reader accepts and some other reader does not.</param>
    [Theory]
    [InlineData("{\"code_challenge_methods_supported\":[\"S256\"] /* fine by some readers */}")]
    [InlineData("{\"code_challenge_methods_supported\":[\"S256\"],}")]
    [InlineData("{\"code_challenge_methods_supported\":[\"S256\"],\"x\":NaN}")]
    [InlineData("{\"code_challenge_methods_supported\":[\"S256\"],\"x\":'single'}")]
    public void NoDocumentTheScreenRefuses_IsOneTheFactReaderStillReads(string discoveryJson)
    {
        // The claim #1054 is about, stated as one property over one body rather than as an argument about
        // two libraries. Each row is a document a LENIENT reader accepts - comments, a trailing comma, NaN,
        // single-quoted strings - and every one of them advertises S256, so a reader that admitted it would
        // report a fact off bytes the screen threw away.
        //
        // The screen's verdict is measured here, not assumed: if a row ever stops being refused, this stops
        // proving anything, and the assertion below would be about a document nobody screens.
        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect(discoveryJson, out _));

        using var document = DiscoveryJson.TryParse(discoveryJson);
        Assert.Null(document);
        Assert.False(OidcDiscoveryReader.FactsFrom(discoveryJson).PkceS256);
    }

    [Fact]
    public void AnUndecodableMethodBesideS256_NeitherThrowsNorHidesTheS256()
    {
        // The screen decodes member NAMES, not values, so it reports this document Clean and the element
        // arrives at the reader. Reading its text throws - an unpaired surrogate escape is text the decoder
        // cannot complete - and the scan has to survive that without either escaping or stopping.
        //
        // Both halves are the point. A throw reaches OidcDiscoveryReader's catch-all and turns a document the
        // screen admitted into a failed read, and answering false would refuse the login wherever RequirePkce
        // is on. Either way a provider that works today goes offline over one bad array element.
        const string Undecodable = "{\"code_challenge_methods_supported\":[\"\\uD800\",\"S256\"]}";

        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect(Undecodable, out _));
        Assert.True(PkceDiscovery.SupportsS256(Undecodable));
        Assert.True(OidcDiscoveryReader.FactsFrom(Undecodable).PkceS256);

        // And the undecodable element is not itself read as an advertisement, which is what would make the
        // row above pass for the wrong reason.
        Assert.False(PkceDiscovery.SupportsS256("{\"code_challenge_methods_supported\":[\"\\uD800\"]}"));
    }

    [Fact]
    public void TheDocumentTheScreenAdmits_IsOneTheFactReaderReads()
    {
        // The positive control the rows above need. Without it every one of them would pass against a reader
        // that returned null for everything, which is the shape a fail-closed guard fails into silently.
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect(BothFacts, out _));

        using var document = DiscoveryJson.TryParse(BothFacts);
        Assert.NotNull(document);
        Assert.True(OidcDiscoveryReader.FactsFrom(BothFacts).PkceS256);
    }

    [Fact]
    public void TheShippedPluginHoldsOneParseSite()
    {
        // The rule the refactor is: one document, one parse, one parser family. Nothing stops a later reader
        // from adding its own JsonDocument.Parse next to the shared one, and nothing about that would fail a
        // behaviour test - both parses would agree. So the count is asserted directly.
        //
        // The scan is over raw file text, so a mention inside a comment counts as a site. That is
        // deliberate: it needs no agreement with anyone else's idea of what a comment is, and prose can say
        // "the shared parse" at no cost.
        var pluginRoot = Path.Combine(RepoTree.Root, "SSO-Auth");
        var owner = Path.Combine("Api", "Oidc", "DiscoveryJson.cs");

        Assert.Equal(new List<string> { owner }, SitesCalling(pluginRoot, "JsonDocument.Parse("));

        // And the family it moved OFF. Newtonsoft still ships in this plugin - the id_token role claim is
        // read with it - so the absence that matters is on this path rather than in the assembly, and an
        // empty list is what says the discovery facts no longer cross a second parser.
        Assert.Empty(SitesCalling(pluginRoot, "JObject.Parse("));
    }

    private static List<string> SitesCalling(string pluginRoot, string call) =>
        Directory.EnumerateFiles(pluginRoot, "*.cs", SearchOption.AllDirectories)
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                && !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(path => File.ReadAllText(path).Contains(call, StringComparison.Ordinal))
            .Select(path => Path.GetRelativePath(pluginRoot, path))
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToList();
}
