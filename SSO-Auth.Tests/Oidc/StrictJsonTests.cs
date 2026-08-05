// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="StrictJson"/> - the per-object-scope walk that decides whether a provider document
/// names a member twice (#1005). Every reader the plugin depends on keeps the LAST occurrence of a repeated
/// member silently, so a document that repeats one means two things at once; a repeated <c>issuer</c>
/// re-points the anchor a login binds to and a repeated <c>jwks_uri</c> re-points the validation keys. They
/// pin: a repeat is found at every scope, a document without one is admitted (the positive controls, without
/// which a walk that refused everything would satisfy the rejection rows), sibling scopes may reuse a name,
/// names are compared ordinally and after unescaping, and hostile input is reported rather than thrown.
/// </summary>
public class StrictJsonTests
{
    // A realistic two-key JWKS: every entry repeats `kty`, `use`, `alg`, `n` and `e` in a SIBLING scope, which
    // is the shape a document-wide name set would refuse while reporting an attack that is not there.
    private const string RealisticJwks =
        "{\"keys\":["
        + "{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":\"a1\",\"n\":\"xGOr\",\"e\":\"AQAB\"},"
        + "{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":\"b2\",\"n\":\"yHPs\",\"e\":\"AQAB\"}]}";

    private const string LoneSurrogateName = "{\"a\\ud800\":1}";

    // The same lone surrogate as a RAW char rather than an escape, which is a different input reaching a
    // different arm. The escape above is thirteen ASCII bytes the reader decodes. This is a char with no
    // UTF-8 encoding at all, so it is refused while the document is being encoded and the reader never sees
    // it. Without that refusal the default replacement fallback would rewrite it to U+FFFD in silence, and
    // the walk would report Clean about bytes it had altered itself.
    private const string RawLoneSurrogateName = "{\"a\uD800\":1}";

    // Two DIFFERENT member names, each ending in a different unpaired surrogate. This is what makes the
    // throwing fallback a rule rather than a sentence about one. Under the default replacement fallback both
    // names encode to the same bytes, because every unpaired surrogate maps to the same U+FFFD, so the walk
    // would report Repeated for a document whose two members are not the same name. That is a false
    // accusation against a provider, which is the one direction a screen must never fail in.
    private const string TwoRawLoneSurrogateNames = "{\"a\uD800\":1,\"a\uDC00\":1}";

    // The same pair spelled as ESCAPES, which is the shape #1197 decides. It reaches a different arm: the
    // escape is thirteen ASCII bytes the encoder is perfectly happy with, and the refusal comes from the
    // decoder inside GetString instead. No name is produced for either member, so the walk cannot fold the
    // two into one however it compares names - which is why the answer here is forced by the decoder rather
    // than chosen by this walk.
    private const string TwoEscapedLoneSurrogateNames = "{\"a\\ud800\":1,\"a\\udc00\":1}";

    // Two member names differing only in case, carrying two DIFFERENT values. This is the document the
    // recorded decision on #1191 is about, and it is a fixture rather than a literal inside one test
    // because the same bytes are read three ways below.
    private const string CaseVariantIssuers = "{\"issuer\":\"https://good.example\",\"ISSUER\":\"https://evil.example\"}";

    // A UTF-8 BOM, which a provider serving a BOM-prefixed file emits. Utf8JsonReader treats it as
    // content, so without stripping it every such document reads as malformed - and Unreadable is a
    // refusal at the seam, so that would lock the provider out.
    private const string Bom = "\uFEFF";

    // The corpora live as plain arrays so the both-TFM row below can walk exactly what the theories run,
    // rather than a second copy that could drift from them.
    private static readonly (string Json, string Member)[] Repeated =
    {
        // At the root, and the two live attacks the screen exists for.
        ("{\"a\":1,\"a\":2}", "a"),
        ("{\"issuer\":\"https://one.example\",\"issuer\":\"https://two.example\"}", "issuer"),
        ("{\"jwks_uri\":\"https://one.example/jwks\",\"jwks_uri\":\"https://evil.example/jwks\"}", "jwks_uri"),

        // Below the root: a nested object, and an object inside an array - a JWKS entry whose own `kty`
        // repeats, which is where key selection would diverge.
        ("{\"outer\":{\"b\":1,\"b\":2}}", "b"),
        ("{\"keys\":[{\"kty\":\"RSA\",\"kty\":\"oct\"}]}", "kty"),

        // The two occurrences STRADDLE a nested scope, so the root's name set must survive the push and pop
        // in between. A walk that reset or replaced the set on entering an object passes every row above and
        // fails only here - and a repeated `issuer` spelled this way is the realistic spelling, since an
        // attacker appending to a document puts other members between the two.
        ("{\"issuer\":\"https://one.example\",\"o\":{\"issuer\":\"nested\"},\"issuer\":\"https://two.example\"}", "issuer"),
        ("{\"a\":1,\"k\":[{\"x\":1},{\"y\":2}],\"a\":2}", "a"),

        // A BOM-prefixed document still has its repeat found: stripping the BOM must not cost detection.
        (Bom + "{\"issuer\":1,\"issuer\":2}", "issuer"),

        // A non-object root. The walk handles it and no fixture covered it, which is how a corpus gap
        // and a behaviour gap become indistinguishable in a review.
        ("[{\"a\":1,\"a\":2}]", "a"),

        // The empty name is a legal member and a provider can repeat it; it must not fold with "no name".
        ("{\"\":1,\"\":2}", ""),
    };

    private static readonly string[] Clean =
    {
        "{\"a\":1,\"b\":2}",
        "{\"issuer\":\"https://one.example\"}",
        "{\"jwks_uri\":\"https://one.example/jwks\"}",
        "{\"outer\":{\"b\":1,\"c\":2}}",
        "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"a1\"}]}",
        RealisticJwks,

        // Nested well inside the cap. This row alone pins nothing about the cap - any value from 11 upward
        // satisfies it - and an earlier comment here claimed it pinned the tightening direction, which it did
        // not. The cap is pinned by its two neighbours in TheDepthCapIsPinnedAtItsBoundary; this fixture is
        // here because a realistically-nested clean document belongs in the corpus regardless.
        "{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":{\"g\":{\"h\":{\"i\":{\"j\":1}}}}}}}}}}",

        // A BOM-prefixed document that is otherwise perfect. Without the strip this is Unreadable, which
        // at the seam refuses a provider that did nothing wrong.
        Bom + "{\"issuer\":\"https://one.example\"}",

        // A DESCENDANT scope reusing an ancestor's member name, which is the scope relation real discovery
        // documents actually contain: RFC 8705 puts a second `token_endpoint` and `userinfo_endpoint` inside
        // `mtls_endpoint_aliases`, and Google, Microsoft and others serve exactly this. Every other clean
        // fixture reuses names between SIBLINGS, so a walk whose child scope inherited its parent's names
        // passed all of them - and would refuse the login of any provider advertising mTLS aliases.
        "{\"issuer\":\"https://one.example\",\"token_endpoint\":\"https://one.example/token\","
            + "\"mtls_endpoint_aliases\":{\"token_endpoint\":\"https://mtls.one.example/token\","
            + "\"userinfo_endpoint\":\"https://mtls.one.example/userinfo\"}}",

        // The recorded decision of #1191: names differing only in case are two members, so this document is
        // admitted. It sits in the corpus rather than only in its own test so that reversing the decision -
        // one word, StringComparer.Ordinal to StringComparer.OrdinalIgnoreCase - fails the corpus theory
        // as well as the row that argues the decision.
        CaseVariantIssuers,
    };

    private static readonly string[] Unreadable =
    {
        "not-json",
        "{\"a\":1,",
        LoneSurrogateName,
        RawLoneSurrogateName,
        TwoRawLoneSurrogateNames,
        TwoEscapedLoneSurrogateNames,
    };

    public static TheoryData<string, string> RepeatedFixtures()
    {
        var data = new TheoryData<string, string>();
        foreach (var (json, member) in Repeated)
        {
            data.Add(json, member);
        }

        return data;
    }

    public static TheoryData<string> CleanFixtures()
    {
        var data = new TheoryData<string>();
        foreach (var json in Clean)
        {
            data.Add(json);
        }

        return data;
    }

    public static TheoryData<string> UnreadableFixtures()
    {
        var data = new TheoryData<string>();
        foreach (var json in Unreadable)
        {
            data.Add(json);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(RepeatedFixtures))]
    public void DuplicateMember_AtAnyScope_IsRepeated(string json, string expectedMember)
    {
        var verdict = StrictJson.Inspect(json, out var repeated);

        Assert.Equal(StrictJson.Verdict.Repeated, verdict);
        Assert.Equal(expectedMember, repeated);
    }

    [Theory]
    [MemberData(nameof(CleanFixtures))]
    public void TheSameDocumentsWithoutTheDuplicate_AreClean(string json)
    {
        // The positive control for every rejection above: without it, a walk that reported Repeated for any
        // input would satisfy the whole rejection set while refusing every real provider.
        var verdict = StrictJson.Inspect(json, out var repeated);

        Assert.Equal(StrictJson.Verdict.Clean, verdict);
        Assert.Null(repeated);
    }

    [Fact]
    public void TheDefaultVerdictIsTheRefusal()
    {
        // default(Verdict) is what an uninitialised field or a skipped assignment yields. On a fail-closed
        // component that value must be the refusal, or the failure mode of forgetting to assign is approval.
        Assert.Equal(StrictJson.Verdict.Unreadable, default(StrictJson.Verdict));
    }

    [Fact]
    public void RepeatedBomPrefixes_AreNotStrippedAway()
    {
        // Exactly one leading BOM is stripped. A document prefixed with several is one no consumer can
        // parse, so admitting it would be this walk disagreeing with its readers in the permissive direction.
        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect(Bom + Bom + "{\"a\":1}", out _));

        // And a BOM that is not first is not a BOM prefix at all.
        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect(" " + Bom + "{\"a\":1}", out _));
    }

    [Fact]
    public void SiblingScopesReusingAName_AreClean()
    {
        // The scope rule: one name set per OPEN object. A walk pooling names document-wide would refuse this
        // and every real JWKS with it.
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect("{\"o\":{\"a\":1},\"p\":{\"a\":2}}", out _));
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect(RealisticJwks, out _));
    }

    [Fact]
    public void NamesDifferingOnlyInCase_AreClean()
    {
        // The decision of #1191, and it is a decision rather than a fact about JSON consumers in general.
        // JSON member names are case-sensitive, and every reader on the plugin's own path INDEXES a name it
        // spells itself - PkceDiscovery and OidcResponseIssuer both JObject.Parse and index, JsonDocument
        // indexes, and the identity library's typed mapping is case-sensitive - so a case-variant pair is
        // unambiguous to all of them. Refusing it would take offline a provider whose document none of its
        // consumers misreads, and the walk compares EVERY member at every scope, so the pair that took the
        // provider down could be two unrelated vendor extensions rather than anything a login rests on.
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect("{\"issuer\":1,\"Issuer\":2}", out _));
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect(CaseVariantIssuers, out _));
    }

    [Fact]
    public void WhatAdmittingACaseVariantPairLeavesOpen_IsMeasuredRatherThanAssumed()
    {
        // The cost of that decision, measured on the exact bytes rather than asserted about consumers in
        // general - the earlier comment here claimed every consumer compares ordinally, which is not
        // established and is false for the case-folding shape below.
        //
        // One document, three readers, three answers. An indexing reader takes the lowercase value; a
        // deserializer configured case-insensitively - which is what JsonSerializerDefaults.Web gives you,
        // and what any PropertyNameCaseInsensitive = true option carries - resolves both spellings onto one
        // property and keeps the LAST, so it takes the other one; a case-sensitive deserializer with no
        // naming policy matches neither spelling and reads nothing at all.
        //
        // No reader on the plugin's current login path is the second kind, which is why the pair is
        // admitted. This row is what makes that a bounded claim instead of a hope: if a future reader on
        // this path folds case, the divergence it would inherit is already written down here.
        using var document = JsonDocument.Parse(CaseVariantIssuers);
        Assert.Equal("https://good.example", document.RootElement.GetProperty("issuer").GetString());

        var caseFolding = JsonSerializer.Deserialize<IssuerCarrier>(CaseVariantIssuers, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.Equal("https://evil.example", caseFolding!.Issuer);

        var caseSensitive = JsonSerializer.Deserialize<IssuerCarrier>(CaseVariantIssuers, new JsonSerializerOptions());
        Assert.Null(caseSensitive!.Issuer);

        // And the fourth reading, which is the one the decision rests on: a reader that spells both names
        // gets both values, because they are two members. Nothing is lost by admitting the document.
        var bothSpellings = JsonSerializer.Deserialize<CaseVariantCarrier>(CaseVariantIssuers, new JsonSerializerOptions());
        Assert.Equal("https://good.example", bothSpellings!.Lower);
        Assert.Equal("https://evil.example", bothSpellings.Upper);
    }

#if NET10_0_OR_GREATER
    [Fact]
    public void TheStrictPresetTakesTheSameDecisionOnCase()
    {
        // #1043 replaces this walk with JsonSerializerOptions.Strict once net9.0 is dropped, so the decision
        // above may not contradict what that preset does with case without saying so. It does not, and this
        // is the measurement rather than a reading of the documentation: Strict refuses a member named twice
        // and does not treat a case-variant pair as one, which is this walk's posture in both directions.
        //
        // Compiled only on net10.0 because the preset does not exist in the .NET 9 System.Text.Json the
        // Jellyfin 10.11 line binds - referencing it there fails the build with CS0117, which is the same
        // reason StrictJson is a hand-rolled walk at all.
        // One carrier for both rows, so the only difference between them is the repeat itself and not which
        // members happened to bind.
        Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<CaseVariantCarrier>("{\"issuer\":\"a\",\"issuer\":\"b\"}", JsonSerializerOptions.Strict));

        var admitted = JsonSerializer.Deserialize<CaseVariantCarrier>(CaseVariantIssuers, JsonSerializerOptions.Strict);
        Assert.Equal("https://good.example", admitted!.Lower);
        Assert.Equal("https://evil.example", admitted.Upper);
    }
#endif

    [Fact]
    public void EscapeSpelledName_CountsAsItsPlainSpelling()
    {
        // \u0069ssuer IS issuer to every reader downstream, so comparing raw spellings would let an attacker
        // spell one of the two occurrences differently and walk straight past the screen.
        var verdict = StrictJson.Inspect("{\"\\u0069ssuer\":1,\"issuer\":2}", out var repeated);

        Assert.Equal(StrictJson.Verdict.Repeated, verdict);
        Assert.Equal("issuer", repeated);
    }

    [Fact]
    public void NamesDifferingOnlyInAnInvalidEscape_AreNeverFoldedIntoOne()
    {
        // The decision of #1197, and the direction matters: this is the FALSE-REFUSAL side. A verdict of
        // Repeated on a document whose two members are not the same name is an accusation against a
        // provider, and Unreadable is a refusal too - both cost the provider its login - so the choice is
        // between two refusals and is made on which one is honest about the bytes.
        //
        // An invalid escape establishes no name at all. Spelled raw, the char has no UTF-8 encoding and the
        // encoder refuses the document before the walk starts; spelled as an escape, the decoder inside
        // GetString refuses the name it cannot complete. Either way the walk never holds two names to
        // compare, so it reports that nothing was established rather than that a member was named twice.
        //
        // The alternative - decoding leniently, which is what the platform default does - is what makes the
        // fold: every unpaired surrogate becomes U+FFFD, so two different names collapse to one key and the
        // walk reports Repeated for a document that has no repeat. That is the false accusation, and it is
        // the reason the strict encoder is here rather than a tidier default.
        //
        // The cost of the decision, stated rather than implied: a provider whose document names a member
        // with an unpaired surrogate is refused, and a lenient reader downstream would have read that
        // document. It is refused because no verdict about its members would be a verdict about the bytes
        // its consumers see.
        foreach (var json in new[] { TwoEscapedLoneSurrogateNames, TwoRawLoneSurrogateNames })
        {
            var verdict = StrictJson.Inspect(json, out var repeated);

            Assert.Equal(StrictJson.Verdict.Unreadable, verdict);
            Assert.NotEqual(StrictJson.Verdict.Repeated, verdict);
            Assert.Null(repeated);
        }

        // The positive control the pair needs: a VALID escape does fold, and must, or an attacker spells one
        // of two occurrences differently and walks past the screen. The two rules are neighbours and it is
        // the difference between them that this row protects.
        Assert.Equal(StrictJson.Verdict.Repeated, StrictJson.Inspect("{\"\\u0061\":1,\"a\":2}", out _));
    }

    [Theory]
    [MemberData(nameof(UnreadableFixtures))]
    public void HostileInput_IsUnreadable_NeverThrows(string json)
    {
        // One fixture per raised type, because each is raised by a different party and a walk that catches
        // one hands the others to a caller that catches none. `not-json` and the truncation raise
        // JsonException from the reader. The ESCAPED surrogate fixtures - LoneSurrogateName and the pair in
        // TwoEscapedLoneSurrogateNames - are thirteen ASCII bytes each and raise InvalidOperationException
        // from GetString, NOT JsonException. The two RAW surrogate fixtures raise EncoderFallbackException
        // from the encoder, before any of the walk has run. Unreadable is what the caller refuses on, so the
        // fail-closed direction holds for all three.
        var verdict = StrictJson.Inspect(json, out var repeated);

        Assert.Equal(StrictJson.Verdict.Unreadable, verdict);
        Assert.Null(repeated);
    }

    private static string NestedTo(int depth) =>
        string.Concat(Enumerable.Repeat("{\"a\":", depth)) + "1" + new string('}', depth);

    [Fact]
    public void NestingPastTheDepthCap_IsUnreadable()
    {
        // The behaviour at the boundary, and only that. An earlier row claimed to pin the cap CONSTANT from
        // both directions; it could not, because the value equals the reader's own default and deleting the
        // constant leaves every verdict identical. The claim is withdrawn rather than restated.
        //
        // 65 opens against the reader's own default of 64: a document this walk cannot reach the bottom of is
        // one its consumers could not read either, so it is refused rather than passed on half-inspected.
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect(NestedTo(64), out _));
        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect(NestedTo(65), out _));
    }

    [Fact]
    public void ADocumentCarryingNoObject_IsUnreadable()
    {
        // Widened from "no input" to its actual rule. A bare scalar and an array of scalars are well-formed
        // and carry no scope in which a member could repeat, so the walk established nothing about them -
        // the same reason an empty body is not Clean. Reporting Clean here would hand a caller an
        // affirmative answer about a document nothing read.
        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect("17", out _));
        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect("true", out _));
        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect("\"a string\"", out _));
        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect("[1,2,3]", out _));

        // An EMPTY object is the boundary of that rule and stays Clean: it has a scope, and that scope
        // repeats nothing.
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect("{}", out _));
    }

    [Fact]
    public void NoInputAtAll_IsUnreadable()
    {
        // Not Clean. Clean is an affirmative "no scope names a member twice", which a caller written the
        // obvious way consumes as approval - and every reader these documents reach rejects an empty body
        // outright, so Clean would make this walk disagree with its own consumers about one document. Nothing
        // was established, which is exactly what Unreadable means.
        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect(null, out _));
        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect(string.Empty, out _));
        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect("   ", out _));
    }

    // The shape a deserializer binds the discovery issuer onto. The property is spelled in the CLR casing a
    // real binding target would carry, which is what makes the naming policy and the case-insensitivity
    // setting decide the answer.
    private sealed class IssuerCarrier
    {
        public string? Issuer { get; set; }
    }

    // Both spellings bound explicitly, so a reader can tell a refusal caused by the repeat from one caused
    // by a member that simply did not map.
    private sealed class CaseVariantCarrier
    {
        [JsonPropertyName("issuer")]
        public string? Lower { get; set; }

        [JsonPropertyName("ISSUER")]
        public string? Upper { get; set; }
    }
}
