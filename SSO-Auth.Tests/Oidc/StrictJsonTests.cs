// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="StrictJson"/> — the per-object-scope walk that decides whether a provider document
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

    // A UTF-8 BOM, which a provider serving a BOM-prefixed file emits. Utf8JsonReader treats it as
    // content, so without stripping it every such document reads as malformed — and Unreadable is a
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

        // Below the root: a nested object, and an object inside an array — a JWKS entry whose own `kty`
        // repeats, which is where key selection would diverge.
        ("{\"outer\":{\"b\":1,\"b\":2}}", "b"),
        ("{\"keys\":[{\"kty\":\"RSA\",\"kty\":\"oct\"}]}", "kty"),

        // The two occurrences STRADDLE a nested scope, so the root's name set must survive the push and pop
        // in between. A walk that reset or replaced the set on entering an object passes every row above and
        // fails only here — and a repeated `issuer` spelled this way is the realistic spelling, since an
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

        // Nested well inside the cap. This row alone pins nothing about the cap — any value from 11 upward
        // satisfies it — and an earlier comment here claimed it pinned the tightening direction, which it did
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
        // passed all of them — and would refuse the login of any provider advertising mTLS aliases.
        "{\"issuer\":\"https://one.example\",\"token_endpoint\":\"https://one.example/token\","
            + "\"mtls_endpoint_aliases\":{\"token_endpoint\":\"https://mtls.one.example/token\","
            + "\"userinfo_endpoint\":\"https://mtls.one.example/userinfo\"}}",
    };

    private static readonly string[] Unreadable =
    {
        "not-json",
        "{\"a\":1,",
        LoneSurrogateName,
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
        // JSON member names are case-sensitive and every consumer of these documents compares them ordinally,
        // so folding case here would refuse a document none of them reads as ambiguous.
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect("{\"issuer\":1,\"Issuer\":2}", out _));
    }

    [Fact]
    public void EscapeSpelledName_CountsAsItsPlainSpelling()
    {
        // \u0069ssuer IS issuer to every reader downstream, so comparing raw spellings would let an attacker
        // spell one of the two occurrences differently and walk straight past the screen.
        var verdict = StrictJson.Inspect("{\"\\u0069ssuer\":1,\"issuer\":2}", out var repeated);

        Assert.Equal(StrictJson.Verdict.Repeated, verdict);
        Assert.Equal("issuer", repeated);
    }

    [Theory]
    [MemberData(nameof(UnreadableFixtures))]
    public void HostileInput_IsUnreadable_NeverThrows(string json)
    {
        // One fixture per raised type. `not-json` and the truncation raise JsonException; the thirteen bytes
        // of LoneSurrogateName raise InvalidOperationException from GetString — NOT JsonException, so a walk
        // catching only the latter hands the crash to a caller that catches neither. Unreadable is what the
        // caller refuses on, so the fail-closed direction holds.
        var verdict = StrictJson.Inspect(json, out var repeated);

        Assert.Equal(StrictJson.Verdict.Unreadable, verdict);
        Assert.Null(repeated);
    }

    private static string NestedTo(int depth) =>
        string.Concat(Enumerable.Repeat("{\"a\":", depth)) + "1" + new string(char.Parse("}"), depth);

    [Fact]
    public void NestingPastTheDepthCap_IsUnreadable()
    {
        // The behaviour at the boundary, and only that. An earlier row claimed to pin the cap CONSTANT from
        // both directions; it could not, because the value equals the reader's own default and deleting the
        // constant leaves every verdict identical. The claim is withdrawn rather than restated.
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect(NestedTo(64), out _));
        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect(NestedTo(65), out _));

        // 65 opens against the reader's own default of 64: a document this walk cannot reach the bottom of is
        // one its consumers could not read either, so it is refused rather than passed on half-inspected.
        var tooDeep = string.Concat(Enumerable.Repeat("{\"a\":", 65)) + "1" + new string('}', 65);

        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect(tooDeep, out _));
    }

    [Fact]
    public void ADocumentCarryingNoObject_IsUnreadable()
    {
        // Widened from "no input" to its actual rule. A bare scalar and an array of scalars are well-formed
        // and carry no scope in which a member could repeat, so the walk established nothing about them —
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
        // obvious way consumes as approval — and every reader these documents reach rejects an empty body
        // outright, so Clean would make this walk disagree with its own consumers about one document. Nothing
        // was established, which is exactly what Unreadable means.
        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect(null, out _));
        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect(string.Empty, out _));
        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect("   ", out _));
    }

}
