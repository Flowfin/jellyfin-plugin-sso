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
    };

    private static readonly string[] Clean =
    {
        "{\"a\":1,\"b\":2}",
        "{\"issuer\":\"https://one.example\"}",
        "{\"jwks_uri\":\"https://one.example/jwks\"}",
        "{\"outer\":{\"b\":1,\"c\":2}}",
        "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"a1\"}]}",
        RealisticJwks,

        // Nested deeper than a hand-picked small cap but far inside the reader's own default, so the cap is
        // pinned from BOTH directions: raising it fails the over-deep row below, and tightening it fails this
        // one. Only the first was pinned before, and a cap tightened to a handful of levels would refuse every
        // real JWKS carrying an `x5c` certificate chain while the suite stayed green.
        "{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":{\"g\":{\"h\":{\"i\":{\"j\":1}}}}}}}}}}",

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

    [Fact]
    public void NestingPastTheDepthCap_IsUnreadable()
    {
        // 65 opens against the reader's own default of 64: a document this walk cannot reach the bottom of is
        // one its consumers could not read either, so it is refused rather than passed on half-inspected.
        var tooDeep = string.Concat(Enumerable.Repeat("{\"a\":", 65)) + "1" + new string('}', 65);

        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect(tooDeep, out _));
    }

    [Fact]
    public void NoInputAtAll_IsClean()
    {
        // A body that carries no member cannot repeat one. Clean rather than Unreadable, so an empty response
        // is refused (or not) by whatever rule owns emptiness, not silently by this walk.
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect(null, out _));
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect("   ", out _));
    }

    [Fact]
    public void TheDecisionIsPinnedForTheFrameworkThisRunIsOn()
    {
        // The acceptance list asks for the corpus decision to be pinned per target framework, because the
        // plugin binds the HOST's System.Text.Json — .NET 9's under Jellyfin 10.11, .NET 10's under 12.0 —
        // and only the latter has the Strict preset whose duplicate policy this walk deliberately does not
        // use. A walk that had picked up a framework-dependent policy would answer differently on the two
        // legs, and this row is what makes that a failure rather than a divergence nobody looks at.
        //
        // It records WHICH framework it ran on in its failure message, so a red leg names itself rather than
        // leaving a reader to work out which of the two matrix runs disagreed.
        var leg = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription;

        foreach (var (json, member) in Repeated)
        {
            Assert.True(StrictJson.Inspect(json, out var actual) == StrictJson.Verdict.Repeated, $"{leg}: expected Repeated for {json}");
            Assert.True(actual == member, $"{leg}: expected member '{member}' for {json}, got '{actual}'");
        }

        foreach (var json in Clean)
        {
            Assert.True(StrictJson.Inspect(json, out _) == StrictJson.Verdict.Clean, $"{leg}: expected Clean for {json}");
        }

        foreach (var json in Unreadable)
        {
            Assert.True(StrictJson.Inspect(json, out _) == StrictJson.Verdict.Unreadable, $"{leg}: expected Unreadable for {json}");
        }
    }
}
