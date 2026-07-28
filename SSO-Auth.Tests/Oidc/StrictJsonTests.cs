// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="StrictJson"/> — the repeated-member screen for the OpenID discovery document
/// (#1005). Each rejection fixture is paired with the SAME document minus the repeat: without that pair a
/// screen that refuses everything would satisfy every rejection here while taking the plugin's OpenID logins
/// offline, and the rejections would prove nothing about duplicates. The must-NOT-catch groups are the other
/// half of that bargain and carry the same weight — a repeat of a member nobody indexes, and a repeat below
/// the root object, are both admitted, because refusing on them is an outage bought with no defence.
/// The file runs on both target frameworks, so a decision that differs between them fails the leg it differs
/// on — the screen deliberately owns no <c>JsonSerializerOptions</c>, whose duplicate switch exists on only
/// one of the two.
/// </summary>
public class StrictJsonTests
{
    // A caller's indexed-member list, in the shape the discovery reader passes one. Two entries, so a
    // fixture can repeat one member while another screened member is present and untouched.
    private static readonly string[] Screened = new[] { "issuer", "jwks_uri" };

    [Theory]
    [InlineData("{\"issuer\":\"https://good\",\"issuer\":\"https://evil\"}", "issuer")] // which issuer the login binds to
    [InlineData("{\"jwks_uri\":\"https://good/jwks\",\"jwks_uri\":\"https://evil/jwks\"}", "jwks_uri")] // which keys the id_token is validated against
    [InlineData("{\"issuer\":\"https://good\",\"\\u0069ssuer\":\"https://evil\"}", "issuer")] // the same name spelled as an escape — compared after unescaping, as its consumers do
    public void RepeatedIndexedMember_IsReported_AndNamed(string json, string expected)
    {
        Assert.Equal(StrictJson.Verdict.Repeated, StrictJson.Inspect(json, Screened, out var repeated));

        // The name is the operator's whole diagnosis: "this document repeats something" leaves an admin
        // hunting one of some sixty members. It is also necessarily one of Screened, which is what makes it
        // safe for the caller to log without sanitizing a provider-authored string.
        Assert.Equal(expected, repeated);
        Assert.Contains(expected, Screened);
    }

    [Theory]
    [InlineData("{\"issuer\":\"https://good\"}")]
    [InlineData("{\"jwks_uri\":\"https://good/jwks\"}")]
    [InlineData("{\"issuer\":\"https://good\",\"jwks_uri\":\"https://good/jwks\"}")]
    public void TheSameDocumentsWithoutTheRepeat_AreClean(string json)
    {
        // The positive control for every fixture above. A screen that reports Repeated unconditionally passes
        // the theory above and fails here.
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect(json, Screened, out var repeated));
        Assert.Null(repeated);
    }

    [Theory]
    [InlineData("{\"scopes_supported\":[\"openid\"],\"scopes_supported\":[\"openid\",\"profile\"]}")] // a real discovery member no reader here indexes
    [InlineData("{\"response_types_supported\":[\"code\"],\"response_types_supported\":[\"token\"]}")] // likewise
    [InlineData("{\"vendor_tenant\":\"a\",\"vendor_tenant\":\"b\"}")] // the general case: a vendor extension
    public void RepeatedMemberNoReaderIndexes_IsClean(string json)
    {
        // The availability half, and the reason the screen takes a member list at all. No value the plugin
        // acts on comes out of these members, so a repeat in one decides nothing — while refusing would
        // convert a working provider's logins into refusals to defend a decision nobody makes.
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect(json, Screened, out var repeated));
        Assert.Null(repeated);
    }

    [Theory]
    [InlineData("{\"mtls_endpoint_aliases\":{\"issuer\":\"https://a\",\"issuer\":\"https://b\"}}")] // one object down
    [InlineData("{\"keys\":[{\"issuer\":\"https://a\",\"issuer\":\"https://b\"}]}")] // inside an array element
    [InlineData("[{\"issuer\":\"https://a\",\"issuer\":\"https://b\"}]")] // an array-rooted document has no root member at all
    public void RepeatBelowTheRootObject_IsClean(string json)
    {
        // The screen's stated reach is the root object, and this is where that stops. An indexed member's
        // NAME appearing twice somewhere the caller never descends into is not the caller's repeat; the
        // array-rooted fixture is the sharp one, because a screen keyed on "an object at the outermost
        // nesting level" would call that element the root and refuse a document with no root member.
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect(json, Screened, out var repeated));
        Assert.Null(repeated);
    }

    [Fact]
    public void SiblingObjectsReusingAName_AreClean()
    {
        // The scope control. A screen keeping ONE name set for the whole document rejects this, which is
        // every JWKS — it would read as a working guard and be an outage.
        Assert.Equal(
            StrictJson.Verdict.Clean,
            StrictJson.Inspect("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"one\"},{\"kty\":\"RSA\",\"kid\":\"two\"}]}", Screened, out _));
    }

    [Fact]
    public void NamesDifferingOnlyInCase_AreClean()
    {
        // JSON member names are case-sensitive and every consumer of these documents compares them
        // ordinally, so `issuer` and `Issuer` are two names and not a repeat. An OrdinalIgnoreCase set would
        // call this an attack and refuse documents no consumer can be confused by.
        Assert.Equal(
            StrictJson.Verdict.Clean,
            StrictJson.Inspect("{\"issuer\":\"https://a\",\"Issuer\":\"https://b\"}", Screened, out _));
    }

    [Fact]
    public void AnEmptyMemberList_ScreensNothing()
    {
        // The screen's reach is exactly the list it is given, stated as a test so nobody has to infer it: a
        // caller that names no members gets no screening. That is why Inspect takes the list as an ordinary
        // required argument rather than a params array — the empty case has to be written down.
        Assert.Equal(
            StrictJson.Verdict.Clean,
            StrictJson.Inspect("{\"issuer\":\"https://a\",\"issuer\":\"https://b\"}", Array.Empty<string>(), out _));
    }

    [Theory]
    [InlineData("not-json")]
    [InlineData("{\"issuer\":\"https://a\"")] // truncated
    [InlineData("{\"issuer\":\"https://a\",}")] // a trailing comma: legal to Newtonsoft, rejected by System.Text.Json
    [InlineData("{\"issuer\":\"https://a\" /* c */}")] // a comment: same split between the two parser families
    [InlineData("{'issuer':'https://a'}")] // single quotes: likewise Newtonsoft-legal only
    [InlineData("\uFEFF{\"issuer\":\"https://a\"}")] // a byte-order mark ahead of an otherwise ordinary document
    [InlineData("{\"issuer\":\"https://a\"}{\"issuer\":\"https://b\"}")] // two top-level values
    public void UntokenizableDocument_IsUnreadable_NotARepeat(string json)
    {
        // The distinction the verdict exists for. Every one of these is a document with NO repeated indexed
        // member, and a screen that answered a single bool would have to call each of them a duplicate —
        // turning a byte-order mark or a vendor grammar quirk into a refused login, under a message telling
        // the operator to hunt a repeat that is not there. "I could not check it" is still not "it is
        // clean", so it is its own answer and the caller decides what to do with it.
        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect(json, Screened, out var repeated));
        Assert.Null(repeated);
    }

    [Fact]
    public void DocumentNestedPastTheReaderDepth_IsUnreadable()
    {
        // Past the reader's depth cap the walk stops, so the document is reported unreadable rather than
        // clean on the strength of the prefix that was read — and, again, not as a repeat it does not
        // contain.
        var deep = string.Concat(Enumerable.Repeat("{\"a\":", 200)) + "1" + new string('}', 200);
        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect(deep, Screened, out _));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void AbsentDocument_IsClean(string? json)
    {
        // Nothing was supplied, so there is nothing to repeat. The caller already has its own branch for an
        // absent document; inventing a refusal here would change what that branch decides without saying so.
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect(json, Screened, out _));
    }
}
