// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="StrictJson"/> — the repeated-property-name screen for provider-supplied JSON
/// (#1005). Each rejection fixture is paired with the SAME document minus the duplicate: without that pair a
/// screen that refuses everything would satisfy every rejection here while taking the plugin's OpenID logins
/// offline, and the rejections would prove nothing about duplicates. The third group is the other half of
/// that bargain — the repeats the screen deliberately admits, because they sit in scopes no reader indexes
/// and refusing on them would be an outage rather than a defence.
/// The file runs on both target frameworks, so a decision that differs between them fails the leg it
/// differs on — the screen deliberately owns no <c>JsonSerializerOptions</c>, whose duplicate switch exists
/// on only one of the two.
/// </summary>
public class StrictJsonTests
{
    [Theory]
    [InlineData("{\"a\":1,\"a\":2}")] // the repeat in the root object, which every caller reads
    [InlineData("{\"issuer\":\"https://good\",\"issuer\":\"https://evil\"}")] // the discovery shape: which issuer the login binds to
    [InlineData("{\"kid\":\"trusted\",\"\\u006bid\":\"attacker\"}")] // the same name spelled as an escape — compared after unescaping, as its consumers do
    public void RepeatedNameInAReadScope_IsReported(string json)
    {
        Assert.Equal(StrictJson.Verdict.Repeated, StrictJson.Inspect(json));
    }

    [Theory]
    [InlineData("{\"a\":1,\"b\":2}")]
    [InlineData("{\"issuer\":\"https://good\"}")]
    [InlineData("{\"kid\":\"trusted\",\"alg\":\"RS256\"}")]
    public void TheSameDocumentsWithoutTheRepeat_AreClean(string json)
    {
        // The positive control for every fixture above, in the same order and the same shape. A screen that
        // reports Repeated unconditionally passes the theory above and fails here.
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect(json));
    }

    [Theory]
    [InlineData("{\"o\":{\"a\":1,\"a\":2}}")] // one object down, where the caller named no path to descend
    [InlineData("{\"mtls_endpoint_aliases\":{\"token_endpoint\":\"https://a\",\"token_endpoint\":\"https://b\"}}")] // the real discovery member no reader here opens
    [InlineData("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"trusted\",\"kid\":\"attacker\"}]}")] // inside an array element, likewise unindexed from here
    public void RepeatedNameOutsideEveryReadScope_IsClean(string json)
    {
        // The availability half, and the reason the screen takes a path at all. A repeat in a scope the
        // caller never indexes decides nothing — no value the plugin acts on comes out of it — so refusing
        // would convert a working provider's logins into refusals to defend a decision nobody makes. The
        // caller that DOES read those scopes says so, which the theory below exercises.
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect(json));
    }

    [Fact]
    public void RepeatedNameInsideTheScopeThePathNames_IsReported()
    {
        // The same document as the first fixture above, inspected by a caller that declares it reads `o`.
        Assert.Equal(StrictJson.Verdict.Repeated, StrictJson.Inspect("{\"o\":{\"a\":1,\"a\":2}}", "o"));
    }

    [Fact]
    public void RepeatedNameInsideADifferentScope_IsClean()
    {
        // The path names a sibling, so the repeat is still outside what the caller reads. Without this the
        // test above would also pass a screen that descends into every object once a path is non-empty.
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect("{\"p\":{\"a\":1},\"o\":{\"b\":2,\"b\":3}}", "p"));
    }

    [Fact]
    public void RepeatedNameInAnArrayElementUnderThePath_IsClean()
    {
        // A path segment names an object to enter, not an array to iterate. The elements of `o` are objects
        // the walk never indexes, so a name repeated inside one of them is not the caller's repeat — and a
        // screen that let the pending name survive an array would call every element the path's object.
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect("{\"o\":[{\"a\":1,\"a\":2}]}", "o"));
    }

    [Fact]
    public void RepeatOfTheScopeNameItself_IsReported()
    {
        // The path segment served twice in the object the caller reads. Descending into the first must not
        // stop the walk seeing the second: it is the repeat that decides which subtree the caller walks.
        Assert.Equal(StrictJson.Verdict.Repeated, StrictJson.Inspect("{\"o\":{\"a\":1},\"o\":{\"b\":2}}", "o"));
    }

    [Theory]
    [InlineData("{\"o\":{\"a\":1},\"p\":{\"a\":2}}")] // two sibling objects that legitimately reuse a name
    [InlineData("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"one\"},{\"kty\":\"RSA\",\"kid\":\"two\"}]}")] // every real JWKS: each entry repeats kty and kid
    public void SiblingObjectsReusingAName_AreClean(string json)
    {
        // The scope control. A screen keeping ONE name set for the whole document rejects both of these,
        // which is every JWKS and most discovery documents — it would read as a working guard and be an
        // outage.
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect(json));
    }

    [Fact]
    public void NamesDifferingOnlyInCase_AreClean()
    {
        // JSON member names are case-sensitive and every consumer of these documents compares them
        // ordinally, so "a" and "A" are two names and not a repeat. An OrdinalIgnoreCase set would call
        // this an attack and refuse documents no consumer can be confused by.
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect("{\"a\":1,\"A\":2}"));
    }

    [Theory]
    [InlineData("not-json")]
    [InlineData("{\"a\":1")] // truncated
    [InlineData("{\"a\":1,}")] // a trailing comma: legal to Newtonsoft, rejected by System.Text.Json
    [InlineData("{\"a\":1 /* c */}")] // a comment: same split between the two parser families
    [InlineData("{'a':1}")] // single quotes: likewise Newtonsoft-legal only
    [InlineData("\uFEFF{\"a\":1}")] // a byte-order mark ahead of an otherwise ordinary document
    [InlineData("{\"a\":1}{\"b\":2}")] // two top-level values
    public void UntokenizableDocument_IsUnreadable_NotARepeat(string json)
    {
        // The distinction the verdict exists for. Every one of these is a document with NO repeated name, and
        // a screen that answered a single bool would have to call each of them a duplicate — turning a
        // byte-order mark or a vendor grammar quirk into a refused login, under a message telling the
        // operator to hunt a repeat that is not there. "I could not check it" is still not "it is clean", so
        // it is its own answer and each caller decides what to do with it on its own terms.
        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect(json));
    }

    [Fact]
    public void DocumentNestedPastTheReaderDepth_IsUnreadable()
    {
        // Past the reader's depth cap the walk cannot reach the inner scopes, so the document is reported
        // unreadable rather than clean on the strength of the prefix that was read — and, again, not as a
        // repeat it does not contain.
        var deep = string.Concat(Enumerable.Repeat("{\"a\":", 200)) + "1" + new string('}', 200);
        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect(deep));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void AbsentDocument_IsClean(string? json)
    {
        // Nothing was supplied, so there is nothing to repeat. Every caller already has its own branch for an
        // absent document; inventing a refusal here would change what those branches decide without saying so.
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect(json));
    }
}
