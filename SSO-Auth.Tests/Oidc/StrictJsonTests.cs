// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="StrictJson"/> — the duplicate-property gate every provider-supplied JSON document
/// passes before the plugin reads it (#1005). Each rejection fixture is paired with the SAME document minus
/// the duplicate: without that pair a gate that refuses everything would satisfy every rejection here while
/// taking the plugin's OpenID logins offline, and the rejections would prove nothing about duplicates.
/// The file runs on both target frameworks, so a decision that differs between them fails the leg it
/// differs on — the gate deliberately owns no <c>JsonSerializerOptions</c>, whose duplicate switch exists
/// on only one of the two.
/// </summary>
public class StrictJsonTests
{
    [Theory]
    [InlineData("{\"a\":1,\"a\":2}")] // the top-level repeat
    [InlineData("{\"o\":{\"a\":1,\"a\":2}}")] // nested one object down, where a root-only check would miss it
    [InlineData("{\"k\":[{\"a\":1,\"a\":2}]}")] // inside an array element, where an object-only walk would miss it
    [InlineData("{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"trusted\",\"kid\":\"attacker\"}]}")] // the JWKS shape: which key id the entry claims
    [InlineData("{\"issuer\":\"https://good\",\"issuer\":\"https://evil\"}")] // the discovery shape: which issuer the login binds to
    [InlineData("{\"kid\":\"trusted\",\"\\u006bid\":\"attacker\"}")] // the same name spelled as an escape — compared after unescaping, as its consumers do
    public void DuplicateProperty_AtEveryDepth_IsRejected(string json)
    {
        Assert.True(StrictJson.HasDuplicateProperty(json));
    }

    [Theory]
    [InlineData("{\"a\":1,\"b\":2}")]
    [InlineData("{\"o\":{\"a\":1,\"b\":2}}")]
    [InlineData("{\"k\":[{\"a\":1,\"b\":2}]}")]
    [InlineData("{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"trusted\"}]}")]
    [InlineData("{\"issuer\":\"https://good\"}")]
    [InlineData("{\"kid\":\"trusted\",\"alg\":\"RS256\"}")]
    public void TheSameDocumentsWithoutTheDuplicate_AreAccepted(string json)
    {
        // The positive control for every fixture above, in the same order and the same shape. A gate that
        // returns true unconditionally passes the rejection theory and fails here.
        Assert.False(StrictJson.HasDuplicateProperty(json));
    }

    [Theory]
    [InlineData("{\"o\":{\"a\":1},\"p\":{\"a\":2}}")] // two sibling objects that legitimately reuse a name
    [InlineData("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"one\"},{\"kty\":\"RSA\",\"kid\":\"two\"}]}")] // every real JWKS: each entry repeats kty and kid
    public void SiblingObjectsReusingAName_AreAccepted(string json)
    {
        // The scope control. A gate keeping ONE name set for the whole document rejects both of these, which
        // is every JWKS and most discovery documents — it would read as a working guard and be an outage.
        Assert.False(StrictJson.HasDuplicateProperty(json));
    }

    [Fact]
    public void NamesDifferingOnlyInCase_AreAccepted()
    {
        // JSON member names are case-sensitive and every consumer of these documents compares them
        // ordinally, so "a" and "A" are two names and not a repeat. An OrdinalIgnoreCase set would call
        // this an attack and refuse documents no consumer can be confused by.
        Assert.False(StrictJson.HasDuplicateProperty("{\"a\":1,\"A\":2}"));
    }

    [Theory]
    [InlineData("not-json")]
    [InlineData("{\"a\":1")] // truncated
    [InlineData("{\"a\":1,}")] // a trailing comma: legal to Newtonsoft, rejected by System.Text.Json
    [InlineData("{\"a\":1 /* c */}")] // a comment: same split between the two parser families
    public void UntokenizableDocument_IsRejected(string json)
    {
        // A document the gate could not clear is refused, not waved through: "I could not check it" must
        // never read as "it is clean". The three malformed spellings are also where the two parser families
        // this plugin depends on disagree about the grammar itself.
        Assert.True(StrictJson.HasDuplicateProperty(json));
    }

    [Fact]
    public void DocumentNestedPastTheReaderDepth_IsRejected()
    {
        // Past the reader's depth cap the walk cannot reach the inner scopes, so the document is refused
        // rather than reported clean on the strength of the prefix that was read.
        var deep = string.Concat(Enumerable.Repeat("{\"a\":", 200)) + "1" + new string('}', 200);
        Assert.True(StrictJson.HasDuplicateProperty(deep));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void AbsentDocument_IsNotADuplicate(string? json)
    {
        // Nothing was supplied, so there is nothing to repeat. Every caller already has its own branch for an
        // absent document; inventing a refusal here would change what those branches decide without saying so.
        Assert.False(StrictJson.HasDuplicateProperty(json));
    }
}
