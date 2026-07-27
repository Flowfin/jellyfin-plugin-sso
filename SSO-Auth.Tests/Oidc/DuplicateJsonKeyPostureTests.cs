// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json;
using Duende.IdentityModel.Jwk;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Microsoft.IdentityModel.JsonWebTokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The cross-reader half of #1005: a security-relevant field that more than one reader takes out of the same
/// bytes must not be readable two ways. Two documents in this plugin are read more than once — the OpenID
/// discovery document (the library's typed read plus the plugin's own two fact readers, in a DIFFERENT parser
/// family) and the id_token (validated once, then re-read raw at four call sites). These tests drive every
/// reader of each over one document and assert a single outcome, and pin the duplicate-key posture of the
/// parsers underneath so a dependency bump that flips one fails here rather than in a login.
/// </summary>
public class DuplicateJsonKeyPostureTests
{
    // Grammar the two parser families disagree about: Newtonsoft accepts all three, System.Text.Json rejects
    // all three. Admitting such a document would mean the plugin's fact readers answering about bytes the
    // library could not read at all.
    private const string CommentGrammar = "{\"code_challenge_methods_supported\":[\"S256\"] /* x */}";
    private const string SingleQuoteGrammar = "{'code_challenge_methods_supported':['S256']}";
    private const string TrailingCommaGrammar = "{\"code_challenge_methods_supported\":[\"S256\"],}";

    [Theory]
    [InlineData("{\"code_challenge_methods_supported\":[\"S256\"],\"authorization_response_iss_parameter_supported\":true}")]
    [InlineData("{\"code_challenge_methods_supported\":[\"plain\"],\"authorization_response_iss_parameter_supported\":false}")]
    [InlineData("{\"issuer\":\"https://idp\"}")]
    [InlineData("{\"code_challenge_methods_supported\":\"S256\",\"authorization_response_iss_parameter_supported\":\"true\"}")] // both facts served as strings
    [InlineData("{\"code_challenge_methods_supported\":[256],\"authorization_response_iss_parameter_supported\":1}")] // and as the wrong JSON types entirely
    public void OnTheDocumentsTheGateAdmits_EveryDiscoveryReaderAgrees(string document)
    {
        // The property the screen buys: for every document that reaches the fact readers, the Newtonsoft
        // answers equal the answers the System.Text.Json family — the library's own parser — gets from the
        // same bytes. Both facts, both readers, one document. The oracle below is therefore System.Text.Json
        // and not a second Newtonsoft read: an oracle from the same family as the code under test compares a
        // parser with itself and would agree on documents the two families read differently.
        Assert.Equal(StrictJson.Verdict.Clean, StrictJson.Inspect(document));

        var (pkce, responseIssuer) = ByTheLibrarysOwnFamily(document);

        Assert.Equal(pkce, PkceDiscovery.SupportsS256(document));
        Assert.Equal(responseIssuer, OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer(document));
    }

    [Theory]
    [InlineData(CommentGrammar)]
    [InlineData(SingleQuoteGrammar)]
    [InlineData(TrailingCommaGrammar)]
    public void WhereTheParserFamiliesDisagree_TheDiscoveryReadIsRefused(string document)
    {
        // The demonstration that the agreement above is not a tautology. On each of these the plugin's
        // Newtonsoft reader happily reports PKCE support for a document System.Text.Json cannot read at all —
        // a divergence of exactly the shape this issue is about. The screen reports each as UNREADABLE rather
        // than as a repeat, which is the honest answer, and the discovery reader refuses an unreadable
        // document, so the divergence stays unreachable on the path where the facts are used.
        Assert.True(PkceDiscovery.SupportsS256(document));
        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect(document));
    }

    // The two discovery facts as the library's own parser family reads them. Total by construction: a fact
    // served as the wrong JSON type answers false rather than throwing, because an oracle that throws on a
    // document the plugin has to survive tests the fixture list instead of the code.
    private static (bool Pkce, bool ResponseIssuer) ByTheLibrarysOwnFamily(string document)
    {
        using var parsed = JsonDocument.Parse(document);
        var root = parsed.RootElement;

        var pkce = root.TryGetProperty("code_challenge_methods_supported", out var methods)
            && methods.ValueKind == JsonValueKind.Array
            && methods.EnumerateArray().Any(m => m.ValueKind == JsonValueKind.String && string.Equals(m.GetString(), "S256", StringComparison.Ordinal));

        return (
            pkce,
            root.TryGetProperty("authorization_response_iss_parameter_supported", out var flag) && flag.ValueKind == JsonValueKind.True);
    }

    [Fact]
    public void EveryReaderOfTheIdToken_ReachesTheSameClaimValue()
    {
        // The id_token is read five times: once by the validator, whose claims come off a JsonWebToken, and
        // then raw at four call sites that re-parse the token string because OidcClient strips the protocol
        // claims from the principal. All five go through the same parser, so a repeated claim resolves the
        // same way everywhere — one value, not one per reader. That is asserted rather than assumed here,
        // because it is the sole reason the id_token needs no gate of its own while the discovery document
        // does, and it would stop being true the moment a reader used a different parser.
        var token = UnsignedToken(
            "{\"alg\":\"RS256\"}",
            "{\"iss\":\"https://first\",\"iss\":\"https://second\","
            + "\"sid\":\"first-session\",\"sid\":\"second-session\","
            + "\"acr\":\"first-acr\",\"acr\":\"second-acr\","
            + "\"auth_time\":1111111111,\"auth_time\":2222222222,\"sub\":\"s\"}");

        var parsed = new JsonWebToken(token);

        Assert.Equal(parsed.Issuer, OidcResponseIssuer.IdTokenIssuer(token));
        Assert.Equal(ClaimOf(parsed, "sid"), OidcIdTokenSid.Read(token));
        Assert.Equal(ClaimOf(parsed, "acr"), OidcIdTokenAcr.Read(token));
        Assert.Equal(
            ClaimOf(parsed, "auth_time"),
            OidcIdTokenAuthTime.Read(token)?.ToString(CultureInfo.InvariantCulture));

        // And the value they agree on is the LAST occurrence, which is the posture the row below pins.
        Assert.Equal("https://second", OidcResponseIssuer.IdTokenIssuer(token));
        Assert.Equal("second-session", OidcIdTokenSid.Read(token));
    }

    [Fact]
    public void RepeatedAudience_CollapsesToTheLastOccurrence()
    {
        // A repeated scalar `aud` is not the multi-valued `aud` array the audience-restriction check is
        // written against: the parser collapses it, so the token presents ONE audience and the azp rule for
        // multiple audiences never engages. Pinned because the collapse is what makes the two shapes behave
        // differently, and nothing else in the suite says so.
        var token = UnsignedToken("{\"alg\":\"RS256\"}", "{\"aud\":\"other-client\",\"aud\":\"this-client\",\"sub\":\"s\"}");

        Assert.Equal(new[] { "this-client" }, new JsonWebToken(token).Audiences);
    }

    [Theory]
    // The measured duplicate-key posture of every parser the plugin PINS through its lockfile: each takes the
    // last occurrence and none raises an error, which is why the screen exists. A dependency bump that
    // changes any row fails here, where the reason is written down, instead of changing what a login decides.
    // That is the claim, and it is no wider: these rows pin what the PINNED version does. The host resolves
    // assembly loads for a plugin, so the copy actually loaded beside Jellyfin may not be the pinned one —
    // this table detects a change in the dependency the plugin declares, not in the one the server supplies.
    //
    // System.Text.Json cannot be covered even that far, so it is deliberately absent: it ships IN the runtime
    // rather than as a package reference, so its version is whichever the host's framework is — .NET 9's in
    // the Jellyfin 10.11 line, .NET 10's in the 12.0 line — and there is no pin for a row to track. This test
    // process loads a 10.x on BOTH legs, so a row would report an assembly that never runs in production.
    // What replaces it is structural: the screen owns no JsonSerializerOptions, which
    // UntrustedJsonConformanceTests enforces.
    [InlineData("newtonsoft-linq")]
    [InlineData("newtonsoft-dictionary")]
    [InlineData("jwt-header")]
    [InlineData("jwt-payload")]
    [InlineData("duende-jwks")]
    public void ParserDuplicateKeyPosture_IsPinned(string parser)
    {
        var taken = parser switch
        {
            "newtonsoft-linq" => JObject.Parse("{\"v\":\"first\",\"v\":\"last\"}")["v"]?.Value<string>(),
            "newtonsoft-dictionary" => JsonConvert.DeserializeObject<IDictionary<string, object>>("{\"v\":\"first\",\"v\":\"last\"}")?["v"].ToString(),
            "jwt-header" => new JsonWebToken(UnsignedToken("{\"alg\":\"first\",\"alg\":\"last\"}", "{\"sub\":\"s\"}")).Alg,
            "jwt-payload" => ClaimOf(new JsonWebToken(UnsignedToken("{\"alg\":\"RS256\"}", "{\"v\":\"first\",\"v\":\"last\"}")), "v"),
            "duende-jwks" => new JsonWebKeySet("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"first\",\"kid\":\"last\"}]}").Keys[0].Kid,
            _ => throw new ArgumentOutOfRangeException(nameof(parser)),
        };

        Assert.Equal("last", taken);
    }

    // The claim as the validator's own view of the token reports it — the validator reads its claims off a
    // JsonWebToken over this same string, so this is that reader, not an approximation of it.
    private static string? ClaimOf(JsonWebToken token, string type) =>
        token.Claims.FirstOrDefault(c => string.Equals(c.Type, type, StringComparison.Ordinal))?.Value;

    // A JWS with an arbitrary header and payload and a placeholder signature. Every reader exercised here
    // parses the token without verifying it, which is exactly the property being examined: they read the same
    // bytes the validator read, so they must not read them differently.
    private static string UnsignedToken(string header, string payload) =>
        Base64Url(header) + "." + Base64Url(payload) + ".c2ln";

    private static string Base64Url(string value) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(value)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
