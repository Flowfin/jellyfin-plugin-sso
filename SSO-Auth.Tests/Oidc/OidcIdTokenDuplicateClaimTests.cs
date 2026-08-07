// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Pins what every id_token read route does with a payload that names one claim TWICE (#1192). The plugin
/// reads four claims out of the raw, signature-verified id_token through their own readers -
/// <see cref="OidcResponseIssuer.IdTokenIssuer"/> for <c>iss</c>, <see cref="OidcIdTokenSid"/>,
/// <see cref="OidcIdTokenAcr"/> and <see cref="OidcIdTokenAuthTime"/> - while the validated principal is
/// built from the same bytes by the JWT library. Each reader takes the LAST match out of a claim
/// collection it did not build, so whether the routes can be made to disagree is a property of that
/// library and not of any code here. It is read rather than assumed.
///
/// Nothing in this file guards anything. It records the posture, so that a dependency bump that changes
/// how a repeated member is folded fails here, at a row that says what the old behaviour was, rather than
/// showing up as a step-up gate and a logout key that disagree about which session was authenticated.
/// </summary>
public sealed class OidcIdTokenDuplicateClaimTests : IDisposable
{
    private const string Issuer = "https://idp.example.test";
    private const string ClientId = "jellyfin-client";

    private const string FirstIssuer = Issuer;
    private const string SecondIssuer = "https://idp.example.test/second";
    private const string FirstSid = "sess-first";
    private const string SecondSid = "sess-second";
    private const string FirstAcr = "acr-first";
    private const string SecondAcr = "acr-second";

    private readonly OidcTokenFixture _fixture = new(Issuer, ClientId);
    private readonly OidcIdTokenValidator _validator = new();

    private readonly long _firstAuthTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 600;
    private readonly long _secondAuthTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 60;

    public void Dispose() => _fixture.Dispose();

    [Fact]
    public void RepeatedMembersAreReallyInThePayload()
    {
        // The liveness control for every row below. All of them asserting "one value" would pass just as
        // well against a payload that named each claim once, so the bytes are checked to carry two
        // occurrences of all four names before anything is concluded from what came back out.
        var payload = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(DuplicatingToken().Split('.')[1]));

        foreach (var member in new[] { "iss", "sid", "acr", "auth_time" })
        {
            Assert.Equal(2, Regex.Matches(payload, "\"" + member + "\":").Count);
        }
    }

    [Fact]
    public async Task ADuplicatingTokenStillValidates()
    {
        // The second control: a token the validator refused would make every agreement below vacuous,
        // because the routes would be agreeing about a document the login path never accepts. The library
        // does accept it, so the four readers below run on a token that would have reached them in a real
        // callback.
        var result = await _validator.ValidateAsync(DuplicatingToken(), Options(), TestContext.Current.CancellationToken);

        Assert.False(result.IsError, result.Error);
    }

    [Fact]
    public void EveryRepeatedMemberFoldsToExactlyOneClaim()
    {
        // The mechanism the four agreements below rest on: the payload is folded into a claim collection
        // BEFORE any reader sees it, and the fold keeps one entry per name. That is why LastOrDefault and
        // JsonWebToken.Issuer cannot pick different occurrences - there is only one left to pick. If a
        // dependency bump ever surfaced both, this row fails first and names the change.
        var claims = new JsonWebToken(DuplicatingToken()).Claims.ToList();

        Assert.Equal(1, claims.Count(c => c.Type == "iss"));
        Assert.Equal(1, claims.Count(c => c.Type == "sid"));
        Assert.Equal(1, claims.Count(c => c.Type == "acr"));
        Assert.Equal(1, claims.Count(c => c.Type == "auth_time"));
    }

    [Fact]
    public void IssuerRoutesAgreeOnTheLastOccurrence()
    {
        // Which occurrence survives is named rather than merely asserted equal, because "the routes agree"
        // stays true if a bump flips both of them to the first value, and the canonical account link is
        // stamped with this issuer (#186).
        var token = DuplicatingToken();

        Assert.Equal(SecondIssuer, new JsonWebToken(token).Issuer);
        Assert.Equal(SecondIssuer, OidcResponseIssuer.IdTokenIssuer(token));
        Assert.NotEqual(FirstIssuer, OidcResponseIssuer.IdTokenIssuer(token));
    }

    [Fact]
    public async Task TheValidatorItselfReadsTheLastIssuerOccurrence()
    {
        // The issuer check is the one place a route's disagreement would be silent rather than visible in
        // a claim: the validator compares the token's iss against the configured anchor and says only
        // accepted or refused. Driving it against BOTH occurrences turns that into two observations, and
        // they are opposite, which is what proves the validator folds the same way the readers do rather
        // than being indifferent to the anchor.
        var token = DuplicatingToken();

        var onTheLast = await _validator.ValidateAsync(token, Options(SecondIssuer), TestContext.Current.CancellationToken);
        var onTheFirst = await _validator.ValidateAsync(token, Options(FirstIssuer), TestContext.Current.CancellationToken);

        Assert.False(onTheLast.IsError, onTheLast.Error);
        Assert.True(onTheFirst.IsError);
    }

    [Fact]
    public void SidRoutesAgreeOnTheLastOccurrence()
    {
        // The persisted back-channel logout key (#727). A split here would revoke a session the provider
        // never named.
        var token = DuplicatingToken();

        Assert.Equal(SecondSid, new JsonWebToken(token).Claims.Single(c => c.Type == "sid").Value);
        Assert.Equal(SecondSid, OidcIdTokenSid.Read(token));
    }

    [Fact]
    public void AcrRoutesAgreeOnTheLastOccurrence()
    {
        // The step-up gate (#757), where the two occurrences are a satisfied and an unsatisfied assurance
        // level and the gate's answer is whichever one it reads.
        var token = DuplicatingToken();

        Assert.Equal(SecondAcr, new JsonWebToken(token).Claims.Single(c => c.Type == "acr").Value);
        Assert.Equal(SecondAcr, OidcIdTokenAcr.Read(token));
    }

    [Fact]
    public void AuthTimeRoutesAgreeOnTheLastOccurrence()
    {
        // The max_age freshness gate (#961). This is the route that can disagree by REJECTING where the
        // others accept, because it parses the surviving value as Unix seconds after picking it, so its
        // agreement is asserted on the parsed long rather than on the string the others compare.
        var token = DuplicatingToken();

        Assert.Equal(
            _secondAuthTime.ToString(System.Globalization.CultureInfo.InvariantCulture),
            new JsonWebToken(token).Claims.Single(c => c.Type == "auth_time").Value);
        Assert.Equal(_secondAuthTime, OidcIdTokenAuthTime.Read(token));
        Assert.NotEqual(_firstAuthTime, OidcIdTokenAuthTime.Read(token));
    }

    [Fact]
    public async Task TheValidatedPrincipalAgreesWithTheRawReaders()
    {
        // The last route, and the one the other four are compared against in the issue: the principal the
        // login path actually carries. iss is absent here by design - OidcClient filters the protocol
        // claims out of the principal, which is the whole reason the readers above re-read the raw token.
        var token = DuplicatingToken();
        var result = await _validator.ValidateAsync(token, Options(), TestContext.Current.CancellationToken);

        Assert.False(result.IsError, result.Error);
        Assert.Equal(SecondSid, result.User.Claims.Single(c => c.Type == "sid").Value);
        Assert.Equal(SecondAcr, result.User.Claims.Single(c => c.Type == "acr").Value);
        Assert.Equal(
            _secondAuthTime.ToString(System.Globalization.CultureInfo.InvariantCulture),
            result.User.Claims.Single(c => c.Type == "auth_time").Value);
    }

    [Fact]
    public void TheSurvivingValueFollowsDocumentOrder()
    {
        // What separates "the last occurrence wins" from "this particular string wins": the same two
        // values, written the other way round, come back the other way round. Without this row every
        // agreement above would also hold for a library that folded to the alphabetically later value, to
        // the longer one, or to a cached constant, and the rows would read as a pin on behaviour while
        // pinning a coincidence of the fixture.
        var reversed = _fixture.RawPayloadIdToken(
            "{\"iss\":\"" + SecondIssuer + "\",\"iss\":\"" + FirstIssuer + "\","
            + "\"sub\":\"user-1\",\"aud\":\"" + ClientId + "\","
            + "\"sid\":\"" + SecondSid + "\",\"sid\":\"" + FirstSid + "\","
            + "\"acr\":\"" + SecondAcr + "\",\"acr\":\"" + FirstAcr + "\","
            + "\"auth_time\":" + _secondAuthTime + ",\"auth_time\":" + _firstAuthTime + "}");

        Assert.Equal(FirstIssuer, OidcResponseIssuer.IdTokenIssuer(reversed));
        Assert.Equal(FirstSid, OidcIdTokenSid.Read(reversed));
        Assert.Equal(FirstAcr, OidcIdTokenAcr.Read(reversed));
        Assert.Equal(_firstAuthTime, OidcIdTokenAuthTime.Read(reversed));
    }

    // One token, used by every row, repeating each of the four claims with two DISTINCT values so a route
    // reading the first occurrence and a route reading the second are visibly different answers rather
    // than the same string twice. exp/nbf/iat are single so the token validates on its lifetime.
    private string DuplicatingToken()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var payload =
            "{\"iss\":\"" + FirstIssuer + "\",\"iss\":\"" + SecondIssuer + "\","
            + "\"sub\":\"user-1\",\"aud\":\"" + ClientId + "\","
            + "\"sid\":\"" + FirstSid + "\",\"sid\":\"" + SecondSid + "\","
            + "\"acr\":\"" + FirstAcr + "\",\"acr\":\"" + SecondAcr + "\","
            + "\"auth_time\":" + _firstAuthTime + ",\"auth_time\":" + _secondAuthTime + ","
            + "\"exp\":" + (now + 300) + ",\"nbf\":" + (now - 60) + ",\"iat\":" + (now - 60) + "}";

        return _fixture.RawPayloadIdToken(payload);
    }

    // Anchored on the SECOND issuer, because that is the occurrence the readers report surviving. The row
    // above proves the validator agrees by refusing the other anchor.
    private OidcClientOptions Options(string? issuerName = null) => new()
    {
        ClientId = ClientId,
        ProviderInformation = new ProviderInformation
        {
            IssuerName = issuerName ?? SecondIssuer,
            KeySet = new Duende.IdentityModel.Jwk.JsonWebKeySet(_fixture.Jwks()),
        },
    };
}
