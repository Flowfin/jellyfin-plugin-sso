// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// A key the provider ADVERTISES may still be unusable, and a symmetric one is the case where believing the
/// advertisement is fatal (#1004). RFC 7517 §6.1 defines <c>kty: oct</c>, whose secret travels in the JWKS
/// as the <c>k</c> member, so an HMAC key published in a discovery document is known to everyone who can
/// fetch that document. A verifier that turned such an entry into an issuer signing key would accept a
/// token minted by any reader of a public URL, on either JWT path the plugin runs.
/// <para>
/// Two independent controls stand between the plugin and that outcome, and the rows here are arranged so
/// each is visible on its own rather than hidden behind the other. The algorithm allowlist in
/// <see cref="OidcSignatureKeys.AllowedSignatureAlgorithms"/> lists no <c>HS*</c> entry, and
/// <see cref="OidcSignatureKeys.Convert"/> reads only the RSA <c>e</c>/<c>n</c> pair and the EC
/// <c>crv</c>/<c>x</c>/<c>y</c> triple, so a <c>k</c> member reaches no key at all. Existing coverage
/// asks the algorithm question with a key the provider never advertised
/// (<c>OidcIdTokenValidatorTests</c>, <c>OidcLogoutTokenValidatorTests</c>); nothing asked whether an
/// ADVERTISED secret becomes a signing key, which is the conversion half and the one this file holds.
/// </para>
/// <para>
/// EVERY REJECTION ROW HERE IS PAIRED WITH A CONTROL, for the reason #1052 was split out of #1004: a
/// fixture the verifier never understood is refused for its malformedness, and the row goes green while
/// the property it names does not hold.
/// <see cref="TheMacdToken_Authenticates_OnceTheAdvertisedSecretIsInTheBasis"/> installs into the SHIPPED
/// basis the one behaviour these rows say is absent - the signing key a <c>k</c>-reading converter would
/// have produced - and requires the forgery to be ACCEPTED, so the refusals cannot be coming from a claim,
/// a time bound or a broken segment. <see cref="TheAlgorithmAllowlist_IsNotWhatRefusesTheMac"/> is its
/// mirror: with <c>HS256</c> added to the shipped allowlist and the key still absent, the token is refused
/// anyway, which is what attributes the refusal to conversion rather than to the algorithm list that
/// <c>TokenValidationBasisConformanceTests</c> already guards.
/// </para>
/// <para>
/// WHAT IS PROVEN UNEVENLY, stated here rather than left to be counted off the rows. On the back-channel
/// path the production algorithm gate (#1164) judges <c>alg</c> before the handler runs, so
/// <see cref="LogoutToken_MacdWithTheAdvertisedSecret_IsRejected"/> records THAT the token is refused and
/// cannot attribute the refusal - its reason code says as much. The attribution rows below run against the
/// shipped validation basis both paths derive from, which is the shared surface the conversion property
/// lives on.
/// </para>
/// <para>
/// Serialized because the back-channel row reaches the process-wide replay cache through
/// <c>OidcLogoutTokenValidator.ResetReplaysForTests</c>. The reset is kept rather than reasoned away: this
/// file's token is refused before any <c>jti</c> could be recorded, but a neighbouring class clearing that
/// static under a one-time-use assertion is the intermittent failure #1171 exists to stop, and the cost of
/// the collection is six fast rows not running in parallel.
/// </para>
/// </summary>
[Collection("SSOController")]
public sealed class OidcAdvertisedSymmetricKeyTests : IDisposable
{
    private const string Issuer = "https://idp.example.test";
    private const string ClientId = "jellyfin-client";
    private const string SymmetricKeyId = "advertised-hmac-key";
    private const string RsaKeyId = "advertised-signing-key";

    private readonly RSA _rsa = RSA.Create(2048);
    private readonly byte[] _secret = RandomNumberGenerator.GetBytes(32);
    private readonly OidcIdTokenValidator _idTokenValidator = new();
    private readonly OidcLogoutTokenValidator _logoutValidator = new();
    private readonly DateTime _now = DateTime.UtcNow;

    public void Dispose()
    {
        _rsa.Dispose();
        OidcLogoutTokenValidator.ResetReplaysForTests();
    }

    [Fact]
    public void AnAdvertisedSymmetricKey_IsNeverConvertedToASigningKey()
    {
        // The conversion property at its own level, where no token, algorithm or claim can stand in for it.
        var ephemeralKeys = new List<IDisposable>();
        try
        {
            Assert.Empty(OidcSignatureKeys.Convert(KeySet(SymmetricJwk()), ephemeralKeys));

            // Beside a usable key the secret is still dropped, and dropping it does not cost the set: a
            // converter that threw on the unfamiliar entry would take the provider's real key down with it.
            var mixed = OidcSignatureKeys.Convert(KeySet(SymmetricJwk() + "," + RsaJwk()), ephemeralKeys);

            var kept = Assert.Single(mixed);
            Assert.IsType<RsaSecurityKey>(kept);
            Assert.Equal(RsaKeyId, kept.KeyId);
        }
        finally
        {
            ephemeralKeys.ForEach(key => key.Dispose());
        }
    }

    [Fact]
    public async Task IdToken_MacdWithTheAdvertisedSecret_IsRejected()
    {
        // The login path. The secret is taken from the JWKS the provider published, so this is what any
        // reader of that document can mint, not what a key holder can.
        var result = await _idTokenValidator.ValidateAsync(
            MacdToken(null), OptionsFor(SymmetricJwk()), TestContext.Current.CancellationToken);

        Assert.True(result.IsError);
        Assert.Null(result.User);
    }

    [Fact]
    public async Task LogoutToken_MacdWithTheAdvertisedSecret_IsRejected()
    {
        // The back-channel path shares the one validation basis, so it must share the property; a drift
        // here revokes a named user's sessions on the say-so of anyone who read the discovery JWKS. The
        // reason code is the honest one: the #1164 algorithm gate answers first on this path, so this row
        // records the refusal and the attribution rows below carry the conversion property.
        var result = await _logoutValidator.ValidateAsync(MacdToken(LogoutClaims()), OptionsFor(SymmetricJwk()), _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.AlgorithmNotAllowed, result.ReasonCode);
        Assert.Null(result.Subject);
        Assert.Null(result.SessionIndex);
    }

    [Fact]
    public async Task TheAlgorithmAllowlist_IsNotWhatRefusesTheMac()
    {
        // One control at a time. HS256 is added to the shipped basis, which removes the algorithm allowlist
        // from the answer entirely, and the token is still refused - because no key in the basis can verify
        // an HMAC. This is what makes the rows above evidence about conversion rather than about a list
        // TokenValidationBasisConformanceTests already pins.
        var ephemeralKeys = new List<IDisposable>();
        try
        {
            var parameters = OidcSignatureKeys.BuildValidationParameters(OptionsFor(SymmetricJwk()), ephemeralKeys);
            parameters.ValidAlgorithms = [.. OidcSignatureKeys.AllowedSignatureAlgorithms, SecurityAlgorithms.HmacSha256];

            var result = await new JsonWebTokenHandler().ValidateTokenAsync(MacdToken(null), parameters);

            // The behavioural assertion comes first on purpose: a converter that read the k member turns
            // this row red on the token rather than on the collection, which is the finding worth having.
            Assert.False(result.IsValid);
            Assert.DoesNotContain(parameters.IssuerSigningKeys, key => key is SymmetricSecurityKey);
        }
        finally
        {
            ephemeralKeys.ForEach(key => key.Dispose());
        }
    }

    [Fact]
    public async Task TheMacdToken_Authenticates_OnceTheAdvertisedSecretIsInTheBasis()
    {
        // #1052's technique. Same bytes, the SHIPPED basis rather than one reassembled here, and the single
        // behaviour this file says is absent installed into it: the signing key a converter that read the
        // JWKS "k" member would have produced. Under it the forgery MUST authenticate. It failing would mean
        // the token is refused for something other than whose key signed it, and every row above would be
        // green for the wrong reason.
        var ephemeralKeys = new List<IDisposable>();
        try
        {
            var parameters = OidcSignatureKeys.BuildValidationParameters(OptionsFor(SymmetricJwk()), ephemeralKeys);
            parameters.ValidAlgorithms = [.. OidcSignatureKeys.AllowedSignatureAlgorithms, SecurityAlgorithms.HmacSha256];
            parameters.IssuerSigningKeys = [new SymmetricSecurityKey(_secret) { KeyId = SymmetricKeyId }];

            var result = await new JsonWebTokenHandler().ValidateTokenAsync(MacdToken(null), parameters);

            Assert.True(result.IsValid, result.Exception?.Message);
        }
        finally
        {
            ephemeralKeys.ForEach(key => key.Dispose());
        }
    }

    [Fact]
    public async Task TheAdvertisedAsymmetricKeyBesideIt_StillValidates()
    {
        // The availability floor, end to end rather than at the converter: a provider that advertises a
        // secret alongside its real signing key keeps working. Without this row a basis that refused every
        // token from such a JWKS would satisfy each rejection above.
        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = ClientId,
            IssuedAt = _now - TimeSpan.FromMinutes(1),
            NotBefore = _now - TimeSpan.FromMinutes(1),
            Expires = _now + TimeSpan.FromMinutes(5),
            Claims = new Dictionary<string, object> { ["sub"] = "user-1" },
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(_rsa) { KeyId = RsaKeyId }, SecurityAlgorithms.RsaSha256),
        });

        var result = await _idTokenValidator.ValidateAsync(
            token, OptionsFor(SymmetricJwk() + "," + RsaJwk()), TestContext.Current.CancellationToken);

        Assert.False(result.IsError, result.Error);
        Assert.Equal("RS256", result.SignatureAlgorithm);
    }

    // --- helpers ---

    private static Dictionary<string, object> LogoutClaims() => new()
    {
        ["sub"] = "user-1",
        ["jti"] = Guid.NewGuid().ToString("N"),
        ["events"] = new Dictionary<string, object>
        {
            ["http://schemas.openid.net/event/backchannel-logout"] = new Dictionary<string, object>(),
        },
    };

    private static Duende.IdentityModel.Jwk.JsonWebKeySet KeySet(string keys) =>
        new("{\"keys\":[" + keys + "]}");

    // A published HMAC key, exactly as RFC 7517 6.1 spells one: kty oct, the secret in k, marked for
    // signature use so nothing about the entry disqualifies it other than being symmetric.
    private string SymmetricJwk() =>
        "{\"kty\":\"oct\",\"use\":\"sig\",\"alg\":\"HS256\",\"kid\":\"" + SymmetricKeyId + "\","
        + "\"k\":\"" + Base64UrlEncoder.Encode(_secret) + "\"}";

    private string RsaJwk()
    {
        var p = _rsa.ExportParameters(false);
        return "{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"" + RsaKeyId + "\",\"alg\":\"RS256\","
            + "\"n\":\"" + Base64UrlEncoder.Encode(p.Modulus) + "\",\"e\":\"" + Base64UrlEncoder.Encode(p.Exponent) + "\"}";
    }

    // The forgery: a well-formed token for this issuer and audience, MAC'd with the advertised secret and
    // naming the advertised kid, so everything a verifier could check about it agrees with the JWKS.
    private string MacdToken(IDictionary<string, object>? claims) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = ClientId,
            IssuedAt = _now - TimeSpan.FromMinutes(1),
            NotBefore = _now - TimeSpan.FromMinutes(1),
            Expires = _now + TimeSpan.FromMinutes(5),
            Claims = claims ?? new Dictionary<string, object> { ["sub"] = "user-1" },
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(_secret) { KeyId = SymmetricKeyId }, SecurityAlgorithms.HmacSha256),
        });

    private OidcClientOptions OptionsFor(string keys) => new()
    {
        ClientId = ClientId,
        ClockSkew = TimeSpan.FromMinutes(5),
        ProviderInformation = new ProviderInformation
        {
            IssuerName = Issuer,
            KeySet = KeySet(keys),
        },
    };
}
