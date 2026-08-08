// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Exercises <see cref="OidcLogoutTokenValidator"/> against a static JWKS (#962). Every OIDC Back-Channel
/// Logout 1.0 §2.6 rule is fail-closed and has a negative test - signature/issuer/audience/lifetime (the
/// SAME <see cref="OidcSignatureKeys"/> basis the id_token uses), the mandatory back-channel-logout event
/// member, the forbidden nonce (an id_token replayed as a logout_token), the at-least-one-of-sub/sid rule,
/// and jti one-time-use. Each rejection carries a fixed reason code and never a subject identifier.
/// </summary>
[Collection("SSOController")]
public sealed class OidcLogoutTokenValidatorTests : IDisposable
{
    private const string Issuer = "https://idp.example.test";
    private const string ClientId = "jellyfin-client";
    private const string KeyId = "test-signing-key";
    private const string LogoutEvent = "http://schemas.openid.net/event/backchannel-logout";

    private static readonly TimeSpan Skew = TimeSpan.FromMinutes(5);

    private readonly RSA _rsa = RSA.Create(2048);
    private readonly OidcLogoutTokenValidator _validator = new();
    private readonly DateTime _now = DateTime.UtcNow;

    public OidcLogoutTokenValidatorTests() => OidcLogoutTokenValidator.ResetReplaysForTests();

    public void Dispose()
    {
        _rsa.Dispose();
        OidcLogoutTokenValidator.ResetReplaysForTests();
    }

    [Fact]
    public async Task ValidLogoutToken_WithSubAndSid_Succeeds()
    {
        var token = CreateToken(claims: Claims(sub: "user-1", sid: "sess-9"));

        var result = await _validator.ValidateAsync(token, Options(), _now);

        Assert.True(result.IsValid);
        Assert.Equal("user-1", result.Subject);
        Assert.Equal("sess-9", result.SessionIndex);
        Assert.Empty(result.ReasonCode);
    }

    [Fact]
    public async Task SubOnly_Succeeds_SidNull()
    {
        var result = await _validator.ValidateAsync(CreateToken(claims: Claims(sub: "user-1")), Options(), _now);

        Assert.True(result.IsValid);
        Assert.Equal("user-1", result.Subject);
        Assert.Null(result.SessionIndex);
    }

    [Fact]
    public async Task SidOnly_Succeeds_SubNull()
    {
        var result = await _validator.ValidateAsync(CreateToken(claims: Claims(sid: "sess-9")), Options(), _now);

        Assert.True(result.IsValid);
        Assert.Null(result.Subject);
        Assert.Equal("sess-9", result.SessionIndex);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public async Task AbsentToken_IsMalformed(string? token)
    {
        // Nothing was sent - a distinct fail-closed code from a bad token that reached the JWT handler.
        var result = await _validator.ValidateAsync(token, Options(), _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.Malformed, result.ReasonCode);
    }

    [Theory]
    [InlineData("not-a-jwt")]
    [InlineData("only.two")]
    public async Task GarbageNonJwt_IsMalformed_FailClosed(string token)
    {
        // A non-empty non-JWT reaches the handler and comes back malformed - still fail-closed, and now
        // under the code whose own summary already claimed this case ("absent, unparseable, or not a JWT").
        var result = await _validator.ValidateAsync(token, Options(), _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.Malformed, result.ReasonCode);
    }

    [Fact]
    public async Task ThreeGarbageSegments_FallThroughToTheUnclassifiedCode()
    {
        // The fail-closed default, exercised rather than described. Three segments of nonsense get far
        // enough into the handler to fail somewhere this plugin has not classified, so the refusal keeps
        // the old collapsed code instead of borrowing a name that would be a guess.
        var result = await _validator.ValidateAsync("a.b.c", Options(), _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.Invalid, result.ReasonCode);
    }

    [Fact]
    public async Task WrongSigningKey_UnderATrustedKid_IsSignatureInvalid()
    {
        using var attacker = RSA.Create(2048);
        var forged = new JsonWebTokenHandler().CreateToken(Descriptor(Claims(sub: "user-1"), signingKey: attacker));

        var result = await _validator.ValidateAsync(forged, Options(), _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.SignatureInvalid, result.ReasonCode);
    }

    [Fact]
    public async Task WrongSigningKey_UnderAnUnknownKid_IsKeyNotFound()
    {
        // The neighbour of the test above, and the pair is the point: the same forgery separates into two
        // codes purely on whether the kid names a key the provider published. An operator reading the trail
        // sees "somebody signed with their own key" apart from "somebody named a key we do not have".
        using var attacker = RSA.Create(2048);
        var descriptor = Descriptor(Claims(sub: "user-1"));
        descriptor.SigningCredentials = new SigningCredentials(
            new RsaSecurityKey(attacker) { KeyId = "some-other-key" },
            SecurityAlgorithms.RsaSha256);
        var forged = new JsonWebTokenHandler().CreateToken(descriptor);

        var result = await _validator.ValidateAsync(forged, Options(), _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.KeyNotFound, result.ReasonCode);
    }

    [Fact]
    public async Task WrongIssuer_IsIssuerInvalid()
    {
        var token = CreateToken(claims: Claims(sub: "user-1"), issuer: "https://evil.example.test");

        var result = await _validator.ValidateAsync(token, Options(), _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.IssuerInvalid, result.ReasonCode);
    }

    [Fact]
    public async Task WrongAudience_IsAudienceInvalid()
    {
        var token = CreateToken(claims: Claims(sub: "user-1"), audience: "another-client");

        var result = await _validator.ValidateAsync(token, Options(), _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.AudienceInvalid, result.ReasonCode);
    }

    [Fact]
    public async Task IncoherentLifetime_IsLifetimeInvalid()
    {
        // exp BEFORE nbf. This is the shape the previous "expired" test actually built, and it is a
        // different refusal from an ordinary expiry: the handler reports the lifetime as incoherent before
        // it ever compares exp to the clock.
        var token = CreateToken(claims: Claims(sub: "user-1"), lifetime: TimeSpan.FromMinutes(-10));

        var result = await _validator.ValidateAsync(token, Options(), _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.LifetimeInvalid, result.ReasonCode);
    }

    [Fact]
    public async Task GenuinelyExpiredToken_IsExpired()
    {
        // A coherent lifetime wholly in the past, beyond the 5-minute skew: the ordinary case an operator
        // reads as a slow or retrying IdP rather than as an attack.
        var descriptor = Descriptor(Claims(sub: "user-1"));
        descriptor.IssuedAt = DateTime.UtcNow - TimeSpan.FromHours(3);
        descriptor.NotBefore = DateTime.UtcNow - TimeSpan.FromHours(3);
        descriptor.Expires = DateTime.UtcNow - TimeSpan.FromHours(1);
        var token = new JsonWebTokenHandler().CreateToken(descriptor);

        var result = await _validator.ValidateAsync(token, Options(), _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.Expired, result.ReasonCode);
    }

    [Fact]
    public async Task NotYetValidToken_IsNotYetValid()
    {
        var descriptor = Descriptor(Claims(sub: "user-1"));
        descriptor.IssuedAt = DateTime.UtcNow;
        descriptor.NotBefore = DateTime.UtcNow + TimeSpan.FromHours(2);
        descriptor.Expires = DateTime.UtcNow + TimeSpan.FromHours(3);
        var token = new JsonWebTokenHandler().CreateToken(descriptor);

        var result = await _validator.ValidateAsync(token, Options(), _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.NotYetValid, result.ReasonCode);
    }

    [Fact]
    public async Task AlgNone_IsAlgorithmNotAllowed()
    {
        var result = await _validator.ValidateAsync(UnsignedAlgNoneToken(), Options(), _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.AlgorithmNotAllowed, result.ReasonCode);
    }

    [Fact]
    public async Task AlgCaseVariant_IsAlgorithmNotAllowed()
    {
        // "rs256" is not "RS256". The allowlist holds the exact RFC 7518 names and the comparison is
        // Ordinal, so a case-folded spelling is refused rather than quietly accepted as its neighbour.
        var reheadered = WithHeaderAlgorithm("rs256", CreateToken(Claims(sub: "user-1")));

        var result = await _validator.ValidateAsync(reheadered, Options(), _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.AlgorithmNotAllowed, result.ReasonCode);
    }

    [Fact]
    public async Task AlgorithmConfusion_HS256KeyedWithTheAdvertisedPublicKey_IsAlgorithmNotAllowed()
    {
        // The classic: sign with HMAC using the provider's PUBLIC key as the secret, which anybody can
        // fetch. It is refused either way; what this pins is that the trail says so. Measured before the
        // gate existed, the handler reported it as an ordinary invalid signature, because ValidAlgorithms
        // is evaluated per key inside signature validation.
        var publicKey = _rsa.ExportSubjectPublicKeyInfo();
        var descriptor = Descriptor(Claims(sub: "user-1"));
        descriptor.SigningCredentials = new SigningCredentials(
            new SymmetricSecurityKey(publicKey) { KeyId = KeyId },
            SecurityAlgorithms.HmacSha256);
        var forged = new JsonWebTokenHandler().CreateToken(descriptor);

        var result = await _validator.ValidateAsync(forged, Options(), _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.AlgorithmNotAllowed, result.ReasonCode);
    }

    [Fact]
    public async Task StrippedSignature_IsSignatureInvalid()
    {
        // alg stays RS256, so the algorithm gate passes it through and the handler owns the refusal. It is
        // not separable from a wrong-key signature here, and the code says signature rather than pretending
        // to a distinction the library does not make.
        var token = CreateToken(Claims(sub: "user-1"));
        var stripped = token[..(token.LastIndexOf('.') + 1)];

        var result = await _validator.ValidateAsync(stripped, Options(), _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.SignatureInvalid, result.ReasonCode);
    }

    [Fact]
    public async Task EveryReasonCodeIsAFixedConstant_AndNoneCarriesTokenText()
    {
        // The constraint the whole split is bounded by: more codes must not mean more information about
        // WHO the token named. Every code is compared against the declared constants, so a code
        // interpolated from a claim would have to be added to this list to pass, which is the moment a
        // reviewer sees it.
        var declared = typeof(OidcLogoutTokenValidator.RejectReason)
            .GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.FlattenHierarchy)
            .Where(f => f.IsLiteral && f.FieldType == typeof(string))
            .Select(f => (string)f.GetRawConstantValue()!)
            .ToList();

        Assert.NotEmpty(declared);
        Assert.Equal(declared.Count, declared.Distinct(StringComparer.Ordinal).Count());

        using var attacker = RSA.Create(2048);
        string[] subjects = ["user-secret-1", "user-secret-2"];
        foreach (var subject in subjects)
        {
            var forged = new JsonWebTokenHandler().CreateToken(Descriptor(Claims(sub: subject), signingKey: attacker));
            var result = await _validator.ValidateAsync(forged, Options(), _now);

            Assert.Contains(result.ReasonCode, declared);
            Assert.DoesNotContain(subject, result.ReasonCode, StringComparison.Ordinal);
        }
    }

    private static string Base64Url(string json) => Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(json));

    private static string UnsignedAlgNoneToken()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var payload = "{\"iss\":\"" + Issuer + "\",\"aud\":\"" + ClientId + "\",\"sub\":\"user-1\",\"jti\":\""
            + Guid.NewGuid() + "\",\"iat\":" + now + ",\"nbf\":" + (now - 60) + ",\"exp\":" + (now + 300)
            + ",\"events\":{\"" + LogoutEvent + "\":{}}}";
        return Header("none") + "." + Base64Url(payload) + ".";
    }

    private static string WithHeaderAlgorithm(string algorithm, string token)
    {
        var parts = token.Split('.');
        return Header(algorithm) + "." + parts[1] + "." + parts[2];
    }

    private static string Header(string algorithm) =>
        Base64Url("{\"alg\":\"" + algorithm + "\",\"typ\":\"JWT\",\"kid\":\"" + KeyId + "\"}");

    [Fact]
    public async Task NoEventsClaim_IsNotALogoutToken()
    {
        var token = CreateToken(claims: new Dictionary<string, object> { ["sub"] = "user-1", ["jti"] = Guid.NewGuid().ToString() });

        var result = await _validator.ValidateAsync(token, Options(), _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.NotALogoutToken, result.ReasonCode);
    }

    [Fact]
    public async Task EventsWithoutTheBackChannelMember_IsNotALogoutToken()
    {
        // A valid, signed token whose events claim names a DIFFERENT event - not a back-channel logout.
        var claims = Claims(sub: "user-1");
        claims["events"] = new Dictionary<string, object> { ["http://schemas.openid.net/event/some-other"] = new Dictionary<string, object>() };
        var token = CreateToken(claims: claims);

        var result = await _validator.ValidateAsync(token, Options(), _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.NotALogoutToken, result.ReasonCode);
    }

    [Fact]
    public async Task TokenCarryingNonce_IsRejected_IdTokenReplayedAsLogout()
    {
        // §2.4: a logout_token MUST NOT carry a nonce - this is what refuses an id_token replayed here.
        var claims = Claims(sub: "user-1");
        claims["nonce"] = "abc123";
        var token = CreateToken(claims: claims);

        var result = await _validator.ValidateAsync(token, Options(), _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.ProhibitedNonce, result.ReasonCode);
    }

    [Fact]
    public async Task NeitherSubNorSid_IsRejected()
    {
        var result = await _validator.ValidateAsync(CreateToken(claims: Claims()), Options(), _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.NoSubjectOrSid, result.ReasonCode);
    }

    [Fact]
    public async Task ReplayedJti_IsRejected_OneTimeUse()
    {
        var token = CreateToken(claims: Claims(sub: "user-1", jti: "fixed-jti"));

        var first = await _validator.ValidateAsync(token, Options(), _now);
        var second = await _validator.ValidateAsync(token, Options(), _now);

        Assert.True(first.IsValid);
        Assert.False(second.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.Replay, second.ReasonCode);
    }

    [Fact]
    public async Task NoJti_ByteIdenticalResend_IsCaughtAsReplay()
    {
        // A token with no jti still gets one-time-use via its signature - a byte-identical resend collides.
        var token = CreateToken(claims: Claims(sub: "user-1"));

        Assert.True((await _validator.ValidateAsync(token, Options(), _now)).IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.Replay, (await _validator.ValidateAsync(token, Options(), _now)).ReasonCode);
    }

    [Fact]
    public async Task NoSubjectIdentifierEverAppearsInAReasonCode()
    {
        // Fixed codes only - a rejection is never a subject oracle (T-I1).
        var token = CreateToken(claims: Claims(sub: "secret-subject", sid: "secret-session"));
        // Force a replay rejection carrying no subject text.
        await _validator.ValidateAsync(token, Options(), _now);
        var replay = await _validator.ValidateAsync(token, Options(), _now);

        Assert.DoesNotContain("secret-subject", replay.ReasonCode, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-session", replay.ReasonCode, StringComparison.Ordinal);
    }

    [Fact]
    public async Task NoExpClaim_StillSucceeds()
    {
        // #962 review fix: OIDC Back-Channel Logout §2.4 does NOT require exp; a spec-compliant exp-less
        // IdP must NOT be silently no-op'd. Replay is bounded by jti one-time-use, not exp.
        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = ClientId,
            IssuedAt = DateTime.UtcNow - TimeSpan.FromMinutes(1),
            Claims = Claims(sub: "user-1"),
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(_rsa) { KeyId = KeyId }, SecurityAlgorithms.RsaSha256),
        });

        var result = await _validator.ValidateAsync(token, Options(), _now);

        Assert.True(result.IsValid);
        Assert.Equal("user-1", result.Subject);
    }

    [Fact]
    public async Task AzpMismatch_IsAuthorizedPartyMismatch()
    {
        // Parity with the id_token validator (OIDC Core 3.1.3.7 rule 5): an azp naming a different party is
        // refused even though this client is the audience.
        var claims = Claims(sub: "user-1");
        claims["azp"] = "another-client";
        var result = await _validator.ValidateAsync(CreateToken(claims: claims), Options(), _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.AuthorizedPartyMismatch, result.ReasonCode);
    }

    [Fact]
    public async Task MultipleAudiencesWithoutAzp_IsItsOwnCode()
    {
        // Rules 3-4: a multi-audience token MUST carry azp; one minted for a co-listed different party is refused.
        var claims = Claims(sub: "user-1");
        claims["aud"] = new[] { ClientId, "another-client" }; // multi-audience, no azp
        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            IssuedAt = DateTime.UtcNow - TimeSpan.FromMinutes(1),
            Expires = DateTime.UtcNow + TimeSpan.FromMinutes(5),
            Claims = claims,
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(_rsa) { KeyId = KeyId }, SecurityAlgorithms.RsaSha256),
        });

        var result = await _validator.ValidateAsync(token, Options(), _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.MultipleAudiencesWithoutAuthorizedParty, result.ReasonCode);
    }

    private static Dictionary<string, object> Claims(string? sub = null, string? sid = null, string? jti = null)
    {
        var claims = new Dictionary<string, object>
        {
            ["events"] = new Dictionary<string, object> { [LogoutEvent] = new Dictionary<string, object>() },
        };
        if (sub != null)
        {
            claims["sub"] = sub;
        }

        if (sid != null)
        {
            claims["sid"] = sid;
        }

        claims["jti"] = jti ?? Guid.NewGuid().ToString();
        return claims;
    }

    // What the endpoint hands the validator: the provider's options, from which the validator derives its
    // own basis (#1176). The requireExpiration:false posture (OIDC Back-Channel Logout §2.4 does not mandate
    // exp) is the validator's own and no longer something a caller - or a test - can choose, which is the
    // point of the change: these tests cannot validate under a posture the endpoint does not use.
    private OidcClientOptions Options()
    {
        var p = _rsa.ExportParameters(false);
        var jwks = $$"""
            {"keys":[{"kty":"RSA","use":"sig","kid":"{{KeyId}}",
              "n":"{{Base64UrlEncoder.Encode(p.Modulus)}}","e":"{{Base64UrlEncoder.Encode(p.Exponent)}}"}]}
            """;
        return new OidcClientOptions
        {
            ClientId = ClientId,
            ClockSkew = Skew,
            ProviderInformation = new ProviderInformation
            {
                IssuerName = Issuer,
                KeySet = new Duende.IdentityModel.Jwk.JsonWebKeySet(jwks),
            },
        };
    }

    private string CreateToken(IDictionary<string, object> claims, string issuer = Issuer, string audience = ClientId, TimeSpan? lifetime = null)
        => new JsonWebTokenHandler().CreateToken(Descriptor(claims, issuer, audience, lifetime));

    private SecurityTokenDescriptor Descriptor(IDictionary<string, object> claims, string issuer = Issuer, string audience = ClientId, TimeSpan? lifetime = null, RSA? signingKey = null)
    {
        var now = DateTime.UtcNow;
        return new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            IssuedAt = now - TimeSpan.FromMinutes(1),
            NotBefore = now - TimeSpan.FromMinutes(1),
            Expires = now + (lifetime ?? TimeSpan.FromMinutes(5)),
            Claims = claims,
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(signingKey ?? _rsa) { KeyId = KeyId }, SecurityAlgorithms.RsaSha256),
        };
    }
}
