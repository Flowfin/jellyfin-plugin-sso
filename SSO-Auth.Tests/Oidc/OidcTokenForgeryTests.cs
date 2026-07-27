// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The JWT forgery battery (#1004): the token shapes an attacker actually submits, each asserted to be
/// rejected on BOTH paths that verify a provider JWT — the login id_token
/// (<see cref="OidcIdTokenValidator"/>) and the anonymous back-channel <c>logout_token</c>
/// (<see cref="OidcLogoutTokenValidator"/>), which share the one
/// <see cref="OidcSignatureKeys"/> basis that <c>OidcTokenValidation_UsesTheSingleHardenedParameterBuilder</c>
/// pins as the only one.
///
/// These tokens are assembled BY HAND rather than through <see cref="JsonWebTokenHandler"/>. That is the
/// point of the file: the handler is a well-behaved issuer and will not emit an <c>alg</c> the JWS spec
/// forbids, a case-mangled header, or a stripped signature, so a test that mints its "forgeries" through it
/// proves only that the library declines to attack itself. Composing the three base64url segments directly
/// is what puts the attacker's actual bytes on the wire.
///
/// Every test asserts the same two things — the result is an error, and NO principal or subject identity
/// comes back — because "rejected" and "rejected without leaking an identity the caller might act on" are
/// different properties, and only the second is worth having.
/// </summary>
public sealed class OidcTokenForgeryTests : IDisposable
{
    private const string Issuer = "https://idp.example.test";
    private const string ClientId = "jellyfin-client";
    private const string KeyId = "test-signing-key";
    private const string LogoutEvent = "http://schemas.openid.net/event/backchannel-logout";

    private static readonly TimeSpan Skew = TimeSpan.FromMinutes(5);

    private readonly RSA _rsa = RSA.Create(2048);
    private readonly OidcIdTokenValidator _idTokenValidator = new();
    private readonly OidcLogoutTokenValidator _logoutTokenValidator = new();

    public OidcTokenForgeryTests() => OidcLogoutTokenValidator.ResetReplaysForTests();

    public void Dispose()
    {
        _rsa.Dispose();
        OidcLogoutTokenValidator.ResetReplaysForTests();
    }

    [Fact]
    [Trait("Spec", "RFC 7518")]
    public async Task IdToken_AlgNoneWithEmptySignature_IsRejected()
    {
        // The oldest forgery in the catalogue: claims that are byte-for-byte acceptable (right issuer,
        // audience and lifetime), a header declaring the token needs no signature, and an empty third
        // segment. It is refused because the allowlist is asymmetric-only and RequireSignedTokens is set —
        // the accepted algorithms are decided by us, never read off the header the attacker wrote.
        var forged = Jws("{\"alg\":\"none\",\"typ\":\"JWT\"}", IdTokenPayload(), signature: string.Empty);

        await AssertIdTokenRejected(forged);
    }

    [Theory]
    [Trait("Spec", "RFC 7518")]
    [InlineData("None")]
    [InlineData("NONE")]
    [InlineData("nOnE")]
    [InlineData("nonE")]
    public async Task IdToken_AlgNoneCaseVariants_AreRejected(string alg)
    {
        // The bypass for a validator that compares the header against a denylist ordinally: JWS `alg` values
        // are case-sensitive, so "None" is not the registered "none" and slips past a check spelled that way.
        // An ALLOWLIST is immune by construction — every one of these is simply not in it — and that immunity
        // is what this theory pins, since it is the reason the code carries no `alg == "none"` comparison at
        // all and a reviewer might otherwise "helpfully" add one.
        var forged = Jws($"{{\"alg\":\"{alg}\",\"typ\":\"JWT\"}}", IdTokenPayload(), signature: string.Empty);

        await AssertIdTokenRejected(forged);
    }

    [Fact]
    [Trait("Spec", "RFC 7518")]
    public async Task IdToken_Rs256PublicKeyReplayedAsHs256Mac_IsRejected()
    {
        // Algorithm confusion, the forgery that makes the asymmetric-only allowlist load-bearing. The RSA
        // public key is published in the JWKS, so the attacker HAS it; declaring HS256 invites the verifier to
        // treat that public material as an HMAC secret, which the attacker can also compute over. The token
        // then verifies against the provider's own advertised key. Both spellings of the key material are
        // tried — the SPKI DER bytes and the modulus, the two an implementation would plausibly hand the HMAC
        // — because a defence that stops one and not the other is not a defence.
        var publicKey = _rsa.ExportSubjectPublicKeyInfo();
        var modulus = _rsa.ExportParameters(false).Modulus!;

        await AssertIdTokenRejected(Hs256(IdTokenPayload(), publicKey));
        await AssertIdTokenRejected(Hs256(IdTokenPayload(), modulus));
    }

    [Fact]
    [Trait("Spec", "OIDC-Core-1.0")]
    public async Task IdToken_SignatureStripped_IsRejected()
    {
        // A genuine, correctly signed token whose signature segment is deleted in transit. The header still
        // says RS256, so an allowlist check alone passes — what refuses it is that the signature must actually
        // verify. Covers the gap between "the algorithm is acceptable" and "the token is authentic".
        var signed = new JsonWebTokenHandler().CreateToken(IdTokenDescriptor());
        var parts = signed.Split('.');
        var stripped = parts[0] + "." + parts[1] + ".";

        await AssertIdTokenRejected(stripped);
    }

    [Fact]
    [Trait("Spec", "RFC 7515")]
    public async Task IdToken_ForgedSignature_ClaimingTheTrustedKid_IsRejected()
    {
        // The header's `kid` names the key the JWKS advertises, but the token is signed by the attacker's own
        // RSA key. A `kid` is an unauthenticated routing hint written by whoever composed the token; it
        // selects which key verifies, and can never itself vouch for a signature. The rejection also maps to
        // the "invalid_signature" contract, which is what makes OidcClient refresh the JWKS and retry once —
        // so this asserts a forgery lands on the same benign path a genuine key rotation does, rather than
        // being distinguishable from it.
        using var attacker = RSA.Create(2048);
        var forged = new JsonWebTokenHandler().CreateToken(IdTokenDescriptor(signingKey: attacker));

        var result = await AssertIdTokenRejected(forged);
        Assert.Equal("invalid_signature", result.Error);
    }

    [Theory]
    [Trait("Spec", "RFC 7515")]
    [InlineData("../../../etc/passwd")]
    [InlineData("..\\..\\windows\\win.ini")]
    [InlineData("/dev/null")]
    [InlineData("\\\\server\\share")]
    [InlineData("%2e%2e%2f%2e%2e%2f")]
    [InlineData("key\0injected")]
    [InlineData("' OR '1'='1")]
    [InlineData("\"><script>alert(1)</script>")]
    [InlineData("{\"jku\":\"https://attacker.example/keys\"}")]
    public async Task IdToken_HostileKidValues_NeverAuthenticate_AndNeverThrow(string kid)
    {
        // The `kid` injection class: path traversal, a null byte, quote/SQL and markup metacharacters, and a
        // nested-JSON smuggling attempt. Each is carried on a token the attacker signed with their own key, so
        // the ONLY thing that could let it in is the header value being treated as something other than an
        // opaque lookup hint.
        //
        // Two properties, not one. Rejection is the obvious half. The other half is that it must be a clean
        // error rather than an exception: the id_token validator runs inside the OIDC callback, where a throw
        // surfaces as a 500 — an attacker-triggerable oracle that distinguishes hostile input from an ordinary
        // bad signature, and a denial-of-service lever on the login path. Awaiting the call outside any
        // assertion is what proves it: an exception fails the test on its own.
        using var attacker = RSA.Create(2048);
        var descriptor = IdTokenDescriptor(signingKey: attacker);
        descriptor.SigningCredentials = new SigningCredentials(
            new RsaSecurityKey(attacker) { KeyId = kid }, SecurityAlgorithms.RsaSha256);
        var forged = new JsonWebTokenHandler().CreateToken(descriptor);

        await AssertIdTokenRejected(forged);
    }

    [Theory]
    [Trait("Spec", "OIDC-Backchannel-Logout-1.0")]
    [InlineData(ForgeryKind.AlgNone)]
    [InlineData(ForgeryKind.AlgNoneMixedCase)]
    [InlineData(ForgeryKind.Hs256WithPublicKey)]
    [InlineData(ForgeryKind.SignatureStripped)]
    [InlineData(ForgeryKind.ForeignKeyWithTrustedKid)]
    [InlineData(ForgeryKind.HostileKid)]
    public async Task LogoutToken_SameForgeries_AreRejected(ForgeryKind kind)
    {
        // The back-channel endpoint is ANONYMOUS — the signature is the only thing authenticating the caller,
        // and a token accepted here revokes a user's sessions. It shares the id_token's validation basis, and
        // the whole value of sharing is that the two cannot drift; a shared builder proves that only while
        // BOTH paths are actually driven through the same attacks. So every forgery above is re-run here
        // rather than reasoned about.
        //
        // The assertion pins the fixed reason code as well as the rejection: these codes are written to the
        // audit trail and are deliberately request-independent, so a forgery must not be reportable in a way
        // that distinguishes it from any other invalid token (no subject-identifier oracle).
        var forged = LogoutForgery(kind);

        var result = await _logoutTokenValidator.ValidateAsync(forged, Params(), Skew, DateTime.UtcNow);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.Invalid, result.ReasonCode);
        Assert.Null(result.Subject);
        Assert.Null(result.SessionIndex);
    }

    [Fact]
    [Trait("Spec", "OIDC-Backchannel-Logout-1.0")]
    public async Task LogoutToken_GenuinelySigned_Succeeds_ProvingTheForgeryBatteryIsNotVacuous()
    {
        // The positive control the battery needs to mean anything. Every test above asserts a rejection, and a
        // validation path that rejected EVERYTHING — a broken JWKS, a wrong audience constant in the fixture —
        // would pass all of them while proving nothing about forgeries. One genuinely signed token, built by
        // the same helpers with the same parameters, has to be accepted for the rejections to carry weight.
        var genuine = new JsonWebTokenHandler().CreateToken(LogoutTokenDescriptor());

        var result = await _logoutTokenValidator.ValidateAsync(genuine, Params(), Skew, DateTime.UtcNow);

        Assert.True(result.IsValid);
        Assert.Equal("user-1", result.Subject);
    }

    [Fact]
    [Trait("Spec", "OIDC-Core-1.0")]
    public async Task IdToken_GenuinelySigned_Succeeds_ProvingTheForgeryBatteryIsNotVacuous()
    {
        // The same positive control for the login path.
        var genuine = new JsonWebTokenHandler().CreateToken(IdTokenDescriptor());

        var result = await _idTokenValidator.ValidateAsync(genuine, Options(), TestContext.Current.CancellationToken);

        Assert.False(result.IsError, result.Error);
        Assert.Equal("RS256", result.SignatureAlgorithm);
    }

    /// <summary>The forgery shapes replayed against the back-channel logout path.</summary>
    public enum ForgeryKind
    {
        /// <summary>A header declaring <c>alg: none</c> with an empty signature segment.</summary>
        AlgNone,

        /// <summary>The same, spelled <c>None</c> — the case bypass for an ordinal denylist.</summary>
        AlgNoneMixedCase,

        /// <summary>An HS256 MAC keyed with the advertised RSA public key (algorithm confusion).</summary>
        Hs256WithPublicKey,

        /// <summary>A genuinely signed token with its signature segment removed.</summary>
        SignatureStripped,

        /// <summary>A token signed by a foreign key whose header claims the trusted <c>kid</c>.</summary>
        ForeignKeyWithTrustedKid,

        /// <summary>A foreign-key signature carrying a path-traversal <c>kid</c>.</summary>
        HostileKid,
    }

    // --- helpers ---

    // Drives the id_token validator and asserts the two properties every forgery must have: an error, and no
    // principal. A validator that "rejected" while still handing back a ClaimsPrincipal would leave the
    // caller one missed if-check away from logging the attacker in.
    private async Task<Duende.IdentityModel.OidcClient.Results.IdentityTokenValidationResult> AssertIdTokenRejected(string token)
    {
        var result = await _idTokenValidator.ValidateAsync(token, Options(), TestContext.Current.CancellationToken);

        Assert.True(result.IsError, "The forged token was accepted.");
        Assert.Null(result.User);
        return result;
    }

    // Builds the requested forgery over a valid logout_token payload.
    private string LogoutForgery(ForgeryKind kind)
    {
        switch (kind)
        {
            case ForgeryKind.AlgNone:
                return Jws("{\"alg\":\"none\",\"typ\":\"JWT\"}", LogoutTokenPayload(), signature: string.Empty);
            case ForgeryKind.AlgNoneMixedCase:
                return Jws("{\"alg\":\"None\",\"typ\":\"JWT\"}", LogoutTokenPayload(), signature: string.Empty);
            case ForgeryKind.Hs256WithPublicKey:
                return Hs256(LogoutTokenPayload(), _rsa.ExportSubjectPublicKeyInfo());
            case ForgeryKind.SignatureStripped:
                var signed = new JsonWebTokenHandler().CreateToken(LogoutTokenDescriptor()).Split('.');
                return signed[0] + "." + signed[1] + ".";
            default:
                using (var attacker = RSA.Create(2048))
                {
                    var descriptor = LogoutTokenDescriptor();
                    descriptor.SigningCredentials = new SigningCredentials(
                        new RsaSecurityKey(attacker) { KeyId = kind == ForgeryKind.HostileKid ? "../../../etc/passwd" : KeyId },
                        SecurityAlgorithms.RsaSha256);
                    return new JsonWebTokenHandler().CreateToken(descriptor);
                }
        }
    }

    // A compact JWS from its three parts, with the header and payload base64url-encoded here rather than by a
    // token handler — the handler would refuse to emit most of what this file needs to submit.
    private static string Jws(string headerJson, string payloadJson, string signature) =>
        Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(headerJson))
        + "." + Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payloadJson))
        + "." + signature;

    // An HS256-signed token over the given payload, MAC'd with the supplied key material — the algorithm-
    // confusion forgery, where that material is the provider's PUBLIC key.
    private static string Hs256(string payloadJson, byte[] key)
    {
        var signingInput = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes("{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"" + KeyId + "\"}"))
            + "." + Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payloadJson));
        using var hmac = new HMACSHA256(key);
        var mac = hmac.ComputeHash(Encoding.UTF8.GetBytes(signingInput));
        return signingInput + "." + Base64UrlEncoder.Encode(mac);
    }

    // An id_token payload whose every claim is acceptable, so the signature is the only thing left to reject
    // it on — otherwise a test could pass because of an expired token rather than the forgery under test.
    private static string IdTokenPayload()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return "{\"iss\":\"" + Issuer + "\",\"aud\":\"" + ClientId + "\",\"sub\":\"user-1\","
            + "\"iat\":" + (now - 60) + ",\"nbf\":" + (now - 60) + ",\"exp\":" + (now + 300) + "}";
    }

    // The logout_token equivalent, carrying the mandatory events member and a sub, so §2.4's own rules cannot
    // be what rejects it.
    private static string LogoutTokenPayload()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return "{\"iss\":\"" + Issuer + "\",\"aud\":\"" + ClientId + "\",\"sub\":\"user-1\","
            + "\"jti\":\"" + Guid.NewGuid() + "\",\"iat\":" + (now - 60) + ",\"exp\":" + (now + 300) + ","
            + "\"events\":{\"" + LogoutEvent + "\":{}}}";
    }

    private SecurityTokenDescriptor IdTokenDescriptor(RSA? signingKey = null)
    {
        var now = DateTime.UtcNow;
        return new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = ClientId,
            IssuedAt = now - TimeSpan.FromMinutes(1),
            NotBefore = now - TimeSpan.FromMinutes(1),
            Expires = now + TimeSpan.FromMinutes(5),
            Claims = new Dictionary<string, object> { ["sub"] = "user-1" },
            SigningCredentials = new SigningCredentials(
                new RsaSecurityKey(signingKey ?? _rsa) { KeyId = KeyId }, SecurityAlgorithms.RsaSha256),
        };
    }

    private SecurityTokenDescriptor LogoutTokenDescriptor()
    {
        var now = DateTime.UtcNow;
        return new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = ClientId,
            IssuedAt = now - TimeSpan.FromMinutes(1),
            NotBefore = now - TimeSpan.FromMinutes(1),
            Expires = now + TimeSpan.FromMinutes(5),
            Claims = new Dictionary<string, object>
            {
                ["sub"] = "user-1",
                ["jti"] = Guid.NewGuid().ToString(),
                ["events"] = new Dictionary<string, object> { [LogoutEvent] = new Dictionary<string, object>() },
            },
            SigningCredentials = new SigningCredentials(
                new RsaSecurityKey(_rsa) { KeyId = KeyId }, SecurityAlgorithms.RsaSha256),
        };
    }

    // The client options carrying this fixture's JWKS — the same shape the login path builds from discovery.
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
            ProviderInformation = new ProviderInformation
            {
                IssuerName = Issuer,
                KeySet = new Duende.IdentityModel.Jwk.JsonWebKeySet(jwks),
            },
        };
    }

    // The logout path's parameters, built through the SAME shared basis with the back-channel's
    // requireExpiration:false posture, so these tests validate exactly what the endpoint validates.
    private TokenValidationParameters Params() =>
        OidcSignatureKeys.BuildValidationParameters(Options(), new List<IDisposable>(), requireExpiration: false);
}
