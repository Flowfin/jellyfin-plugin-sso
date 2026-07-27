// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
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
/// The JWT forgery battery (#1004): token shapes an attacker can compose against the two paths that verify a
/// provider JWT — the login id_token (<see cref="OidcIdTokenValidator"/>) and the anonymous back-channel
/// <c>logout_token</c> (<see cref="OidcLogoutTokenValidator"/>), which share the one
/// <see cref="OidcSignatureKeys"/> basis that <c>OidcTokenValidation_UsesTheSingleHardenedParameterBuilder</c>
/// pins as the only one.
///
/// Every SHAPE the login path submits has a <see cref="ForgeryKind"/> counterpart on the logout path, which is
/// the parity that matters: the back-channel endpoint is anonymous, so a shape refused only on the login side
/// would be refused by nothing where it costs most. The parity is per shape, not per row — the login side
/// additionally fans each shape out over its spellings (four <c>alg</c> casings, two key encodings, nine
/// hostile <c>kid</c> values), and those fan-outs are not repeated here, because what they vary is how the
/// header is written and both paths hand the same header to the same handler through the same basis.
///
/// Tokens are assembled BY HAND rather than through <see cref="JsonWebTokenHandler"/> wherever the shape
/// requires it: the handler is a well-behaved issuer and will not emit an <c>alg</c> the JWS spec forbids, a
/// case-mangled header, or a stripped signature, so a "forgery" minted through it proves only that the
/// library declines to attack itself.
///
/// What each rejection is ATTRIBUTABLE to is not uniform, and the file does not pretend otherwise. Most of
/// these shapes are refused by the key/signature layer, and would still be refused with the algorithm
/// allowlist deleted — they establish that the posture holds, not which term holds it. The tests that isolate
/// a single term carry their own in-test control, which fails if that term stops deciding:
/// <see cref="AlgorithmAllowlist_RefusesAnHs256TokenTheKeySetWouldOtherwiseVerify"/> for the allowlist and
/// <see cref="HostileKidValues_DecideNothing_AndNeverThrow"/> for <c>kid</c> handling.
///
/// Every rejection asserts two things — an error, and NO principal or subject identity coming back —
/// because "rejected" and "rejected without leaking an identity the caller might act on" are different
/// properties and only the second is worth having.
/// </summary>
[Collection("SSOController")]
public sealed class OidcTokenForgeryTests : IDisposable
{
    private const string Issuer = "https://idp.example.test";
    private const string ClientId = "jellyfin-client";
    private const string KeyId = "test-signing-key";
    private const string SharedSecretKeyId = "advertised-shared-secret";
    private const string LogoutEvent = "http://schemas.openid.net/event/backchannel-logout";

    private static readonly TimeSpan Skew = TimeSpan.FromMinutes(5);

    private readonly RSA _rsa = RSA.Create(2048);

    // The disposal contract BuildValidationParameters imposes on its caller, honoured here exactly as both
    // production callers honour it: an EC key advertised in a JWKS yields a native ECDsa handle that is the
    // caller's to release.
    private readonly List<IDisposable> _ephemeralKeys = new List<IDisposable>();
    private readonly OidcIdTokenValidator _idTokenValidator = new();
    private readonly OidcLogoutTokenValidator _logoutTokenValidator = new();

    public OidcTokenForgeryTests() => OidcLogoutTokenValidator.ResetReplaysForTests();

    public void Dispose()
    {
        foreach (var key in _ephemeralKeys)
        {
            key.Dispose();
        }

        _rsa.Dispose();
        OidcLogoutTokenValidator.ResetReplaysForTests();
    }

    [Fact]
    [Trait("Spec", "RFC 7518")]
    public async Task IdToken_AlgNoneWithEmptySignature_IsRejected()
    {
        // The oldest forgery in the catalogue: claims that are byte-for-byte acceptable (right issuer,
        // audience and lifetime), a header declaring the token needs no signature, and an empty third
        // segment. RequireSignedTokens is what refuses it — measured, not assumed: with ValidAlgorithms
        // removed it still rejects, so this row pins the fail-closed outcome and not the allowlist.
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
        // The plugin carries no `alg == "none"` comparison at all, and this theory is why a reviewer must not
        // "helpfully" add one — an allowlist is immune to the whole family by construction.
        var forged = Jws($"{{\"alg\":\"{alg}\",\"typ\":\"JWT\"}}", IdTokenPayload(), signature: string.Empty);

        await AssertIdTokenRejected(forged);
    }

    [Fact]
    [Trait("Spec", "RFC 7518")]
    public async Task IdToken_Rs256PublicKeyReplayedAsHs256Mac_IsRejected()
    {
        // Algorithm confusion as an attacker can actually mount it here: the RSA public key is published in
        // the JWKS, so the attacker HAS it, and declaring HS256 invites a verifier to treat that public
        // material as an HMAC secret. Both spellings are tried — SPKI DER bytes and the bare modulus — since
        // a defence that stops one and not the other is not a defence. On this stack the refusal comes from
        // key typing (an RsaSecurityKey is never handed to an HMAC), NOT from the allowlist; the allowlist's
        // own load-bearing case is the test below.
        var publicKey = _rsa.ExportSubjectPublicKeyInfo();
        var modulus = _rsa.ExportParameters(false).Modulus!;

        await AssertIdTokenRejected(Hs256(IdTokenPayload(), publicKey, KeyId));
        await AssertIdTokenRejected(Hs256(IdTokenPayload(), modulus, KeyId));
    }

    [Fact]
    [Trait("Spec", "RFC 7518")]
    public async Task AlgorithmAllowlist_RefusesAnHs256TokenTheKeySetWouldOtherwiseVerify()
    {
        // The shape where ValidAlgorithms is the DECIDING term, which none of the rows above is: a token
        // whose signature the advertised key set can verify, refused only because HS256 is not on the list.
        // The symmetric key is placed into the key set by hand because today's JWK conversion never yields
        // one — that is a separate property, pinned by SymmetricJwksKey_IsNeverConvertedToASigningKey — and
        // the allowlist is the second layer that has to hold when the first fails, which is one "our IdP
        // wants HS256" commit away. A secret advertised in a JWKS is held by every party that reads it, so
        // anyone could mint this token.
        var secret = RandomNumberGenerator.GetBytes(32);
        var forged = Hs256(IdTokenPayload(), secret, SharedSecretKeyId);
        var keys = new List<SecurityKey>(Params().IssuerSigningKeys)
        {
            new SymmetricSecurityKey(secret) { KeyId = SharedSecretKeyId },
        };

        var hardened = Params();
        hardened.IssuerSigningKeys = keys;

        // The control that makes the assertion load-bearing rather than one more rejection of unknown cause:
        // the SAME token against the SAME keys with ONLY ValidAlgorithms removed is ACCEPTED. That pins the
        // refusal to that one field — deleting it from OidcSignatureKeys turns this test red, which is
        // exactly what the rest of the battery does not do.
        var withoutAllowlist = Params();
        withoutAllowlist.IssuerSigningKeys = keys;
        withoutAllowlist.ValidAlgorithms = null;

        var refused = await new JsonWebTokenHandler().ValidateTokenAsync(forged, hardened);
        var accepted = await new JsonWebTokenHandler().ValidateTokenAsync(forged, withoutAllowlist);

        Assert.False(refused.IsValid, "The HS256 forgery was accepted under the hardened basis.");
        Assert.True(
            accepted.IsValid,
            "The control did not verify, so the forgery is being refused by something other than the allowlist and this test proves nothing about it.");
    }

    [Fact]
    [Trait("Spec", "OIDC-Core-1.0")]
    public async Task IdToken_SignatureStripped_IsRejected()
    {
        // A genuine, correctly signed token whose signature segment is deleted in transit. The header still
        // says RS256, so an allowlist check alone passes — what refuses it is that the signature must
        // actually verify. Covers the gap between "the algorithm is acceptable" and "the token is authentic".
        var parts = new JsonWebTokenHandler().CreateToken(IdTokenDescriptor()).Split('.');

        await AssertIdTokenRejected(parts[0] + "." + parts[1] + ".");
    }

    [Fact]
    [Trait("Spec", "RFC 7515")]
    public async Task IdToken_ForgedSignature_ClaimingTheTrustedKid_IsRejected()
    {
        // The header's `kid` names the key the JWKS advertises, but the token is signed by the attacker's own
        // RSA key. The rejection maps to the "invalid_signature" contract, which is what makes OidcClient
        // refresh the JWKS and retry once — so a forgery lands on the same benign path a genuine key rotation
        // does, rather than being distinguishable from it.
        using var attacker = RSA.Create(2048);
        var forged = SignedWith(IdTokenDescriptor(), attacker, KeyId);

        var result = await AssertIdTokenRejected(forged);
        Assert.Equal("invalid_signature", result.Error);
    }

    [Fact]
    [Trait("Spec", "RFC 7515")]
    public async Task IdToken_HeaderSuppliedKeyMaterial_IsNeverConsulted()
    {
        // Real JWS header injection, RFC 7515 §4.1.2/§4.1.5/§4.1.6: `jku` and `x5u` name a URL a verifier
        // could fetch a key from and `x5c` carries one inline. The token is signed by the attacker's key and
        // the header hands that same key over all three ways, so a verifier that consulted ANY of them would
        // accept it — which is what makes the rejection attributable to the header material being ignored
        // rather than to the signature. Consulting it is not something to acquire by accident later: an
        // IssuerSigningKeyResolver that reads x5c turns this test red.
        using var attacker = RSA.Create(2048);
        var forged = HeaderInjected(IdTokenPayload(), attacker);

        await AssertIdTokenRejected(forged);
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
    public async Task HostileKidValues_DecideNothing_AndNeverThrow(string kid)
    {
        // The `kid` injection class: path traversal, a null byte, quote/SQL and markup metacharacters, and a
        // nested-JSON smuggling attempt. Asserting only that a hostile `kid` is rejected would be
        // unfalsifiable — the token carries an attacker signature, which can never verify whatever the kid
        // handling does. So two tokens are submitted that differ ONLY in who signed them: the provider-signed
        // one is ACCEPTED and the foreign-signed one is REJECTED, for every hostile spelling. That difference
        // is the property — the value decides nothing, opening no path and closing none.
        //
        // The second property is that neither is an exception. The id_token validator runs inside the OIDC
        // callback, where a throw surfaces as a 500: an attacker-triggerable oracle distinguishing hostile
        // input from an ordinary bad signature, and a denial-of-service lever on the login path. Awaiting
        // both calls outside any assertion is what proves it.
        //
        // The acceptance half deliberately flips if the `kid` allowlist of #1029 lands — that change must be
        // a conscious one, not a silent posture shift.
        using var attacker = RSA.Create(2048);

        var accepted = await _idTokenValidator.ValidateAsync(
            SignedWith(IdTokenDescriptor(), _rsa, kid), Options(), TestContext.Current.CancellationToken);

        Assert.False(accepted.IsError, accepted.Error);
        await AssertIdTokenRejected(SignedWith(IdTokenDescriptor(), attacker, kid));
    }

    [Theory]
    [Trait("Spec", "OIDC-Backchannel-Logout-1.0")]
    [InlineData(ForgeryKind.AlgNone)]
    [InlineData(ForgeryKind.AlgNoneMixedCase)]
    [InlineData(ForgeryKind.Hs256WithPublicKey)]
    [InlineData(ForgeryKind.SignatureStripped)]
    [InlineData(ForgeryKind.ForeignKeyWithTrustedKid)]
    [InlineData(ForgeryKind.ForeignKeyWithTraversalKid)]
    [InlineData(ForgeryKind.HeaderSuppliedKeyMaterial)]
    public async Task LogoutToken_SameForgeries_AreRejected(ForgeryKind kind)
    {
        // The back-channel endpoint is ANONYMOUS — the signature is the only thing authenticating the caller,
        // and a token accepted here revokes a user's sessions. It shares the id_token's validation basis, and
        // a shared builder proves the two cannot drift only while BOTH paths are actually driven through the
        // same attacks, so every SHAPE above is re-run here rather than reasoned about (the class doc says
        // which spellings of each are not, and why).
        //
        // What the reason code is asserted to be is the LAYER the refusal came from, not one fixed string.
        // Every shape here must die in signature/lifetime validation, before any logout_token claim-shape
        // check runs — that is the security property, and it is what the codes below would contradict.
        // Today all of them report one code, which is why an operator cannot tell alg-none from a stripped
        // signature (separating them is #1039); pinning that one string as well would make that separation
        // arrive as a red test in this file, which is not a claim this test is entitled to make.
        var pastSignatureValidation = new[]
        {
            OidcLogoutTokenValidator.RejectReason.NotALogoutToken,
            OidcLogoutTokenValidator.RejectReason.ProhibitedNonce,
            OidcLogoutTokenValidator.RejectReason.NoSubjectOrSid,
            OidcLogoutTokenValidator.RejectReason.Replay,
        };
        var forged = LogoutForgery(kind);

        var result = await _logoutTokenValidator.ValidateAsync(forged, Params(), Skew, DateTime.UtcNow);

        Assert.False(result.IsValid);
        Assert.False(string.IsNullOrEmpty(result.ReasonCode), "A rejection must carry a reason code — it is the only thing the audit trail records.");
        Assert.False(
            pastSignatureValidation.Contains(result.ReasonCode, StringComparer.Ordinal),
            $"The forgery was refused as '{result.ReasonCode}', a code only reachable once signature validation has already PASSED.");
        Assert.Null(result.Subject);
        Assert.Null(result.SessionIndex);
    }

    [Fact]
    [Trait("Spec", "OIDC-Backchannel-Logout-1.0")]
    public async Task LogoutToken_GenuinelySigned_Succeeds_ProvingTheForgeryBatteryIsNotVacuous()
    {
        // The positive control the battery needs to mean anything. Every test above asserts a rejection, and
        // a validation path that rejected EVERYTHING — a broken JWKS, a wrong audience constant in the
        // fixture — would pass all of them while proving nothing. One genuinely signed token, built by the
        // same helpers with the same parameters, has to be accepted for the rejections to carry weight.
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

        /// <summary>
        /// The same foreign-key forgery under a path-traversal <c>kid</c>. It differs from
        /// <see cref="ForeignKeyWithTrustedKid"/> only in that string, and both die on the signature, so this
        /// row does NOT show that the <c>kid</c> decides nothing — there is no acceptance control on this path
        /// to show it against, and <see cref="HostileKidValues_DecideNothing_AndNeverThrow"/> is where that
        /// property is established, differentially, on the login path. What this row holds is narrower and
        /// still worth the line: a traversal <c>kid</c> at the ANONYMOUS endpoint is REFUSED, not thrown on.
        /// A throw there is an unauthenticated 500 — an oracle separating hostile input from an ordinary bad
        /// signature, and a denial-of-service lever — and it is exactly what a <c>kid</c> sanitiser added
        /// later would produce.
        /// </summary>
        ForeignKeyWithTraversalKid,

        /// <summary>
        /// A foreign-key signature whose header hands that same key over in <c>jku</c>, <c>x5u</c> and
        /// <c>x5c</c>. The shape that matters most here: a verifier consulting header-supplied key material
        /// would accept it, and on this endpoint the signature is the only thing authenticating the caller.
        /// </summary>
        HeaderSuppliedKeyMaterial,
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

    // Builds the requested forgery over a valid logout_token payload. A switch EXPRESSION with a throwing
    // default: a new ForgeryKind added without a case here fails loudly instead of being silently tested as
    // whichever shape a catch-all arm happened to build.
    private string LogoutForgery(ForgeryKind kind) => kind switch
    {
        ForgeryKind.AlgNone => Jws("{\"alg\":\"none\",\"typ\":\"JWT\"}", LogoutTokenPayload(), signature: string.Empty),
        ForgeryKind.AlgNoneMixedCase => Jws("{\"alg\":\"None\",\"typ\":\"JWT\"}", LogoutTokenPayload(), signature: string.Empty),
        ForgeryKind.Hs256WithPublicKey => Hs256(LogoutTokenPayload(), _rsa.ExportSubjectPublicKeyInfo(), KeyId),
        ForgeryKind.SignatureStripped => StripSignature(new JsonWebTokenHandler().CreateToken(LogoutTokenDescriptor())),
        ForgeryKind.ForeignKeyWithTrustedKid => ForeignKeySignedLogoutToken(KeyId),
        ForgeryKind.ForeignKeyWithTraversalKid => ForeignKeySignedLogoutToken("../../../etc/passwd"),
        ForgeryKind.HeaderSuppliedKeyMaterial => HeaderInjectedLogoutToken(),
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "No forgery is defined for this kind."),
    };

    private string ForeignKeySignedLogoutToken(string kid)
    {
        using var attacker = RSA.Create(2048);
        return SignedWith(LogoutTokenDescriptor(), attacker, kid);
    }

    private static string HeaderInjectedLogoutToken()
    {
        using var attacker = RSA.Create(2048);
        return HeaderInjected(LogoutTokenPayload(), attacker);
    }

    private static string SignedWith(SecurityTokenDescriptor descriptor, RSA key, string kid)
    {
        descriptor.SigningCredentials = new SigningCredentials(
            new RsaSecurityKey(key) { KeyId = kid }, SecurityAlgorithms.RsaSha256);
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    private static string StripSignature(string token)
    {
        var parts = token.Split('.');
        return parts[0] + "." + parts[1] + ".";
    }

    // A compact JWS from its three parts, with the header and payload base64url-encoded here rather than by a
    // token handler — the handler would refuse to emit most of what this file needs to submit.
    private static string Jws(string headerJson, string payloadJson, string signature) =>
        Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(headerJson))
        + "." + Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payloadJson))
        + "." + signature;

    // An HS256-signed token, MAC'd with the supplied key material under the supplied `kid`.
    private static string Hs256(string payloadJson, byte[] key, string kid)
    {
        var signingInput = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes("{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"" + kid + "\"}"))
            + "." + Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payloadJson));
        using var hmac = new HMACSHA256(key);
        return signingInput + "." + Base64UrlEncoder.Encode(hmac.ComputeHash(Encoding.UTF8.GetBytes(signingInput)));
    }

    // An RS256 token signed by the given key, whose header advertises that same key three ways — inline in
    // x5c and by URL in jku and x5u. Hand-composed because JsonWebTokenHandler emits none of those members.
    private static string HeaderInjected(string payloadJson, RSA key)
    {
        var header = "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"" + KeyId + "\","
            + "\"jku\":\"https://attacker.example/jwks.json\","
            + "\"x5u\":\"https://attacker.example/cert.pem\","
            + "\"x5c\":[\"" + Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()) + "\"]}";
        var signingInput = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header))
            + "." + Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payloadJson));
        var signature = key.SignData(Encoding.UTF8.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return signingInput + "." + Base64UrlEncoder.Encode(signature);
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

    private SecurityTokenDescriptor IdTokenDescriptor()
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
                new RsaSecurityKey(_rsa) { KeyId = KeyId }, SecurityAlgorithms.RsaSha256),
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
        OidcSignatureKeys.BuildValidationParameters(Options(), _ephemeralKeys, requireExpiration: false);
}
