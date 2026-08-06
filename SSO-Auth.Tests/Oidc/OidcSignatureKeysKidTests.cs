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
/// The token-header <c>kid</c> allowlist (#1167, part of #1029). A <c>kid</c> outside the RFC 3986
/// unreserved set, or over the length cap, is refused before any signing key is looked up - on BOTH JWT
/// paths, from one predicate in <see cref="OidcSignatureKeys"/>, so the id_token and the back-channel
/// <c>logout_token</c> postures cannot drift apart.
/// <para>
/// This is defence in depth rather than a live fix: today the value only ever reaches an ordinal compare
/// against the in-memory <c>KeyId</c> values converted from the discovery JWKS, so there is no sink to
/// exploit. The tests that matter most are therefore the COMPATIBILITY ones - a constraint nobody needs
/// yet, set too tight, buys a real IdP lockout for a hypothetical attack.
/// </para>
/// </summary>
public sealed class OidcSignatureKeysKidTests : IDisposable
{
    private const string Issuer = "https://idp.example.test";
    private const string ClientId = "jellyfin-client";
    private const string KeyId = "test-signing-key";
    private const string LogoutEvent = "http://schemas.openid.net/event/backchannel-logout";

    private static readonly TimeSpan Skew = TimeSpan.FromMinutes(5);

    private readonly RSA _rsa = RSA.Create(2048);
    // A SECOND key, so a set can carry an entry whose material is not the one that signed the token. Without
    // it, every mixed-set row would verify through whichever entry survived and prove nothing about which.
    private readonly RSA _other = RSA.Create(2048);
    private readonly OidcIdTokenValidator _idTokenValidator = new();
    private readonly OidcLogoutTokenValidator _logoutValidator = new();
    private readonly DateTime _now = DateTime.UtcNow;

    /// <summary>
    /// One row per character class the allowlist exists to stop. Every one of these is a shape that a
    /// future consumer of the header value - a log line, a cache key, a path, a URL - would read
    /// differently from an opaque identifier.
    /// </summary>
    public static TheoryData<string> HostileKeyIds() => new()
    {
        "../etc/passwd",           // dot-segment
        "keys/../../secret",       // dot-segment, embedded
        "keys/live",               // forward separator
        "keys\\live",              // backward separator
        "%2e%2e%2fkeys",           // percent-encoded dot-segment
        "key\0null",               // null byte
        "key'or'1",                // single quote
        "key\"quoted\"",           // double quote
        "key id",                  // whitespace inside
        "key\nid",                 // line break, the log-forging shape
        "https://evil.example.net/jwks",
    };

    /// <summary>
    /// The shapes real identity providers actually mint. If any of these is refused, the change is an
    /// outage rather than a hardening, so they are pinned end to end against a real signature.
    /// </summary>
    public static TheoryData<string> RealWorldKeyIds() => new()
    {
        "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",   // base64url certificate thumbprint
        "1e9gdk7",                                        // short alphanumeric
        "7c309e3a-1f6d-4f5c-9a02-4d0d4b2e0c11",           // UUID
        "0123456789",                                     // numeric
        "sig.key_2026~rotate-3",                          // every remaining unreserved character
    };

    public void Dispose()
    {
        _rsa.Dispose();
        _other.Dispose();
        OidcLogoutTokenValidator.ResetReplaysForTests();
    }

    [Theory]
    [MemberData(nameof(HostileKeyIds))]
    public void HostileKeyId_IsRefusedByThePredicate(string keyId)
    {
        Assert.False(OidcSignatureKeys.IsAcceptableKeyId(keyId));
    }

    [Theory]
    [MemberData(nameof(RealWorldKeyIds))]
    public void RealWorldKeyId_IsAcceptedByThePredicate(string keyId)
    {
        Assert.True(OidcSignatureKeys.IsAcceptableKeyId(keyId));
    }

    [Fact]
    public void OverLengthKeyId_IsRefused_AndTheBoundaryIsPinned()
    {
        // The cap is a boundary, so both sides of it are pinned: a 256-character kid of otherwise legal
        // characters is accepted and a 257-character one is not. Without the accepting half, tightening
        // the cap to 8 would leave this test green.
        Assert.True(OidcSignatureKeys.IsAcceptableKeyId(new string('a', 256)));
        Assert.False(OidcSignatureKeys.IsAcceptableKeyId(new string('a', 257)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void AbsentKeyId_IsNotAViolation(string? keyId)
    {
        // An absent kid is the ordinary "try every advertised key" case. Refusing it would break every
        // provider that mints tokens without one, and it also keeps the predicate indifferent to whether
        // the token library reports an absent header member as null or as an empty string.
        Assert.True(OidcSignatureKeys.IsAcceptableKeyId(keyId));
    }

    [Fact]
    public void UnreadableToken_IsNotRefusedByTheGate()
    {
        // The gate is not the fail-closed floor and must not pretend to be one: a token whose header will
        // not parse is refused by the handler moments later, on its own terms. Answering here would swap an
        // accurate rejection reason for a misleading one.
        Assert.True(OidcSignatureKeys.TokenHasAcceptableKeyId("not-a-jwt"));
        Assert.True(OidcSignatureKeys.TokenHasAcceptableKeyId("only.two"));
        Assert.True(OidcSignatureKeys.TokenHasAcceptableKeyId("a.b.c"));
        Assert.True(OidcSignatureKeys.TokenHasAcceptableKeyId(null));
        Assert.True(OidcSignatureKeys.TokenHasAcceptableKeyId(string.Empty));
    }

    [Theory]
    [MemberData(nameof(HostileKeyIds))]
    public async Task IdTokenPath_RefusesHostileKeyId(string keyId)
    {
        // Signed by the RIGHT key, so nothing but the kid can be the reason for the rejection - the same
        // token with an ordinary kid succeeds in ValidToken_OnBothPaths_StillSucceeds below.
        var result = await _idTokenValidator.ValidateAsync(
            CreateToken(keyId: keyId), Options(), TestContext.Current.CancellationToken);

        Assert.True(result.IsError);
        Assert.Contains("unacceptable kid", result.Error, StringComparison.Ordinal);
        // Never the key-refresh contract: "invalid_signature" makes OidcClient re-fetch the JWKS and retry,
        // which would turn every hostile kid into two provider round trips.
        Assert.DoesNotContain("invalid_signature", result.Error, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(HostileKeyIds))]
    public async Task LogoutTokenPath_RefusesHostileKeyId(string keyId)
    {
        var token = CreateToken(keyId: keyId, claims: LogoutClaims());

        var result = await _logoutValidator.ValidateAsync(token, Options(), _now);

        Assert.False(result.IsValid);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.UnacceptableKeyId, result.ReasonCode);
        Assert.Null(result.Subject);
        Assert.Null(result.SessionIndex);
    }

    [Theory]
    [MemberData(nameof(RealWorldKeyIds))]
    public async Task IdTokenPath_AcceptsRealWorldKeyId(string keyId)
    {
        // End to end against a JWKS advertising the same kid, so this proves the token still VALIDATES
        // rather than merely getting past the gate into a different rejection.
        var result = await _idTokenValidator.ValidateAsync(
            CreateToken(keyId: keyId), Options(keyId), TestContext.Current.CancellationToken);

        Assert.False(result.IsError, result.Error);
        Assert.Equal("RS256", result.SignatureAlgorithm);
    }

    [Theory]
    [MemberData(nameof(RealWorldKeyIds))]
    public async Task LogoutTokenPath_AcceptsRealWorldKeyId(string keyId)
    {
        var token = CreateToken(keyId: keyId, claims: LogoutClaims());

        var result = await _logoutValidator.ValidateAsync(token, Options(keyId), _now);

        Assert.True(result.IsValid, result.ReasonCode);
        Assert.Equal("user-1", result.Subject);
    }

    /// <summary>
    /// The other half of the same question (#1029): a <c>kid</c> the PROVIDER advertises in its JWKS,
    /// outside the same allowlist. These are the shapes that turn up in the field - a standard-base64
    /// thumbprint rather than a base64url one is the common case, because the two alphabets differ in
    /// exactly the characters the allowlist excludes.
    /// </summary>
    public static TheoryData<string> OutOfAllowlistAdvertisedKeyIds() => new()
    {
        "ab+cd/ef=",              // standard base64 rather than base64url: + / =
        "signing key 2026",       // spaces
        "kid:2026:rotate",        // colons, the shape of a namespaced identifier
    };

    [Theory]
    [MemberData(nameof(OutOfAllowlistAdvertisedKeyIds))]
    public void AdvertisedKeyOutsideTheAllowlist_IsKept(string keyId)
    {
        // THE DECISION, pinned: the allowlist screens the needle, never the haystack. An advertised key is
        // skipped only when it is unusable AS A KEY - not a signing key, under the RSA floor, un-decodable
        // material - and the spelling of its kid is none of those. Skipping it would refuse a
        // well-behaved provider over an alphabet choice and take its signature verification down with it,
        // which is a real outage traded for nothing: the header screen already stops a hostile kid from
        // reaching the lookup, and this value is what the lookup is searched THROUGH.
        Assert.False(OidcSignatureKeys.IsAcceptableKeyId(keyId), "row is not actually outside the allowlist");

        var ephemeral = new List<IDisposable>();
        try
        {
            var keys = OidcSignatureKeys.Convert(new Duende.IdentityModel.Jwk.JsonWebKeySet(Jwks(keyId)), ephemeral);

            var key = Assert.Single(keys);
            Assert.Equal(keyId, key.KeyId);
        }
        finally
        {
            foreach (var disposable in ephemeral)
            {
                disposable.Dispose();
            }
        }
    }

    [Theory]
    [MemberData(nameof(OutOfAllowlistAdvertisedKeyIds))]
    public async Task TokenWithoutAKid_StillValidatesAgainstSuchAKey(string keyId)
    {
        // "Kept" is not the same as "usable", so the decision is pinned end to end as well: the provider
        // advertises only this key, the token names no key, and the signature still verifies. Without this
        // row, a change that kept the key but made it unreachable would leave the row above green.
        var token = CreateTokenWithoutKid();
        Assert.True(string.IsNullOrEmpty(new JsonWebToken(token).Kid), "the token was supposed to carry no kid");

        var result = await _idTokenValidator.ValidateAsync(token, Options(keyId), TestContext.Current.CancellationToken);

        Assert.False(result.IsError, result.Error);
        Assert.Equal("RS256", result.SignatureAlgorithm);
    }

    [Theory]
    [MemberData(nameof(OutOfAllowlistAdvertisedKeyIds))]
    public async Task TokenNamingSuchAKeyByKid_IsStillRefused(string keyId)
    {
        // And the cost of the decision, stated rather than left to be discovered: such a key can be reached
        // by trying every advertised key, but never BY NAME, because naming it means putting the same
        // characters in the token header where the screen refuses them. A provider that advertises one of
        // these AND mints tokens carrying it therefore does not log anyone in - which is a configuration
        // this repository cannot verify against a live IdP, so it is recorded here rather than claimed to
        // be impossible.
        var result = await _idTokenValidator.ValidateAsync(
            CreateToken(keyId: keyId), Options(keyId), TestContext.Current.CancellationToken);

        Assert.True(result.IsError);
        Assert.Contains("unacceptable kid", result.Error, StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(OutOfAllowlistAdvertisedKeyIds))]
    public async Task OneOddKeyInTheSet_DoesNotTakeDownTheGoodOne(string oddKeyId)
    {
        // The availability half of the decision, and the reason the answer is skip-nothing rather than
        // refuse-the-set (#1168). The provider advertises two keys: one whose kid is outside the allowlist,
        // one ordinary. The token is signed by the ordinary key and names it. If the odd entry were refused
        // AS A SET, this login would be gone; if it were skipped, this login would survive - and the rows
        // above cannot tell those two apart, because they use a set of one.
        //
        // The two entries carry DIFFERENT key material, so the signature can only verify through the good
        // entry. A mixed set built from one modulus would pass even if the good entry had been dropped.
        var result = await _idTokenValidator.ValidateAsync(
            CreateToken(), OptionsFor(MixedJwks(oddKeyId)), TestContext.Current.CancellationToken);

        Assert.False(result.IsError, result.Error);
        Assert.Equal("RS256", result.SignatureAlgorithm);
    }

    [Theory]
    [MemberData(nameof(OutOfAllowlistAdvertisedKeyIds))]
    public async Task ASetWhoseEveryKeyIsOdd_AndNoneIsTheSigner_FailsClosedWithoutThrowing(string oddKeyId)
    {
        // The other end of the same contract: keeping an odd-kid key is not a way into anything. Every
        // advertised key here is outside the allowlist AND none of them is the key that signed the token,
        // so verification has nothing to succeed with. The requirement is that it FAILS - fail-closed,
        // through the ordinary no-usable-key path - rather than throwing, which on the callback becomes a
        // 500 on an anonymous endpoint instead of a rejection.
        var jwks = "{\"keys\":[" + KeyEntry(oddKeyId, _other) + "," + KeyEntry(oddKeyId + "-2", _other) + "]}";

        var result = await _idTokenValidator.ValidateAsync(
            CreateToken(), OptionsFor(jwks), TestContext.Current.CancellationToken);

        Assert.True(result.IsError);
        Assert.False(string.IsNullOrEmpty(result.Error));
    }

    [Fact]
    public async Task AnAdvertisedKeyWithNoKidAtAll_KeepsWorking()
    {
        // A single-key set that names no kid is the ordinary small-provider shape, and it must be untouched
        // by anything the allowlist does. Both directions: the token names no key, and the token names one
        // the set does not carry - in each case the only usable key is the one advertised without a name.
        var jwks = "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\"," + Material(_rsa) + "}]}";

        var withoutKid = await _idTokenValidator.ValidateAsync(
            CreateTokenWithoutKid(), OptionsFor(jwks), TestContext.Current.CancellationToken);
        Assert.False(withoutKid.IsError, withoutKid.Error);

        var withKid = await _idTokenValidator.ValidateAsync(
            CreateToken(), OptionsFor(jwks), TestContext.Current.CancellationToken);
        Assert.False(withKid.IsError, withKid.Error);
    }

    [Fact]
    public async Task ValidToken_OnBothPaths_StillSucceeds()
    {
        // The floor this change must not lower: the ordinary token, with the ordinary kid, on both paths.
        var idResult = await _idTokenValidator.ValidateAsync(
            CreateToken(), Options(), TestContext.Current.CancellationToken);
        Assert.False(idResult.IsError, idResult.Error);

        var logoutResult = await _logoutValidator.ValidateAsync(
            CreateToken(claims: LogoutClaims()), Options(), _now);
        Assert.True(logoutResult.IsValid, logoutResult.ReasonCode);
    }

    // --- helpers ---

    private static Dictionary<string, object> LogoutClaims() => new()
    {
        ["sub"] = "user-1",
        ["jti"] = Guid.NewGuid().ToString("N"),
        ["events"] = new Dictionary<string, object> { [LogoutEvent] = new Dictionary<string, object>() },
    };

    private OidcClientOptions Options(string keyId = KeyId) => OptionsFor(Jwks(keyId));

    private OidcClientOptions OptionsFor(string jwks) => new()
    {
        ClientId = ClientId,
        ClockSkew = Skew,
        ProviderInformation = new ProviderInformation
        {
            IssuerName = Issuer,
            KeySet = new Duende.IdentityModel.Jwk.JsonWebKeySet(jwks),
        },
    };

    private string Jwks(string keyId) => "{\"keys\":[" + KeyEntry(keyId, _rsa) + "]}";

    // Two advertised keys: the odd-kid one FIRST, so a walk that aborted on it would never reach the good
    // one, and the good one second carrying the material that actually signed the token.
    private string MixedJwks(string oddKeyId) =>
        "{\"keys\":[" + KeyEntry(oddKeyId, _other) + "," + KeyEntry(KeyId, _rsa) + "]}";

    private static string KeyEntry(string keyId, RSA rsa) =>
        "{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"" + keyId + "\"," + Material(rsa) + "}";

    private static string Material(RSA rsa)
    {
        var p = rsa.ExportParameters(false);
        return "\"n\":\"" + Base64UrlEncoder.Encode(p.Modulus) + "\",\"e\":\"" + Base64UrlEncoder.Encode(p.Exponent) + "\"";
    }

    // A token signed by the same RSA key but carrying no kid header, so key resolution has to fall back to
    // trying every advertised key. The signing credentials get no KeyId, which is what leaves the header
    // member out; the caller asserts the absence rather than trusting it.
    private string CreateTokenWithoutKid()
    {
        var now = DateTime.UtcNow;
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = ClientId,
            IssuedAt = now - TimeSpan.FromMinutes(1),
            NotBefore = now - TimeSpan.FromMinutes(1),
            Expires = now + TimeSpan.FromMinutes(5),
            Claims = new Dictionary<string, object> { ["sub"] = "user-1" },
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(_rsa), SecurityAlgorithms.RsaSha256),
        });
    }

    private string CreateToken(string keyId = KeyId, IDictionary<string, object>? claims = null)
    {
        var now = DateTime.UtcNow;
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = ClientId,
            IssuedAt = now - TimeSpan.FromMinutes(1),
            NotBefore = now - TimeSpan.FromMinutes(1),
            Expires = now + TimeSpan.FromMinutes(5),
            Claims = claims ?? new Dictionary<string, object> { ["sub"] = "user-1" },
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(_rsa) { KeyId = keyId }, SecurityAlgorithms.RsaSha256),
        });
    }
}
