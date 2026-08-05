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

        var result = await _logoutValidator.ValidateAsync(token, Parameters(), Skew, _now);

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

        var result = await _logoutValidator.ValidateAsync(token, Parameters(keyId), Skew, _now);

        Assert.True(result.IsValid, result.ReasonCode);
        Assert.Equal("user-1", result.Subject);
    }

    [Fact]
    public async Task ValidToken_OnBothPaths_StillSucceeds()
    {
        // The floor this change must not lower: the ordinary token, with the ordinary kid, on both paths.
        var idResult = await _idTokenValidator.ValidateAsync(
            CreateToken(), Options(), TestContext.Current.CancellationToken);
        Assert.False(idResult.IsError, idResult.Error);

        var logoutResult = await _logoutValidator.ValidateAsync(
            CreateToken(claims: LogoutClaims()), Parameters(), Skew, _now);
        Assert.True(logoutResult.IsValid, logoutResult.ReasonCode);
    }

    // --- helpers ---

    private static Dictionary<string, object> LogoutClaims() => new()
    {
        ["sub"] = "user-1",
        ["jti"] = Guid.NewGuid().ToString("N"),
        ["events"] = new Dictionary<string, object> { [LogoutEvent] = new Dictionary<string, object>() },
    };

    private OidcClientOptions Options(string keyId = KeyId) => new()
    {
        ClientId = ClientId,
        ProviderInformation = new ProviderInformation
        {
            IssuerName = Issuer,
            KeySet = new Duende.IdentityModel.Jwk.JsonWebKeySet(Jwks(keyId)),
        },
    };

    private TokenValidationParameters Parameters(string keyId = KeyId) =>
        OidcSignatureKeys.BuildValidationParameters(Options(keyId), new List<IDisposable>(), requireExpiration: false);

    private string Jwks(string keyId)
    {
        var p = _rsa.ExportParameters(false);
        return "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"" + keyId + "\","
            + "\"n\":\"" + Base64UrlEncoder.Encode(p.Modulus) + "\",\"e\":\"" + Base64UrlEncoder.Encode(p.Exponent) + "\"}]}";
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
