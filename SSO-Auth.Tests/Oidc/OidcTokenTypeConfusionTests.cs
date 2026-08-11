// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// RFC 7519 §4.1.9 on both token paths (#1317): a JWT whose header declares one of the media types this
/// plugin can attribute to another endpoint is refused there, so the token families are separated by what
/// they say they are and not only by the shape of their payloads.
/// <para>
/// Both directions were accepted before this rule existed, measured on the shipped validators: a genuine
/// <c>logout+jwt</c> validated on the id_token path, and a <c>logout_token</c> whose header said
/// <c>at+jwt</c> validated on the logout path. That is the reason the rows below exist in both directions
/// rather than only in the one the payload rules already cover.
/// </para>
/// <para>
/// Every token here is GENUINELY SIGNED by the key the JWKS advertises and is otherwise valid, and each
/// rejection is paired with the same token minus the header. Without that pairing a rejection proves
/// nothing about <c>typ</c>: a fixture the validator would refuse anyway passes for a reason it does not
/// name.
/// </para>
/// </summary>
[Collection("SSOController")]
public sealed class OidcTokenTypeConfusionTests : IDisposable
{
    private const string Issuer = "https://idp.example.test";
    private const string ClientId = "jellyfin-client";
    private const string KeyId = "test-signing-key";
    private const string LogoutEvent = "http://schemas.openid.net/event/backchannel-logout";

    private readonly RSA _rsa = RSA.Create(2048);
    private readonly OidcIdTokenValidator _idTokenValidator = new();
    private readonly OidcLogoutTokenValidator _logoutValidator = new();

    public OidcTokenTypeConfusionTests() => OidcLogoutTokenValidator.ResetReplaysForTests();

    /// <summary>
    /// The media types that name a purpose other than an id_token, in every spelling one can arrive in.
    /// <para>
    /// The prefixed and case-variant rows are the near-miss this file is built around, and they are the
    /// rows that die if the screen compares the raw header value with an ordinal equality: RFC 7519 §5.1
    /// lets a producer omit the <c>application/</c> prefix and media types are case-insensitive, so
    /// <c>application/logout+jwt</c> and <c>LOGOUT+JWT</c> are the same declaration as <c>logout+jwt</c>
    /// and a screen that misses them is bypassed by re-spelling one header field.
    /// </para>
    /// </summary>
    public static TheoryData<string, string> ForeignToIdToken => new()
    {
        { "logout-token", "logout+jwt" },
        { "logout-token-prefixed", "application/logout+jwt" },
        { "logout-token-upper", "LOGOUT+JWT" },
        { "logout-token-mixed-prefix", "Application/Logout+Jwt" },
        { "access-token", "at+jwt" },
        { "access-token-prefixed", "application/at+jwt" },
        { "dpop-proof", "dpop+jwt" },
        { "security-event", "secevent+jwt" },
    };

    /// <summary>
    /// The media types foreign to the back-channel logout endpoint. Smaller than the set above, and the
    /// asymmetry is the point: a <c>logout_token</c> IS a security event token, so <c>secevent+jwt</c> and
    /// <c>logout+jwt</c> are its own family, and an id_token has no reserved media type for a screen to
    /// name. The id_token replayed here stays the job of the forbidden <c>nonce</c> and the required
    /// <c>events</c> member, which have their own tests.
    /// </summary>
    public static TheoryData<string, string> ForeignToLogoutToken => new()
    {
        { "access-token", "at+jwt" },
        { "access-token-prefixed", "application/at+jwt" },
        { "access-token-upper", "AT+JWT" },
        { "dpop-proof", "dpop+jwt" },
    };

    /// <summary>
    /// Values that declare no purpose this plugin can attribute, and are therefore admitted by the screen
    /// and left to every rule that follows. This is the availability half of the decision, written as
    /// tests so it is a choice rather than an accident: <c>typ</c> is optional, and providers omit it, send
    /// the generic <c>JWT</c>, or send a value of their own. Refusing those would lock out working
    /// providers to gain nothing, since none of them names another endpoint.
    /// </summary>
    public static TheoryData<string, string> AcceptedTokenTypes => new()
    {
        { "generic", "JWT" },
        { "generic-lowercase", "jwt" },
        { "generic-prefixed", "application/jwt" },
        { "vendor", "vnd.example.token+jwt" },
        { "unrelated", "example" },
    };

    public void Dispose()
    {
        _rsa.Dispose();
        OidcLogoutTokenValidator.ResetReplaysForTests();
    }

    [Fact]
    public async Task IdToken_WithoutTypHeader_IsAccepted()
    {
        // The positive control every rejection below is read against: this fixture differs from them by the
        // header member and nothing else, so a rejection there is attributable to typ.
        var result = await _idTokenValidator.ValidateAsync(IdToken(), Options(), TestContext.Current.CancellationToken);

        Assert.False(result.IsError, result.Error);
    }

    [Theory]
    [MemberData(nameof(ForeignToIdToken))]
    public async Task IdToken_DeclaringAForeignType_IsRejected(string shape, string typ)
    {
        var result = await _idTokenValidator.ValidateAsync(IdToken(typ), Options(), TestContext.Current.CancellationToken);

        Assert.True(result.IsError, shape);
        Assert.Contains("unacceptable token type", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task IdToken_RefusalIsNotTheSignatureCode()
    {
        // "invalid_signature" is a contract with OidcClient: it refreshes the discovery JWKS and retries
        // once. Reporting a type refusal that way would spend a JWKS fetch on a token that will be refused
        // identically the second time.
        var result = await _idTokenValidator.ValidateAsync(IdToken("logout+jwt"), Options(), TestContext.Current.CancellationToken);

        Assert.NotEqual("invalid_signature", result.Error);
    }

    [Fact]
    public async Task GenuineLogoutToken_IsRejectedOnTheIdTokenPath()
    {
        // The measured direction, end to end: a real back-channel logout token, correctly typed, signed by
        // the trusted key and addressed to this client, used as a login credential. Before #1317 this
        // returned a principal.
        var logoutToken = Sign(LogoutClaims(), "logout+jwt");

        var result = await _idTokenValidator.ValidateAsync(logoutToken, Options(), TestContext.Current.CancellationToken);

        Assert.True(result.IsError);
        Assert.Null(result.User);
    }

    [Theory]
    [MemberData(nameof(AcceptedTokenTypes))]
    public async Task IdToken_DeclaringAnUnattributableType_IsAccepted(string shape, string typ)
    {
        var result = await _idTokenValidator.ValidateAsync(IdToken(typ), Options(), TestContext.Current.CancellationToken);

        Assert.False(result.IsError, $"{shape}: {result.Error}");
    }

    [Fact]
    public async Task LogoutToken_WithoutTypHeader_IsAccepted()
    {
        var result = await _logoutValidator.ValidateAsync(LogoutToken(), Options(), DateTime.UtcNow);

        Assert.True(result.IsValid, result.ReasonCode);
        Assert.Equal("user-1", result.Subject);
    }

    [Fact]
    public async Task LogoutToken_DeclaringItsOwnTypes_IsAccepted()
    {
        // The asymmetry asserted rather than assumed. Both of these name this token's own family, so
        // refusing either would reject a spec-conformant provider at the endpoint the spec recommends the
        // value for.
        foreach (var typ in new[] { "logout+jwt", "secevent+jwt" })
        {
            var result = await _logoutValidator.ValidateAsync(LogoutToken(typ), Options(), DateTime.UtcNow);

            Assert.True(result.IsValid, $"{typ}: {result.ReasonCode}");
        }
    }

    [Theory]
    [MemberData(nameof(ForeignToLogoutToken))]
    public async Task LogoutToken_DeclaringAForeignType_IsRejected(string shape, string typ)
    {
        var result = await _logoutValidator.ValidateAsync(LogoutToken(typ), Options(), DateTime.UtcNow);

        Assert.False(result.IsValid, shape);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.UnacceptableTokenType, result.ReasonCode);
    }

    [Fact]
    public async Task LogoutToken_TypeRefusal_IsNotTheGenericInvalidCode()
    {
        // The code is what an operator alerts on. Collapsed into the generic code, a provider sending the
        // wrong media type reads as a forgery attempt, and the two want different responses.
        var result = await _logoutValidator.ValidateAsync(LogoutToken("at+jwt"), Options(), DateTime.UtcNow);

        Assert.NotEqual(OidcLogoutTokenValidator.RejectReason.Invalid, result.ReasonCode);
    }

    [Fact]
    public async Task LogoutToken_RefusedForItsType_IsNotConsumedFromTheReplaySet()
    {
        // The screen runs before the jti is consumed, so a refused token has not spent its one use. A
        // provider that mislabels one delivery and re-sends it correctly must still be able to log the
        // session out; the reverse ordering would turn a header mistake into a permanent no-op.
        var jti = Guid.NewGuid().ToString();

        var refused = await _logoutValidator.ValidateAsync(Sign(LogoutClaims(jti), "at+jwt"), Options(), DateTime.UtcNow);
        var accepted = await _logoutValidator.ValidateAsync(Sign(LogoutClaims(jti), null), Options(), DateTime.UtcNow);

        Assert.False(refused.IsValid);
        Assert.True(accepted.IsValid, accepted.ReasonCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-jwt")]
    [InlineData("only.two")]
    [InlineData("!!!.eyJpc3MiOiJoIn0.sig")]
    [InlineData(".eyJhbGciOiJSUzI1NiJ9.sig")]
    [InlineData("eyJub3QtanNvbg.payload.sig")]
    public void UnreadableHeader_IsNotRefusedHere(string? token)
    {
        // The gate is not the fail-closed floor and must not pretend to be one: a header it cannot read
        // goes to the handler, which refuses the token on its own terms and with an accurate reason. These
        // inputs also reach the two catch arms from outside, and the back-channel endpoint is anonymous, so
        // an unhandled decode failure here would be a 500 an unauthenticated caller can drive.
        Assert.True(OidcSignatureKeys.TokenTypeIsAcceptableForIdToken(token));
        Assert.True(OidcSignatureKeys.TokenTypeIsAcceptableForLogoutToken(token));
    }

    [Fact]
    public void NonStringTypHeader_IsNotRefusedHere()
    {
        // A typ that is not a string is malformed rather than a declaration of another purpose, so it is
        // admitted and judged by the rules that follow. Pinned so the behaviour is a decision on the
        // record: the alternative, refusing anything unreadable in that member, is a fail-closed choice
        // this screen deliberately does not make, because it is not the floor.
        var numeric = Sign(new Dictionary<string, object> { ["sub"] = "user-1" }, null, new Dictionary<string, object> { ["typ"] = 5 });

        Assert.True(OidcSignatureKeys.TokenTypeIsAcceptableForIdToken(numeric));
    }

    // --- helpers ---

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
            ClockSkew = TimeSpan.FromMinutes(5),
            ProviderInformation = new ProviderInformation
            {
                IssuerName = Issuer,
                KeySet = new Duende.IdentityModel.Jwk.JsonWebKeySet(jwks),
            },
        };
    }

    private static Dictionary<string, object> LogoutClaims(string? jti = null) => new()
    {
        ["events"] = new Dictionary<string, object> { [LogoutEvent] = new Dictionary<string, object>() },
        ["jti"] = jti ?? Guid.NewGuid().ToString(),
        ["sub"] = "user-1",
    };

    private string IdToken(string? typ = null) =>
        Sign(new Dictionary<string, object> { ["sub"] = "user-1", ["preferred_username"] = "alice" }, typ);

    private string LogoutToken(string? typ = null) => Sign(LogoutClaims(), typ);

    private string Sign(IDictionary<string, object> claims, string? typ, IDictionary<string, object>? header = null)
    {
        var now = DateTime.UtcNow;
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = ClientId,
            IssuedAt = now - TimeSpan.FromMinutes(1),
            NotBefore = now - TimeSpan.FromMinutes(1),
            Expires = now + TimeSpan.FromMinutes(5),
            Claims = claims,
            TokenType = typ,
            AdditionalHeaderClaims = header,
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(_rsa) { KeyId = KeyId }, SecurityAlgorithms.RsaSha256),
        });
    }
}
