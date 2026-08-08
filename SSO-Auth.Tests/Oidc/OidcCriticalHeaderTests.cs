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
/// RFC 7515 §4.1.11 on both token paths (#1038): a JWS whose header carries <c>crit</c> is refused,
/// because this plugin implements no JWS extension and therefore understands and processes none of them.
/// <para>
/// Every token below is GENUINELY SIGNED by the key the JWKS advertises and is otherwise valid, and each
/// rejection test is paired with the same token minus the header. Without that pairing a rejection proves
/// nothing about <c>crit</c> - a fixture the code cannot parse is refused by the signature check and the
/// test passes for a reason it does not name.
/// </para>
/// <para>
/// The two paths are asserted against ONE predicate on purpose. The handler ignores <c>crit</c> outright,
/// so this is the plugin's own rule, and a rule the id_token path holds while the anonymous back-channel
/// logout endpoint does not is the drift <see cref="OidcSignatureKeys"/> exists to prevent.
/// </para>
/// </summary>
[Collection("SSOController")]
public sealed class OidcCriticalHeaderTests : IDisposable
{
    private const string Issuer = "https://idp.example.test";
    private const string ClientId = "jellyfin-client";
    private const string KeyId = "test-signing-key";
    private const string LogoutEvent = "http://schemas.openid.net/event/backchannel-logout";
    private const string UnknownExtension = "http://example.test/unknown";

    private readonly RSA _rsa = RSA.Create(2048);
    private readonly OidcIdTokenValidator _idTokenValidator = new();
    private readonly OidcLogoutTokenValidator _logoutValidator = new();

    public OidcCriticalHeaderTests() => OidcLogoutTokenValidator.ResetReplaysForTests();

    /// <summary>
    /// The shapes a <c>crit</c> member can arrive in. All are refused, and the refusal is one rule rather
    /// than six: the plugin processes no extension, so no value could make the header acceptable and the
    /// malformed shapes §4.1.11 forbids need no branch of their own.
    /// <para>
    /// The <c>json-string</c>, <c>number</c> and <c>bool</c> rows are the near-miss this file is built
    /// around. They are what a <c>crit</c> written by hand rather than by a library looks like, and they
    /// are the rows that die if the guard reads the member as a TYPE instead of asking whether it is
    /// there: <c>JsonWebToken.TryGetHeaderValue&lt;JsonElement&gt;("crit", out _)</c> returns FALSE for
    /// each of them - measured, not assumed - so a typed read reports the member absent and admits the
    /// token. Every other row here survives that mistake, which is why it needs its own rows.
    /// </para>
    /// </summary>
    public static TheoryData<string, object> CriticalHeaderShapes => new()
    {
        { "named-extension", new[] { UnknownExtension } },
        { "json-string", UnknownExtension },
        { "number", 5 },
        { "bool", true },
        { "empty-array", Array.Empty<string>() },
        { "null-member", new string?[] { null } },
        { "empty-string-member", new[] { string.Empty } },
        { "registered-header-name", new[] { "alg" } },
        { "duplicate-member", new[] { UnknownExtension, UnknownExtension } },
        { "object", new Dictionary<string, object>() },
    };

    public void Dispose()
    {
        _rsa.Dispose();
        OidcLogoutTokenValidator.ResetReplaysForTests();
    }

    [Fact]
    public async Task IdToken_WithoutCriticalHeader_IsAccepted()
    {
        // The positive control the rejections below are read against: this fixture differs from them by
        // the header member and nothing else, so a rejection there is attributable to crit.
        var result = await _idTokenValidator.ValidateAsync(IdToken(), Options(), TestContext.Current.CancellationToken);

        Assert.False(result.IsError, result.Error);
    }

    [Theory]
    [MemberData(nameof(CriticalHeaderShapes))]
    public async Task IdToken_WithCriticalHeader_IsRejected(string shape, object crit)
    {
        var token = IdToken(new Dictionary<string, object> { ["crit"] = crit });

        var result = await _idTokenValidator.ValidateAsync(token, Options(), TestContext.Current.CancellationToken);

        Assert.True(result.IsError, shape);
        Assert.Contains("critical header", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task IdToken_CriticalHeaderNamingAProcessedExtension_IsStillRejected()
    {
        // A provider that marks a member critical AND supplies it gets no better treatment. The plugin
        // reads no JWS extension, so "understood and processed" is false for every name that can appear.
        var token = IdToken(new Dictionary<string, object>
        {
            ["crit"] = new[] { UnknownExtension },
            [UnknownExtension] = true,
        });

        var result = await _idTokenValidator.ValidateAsync(token, Options(), TestContext.Current.CancellationToken);

        Assert.True(result.IsError);
    }

    [Fact]
    public async Task LogoutToken_WithoutCriticalHeader_IsAccepted()
    {
        var result = await _logoutValidator.ValidateAsync(LogoutToken(), Options(), DateTime.UtcNow);

        Assert.True(result.IsValid, result.ReasonCode);
        Assert.Equal("user-1", result.Subject);
    }

    [Theory]
    [MemberData(nameof(CriticalHeaderShapes))]
    public async Task LogoutToken_WithCriticalHeader_IsRejected(string shape, object crit)
    {
        var token = LogoutToken(new Dictionary<string, object> { ["crit"] = crit });

        var result = await _logoutValidator.ValidateAsync(token, Options(), DateTime.UtcNow);

        Assert.False(result.IsValid, shape);
        Assert.Equal(OidcLogoutTokenValidator.RejectReason.CriticalHeader, result.ReasonCode);
    }

    [Fact]
    public async Task LogoutToken_CriticalHeaderRefusal_IsNotTheGenericInvalidCode()
    {
        // The code is what an operator alerts on. Collapsing this into signature_or_time_invalid would
        // report a provider defect as a forgery attempt, and the two want different responses.
        var result = await _logoutValidator.ValidateAsync(
            LogoutToken(new Dictionary<string, object> { ["crit"] = new[] { UnknownExtension } }), Options(), DateTime.UtcNow);

        Assert.NotEqual(OidcLogoutTokenValidator.RejectReason.Invalid, result.ReasonCode);
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
        // The gate is not the fail-closed floor and must not pretend to be one: a header it cannot read is
        // passed on to the handler, which refuses the token on its own terms and with an accurate reason.
        // These inputs also reach the two catch arms from outside - the back-channel endpoint is anonymous,
        // so an unhandled decode or parse failure here would be a 500 an unauthenticated caller can drive.
        Assert.True(OidcSignatureKeys.TokenHasNoCriticalHeader(token));
    }

    [Fact]
    public void HeaderWithoutCrit_IsAcceptedByThePredicate()
    {
        // The predicate's own positive control: it must not refuse every token it can read.
        Assert.True(OidcSignatureKeys.TokenHasNoCriticalHeader(IdToken()));
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

    private string IdToken(IDictionary<string, object>? header = null) =>
        Sign(new Dictionary<string, object> { ["sub"] = "user-1", ["preferred_username"] = "alice" }, header);

    private string LogoutToken(IDictionary<string, object>? header = null) =>
        Sign(
            new Dictionary<string, object>
            {
                ["events"] = new Dictionary<string, object> { [LogoutEvent] = new Dictionary<string, object>() },
                ["jti"] = Guid.NewGuid().ToString(),
                ["sub"] = "user-1",
            },
            header);

    private string Sign(IDictionary<string, object> claims, IDictionary<string, object>? header)
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
            AdditionalHeaderClaims = header,
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(_rsa) { KeyId = KeyId }, SecurityAlgorithms.RsaSha256),
        });
    }
}
