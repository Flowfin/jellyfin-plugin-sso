// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// A token may not vouch for its own signing key (#1004). RFC 7515 lets a JWS header carry the key it was
/// signed with - inline as <c>x5c</c>, or by reference as <c>jku</c> / <c>x5u</c> - and a verifier that
/// reads any of them accepts whatever the attacker attached, which is a complete authentication bypass on
/// both JWT paths this plugin runs. The trust root here is the discovery JWKS and nothing else.
/// <para>
/// EVERY ROW HERE ASSERTS A REJECTION, AND A REJECTION IS THE CHEAPEST THING IN THE WORLD TO GET WRONG:
/// a fixture the verifier never understood is refused for its malformedness and the row goes green while
/// the property it names does not hold. That is not hypothetical, it is the finding #1052 was split out
/// for, measured on an earlier attempt at this battery whose <c>x5c</c> carried a SubjectPublicKeyInfo
/// where RFC 7515 §4.1.6 requires a DER certificate. So each rejection row is paired with a control that
/// makes the attack real:
/// </para>
/// <para>
/// <see cref="TheForgedToken_ValidatesOnceItsOwnKeyIsAdvertised"/> proves the attacker's token is valid in
/// every respect except whose key signed it, so the rejections above cannot be coming from a claim, a
/// time bound, an algorithm or a malformed segment. <see
/// cref="TheX5cFixture_AuthenticatesAVerifierThatReadsIt"/> goes one step further for the inline case: it
/// takes the SHIPPED validation basis, adds the one behaviour the rows say is absent - a spec-correct
/// <c>x5c</c>-reading resolver - and requires the forgery to be ACCEPTED. A fixture that cannot pass that
/// test cannot fail the rows for the reason they name.
/// </para>
/// <para>
/// WHAT IS PROVEN UNEVENLY, said here rather than left to be assumed from the row count. The <c>x5c</c>
/// rows were run against a build whose shipped basis resolves the header certificate, and all three go
/// red there, the endpoint row included. The <c>jku</c> and <c>x5u</c> rows had no such run: a faithful
/// weakening would have to fetch the URL, which means writing the vulnerability into the plugin rather
/// than into a test double. They rest on the positive control alone, which is weaker, and it is the reason
/// this paragraph exists.
/// </para>
/// </summary>
public sealed class OidcHeaderKeyMaterialTests : IDisposable
{
    private const string Issuer = "https://idp.example.test";
    private const string ClientId = "jellyfin-client";
    private const string TrustedKeyId = "trusted-signing-key";

    /// <summary>
    /// The three RFC 7515 header members that carry, or point at, the key material a JWS was signed with:
    /// <c>x5c</c> inline (§4.1.6), <c>jku</c> and <c>x5u</c> by URL (§4.1.2, §4.1.5).
    /// </summary>
    public static TheoryData<string> HeaderKeyMaterialMembers() => new() { "x5c", "jku", "x5u" };

    private readonly RSA _trusted = RSA.Create(2048);
    private readonly RSA _attacker = RSA.Create(2048);
    private readonly OidcIdTokenValidator _idTokenValidator = new();
    private readonly OidcLogoutTokenValidator _logoutValidator = new();
    private readonly DateTime _now = DateTime.UtcNow;

    public void Dispose()
    {
        _trusted.Dispose();
        _attacker.Dispose();
        OidcLogoutTokenValidator.ResetReplaysForTests();
    }

    [Theory]
    [MemberData(nameof(HeaderKeyMaterialMembers))]
    public async Task IdToken_SignedByAKeyOnlyItsOwnHeaderVouchesFor_IsRejected(string member)
    {
        var token = ForgedToken(member);

        // The fixture is only worth anything if the member actually reached the header, so that is read
        // back off the produced token rather than trusted from the descriptor that asked for it.
        Assert.True(new JsonWebToken(token).TryGetHeaderValue<object>(member, out _));

        var result = await _idTokenValidator.ValidateAsync(token, TrustedOptions(), TestContext.Current.CancellationToken);

        Assert.True(result.IsError);
        Assert.Null(result.User);
    }

    [Theory]
    [MemberData(nameof(HeaderKeyMaterialMembers))]
    public async Task LogoutToken_SignedByAKeyOnlyItsOwnHeaderVouchesFor_IsRejected(string member)
    {
        // The back-channel path shares the one validation basis, so it must share the property; a drift
        // here would revoke sessions on an attacker's say-so without ever touching the login path.
        var result = await _logoutValidator.ValidateAsync(ForgedToken(member, LogoutClaims()), TrustedOptions(), _now);

        Assert.False(result.IsValid);
        Assert.Null(result.Subject);
        Assert.Null(result.SessionIndex);
    }

    [Theory]
    [MemberData(nameof(HeaderKeyMaterialMembers))]
    public async Task TheForgedToken_ValidatesOnceItsOwnKeyIsAdvertised(string member)
    {
        // The control for every rejection above. Same bytes, same header, one difference: the discovery
        // JWKS now advertises the attacker's key. If this did not validate, the rows above would be
        // refusing the token for a claim, a time bound, an algorithm or a broken segment, and would prove
        // nothing about header-supplied key material.
        var result = await _idTokenValidator.ValidateAsync(
            ForgedToken(member), OptionsFor(JwksFor(_attacker)), TestContext.Current.CancellationToken);

        Assert.False(result.IsError, result.Error);
        Assert.Equal("RS256", result.SignatureAlgorithm);
    }

    [Fact]
    public async Task TheX5cFixture_AuthenticatesAVerifierThatReadsIt()
    {
        // #1052's technique, run against the inline case where the fixture bytes are the thing that can be
        // wrong. The basis is the SHIPPED one, taken from the production builder rather than reassembled
        // here, plus the single behaviour this file says is absent: a resolver that reads x5c the way RFC
        // 7515 §4.1.6 defines it. Under that resolver the forgery MUST authenticate. It failing would mean
        // the certificate in the header is not one a spec-correct reader can use, and every x5c row above
        // would be green for the wrong reason.
        var ephemeralKeys = new List<IDisposable>();
        var parameters = OidcSignatureKeys.BuildValidationParameters(TrustedOptions(), ephemeralKeys);
        parameters.IssuerSigningKeyResolver = (_, securityToken, _, _) => KeysFromX5c(securityToken);

        try
        {
            var result = await new JsonWebTokenHandler().ValidateTokenAsync(ForgedToken("x5c"), parameters);

            Assert.True(result.IsValid, result.Exception?.Message);
        }
        finally
        {
            ephemeralKeys.ForEach(key => key.Dispose());
        }
    }

    [Fact]
    public async Task TheTrustedKey_StillValidates_OnBothPaths()
    {
        // The floor under the whole file: the ordinary token from the ordinary key is accepted. Without it
        // a basis that refused everything would satisfy every rejection row above.
        var idToken = SignedBy(_trusted, TrustedKeyId, null, null);
        var idResult = await _idTokenValidator.ValidateAsync(idToken, TrustedOptions(), TestContext.Current.CancellationToken);
        Assert.False(idResult.IsError, idResult.Error);

        var logoutResult = await _logoutValidator.ValidateAsync(
            SignedBy(_trusted, TrustedKeyId, null, LogoutClaims()), TrustedOptions(), _now);
        Assert.True(logoutResult.IsValid, logoutResult.ReasonCode);
        Assert.Equal("user-1", logoutResult.Subject);
    }

    // --- helpers ---

    internal static Dictionary<string, object> LogoutClaims() => new()
    {
        ["sub"] = "user-1",
        ["jti"] = Guid.NewGuid().ToString("N"),
        ["events"] = new Dictionary<string, object>
        {
            ["http://schemas.openid.net/event/backchannel-logout"] = new Dictionary<string, object>(),
        },
    };

    // The attacker's key material as the named header member would carry it: x5c inline as a base64 DER
    // certificate chain, jku and x5u as URLs the attacker controls. The URLs are never fetched by this
    // plugin, which is the property under test; they are here because a reference is the other half of the
    // same trust mistake and a verifier that resolved one would land on the same key.
    private static Dictionary<string, object> HeaderFor(string member, RSA key) => member switch
    {
        "x5c" => new Dictionary<string, object> { ["x5c"] = new[] { Convert.ToBase64String(SelfSignedDer(key)) } },
        "jku" => new Dictionary<string, object> { ["jku"] = "https://evil.example.net/jwks.json" },
        "x5u" => new Dictionary<string, object> { ["x5u"] = "https://evil.example.net/chain.pem" },
        _ => throw new ArgumentOutOfRangeException(nameof(member), member, "Unknown header member."),
    };

    private static byte[] SelfSignedDer(RSA key)
    {
        var request = new CertificateRequest("CN=idp.example.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return certificate.Export(X509ContentType.Cert);
    }

    // RFC 7515 §4.1.6: the first x5c entry is the base64 DER of the certificate whose public key signed the
    // JWS. Reading it is exactly the behaviour the plugin must not have, which is why it exists only here.
    private static IEnumerable<SecurityKey> KeysFromX5c(SecurityToken securityToken)
    {
        if (securityToken is not JsonWebToken jwt || !jwt.TryGetHeaderValue<string[]>("x5c", out var chain) || chain.Length == 0)
        {
            return [];
        }

        return [new X509SecurityKey(X509CertificateLoader.LoadCertificate(Convert.FromBase64String(chain[0])))];
    }

    private static string Material(RSA rsa)
    {
        var p = rsa.ExportParameters(false);
        return "\"n\":\"" + Base64UrlEncoder.Encode(p.Modulus) + "\",\"e\":\"" + Base64UrlEncoder.Encode(p.Exponent) + "\"";
    }

    private static string SignedBy(RSA key, string? keyId, IDictionary<string, object>? headers, IDictionary<string, object>? claims)
    {
        var now = DateTime.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = ClientId,
            IssuedAt = now - TimeSpan.FromMinutes(1),
            NotBefore = now - TimeSpan.FromMinutes(1),
            Expires = now + TimeSpan.FromMinutes(5),
            Claims = claims ?? new Dictionary<string, object> { ["sub"] = "user-1" },
            SigningCredentials = keyId is null
                ? new SigningCredentials(new RsaSecurityKey(key), SecurityAlgorithms.RsaSha256)
                : new SigningCredentials(new RsaSecurityKey(key) { KeyId = keyId }, SecurityAlgorithms.RsaSha256),
        };

        if (headers is not null)
        {
            descriptor.AdditionalHeaderClaims = headers;
        }

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    // The forgery: signed by a key the provider never advertised, carrying that key in the header member
    // under test. No kid, so nothing in the token even claims to name a trusted key - the header material
    // is the only thing offered in support of the signature.
    private string ForgedToken(string member, IDictionary<string, object>? claims = null) =>
        SignedBy(_attacker, null, HeaderFor(member, _attacker), claims);

    private string JwksFor(RSA rsa) =>
        "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"" + TrustedKeyId + "\"," + Material(rsa) + "}]}";

    private OidcClientOptions TrustedOptions() => OptionsFor(JwksFor(_trusted));

    private static OidcClientOptions OptionsFor(string jwks) => new()
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

/// <summary>
/// The endpoint half (#1004): at least one forgery has to cross the production entry point rather than a
/// basis a test assembled. The back-channel logout endpoint is the one that matters, because it is
/// anonymous and the signature is the whole of its authentication - a header-supplied key accepted here
/// revokes a named user's sessions on an attacker's request.
/// </summary>
[Collection("SSOController")]
public sealed class OidcHeaderKeyMaterialEndpointTests : IDisposable
{
    private const string Authority = "https://idp-header-material.example.test";
    private static readonly Guid UserA = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");

    private readonly OidcTokenFixture _fixture = new(Authority, "jf");
    private readonly RSA _attacker = RSA.Create(2048);

    public OidcHeaderKeyMaterialEndpointTests() => OidcLogoutTokenValidator.ResetReplaysForTests();

    public void Dispose()
    {
        _fixture.Dispose();
        _attacker.Dispose();
        OidcLogoutTokenValidator.ResetReplaysForTests();
    }

    [Fact]
    public async Task BackChannelLogout_WithAKeySuppliedByTheTokenHeader_IsRefused_AndRevokesNothing()
    {
        // A captured session that MATCHES the forged token's sub and sid is seeded deliberately. Without one
        // the endpoint has nothing it could revoke, so "no revoke happened" would be true however the token
        // was judged and the row would prove nothing. With one, a verifier that read the header's key
        // material revokes UserA and empties the capture, which is what the weakening run has to show.
        var harness = new SsoControllerHarness(
            c =>
            {
                c.EnableSingleLogout = true;
                c.OidConfigs["kc"] = new OidConfig
                {
                    Enabled = true,
                    OidEndpoint = Authority,
                    OidClientId = "jf",
                    EnableBackChannelLogout = true,
                };
                c.LogoutSessions["a"] = new LogoutSession
                {
                    Protocol = "OpenID",
                    Provider = "kc",
                    Subject = "sub-1",
                    SessionIndex = "sess-9",
                    UserId = UserA,
                    IdToken = "raw.id.token",
                };
            },
            httpResponder: Responder);

        var result = await harness.Controller.OidBackChannelLogout("kc", ForgedLogoutToken());

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("Logout token could not be processed", content.Content);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string>());
        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("a")));
    }

    // A logout_token for a real subject, signed by a key the provider never advertised, carrying that key
    // inline as an RFC 7515 x5c chain. Everything else about it is well formed.
    private string ForgedLogoutToken()
    {
        var request = new CertificateRequest("CN=idp-header-material.example.test", _attacker, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var now = DateTime.UtcNow;
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Authority,
            Audience = "jf",
            IssuedAt = now - TimeSpan.FromMinutes(1),
            NotBefore = now - TimeSpan.FromMinutes(1),
            Expires = now + TimeSpan.FromMinutes(5),
            Claims = new Dictionary<string, object>
            {
                ["sub"] = "sub-1",
                ["sid"] = "sess-9",
                ["jti"] = Guid.NewGuid().ToString("N"),
                ["events"] = new Dictionary<string, object>
                {
                    ["http://schemas.openid.net/event/backchannel-logout"] = new Dictionary<string, object>(),
                },
            },
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                ["x5c"] = new[] { Convert.ToBase64String(certificate.Export(X509ContentType.Cert)) },
            },
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(_attacker), SecurityAlgorithms.RsaSha256),
        });
    }

    // Serves the fixture's discovery document and its JWKS - which advertises only the provider's real
    // signing key - so the refusal is about whose key signed the token and not a failure to reach the
    // provider. Any other URL 404s, so an unexpected outbound call is visible rather than silent.
    private HttpResponseMessage Responder(HttpRequestMessage request)
    {
        var url = request.RequestUri!.AbsoluteUri;
        if (url == _fixture.DiscoveryUrl)
        {
            return Json(_fixture.Discovery());
        }

        return url == _fixture.JwksUrl ? Json(_fixture.Jwks()) : new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private static HttpResponseMessage Json(string body) => new HttpResponseMessage(HttpStatusCode.OK)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json"),
    };
}
