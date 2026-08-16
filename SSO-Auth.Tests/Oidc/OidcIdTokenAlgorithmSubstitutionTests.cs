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
/// What refuses an algorithm substitution on the LOGIN path, asked of the login path itself (#1004). A
/// forged <c>alg</c> header is the oldest JWT attack there is, and the plugin holds it in two different
/// ways on its two token paths, which is why proving it on one does not prove it on the other.
/// <para>
/// On the back-channel <c>logout_token</c> path <see cref="OidcSignatureKeys.TokenHasAllowedAlgorithm"/>
/// judges <c>alg</c> BEFORE the handler runs (#1164), and <c>OidcLogoutTokenValidatorTests</c> pins that
/// gate's verdict on these same shapes. The id_token path is deliberately excluded from that gate, because
/// <c>OidcClient</c> depends on the <c>invalid_signature</c> string the handler produces to refresh the
/// JWKS and retry across a signing-key rotation. So on the path an unauthenticated visitor actually drives,
/// the answer comes from inside the handler and from nothing the plugin wrote, and nothing asked it. Every
/// rejection row here runs through <see cref="OidcIdTokenValidator"/> rather than through a basis
/// reassembled in the test.
/// </para>
/// <para>
/// EVERY REJECTION ROW IS PAIRED WITH A CONTROL, for the reason #1052 was split out of this issue: a
/// fixture the verifier never understood is refused for being malformed, and the row goes green while the
/// property it names does not hold. Two kinds of control appear below.
/// <see cref="TheUntamperedToken_Authenticates"/> and
/// <see cref="TheSpellingIsTheOnlyDefect_TheCorrectlySpelledTwinAuthenticates"/> are differential: the same
/// bytes with the one deliberate defect removed MUST log in, so a refusal above cannot be coming from a
/// claim, a time bound, the <c>kid</c> screen or a segment that will not decode. The remaining three
/// install into the SHIPPED basis from <see cref="OidcSignatureKeys.BuildValidationParameters"/> the exact
/// behaviour a row says is absent, and ask what happens.
/// </para>
/// <para>
/// WHICH CONTROL ANSWERS WAS MEASURED RATHER THAN ASSUMED, and it is not the one the shapes suggest. For
/// <c>alg: none</c> and for a stripped signature the answer is <see cref="TokenValidationParameters.RequireSignedTokens"/>
/// ALONE: admitting <c>none</c> to <see cref="OidcSignatureKeys.AllowedSignatureAlgorithms"/> leaves both
/// refused (<see cref="TheAlgNoneToken_StaysRefused_WhenNoneIsAdmittedToTheAllowlist"/>), and dropping the
/// signed-token requirement alone lets the forgery through
/// (<see cref="TheAlgNoneToken_Authenticates_OnceSignedTokensAreNoLongerRequired"/>). An empty signature is
/// never carried as far as the algorithm, so the allowlist never speaks for these shapes and a reader who
/// credited it would be crediting the wrong control.
/// </para>
/// <para>
/// The case-folded spelling is the same correction one step over. The allowlist comparison is Ordinal, but
/// it is not what refuses <c>rs256</c>: with that spelling admitted to the allowlist the token is STILL
/// refused (<see cref="TheCaseFoldedSpelling_StaysRefused_WhenAdmittedToTheAllowlist"/>), as
/// <c>IDX10511</c>, because the algorithm name is also what resolves a signature provider for the key and
/// no provider answers to a lower-case spelling. That row is the falsifiable part: the day a library
/// version folds case there, it goes red and the plugin's own Ordinal list becomes the only thing standing.
/// </para>
/// <para>
/// PROVEN UNEVENLY, and the rows do not hide which way. Only two families can be reddened by weakening
/// the SHIPPED code: setting <c>RequireSignedTokens</c> to <c>false</c> in
/// <see cref="OidcSignatureKeys.BuildValidationParameters"/> turns the four <c>alg: none</c> rows and the
/// stripped-signature row red together and moves nothing else. The other two rest on the basis-level
/// positive controls instead, because the production change that would redden them is the vulnerability
/// itself: for the case-folded family a verifier that folds the algorithm name, for HS256 a converter that
/// builds a symmetric key out of an RSA public key. Each control installs exactly that behaviour into the
/// shipped basis and requires the forgery to be ACCEPTED, which is the same statement made from the other
/// side rather than a weaker one.
/// </para>
/// </summary>
public sealed class OidcIdTokenAlgorithmSubstitutionTests : IDisposable
{
    private const string Issuer = "https://idp.example.test";
    private const string ClientId = "jellyfin-client";
    private const string KeyId = "advertised-signing-key";

    private readonly RSA _rsa = RSA.Create(2048);
    private readonly OidcIdTokenValidator _validator = new();

    public void Dispose() => _rsa.Dispose();

    [Theory]
    [InlineData("none")]
    [InlineData("None")]
    [InlineData("NONE")]
    [InlineData("nOnE")]
    public async Task AlgNoneInAnySpelling_IsRejected_AndYieldsNoPrincipal(string spelling)
    {
        // The unauthenticated token. A verifier that reads alg out of the header and believes it logs in
        // whoever asks. The case variants are here because a screen written as a comparison against one
        // spelling is the classic way past a check that looked present.
        var result = await _validator.ValidateAsync(
            UnsignedToken(spelling), Options(), TestContext.Current.CancellationToken);

        Assert.True(result.IsError);
        Assert.Null(result.User);
    }

    [Theory]
    [InlineData("rs256")]
    [InlineData("Rs256")]
    [InlineData("rS256")]
    public async Task ACaseFoldedSpellingOfATrustedAlgorithm_IsRejected(string spelling)
    {
        // Not a malformed token: the signature is computed over this exact header with the provider's real
        // private key, so the bytes verify under a verifier that reads the header as RS256. What must not
        // happen is a spelling the basis does not list being treated as the neighbour it resembles.
        var result = await _validator.ValidateAsync(
            GenuinelySignedToken(spelling), Options(), TestContext.Current.CancellationToken);

        Assert.True(result.IsError);
        Assert.Null(result.User);
    }

    [Fact]
    public async Task Hs256KeyedWithTheAdvertisedPublicKey_IsRejected()
    {
        // Algorithm confusion in its original form: MAC the token with the provider's PUBLIC key as the
        // shared secret. That material is in the discovery JWKS, so everyone who can fetch a URL holds it.
        // This is not OidcAdvertisedSymmetricKeyTests' question - there a provider published an HMAC key
        // and the converter had to drop it; here nothing symmetric is advertised at all and the attacker
        // repurposes the asymmetric key that already is.
        var result = await _validator.ValidateAsync(
            Hs256ForgedWithThePublicKey(), Options(), TestContext.Current.CancellationToken);

        Assert.True(result.IsError);
        Assert.Null(result.User);
    }

    [Fact]
    public async Task ATokenWithItsSignatureStripped_IsRejected()
    {
        // alg stays RS256, so nothing about the header is unusual and only the third segment is gone. This
        // is the shape a proxy or a truncating log produces by accident as well as the one an attacker
        // produces on purpose.
        var token = SignedRs256Token();

        var result = await _validator.ValidateAsync(
            token[..(token.LastIndexOf('.') + 1)], Options(), TestContext.Current.CancellationToken);

        Assert.True(result.IsError);
        Assert.Null(result.User);
    }

    [Fact]
    public async Task TheUntamperedToken_Authenticates()
    {
        // The differential control for the stripped-signature row and the floor under every row here: this
        // fixture's issuer, audience, lifetime, kid and claims are all acceptable, so a refusal above is
        // about what this file says it is about. Without this row a basis that refused everything would
        // satisfy each rejection.
        var result = await _validator.ValidateAsync(
            SignedRs256Token(), Options(), TestContext.Current.CancellationToken);

        Assert.False(result.IsError, result.Error);
        Assert.Equal("RS256", result.SignatureAlgorithm);
    }

    [Fact]
    public async Task TheSpellingIsTheOnlyDefect_TheCorrectlySpelledTwinAuthenticates()
    {
        // The differential control for the case-folded rows. Same builder, same key, same payload bytes,
        // one string changed. If this failed, those rows would be recording a broken fixture.
        var result = await _validator.ValidateAsync(
            GenuinelySignedToken("RS256"), Options(), TestContext.Current.CancellationToken);

        Assert.False(result.IsError, result.Error);
        Assert.Equal("RS256", result.SignatureAlgorithm);
    }

    [Fact]
    public async Task TheAlgNoneToken_StaysRefused_WhenNoneIsAdmittedToTheAllowlist()
    {
        // Attribution, and it corrects the reading the shape invites. With "none" in the shipped allowlist
        // the token is refused anyway, so the algorithm list is NOT what the alg:none rows are evidence
        // about. Removing an entry from that list would leave them green and the property intact.
        var result = await ValidateAgainstShippedBasis(
            UnsignedToken("none"), p => p.ValidAlgorithms = [.. OidcSignatureKeys.AllowedSignatureAlgorithms, "none"]);

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task TheAlgNoneToken_Authenticates_OnceSignedTokensAreNoLongerRequired()
    {
        // #1052's technique, aimed at the control the row above rules out. The same bytes, the SHIPPED
        // basis rather than one reassembled here, and one field changed: RequireSignedTokens. Under it the
        // forgery MUST authenticate, which is what makes the alg:none rows evidence about that field.
        // Measured, not deduced: the allowlist is left untouched here and the token still logs in, because
        // an empty signature is never carried as far as the algorithm.
        var result = await ValidateAgainstShippedBasis(
            UnsignedToken("none"), p => p.RequireSignedTokens = false);

        Assert.True(result.IsValid, result.Exception?.Message);
    }

    [Fact]
    public async Task TheCaseFoldedSpelling_StaysRefused_WhenAdmittedToTheAllowlist()
    {
        // The same attribution for the case-folded family, and the row that keeps this file honest about
        // it. Admitting "rs256" to the shipped allowlist does not let the token in: the algorithm name also
        // selects the signature provider for the key, and none answers to that spelling, so the refusal
        // comes from the library rather than from the plugin's Ordinal list. Should a future version fold
        // case there, this row goes red and says so.
        var result = await ValidateAgainstShippedBasis(
            GenuinelySignedToken("rs256"),
            p => p.ValidAlgorithms = [.. OidcSignatureKeys.AllowedSignatureAlgorithms, "rs256"]);

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task TheCaseFoldedToken_Authenticates_OnceAProviderAnswersToThatSpelling()
    {
        // The positive control for the case-folded family, on the SAME BYTES rather than on a twin. The one
        // behaviour those rows say is absent - a verifier that treats "rs256" as RS256 - is installed into
        // the shipped basis as a crypto provider factory that folds the name, and under it the token MUST
        // authenticate. So the signature is genuine, the claims are acceptable, and the spelling is the
        // whole of the defect; a row that could not be turned green this way would be evidence of nothing.
        var result = await ValidateAgainstShippedBasis(
            GenuinelySignedToken("rs256"),
            p =>
            {
                p.ValidAlgorithms = [.. OidcSignatureKeys.AllowedSignatureAlgorithms, "rs256"];
                p.CryptoProviderFactory = new CaseFoldingCryptoProviderFactory();
            });

        Assert.True(result.IsValid, result.Exception?.Message);
    }

    [Fact]
    public async Task TheHs256Forgery_Authenticates_OnceItsAlgorithmAndKeyAreInTheBasis()
    {
        // The positive control for the confusion row: HS256 admitted to the allowlist and the public key
        // installed as the symmetric secret a confused verifier would derive from it. The forgery must be
        // ACCEPTED, which proves it is a well-formed HMAC over this issuer, audience and lifetime rather
        // than a token thrown out before the algorithm was ever reached.
        var result = await ValidateAgainstShippedBasis(
            Hs256ForgedWithThePublicKey(),
            p =>
            {
                p.ValidAlgorithms = [.. OidcSignatureKeys.AllowedSignatureAlgorithms, SecurityAlgorithms.HmacSha256];
                p.IssuerSigningKeys = [new SymmetricSecurityKey(_rsa.ExportSubjectPublicKeyInfo()) { KeyId = KeyId }];
            });

        Assert.True(result.IsValid, result.Exception?.Message);
    }

    // --- helpers ---

    private static string Base64Url(string json) => Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(json));

    private static string Header(string algorithm) =>
        Base64Url("{\"alg\":\"" + algorithm + "\",\"typ\":\"JWT\",\"kid\":\"" + KeyId + "\"}");

    // The claim set every fixture in this file shares: acceptable to this issuer, this audience and this
    // clock, so the algorithm is the only thing left for a verdict to be about.
    private static string Payload()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return "{\"iss\":\"" + Issuer + "\",\"aud\":\"" + ClientId + "\",\"sub\":\"user-1\",\"iat\":" + now
            + ",\"nbf\":" + (now - 60) + ",\"exp\":" + (now + 300) + "}";
    }

    // header.payload. - three segments with an empty signature, which is how RFC 7519 section 6.1 spells an
    // unsecured JWS.
    private static string UnsignedToken(string spelling) => Header(spelling) + "." + Base64Url(Payload()) + ".";

    // A real RSASSA-PKCS1-v1_5 / SHA-256 signature over THIS header, so the only thing wrong with the token
    // is how the header spells the algorithm. Built by hand because a library that owns the header would
    // rewrite the spelling under test.
    private string GenuinelySignedToken(string spelling)
    {
        var signingInput = Header(spelling) + "." + Base64Url(Payload());
        var signature = _rsa.SignData(
            Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return signingInput + "." + Base64UrlEncoder.Encode(signature);
    }

    private string SignedRs256Token() => new JsonWebTokenHandler().CreateToken(Descriptor(
        new SigningCredentials(new RsaSecurityKey(_rsa) { KeyId = KeyId }, SecurityAlgorithms.RsaSha256)));

    private string Hs256ForgedWithThePublicKey() => new JsonWebTokenHandler().CreateToken(Descriptor(
        new SigningCredentials(
            new SymmetricSecurityKey(_rsa.ExportSubjectPublicKeyInfo()) { KeyId = KeyId },
            SecurityAlgorithms.HmacSha256)));

    private SecurityTokenDescriptor Descriptor(SigningCredentials credentials) => new()
    {
        Issuer = Issuer,
        Audience = ClientId,
        IssuedAt = DateTime.UtcNow.AddMinutes(-1),
        NotBefore = DateTime.UtcNow.AddMinutes(-1),
        Expires = DateTime.UtcNow.AddMinutes(5),
        Claims = new Dictionary<string, object> { ["sub"] = "user-1" },
        SigningCredentials = credentials,
    };

    // Runs a token against the parameters the plugin actually ships, with one named control changed.
    // Reassembling a basis here instead would prove something about the test rather than about the plugin.
    private async Task<TokenValidationResult> ValidateAgainstShippedBasis(
        string token, Action<TokenValidationParameters> weaken)
    {
        var ephemeralKeys = new List<IDisposable>();
        try
        {
            var parameters = OidcSignatureKeys.BuildValidationParameters(Options(), ephemeralKeys);
            weaken(parameters);
            return await new JsonWebTokenHandler().ValidateTokenAsync(token, parameters);
        }
        finally
        {
            ephemeralKeys.ForEach(key => key.Dispose());
        }
    }

    private OidcClientOptions Options()
    {
        var parameters = _rsa.ExportParameters(false);
        var jwk = "{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"" + KeyId + "\",\"alg\":\"RS256\","
            + "\"n\":\"" + Base64UrlEncoder.Encode(parameters.Modulus) + "\","
            + "\"e\":\"" + Base64UrlEncoder.Encode(parameters.Exponent) + "\"}";
        return new OidcClientOptions
        {
            ClientId = ClientId,
            ClockSkew = TimeSpan.FromMinutes(5),
            ProviderInformation = new ProviderInformation
            {
                IssuerName = Issuer,
                KeySet = new Duende.IdentityModel.Jwk.JsonWebKeySet("{\"keys\":[" + jwk + "]}"),
            },
        };
    }

    // The spec-incorrect verifier the case-folded rows say does not exist here: one that answers to
    // "rs256" as though it were "RS256". Installed into the shipped basis by the control above, where it
    // has to turn the forgery into a valid login or the rows it stands behind mean nothing.
    private sealed class CaseFoldingCryptoProviderFactory : CryptoProviderFactory
    {
        public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key) =>
            base.IsSupportedAlgorithm(Canonical(algorithm), key);

        public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm) =>
            base.CreateForVerifying(key, Canonical(algorithm));

        private static string Canonical(string algorithm) =>
            string.Equals(algorithm, SecurityAlgorithms.RsaSha256, StringComparison.OrdinalIgnoreCase)
                ? SecurityAlgorithms.RsaSha256
                : algorithm;
    }
}
