// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api.Crypto;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// The ONE OpenID signature-validation basis, shared by every token the plugin verifies against a
/// provider's discovery JWKS - the id_token (<see cref="OidcIdTokenValidator"/>) and the back-channel
/// <c>logout_token</c> (<see cref="OidcLogoutTokenValidator"/>, #962). Centralising the asymmetric-only
/// algorithm allowlist and the JWK→<see cref="SecurityKey"/> conversion here means there is provably no
/// second, laxer verification path: a token type cannot accidentally accept HS*, <c>none</c>, an
/// under-strength key, or malformed key material that the other type rejects.
/// </summary>
internal static class OidcSignatureKeys
{
    /// <summary>
    /// The longest token-header <c>kid</c> the plugin will look a key up by. Every shape a real provider
    /// mints is far shorter - a base64url certificate thumbprint is 43 characters, a UUID 36 - so the cap
    /// is set well above the field rather than close to it: the value being bounded is what matters, and a
    /// tight cap would trade a hypothetical attack for a real lockout of an IdP nobody surveyed.
    /// </summary>
    private const int MaxKeyIdLength = 256;

    // RFC 7519 §5.1: the "application/" prefix on a typ value MAY be omitted, so both spellings of one
    // media type have to be recognised as the same declaration.
    private const string MediaTypePrefix = "application/";

    // The JWT media types this plugin can attribute to a purpose, and therefore the only ones a typ screen
    // can act on. Each is a registered value with one meaning, so a token carrying it is telling the reader
    // which endpoint minted it: RFC 9068 for an OAuth access token, RFC 9449 for a DPoP proof, RFC 8417 for
    // a security event token, and OIDC Back-Channel Logout 1.0 §2.4 for a logout_token.
    private const string AccessTokenType = "at+jwt";
    private const string DpopProofType = "dpop+jwt";
    private const string SecurityEventType = "secevent+jwt";
    private const string LogoutTokenType = "logout+jwt";

    // What each entry point refuses. Two lists rather than one because the families are not symmetric: a
    // logout_token IS a security event token, so secevent+jwt and logout+jwt are its own types and only
    // foreign to the id_token path.
    private static readonly ImmutableArray<string> ForeignToIdToken =
        [AccessTokenType, DpopProofType, SecurityEventType, LogoutTokenType];

    private static readonly ImmutableArray<string> ForeignToLogoutToken = [AccessTokenType, DpopProofType];

    /// <summary>Gets the asymmetric signature algorithms the plugin accepts (RFC 7518); symmetric HS* and <c>none</c> are rejected whatever discovery advertises.</summary>
    /// <remarks>Immutable rather than get-only, because the same instance is handed by reference into the validation parameters of both token types, and a writable array would let one in-assembly write change what both accept with nothing noticing (#1190).</remarks>
    internal static ImmutableArray<string> AllowedSignatureAlgorithms { get; } =
    [
        "RS256", "RS384", "RS512",
        "PS256", "PS384", "PS512",
        "ES256", "ES384", "ES512",
    ];

    /// <summary>Whether a token-header <c>kid</c> may be used as a key-lookup value: the RFC 3986 unreserved set only, up to <see cref="MaxKeyIdLength"/>.</summary>
    /// <remarks>
    /// There is no live sink today, the value is only compared ordinally against in-memory key ids, so this is the
    /// standing mitigation for the <c>kid</c>-injection class applied ahead of any future consumer. An absent
    /// <c>kid</c> is the ordinary try-every-key case, so null, empty and whitespace are accepted.
    /// </remarks>
    /// <param name="keyId">The <c>kid</c> read from the token header, or null when the header carries none.</param>
    /// <returns><c>true</c> when the value may reach a key lookup.</returns>
    internal static bool IsAcceptableKeyId(string? keyId)
    {
        if (string.IsNullOrWhiteSpace(keyId))
        {
            return true;
        }

        if (keyId.Length > MaxKeyIdLength)
        {
            return false;
        }

        foreach (var character in keyId)
        {
            var unreserved = (character >= 'A' && character <= 'Z')
                || (character >= 'a' && character <= 'z')
                || (character >= '0' && character <= '9')
                || character == '-' || character == '.' || character == '_' || character == '~';

            if (!unreserved)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Whether a compact-serialized JWT's header <c>kid</c> passes <see cref="IsAcceptableKeyId"/>; both token paths call this ahead of validation, so the constraint has one definition.</summary>
    /// <remarks>A token this cannot read at all is reported as acceptable rather than refused, and that is not a fail-open: the handler that follows owns signature, issuer, audience and lifetime and refuses an unreadable token on its own terms, so a refusal from here would only replace an accurate reason with a misleading one.</remarks>
    /// <param name="token">The raw compact-serialized JWT.</param>
    /// <returns><c>false</c> only when a <c>kid</c> was positively read and is outside the allowlist.</returns>
    internal static bool TokenHasAcceptableKeyId(string? token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return true;
        }

        string? keyId;
        try
        {
            keyId = new JsonWebToken(token).Kid;
        }
        catch (ArgumentException)
        {
            // Not a readable JWT. The handler rejects it on its own terms; see the remark above.
            return true;
        }
        catch (FormatException)
        {
            // The same case arriving under another name. A token with more than three segments gets far
            // enough for the library to base64url-decode a LATER segment, and that decode raises
            // FormatException rather than the malformed-token ArgumentException the line above catches -
            // so an anonymous caller could turn this gate into a 500. Unreadable is unreadable whichever
            // exception says so; the handler still owns the refusal.
            return true;
        }

        return IsAcceptableKeyId(keyId);
    }

    /// <summary>Whether a compact-serialized JWT's header <c>alg</c> is in <see cref="AllowedSignatureAlgorithms"/>, judged before the handler so an algorithm attack is audited as one rather than as a bad signature (#1164).</summary>
    /// <remarks>
    /// The handler refuses a disallowed algorithm on its own, so this changes nothing about what is accepted, only
    /// what the refusal can be called. Called by the back-channel <c>logout_token</c> path only, because the id_token
    /// path depends on the <c>invalid_signature</c> contract the handler produces. Comparison is ordinal, so a case
    /// variant is refused; an unreadable token is reported as allowed for the same reason as <see cref="TokenHasAcceptableKeyId"/>.
    /// </remarks>
    /// <param name="token">The raw compact-serialized JWT.</param>
    /// <returns><c>false</c> only when an <c>alg</c> was positively read and is outside the allowlist.</returns>
    internal static bool TokenHasAllowedAlgorithm(string? token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return true;
        }

        string? algorithm;
        try
        {
            algorithm = new JsonWebToken(token).Alg;
        }
        catch (ArgumentException)
        {
            // Not a readable JWT. The handler rejects it on its own terms; see the remark above.
            return true;
        }
        catch (FormatException)
        {
            // A later segment that will not base64url-decode, the shape TokenHasAcceptableKeyId documents.
            return true;
        }

        return string.IsNullOrEmpty(algorithm) || AllowedSignatureAlgorithms.Contains(algorithm, StringComparer.Ordinal);
    }

    /// <summary>Whether a compact-serialized JWT's header is free of the <c>crit</c> parameter (RFC 7515 §4.1.11, #1038); this plugin implements no JWS extension, so the rule collapses to a presence test shared by both token paths.</summary>
    /// <remarks>
    /// A provider marks an extension critical because ignoring it changes what the token asserts, so accepting one
    /// means acting on an assertion whose constraints were dropped. The member is looked up by presence as
    /// <c>object</c> rather than read as a typed array, because a typed read reports a string-valued <c>crit</c> as
    /// absent and admits a malformed header; an unreadable token is reported as free of it for the same reason as <see cref="TokenHasAcceptableKeyId"/>.
    /// </remarks>
    /// <param name="token">The raw compact-serialized JWT.</param>
    /// <returns><c>false</c> only when a header member named <c>crit</c> was positively read.</returns>
    internal static bool TokenHasNoCriticalHeader(string? token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return true;
        }

        try
        {
            return !new JsonWebToken(token).TryGetHeaderValue<object>("crit", out _);
        }
        catch (ArgumentException)
        {
            // Not a readable JWT. The handler rejects it on its own terms; see the remark above.
            return true;
        }
        catch (FormatException)
        {
            // A later segment that will not base64url-decode, the same shape TokenHasAcceptableKeyId
            // documents. This endpoint is anonymous, so an escaping decode failure would be a 500 an
            // unauthenticated caller can drive.
            return true;
        }
    }

    /// <summary>
    /// Whether a compact-serialized JWT may be read as an id_token, judged on the <c>typ</c> header alone
    /// (#1317). A token declaring itself an access token, a DPoP proof, a security event or a
    /// <c>logout_token</c> was minted for a different endpoint and is refused here rather than left to be
    /// separated by the shape of its payload.
    /// </summary>
    /// <param name="token">The raw compact-serialized JWT.</param>
    /// <returns><c>false</c> only when the header positively declares one of the foreign media types.</returns>
    internal static bool TokenTypeIsAcceptableForIdToken(string? token) => !DeclaresForeignType(token, ForeignToIdToken);

    /// <summary>
    /// Whether a compact-serialized JWT may be read as a back-channel <c>logout_token</c>, judged on the
    /// <c>typ</c> header alone (#1317). The foreign set is smaller than the id_token's on purpose:
    /// <c>secevent+jwt</c> and <c>logout+jwt</c> name this token's OWN family, and an id_token has no
    /// reserved media type to name, so the reverse confusion is caught by the forbidden <c>nonce</c> and
    /// the required <c>events</c> member instead.
    /// </summary>
    /// <param name="token">The raw compact-serialized JWT.</param>
    /// <returns><c>false</c> only when the header positively declares one of the foreign media types.</returns>
    internal static bool TokenTypeIsAcceptableForLogoutToken(string? token) => !DeclaresForeignType(token, ForeignToLogoutToken);

    // Whether the header declares one of the media types this plugin can attribute to another purpose. RFC 7519
    // §5.1 lets a producer omit the "application/" prefix and media types are case-insensitive, so both spellings
    // are matched rather than compared ordinally. Absent, empty, non-string and unrecognised values all return false,
    // because typ is optional in an id_token and anything narrower would refuse working providers.
    private static bool DeclaresForeignType(string? token, ImmutableArray<string> foreign)
    {
        if (string.IsNullOrEmpty(token))
        {
            return false;
        }

        try
        {
            if (!new JsonWebToken(token).TryGetHeaderValue<string>("typ", out var declared) || string.IsNullOrEmpty(declared))
            {
                return false;
            }

            var mediaType = declared.StartsWith(MediaTypePrefix, StringComparison.OrdinalIgnoreCase)
                ? declared[MediaTypePrefix.Length..]
                : declared;
            return foreign.Contains(mediaType, StringComparer.OrdinalIgnoreCase);
        }
        catch (ArgumentException)
        {
            // Not a readable JWT; the handler refuses it on its own terms, as with the two gates above.
            return false;
        }
        catch (FormatException)
        {
            // A segment that will not base64url-decode. The back-channel endpoint is anonymous, so an
            // escaping decode failure here would be a 500 an unauthenticated caller can drive.
            return false;
        }
    }

    /// <summary>
    /// Builds the signature/issuer/audience/lifetime validation parameters every JWT the plugin verifies
    /// against a provider uses - the id_token and the back-channel logout_token share this ONE builder, so
    /// their signature posture cannot drift apart. Signed + expiring tokens are required (fail closed); the
    /// provider-level <c>DoNotValidateIssuerName</c> escape hatch relaxes ONLY the issuer match.
    /// </summary>
    /// <param name="options">The provider's client options (discovery issuer + JWKS, client id, skew, policy).</param>
    /// <param name="ephemeralKeys">Collects disposable ECDsa handles for the caller to release.</param>
    /// <param name="requireExpiration">Whether an <c>exp</c> claim is mandatory. True for the id_token (OIDC Core 3.1.3.7 mandates exp); false for the back-channel logout_token, where OIDC Back-Channel Logout 1.0 §2.4 does NOT list exp among the required claims (replay is bounded by the jti one-time-use instead) - requiring it would silently no-op a spec-compliant exp-less IdP (#962).</param>
    /// <returns>The hardened validation parameters.</returns>
    internal static TokenValidationParameters BuildValidationParameters(OidcClientOptions options, List<IDisposable> ephemeralKeys, bool requireExpiration = true)
    {
        ArgumentNullException.ThrowIfNull(options);
        return new TokenValidationParameters
        {
            ValidIssuer = options.ProviderInformation.IssuerName,
            ValidAudience = options.ClientId,
            IssuerSigningKeys = Convert(options.ProviderInformation.KeySet, ephemeralKeys),
            ValidAlgorithms = AllowedSignatureAlgorithms,
            ClockSkew = options.ClockSkew,
            RequireSignedTokens = true,
            RequireExpirationTime = requireExpiration,

            // The provider-level escape hatch (DoNotValidateIssuerName) exists for IdPs whose issuer
            // legitimately differs from the discovery location; it relaxes ONLY the issuer match.
            // Signature, audience and lifetime validation have no off switch.
            ValidateIssuer = options.Policy.Discovery.ValidateIssuerName,

            // The downstream claim scan compares raw JWT claim names ordinally, so the principal must carry
            // the payload names verbatim - these two only name the identity's Name/Role accessors.
            NameClaimType = "name",
            RoleClaimType = "role",
        };
    }

    /// <summary>Converts the advertised JWKS into usable signing keys, skipping a null entry, a non-signing key, a key under the RSA size floor (#733) or invalid material, so one broken key cannot take down verification against a good one; never throws.</summary>
    /// <remarks>The advertised <c>kid</c> is not screened against <see cref="IsAcceptableKeyId"/>, and that is a decision (#1029): every exclusion is a key that cannot do the job, a spelling is not one, and refusing a key over its alphabet would take a well-behaved provider down for nothing the header screen does not already stop. Such a key is reachable by trying every key but never by name.</remarks>
    /// <param name="keySet">The advertised JSON Web Key Set (may be null/empty).</param>
    /// <param name="ephemeralKeys">Collects disposable ECDsa handles for the caller to release.</param>
    /// <returns>The usable signing keys (possibly empty).</returns>
    internal static List<SecurityKey> Convert(Duende.IdentityModel.Jwk.JsonWebKeySet? keySet, List<IDisposable> ephemeralKeys)
    {
        ArgumentNullException.ThrowIfNull(ephemeralKeys);
        var keys = new List<SecurityKey>();
        if (keySet?.Keys == null)
        {
            return keys;
        }

        foreach (var webKey in keySet.Keys)
        {
            if (TryConvertSigningKey(webKey, ephemeralKeys, out var key))
            {
                keys.Add(key);
            }
        }

        return keys;
    }

    // Converts one advertised JWK into a usable signing key, or reports it unusable: a literal null entry is skipped
    // rather than dereferenced, use != "sig" is not a signing key, and invalid material is caught, so the caller
    // drops the key without aborting the scan and never sees a throw. The advertised kid is not an exclusion, the
    // decided contract of #1029 and #1168, and the set is never refused whole over one entry.
    private static bool TryConvertSigningKey(Duende.IdentityModel.Jwk.JsonWebKey? webKey, List<IDisposable> ephemeralKeys, [NotNullWhen(true)] out SecurityKey? key)
    {
        key = null;
        if (webKey == null)
        {
            return false;
        }

        if (webKey.Use != null && !string.Equals(webKey.Use, "sig", StringComparison.Ordinal))
        {
            return false;
        }

        try
        {
            // RSA (e/n) is tried first; an EC (crv/x/y) key is only attempted when the key is not RSA-shaped,
            // preserving the original else-if precedence. A decode/point failure throws out of the converter
            // and is caught below as a skip.
            key = (SecurityKey?)ConvertRsaSigningKey(webKey) ?? ConvertEcSigningKey(webKey, ephemeralKeys);
        }
        catch (FormatException)
        {
            // Un-decodable key material in one advertised key: skip it, the remaining keys decide.
            return false;
        }
        catch (CryptographicException)
        {
            // Invalid EC point/curve combination: likewise skip.
            return false;
        }

        return key != null;
    }

    // RSA signing key from the JWK e/n pair (RFC 7518). Returns null when the key does not carry both
    // parameters (not RSA-shaped, so the EC conversion is tried instead) OR when the built key is below the
    // minimum size floor (#733) - an under-strength RSA key from the discovery JWKS (or a compromised one) is
    // as forgeable as a weak hash, so it is skipped exactly like a malformed key; the remaining advertised
    // keys decide, and if none is usable verification fails via the key-not-found path. A non-base64url
    // exponent/modulus throws FormatException, surfaced to TryConvertSigningKey's skip path.
    private static RsaSecurityKey? ConvertRsaSigningKey(Duende.IdentityModel.Jwk.JsonWebKey webKey)
    {
        if (string.IsNullOrEmpty(webKey.E) || string.IsNullOrEmpty(webKey.N))
        {
            return null;
        }

        var key = new RsaSecurityKey(new RSAParameters
        {
            Exponent = Base64UrlEncoder.DecodeBytes(webKey.E),
            Modulus = Base64UrlEncoder.DecodeBytes(webKey.N),
        })
        { KeyId = webKey.Kid };

        return SigningKeyStrength.IsAcceptableRsaKeySize(key.KeySize) ? key : null;
    }

    // EC signing key from the JWK crv/x/y triple. Returns null when a coordinate is absent or the curve is
    // unsupported (TryGetCurve false), so the key is skipped. The ECDsa instance is registered in
    // ephemeralKeys for disposal by the caller. A non-base64url coordinate throws FormatException and an
    // invalid point throws CryptographicException - both surfaced to TryConvertSigningKey's skip path.
    private static ECDsaSecurityKey? ConvertEcSigningKey(Duende.IdentityModel.Jwk.JsonWebKey webKey, List<IDisposable> ephemeralKeys)
    {
        if (string.IsNullOrEmpty(webKey.X) || string.IsNullOrEmpty(webKey.Y) || !TryGetCurve(webKey.Crv, out var curve))
        {
            return null;
        }

        var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = curve,
            Q = new ECPoint
            {
                X = Base64UrlEncoder.DecodeBytes(webKey.X),
                Y = Base64UrlEncoder.DecodeBytes(webKey.Y),
            },
        });
        ephemeralKeys.Add(ecdsa);
        return new ECDsaSecurityKey(ecdsa) { KeyId = webKey.Kid };
    }

    private static bool TryGetCurve(string? crv, out ECCurve curve)
    {
        switch (crv)
        {
            case "P-256":
                curve = ECCurve.NamedCurves.nistP256;
                return true;
            case "P-384":
                curve = ECCurve.NamedCurves.nistP384;
                return true;
            case "P-521":
                curve = ECCurve.NamedCurves.nistP521;
                return true;
            default:
                curve = default;
                return false;
        }
    }
}
