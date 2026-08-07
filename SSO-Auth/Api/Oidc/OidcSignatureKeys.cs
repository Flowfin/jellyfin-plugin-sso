// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
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

    /// <summary>
    /// Gets the asymmetric signature algorithms the plugin accepts (RFC 7518). Symmetric HS* would accept a
    /// token minted by anyone holding the shared client secret, and <c>none</c> is unauthenticated by
    /// definition - both are rejected regardless of what the discovery document advertises.
    /// </summary>
    /// <remarks>
    /// Immutable, not just get-only: the same instance is handed by reference into the validation parameters
    /// of BOTH token types, so a writable array would let one in-assembly write to element zero change what
    /// the id_token and the back-channel logout_token accept, at once, with nothing else noticing. Freezing
    /// the collection makes that write a compile error rather than a control nobody is watching (#1190).
    /// </remarks>
    internal static ImmutableArray<string> AllowedSignatureAlgorithms { get; } =
    [
        "RS256", "RS384", "RS512",
        "PS256", "PS384", "PS512",
        "ES256", "ES384", "ES512",
    ];

    /// <summary>
    /// Whether a token-header <c>kid</c> may be used as a key-lookup value. Accepts the RFC 3986 unreserved
    /// set only, up to <see cref="MaxKeyIdLength"/>.
    /// <para>
    /// There is no live sink today: the value is only ever compared ordinally against the in-memory
    /// <see cref="SecurityKey.KeyId"/> values converted from the discovery JWKS, so it reaches no
    /// filesystem, database, URL or parser. This is the standing mitigation for the JWT <c>kid</c>-injection
    /// class applied ahead of a sink, so that any future consumer of the header value - a log line, a cache
    /// key, a keyed store, a remote key fetch - is born behind the constraint instead of re-opening it.
    /// </para>
    /// <para>
    /// An ABSENT <c>kid</c> is not a violation: it is the ordinary "try every advertised key" case and must
    /// keep working, so null, empty and whitespace are accepted. That also makes the predicate indifferent
    /// to whether the token library reports an absent header member as null or as an empty string.
    /// </para>
    /// </summary>
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

    /// <summary>
    /// Whether a compact-serialized JWT's header <c>kid</c> passes <see cref="IsAcceptableKeyId"/>. Both
    /// token paths call this ahead of validation, so the constraint has ONE definition and the id_token and
    /// <c>logout_token</c> postures cannot drift.
    /// <para>
    /// A token this cannot read at all is reported as acceptable rather than refused. That is deliberate and
    /// it is not a fail-open: this gate is not the floor. A token whose header will not parse is refused
    /// moments later by the handler, which owns signature, issuer, audience and lifetime, and reporting a
    /// refusal from here would only replace an accurate rejection reason with a misleading one.
    /// </para>
    /// </summary>
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

    /// <summary>
    /// Whether a compact-serialized JWT's header is free of the <c>crit</c> parameter (RFC 7515 §4.1.11,
    /// #1038). A recipient MUST reject a token whose <c>crit</c> names an extension it does not understand
    /// AND process; this plugin implements no JWS extension at all, so the rule collapses to a presence
    /// test: <c>crit</c> in the header means refuse. Both token paths call this, so the id_token and the
    /// <c>logout_token</c> cannot drift on it, exactly as they share the algorithm allowlist.
    /// <para>
    /// Not exploitable on its own - the token must still carry a signature from a key in the discovery
    /// JWKS. What it prevents is semantic: an IdP marks a header extension critical precisely because
    /// ignoring it changes what the token asserts (a narrowed audience, a scope restriction, a
    /// proof-of-possession binding), so accepting one means acting on an assertion whose stated
    /// constraints were silently dropped.
    /// </para>
    /// <para>
    /// The member is looked up by PRESENCE - <c>object</c>, the one type every JSON value converts to -
    /// and not by reading it as the string array §4.1.11 says a well-formed <c>crit</c> is. Reading it as
    /// a typed value is the mistake this spelling exists to avoid, and the difference is measured rather
    /// than supposed: <c>TryGetHeaderValue&lt;JsonElement&gt;</c> reports a STRING-valued <c>crit</c> as
    /// ABSENT, so a typed read admits <c>"crit":"urn:example:ext"</c> - a malformed <c>crit</c>, which the
    /// RFC forbids too, walking through the guard meant to stop it. Presence subsumes every malformed
    /// shape the RFC lists (non-array, empty array, empty or duplicate member, registered header name, a
    /// bare null): no extension is processed here, so nothing about the value could make it acceptable.
    /// </para>
    /// <para>
    /// A token this cannot read at all is reported as free of it rather than refused, the same contract
    /// (and the same reason) as <see cref="TokenHasAcceptableKeyId"/>: this gate is not the fail-closed
    /// floor. The handler that follows owns signature, issuer, audience and lifetime and refuses an
    /// unreadable token on its own terms, and refusing from here would replace an accurate rejection
    /// reason with a misleading one. It reads the header through the token library for the same reason
    /// that predicate does - so the plugin gains no second, unscreened JSON parse over provider bytes.
    /// </para>
    /// </summary>
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

    /// <summary>
    /// Converts the advertised JWKS into usable signing keys, skipping any key that is null, not a signing
    /// key (<c>use != "sig"</c>), under the RSA size floor (#733), or of un-decodable/invalid material - so
    /// one broken key in the set cannot take down verification against a good one. Never throws.
    /// <para>
    /// The <c>kid</c> the PROVIDER advertises is deliberately NOT screened against
    /// <see cref="IsAcceptableKeyId"/>, and that is a decision rather than an omission (#1029). Every
    /// exclusion above is a key that cannot do the job; a spelling is not one of them. The two sides of a
    /// lookup are not symmetric: the token header is the needle and arrives from outside, the advertised
    /// <c>kid</c> is what the haystack is searched THROUGH, and refusing a key over its alphabet - a
    /// standard-base64 thumbprint rather than a base64url one is the ordinary case - would take a
    /// well-behaved provider's signature verification down for nothing the header screen does not already
    /// stop. The cost that comes with it is that such a key is reachable by trying every advertised key
    /// but never by name, and <c>OidcSignatureKeysKidTests</c> pins both halves.
    /// </para>
    /// </summary>
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

    // Converts one advertised JWK into a usable signing key, or reports that it is unusable (out false).
    // The exclusions and the skip-on-malformed contract live here: a literal null entry (["keys":[null]])
    // must be skipped rather than dereferenced (otherwise the whole verification 500s), a key marked
    // use!="sig" is not a signing key, and un-decodable/invalid key material is caught and skipped so one
    // broken key in the set cannot take down verification signed by a good one. Returns false - never
    // throws - on every reject path so the caller drops the key without aborting the scan.
    //
    // The advertised kid is NOT one of the exclusions, and that is the decided contract rather than a
    // gap (#1029, #1168): every exclusion above is a key that cannot do the job, and a spelling is not
    // one of those. The set is also never refused whole over one entry - the odd key is kept, the good
    // ones beside it keep working, and the token header's own kid is screened separately by
    // IsAcceptableKeyId before any lookup. OidcSignatureKeysKidTests holds both directions of this,
    // including what it costs: such a key is reachable by trying every advertised key, never by name.
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
