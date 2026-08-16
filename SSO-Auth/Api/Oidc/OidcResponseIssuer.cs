// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Diagnostics;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// RFC 9207 authorization-response issuer check (OpenID Connect mix-up defense, #125, hardened in #210).
/// The library the plugin uses (Duende.IdentityModel.OidcClient 7.1.0) parses the response <c>iss</c>
/// parameter but never validates it, and strips it from the resulting claims, so the check has to live
/// here. A present response <c>iss</c> must match the authorization server this callback is bound to -
/// identified by its discovery issuer (<see cref="Duende.IdentityModel.OidcClient.ProviderInformation.IssuerName"/>,
/// the value RFC 9207 §2.4 names) OR by the redeemed id_token's own issuer. Both are accepted because a
/// provider whose issuer legitimately differs from its discovery location (the <c>DoNotValidateIssuerName</c>
/// escape hatch - templated / multi-tenant setups) emits a response <c>iss</c> equal to the concrete
/// id_token issuer, not the templated discovery issuer; requiring the discovery issuer alone would lock
/// that supported configuration out. A response <c>iss</c> that matches neither means the response came
/// from a different authorization server than the one this callback is bound to - a mix-up - so reject.
/// </summary>
internal static class OidcResponseIssuer
{
    /// <summary>
    /// Decides whether the RFC 9207 check rejects this authorization response. A present
    /// <paramref name="responseIssuer"/> is accepted only when it ordinally equals the discovery issuer
    /// (<paramref name="discoveryIssuer"/>) or the id_token issuer; matching neither is a mix-up and is
    /// rejected, as is a present response issuer while both anchors are unknown. Absence of a response
    /// issuer is tolerated only when the server did not advertise the parameter (<paramref name="required"/>
    /// is false), so IdPs that never emit <c>iss</c> keep working; when the server advertises
    /// <c>authorization_response_iss_parameter_supported</c> (RFC 9207 §2.4) its absence is a downgrade
    /// and is rejected.
    /// </summary>
    /// <param name="responseIssuer">The <c>iss</c> query parameter from the authorization response, if any.</param>
    /// <param name="discoveryIssuer">The authorization server's discovery issuer identifier, or null when it could not be determined.</param>
    /// <param name="identityToken">The redeemed id_token (already validated upstream), whose issuer is the second accepted anchor.</param>
    /// <param name="required">Whether the server advertised the response-<c>iss</c> parameter, making its presence mandatory.</param>
    /// <returns><see langword="true"/> when the response must be rejected.</returns>
    internal static bool IsRejected(string? responseIssuer, string? discoveryIssuer, string? identityToken, bool required)
    {
        if (string.IsNullOrEmpty(responseIssuer))
        {
            return required;
        }

        return !string.Equals(responseIssuer, discoveryIssuer, StringComparison.Ordinal)
            && !string.Equals(responseIssuer, TokenIssuer(identityToken), StringComparison.Ordinal);
    }

    /// <summary>
    /// Reports whether the discovery document advertises the RFC 9207 authorization-response <c>iss</c>
    /// parameter (<c>authorization_response_iss_parameter_supported: true</c>, §2.4). Read at challenge
    /// and carried on the authorize state so the callback can require <c>iss</c> without a second fetch.
    /// Fails tolerant (<c>false</c>) on absence, a non-true value, or malformed/blank JSON - an
    /// unreadable flag must not lock out a provider that omits <c>iss</c>.
    /// </summary>
    /// <param name="discoveryJson">The raw OpenID discovery document JSON.</param>
    /// <returns><c>true</c> only when the parameter is explicitly advertised as <c>true</c>.</returns>
    internal static bool DiscoveryAdvertisesResponseIssuer(string? discoveryJson)
    {
        using var document = DiscoveryJson.TryParse(discoveryJson);
        return DiscoveryAdvertisesResponseIssuer(document?.RootElement);
    }

    /// <summary>
    /// The same flag read off an already-parsed document, so the challenge reads both of its discovery facts
    /// out of one parse (#1170). Stays tolerant (<c>false</c>) on a null root, exactly as the raw-JSON entry
    /// point is on absent, blank or malformed input.
    /// </summary>
    /// <param name="discovery">The parsed discovery document's root, or <see langword="null"/> when it could not be parsed.</param>
    /// <returns><c>true</c> only when the parameter is explicitly advertised as <c>true</c>.</returns>
    internal static bool DiscoveryAdvertisesResponseIssuer(JsonElement? discovery)
    {
        // Only the JSON literal `true` advertises the parameter. A string "true", a 1, or the literal `false`
        // all read as not advertised, which is the tolerant direction: requiring `iss` off a value the
        // provider did not write as a boolean would lock out a provider that never sends one.
        //
        // The ValueKind test on the root is not redundant with the null test, for the same reason it is not
        // in PkceDiscovery: enumerating a non-object element throws rather than answering false. The lookup
        // itself goes through JsonMember, which skips a member name whose escape the decoder cannot
        // complete instead of letting it abandon the read (#1340).
        var advertised = discovery is { ValueKind: JsonValueKind.Object } root
            && JsonMember.TryGet(root, "authorization_response_iss_parameter_supported", out var value)
            && value.ValueKind == JsonValueKind.True;

        // Post-condition, compiled out of the shipped build (#1082): a document that did not parse advertises
        // nothing. Reading true off an unparsed document would make the callback REQUIRE an iss parameter the
        // provider may never send, which is the tolerant direction this flag is deliberately not taking.
        Debug.Assert(discovery is not null || !advertised, "DiscoveryAdvertisesResponseIssuer reported true for a document that did not parse.");
        return advertised;
    }

    /// <summary>
    /// The validated id_token's issuer (its <c>iss</c> claim), or null when the token is absent/degenerate.
    /// Read from the RAW token rather than the redeemed <c>result.User</c> claims because OidcClient filters
    /// the standard protocol claims (<c>iss</c>, <c>aud</c>, <c>exp</c>, …) out of the principal - the same
    /// reason the mix-up check above re-reads it here. This is the authoritative (iss, sub) issuer the
    /// canonical link is bound to (#186).
    /// </summary>
    /// <param name="identityToken">The redeemed, already-validated id_token.</param>
    /// <returns>The token's issuer; null when the token does not parse, and empty when it carries no <c>iss</c> (JsonWebToken.Issuer returns "" for an absent claim). Both are treated as "no issuer" by every consumer (IsNullOrWhiteSpace / ordinal Equals), so the link stays un-stamped.</returns>
    internal static string? IdTokenIssuer(string? identityToken)
    {
        var issuer = TokenIssuer(identityToken);

        // Post-condition, compiled out of the shipped build (#1082): no token, no issuer. The canonical link
        // is bound to (iss, sub), so an issuer invented where there was no token to read one from would stamp
        // a link with an anchor nothing authenticated. Deliberately NOT asserted: that a non-null issuer is
        // non-empty or trimmed. This method's contract says empty is what an absent iss claim returns, and
        // JsonWebToken hands back the claim value as written, whitespace included.
        Debug.Assert(!string.IsNullOrEmpty(identityToken) || issuer is null, "IdTokenIssuer produced an issuer without a token.");
        return issuer;
    }

    // The id_token was validated by OidcIdTokenValidator before this runs, so it parses; the guard and
    // catch are defensive so a degenerate token can never turn the mix-up check itself into a 500.
    private static string? TokenIssuer(string? identityToken)
    {
        if (string.IsNullOrEmpty(identityToken))
        {
            return null;
        }

        try
        {
            return new JsonWebToken(identityToken).Issuer;
        }
        catch (ArgumentException)
        {
            return null;
        }
        catch (SecurityTokenException)
        {
            return null;
        }
        catch (FormatException)
        {
            // A token with more than three segments gets far enough for the library to base64url-decode a
            // LATER segment, and that decode raises FormatException rather than the malformed-token
            // ArgumentException above. Unreadable by another name, so it reads as absent like the rest.
            return null;
        }
    }
}
