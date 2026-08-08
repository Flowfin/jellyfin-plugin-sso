// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// Validates an inbound OpenID Connect back-channel <c>logout_token</c> (OIDC Back-Channel Logout 1.0
/// §2.4–§2.6, #962). The endpoint that calls this is ANONYMOUS - the token's signature is the only
/// authenticator - so every §2.6 rule is fail-closed and each maps to a fixed reason code (never
/// request-derived text, so a rejection leaves an audit trail without a subject-identifier oracle,
/// mirroring the SAML inbound-logout validator). Signature/JWKS/algorithm verification goes through the
/// SAME <see cref="OidcSignatureKeys"/> basis the id_token validator uses - there is no second, laxer
/// verification path, and this class derives that basis from the provider's options itself rather than
/// accepting one, so no caller holds the object between its construction and the verification (#1176). On
/// success it yields the (sub, sid) pair the revocation lookup keys on; the validator itself revokes
/// nothing.
/// </summary>
internal sealed class OidcLogoutTokenValidator
{
    // The logout event the events claim MUST contain (§2.4). A member-presence check, not equality on the
    // whole claim - the claim is a JSON object whose keys are event URIs.
    private const string BackChannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout";

    // Distinct from the login-path id_token replay set and the SAML logout set: a consumed logout_token jti
    // must not be redeemable twice (§2.6 rule the spec RECOMMENDS; here it is enforced as one-time-use so a
    // captured valid token cannot churn revocations). Process-wide, bounded, fail-closed at capacity.
    private static readonly ReplayCache LogoutTokenReplays = new ReplayCache();

    /// <summary>Clears the replay set so a jti consumed in one test does not leak into a sibling.</summary>
    internal static void ResetReplaysForTests() => LogoutTokenReplays.Clear();

    /// <summary>
    /// Parses and fully validates a <c>logout_token</c> for a provider.
    /// </summary>
    /// <param name="logoutToken">The raw compact-serialized logout_token.</param>
    /// <param name="options">The provider's client options - the issuer, client id, discovery JWKS and clock skew this method derives its own validation basis from.</param>
    /// <param name="nowUtc">The current time (injected for determinism).</param>
    /// <returns>The validation outcome.</returns>
    internal async Task<Result> ValidateAsync(
        string? logoutToken,
        OidcClientOptions options,
        DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrEmpty(logoutToken))
        {
            return new Result(false, null, null, RejectReason.Malformed);
        }

        // The header kid is constrained to the shared allowlist BEFORE any signing key is looked up
        // (#1167), from the same predicate the id_token path calls, so the two postures cannot drift.
        if (!OidcSignatureKeys.TokenHasAcceptableKeyId(logoutToken))
        {
            return new Result(false, null, null, RejectReason.UnacceptableKeyId);
        }

        // RFC 7515 4.1.11, from the same shared predicate the id_token path calls (#1038). The handler
        // below ignores crit, so without this a genuinely signed token could assert a constraint this
        // plugin never applied - and this endpoint is anonymous, which is where that matters most.
        if (!OidcSignatureKeys.TokenHasNoCriticalHeader(logoutToken))
        {
            return new Result(false, null, null, RejectReason.CriticalHeader);
        }

        // The algorithm is judged before the handler runs, purely so the refusal can be named. The handler
        // refuses a disallowed alg on its own - nothing new is rejected here - but it reports alg: none, a
        // case-variant spelling and an HS256 token keyed with the advertised public key as
        // SecurityTokenInvalidSignatureException, indistinguishable from an ordinary bad signature, because
        // ValidAlgorithms is evaluated per key inside signature validation. An operator watching this
        // endpoint needs those apart: a spread of algorithm refusals is somebody probing, a steady stream of
        // signature failures is usually a rotated key nobody re-published (#1164).
        if (!OidcSignatureKeys.TokenHasAllowedAlgorithm(logoutToken))
        {
            return new Result(false, null, null, RejectReason.AlgorithmNotAllowed);
        }

        // ECDsa instances built from the JWKS are ours to dispose; RSA keys built from RSAParameters are
        // not disposable. Owned here rather than by the caller because the basis is now built here too -
        // the finally must not run until ValidateTokenAsync has returned (#1176).
        var ephemeralKeys = new List<IDisposable>();
        try
        {
            // Signature / issuer / audience / lifetime, from the SAME hardened basis as the id_token; any
            // failure is fail-closed. The basis is built into the call rather than into a local, exactly as
            // OidcIdTokenValidator does it: no reference to it exists for anything to write through
            // between construction and verification (#1176).
            //
            // requireExpiration:false - OIDC Back-Channel Logout 1.0 §2.4 does not mandate exp on a
            // logout_token; replay is bounded by the jti one-time-use below, not by exp. Requiring it would
            // silently reject (and so no-op the logout for) a spec-compliant exp-less IdP (#962).
            var handler = new JsonWebTokenHandler { MapInboundClaims = false };
            var result = await handler.ValidateTokenAsync(
                logoutToken,
                OidcSignatureKeys.BuildValidationParameters(options, ephemeralKeys, requireExpiration: false)).ConfigureAwait(false);
            if (!result.IsValid)
            {
                return new Result(false, null, null, ReasonFor(result.Exception));
            }

            var token = (JsonWebToken)result.SecurityToken;

            // azp / additional-audience restriction (OIDC Core 3.1.3.7 rules 3-5), the SAME check the
            // id_token validator applies - §2.4 says the logout_token aud follows OpenID.Core, so the two
            // token types must not drift on it: when azp is present it MUST equal this client's id, and a
            // multi-audience token MUST carry azp (a token minted for a different party that merely
            // co-lists this client is refused). ValidateAudience already confirmed this client is AMONG the
            // audiences, from the same options.ClientId compared here.
            var azp = result.ClaimsIdentity.FindFirst("azp")?.Value;
            if (azp != null && !string.Equals(azp, options.ClientId, StringComparison.Ordinal))
            {
                return new Result(false, null, null, RejectReason.AuthorizedPartyMismatch);
            }

            if (azp == null && token.Audiences.Count() > 1)
            {
                return new Result(false, null, null, RejectReason.MultipleAudiencesWithoutAuthorizedParty);
            }

            // §2.4: a logout_token MUST NOT contain a nonce. Rejecting it here is what refuses an id_token
            // (which carries nonce) replayed at the back-channel endpoint.
            if (token.TryGetPayloadValue<string>("nonce", out var nonce) && !string.IsNullOrEmpty(nonce))
            {
                return new Result(false, null, null, RejectReason.ProhibitedNonce);
            }

            // §2.4/§2.6: the events claim MUST be a JSON object containing the back-channel-logout member.
            if (!HasBackChannelLogoutEvent(token))
            {
                return new Result(false, null, null, RejectReason.NotALogoutToken);
            }

            var sub = token.TryGetPayloadValue<string>("sub", out var s) && !string.IsNullOrEmpty(s) ? s : null;
            var sid = token.TryGetPayloadValue<string>("sid", out var i) && !string.IsNullOrEmpty(i) ? i : null;

            // §2.4: at least one of sub / sid MUST be present.
            if (sub is null && sid is null)
            {
                return new Result(false, null, null, RejectReason.NoSubjectOrSid);
            }

            // One-time-use on jti so a captured valid token cannot be replayed to churn revocations. A token
            // without a jti is treated as non-replayable-once (fail-closed): give it a synthetic key derived
            // from its signature so an identical token still collides, while distinct tokens do not.
            var jti = token.TryGetPayloadValue<string>("jti", out var j) && !string.IsNullOrEmpty(j)
                ? j
                : token.EncodedSignature;
            var retention = ReplayCache.ComputeRetention(nowUtc, token.ValidTo == DateTime.MinValue ? null : token.ValidTo, options.ClockSkew);
            if (!LogoutTokenReplays.TryConsume(jti, retention, nowUtc, out _))
            {
                return new Result(false, null, null, RejectReason.Replay);
            }

            return new Result(true, sub, sid, string.Empty);
        }
        finally
        {
            foreach (var key in ephemeralKeys)
            {
                key.Dispose();
            }
        }
    }

    // The fixed code for a handler refusal, chosen from the exception TYPE and never from its message: an
    // IdentityModel message can embed claim values, and this trail must stay free of anything derived from
    // the token's subject. Every arm is a const, so no request byte can reach the audit line.
    //
    // Which exception each shape actually produces was measured against this basis rather than inferred from
    // the type names, and the measurement is why several shapes share one arm: alg: none, a case-variant
    // alg, an HS256 token keyed with the advertised public key, a stripped signature and a foreign key
    // signing under a trusted kid all arrive as SecurityTokenInvalidSignatureException. The first three are
    // separated ahead of the handler by the algorithm gate above; the last two are not separable here, and
    // calling both signature_invalid is the honest answer rather than a guess.
    //
    // Anything unmapped keeps the old collapsed code, which is the fail-closed default: a library version
    // introducing a new exception type reports a refusal this plugin has not classified, rather than
    // reporting one it has.
    private static string ReasonFor(Exception? exception) => exception switch
    {
        SecurityTokenMalformedException => RejectReason.Malformed,
        SecurityTokenSignatureKeyNotFoundException => RejectReason.KeyNotFound,
        SecurityTokenInvalidSignatureException => RejectReason.SignatureInvalid,
        SecurityTokenInvalidAlgorithmException => RejectReason.AlgorithmNotAllowed,
        SecurityTokenInvalidIssuerException => RejectReason.IssuerInvalid,
        SecurityTokenInvalidAudienceException => RejectReason.AudienceInvalid,
        SecurityTokenExpiredException => RejectReason.Expired,
        SecurityTokenNotYetValidException => RejectReason.NotYetValid,
        SecurityTokenInvalidLifetimeException => RejectReason.LifetimeInvalid,
        SecurityTokenNoExpirationException => RejectReason.LifetimeInvalid,
        _ => RejectReason.Invalid,
    };

    // The events claim is a JSON object; presence of the back-channel-logout member is what makes this a
    // logout_token. Read it as a JsonElement and require the member - a claim that is absent, not an object,
    // or an object without the member is rejected. Any parse failure is a fail-closed "not a logout_token".
    private static bool HasBackChannelLogoutEvent(JsonWebToken token)
    {
        if (!token.TryGetPayloadValue<JsonElement>("events", out var events))
        {
            return false;
        }

        return events.ValueKind == JsonValueKind.Object
            && events.TryGetProperty(BackChannelLogoutEvent, out _);
    }

    /// <summary>
    /// The outcome of validating a <c>logout_token</c>: on success the (sub, sid) pair the caller keys its
    /// <c>FindByProviderSubject</c> lookup on (either may be null, but never both - §2.4); on failure a
    /// fixed <see cref="RejectReason"/> code.
    /// </summary>
    /// <param name="IsValid">Whether the token is a valid logout_token.</param>
    /// <param name="Subject">The token's <c>sub</c> claim on success, else null.</param>
    /// <param name="SessionIndex">The token's <c>sid</c> claim on success, else null.</param>
    /// <param name="ReasonCode">A fixed rejection reason code on failure, else empty.</param>
    internal readonly record struct Result(bool IsValid, string? Subject, string? SessionIndex, string ReasonCode);

    /// <summary>The fixed rejection reason codes - request-independent, safe to audit and never a subject oracle.</summary>
    internal static class RejectReason
    {
        /// <summary>The token was absent, unparseable, or not a JWT.</summary>
        internal const string Malformed = "malformed";

        /// <summary>The header carries a crit parameter, naming a JWS extension this plugin does not process (RFC 7515 4.1.11, #1038).</summary>
        internal const string CriticalHeader = "unprocessed_critical_header";

        /// <summary>
        /// A handler refusal this plugin has not classified. Every shape reaching it today has its own code
        /// below; this is what a future library version's new exception type falls through to, so an
        /// unrecognised refusal reads as unrecognised instead of borrowing a neighbour's name (#1164).
        /// </summary>
        internal const string Invalid = "signature_or_time_invalid";

        /// <summary>The header alg is outside the asymmetric-only allowlist: alg none, a case variant, or a symmetric algorithm keyed with the advertised public key (#1164).</summary>
        internal const string AlgorithmNotAllowed = "algorithm_not_allowed";

        /// <summary>The signature did not verify under any advertised key, or the token carries none. A stripped signature and a foreign key signing under a trusted kid are not separable here (#1164).</summary>
        internal const string SignatureInvalid = "signature_invalid";

        /// <summary>The header names a kid no key in the provider's JWKS carries, so nothing could verify it (#1164).</summary>
        internal const string KeyNotFound = "key_not_found";

        /// <summary>The iss claim is not this provider's issuer (#1164).</summary>
        internal const string IssuerInvalid = "issuer_invalid";

        /// <summary>The aud claim does not list this client (#1164).</summary>
        internal const string AudienceInvalid = "audience_invalid";

        /// <summary>The token's exp has passed, allowing for the configured clock skew (#1164).</summary>
        internal const string Expired = "expired";

        /// <summary>The token's nbf is still in the future, allowing for the configured clock skew (#1164).</summary>
        internal const string NotYetValid = "not_yet_valid";

        /// <summary>The token's lifetime is not coherent: nbf at or after exp, or a required expiry absent (#1164).</summary>
        internal const string LifetimeInvalid = "lifetime_invalid";

        /// <summary>The azp claim names a party other than this client (OIDC Core 3.1.3.7 rule 4, #1164).</summary>
        internal const string AuthorizedPartyMismatch = "azp_mismatch";

        /// <summary>The token lists several audiences and carries no azp, so it was not minted for this client alone (OIDC Core 3.1.3.7 rule 3, #1164).</summary>
        internal const string MultipleAudiencesWithoutAuthorizedParty = "multiple_audiences_without_azp";

        /// <summary>The events claim is absent or does not contain the back-channel-logout event - this is not a logout_token.</summary>
        internal const string NotALogoutToken = "not_a_logout_token";

        /// <summary>The token carries a nonce, which §2.4 forbids (an id_token replayed as a logout_token).</summary>
        internal const string ProhibitedNonce = "prohibited_nonce";

        /// <summary>Neither sub nor sid is present - nothing to match a session on.</summary>
        internal const string NoSubjectOrSid = "no_subject_or_sid";

        /// <summary>The jti was already consumed - a replayed logout_token.</summary>
        internal const string Replay = "replay";

        /// <summary>The header kid carries characters outside the accepted set, or is over-length (#1167).</summary>
        internal const string UnacceptableKeyId = "unacceptable_kid";

        /// <summary>
        /// The provider's discovery document could not be read, so the signing keys never arrived and the
        /// token was never checked. Alone among these codes it does not describe a refused forgery: the
        /// legitimate IdP ordered a termination and the plugin declined to perform it, which the caller
        /// audits as its own event at its own severity (#1184).
        /// </summary>
        internal const string ProviderUnreachable = "discovery_unavailable";
    }
}
