// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>Orchestrates the inbound identity-provider-initiated SAML LogoutRequest validation (#727): parse with signature and time validation, then the one-time consume of the request ID.</summary>
/// <remarks>
/// It is the logout analogue of <see cref="SamlAssertionValidator"/> and owns the process-wide replay cache
/// as a <c>static readonly</c> field, so the calling endpoint holds no mutable static state, reusing the
/// shared replay primitive rather than a copy. On failure the caller receives a fixed reason code, never
/// request-derived text, and that reason is server-side only, because the endpoint renders every failure as
/// one uniform 400.
/// </remarks>
internal sealed class SamlLogoutValidator
{
    // One-time-use tracking for consumed LogoutRequest IDs (replay protection), process-wide exactly like the
    // login-path SamlAssertionValidator.SamlReplays - a captured LogoutRequest must not revoke twice.
    private static readonly ReplayCache LogoutReplays = new ReplayCache();

    /// <summary>
    /// Test-only. Clears the process-wide one-time replay cache between tests so a consumed request ID does
    /// not leak into a sibling test (mirrors <see cref="SamlAssertionValidator.ResetReplaysForTests"/>).
    /// </summary>
    internal static void ResetReplaysForTests() => LogoutReplays.Clear();

    /// <summary>Parses and fully validates an inbound LogoutRequest for a provider: signature, the optional time bound and one-time use of the request ID, failing closed with a fixed reason and no resolved subject.</summary>
    /// <param name="config">The SAML provider configuration, carrying the signing certificates.</param>
    /// <param name="provider">The provider the request arrived for, which scopes the replay key so two identity providers cannot block each other.</param>
    /// <param name="rawRequest">The untrusted, Base64-encoded SAMLRequest.</param>
    /// <param name="nowUtc">The current UTC time, supplied for determinism.</param>
    /// <param name="nameId">On success, the subject NameID the request names.</param>
    /// <param name="sessionIndexes">On success, the SessionIndex values the request carries, possibly empty.</param>
    /// <param name="requestId">On success, the request ID this service provider echoes as the InResponseTo of the signed LogoutResponse (#727); empty on failure.</param>
    /// <param name="reasonCode">On failure, a fixed audit reason code; empty on success.</param>
    /// <returns>True when the request is fully valid; otherwise false.</returns>
    internal bool TryValidate(
        SamlConfig config,
        string provider,
        string? rawRequest,
        DateTime nowUtc,
        out string nameId,
        out IReadOnlyList<string> sessionIndexes,
        out string requestId,
        out string reasonCode)
    {
        ArgumentNullException.ThrowIfNull(config);
        nameId = string.Empty;
        sessionIndexes = Array.Empty<string>();
        requestId = string.Empty;

        if (!SamlLogoutRequest.TryParse(config.SamlCertificate ?? string.Empty, config.SamlSecondaryCertificate, rawRequest, out var logoutRequest))
        {
            reasonCode = RejectReason.Malformed;
            return false;
        }

        // The parsed request owns an unmanaged certificate handle; dispose it on every path.
        using var owned = logoutRequest;

        // Signature + time-bound validation. An unsigned, wrong-key, wrapped, weak-algorithm or expired
        // request fails here, before any subject is exposed or any replay slot is consumed.
        if (!logoutRequest.IsValid())
        {
            reasonCode = RejectReason.Invalid;
            return false;
        }

        // A validated request with no usable NameID resolves no subject - reject rather than fall through to a
        // blank-subject lookup (SessionLogoutStore.FindByProviderSubject also refuses a blank subject, but the
        // guard here keeps the contract explicit and fail-closed).
        var resolvedNameId = logoutRequest.GetNameId();
        if (string.IsNullOrEmpty(resolvedNameId))
        {
            reasonCode = RejectReason.Invalid;
            return false;
        }

        // One-time use: consume the request ID so a captured LogoutRequest cannot be replayed to revoke again,
        // retained for its own NotOnOrAfter window or the one-hour floor, the same policy the login replay path
        // uses. The consume is deliberately at validation time rather than on a successful revoke (#727),
        // because TryConsume is the atomic claim that serialises concurrent copies of one request, and because
        // revocation is idempotent while a real identity provider mints a fresh ID per retry, so burning the ID
        // on a transient fault blocks no genuine retry. Replay protection here is a hygiene bound rather than a
        // session-minting gate.
        var retention = ReplayCache.ComputeRetention(nowUtc, logoutRequest.GetNotOnOrAfter(), SamlAssertionTime.ClockSkew);
        var resolvedRequestId = logoutRequest.GetRequestId();
        var replayKey = ProviderScopedKey.For(provider, resolvedRequestId);
        if (!LogoutReplays.TryConsume(replayKey, retention, nowUtc, out _))
        {
            reasonCode = RejectReason.Replay;
            return false;
        }

        nameId = resolvedNameId;
        sessionIndexes = logoutRequest.GetSessionIndexes();
        // TryConsume succeeded above, and ProviderScopedKey.For fails closed on a null/blank id, so a true
        // return here guarantees a usable request ID to echo as the LogoutResponse InResponseTo.
        requestId = resolvedRequestId ?? string.Empty;
        reasonCode = string.Empty;
        return true;
    }

    /// <summary>The fixed audit reason codes for a rejected logout request; never request-derived text.</summary>
    internal static class RejectReason
    {
        /// <summary>The body did not parse (non-base64, malformed XML, prohibited DOCTYPE, or an unloadable configured certificate).</summary>
        internal const string Malformed = "malformed";

        /// <summary>The signature or time-bound validation failed (unsigned, wrong key, wrapped, weak algorithm, expired).</summary>
        internal const string Invalid = "signature_or_time_invalid";

        /// <summary>The request ID was already consumed (a replay) or absent.</summary>
        internal const string Replay = "replay";
    }
}
