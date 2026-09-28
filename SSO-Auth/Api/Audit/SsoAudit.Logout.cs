// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Audit;

/// <summary>The logout lines for both protocols, with the provider name bounded because the route chooses it (#1792).</summary>
internal static partial class SsoAudit
{
    /// <summary>Records a validated inbound SAML LogoutRequest that revoked sessions (#727): the provider and a count, never the NameID or SessionIndex (T-I1).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="provider">The SAML provider the request arrived for.</param>
    /// <param name="usersRevoked">How many distinct Jellyfin users had their tokens revoked.</param>
    internal static void LogoutRequested(ILogger logger, string provider, int usersRevoked)
    {
        if (!logger.IsEnabled(LogLevel.Information))
        {
            return;
        }

        logger.LogInformation(
            "[SSO Audit] SAML logout requested: a validated LogoutRequest for provider '{Provider}' revoked tokens for {UsersRevoked} user(s).",
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            usersRevoked);
    }

    /// <summary>Records an inbound SAML LogoutRequest rejected fail-closed (#727, T-R1) with a fixed reason code; the caller sees one uniform 400.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="provider">The SAML provider the request arrived for.</param>
    /// <param name="reasonCode">The fixed rejection reason code.</param>
    internal static void LogoutRejected(ILogger logger, string provider, string reasonCode)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] SAML logout request REJECTED for provider '{Provider}' ({ReasonCode}). No session was terminated.",
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            reasonCode);
    }

    /// <summary>Records an inbound OpenID logout_token rejected fail-closed (#962) with a fixed reason code; its own line, so a filter for OpenID logout failures finds it (#1184).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="provider">The OpenID provider the token arrived for.</param>
    /// <param name="reasonCode">The fixed rejection reason code.</param>
    internal static void BackChannelLogoutRejected(ILogger logger, string provider, string reasonCode)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] OpenID back-channel logout REJECTED for provider '{Provider}' ({ReasonCode}). No session was terminated.",
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            reasonCode);
    }

    /// <summary>Records the RP-initiated OpenID logout refusing a caller (#1768) with a fixed reason code; the provider is route input and is cut at <see cref="MaxLoggedProviderChars"/> (#1792).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="provider">The OpenID provider named in the route.</param>
    /// <param name="reasonCode">The fixed refusal reason code.</param>
    internal static void OpenIdLogoutRefused(ILogger logger, string provider, string reasonCode)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] OpenID logout REFUSED for provider '{Provider}' ({ReasonCode}). No session was terminated.",
            string.Concat(BoundedForLog(provider)?.ReplaceLineEndings(string.Empty).Replace('[', '('), CutMarkFor(provider)),
            reasonCode);
    }

    /// <summary>Records how many credential-less refusals of the RP-initiated logout went unrecorded while their line budget was spent (#1792); a count and nothing a caller wrote.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="count">How many refusals went unrecorded since the budget last reopened.</param>
    internal static void OpenIdLogoutRefusalsNotRecorded(ILogger logger, long count)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] OpenID logout REFUSED {Count} further time(s) since the last recorded refusal; those lines were not written because the budget on them was spent. No session was terminated.",
            count);
    }

    // Cut unsanitized; the sanitizers stay inline at the logging call for CodeQL and the conformance rule.
    private static string? BoundedForLog(string? provider) =>
        provider is { Length: > MaxLoggedProviderChars } ? provider[..MaxLoggedProviderChars] : provider;

    // Appended after the sanitizers: it is this plugin's text, so its bracket stays.
    private static string CutMarkFor(string? provider) =>
        provider is { Length: > MaxLoggedProviderChars } ? ProviderCutMark : string.Empty;

    /// <summary>Records a ticket-borne RP-initiated OpenID logout that completed (#1795): the ticket was redeemed and the session it was minted from ended; a fixed outcome code says where the browser went, and no account is named.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="provider">The OpenID provider named in the route.</param>
    /// <param name="outcomeCode">The fixed outcome code: where the browser was sent after the local sign-out.</param>
    internal static void OpenIdTicketLogoutCompleted(ILogger logger, string provider, string outcomeCode)
    {
        if (!logger.IsEnabled(LogLevel.Information))
        {
            return;
        }

        logger.LogInformation(
            "[SSO Audit] OpenID logout completed for provider '{Provider}' ({OutcomeCode}): a one-time ticket ended the Jellyfin session it was minted from.",
            string.Concat(BoundedForLog(provider)?.ReplaceLineEndings(string.Empty).Replace('[', '('), CutMarkFor(provider)),
            outcomeCode);
    }

    /// <summary>Records a back-channel logout the plugin could not perform (#1184): the provider ordered a termination and a session may still run; Error, so it separates from the rejections.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="provider">The OpenID provider the termination was ordered for.</param>
    /// <param name="reasonCode">The fixed reason code.</param>
    internal static void BackChannelLogoutNotPerformed(ILogger logger, string provider, string reasonCode)
    {
        if (!logger.IsEnabled(LogLevel.Error))
        {
            return;
        }

        logger.LogError(
            "[SSO Audit] OpenID back-channel logout could NOT be performed for provider '{Provider}' ({ReasonCode}). The identity provider ordered a termination and no session was terminated, so a signed-out session may still be running.",
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            reasonCode);
    }

    /// <summary>Records an OpenID role claim the walk refused (#1149) with a fixed reason code; the claim value never appears, because it carries memberships and addresses.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="provider">The OpenID provider whose claim was refused.</param>
    /// <param name="reasonCode">The fixed refusal reason from the walk.</param>
    internal static void RoleClaimRefused(ILogger logger, string provider, string reasonCode)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] OpenID provider '{Provider}': the configured role claim could not be read ({ReasonCode}), so this login was granted NO roles from it. Under a configured role allow-list that denies the login; check the role-claim path against what the provider actually emits.",
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            reasonCode);
    }
}
