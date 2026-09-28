// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Audit;

/// <summary>The link administration lines: imports, pre-provisioning, approvals, purges, stranding refusals and SSO-only mode.</summary>
internal static partial class SsoAudit
{
    /// <summary>Records an administrator restoring an account-link backup (#1129): a bulk grant of future login with no identity-provider round trip, so it is warned.</summary>
    /// <remarks>Per-provider counts and no subjects (T-I1).</remarks>
    /// <param name="logger">The logger.</param>
    /// <param name="actor">The elevated administrator who applied the backup.</param>
    /// <param name="totalLinks">How many links the import restored in total.</param>
    /// <param name="perProvider">A rendered "Protocol 'provider': n" list, one entry per provider that got links back.</param>
    internal static void LinksImported(ILogger logger, string actor, int totalLinks, string perProvider)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] Account-link backup restored by {Actor}: {TotalLinks} link(s) rebound to this instance's accounts, with no identity-provider response redeemed. Per provider: {PerProvider}.",
            actor?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            totalLinks,
            perProvider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records an administrator pre-provisioning a canonical link with no identity-provider round trip (#1133): a grant of future login, so it is warned.</summary>
    /// <remarks>The subject is not a field (T-I1); provider and account identify the grant.</remarks>
    /// <param name="logger">The logger.</param>
    /// <param name="actor">The elevated administrator who made the link.</param>
    /// <param name="protocol">OpenID or SAML.</param>
    /// <param name="provider">The provider the link was written on.</param>
    /// <param name="jellyfinUserId">The Jellyfin account the identity was linked to.</param>
    internal static void LinkPreprovisioned(ILogger logger, string actor, string protocol, string provider, Guid jellyfinUserId)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] Canonical link pre-provisioned by {Actor}: {Protocol} '{Provider}' -> Jellyfin user {UserId}, with no identity-provider response redeemed.",
            actor?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            protocol,
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            jellyfinUserId);
    }

    /// <summary>Records an administrator enabling an account this plugin provisioned inert (#1529): a grant of access, so it is warned; no subject is named (T-I1).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="actor">The elevated administrator who approved the account.</param>
    /// <param name="protocol">OpenID or SAML.</param>
    /// <param name="provider">The provider the account was provisioned from.</param>
    /// <param name="jellyfinUserId">The Jellyfin account that was enabled.</param>
    internal static void AccountApproved(ILogger logger, string actor, string protocol, string provider, Guid jellyfinUserId)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] Account approved by {Actor}: Jellyfin user {UserId}, provisioned inert by {Protocol} provider '{Provider}', was enabled. No other permission was changed.",
            actor?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            jellyfinUserId,
            protocol,
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records the links of a deleted Jellyfin account being removed with it (#1649), naming the providers and the account id and no subject (T-I1).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="jellyfinUserId">The deleted account.</param>
    /// <param name="removed">How many links were removed.</param>
    /// <param name="providers">The providers that held them, each labelled by protocol.</param>
    internal static void DeletedAccountUnlinked(ILogger logger, Guid jellyfinUserId, int removed, IReadOnlyList<string> providers)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] Jellyfin user {UserId} was deleted; removed its {Count} SSO link(s) from {Providers}. Any deadline, last-login stamp and pending-approval record went with them.",
            jellyfinUserId,
            removed,
            string.Join(", ", providers ?? Array.Empty<string>()).ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records an administrator removing every link one provider holds (#1519): one line for the act with the actor and the counts, no subject or account name (T-I1).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="actor">The elevated administrator who ran the unlink.</param>
    /// <param name="protocol">OpenID or SAML.</param>
    /// <param name="provider">The provider whose link table was emptied.</param>
    /// <param name="removedLinks">How many links were removed.</param>
    /// <param name="unlinkedAccounts">How many accounts were left holding no SSO link at all.</param>
    /// <param name="signedOut">How many of those the token revocation reached.</param>
    internal static void ProviderLinksPurged(ILogger logger, string actor, string protocol, string provider, int removedLinks, int unlinkedAccounts, int signedOut)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        // Two counts on purpose: a revoke that threw would otherwise hide inside the unlinked count.
        logger.LogWarning(
            "[SSO Audit] Every canonical link on {Protocol} '{Provider}' removed by {Actor}: {RemovedLinks} link(s) gone, {UnlinkedAccounts} account(s) left with no SSO link, {SignedOut} of them signed out. No Jellyfin account, permission or password was changed.",
            protocol,
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            actor?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            removedLinks,
            unlinkedAccounts,
            signedOut);
    }

    /// <summary>Records that a bulk unlink left an administrator with no way to sign in after all (#1519): the guard was right when it ran and a password door closed in between; Error, naming the accounts so somebody can repair it.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">OpenID or SAML.</param>
    /// <param name="provider">The provider whose links were removed.</param>
    /// <param name="administrators">The rendered list of administrator accounts now without a way in.</param>
    internal static void ProviderLinksPurgeStrandedAdministrator(ILogger logger, string protocol, string provider, string administrators)
        => logger.LogError(
            "[SSO Audit] After emptying {Protocol} '{Provider}', these administrator account(s) have no way to sign in: {Administrators}. They were judged to have one when the run was checked, so something changed in between. Give one of them a usable password or re-link it.",
            protocol,
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            administrators?.ReplaceLineEndings(string.Empty).Replace('[', '('));

    /// <summary>Records a holder's own last-link removal being refused because it would leave the account with no way in (#1720); Information, nothing changed, the account id only.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="jellyfinUserId">The account whose own last link was kept.</param>
    internal static void SelfUnlinkRefusedWouldStrand(ILogger logger, Guid jellyfinUserId)
    {
        if (!logger.IsEnabled(LogLevel.Information))
        {
            return;
        }

        logger.LogInformation(
            "[SSO Audit] Refused a user's removal of their own last SSO link for user {UserId}: the account accepts no password, so the removal would have left it unable to sign in. Nothing was changed.",
            jellyfinUserId);
    }

    /// <summary>Records an administrator's revoke of their own links being refused because no other administrator holds a link that can sign them in (#1741); Information, nothing changed.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="jellyfinUserId">The administrator account whose links were kept.</param>
    internal static void UnregisterRefusedWouldStrandServer(ILogger logger, Guid jellyfinUserId)
    {
        if (!logger.IsEnabled(LogLevel.Information))
        {
            return;
        }

        logger.LogInformation(
            "[SSO Audit] Refused an administrator's revoke of their own SSO links for user {UserId}: no other administrator holds an SSO link that can sign them in, so the revoke could have left this server with no administrator able to reach it. Nothing was changed.",
            jellyfinUserId);
    }

    /// <summary>Records a per-provider bulk unlink being refused (#1519, T-R1) with a fixed verdict code, never caller input (T-I1).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="actor">The elevated administrator whose unlink was refused.</param>
    /// <param name="protocol">OpenID or SAML.</param>
    /// <param name="provider">The provider named in the request.</param>
    /// <param name="reasonCode">The refusal verdict name, a fixed enum member.</param>
    internal static void ProviderLinksPurgeRefused(ILogger logger, string actor, string protocol, string provider, string reasonCode)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] Bulk unlink REFUSED for {Actor} on {Protocol} '{Provider}' ({ReasonCode}). No link was removed.",
            actor?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            protocol,
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            reasonCode);
    }

    /// <summary>Records SSO-only login being turned on (#165), with the guaranteed break-glass survivor.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="actor">The elevated administrator who enabled the mode.</param>
    /// <param name="breakGlassAdmin">The designated break-glass admin whose password door survives.</param>
    /// <param name="repointedCount">How many accounts were repointed off the password provider.</param>
    internal static void SsoOnlyLoginEnabled(ILogger logger, string actor, string? breakGlassAdmin, int repointedCount)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] SSO-only login ENABLED by {Actor}: break-glass admin '{BreakGlassAdmin}' keeps password login; {RepointedCount} account(s) repointed to SSO-only.",
            actor?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            breakGlassAdmin?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            repointedCount);
    }

    /// <summary>Records SSO-only login being turned off (#165), the reversible no-SSO off-switch.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="actor">The elevated administrator who disabled the mode.</param>
    /// <param name="restoredCount">How many accounts had native password routing restored.</param>
    internal static void SsoOnlyLoginDisabled(ILogger logger, string actor, int restoredCount)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] SSO-only login DISABLED by {Actor}: native password routing restored for {RestoredCount} account(s); no password hash was reset.",
            actor?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            restoredCount);
    }

    /// <summary>Records an SSO-only activation or designation refused by the fail-closed guard (#165, T-R1) with a fixed verdict code (T-I1).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="actor">The elevated administrator whose activation was refused.</param>
    /// <param name="reasonCode">The guard verdict name, a fixed enum member.</param>
    internal static void SsoOnlyLoginActivationRefused(ILogger logger, string actor, string reasonCode)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] SSO-only login activation REFUSED for {Actor}: no surviving admin login path ({ReasonCode}). No change was made.",
            actor?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            reasonCode);
    }

    /// <summary>Records the break-glass admin designation being set or changed (#165), an elevated operation.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="actor">The elevated administrator who changed the designation.</param>
    /// <param name="breakGlassAdmin">The newly designated break-glass admin.</param>
    internal static void BreakGlassAdminDesignated(ILogger logger, string actor, string? breakGlassAdmin)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] Break-glass admin designated by {Actor}: '{BreakGlassAdmin}' is now the account SSO-only login never repoints.",
            actor?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            breakGlassAdmin?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }
}
