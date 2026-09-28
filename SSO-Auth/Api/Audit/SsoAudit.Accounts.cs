// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Audit;

/// <summary>The account lines: login, provisioning, adoption, rename, deprovisioning and expiry.</summary>
internal static partial class SsoAudit
{
    /// <summary>Records a successful login under the Jellyfin account's name, so the line matches the host's own AuthenticationSuccess event (#1551).</summary>
    /// <remarks>The presented name and the mapped privilege are printed only where they differ from the account's name and the granted privilege (#1554).</remarks>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">OpenID or SAML.</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="username">The Jellyfin account the session was issued for.</param>
    /// <param name="grantedAdmin">Whether the minted session holds administrator rights, read from the host's own result; null when there was no result to read.</param>
    /// <param name="mappedAdmin">Whether a role this login carried is on the provider's <c>AdminRoles</c> list.</param>
    /// <param name="presentedUsername">The username the identity provider presented; null suppresses the comparison.</param>
    internal static void LoginSucceeded(ILogger logger, string protocol, string provider, string username, bool? grantedAdmin, bool mappedAdmin, string? presentedUsername = null)
    {
        if (!logger.IsEnabled(LogLevel.Information))
        {
            return;
        }

        // "unknown" is a third value of the one field, so the four templates below stay four (#1554).
        var granted = grantedAdmin switch
        {
            true => "True",
            false => "False",
            _ => "unknown",
        };

        // The mapping is named only where it disagrees; an absent outcome disagrees with everything, so that line still names it.
        var mappingDisagrees = grantedAdmin != mappedAdmin;

        // Compared as printed, ordinally: both names carry the same sanitizers, and the rename path compares them the same way (#1555).
        var namesDiffer = presentedUsername is not null
            && !string.Equals(
                presentedUsername.ReplaceLineEndings(string.Empty).Replace('[', '('),
                username?.ReplaceLineEndings(string.Empty).Replace('[', '('),
                StringComparison.Ordinal);

        // Four whole templates keep the structured field names stable for log readers and for the log-forging rules.
        if (namesDiffer && mappingDisagrees)
        {
            logger.LogInformation(
                "[SSO Audit] Login succeeded: {Username} via {Protocol} provider '{Provider}' (admin={IsAdmin}). The provider presented the name '{PresentedUsername}', and its roles mapped to admin={MappedAdmin}.",
                username?.ReplaceLineEndings(string.Empty).Replace('[', '('),
                protocol,
                provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
                granted,
                presentedUsername!.ReplaceLineEndings(string.Empty).Replace('[', '('),
                mappedAdmin);
            return;
        }

        if (namesDiffer)
        {
            logger.LogInformation(
                "[SSO Audit] Login succeeded: {Username} via {Protocol} provider '{Provider}' (admin={IsAdmin}). The provider presented the name '{PresentedUsername}'.",
                username?.ReplaceLineEndings(string.Empty).Replace('[', '('),
                protocol,
                provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
                granted,
                presentedUsername!.ReplaceLineEndings(string.Empty).Replace('[', '('));
            return;
        }

        if (mappingDisagrees)
        {
            logger.LogInformation(
                "[SSO Audit] Login succeeded: {Username} via {Protocol} provider '{Provider}' (admin={IsAdmin}). The provider's roles mapped to admin={MappedAdmin}.",
                username?.ReplaceLineEndings(string.Empty).Replace('[', '('),
                protocol,
                provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
                granted,
                mappedAdmin);
            return;
        }

        logger.LogInformation(
            "[SSO Audit] Login succeeded: {Username} via {Protocol} provider '{Provider}' (admin={IsAdmin}).",
            username?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            protocol,
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            granted);
    }

    /// <summary>Records that an account this login created was deleted again because the login could not be completed (#1533); Warning, so the provisioning lines above it read as undone.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">OpenID or SAML.</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="username">The Jellyfin username the account had been created under.</param>
    internal static void ProvisionedAccountRolledBack(ILogger logger, string protocol, string provider, string username)
    {
        if (logger is null || !logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] Provisioning rolled back for {Protocol} provider '{Provider}': the account '{Username}' was created and then deleted again because the login could not be completed. Nothing was left behind, and the failure that stopped it is logged separately. The user can sign in once that failure is fixed.",
            protocol?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            username?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records that the rollback could not delete the account (#1533): it holds no link and no usable password, and it blocks that identity's name until deleted by hand.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="username">The Jellyfin username the account was created under.</param>
    /// <param name="error">What the delete threw; no credential material is recorded.</param>
    internal static void ProvisionedAccountRollbackFailed(ILogger logger, string username, Exception error)
    {
        if (logger is null || !logger.IsEnabled(LogLevel.Error))
        {
            return;
        }

        logger.LogError(
            "[SSO Audit] Provisioning could not be rolled back ({Reason}): the account '{Username}' was created for a login that then failed, and deleting it again did not work. It holds no SSO link and no usable password, and it will refuse that identity a fresh account under the same name - delete it manually.",
            error?.Message?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            username?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records a new SSO identity provisioned as a disabled account awaiting administrator approval (#737); no session was issued.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">OpenID or SAML.</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="username">The Jellyfin username the disabled account was created under.</param>
    internal static void ProvisionedPendingApproval(ILogger logger, string protocol, string provider, string username)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] New account provisioned pending approval: '{Username}' via {Protocol} provider '{Provider}' was created disabled (ProvisionNewUsersDisabled); no session issued. Approve it on the plugin's Accounts tab, or enable it in the Jellyfin dashboard.",
            username?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            protocol,
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records an SSO identity being linked to a pre-existing account (the opt-in adoption path).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="displayName">The adopted account's name.</param>
    internal static void AccountAdopted(ILogger logger, string protocol, string provider, string displayName)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] SSO identity linked to existing account '{DisplayName}' via {Protocol} provider '{Provider}' (AllowExistingAccountLink).",
            displayName?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            protocol,
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records a linked account being renamed to follow its identity provider (#1138), naming both names.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">OpenID or SAML.</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="previousName">The name the account held before the rename.</param>
    /// <param name="newName">The sanitized name it now holds.</param>
    internal static void AccountRenamed(ILogger logger, string protocol, string provider, string previousName, string newName)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] Linked account renamed from '{PreviousName}' to '{NewName}' to follow {Protocol} provider '{Provider}' (SyncUsernameFromProvider).",
            previousName?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            newName?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            protocol,
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records an account disabled by login-time deprovisioning (#831): the role allow-list denied the login and the provider opts into disabling; no subject or username is named (T-I1).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">OpenID or SAML.</param>
    /// <param name="provider">The provider name.</param>
    internal static void AccountDeprovisioned(ILogger logger, string protocol, string provider)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] Account disabled by login-time deprovisioning: an SSO login via {Protocol} provider '{Provider}' was denied by the role allow-list and the account was disabled (DisableAccountOnRoleDenied). Administrators are never disabled by this path.",
            protocol,
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records an account disabled because the access deadline a login carried has passed (#1144); fired once, at the transition; neither subject nor deadline is named (T-I1).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">OpenID or SAML.</param>
    /// <param name="provider">The provider name.</param>
    internal static void AccountExpired(ILogger logger, string protocol, string provider)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] Account disabled by account expiry: an SSO login via {Protocol} provider '{Provider}' carried an expiry instant at or before now, so the account was disabled and its tokens were revoked (AccountExpiryClaim). Administrators are never disabled by this path.",
            protocol,
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records an account disabled by the between-logins expiry sweep (#1145); fired once, at the transition, and worded apart from the login-time line.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">OpenID or SAML.</param>
    /// <param name="provider">The provider name.</param>
    internal static void AccountExpiredBySweep(ILogger logger, string protocol, string provider)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] Account disabled by account expiry: the background expiry sweep found a stored deadline at or before now for a {Protocol} provider '{Provider}' link with no intervening login, so the account was disabled and its tokens were revoked (AccountExpiryClaim). Administrators are never disabled by this path.",
            protocol,
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records the boot-time sweep giving SSO-linked accounts that had no stored password an unguessable one (#1440); a count and nothing else (T-I1).</summary>
    /// <remarks>The line names no version range: the population is a state, not a span of releases (#1454).</remarks>
    /// <param name="logger">The logger.</param>
    /// <param name="sealedAccounts">How many accounts the sweep gave a password to.</param>
    internal static void PasswordlessAccountsSealed(ILogger logger, int sealedAccounts)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] Sealed {Count} SSO-linked account(s) that had no stored password: an account with none accepts the empty password on the ordinary login form, so these were reachable without the identity provider. Each was given an unguessable password that nothing knows and nothing can recover; their login provider routing was left exactly as it was. Any SSO-linked account that held no stored password is in this set, whatever plugin version created it.",
            sealedAccounts);
    }
}
