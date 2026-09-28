// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Audit;

/// <summary>Writes the "[SSO Audit]" lines for the security events of this plugin: logins, adoptions, provisioning, configuration and logout.</summary>
/// <remarks>
/// A foreign value loses its line endings and its "[" becomes "(" at every call, spelled out inline so CodeQL's log-forging
/// tracking sees it (#1555, #1557); a path this server composed keeps only the line-ending strip. Every call is guarded by
/// <see cref="ILogger.IsEnabled(LogLevel)"/> (CA1873, #566). What a line may name and why the bracket is substituted:
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model#audit-trail"/>.
/// </remarks>
internal static class SsoAudit
{
    /// <summary>The most characters of a route-chosen provider name a logout line prints (#1792); the rest is cut and marked.</summary>
    internal const int MaxLoggedProviderChars = 128;

    /// <summary>Marks a provider name a logout line cut, so a truncated name is not read as the whole one.</summary>
    internal const string ProviderCutMark = "[truncated]";

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

    /// <summary>Records a provider being added or updated.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
    /// <param name="provider">The provider name.</param>
    internal static void ProviderConfigured(ILogger logger, string protocol, string provider)
    {
        if (!logger.IsEnabled(LogLevel.Information))
        {
            return;
        }

        logger.LogInformation(
            "[SSO Audit] Provider configured: {Protocol} '{Provider}'.",
            protocol,
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records a provider being removed.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
    /// <param name="provider">The provider name.</param>
    internal static void ProviderRemoved(ILogger logger, string protocol, string provider)
    {
        if (!logger.IsEnabled(LogLevel.Information))
        {
            return;
        }

        logger.LogInformation(
            "[SSO Audit] Provider removed: {Protocol} '{Provider}'.",
            protocol,
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records that a ConfigurationChanged subscriber threw after a completed save (#1521); the save stands, so the failure is contained here at Warning.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="error">What the subscriber threw; no configuration content is recorded.</param>
    internal static void ConfigurationChangedSubscriberFailed(ILogger logger, Exception error)
    {
        if (logger is null || !logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] A ConfigurationChanged subscriber failed after a completed configuration save ({Reason}). The save itself is stored and live; whatever that subscriber keeps in step with the configuration may not be.",
            error?.Message?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records a configuration write going ahead without an undo because the previous state could not be serialized (#1521); refusing the write would make the configuration permanently unwritable.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="error">What refused the serialization; no configuration content is recorded.</param>
    internal static void ConfigurationRollbackUnavailable(ILogger logger, Exception error)
    {
        if (logger is null || !logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] Configuration write proceeding without a rollback: the current configuration could not be serialized for one ({Reason}). If this write fails, the running server keeps the change while the file does not, until the next restart.",
            error?.Message?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records a configuration write that failed and whose undo failed too (#1521): the running server carries a change the file lacks until a restart.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="error">What the restore threw; no configuration content is recorded.</param>
    internal static void ConfigurationRollbackFailed(ILogger logger, Exception error)
    {
        if (logger is null || !logger.IsEnabled(LogLevel.Error))
        {
            return;
        }

        logger.LogError(
            "[SSO Audit] Configuration write failed and could not be rolled back ({Reason}): the running server is carrying a change that is not in the file. Restart the server to put it back on the stored configuration.",
            error?.Message?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records a settings-page save whose change to a declaratively managed provider was ignored and the stored value kept (#1102).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">OpenID or SAML.</param>
    /// <param name="provider">The provider name; no field value is recorded.</param>
    internal static void DeclarativeWriteIgnored(ILogger logger, string protocol, string provider)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] Configuration save ignored for {Protocol} provider '{Provider}': it is managed by a declarative source, so the stored value was kept. Edit the source and restart the server to change it.",
            protocol,
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records a save whose write to a declaratively defined provisioning profile was ignored and the stored value kept (#1102).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="profile">The profile name; no field value is recorded.</param>
    internal static void DeclarativeProfileWriteIgnored(ILogger logger, string profile)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] Configuration save ignored for provisioning profile '{Profile}': it is defined by a declarative source, so the stored value was kept. Edit the source and restart the server to change it.",
            profile?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records an elevated single-provider door refusing to alter or delete a declaratively managed provider (#1415); unlike the settings page it cannot half-honour the request, so nothing is written.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="door">The route that was refused, such as <c>OID/Del</c>.</param>
    /// <param name="protocol">OpenID or SAML.</param>
    /// <param name="provider">The provider name; no field value is recorded.</param>
    /// <param name="source">The declarative source that owns the provider.</param>
    internal static void DeclarativeWriteRefused(ILogger logger, string door, string protocol, string provider, string source)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] {Door} refused for {Protocol} provider '{Provider}': it is managed by the declarative source {Source}, so nothing was written. Edit that source and restart the server to change it.",
            door?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            protocol,
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            source?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>Records a whole-document write refused because the document redefines a declaratively defined profile (#1102); an import is all-or-nothing.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="door">The route that was refused, such as <c>Config/Import</c>.</param>
    /// <param name="profile">The profile name; no field value is recorded.</param>
    /// <param name="source">The declarative source that defined the profile.</param>
    internal static void DeclarativeProfileWriteRefused(ILogger logger, string door, string profile, string source)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] {Door} refused for provisioning profile '{Profile}': it is defined by the declarative source {Source}, so nothing was written. Edit that source and restart the server to change it.",
            door?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            profile?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            source?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>Records that a provider's authorization server does not advertise PKCE S256 support (#141).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="provider">The provider name.</param>
    internal static void PkceNotAdvertised(ILogger logger, string provider)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] OpenID provider '{Provider}' does not advertise PKCE (S256) in its discovery document (code_challenge_methods_supported). PKCE is still sent, but a server that ignores it leaves cross-session authorization-code injection undetectable (RFC 9700 §2.1.1). Set RequirePkce to fail closed once the provider supports it.",
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
    }

    /// <summary>Records an administrator importing a configuration document (#161).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="oidProviders">How many OpenID providers the import merged.</param>
    /// <param name="samlProviders">How many SAML providers the import merged.</param>
    internal static void ConfigImported(ILogger logger, int oidProviders, int samlProviders)
        => logger.LogWarning(
            "[SSO Audit] Configuration imported by an administrator: {OidProviders} OpenID and {SamlProviders} SAML provider(s) merged. Server-managed secrets and links were preserved; redacted secrets must be re-entered on this instance.",
            oidProviders,
            samlProviders);

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

    /// <summary>Records a provider being saved with one or more default-on security checks disabled (#140, #672).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="options">The enabled insecure option names (configuration keys, not user input).</param>
    internal static void InsecureOptionsEnabled(ILogger logger, string protocol, string provider, IReadOnlyList<string> options)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        // Shared by OpenID (#140) and SAML (#672); the option names are configuration keys.
        logger.LogWarning(
            "[SSO Audit] {Protocol} provider '{Provider}' saved with security checks disabled: {Options}. Each switches off a default-on protection on the login path (such as transport, issuer/audience, or endpoint binding); keep them only if the provider genuinely requires it.",
            protocol,
            provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
            string.Join(", ", options));
    }

    /// <summary>Records that the stored configuration could not be read at start (#1543): defaults are served and SSO refuses until a configuration arrives; Error, naming the preserved copy or its absence.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="configurationFilePath">The configuration file that failed to read back.</param>
    /// <param name="preservedCopyPath">Where the damaged file was copied, or <see langword="null"/> when the copy failed.</param>
    internal static void UnreadableConfigurationFound(ILogger logger, string configurationFilePath, string? preservedCopyPath)
    {
        if (!logger.IsEnabled(LogLevel.Error))
        {
            return;
        }

        if (preservedCopyPath is null)
        {
            logger.LogError(
                "[SSO Audit] {ConfigurationFile} could not be read, and NO copy of it was kept. Default settings are being served, the server is about to overwrite the file with them, and every SSO sign-in is refused with 503 until a configuration holding at least one provider is saved or imported, or the stored file is restored and the server started again - a save that carries no provider does not end it, and a server serving defaults usually has none to save. This plugin does not touch Jellyfin password sign-in - but an account it provisioned has none, and on a server that was in SSO-only mode the accounts it repointed have none either, so the only certain way in is the break-glass administrator. If nobody can sign in at all, move the unreadable configuration file out of the way and delete the marker file beside it - the one whose name is the configuration file plus .unreadable, with no timestamp on the end - then restart: SSO then answers as it did before this check existed. Keep any timestamped copies lying beside the configuration file rather than deleting them: they are from an earlier fault, or from an earlier boot of this one whose record was lost, and one of them may hold more than this server now has.",
                configurationFilePath?.ReplaceLineEndings(string.Empty));
            return;
        }

        logger.LogError(
            "[SSO Audit] {ConfigurationFile} could not be read. It was copied to {PreservedCopy} before the server overwrites it. Default settings are being served - no provider, no account link, no stored secret - and every SSO sign-in is refused with 503 until a configuration holding at least one provider is saved or imported, or the stored file is restored and the server started again. A save that carries no provider does not end it, and a server serving defaults usually has none to save. This plugin does not touch Jellyfin password sign-in - but an account it provisioned has none, and on a server that was in SSO-only mode the accounts it repointed have none either, so the only certain way in is the break-glass administrator. If nobody can sign in at all, move the unreadable configuration file out of the way and delete the marker file beside it - the one whose name is the configuration file plus .unreadable, with no timestamp on the end - then restart: SSO then answers as it did before this check existed. Do not delete it, nor any other timestamped copy beside the configuration file: the one named above is what was kept this time, and any others are from earlier boots or earlier faults and may hold more than it does.",
            configurationFilePath?.ReplaceLineEndings(string.Empty),
            preservedCopyPath?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>Records that the damaged configuration could not be copied aside (#1543); its own line, because lost evidence is a different failure from an unreadable file.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="preservedCopyPath">The copy that was attempted.</param>
    /// <param name="error">Why the copy failed.</param>
    internal static void UnreadableConfigurationNotPreserved(ILogger logger, string preservedCopyPath, Exception error)
        => logger.LogError(
            error,
            "[SSO Audit] The unreadable configuration could not be copied to {PreservedCopy}. The line after this one says what copy, if any, remains.",
            preservedCopyPath?.ReplaceLineEndings(string.Empty));

    /// <summary>Records that the readability check could not open the configuration and decided nothing (#1543); Warning, because the host's own read may still succeed.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="configurationFilePath">The configuration file that could not be read.</param>
    /// <param name="error">Why it could not be read.</param>
    internal static void UnreadableConfigurationCheckSkipped(ILogger logger, string configurationFilePath, Exception error)
        => logger.LogWarning(
            error,
            "[SSO Audit] {ConfigurationFile} could not be opened for the startup readability check, so it was not judged. If the server can read it, nothing is wrong; if it cannot, it will serve default settings without this warning saying so.",
            configurationFilePath?.ReplaceLineEndings(string.Empty));

    /// <summary>Records that an earlier start found the configuration unreadable and none has been supplied since (#1543); the marker is believed over the file the host rewrote.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="configurationFilePath">The configuration file now holding defaults.</param>
    /// <param name="preservedCopyPath">Where the damaged file was kept, or <see langword="null"/> when no copy is recorded or the recorded one is gone.</param>
    internal static void UnreadableConfigurationStillUnrepaired(ILogger logger, string configurationFilePath, string? preservedCopyPath)
        => logger.LogError(
            "[SSO Audit] {ConfigurationFile} was unreadable at an earlier start and no configuration has been supplied since, so this server is still serving default settings and still refusing every SSO sign-in. The copy kept for this incident: {PreservedCopy}. Save or import a configuration holding at least one provider to clear this; if no administrator can sign in at all, move the unreadable configuration file out of the way, delete the marker file beside it - the configuration file plus .unreadable, with no timestamp - and restart. Do not delete the copy named above, nor any other timestamped copy beside the configuration file: the one named is this incident's, and an earlier one may hold more than it does.",
            configurationFilePath?.ReplaceLineEndings(string.Empty),
            preservedCopyPath?.ReplaceLineEndings(string.Empty) ?? "none recorded, or the recorded one is no longer beside the configuration");

    /// <summary>Records the configuration coming back on disk while the marker stood (#1543), which ends the refusal.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="configurationFilePath">The configuration file that now holds providers again.</param>
    internal static void UnreadableConfigurationRepairedOnDisk(ILogger logger, string configurationFilePath)
        => logger.LogWarning(
            "[SSO Audit] {ConfigurationFile} holds a configuration again, so this server stops serving defaults and accepts SSO sign-in. The preserved copy of the unreadable file is left where it is.",
            configurationFilePath?.ReplaceLineEndings(string.Empty));

    /// <summary>Records that the marker keeping the refusal across a restart could not be written (#1543); reported rather than thrown, because it costs only the restart.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="markerPath">The marker that could not be written.</param>
    /// <param name="error">Why it could not be written.</param>
    internal static void UnreadableConfigurationMarkerNotWritten(ILogger logger, string markerPath, Exception error)
        => logger.LogError(
            error,
            "[SSO Audit] The marker {MarkerPath} could not be written. This server is serving default settings and refusing SSO now, but a restart will forget that and answer as though no provider were configured.",
            markerPath?.ReplaceLineEndings(string.Empty));

    /// <summary>Records that the marker could not be removed after a configuration arrived (#1543); a restart would refuse again.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="markerPath">The marker that could not be removed.</param>
    /// <param name="error">Why it could not be removed.</param>
    internal static void UnreadableConfigurationMarkerNotCleared(ILogger logger, string markerPath, Exception error)
        => logger.LogError(
            error,
            "[SSO Audit] The marker {MarkerPath} could not be removed. SSO is accepted again now, but a restart would refuse it once more; delete that file by hand.",
            markerPath?.ReplaceLineEndings(string.Empty));

    /// <summary>Records a configuration with a provider arriving while defaults were served (#1543), which ends the refusal; it names what landed and not who, because this line cannot know the caller.</summary>
    /// <param name="logger">The logger.</param>
    internal static void UnreadableConfigurationCleared(ILogger logger)
        => logger.LogWarning(
            "[SSO Audit] A configuration holding at least one provider was persisted; the server stops serving defaults and SSO sign-in is accepted again. The preserved copy of the unreadable file is left where it is.");

    /// <summary>Records a second copy of this plugin loaded into the same server (#1601), naming the files and the preserved copy, because the remedy is deleting a directory.</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="installLocations">The file each loaded copy came from.</param>
    /// <param name="preservedCopyPath">Where the configuration was copied, or <see langword="null"/> when it was not.</param>
    internal static void DuplicateInstallFound(ILogger logger, string installLocations, string? preservedCopyPath)
    {
        if (!logger.IsEnabled(LogLevel.Error))
        {
            return;
        }

        if (preservedCopyPath is null)
        {
            logger.LogError(
                "[SSO Audit] This plugin is loaded TWICE in this server, from {InstallLocations}, and NO copy of the configuration was kept. Two copies register every route twice, so the settings page answers nothing, and the host cannot read a configuration back across them - it serves defaults and writes them over the file, destroying every provider it holds. Every configuration write from this plugin is refused while this lasts. Stop the server, keep exactly ONE plugin directory for this plugin under the plugins folder, delete the others, and start it again. A downgrade through the plugin catalog is what usually leaves two: it adds the older version beside the newer one instead of replacing it.",
                installLocations.ReplaceLineEndings(string.Empty));
            return;
        }

        logger.LogError(
            "[SSO Audit] This plugin is loaded TWICE in this server, from {InstallLocations}. The configuration was copied to {PreservedCopy} first, and that copy is what to restore from. Two copies register every route twice, so the settings page answers nothing, and the host cannot read a configuration back across them - it serves defaults and writes them over the file. Every configuration write from this plugin is refused while this lasts. Stop the server, keep exactly ONE plugin directory for this plugin under the plugins folder, delete the others, start it again, and put the copy back over SSO-Auth.xml if the providers are gone from it. A downgrade through the plugin catalog is what usually leaves two: it adds the older version beside the newer one instead of replacing it.",
            installLocations.ReplaceLineEndings(string.Empty),
            preservedCopyPath.ReplaceLineEndings(string.Empty));
    }
}
