// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Audit;

/// <summary>
/// Emits consistent, structured audit-log entries for security-relevant SSO events that exist today:
/// successful logins, adoption of a pre-existing account, and provider configuration changes. Every
/// entry shares the "[SSO Audit]" prefix so operators can filter the trail, and only non-sensitive
/// fields are logged (never secrets or certificates). Identity-provider- and admin-supplied values
/// are stripped of line endings inline before logging so they cannot forge or split an entry.
/// Each call is guarded by <see cref="ILogger.IsEnabled(LogLevel)"/> so the inline line-ending
/// sanitizer is not evaluated when the level is disabled (net10 CA1873, #566); the sanitizer stays
/// at the logging call so CodeQL's log-forging taint tracking still sees it inline.
/// </summary>
internal static class SsoAudit
{
    /// <summary>Records a successful login (a session was issued).</summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="username">The Jellyfin username the session was issued for.</param>
    /// <param name="isAdmin">Whether the session was granted administrator rights.</param>
    internal static void LoginSucceeded(ILogger logger, string protocol, string provider, string username, bool isAdmin)
    {
        if (!logger.IsEnabled(LogLevel.Information))
        {
            return;
        }

        logger.LogInformation(
            "[SSO Audit] Login succeeded: {Username} via {Protocol} provider '{Provider}' (admin={IsAdmin}).",
            username?.ReplaceLineEndings(string.Empty),
            protocol,
            provider?.ReplaceLineEndings(string.Empty),
            isAdmin);
    }

    /// <summary>
    /// Records a new SSO identity being provisioned as a disabled account pending administrator approval
    /// (#737, ProvisionNewUsersDisabled). No session was issued; an administrator must enable the account.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="username">The Jellyfin username the disabled account was created under.</param>
    internal static void ProvisionedPendingApproval(ILogger logger, string protocol, string provider, string username)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] New account provisioned pending approval: '{Username}' via {Protocol} provider '{Provider}' was created disabled (ProvisionNewUsersDisabled); no session issued. Enable it in the Jellyfin dashboard to approve.",
            username?.ReplaceLineEndings(string.Empty),
            protocol,
            provider?.ReplaceLineEndings(string.Empty));
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
            displayName?.ReplaceLineEndings(string.Empty),
            protocol,
            provider?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>
    /// Records a linked account being renamed to follow its identity provider (#1138). The rename changes
    /// the name an administrator sees in the Jellyfin dashboard and nothing else, so the trail has to say
    /// which name became which - without it, an account an operator is looking for has silently become a
    /// different row in the user list with no record of why. Both names are identity-provider-influenced,
    /// so both are stripped of line endings inline at the call, like every other name this file logs.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
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
            previousName?.ReplaceLineEndings(string.Empty),
            newName?.ReplaceLineEndings(string.Empty),
            protocol,
            provider?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>
    /// Records an existing account being disabled by login-time deprovisioning (#831): its SSO login was
    /// denied by the role allow-list and the provider opts into disabling on denial. Only non-sensitive
    /// fields are logged - the protocol and provider name, never the subject/username (T-I1) - so an
    /// offboarding (or a mass-disable incident from a misconfigured allow-list) leaves an operator trail.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
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
            provider?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>
    /// Records an existing account being disabled because its access deadline has passed (#1144): the
    /// provider configures an account-expiry claim and the login carried an instant at or before now. Fired
    /// once, at the transition, never on the later refused logins of an account already disabled by it. Only
    /// non-sensitive fields are logged - the protocol and provider name, never the subject/username or the
    /// deadline itself (T-I1) - so an offboarding, or a mass-expiry incident from an identity provider that
    /// starts emitting a past instant, leaves an operator trail.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
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
            provider?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>
    /// Records an account being disabled by the between-logins expiry sweep (#1145): its persisted deadline
    /// passed with no login attempt in between, so nothing on the login path was ever going to notice. Fired
    /// once, at the transition, never on later ticks that find the account already disabled. Carries the same
    /// non-sensitive fields as the login-time line - the protocol and provider name, never the subject or the
    /// deadline (T-I1) - and is worded distinctly from it because the two answer different operator questions:
    /// this one says access ended on the clock while the user was away.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
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
            provider?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>
    /// Records the boot-time sweep sealing SSO-linked accounts that carried no stored password (#1440).
    /// A Jellyfin account created without one accepts the EMPTY password on the ordinary login form, so
    /// an account this plugin provisioned was reachable without it on every build before the create arm's
    /// password write was made durable. THE LINE NAMES NO VERSION RANGE, and #1454 is why: that write
    /// existed for years and reached no database, so the population is a STATE - a linked account holding
    /// no password - rather than a span of releases, and a message naming one told an operator with newer
    /// accounts to stop looking. Fired once per boot and only when the sweep actually sealed something, so a
    /// server that has none stays silent. Carries a COUNT and nothing else - no username, no account id and
    /// no provider (T-I1): an account already reachable by anybody is the last thing to name in a log an
    /// operator may paste into a bug report.
    /// </summary>
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
            provider?.ReplaceLineEndings(string.Empty));
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
            provider?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>
    /// Records that a subscriber to the plugin's <c>ConfigurationChanged</c> event threw (#1521). The write
    /// it is being told about is already on disk and already live, so the failure is contained here rather
    /// than unwound: letting it out would reach the store's rollback and revert a durable change. Warning
    /// rather than Error: whoever subscribed did not get its update, and nothing this plugin owns is wrong.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="error">What the subscriber threw. No configuration content is recorded.</param>
    internal static void ConfigurationChangedSubscriberFailed(ILogger logger, Exception error)
    {
        if (logger is null || !logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] A ConfigurationChanged subscriber failed after a completed configuration save ({Reason}). The save itself is stored and live; whatever that subscriber keeps in step with the configuration may not be.",
            error?.Message?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>
    /// Records that a configuration write went ahead without an undo, because the state it would have
    /// restored could not be serialized (#1521). The write itself is NOT refused: refusing it would make a
    /// configuration that once reached this state permanently unwritable, including the delete that would
    /// repair it. Warning, because the all-or-nothing property the import endpoints promise does not hold
    /// for this one write and an operator reading a later 500 deserves to find this line above it.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="error">What refused the serialization. No configuration content is recorded.</param>
    internal static void ConfigurationRollbackUnavailable(ILogger logger, Exception error)
    {
        if (logger is null || !logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] Configuration write proceeding without a rollback: the current configuration could not be serialized for one ({Reason}). If this write fails, the running server keeps the change while the file does not, until the next restart.",
            error?.Message?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>
    /// Records that a configuration write failed AND the undo for it failed too (#1521), so the running
    /// server is left carrying a change the file does not have. Error rather than Warning: this is the state
    /// the rollback exists to prevent, the exception the caller sees names the write rather than this, and a
    /// restart is what puts the server back on the file.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="error">What the restore threw. No configuration content is recorded.</param>
    internal static void ConfigurationRollbackFailed(ILogger logger, Exception error)
    {
        if (logger is null || !logger.IsEnabled(LogLevel.Error))
        {
            return;
        }

        logger.LogError(
            "[SSO Audit] Configuration write failed and could not be rolled back ({Reason}): the running server is carrying a change that is not in the file. Restart the server to put it back on the stored configuration.",
            error?.Message?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>
    /// Records a config-page save whose changes to a declaratively managed provider were ignored (#1102). The
    /// provider is decided by the mounted document or the environment, so the stored value was kept and the
    /// posted one discarded. Warning rather than Information: an administrator has just made an edit the
    /// server did not take, and the settings page is where they would otherwise wait for it to hold.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
    /// <param name="provider">The provider name. No field value is recorded - the point is which provider, not what was posted.</param>
    internal static void DeclarativeWriteIgnored(ILogger logger, string protocol, string provider)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] Configuration save ignored for {Protocol} provider '{Provider}': it is managed by a declarative source, so the stored value was kept. Edit the source and restart the server to change it.",
            protocol,
            provider?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>
    /// Records a configuration save whose write to a declaratively defined provisioning profile was ignored
    /// (#1102). The profile is what a managed provider provisions a new account THROUGH, so a save that
    /// redefines one changes what that provider grants without naming it - which is why this line exists
    /// separately from <see cref="DeclarativeWriteIgnored"/> rather than borrowing its wording.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="profile">The profile name. No field value is recorded - the point is which profile, not what was posted.</param>
    internal static void DeclarativeProfileWriteIgnored(ILogger logger, string profile)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] Configuration save ignored for provisioning profile '{Profile}': it is defined by a declarative source, so the stored value was kept. Edit the source and restart the server to change it.",
            profile?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>
    /// Records an elevated write door refusing to alter or delete a declaratively managed provider (#1415).
    /// The config-page save IGNORES such a write and keeps the stored value (see
    /// <see cref="DeclarativeWriteIgnored"/>); these doors carry a single-provider intent that cannot be
    /// half-honoured, so they refuse instead and nothing is written. Warning for the same reason: an
    /// administrator has just asked for a change the server did not make.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="door">The route that was refused, e.g. <c>OID/Del</c>.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
    /// <param name="provider">The provider name. No field value is recorded - the point is which provider, not what was posted.</param>
    /// <param name="source">What names the source that owns the provider, so the line says where the change belongs.</param>
    internal static void DeclarativeWriteRefused(ILogger logger, string door, string protocol, string provider, string source)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] {Door} refused for {Protocol} provider '{Provider}': it is managed by the declarative source {Source}, so nothing was written. Edit that source and restart the server to change it.",
            door?.ReplaceLineEndings(string.Empty),
            protocol,
            provider?.ReplaceLineEndings(string.Empty),
            source?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>
    /// Records a whole-document write door refusing because the document redefines a declaratively defined
    /// provisioning profile (#1102). Refuse rather than ignore, for the reason
    /// <see cref="DeclarativeWriteRefused"/> gives: an import is all-or-nothing on every other rejection,
    /// and dropping part of a document silently is the worse failure.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="door">The route that was refused, e.g. <c>Config/Import</c>.</param>
    /// <param name="profile">The profile name. No field value is recorded.</param>
    /// <param name="source">What names the source that defined the profile, so the line says where the change belongs.</param>
    internal static void DeclarativeProfileWriteRefused(ILogger logger, string door, string profile, string source)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] {Door} refused for provisioning profile '{Profile}': it is defined by the declarative source {Source}, so nothing was written. Edit that source and restart the server to change it.",
            door?.ReplaceLineEndings(string.Empty),
            profile?.ReplaceLineEndings(string.Empty),
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
            provider?.ReplaceLineEndings(string.Empty));
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

    /// <summary>
    /// Records an administrator restoring an account-link backup (#1129). Every restored link is a grant
    /// of future login capability made on an administrator credential alone and with no identity-provider
    /// round trip, in bulk, so it is warned rather than informed for the same reason the single
    /// pre-provision write below is: it is the line an operator looks for when an account turns out to
    /// sign in as somebody it should not.
    /// </summary>
    /// <remarks>
    /// The canonical subjects are deliberately not fields here, exactly as they are not on the single
    /// write below (T-I1). The per-provider counts are what tell an operator whether the restore matched
    /// the backup they applied, and a subject is the one value in that document that identifies a real
    /// person at the identity provider.
    /// </remarks>
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
            actor?.ReplaceLineEndings(string.Empty),
            totalLinks,
            perProvider?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>
    /// Records an administrator pre-provisioning a canonical link with no identity-provider round trip
    /// (#1133). A grant of future login capability made on an administrator credential alone, so it is
    /// warned rather than informed: it is the line an operator looks for when an account turns out to sign
    /// in as somebody it should not.
    /// </summary>
    /// <remarks>
    /// The canonical subject is deliberately NOT a field here. The audit trail already carries no raw
    /// subject value (T-I1), the provider and the target account are what identify the grant for an
    /// operator, and the subject would be the one member of the request that is an identifier for a real
    /// person at the identity provider.
    /// </remarks>
    /// <param name="logger">The logger.</param>
    /// <param name="actor">The elevated administrator who made the link.</param>
    /// <param name="protocol">The protocol (OpenID or SAML).</param>
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
            actor?.ReplaceLineEndings(string.Empty),
            protocol,
            provider?.ReplaceLineEndings(string.Empty),
            jellyfinUserId);
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
            actor?.ReplaceLineEndings(string.Empty),
            breakGlassAdmin?.ReplaceLineEndings(string.Empty),
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
            actor?.ReplaceLineEndings(string.Empty),
            restoredCount);
    }

    /// <summary>
    /// Records an SSO-only activation (or designation) being REFUSED by the fail-closed guard (#165), so a
    /// blocked lockout attempt leaves a trail (T-R1). The reason is a fixed verdict CODE, never a username or
    /// roster (T-I1).
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="actor">The elevated administrator whose activation was refused.</param>
    /// <param name="reasonCode">The guard verdict name (a fixed enum member, not user input).</param>
    internal static void SsoOnlyLoginActivationRefused(ILogger logger, string actor, string reasonCode)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] SSO-only login activation REFUSED for {Actor}: no surviving admin login path ({ReasonCode}). No change was made.",
            actor?.ReplaceLineEndings(string.Empty),
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
            actor?.ReplaceLineEndings(string.Empty),
            breakGlassAdmin?.ReplaceLineEndings(string.Empty));
    }

    /// <summary>
    /// Records a validated inbound SAML <c>LogoutRequest</c> that terminated sessions (#727, SLO-3b). Only
    /// non-sensitive fields are logged: the provider name and the count of Jellyfin users whose tokens were
    /// revoked - never the raw NameID or SessionIndex, which are subject identifiers (T-I1). The provider is
    /// route input, so its line endings are stripped inline before logging (log-forging defense).
    /// </summary>
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
            provider?.ReplaceLineEndings(string.Empty),
            usersRevoked);
    }

    /// <summary>
    /// Records an inbound SAML <c>LogoutRequest</c> being rejected fail-closed (#727, SLO-3b). The reason is a
    /// FIXED code (unsigned/malformed/replay/no-matching-session, a constant, never request-derived text), so
    /// a blocked forged logout leaves a trail (T-R1) without disclosing subject identifiers or which branch
    /// rejected it to the caller (the caller sees only a uniform 400). The provider is route input, stripped
    /// of line endings inline before logging.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="provider">The SAML provider the request arrived for.</param>
    /// <param name="reasonCode">The fixed rejection reason code (not request-derived).</param>
    internal static void LogoutRejected(ILogger logger, string provider, string reasonCode)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] SAML logout request REJECTED for provider '{Provider}' ({ReasonCode}). No session was terminated.",
            provider?.ReplaceLineEndings(string.Empty),
            reasonCode);
    }

    /// <summary>
    /// Records an inbound OpenID <c>logout_token</c> being rejected fail-closed (#962). Separate from
    /// <see cref="LogoutRejected"/>, which is worded for the SAML <c>LogoutRequest</c> sites it is shared by:
    /// an operator filtering their log for OpenID logout failures used to find every one of them filed under
    /// "SAML" (#1184). This is the benign class - a forged, replayed or malformed token is the system working,
    /// and nothing was supposed to be terminated. The reason is a FIXED code, never token-derived, and the
    /// caller still answers the one uniform 400, so nothing here becomes a branch oracle.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="provider">The OpenID provider the token arrived for.</param>
    /// <param name="reasonCode">The fixed rejection reason code (not token-derived).</param>
    internal static void BackChannelLogoutRejected(ILogger logger, string provider, string reasonCode)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] OpenID back-channel logout REJECTED for provider '{Provider}' ({ReasonCode}). No session was terminated.",
            provider?.ReplaceLineEndings(string.Empty),
            reasonCode);
    }

    /// <summary>
    /// Records a back-channel logout the plugin could NOT perform (#1184) - the inverse of
    /// <see cref="BackChannelLogoutRejected"/> and the reason the two are separate events. Here the identity
    /// provider ordered a termination and the plugin declined it, so an authenticated session is still running
    /// after the IdP signed the user out. That is the entry an operator alerts on, and it is reachable
    /// deliberately: an attacker who can disrupt the server-to-IdP path can produce it. Recorded at
    /// <see cref="LogLevel.Error"/> so it separates from the rejection noise by severity as well as by text.
    /// The wire response is unchanged - the same uniform 400 - so the distinction stays in the audit trail.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="provider">The OpenID provider the termination was ordered for.</param>
    /// <param name="reasonCode">The fixed reason code (not token-derived).</param>
    internal static void BackChannelLogoutNotPerformed(ILogger logger, string provider, string reasonCode)
    {
        if (!logger.IsEnabled(LogLevel.Error))
        {
            return;
        }

        logger.LogError(
            "[SSO Audit] OpenID back-channel logout could NOT be performed for provider '{Provider}' ({ReasonCode}). The identity provider ordered a termination and no session was terminated, so a signed-out session may still be running.",
            provider?.ReplaceLineEndings(string.Empty),
            reasonCode);
    }

    /// <summary>
    /// Records an OpenID role claim the walk REFUSED, with the reason it refused it (#1149). Before this
    /// existed a broken role-claim path and a provider that legitimately sent no roles looked identical from
    /// outside: both produced an empty role set and no entry, and under a configured <c>Roles</c> allow-list
    /// both produced a denied login the operator could not explain.
    /// <para>
    /// The reason is a FIXED code taken from the walk's own outcome, never claim-derived text. The claim
    /// VALUE never appears: a role claim carries group memberships, distinguished names and sometimes
    /// e-mail addresses, so the provider name and the reason code are the whole permitted payload. The
    /// provider is stripped of line endings inline at the call, like every other entry here.
    /// </para>
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="provider">The OpenID provider whose claim was refused.</param>
    /// <param name="reasonCode">The fixed refusal reason from the walk (not claim-derived).</param>
    internal static void RoleClaimRefused(ILogger logger, string provider, string reasonCode)
    {
        if (!logger.IsEnabled(LogLevel.Warning))
        {
            return;
        }

        logger.LogWarning(
            "[SSO Audit] OpenID provider '{Provider}': the configured role claim could not be read ({ReasonCode}), so this login was granted NO roles from it. Under a configured role allow-list that denies the login; check the role-claim path against what the provider actually emits.",
            provider?.ReplaceLineEndings(string.Empty),
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

        // Shared by OpenID (#140) and SAML (#672), so the wording stays protocol-neutral: each named option
        // switches off a protection that is on by default (OpenID transport/issuer/endpoint binding, SAML
        // audience binding). Naming the exact options is what the audit trail needs; the per-option detail
        // lives in each toggle's config doc.
        logger.LogWarning(
            "[SSO Audit] {Protocol} provider '{Provider}' saved with security checks disabled: {Options}. Each switches off a default-on protection on the login path (such as transport, issuer/audience, or endpoint binding); keep them only if the provider genuinely requires it.",
            protocol,
            provider?.ReplaceLineEndings(string.Empty),
            string.Join(", ", options));
    }
}
