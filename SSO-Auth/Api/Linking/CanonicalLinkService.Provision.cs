// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Api.Metrics;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Cryptography;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Linking;

/// <summary>The provision arm: creating an account, its name, its home screen, its pending approval and its minted password.</summary>
internal sealed partial class CanonicalLinkService
{
    // Provisions a fresh account for this identity and links it on the subject key; with provisionDisabled (#737) it is created inert for an administrator to approve.
    private async Task<Guid> CreateNewAccountAsync(ProviderMode mode, string provider, string canonicalKey, string username, string? issuer, Guid? legacyLink, bool provisionDisabled, TimeSpan? provisionedAccessDuration, string? provisioningProfile)
    {
        // Resolved before the orphan warning (#1137), so a refusal cannot leave that warning untrue in the log.
        var provisionedName = ResolveProvisionedName(mode, provider, username);

        if (legacyLink.HasValue && _legacyLinkWarnGate.TryEnter(_clock()))
        {
            // The once-silent case (#354, #361): a fresh account is provisioned and the legacy target is orphaned; the upgrade runbook is https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Provider-Setup.
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "SSO login for {Name} via {Mode}/{Provider}: a legacy username-keyed link exists but no live account bears the name (it was renamed on the Jellyfin side), so a fresh account is being provisioned and the original account is now orphaned. Re-link it to this subject via the admin endpoints.",
                    username.ReplaceLineEndings(string.Empty).Replace('[', '('),
                    mode.ToToken(),
                    provider.ReplaceLineEndings(string.Empty).Replace('[', '('));
            }
        }

        if (_logger.IsEnabled(LogLevel.Information))
        {
            _logger.LogInformation("SSO user {Name} doesn't exist, creating...", provisionedName.ReplaceLineEndings(string.Empty).Replace('[', '('));
        }

        var user = await _userManager.CreateUserAsync(provisionedName).ConfigureAwait(false);

        // One guard from here to the link write (#1533): an account created here either ends up linked or does not exist, on this arm only, because the adopt arm must never delete an account.
        var linked = false;
        try
        {
            user.AuthenticationProviderId = SsoManagedProviderId.Value;

            // Counted where the account comes into existence (#1139), not at the pending-approval audit, which fires only on some providers.
            SsoMetrics.AccountProvisioned(ProvisioningOutcome.Created);

            // The static provisioning template (#1099), applied on the one arm where the account is new, so an administrator's later per-user edit survives every login.
            var template = ProvisioningTemplateFor(mode, provider, provisioningProfile);
            ProvisioningPolicy.ApplyAtProvisioning(user, template);
            // The manual-login door (#1440): a user with no password accepts the empty one, so one is minted through the helper the boot-time sweep shares.
            user.Password = ProvisionedPassword.Mint(_cryptoProvider);

            // Recorded in the same breath (#1733), so the seal can be told from a password somebody holds; its own write, because the link write below is behind the #133 race and the loser would skip the record.
            _configStore.Mutate(configuration => ProvisionedPassword.Record(configuration, user.Id, user.Password));

            // Persisted here, once: the session mint rewrites the account by id, so only this write carries the routing, the password and the disabled flag (#1440, #737); IsDisabled is written for a brand-new account only.
            if (provisionDisabled)
            {
                user.SetPermission(PermissionKind.IsDisabled, true);
            }

            await _userManager.UpdateUserAsync(user).ConfigureAwait(false);

            // A second persistence surface (#1101), written only after the account row exists; nothing about a layout may fail a login.
            SeedHomeScreen(user.Id, provisionedName, template);

            if (provisionDisabled)
            {
                // Audited at the provisioning event, so the line fires once and never mislabels an administrator's later ban.
                SsoAudit.ProvisionedPendingApproval(_logger, mode == ProviderMode.Oid ? "OpenID" : "SAML", provider, provisionedName);
            }

            // Atomic check-then-link (#133): the race loser keeps an unlinked account rather than overwriting the winner; the issuer (#186) and the deadline (#1146) are stamped only by the call that wrote the link.
            var (effectiveUserId, _) = LinkCanonicalIfAbsent(mode, provider, canonicalKey, user.Id, issuer, provisionedAccessDuration, provisionDisabled);

            // The race loser wrote no link and keeps its account; that pre-existing #133 outcome is not widened into a deletion.
            linked = true;
            return effectiveUserId;
        }
        finally
        {
            if (!linked)
            {
                await RollBackProvisionedAccountAsync(user.Id, provisionedName, mode, provider).ConfigureAwait(false);
            }
        }
    }

    // Deletes an account this login created and could not finish (#1533); its own failure is swallowed, because a throw from a finally would replace the exception that says what went wrong.
    private async Task RollBackProvisionedAccountAsync(Guid userId, string provisionedName, ProviderMode mode, string provider)
    {
        try
        {
            await _userManager.DeleteUserAsync(userId).ConfigureAwait(false);
            SsoAudit.ProvisionedAccountRolledBack(_logger, mode == ProviderMode.Oid ? "OpenID" : "SAML", provider, provisionedName);
        }
#pragma warning disable CA1031 // the failure being unwound must reach the caller, whatever the delete did
        catch (Exception ex)
#pragma warning restore CA1031
        {
            SsoAudit.ProvisionedAccountRollbackFailed(_logger, provisionedName, ex);
        }
    }

    // Writes the template's home-screen layout (#1101) for a persisted account and never lets the outcome reach the login.
    private void SeedHomeScreen(Guid userId, string provisionedName, ProvisioningPolicyTemplate? template)
    {
        if (!HomeScreenPolicy.NamesLayout(template))
        {
            return;
        }

        if (_displayPreferences is null)
        {
            _logger.LogWarning(
                "SSO user {Name}: the provisioning template names a home-screen layout, but this path holds no display-preferences store, so none was written.",
                provisionedName.ReplaceLineEndings(string.Empty).Replace('[', '('));
            return;
        }

        try
        {
            if (HomeScreenPolicy.ApplyAtProvisioning(_displayPreferences, userId, template) == 0)
            {
                // A layout was named and none was written: the stored list fails the parse the save-time validator applies.
                _logger.LogWarning(
                    "SSO user {Name}: the provisioning template's home-screen layout names a section that is not a HomeSectionType or lists more than {Slots} entries, so none was written; a save would have refused the same list.",
                    provisionedName.ReplaceLineEndings(string.Empty).Replace('[', '('),
                    HomeScreenPolicy.SlotCount);
            }
        }
        catch (Exception ex)
        {
            // Deliberately broad: the store is the host's, and a layout must never fail a login for an account that exists.
            _logger.LogWarning(
                ex,
                "SSO user {Name}: the provisioning template's home-screen layout could not be written; the account was created without it.",
                provisionedName.ReplaceLineEndings(string.Empty).Replace('[', '('));
        }
    }

    // The provider's template (#1099, #1105), read in its own short transaction so the profile set and the name pointing into it are read together; a missing or null-bodied provider (#350) carries none.
    private ProvisioningPolicyTemplate? ProvisioningTemplateFor(ProviderMode mode, string provider, string? provisioningProfile)
    {
        var resolution = _configStore.Read(configuration => ProvisioningPolicy.TemplateFor(configuration, ProviderConfigFor(configuration, mode, provider), provisioningProfile));

        // The once-silent arm (#1106): a name that resolves to nothing writes no policy and never falls back, so this line is the only sign a configured name failed; once per account, on the create arm.
        if (resolution.UnresolvedProfile is not null && _logger.IsEnabled(LogLevel.Warning))
        {
            _logger.LogWarning(
                "SSO provisioning via {Mode}/{Provider}: provisioning profile {Profile} ({Source}) is not defined, so the new account was created with NO provisioning policy. The resolution deliberately does not fall back; define that profile or remove the reference.",
                mode.ToToken(),
                provider.ReplaceLineEndings(string.Empty).Replace('[', '('),
                resolution.UnresolvedProfile.ReplaceLineEndings(string.Empty).Replace('[', '('),
                resolution.SelectedByRole ? "selected by a role mapping" : "the provider default");
        }

        return resolution.Template;
    }

    // The name a brand-new account is created under (#1137): sanitized on the create arm only, while the legacy key, the same-name lookup and the adoption comparison keep the raw name, because sanitizing those would re-point links (#829).
    private string ResolveProvisionedName(ProviderMode mode, string provider, string username)
    {
        if (!ProvisionedUsername.TrySanitize(username, out var provisionedName))
        {
            // Nothing Jellyfin would accept survived; refuse with a named reason rather than invent a name.
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "SSO login via {Mode}/{Provider} refused: the identity provider's username has no character Jellyfin accepts in an account name, so no account can be provisioned for it.",
                    mode.ToToken(),
                    provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
            }

            throw new AccountLinkForbiddenException("The SSO username contains no character Jellyfin accepts in an account name; refusing to provision an account under an invented name.");
        }

        if (string.Equals(provisionedName, username, StringComparison.Ordinal))
        {
            // Unchanged, so the caller's name-taken check still stands and the pre-#1137 path is taken byte for byte.
            return provisionedName;
        }

        if (_userManager.GetUserByName(provisionedName) != null)
        {
            // The normalized name belongs to an account this identity has not proved it owns; adopting it would be the takeover #829 rules out, so refuse and name both spellings.
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "SSO login for {Name} via {Mode}/{Provider} refused: the name normalizes to {Provisioned}, which an existing Jellyfin account already bears. Rename that account or the identity provider's username.",
                    username?.ReplaceLineEndings(string.Empty).Replace('[', '('),
                    mode.ToToken(),
                    provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
                    provisionedName.ReplaceLineEndings(string.Empty).Replace('[', '('));
            }

            throw new AccountLinkForbiddenException("The sanitized SSO username is already taken by another Jellyfin account; refusing to adopt it by name.");
        }

        if (_logger.IsEnabled(LogLevel.Information))
        {
            _logger.LogInformation(
                "SSO username {Name} via {Mode}/{Provider} carries characters Jellyfin does not accept in an account name; provisioning as {Provisioned}. The account link is keyed on the provider subject, so the rename does not affect which account later logins resolve to.",
                username?.ReplaceLineEndings(string.Empty).Replace('[', '('),
                mode.ToToken(),
                provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
                provisionedName.ReplaceLineEndings(string.Empty).Replace('[', '('));
        }

        return provisionedName;
    }

    /// <summary>Whether the resolved account is disabled and so must not be issued a session (#737); a user that vanished is left to the minter's own null guard.</summary>
    /// <param name="userId">The resolved Jellyfin user id.</param>
    /// <returns><see langword="true"/> when the account exists and is disabled.</returns>
    internal bool IsAccountAwaitingApproval(Guid userId)
    {
        var user = _userManager.GetUserById(userId);
        return user is not null && user.HasPermission(PermissionKind.IsDisabled);
    }

    /// <summary>Whether the resolved account is an administrator, read from the account and never from the provider's claim, for the mass-lockout guard (T-D1) the expiry gate (#1144) decides before acting; a vanished user reports false.</summary>
    /// <param name="userId">The resolved Jellyfin user id.</param>
    /// <returns><see langword="true"/> when the account exists and is an administrator.</returns>
    internal bool IsAccountAdministrator(Guid userId)
    {
        var user = _userManager.GetUserById(userId);
        return user is not null && user.HasPermission(PermissionKind.IsAdministrator);
    }

    /// <summary>Approves an account this plugin provisioned inert (#1529): enables it, and does nothing else.</summary>
    /// <remarks>
    /// Only an identity the create arm recorded, whose record still names the linked account, is approvable; an administrator account is refused (T-D1); the state is re-read here, and the two arms that prove the record false remove it.
    /// The enable is persisted before the record is removed, so a failed write leaves at worst a record the next read refuses.
    /// </remarks>
    /// <param name="mode">The protocol the provider speaks.</param>
    /// <param name="provider">The provider the link belongs to.</param>
    /// <param name="canonicalName">The identity key whose account is approved.</param>
    /// <returns>What happened, and the account it happened to, so the caller can audit the grant by the account it granted rather than by the subject that names a person.</returns>
    internal async Task<(PendingApprovalResult Outcome, Guid UserId)> ApproveProvisionedAccountAsync(ProviderMode mode, string provider, string? canonicalName)
    {
        // An unknown provider and a key with no live record are different answers; collapsing them would make the endpoint an existence oracle for provider names.
        var known = _configStore.Read(configuration =>
            TryGetProvider(configuration, mode, provider, out var config)
                ? (Provider: true, User: (Guid?)PendingApproval.Live(config, canonicalName)?.UserId)
                : (Provider: false, User: null));

        if (!known.Provider)
        {
            return (PendingApprovalResult.UnknownProvider, Guid.Empty);
        }

        if (known.User is not { } userId)
        {
            return (PendingApprovalResult.NotPending, Guid.Empty);
        }

        var user = _userManager.GetUserById(userId);
        if (user is null)
        {
            // The record outlived the account, so it goes with the answer rather than being offered again.
            RemovePendingApprovalOutsideLock(mode, provider, canonicalName!, userId);
            return (PendingApprovalResult.AccountGone, userId);
        }

        if (user.HasPermission(PermissionKind.IsAdministrator))
        {
            // The record is true and stays; an administrator account is enabled in the Jellyfin dashboard, not here.
            return (PendingApprovalResult.Administrator, userId);
        }

        if (!user.HasPermission(PermissionKind.IsDisabled))
        {
            // Enabled by somebody else since it was provisioned, which is the one transition nothing else here observes.
            RemovePendingApprovalOutsideLock(mode, provider, canonicalName!, userId);
            return (PendingApprovalResult.AlreadyEnabled, userId);
        }

        user.SetPermission(PermissionKind.IsDisabled, false);
        await _userManager.UpdateUserAsync(user).ConfigureAwait(false);

        RemovePendingApprovalOutsideLock(mode, provider, canonicalName!, userId);
        return (PendingApprovalResult.Approved, userId);
    }

    /// <summary>Drops a link's pending-approval record after a login that minted a session (#1637), because the account was evidently enabled outside this plugin; the common case is a locked read that writes nothing.</summary>
    /// <param name="mode">The provider protocol.</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="canonicalKey">The identity's stable subject key.</param>
    internal void ClearPendingApprovalAfterLogin(ProviderMode mode, string provider, string? canonicalKey)
    {
        if (string.IsNullOrWhiteSpace(canonicalKey))
        {
            return;
        }

        var standing = _configStore.Read(configuration =>
            TryGetProvider(configuration, mode, provider, out var config)
            && config.CanonicalLinkPendingApprovals.ContainsKey(canonicalKey));

        if (!standing)
        {
            return;
        }

        // Availability: this runs after the mint, so a failed persist must not turn a successful login into an error; the cost is a stale row the approve action refuses on its own.
        try
        {
            _configStore.Mutate(configuration => RemovePendingApproval(configuration, mode, provider, canonicalKey));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "[SSO] Could not clear the pending-approval record for provider {Provider}. The login itself succeeded; the account may still be listed as waiting.",
                provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
        }
    }

    /// <summary>The accounts the minted-password record names (#1733), read without holding the lock while the caller judges them.</summary>
    /// <returns>The account ids the record holds an entry for.</returns>
    internal IReadOnlyCollection<Guid> ProvisionedPasswordAccounts()
    {
        return _configStore.Read(configuration => (IReadOnlyCollection<Guid>)configuration.ProvisionedPasswords.Keys.ToList());
    }

    /// <summary>Applies a whole pass of the boot-time sweep to the minted-password record in one write (#1733): the accounts it sealed and the records it reclaimed.</summary>
    /// <remarks>One write for the pass, because every configuration write persists the whole store, on the startup path of exactly the upgraded servers the pass exists for.</remarks>
    /// <param name="minted">Account id to the value written to its <c>User.Password</c>.</param>
    /// <param name="reclaimed">Accounts whose record is dropped because the account no longer exists.</param>
    internal void UpdateProvisionedPasswords(IReadOnlyDictionary<Guid, string> minted, IReadOnlyCollection<Guid> reclaimed)
    {
        ArgumentNullException.ThrowIfNull(minted);
        ArgumentNullException.ThrowIfNull(reclaimed);

        _configStore.Mutate(configuration =>
        {
            foreach (var entry in minted)
            {
                ProvisionedPassword.Record(configuration, entry.Key, entry.Value);
            }

            foreach (var account in reclaimed)
            {
                ProvisionedPassword.Forget(configuration, account);
            }
        });
    }

    /// <summary>Forgets the minted-password record of a deleted account (#1733, #1649); keyed on the account and not its links, because an unlink changes no password.</summary>
    /// <param name="userId">The account to forget.</param>
    /// <returns>True when a record was removed.</returns>
    internal bool ForgetProvisionedPassword(Guid userId)
    {
        // Writes unconditionally: a Mutate persists either way, so DeletionFootprint asks first whether there is a record.
        return _configStore.Mutate(configuration => ProvisionedPassword.Forget(configuration, userId));
    }

    /// <summary>What an account leaves behind in this plugin, in one configuration acquisition: whether any provider links it and whether it holds a minted-password record (#1733, #1649).</summary>
    /// <remarks>One acquisition for both answers, because the deletion consumer asks for every deleted account and most answer no to both.</remarks>
    /// <param name="userId">The account being deleted.</param>
    /// <returns>Whether it holds a link, and whether it holds a minted-password record.</returns>
    internal (bool HoldsLink, bool HoldsMintedPasswordRecord) DeletionFootprint(Guid userId)
    {
        return _configStore.Read(configuration =>
        {
            var holdsLink = configuration.SamlConfigs.Values
                .Concat<ProviderConfigBase>(configuration.OidConfigs.Values)
                // A provider stored with a null config object (#350) holds no links.
                .Any(config => config?.CanonicalLinks is { } links && links.ContainsValue(userId));

            return (holdsLink, configuration.ProvisionedPasswords.ContainsKey(userId));
        });
    }

    /// <summary>Whether the only password the account holds is one this plugin minted (#1733).</summary>
    /// <param name="user">The account being asked about.</param>
    /// <returns>True when the stored password is the recorded one and nothing has replaced it.</returns>
    internal bool HoldsOnlyAProvisionedPassword(User user)
    {
        return user is not null
            && _configStore.Read(configuration => ProvisionedPassword.IsTheOnlyPassword(configuration, user));
    }

    // Logs the name-taken refusal and returns the exception the caller throws; only the warning is throttled (#362), never the refusal.
    private AccountLinkForbiddenException RejectNameTaken(Guid? legacyLink, ProviderMode mode, string provider, string username)
    {
        if (legacyLink.HasValue)
        {
            // The migratable case (#354): a legacy link is pending and a live account bears the name, distinct from an ordinary #95 collision.
            if (_legacyLinkWarnGate.TryEnter(_clock()))
            {
                if (_logger.IsEnabled(LogLevel.Warning))
                {
                    _logger.LogWarning(
                        "SSO login for {Name} via {Mode}/{Provider} refused: a legacy username-keyed link is pending but AllowExistingAccountLink is off and a live account still bears the name. Enable AllowExistingAccountLink (a short controlled window) or link the account via the admin endpoints to migrate it.",
                        username?.ReplaceLineEndings(string.Empty).Replace('[', '('),
                        mode.ToToken(),
                        provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
                }
            }
        }
        else
        {
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "SSO login for {Name} via {Mode}/{Provider} refused: a pre-existing unlinked Jellyfin account exists and AllowExistingAccountLink is disabled for this provider.",
                    username?.ReplaceLineEndings(string.Empty).Replace('[', '('),
                    mode.ToToken(),
                    provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
            }
        }

        return new AccountLinkForbiddenException();
    }

    // Records that this login provisioned the linked account inert (#1529), with the provisioning instant, so the accounts page can say how long somebody has waited.
    // A set-or-clear: every other write of the same key is not a provisioning, and a record left standing would name somebody else's account.
    private void RecordPendingApprovalInPlace(PluginConfiguration configuration, ProviderMode mode, string provider, string canonicalKey, Guid userId, bool provisionedPendingApproval)
    {
        if (!TryGetProvider(configuration, mode, provider, out var config))
        {
            return;
        }

        if (!provisionedPendingApproval)
        {
            config.CanonicalLinkPendingApprovals.Remove(canonicalKey);
            return;
        }

        config.CanonicalLinkPendingApprovals[canonicalKey] = new PendingApproval
        {
            UserId = userId,
            SinceUtc = _clock().ToUniversalTime(),
        };
    }

    // Its own step beside the two above, because an orphan mark is an offer to enable an account (#1529).
    private static void RemovePendingApproval(PluginConfiguration configuration, ProviderMode mode, string provider, string canonicalKey)
    {
        if (TryGetProvider(configuration, mode, provider, out var config))
        {
            config.CanonicalLinkPendingApprovals.Remove(canonicalKey);
        }
    }

    // The same removal for the approve and disable paths, which write the account between reading the record and dropping it and so hold no transaction (#1529).
    // Compare-and-remove: the key may have been freed and written for a new account in between, and that account's record must stay.
    private void RemovePendingApprovalOutsideLock(ProviderMode mode, string provider, string canonicalKey, Guid userId)
        => _configStore.Mutate(configuration =>
        {
            if (TryGetProvider(configuration, mode, provider, out var config)
                && config.CanonicalLinkPendingApprovals.TryGetValue(canonicalKey, out var record)
                && record?.UserId == userId)
            {
                config.CanonicalLinkPendingApprovals.Remove(canonicalKey);
            }
        });

    // Stamps the role-mapped deadline beside a link this transaction wrote (#1146), from the instance clock, on both protocols; a duration outside the validator's bounds stamps nothing rather than throwing, since DateTime.AddHours throws past MaxValue.
    private void RecordProvisionedDeadlineInPlace(PluginConfiguration configuration, ProviderMode mode, string provider, string canonicalKey, TimeSpan? provisionedAccessDuration)
    {
        if (!TryGetProvider(configuration, mode, provider, out var config))
        {
            return;
        }

        // A set-or-clear (#1638): the key may have held a deleted account's deadline, and a login without a duration must not inherit it.
        if (provisionedAccessDuration is not { } duration
            || duration <= TimeSpan.Zero
            || duration > TimeSpan.FromHours(GuestAccessDurationRoleMap.MaxDurationHours))
        {
            config.CanonicalLinkDeadlines.Remove(canonicalKey);
            return;
        }

        config.CanonicalLinkDeadlines[canonicalKey] = _clock().ToUniversalTime() + duration;
    }
}
