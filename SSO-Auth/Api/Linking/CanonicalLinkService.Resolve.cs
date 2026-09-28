// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Metrics;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Cryptography;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Linking;

/// <summary>The resolve arm: an SSO identity to a Jellyfin account, the legacy-link migration and the issuer binding.</summary>
internal sealed partial class CanonicalLinkService
{
    /// <summary>Resolves the login's stable identity to a Jellyfin user, creating or adopting the account per the provider's policy, and returns its id; throws <see cref="AccountLinkForbiddenException"/> when the login must be refused.</summary>
    /// <param name="mode">The protocol the operation applies to, parsed once at the controller boundary (#369).</param>
    /// <param name="provider">The provider the login authenticated against.</param>
    /// <param name="canonicalKey">The stable identity key (OpenID sub / SAML NameID).</param>
    /// <param name="username">The display name the account is provisioned/adopted under.</param>
    /// <param name="allowExistingAccountLink">Whether adopting a pre-existing unlinked account is permitted.</param>
    /// <param name="adoptionGate">The proof a same-named adoption must clear (#218): a privileged target is always refused, and a gate that requires a verified email refuses a login without <c>email_verified</c>.</param>
    /// <param name="issuer">The OpenID login's id_token issuer the link is bound to (#186): a stored issuer that differs refuses the login, an absent one is stamped on first use; null for SAML or a token without <c>iss</c>.</param>
    /// <param name="provisionDisabled">The provider's ProvisionNewUsersDisabled policy (#737): a brand-new account is created disabled for an administrator to approve; never applied to an existing or adopted account.</param>
    /// <param name="provisionedAccessDuration">The role-mapped access duration (#1146), stamped as a deadline beside the link on the create arm only, so it is set once and never slid forward or given to an adopted account.</param>
    /// <param name="syncUsername">The provider's SyncUsernameFromProvider policy (#1138): on the resolve arm only, rename the linked account to the name the login presents.</param>
    /// <param name="provisioningProfile">The provisioning-profile name the login's roles selected (#1106), applied on the create arm only and resolved inside this service's own locked read; null lets the provider's default decide (#1105).</param>
    /// <returns>The resolved Jellyfin user id.</returns>
    internal async Task<Guid> ResolveOrCreateAsync(ProviderMode mode, string provider, string canonicalKey, string username, bool allowExistingAccountLink, AdoptionGate adoptionGate = default, string? issuer = null, bool provisionDisabled = false, TimeSpan? provisionedAccessDuration = null, bool syncUsername = false, string? provisioningProfile = null)
    {
        // Defense in depth (#95, #155): both callbacks reject such logins before calling here.
        if (string.IsNullOrWhiteSpace(canonicalKey) || string.IsNullOrWhiteSpace(username))
        {
            throw new AccountLinkForbiddenException("The SSO login did not resolve an identity; refusing to create or link an account.");
        }

        // Read candidates, refuse a repoint, maybe migrate or stamp, resolve, act.
        var candidates = ReadResolutionCandidates(mode, provider, canonicalKey, username, issuer);

        RefuseRepointedIssuer(candidates, mode, provider, username);

        // Resolved once outside the config lock; it is the adoption candidate and, when it is the legacy link's target, the proof that the legacy name still matches (#361).
        var existingAccount = _userManager.GetUserByName(username);
        Guid? existingAccountUserId = existingAccount?.Id;
        bool legacyNameStillHeldByTarget = candidates.LegacyLink.HasValue && existingAccountUserId == candidates.LegacyLink;

        var (linkedUserId, migrateLegacy) = AccountLinkResolver.ResolveCanonicalLink(candidates.SubjectLink, candidates.LegacyLink, legacyNameStillHeldByTarget, allowExistingAccountLink);
        if (migrateLegacy)
        {
            // Migration fires only when the account bearing the name is the legacy target, so existingAccount is non-null here.
            linkedUserId = MigrateLegacyLinkIfEligible(mode, provider, canonicalKey, username, issuer, existingAccount!);
        }
        else if (candidates.SubjectLink.HasValue && candidates.SubjectIssuer == IssuerBinding.Absent)
        {
            // Trust-on-first-use (#186): a subject link with no stored issuer is stamped with this login's, so a later issuer swap behind the same URL is caught; skipped when the login carries none.
            StampIssuer(mode, provider, canonicalKey, issuer);
        }

        // An un-migrated legacy link is labelled by its terminal branch below, each through the shared once-per-interval gate (#362); only the warning is throttled, never the refusal or the creation.

        // Adoption of a pre-existing unlinked account still matches on the display name resolved above.
        var decision = AccountLinkResolver.Resolve(linkedUserId, existingAccountUserId, allowExistingAccountLink);
        switch (decision.Action)
        {
            case AccountLinkAction.UseExistingLink:
                // The one arm where the two names can have drifted apart since the account was created.
                return await SyncUsernameIfRequestedAsync(syncUsername, mode, provider, decision.UserId, username).ConfigureAwait(false);

            case AccountLinkAction.AdoptExistingAccount:
                // existingAccount is non-null here (adoption is only chosen when a named account resolved).
                return AdoptExistingAccount(mode, provider, canonicalKey, username, issuer, existingAccount!, adoptionGate, decision.UserId);

            case AccountLinkAction.CreateNewAccount:
                return await CreateNewAccountAsync(mode, provider, canonicalKey, username, issuer, candidates.LegacyLink, provisionDisabled, provisionedAccessDuration, provisioningProfile).ConfigureAwait(false);

            case AccountLinkAction.RejectNameTaken:
                throw RejectNameTaken(candidates.LegacyLink, mode, provider, username);

            default:
                throw new InvalidOperationException($"Unhandled account-link action: {decision.Action}");
        }
    }

    // Reads the subject-keyed link, the legacy username-keyed link (#155) and the subject link's issuer binding (#186) in one locked pass, so a concurrent migration or stamp cannot tear the verdict.
    // The legacy key is a name the identity provider controls, so following it honours AllowExistingAccountLink (#354) and only while the target still bears the name (#361); a link to a deleted user counts as absent.
    private ResolutionCandidates ReadResolutionCandidates(ProviderMode mode, string provider, string canonicalKey, string username, string? issuer)
    {
        return _configStore.Read(configuration =>
        {
            // Deleted or disabled since the callback's lookup: fail closed (#373, #380). The mint runs outside the lock, so the last guarded transaction of each arm is the final checkpoint.
            if (!TryGetLinks(configuration, mode, provider, requireEnabled: true, out var links))
            {
                throw new AccountLinkForbiddenException("The SSO provider is no longer configured or is disabled; refusing to resolve or create an account.");
            }

            Guid? bySubject = links.TryGetValue(canonicalKey, out var s) && _userManager.GetUserById(s) != null
                ? s : null;
            Guid? byName = bySubject is null
                && !string.Equals(canonicalKey, username, StringComparison.Ordinal)
                && links.TryGetValue(username, out var n) && _userManager.GetUserById(n) != null
                ? n : (Guid?)null;

            // Classified in the same locked read (#186), so the verdict cannot tear against a concurrent stamp or repoint.
            var issuerVerdict = bySubject is null
                ? IssuerBinding.NotBound
                : ClassifyIssuer(configuration, mode, provider, canonicalKey, issuer);
            return new ResolutionCandidates(bySubject, byName, issuerVerdict);
        });
    }

    // Fail closed (#186): a subject link minted under a different issuer belongs to another identity provider's user; a login carrying no issuer against a stamped link is a mismatch too.
    private void RefuseRepointedIssuer(ResolutionCandidates candidates, ProviderMode mode, string provider, string username)
    {
        if (candidates.SubjectLink.HasValue && candidates.SubjectIssuer == IssuerBinding.Mismatch)
        {
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "OpenID login for {Name} via {Mode}/{Provider} refused: the account link's stored issuer does not match the login's issuer (the provider entry may have been repointed at a different identity provider). Re-establish the link via the admin endpoints.",
                    username?.ReplaceLineEndings(string.Empty).Replace('[', '('),
                    mode.ToToken(),
                    provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
            }

            throw new AccountLinkForbiddenException("The account link was minted under a different issuer; refusing to resolve it after an apparent provider repoint.");
        }
    }

    // The #155 legacy re-key behind the admin refusal, in one config transaction (#363); the name contains "Migrate", so the #363 conformance rule pins its Guid? return type.
    private Guid? MigrateLegacyLinkIfEligible(ProviderMode mode, string provider, string canonicalKey, string username, string? issuer, User existingAccount)
    {
        // The re-key is name-based matching too (#218): a new subject presenting an administrator's preferred_username must not take the account over; the verified-email gate is not applied to a relationship formed before #155.
        if (AdoptionEligibilityResolver.Resolve(existingAccount.HasPermission(PermissionKind.IsAdministrator), AdoptionGate.None) != AdoptionVerdict.Allow)
        {
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "SSO login for {Name} via {Mode}/{Provider} refused: a legacy username-keyed link points at an administrator account, which is not adopted by name. Sign in to that account with its own password and link it at /SSOViews/linking, or pre-provision the link with an elevated call to the account-management API.",
                    username?.ReplaceLineEndings(string.Empty).Replace('[', '('),
                    mode.ToToken(),
                    provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
            }

            throw new AccountLinkForbiddenException();
        }

        // Re-key and re-resolve in one transaction (#363) and bind to what it returns, so a concurrent migration between the candidate read and here cannot be bound to a stale snapshot.
        var migratedUserId = MigrateAndResolveCanonicalLink(mode, provider, canonicalKey, username, issuer);
        if (_logger.IsEnabled(LogLevel.Information))
        {
            _logger.LogInformation(
                "Migrated {Mode}/{Provider} canonical link from the legacy username key to the stable subject key.",
                mode.ToToken(),
                provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
        }

        return migratedUserId;
    }

    // Renames a resolved account to follow its identity provider (#1138); every early return keeps the name and still logs the user in, and the account arrives by id, so the name never selects one.
    // Guards, in order: the presented name is sanitized like a provisioned one (#1137), a name held by a different account is left alone, and any other host refusal is logged and swallowed.
    private async Task<Guid> SyncUsernameIfRequestedAsync(bool syncUsername, ProviderMode mode, string provider, Guid userId, string presentedName)
    {
        if (!syncUsername || !ProvisionedUsername.TrySanitize(presentedName, out var desiredName))
        {
            return userId;
        }

        var account = _userManager.GetUserById(userId);
        if (account is null || string.Equals(account.Username, desiredName, StringComparison.Ordinal))
        {
            return userId;
        }

        var currentName = account.Username;
        var holder = _userManager.GetUserByName(desiredName);
        if (holder is not null && holder.Id != userId)
        {
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "SSO login via {Mode}/{Provider}: the identity provider's username is already held by a different Jellyfin account, so the linked account keeps its current name. Rename or merge the other account to let the sync proceed.",
                    mode.ToToken(),
                    provider.ReplaceLineEndings(string.Empty).Replace('[', '('));
            }

            return userId;
        }

        // Bound at runtime: IUserManager.RenameUser changed shape between 10.11.8 and 10.11.9, and HostRename resolves whichever the host has.
        try
        {
            var call = HostRename.Resolve(_userManager.GetType(), account, userId, currentName, desiredName)
                ?? throw new InvalidOperationException(HostRename.NeitherShape);

            object? returned;
            try
            {
                returned = call.Method.Invoke(_userManager, call.Arguments);
            }
            catch (TargetInvocationException wrapped) when (wrapped.InnerException is not null)
            {
                // Unwrapped so the log names the host's reason rather than the reflection wrapper.
                ExceptionDispatchInfo.Capture(wrapped.InnerException).Throw();
                throw;
            }

            // A shape that returns no Task is awaited as nothing: the rename has already happened.
            if (returned is Task rename)
            {
                await rename.ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            // Deliberately broad: the host decides what a legal name is, and a cosmetic mismatch must never fail a login.
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    ex,
                    "SSO login via {Mode}/{Provider}: renaming the linked account to follow the identity provider failed; it keeps its current name and the login continues.",
                    mode.ToToken(),
                    provider.ReplaceLineEndings(string.Empty).Replace('[', '('));
            }

            return userId;
        }

        SsoAudit.AccountRenamed(_logger, mode == ProviderMode.Oid ? "OpenID" : "SAML", provider, currentName, desiredName);
        return userId;
    }

    // Adopts the account that shares the display name after the eligibility gate; existingAccount is non-null by the caller's contract.
    private Guid AdoptExistingAccount(ProviderMode mode, string provider, string canonicalKey, string username, string? issuer, User existingAccount, AdoptionGate adoptionGate, Guid candidateUserId)
    {
        // Same-name adoption trusts the identity provider to keep names unique (#218): an administrator is never adopted by name, and a verified-email gate must be met; a refusal writes no link and no audit.
        var verdict = AdoptionEligibilityResolver.Resolve(
            existingAccount.HasPermission(PermissionKind.IsAdministrator),
            adoptionGate);
        if (verdict != AdoptionVerdict.Allow)
        {
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "SSO login for {Name} via {Mode}/{Provider} refused adoption of a pre-existing account: {Reason}.",
                    username?.ReplaceLineEndings(string.Empty).Replace('[', '('),
                    mode.ToToken(),
                    provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
                    DescribeAdoptionRefusal(verdict));
            }

            throw new AccountLinkForbiddenException();
        }

        // Atomic check-then-link (#133): a concurrent first login's winner is used, with no second write or audit.
        var (adoptedUserId, wrote) = LinkCanonicalIfAbsent(mode, provider, canonicalKey, candidateUserId, issuer);
        if (wrote)
        {
            SsoAudit.AccountAdopted(_logger, mode == ProviderMode.Oid ? "OpenID" : "SAML", provider, username);
            SsoMetrics.AccountProvisioned(ProvisioningOutcome.Adopted);
        }

        return adoptedUserId;
    }

    /// <summary>The fixed reason phrase the refusal line carries for an adoption this gate turned down.</summary>
    /// <remarks>Internal so a test can read the phrases; a literal per arm keeps CodeQL's private-information heuristic off the enum member name (#1765).</remarks>
    /// <param name="verdict">The eligibility verdict the resolver returned.</param>
    /// <returns>A non-PII phrase naming what was refused and, where there is one, the way through.</returns>
    internal static string DescribeAdoptionRefusal(AdoptionVerdict verdict) => verdict switch
    {
        AdoptionVerdict.RefusePrivileged => "the target account is an administrator; sign in to that account with its own password and link it at /SSOViews/linking, or pre-provision the link with an elevated call to the account-management API",
        AdoptionVerdict.RefuseUnverifiedEmail => "the provider requires a verified email for adoption and the login carried none",
        _ => "the account is not eligible for name-based adoption",
    };

    /// <summary>Whether the identity may still mint a session for the user: the provider is enabled, its link still points at the user, and the user exists; read under the lock, so it is linearized against a revocation or a disable.</summary>
    /// <remarks>The in-flight revocation gate (#232): the mint runs after the lock is released, so the flow re-reads this before the side effects and again last before the mint, shrinking the window to the one unavoidable gap; every unknown resolves to false.</remarks>
    /// <param name="mode">The protocol the operation applies to, parsed once at the controller boundary (#369).</param>
    /// <param name="provider">The provider the login authenticated against.</param>
    /// <param name="canonicalKey">The stable identity key the link is stored under (OpenID sub / SAML NameID).</param>
    /// <param name="userId">The Jellyfin user the login resolved to.</param>
    /// <returns>True only when a live, enabled link for this identity still points at the user.</returns>
    internal bool IsIdentityStillLinked(ProviderMode mode, string provider, string? canonicalKey, Guid userId)
    {
        if (string.IsNullOrWhiteSpace(canonicalKey))
        {
            return false;
        }

        return _configStore.Read(configuration =>
            TryGetLinks(configuration, mode, provider, requireEnabled: true, out var links)
            && links.TryGetValue(canonicalKey, out var linkedId)
            && linkedId == userId
            && _userManager.GetUserById(linkedId) != null);
    }

    // Atomically links the key unless a live link exists (#133): the existence check and the write are one Mutate, so the race loser observes the winner and writes nothing.
    private (Guid EffectiveUserId, bool WroteLink) LinkCanonicalIfAbsent(ProviderMode mode, string provider, string canonicalKey, Guid candidateUserId, string? issuer, TimeSpan? provisionedAccessDuration = null, bool provisionedPendingApproval = false)
    {
        return _configStore.Mutate(configuration =>
        {
            // Deleted or disabled since the login resolved it: fail closed (#373, #380); an orphaned fresh user is the benign #133 outcome.
            if (!TryGetLinks(configuration, mode, provider, requireEnabled: true, out var links))
            {
                throw new AccountLinkForbiddenException("The SSO provider is no longer configured or is disabled; refusing to link an account.");
            }

            Guid? existing = links.TryGetValue(canonicalKey, out var current) && _userManager.GetUserById(current) != null
                ? current
                : (Guid?)null;

            var (effectiveUserId, wroteLink) = AccountLinkResolver.ResolveLinkWrite(existing, candidateUserId);
            if (wroteLink)
            {
                links[canonicalKey] = effectiveUserId;

                // The link carries this login's issuer (#186); the race loser stamps nothing.
                StampIssuerInPlace(configuration, mode, provider, canonicalKey, issuer);

                // The role-mapped deadline (#1146) is stamped only by the call that wrote the link, so it is set once and never slides.
                RecordProvisionedDeadlineInPlace(configuration, mode, provider, canonicalKey, provisionedAccessDuration);

                // A stamp under a key that held no live link is the previous holder's (#1638); the login that earns one writes it after the mint.
                RemoveLastSsoLogin(configuration, mode, provider, canonicalKey);

                // The pending-approval record (#1529) is written by the same transaction as the link, and cleared where the key is repointed, so the race loser leaves none and an adoption inherits none.
                RecordPendingApprovalInPlace(configuration, mode, provider, canonicalKey, effectiveUserId, provisionedPendingApproval);
            }

            return (effectiveUserId, wroteLink);
        });
    }

    // Re-keys a legacy username-keyed link to the subject key (#155) and returns the id the identity now resolves to, in one transaction (#363); idempotent under concurrency, never overwriting a live subject link, and null when neither key resolves a live account.
    private Guid? MigrateAndResolveCanonicalLink(ProviderMode mode, string provider, string canonicalKey, string legacyKey, string? issuer)
    {
        return _configStore.Mutate<Guid?>(configuration =>
        {
            // Deleted or disabled since the candidate read: fail closed (#373, #380) rather than bind to the pre-window id.
            if (!TryGetLinks(configuration, mode, provider, requireEnabled: true, out var links))
            {
                throw new AccountLinkForbiddenException("The SSO provider is no longer configured or is disabled; refusing to migrate the account link.");
            }

            // Re-key only while the subject key is absent or dangling; the moved value is the authoritative id.
            if (links.TryGetValue(legacyKey, out var legacyUserId)
                && (!links.TryGetValue(canonicalKey, out var subjectUserId) || _userManager.GetUserById(subjectUserId) == null))
            {
                links.Remove(legacyKey);
                links[canonicalKey] = legacyUserId;

                // A fresh subject-keyed link written under this login carries its issuer (#186).
                StampIssuerInPlace(configuration, mode, provider, canonicalKey, issuer);

                // Both keys lose any pending-approval record (#1529): the subject key dangled and the legacy key has no link left.
                RemovePendingApproval(configuration, mode, provider, canonicalKey);
                RemovePendingApproval(configuration, mode, provider, legacyKey);

                // The deadline and the last-login stamp as well, on both keys (#1638).
                RemoveDeadline(configuration, mode, provider, canonicalKey);
                RemoveDeadline(configuration, mode, provider, legacyKey);
                RemoveLastSsoLogin(configuration, mode, provider, canonicalKey);
                RemoveLastSsoLogin(configuration, mode, provider, legacyKey);
                return legacyUserId;
            }

            // Nothing to migrate: bind to the live subject link, treating a dangling one as absent.
            return links.TryGetValue(canonicalKey, out var live) && _userManager.GetUserById(live) != null
                ? live
                : (Guid?)null;
        });
    }

    // Classifies an OpenID subject link's issuer against the login's under the caller's lock (#186): NotBound outside OpenID, Absent without a stored issuer, Match on ordinal equality, otherwise Mismatch, including a login that carries none.
    private static IssuerBinding ClassifyIssuer(PluginConfiguration configuration, ProviderMode mode, string provider, string canonicalKey, string? issuer)
    {
        if (mode != ProviderMode.Oid)
        {
            return IssuerBinding.NotBound;
        }

        var stored = configuration.OidConfigs.TryGetValue(provider, out var config) && config?.CanonicalLinkIssuers is { } issuers
            && issuers.TryGetValue(canonicalKey, out var storedIssuer)
            ? storedIssuer
            : null;

        if (string.IsNullOrWhiteSpace(stored))
        {
            return IssuerBinding.Absent;
        }

        return string.Equals(stored, issuer, StringComparison.Ordinal) ? IssuerBinding.Match : IssuerBinding.Mismatch;
    }

    // Trust-on-first-use stamp in its own transaction (#186): written only while the link exists and its issuer is still absent, and never for SAML or a blank issuer.
    private void StampIssuer(ProviderMode mode, string provider, string canonicalKey, string? issuer)
    {
        if (mode != ProviderMode.Oid || string.IsNullOrWhiteSpace(issuer))
        {
            return;
        }

        _configStore.Mutate(configuration =>
        {
            if (configuration.OidConfigs.TryGetValue(provider, out var config) && config?.CanonicalLinks is { } links
                && links.ContainsKey(canonicalKey)
                && !config.CanonicalLinkIssuers.ContainsKey(canonicalKey))
            {
                config.CanonicalLinkIssuers[canonicalKey] = issuer;
            }
        });
    }

    // Overwrites the issuer inside the caller's transaction right after a link write (#186): a link just written belongs to this login's issuer. A no-op for SAML or a blank issuer.
    private static void StampIssuerInPlace(PluginConfiguration configuration, ProviderMode mode, string provider, string canonicalKey, string? issuer)
    {
        if (mode != ProviderMode.Oid || string.IsNullOrWhiteSpace(issuer))
        {
            return;
        }

        if (configuration.OidConfigs.TryGetValue(provider, out var config) && config is not null)
        {
            config.CanonicalLinkIssuers[canonicalKey] = issuer;
        }
    }

    // The issuer entry goes with the link (#186); a no-op for SAML.
    private static void RemoveIssuer(PluginConfiguration configuration, ProviderMode mode, string provider, string canonicalKey)
    {
        if (mode == ProviderMode.Oid
            && configuration.OidConfigs.TryGetValue(provider, out var config)
            && config?.CanonicalLinkIssuers is { } issuers)
        {
            issuers.Remove(canonicalKey);
        }
    }

    // The single locked candidate read: both links, if live, and the subject link's issuer binding (#186).
    private readonly record struct ResolutionCandidates(Guid? SubjectLink, Guid? LegacyLink, IssuerBinding SubjectIssuer);
}
