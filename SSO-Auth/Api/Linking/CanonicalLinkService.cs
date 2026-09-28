// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Api.Metrics;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Cryptography;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Linking;

/// <summary>The outcome of a manual link-creation request; closed by convention, so the controller's mapper throws on a new arm rather than falling through.</summary>
internal enum CanonicalLinkWriteResult
{
    /// <summary>The link was created.</summary>
    Created,

    /// <summary>The SSO identity did not resolve a usable key; nothing was written.</summary>
    EmptyKey,

    /// <summary>No provider of that mode/name exists; nothing was written.</summary>
    UnknownProvider,

    /// <summary>The key is already held by a different Jellyfin user; nothing was written (#1133).</summary>
    ConflictingUser,
}

/// <summary>The outcome of a manual unlink request; closed by convention, so the controller's mapper throws on a new arm.</summary>
internal enum CanonicalLinkRemoveResult
{
    /// <summary>The link was removed.</summary>
    Removed,

    /// <summary>No link is registered for that canonical name.</summary>
    NotFound,

    /// <summary>A link exists but is registered to a different Jellyfin user; nothing was removed.</summary>
    Mismatch,

    /// <summary>No provider of that mode/name exists; nothing was removed.</summary>
    UnknownProvider,

    /// <summary>The link carries a provisioned access deadline and the caller is not an administrator; nothing was removed (#1647).</summary>
    TimeLimited,

    /// <summary>Removing this link would leave its holder unable to sign in by any means, and the caller is the holder; nothing was removed (#1720).</summary>
    WouldStrandAccount,
}

/// <summary>The outcome of approving an account this plugin provisioned inert (#1529); closed by convention, so the controller's mapper throws on a new arm.</summary>
/// <remarks>The refusals stay distinct because each tells the administrator something different, and only one sends them elsewhere.</remarks>
internal enum PendingApprovalResult
{
    /// <summary>The account was enabled and its record removed.</summary>
    Approved,

    /// <summary>No provider of that mode/name exists; nothing was changed.</summary>
    UnknownProvider,

    /// <summary>This plugin holds no live record that it provisioned that identity's account inert; nothing was changed.</summary>
    NotPending,

    /// <summary>The recorded account is an administrator and is not approvable here; the record was left as it is.</summary>
    Administrator,

    /// <summary>The recorded account is already enabled; the record it had outlived was removed and nothing else changed.</summary>
    AlreadyEnabled,

    /// <summary>The recorded account no longer exists; the record was removed and nothing else changed.</summary>
    AccountGone,
}

/// <summary>The issuer binding of a resolved subject-keyed OpenID link against the current login's issuer (#186); SAML and a login with no subject link are <see cref="NotBound"/>.</summary>
internal enum IssuerBinding
{
    /// <summary>Issuer binding does not apply (SAML / any non-OpenID mode, or no subject link resolved).</summary>
    NotBound,

    /// <summary>The link's stored issuer ordinally equals the login's issuer - proceed, no write.</summary>
    Match,

    /// <summary>The link carries no stored issuer (a legacy/un-stamped link) - eligible for trust-on-first-use stamping.</summary>
    Absent,

    /// <summary>The link's stored issuer differs from the login's - refuse the login (fail closed).</summary>
    Mismatch,
}

/// <summary>The outcome of a manual unlink, with whether the user still holds any other canonical link after it, read in the same transaction; the controller revokes tokens only when the last link went (#468).</summary>
/// <param name="Result">The remove outcome.</param>
/// <param name="UserRetainsAnyLink">Whether any provider still links the user; defined only when <paramref name="Result"/> is <see cref="CanonicalLinkRemoveResult.Removed"/>, false otherwise.</param>
internal readonly record struct CanonicalLinkRemoval(CanonicalLinkRemoveResult Result, bool UserRetainsAnyLink);

/// <summary>One canonical link whose persisted deadline has passed (#1145), as a detached snapshot from one locked pass; the disable it feeds re-resolves and re-guards it, so a stale entry is a no-op.</summary>
/// <param name="Mode">The provider protocol the link belongs to.</param>
/// <param name="Provider">The provider name.</param>
/// <param name="CanonicalKey">The stable subject key the link and the deadline are stored under.</param>
/// <param name="UserId">The Jellyfin user the link points at, as read in that pass.</param>
internal readonly record struct ExpiredCanonicalLink(ProviderMode Mode, string Provider, string CanonicalKey, Guid UserId);

/// <summary>The account-linking workflow behind the login and admin endpoints: resolves an SSO identity to a Jellyfin account, migrates legacy username-keyed links to the subject key (#155), and removes links.</summary>
/// <remarks>
/// The controller keeps the HTTP boundary and the authorization guards; this service owns every read and write of a provider's link maps, through <see cref="ProviderConfigStore"/> so each check-then-write stays under one lock.
/// The rules behind the guards: <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Linked-Accounts#design-record-links-keys-and-guards"/>.
/// </remarks>
internal sealed class CanonicalLinkService
{
    // Process-wide on purpose: the service is built per request, so an instance gate would throttle nothing (#362); one minute matches the sibling cap-warn gates (#246).
    private static readonly IntervalGate SharedLegacyLinkWarnGate = new(TimeSpan.FromMinutes(1));

    private readonly IUserManager _userManager;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly ProviderConfigStore _configStore;
    private readonly ILogger _logger;
    private readonly IntervalGate _legacyLinkWarnGate;
    private readonly Func<DateTime> _clock;
    private readonly IDisplayPreferencesManager? _displayPreferences;

    /// <summary>Initializes a new instance of the <see cref="CanonicalLinkService"/> class.</summary>
    /// <param name="userManager">The Jellyfin user manager.</param>
    /// <param name="cryptoProvider">The crypto provider used for legacy link hashing.</param>
    /// <param name="configStore">The provider configuration store the link maps live in.</param>
    /// <param name="logger">The logger.</param>
    /// <param name="legacyLinkWarnGate">The pending-legacy-link warning throttle; null takes the shared process-wide gate.</param>
    /// <param name="clock">The clock driving the warning throttle; null uses the wall clock.</param>
    /// <param name="displayPreferences">The host's display-preferences store the create arm seeds a home-screen layout into (#1101); null on the paths that never reach the create arm, and a template naming a layout then logs instead of throwing.</param>
    internal CanonicalLinkService(
        IUserManager userManager,
        ICryptoProvider cryptoProvider,
        ProviderConfigStore configStore,
        ILogger logger,
        IntervalGate? legacyLinkWarnGate = null,
        Func<DateTime>? clock = null,
        IDisplayPreferencesManager? displayPreferences = null)
    {
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
        _configStore = configStore ?? throw new ArgumentNullException(nameof(configStore));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _displayPreferences = displayPreferences;

        // Production leaves both null; tests pass a fresh gate and a fake clock.
        _legacyLinkWarnGate = legacyLinkWarnGate ?? SharedLegacyLinkWarnGate;
        _clock = clock ?? (() => DateTime.UtcNow);
    }

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

    // The stored provider object, or null when it is gone or was stored with a null config object (#350).
    private static ProviderConfigBase? ProviderConfigFor(PluginConfiguration configuration, ProviderMode mode, string provider) =>
        mode switch
        {
            ProviderMode.Saml => configuration.SamlConfigs.TryGetValue(provider, out var saml) ? saml : null,
            ProviderMode.Oid => configuration.OidConfigs.TryGetValue(provider, out var oid) ? oid : null,
            _ => null,
        };

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

    /// <summary>Login-time deprovisioning (#831): disables the existing linked account when the role allow-list denied the login, opt-in per provider (<see cref="ProviderConfigBase.DisableAccountOnRoleDenied"/>).</summary>
    /// <remarks>An administrator is never disabled by this path (T-D1), it acts only on an existing subject-keyed link, and an already disabled account is a no-op.</remarks>
    /// <param name="mode">The provider protocol.</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="canonicalKey">The identity's stable subject key (OpenID sub / SAML NameID) whose login was denied.</param>
    /// <param name="issuer">The denied login's token issuer (OpenID only; null for SAML), checked against the link's stored issuer binding (#186) so a colliding subject from a repointed identity provider cannot disable the prior provider's account.</param>
    /// <returns><see langword="true"/> when an enabled non-admin account was actually disabled (so the caller audits it); otherwise <see langword="false"/>.</returns>
    internal async Task<bool> DisableDeniedAccountAsync(ProviderMode mode, string provider, string? canonicalKey, string? issuer = null) =>
        await DisableLinkedAccountAsync(mode, provider, canonicalKey, issuer, enforceIssuerBinding: true).ConfigureAwait(false) is not null;

    /// <summary>Login-time enforcement of an account-expiry deadline (#1144): disables the existing linked account when the login's expiry instant has passed, opt-in per provider (<see cref="ProviderConfigBase.AccountExpiryClaim"/>).</summary>
    /// <remarks>The same body as <see cref="DisableDeniedAccountAsync"/>, so the two share every guard; the names differ because each caller owes its own audit line.</remarks>
    /// <param name="mode">The provider protocol.</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="canonicalKey">The identity's stable subject key (OpenID sub / SAML NameID) whose deadline has passed.</param>
    /// <param name="issuer">The login's token issuer (OpenID only; null for SAML), checked against the link's stored issuer binding (#186).</param>
    /// <returns><see langword="true"/> when an enabled non-admin account was actually disabled (so the caller audits it once, at the transition); otherwise <see langword="false"/>.</returns>
    internal async Task<bool> DisableExpiredAccountAsync(ProviderMode mode, string provider, string? canonicalKey, string? issuer = null) =>
        await DisableLinkedAccountAsync(mode, provider, canonicalKey, issuer, enforceIssuerBinding: true).ConfigureAwait(false) is not null;

    /// <summary>Between-logins enforcement of an account-expiry deadline (#1145): the sweep's disable for a link whose persisted deadline passed, returning the account it disabled so the caller can revoke its tokens.</summary>
    /// <remarks>Same body and guards as the login paths, without the issuer binding (#186): a sweep has no incoming login to bind against, and a null issuer would read every bound link as a mismatch.</remarks>
    /// <param name="mode">The provider protocol the link belongs to.</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="canonicalKey">The stable subject key whose persisted deadline has passed.</param>
    /// <returns>The Jellyfin user id disabled by this call, or <see langword="null"/> when nothing was disabled (no live link, deleted user, administrator, or already disabled).</returns>
    internal Task<Guid?> DisableExpiredAccountBySweepAsync(ProviderMode mode, string provider, string? canonicalKey) =>
        DisableLinkedAccountAsync(mode, provider, canonicalKey, issuer: null, enforceIssuerBinding: false);

    /// <summary>Persists the expiry instant a login carried for one link (#1145), last writer wins, and only while the link exists; the map is withheld from JSON so a configuration PUT cannot forge a past deadline.</summary>
    /// <param name="mode">The provider protocol the link belongs to.</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="canonicalKey">The stable subject key the link is stored under.</param>
    /// <param name="deadlineUtc">The expiry instant to persist, in UTC.</param>
    internal void RecordAccountDeadline(ProviderMode mode, string provider, string? canonicalKey, DateTime deadlineUtc)
    {
        if (string.IsNullOrWhiteSpace(canonicalKey))
        {
            return;
        }

        _configStore.Mutate(configuration =>
        {
            if (TryGetProvider(configuration, mode, provider, out var config) && config.CanonicalLinks.ContainsKey(canonicalKey))
            {
                config.CanonicalLinkDeadlines[canonicalKey] = deadlineUtc.ToUniversalTime();
            }
        });
    }

    /// <summary>Stamps the instant of a successful login against the link it resolved (#1120), so the roster answers "last SSO login" without an event log.</summary>
    /// <remarks>Bounded by construction: an entry is only ever written beside a live link, and it is rewritten only once it has aged past <see cref="ProviderConfigBase.LastSsoLoginGranularity"/>, so a repeat login pays no write on the hot path.</remarks>
    /// <param name="mode">The provider protocol the link belongs to.</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="canonicalKey">The stable subject key the link is stored under.</param>
    internal void RecordLastSsoLogin(ProviderMode mode, string provider, string? canonicalKey)
    {
        if (string.IsNullOrWhiteSpace(canonicalKey))
        {
            return;
        }

        var nowUtc = _clock().ToUniversalTime();

        // Decided under a locked read, so a repeat login inside the granularity window reaches no write; a stored instant in the future is due too, or a stepped-back clock would freeze it.
        var due = _configStore.Read(configuration =>
            TryGetProvider(configuration, mode, provider, out var config)
            && config.CanonicalLinks.ContainsKey(canonicalKey)
            && (!config.CanonicalLinkLastLogins.TryGetValue(canonicalKey, out var stored)
                || stored.ToUniversalTime() > nowUtc
                || nowUtc - stored.ToUniversalTime() >= ProviderConfigBase.LastSsoLoginGranularity));

        if (!due)
        {
            return;
        }

        // Availability: this runs after the mint, so a failed persist is a warning and a stale roster column, not a failed login; the deadline writer above is deliberately not treated the same.
        try
        {
            _configStore.Mutate(configuration =>
            {
                // Re-tested under the write lock: an unlink between the two acquisitions must not resurrect a stamp.
                if (TryGetProvider(configuration, mode, provider, out var config) && config.CanonicalLinks.ContainsKey(canonicalKey))
                {
                    config.CanonicalLinkLastLogins[canonicalKey] = nowUtc;
                }
            });
        }
        catch (Exception ex)
        {
            // The provider only, never the subject; the sanitizer stays at the call.
            _logger.LogWarning(
                ex,
                "[SSO] Could not record the last SSO login for provider {Provider}. The login itself succeeded; the roster timestamp is stale.",
                provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
        }
    }

    /// <summary>The canonical links whose persisted deadline is at or before <paramref name="nowUtc"/>, across both protocols, materialized in one locked pass (#1145).</summary>
    /// <remarks>A candidate list, not a verdict: <see cref="DisableExpiredAccountBySweepAsync"/> re-resolves each entry and applies every guard, including the disabled-provider skip, so the test is stated once.</remarks>
    /// <param name="nowUtc">The instant to compare each deadline against.</param>
    /// <returns>The expired links, as a detached snapshot.</returns>
    internal IReadOnlyList<ExpiredCanonicalLink> ExpiredLinks(DateTime nowUtc)
    {
        return _configStore.Read(configuration =>
        {
            var expired = new List<ExpiredCanonicalLink>();
            Collect(configuration.SamlConfigs, ProviderMode.Saml, expired);
            Collect(configuration.OidConfigs, ProviderMode.Oid, expired);
            return (IReadOnlyList<ExpiredCanonicalLink>)expired;
        });

        void Collect<T>(SerializableDictionary<string, T> configs, ProviderMode mode, List<ExpiredCanonicalLink> into)
            where T : ProviderConfigBase
        {
            foreach (var entry in configs)
            {
                // A provider stored with a null config object (#350) holds nothing to sweep.
                if (entry.Value is not { } config)
                {
                    continue;
                }

                foreach (var deadline in config.CanonicalLinkDeadlines)
                {
                    if (deadline.Value <= nowUtc && config.CanonicalLinks.TryGetValue(deadline.Key, out var userId))
                    {
                        into.Add(new ExpiredCanonicalLink(mode, entry.Key, deadline.Key, userId));
                    }
                }
            }
        }
    }

    /// <summary>Every distinct Jellyfin account any provider still links, as a detached snapshot read once under the lock (#1440).</summary>
    /// <remarks>The link is what says an account belongs to this plugin, since the mint overwrites AuthenticationProviderId on every login; a disabled provider is walked too, because this sweep only removes an empty-password door.</remarks>
    /// <returns>The linked account ids, without duplicates.</returns>
    internal IReadOnlyCollection<Guid> LinkedUserIds()
    {
        return _configStore.Read(configuration =>
        {
            var linked = new HashSet<Guid>();
            foreach (var config in configuration.SamlConfigs.Values.Concat<ProviderConfigBase>(configuration.OidConfigs.Values))
            {
                // A provider stored with a null config object (#350) holds no links.
                if (config?.CanonicalLinks is { } links)
                {
                    linked.UnionWith(links.Values);
                }
            }

            return (IReadOnlyCollection<Guid>)linked;
        });
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

    // The shared body of every disable path (#831, #1144, #1145): PermissionRolePolicy bars IsDisabled from role mapping, and these sanctioned exceptions share one body so the guard below cannot be absent from one of them.
    private async Task<Guid?> DisableLinkedAccountAsync(ProviderMode mode, string provider, string? canonicalKey, string? issuer, bool enforceIssuerBinding)
    {
        if (string.IsNullOrWhiteSpace(canonicalKey))
        {
            return null;
        }

        // Resolve the existing subject link only, never a create or the legacy path; a disabled provider fails closed, and an issuer mismatch (#186) means the account is somebody else's.
        var userId = _configStore.Read(configuration =>
            TryGetLinks(configuration, mode, provider, requireEnabled: true, out var links)
                && links.TryGetValue(canonicalKey, out var linked)
                && (!enforceIssuerBinding || ClassifyIssuer(configuration, mode, provider, canonicalKey, issuer) != IssuerBinding.Mismatch)
                ? (Guid?)linked
                : null);
        if (userId is null)
        {
            return null;
        }

        var user = _userManager.GetUserById(userId.Value);
        if (user is null)
        {
            return null;
        }

        // The guard (T-D1): an administrator is never disabled by SSO, and an already disabled account is not re-audited.
        if (user.HasPermission(PermissionKind.IsAdministrator) || user.HasPermission(PermissionKind.IsDisabled))
        {
            return null;
        }

        user.SetPermission(PermissionKind.IsDisabled, true);
        await _userManager.UpdateUserAsync(user).ConfigureAwait(false);

        // The account was enabled, so a pending-approval record on it was false (#1529); left standing it would put the account straight back onto the approval list.
        RemovePendingApprovalOutsideLock(mode, provider, canonicalKey, userId.Value);
        return userId;
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

    /// <summary>Creates a manual canonical link from a provider-side identity to a Jellyfin user, under the config lock; the controller maps the result to a response.</summary>
    /// <param name="mode">The protocol the operation applies to, parsed once at the controller boundary (#369).</param>
    /// <param name="provider">The provider the link belongs to.</param>
    /// <param name="providerUserId">The provider-side identity key (OpenID sub / SAML NameID).</param>
    /// <param name="jellyfinUserId">The Jellyfin user to link the identity to.</param>
    /// <param name="issuer">The OpenID id_token issuer to issuer-bind the new link to (#186); null for SAML or an unauthenticated admin link, which leaves the link un-stamped (trust-on-first-use applies on its first login).</param>
    /// <returns>The write outcome.</returns>
    internal CanonicalLinkWriteResult TryCreateLink(ProviderMode mode, string provider, string providerUserId, Guid jellyfinUserId, string? issuer = null)
        => WriteLink(mode, provider, providerUserId, jellyfinUserId, issuer, refuseRebind: false);

    /// <summary>Creates a canonical link for a provisioning tool that holds no identity-provider response (#1133); a key already held by a different user is refused rather than repointed.</summary>
    /// <remarks>The refusal lives inside the same <c>Mutate</c> as the write, so "nothing was written" is true of a conflict rather than likely; <see cref="TryCreateLink"/> keeps its repoint because its callers proved control of the subject in a live flow.</remarks>
    /// <param name="mode">The protocol the operation applies to, parsed once at the controller boundary (#369).</param>
    /// <param name="provider">The provider the link belongs to.</param>
    /// <param name="providerUserId">The provider-side identity key (OpenID sub / SAML NameID).</param>
    /// <param name="jellyfinUserId">The Jellyfin user to link the identity to.</param>
    /// <returns>The write outcome, including <see cref="CanonicalLinkWriteResult.ConflictingUser"/>.</returns>
    internal CanonicalLinkWriteResult TryPreprovisionLink(ProviderMode mode, string provider, string providerUserId, Guid jellyfinUserId)
        => WriteLink(mode, provider, providerUserId, jellyfinUserId, issuer: null, refuseRebind: true);

    /// <summary>The one canonical-link write behind both entry points, so the empty-key guard, the provider lookup and the issuer stamp cannot drift.</summary>
    /// <param name="mode">The protocol the operation applies to.</param>
    /// <param name="provider">The provider the link belongs to.</param>
    /// <param name="providerUserId">The provider-side identity key.</param>
    /// <param name="jellyfinUserId">The Jellyfin user to link the identity to.</param>
    /// <param name="issuer">The OpenID id_token issuer to bind the new link to (#186), or null.</param>
    /// <param name="refuseRebind">Whether a key already held by another Jellyfin user is refused instead of repointed.</param>
    /// <returns>The write outcome.</returns>
    private CanonicalLinkWriteResult WriteLink(ProviderMode mode, string provider, string providerUserId, Guid jellyfinUserId, string? issuer, bool refuseRebind)
    {
        // Fail closed (#95) before the provider lookup, so the two refusals keep their distinct response bodies.
        if (string.IsNullOrWhiteSpace(providerUserId))
        {
            return CanonicalLinkWriteResult.EmptyKey;
        }

        return _configStore.Mutate(configuration =>
        {
            // Link creation is a grant, so a provider disabled between the controller gate and this transaction is refused (#380).
            if (!TryGetLinks(configuration, mode, provider, requireEnabled: true, out var links))
            {
                return CanonicalLinkWriteResult.UnknownProvider;
            }

            // Whether the key changes hands decides the rebind refusal (#1133) and what the write leaves of the key's entries; a repeat of the same mapping is neither.
            var holds = links.TryGetValue(providerUserId, out var held);
            var sameHolder = holds && held == jellyfinUserId;

            if (refuseRebind && holds && !sameHolder)
            {
                return CanonicalLinkWriteResult.ConflictingUser;
            }

            links[providerUserId] = jellyfinUserId;
            StampIssuerInPlace(configuration, mode, provider, providerUserId, issuer);

            // The entries the key carried go only when the key changes hands (#1529, #1638): a same-mapping write keeps them, and a time-limited user cannot shed a deadline by re-linking.
            if (!sameHolder)
            {
                RemovePendingApproval(configuration, mode, provider, providerUserId);
                RemoveDeadline(configuration, mode, provider, providerUserId);
                RemoveLastSsoLogin(configuration, mode, provider, providerUserId);
            }

            return CanonicalLinkWriteResult.Created;
        });
    }

    /// <summary>Removes a manual canonical link when it is registered to the given user, in one read-modify-write under the config lock; the controller maps the result to a response.</summary>
    /// <param name="mode">The protocol the operation applies to, parsed once at the controller boundary (#369).</param>
    /// <param name="provider">The provider the link belongs to.</param>
    /// <param name="canonicalName">The provider-side identity key whose link is removed.</param>
    /// <param name="jellyfinUserId">The Jellyfin user the link must belong to.</param>
    /// <param name="callerIsAdministrator">Whether the caller is an administrator (#1647); a link carrying a deadline is removed only when true, and the default refuses.</param>
    /// <param name="passwordLoginDisabled">Whether the holder's account refuses password sign-in (#1720); the holder's removal of their last way in is refused when true, and the default refuses.</param>
    /// <param name="callerIsTheHolder">Whether the caller is the account named by <paramref name="jellyfinUserId"/> (#1732); narrows the administrator exemption to acts on somebody else's link, and the default refuses.</param>
    /// <param name="anotherAdministratorKeepsAWayIn">Whether another administrator can still sign in, measured at the boundary with <see cref="AdministratorsWithNoWayIn"/> (#1732); the default refuses.</param>
    /// <returns>The remove outcome, plus whether the user retains any other link (#468).</returns>
    internal CanonicalLinkRemoval TryRemoveLink(ProviderMode mode, string provider, string canonicalName, Guid jellyfinUserId, bool callerIsAdministrator = false, bool passwordLoginDisabled = true, bool callerIsTheHolder = true, bool anotherAdministratorKeepsAWayIn = false)
    {
        // One Mutate, so find, ownership check, removal and the last-link check cannot interleave; a no-result outcome still persists the unchanged configuration.
        return _configStore.Mutate(configuration =>
        {
            // Removal revokes a grant, so it keeps working on a disabled provider (#380); only absence is unknown.
            if (!TryGetLinks(configuration, mode, provider, requireEnabled: false, out var links))
            {
                return new CanonicalLinkRemoval(CanonicalLinkRemoveResult.UnknownProvider, UserRetainsAnyLink: false);
            }

            if (!links.TryGetValue(canonicalName, out var linkedId))
            {
                return new CanonicalLinkRemoval(CanonicalLinkRemoveResult.NotFound, UserRetainsAnyLink: false);
            }

            if (linkedId != jellyfinUserId)
            {
                return new CanonicalLinkRemoval(CanonicalLinkRemoveResult.Mismatch, UserRetainsAnyLink: false);
            }

            // A time-limited link is not its holder's to remove (#1647): the unlink would prune the deadline and a re-login could adopt the account with none; decided in this transaction.
            if (!callerIsAdministrator
                && TryGetProvider(configuration, mode, provider, out var config)
                && config.CanonicalLinkDeadlines.ContainsKey(canonicalName))
            {
                return new CanonicalLinkRemoval(CanonicalLinkRemoveResult.TimeLimited, UserRetainsAnyLink: false);
            }

            // A holder may not strand their own account (#1720), and an administrator acting on their own last way in is refused where no other administrator could undo it (#1732).
            // A way in is a link on an enabled provider, the login path's reading, not the any-link reading the revoke below uses; why, and what it costs: https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Linked-Accounts#design-record-links-keys-and-guards.
            // The two facts about the caller come from the boundary, outside this lock; the link reading is taken inside it.
            if ((!callerIsAdministrator || (callerIsTheHolder && !anotherAdministratorKeepsAWayIn))
                && passwordLoginDisabled
                && TryGetProvider(configuration, mode, provider, out var removingFrom)
                && removingFrom.Enabled
                && !UserKeepsAnEnabledWayIn(configuration, jellyfinUserId, mode, provider, canonicalName))
            {
                return new CanonicalLinkRemoval(CanonicalLinkRemoveResult.WouldStrandAccount, UserRetainsAnyLink: false);
            }

            links.Remove(canonicalName);

            // The issuer entry goes with the link (#186); a no-op for SAML.
            RemoveIssuer(configuration, mode, provider, canonicalName);

            // The deadline goes with the link (#1145), so a re-link of the subject starts with none.
            RemoveDeadline(configuration, mode, provider, canonicalName);

            // The last-login stamp goes with the link (#1120): unlinking is the erasure route for that personal data.
            RemoveLastSsoLogin(configuration, mode, provider, canonicalName);

            // The pending-approval mark goes with the link (#1529); it would otherwise keep offering an account with no SSO route.
            RemovePendingApproval(configuration, mode, provider, canonicalName);

            // Read in the same transaction as the removal (#468), so a concurrent link change cannot mislead the last-link revocation.
            var retainsAnyLink = UserHasAnyLink(configuration, jellyfinUserId);
            return new CanonicalLinkRemoval(CanonicalLinkRemoveResult.Removed, retainsAnyLink);
        });
    }

    /// <summary>Projects, for one protocol, a provider to linked-keys map for the user, materialized under the lock so serialization cannot tear against a concurrent write (#157).</summary>
    /// <param name="mode">The protocol the operation applies to, parsed once at the controller boundary (#369).</param>
    /// <param name="jellyfinUserId">The Jellyfin user whose links are listed.</param>
    /// <returns>A provider -> link-key-list map.</returns>
    internal SerializableDictionary<string, IEnumerable<string>> LinksByUser(ProviderMode mode, Guid jellyfinUserId)
    {
        return _configStore.Read(configuration =>
        {
            // A provider stored with a null config object (#350) yields null links and is skipped.
            var providerLinks = mode == ProviderMode.Saml
                ? configuration.SamlConfigs.Select(p => (p.Key, p.Value?.CanonicalLinks))
                : configuration.OidConfigs.Select(p => (p.Key, p.Value?.CanonicalLinks));

            var mappings = new SerializableDictionary<string, IEnumerable<string>>();
            foreach (var (provider, links) in providerLinks)
            {
                if (links != null)
                {
                    mappings[provider] = links
                        .Where(link => link.Value == jellyfinUserId)
                        .Select(link => link.Key)
                        .ToList();
                }
            }

            return mappings;
        });
    }

    /// <summary>Removes every canonical link pointing at the user across all providers, under the config lock, and returns how many went.</summary>
    /// <param name="userId">The Jellyfin user whose links are revoked.</param>
    /// <param name="removedFrom">When given, receives every provider a link was removed from, labelled by protocol, filled inside the same lock (#1649).</param>
    /// <param name="alsoForgetProvisionedPassword">When true, the minted-password record goes in the same transaction (#1733); the administrator revoke leaves it, because the account stands.</param>
    /// <returns>The number of links removed.</returns>
    internal int RemoveUserEverywhere(Guid userId, ICollection<string>? removedFrom = null, bool alsoForgetProvisionedPassword = false)
    {
        return _configStore.Mutate(configuration =>
        {
            int removed = 0;

            // Opt-in: the administrator revoke leaves the account standing, and a standing account keeps whatever password it holds.
            if (alsoForgetProvisionedPassword)
            {
                ProvisionedPassword.Forget(configuration, userId);
            }

            // One loop over both protocols, named for the caller's audit line; a null config object (#350) holds no links.
            var providers = configuration.SamlConfigs.Select(p => (p.Key, Protocol: "SAML", Config: (ProviderConfigBase?)p.Value))
                .Concat(configuration.OidConfigs.Select(p => (p.Key, Protocol: "OpenID", Config: (ProviderConfigBase?)p.Value)));
            foreach (var (name, protocol, config) in providers)
            {
                if (config?.CanonicalLinks is { } links)
                {
                    var here = CanonicalLinkRevoker.RemoveUser(links, userId);
                    removed += here;
                    if (here > 0)
                    {
                        removedFrom?.Add(protocol + " '" + name + "'");
                    }
                }

                // Orphaned issuer entries go (#186), so they cannot bind or refuse a future re-link; SAML has no issuer map.
                if (config is OidConfig oid && oid.CanonicalLinks is { } liveLinks)
                {
                    foreach (var staleKey in oid.CanonicalLinkIssuers.Keys.Where(k => !liveLinks.ContainsKey(k)).ToList())
                    {
                        oid.CanonicalLinkIssuers.Remove(staleKey);
                    }
                }

                // Orphaned deadlines go on both protocols (#1145); one left would expire a re-link on the next sweep tick.
                if (config?.CanonicalLinks is { } remaining)
                {
                    foreach (var staleKey in config.CanonicalLinkDeadlines.Keys.Where(k => !remaining.ContainsKey(k)).ToList())
                    {
                        config.CanonicalLinkDeadlines.Remove(staleKey);
                    }

                    // Orphaned last-login stamps go (#1120): Unregister is the erasure route the retention promise names.
                    foreach (var staleKey in config.CanonicalLinkLastLogins.Keys.Where(k => !remaining.ContainsKey(k)).ToList())
                    {
                        config.CanonicalLinkLastLogins.Remove(staleKey);
                    }

                    // Orphaned pending-approval marks go (#1529); one left would offer an account with no SSO route for approval.
                    foreach (var staleKey in config.CanonicalLinkPendingApprovals.Keys.Where(k => !remaining.ContainsKey(k)).ToList())
                    {
                        config.CanonicalLinkPendingApprovals.Remove(staleKey);
                    }
                }
            }

            return removed;
        });
    }

    /// <summary>Reads what one provider's link table looks like before a bulk unlink (#1519): whether it is stored, how many links it holds, and which accounts would be left with no link anywhere.</summary>
    /// <remarks>A read and not the act: the accounts are resolved through the user manager outside the lock, and <see cref="TryPurgeProviderLinks"/> re-derives the set under the lock and refuses when it moved. A disabled provider is surveyed like an enabled one (#380).</remarks>
    /// <param name="mode">The provider protocol.</param>
    /// <param name="provider">The provider whose links would be removed.</param>
    /// <returns>The snapshot to judge; <c>ProviderExists = false</c> when no such provider is stored.</returns>
    internal ProviderLinkSurvey SurveyProviderLinks(ProviderMode mode, string provider)
    {
        return _configStore.Read(configuration =>
            TryGetLinks(configuration, mode, provider, requireEnabled: false, out var links)
                ? new ProviderLinkSurvey(true, links.Count, links.Values.Distinct().ToList())
                : new ProviderLinkSurvey(false, 0, Array.Empty<Guid>()));
    }

    /// <summary>Names the administrators among the given doors that have no way to sign in, read against the configuration as it stands now (#1519).</summary>
    /// <remarks>The safety net under the purge: an account can lose its password door in the window before the removal took the lock, which no link-table comparison can see, so it is read again afterwards.</remarks>
    /// <param name="doors">The accounts to re-judge, resolved through the user manager after the removal.</param>
    /// <returns>The usernames of administrators with neither a password door nor a link on an enabled provider.</returns>
    internal IReadOnlyList<string> AdministratorsWithNoWayIn(IReadOnlyList<AccountDoors> doors)
    {
        ArgumentNullException.ThrowIfNull(doors);

        return _configStore.Read(configuration =>
        {
            var stillLinked = UsersWithAnEnabledLink(configuration);
            return (IReadOnlyList<string>)doors
                .Where(door => door.IsAdministrator && !door.IsDisabled)
                .Where(door => !stillLinked.Contains(door.UserId))
                .Select(door => door.Username)
                .OrderBy(username => username, StringComparer.OrdinalIgnoreCase)
                .ToList();
        });
    }

    /// <summary>Removes every canonical link one provider holds (#1519), the way back from a link import that restored the wrong document; it refuses when the provider is unknown, the count differs, the table moved since <paramref name="judged"/> was resolved, or an administrator would be left with no way in.</summary>
    /// <remarks>
    /// One <c>Mutate</c>, so the count, the lockout guard (T-D1) and the removal cannot interleave; a stored password does not count as a way in, because the plugin's own seals (#1440) cannot be told from a password somebody holds.
    /// Why, and what the refusal costs: <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Linked-Accounts#design-record-links-keys-and-guards"/>.
    /// </remarks>
    /// <param name="mode">The provider protocol.</param>
    /// <param name="provider">The provider whose links are removed.</param>
    /// <param name="expectedLinkCount">The number of links the caller was shown and expects to remove.</param>
    /// <param name="judged">The doors of every account <see cref="SurveyProviderLinks"/> named, resolved outside this lock.</param>
    /// <returns>What happened, what to revoke, and - on the lockout refusal - who would have been stranded.</returns>
    internal ProviderLinkPurgeOutcome TryPurgeProviderLinks(ProviderMode mode, string provider, int expectedLinkCount, IReadOnlyList<AccountDoors> judged)
    {
        ArgumentNullException.ThrowIfNull(judged);

        return _configStore.Mutate(configuration =>
        {
            if (!TryGetLinks(configuration, mode, provider, requireEnabled: false, out var links))
            {
                return ProviderLinkPurgeOutcome.Refusing(ProviderLinkPurgeResult.UnknownProvider, 0);
            }

            if (links.Count != expectedLinkCount)
            {
                return ProviderLinkPurgeOutcome.Refusing(ProviderLinkPurgeResult.CountMismatch, links.Count);
            }

            // Re-derived here: the survey read an earlier transaction, and an account it never judged means the table moved.
            var linked = links.Values.Distinct().ToList();
            var doors = judged.ToDictionary(door => door.UserId);
            if (linked.Any(userId => !doors.ContainsKey(userId)))
            {
                return ProviderLinkPurgeOutcome.Refusing(ProviderLinkPurgeResult.LinkTableChanged, links.Count);
            }

            // Two questions over the same accounts: who is signed out holds no link anywhere, who is stranded holds none on an enabled provider (#380); both from one walk, because this lock is the one every login takes.
            var elsewhere = LinksHeldElsewhere(configuration, links);
            var losing = linked.Where(userId => !elsewhere.Any.Contains(userId)).ToList();

            // A run strands an administrator only when it takes their last way in; a disabled target was no way in before the run.
            var stranded = elsewhere.TargetEnabled
                ? linked
                    .Select(userId => doors[userId])
                    .Where(door => door.IsAdministrator && !door.IsDisabled)
                    .Where(door => !elsewhere.OnAnEnabledProvider.Contains(door.UserId))
                    .Select(door => door.Username)
                    .OrderBy(username => username, StringComparer.OrdinalIgnoreCase)
                    .ToList()
                : new List<string>();
            if (stranded.Count > 0)
            {
                return new ProviderLinkPurgeOutcome(ProviderLinkPurgeResult.WouldStrandAdministrator, 0, links.Count, Array.Empty<Guid>(), stranded, elsewhere.TargetEnabled);
            }

            var removed = links.Count;
            links.Clear();

            // Every stamp keyed on this provider's links is now an orphan, so the maps are cleared wholesale.
            if (TryGetProvider(configuration, mode, provider, out var config))
            {
                config.CanonicalLinkDeadlines.Clear();
                config.CanonicalLinkLastLogins.Clear();
                config.CanonicalLinkPendingApprovals.Clear();
                if (config is OidConfig oid)
                {
                    oid.CanonicalLinkIssuers.Clear();
                }
            }

            return new ProviderLinkPurgeOutcome(ProviderLinkPurgeResult.Purged, removed, removed, losing, Array.Empty<string>(), elsewhere.TargetEnabled);
        });
    }

    // One walk over the other providers under the caller's lock: who holds a link elsewhere at all, who holds one on an enabled provider, and whether the target is enabled; the target is excluded by reference, since a SAML and an OpenID provider may share a name.
    private static LinksElsewhere LinksHeldElsewhere(PluginConfiguration configuration, SerializableDictionary<string, Guid> targetLinks)
    {
        var any = new HashSet<Guid>();
        var enabled = new HashSet<Guid>();
        var targetEnabled = false;

        foreach (var config in AllProviders(configuration))
        {
            if (config?.CanonicalLinks is not { } links)
            {
                continue;
            }

            if (ReferenceEquals(links, targetLinks))
            {
                targetEnabled |= config.Enabled;
                continue;
            }

            foreach (var userId in links.Values)
            {
                any.Add(userId);
                if (config.Enabled)
                {
                    enabled.Add(userId);
                }
            }
        }

        return new LinksElsewhere(any, enabled, targetEnabled);
    }

    // Both protocols' providers as one sequence, so a walk over them is written once.
    private static IEnumerable<ProviderConfigBase> AllProviders(PluginConfiguration configuration)
        => configuration.SamlConfigs.Values.Concat<ProviderConfigBase>(configuration.OidConfigs.Values);

    /// <summary>Whether an enabled provider of either protocol still links the account (#1741); the administrator revoke asks before refusing, because a revoke that takes no way in strands nobody.</summary>
    /// <remarks>The same reading <see cref="AdministratorsWithNoWayIn"/> takes of every other administrator, so the two halves of the guard agree on what a way in is.</remarks>
    /// <param name="userId">The account the revoke would act on.</param>
    /// <returns>True when at least one enabled provider holds a link pointing at the account.</returns>
    internal bool UserHoldsAnEnabledLink(Guid userId)
        => _configStore.Read(configuration => UsersWithAnEnabledLink(configuration).Contains(userId));

    // The after-the-fact form of the guard's reading, with no target to exclude; one walk, under the lock every login takes.
    private static HashSet<Guid> UsersWithAnEnabledLink(PluginConfiguration configuration)
    {
        var linked = new HashSet<Guid>();
        foreach (var config in AllProviders(configuration))
        {
            if (config is { Enabled: true, CanonicalLinks: { } links })
            {
                foreach (var userId in links.Values)
                {
                    linked.Add(userId);
                }
            }
        }

        return linked;
    }

    // Whether any provider still links the user, inside the caller's transaction (#468); a null config object (#350) is skipped.
    private static bool UserHasAnyLink(PluginConfiguration configuration, Guid userId)
    {
        foreach (var config in configuration.SamlConfigs.Values.Concat<ProviderConfigBase>(configuration.OidConfigs.Values))
        {
            if (config?.CanonicalLinks is { } links && links.ContainsValue(userId))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Whether the user would still hold a link that can sign them in after the named one is removed (#1720): a link on an enabled provider other than the one being removed.</summary>
    /// <remarks>Not <see cref="UserHasAnyLink"/>: that one decides the last-link revoke and counts a disabled provider's link, this one decides whether the account can still get in, as the login path reads it.</remarks>
    /// <param name="configuration">The configuration to read, inside the caller's transaction.</param>
    /// <param name="userId">The Jellyfin user whose remaining ways in are being counted.</param>
    /// <param name="mode">The protocol of the link being removed.</param>
    /// <param name="provider">The provider of the link being removed.</param>
    /// <param name="canonicalName">The key of the link being removed, which does not count for itself.</param>
    /// <returns>True when some other enabled provider still links this user.</returns>
    private static bool UserKeepsAnEnabledWayIn(PluginConfiguration configuration, Guid userId, ProviderMode mode, string provider, string canonicalName)
    {
        foreach (var (protocol, providers) in new (ProviderMode Mode, IEnumerable<KeyValuePair<string, ProviderConfigBase>> Providers)[]
        {
            (ProviderMode.Oid, configuration.OidConfigs.Select(entry => new KeyValuePair<string, ProviderConfigBase>(entry.Key, entry.Value))),
            (ProviderMode.Saml, configuration.SamlConfigs.Select(entry => new KeyValuePair<string, ProviderConfigBase>(entry.Key, entry.Value))),
        })
        {
            foreach (var (name, config) in providers)
            {
                if (config is not { Enabled: true, CanonicalLinks: { } links })
                {
                    continue;
                }

                // The link being removed is not its own replacement; matched on protocol, provider and key, since one key may exist on several providers.
                var isTheOneBeingRemoved = protocol == mode && string.Equals(name, provider, StringComparison.Ordinal);
                foreach (var entry in links)
                {
                    if (entry.Value == userId
                        && !(isTheOneBeingRemoved && string.Equals(entry.Key, canonicalName, StringComparison.Ordinal)))
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

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

    // The provider's links map by TryGetValue, so an unknown provider or a null config object (#350) fails closed instead of throwing (#241); with requireEnabled a disabled provider counts as absent (#380), which every grant path passes and removal does not.
    // Callers hold the config lock; the map is self-healing, so mutating it persists.
    private static bool TryGetLinks(PluginConfiguration configuration, ProviderMode mode, string provider, bool requireEnabled, [NotNullWhen(true)] out SerializableDictionary<string, Guid>? links)
    {
        switch (mode)
        {
            case ProviderMode.Saml:
                return TryGetLinks(configuration.SamlConfigs, provider, requireEnabled, out links);

            case ProviderMode.Oid:
                return TryGetLinks(configuration.OidConfigs, provider, requireEnabled, out links);

            default:
                throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unknown provider mode.");
        }
    }

    // One body for both protocols (#204); Enabled is read only after the links proved the config non-null.
    private static bool TryGetLinks<T>(SerializableDictionary<string, T> configs, string provider, bool requireEnabled, [NotNullWhen(true)] out SerializableDictionary<string, Guid>? links)
        where T : ProviderConfigBase
    {
        var ok = configs.TryGetValue(provider, out var config);
        links = config?.CanonicalLinks;
        return ok && links != null && (!requireEnabled || config?.Enabled == true);
    }

    // The provider object itself, for the maps that hang off it; same fail-closed shape as TryGetLinks, and callers hold the lock.
    private static bool TryGetProvider(PluginConfiguration configuration, ProviderMode mode, string provider, [NotNullWhen(true)] out ProviderConfigBase? config)
    {
        config = mode switch
        {
            ProviderMode.Saml => configuration.SamlConfigs.TryGetValue(provider, out var saml) ? saml : null,
            ProviderMode.Oid => configuration.OidConfigs.TryGetValue(provider, out var oid) ? oid : null,
            _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unknown provider mode."),
        };

        return config is not null;
    }

    // The deadline goes with the link (#1145), or a re-link of the subject would be swept at once.
    private static void RemoveDeadline(PluginConfiguration configuration, ProviderMode mode, string provider, string canonicalKey)
    {
        if (TryGetProvider(configuration, mode, provider, out var config))
        {
            config.CanonicalLinkDeadlines.Remove(canonicalKey);
        }
    }

    // Its own step beside RemoveDeadline, because an orphan stamp is retained personal data (#1120), not bookkeeping.
    private static void RemoveLastSsoLogin(PluginConfiguration configuration, ProviderMode mode, string provider, string canonicalKey)
    {
        if (TryGetProvider(configuration, mode, provider, out var config))
        {
            config.CanonicalLinkLastLogins.Remove(canonicalKey);
        }
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
