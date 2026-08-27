// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
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
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Cryptography;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Linking;

/// <summary>
/// The outcome of a manual link-creation request. Closed by convention (the controller's mapper throws
/// on an unhandled arm), so a new outcome forces a new mapping rather than a silent fall-through.
/// </summary>
internal enum CanonicalLinkWriteResult
{
    /// <summary>The link was created.</summary>
    Created,

    /// <summary>The SSO identity did not resolve a usable key; nothing was written.</summary>
    EmptyKey,

    /// <summary>No provider of that mode/name exists; nothing was written.</summary>
    UnknownProvider,

    /// <summary>The key is already held by a DIFFERENT Jellyfin user; nothing was written (#1133).</summary>
    ConflictingUser,
}

/// <summary>
/// The outcome of a manual unlink request. Closed by convention (the controller's mapper throws on an
/// unhandled arm).
/// </summary>
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
}

/// <summary>
/// The issuer binding of a resolved subject-keyed OpenID link against the current login's issuer (#186).
/// SAML (any non-OpenID mode) and a login with no resolved subject link are <see cref="NotBound"/>.
/// </summary>
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

/// <summary>
/// The outcome of a manual unlink, together with whether the target user still holds any other canonical
/// SSO link after it. The remainder is meaningful only when <see cref="Result"/> is
/// <see cref="CanonicalLinkRemoveResult.Removed"/> (the other outcomes change no state); the controller
/// uses it to revoke the user's active tokens ONLY when the unlink removed their LAST link, matching the
/// hard-lockdown posture of Unregister (#440/#468) without logging out a user who still has a working SSO
/// identity.
/// </summary>
/// <param name="Result">The remove outcome.</param>
/// <param name="UserRetainsAnyLink">
/// Whether any SAML or OpenID provider still holds a canonical link pointing at the unlinked user,
/// evaluated in the SAME transaction as the removal. Only defined when <paramref name="Result"/> is
/// <see cref="CanonicalLinkRemoveResult.Removed"/>; false on the no-op outcomes.
/// </param>
internal readonly record struct CanonicalLinkRemoval(CanonicalLinkRemoveResult Result, bool UserRetainsAnyLink);

/// <summary>
/// One canonical link whose persisted account-expiry deadline has passed (#1145), as seen in a single locked
/// pass. A detached snapshot rather than a live view: the sweep acts on each entry in its own transaction, so
/// materializing the candidates first keeps the config lock short and cannot tear against a concurrent login.
/// Every entry is re-resolved and re-guarded by the disable it feeds, so an entry that stopped being true in
/// between is a no-op rather than a wrong disable.
/// </summary>
/// <param name="Mode">The provider protocol the link belongs to.</param>
/// <param name="Provider">The provider name.</param>
/// <param name="CanonicalKey">The stable subject key the link and the deadline are stored under.</param>
/// <param name="UserId">The Jellyfin user the link points at, as read in that pass.</param>
internal readonly record struct ExpiredCanonicalLink(ProviderMode Mode, string Provider, string CanonicalKey, Guid UserId);

/// <summary>
/// The account-linking workflow behind the SSO login and admin endpoints: it resolves an SSO identity
/// to a Jellyfin account (reusing an existing canonical link, adopting a pre-existing account, or
/// creating one), migrates legacy username-keyed links to the stable subject key (#155), and revokes
/// links. The controller keeps the HTTP boundary, the authorization guards, and the one-time-use
/// replay/state consume; this service keeps the account-resolution decision (via the pure
/// <see cref="AccountLinkResolver"/>) and every read/write of a provider's canonical-links map, all
/// through the <see cref="ProviderConfigStore"/> facade so each check-then-write stays under one lock.
/// </summary>
internal sealed class CanonicalLinkService
{
    // The once-per-interval throttle for the two terminal pending-legacy-link warnings (the
    // CreateNewAccount-orphan and RejectNameTaken-migratable branches). It is PROCESS-WIDE (static) on
    // purpose: this service is constructed per request by the controller, so an instance field would
    // reset every login and throttle nothing. During an upgrade window a hot login loop for a
    // not-yet-migrated user would otherwise re-emit the same warning on every attempt (CWE-400,
    // log-volume - #362/#358); the shared gate bounds that to one line per interval across all requests.
    // A one-minute interval matches the sibling cap-warn gates (OidcStateStore / SamlRequestCache, #246).
    // Tests inject a fresh gate + a fake clock so the throttle is deterministic and never leaks its cursor
    // across cases.
    private static readonly IntervalGate SharedLegacyLinkWarnGate = new(TimeSpan.FromMinutes(1));

    private readonly IUserManager _userManager;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly ProviderConfigStore _configStore;
    private readonly ILogger _logger;
    private readonly IntervalGate _legacyLinkWarnGate;
    private readonly Func<DateTime> _clock;

    /// <summary>
    /// Initializes a new instance of the <see cref="CanonicalLinkService"/> class. The optional gate and
    /// clock are test seams: production omits them, taking the process-wide legacy-link warn gate and the
    /// wall clock so the warning throttle survives this per-request service's reconstruction.
    /// </summary>
    /// <param name="userManager">The Jellyfin user manager.</param>
    /// <param name="cryptoProvider">The crypto provider used for legacy link hashing.</param>
    /// <param name="configStore">The provider configuration store the link maps live in.</param>
    /// <param name="logger">The logger.</param>
    /// <param name="legacyLinkWarnGate">The pending-legacy-link warning throttle; null takes the shared process-wide gate.</param>
    /// <param name="clock">The clock driving the warning throttle; null uses the wall clock.</param>
    internal CanonicalLinkService(
        IUserManager userManager,
        ICryptoProvider cryptoProvider,
        ProviderConfigStore configStore,
        ILogger logger,
        IntervalGate? legacyLinkWarnGate = null,
        Func<DateTime>? clock = null)
    {
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
        _configStore = configStore ?? throw new ArgumentNullException(nameof(configStore));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        // Production leaves both null and gets the process-wide gate + wall clock; tests pass a fresh gate
        // and a fake clock so the throttle stays deterministic and isolated per case.
        _legacyLinkWarnGate = legacyLinkWarnGate ?? SharedLegacyLinkWarnGate;
        _clock = clock ?? (() => DateTime.UtcNow);
    }

    /// <summary>
    /// Resolves the SSO login's stable identity to a Jellyfin user, creating or adopting the account per
    /// the provider's policy, and returns its id. Throws <see cref="AccountLinkForbiddenException"/> when
    /// the login must be refused (no identity resolved, or a pre-existing account may not be adopted).
    /// </summary>
    /// <param name="mode">The protocol the operation applies to, parsed once at the controller boundary (#369).</param>
    /// <param name="provider">The provider the login authenticated against.</param>
    /// <param name="canonicalKey">The stable identity key (OpenID sub / SAML NameID).</param>
    /// <param name="username">The display name the account is provisioned/adopted under.</param>
    /// <param name="allowExistingAccountLink">Whether adopting a pre-existing unlinked account is permitted.</param>
    /// <param name="adoptionGate">
    /// The extra proof a same-named adoption must clear (#218): a privileged target is always refused, and
    /// when the gate requires a verified email the login must carry <c>email_verified == true</c>. Default
    /// (<see cref="AdoptionGate.None"/>) is the SAML/legacy posture: admin refusal only.
    /// </param>
    /// <param name="issuer">
    /// The OpenID login's id_token issuer, used to issuer-bind the canonical link (#186): a resolved link
    /// whose stored issuer does not match this value is refused (fail closed, after an apparent repoint),
    /// and a link with no stored issuer is stamped with this value on first use (trust-on-first-use). Null
    /// for SAML and for a token that carried no <c>iss</c>; both skip the binding.
    /// </param>
    /// <param name="provisionDisabled">
    /// The provider's ProvisionNewUsersDisabled policy (#737): when a brand-new account is created on this
    /// login (the create arm only), provision it disabled and persisted so it exists inert for an administrator
    /// to approve. Never disables an existing or adopted account. Default off (a new account is created
    /// enabled); the caller inspects the resolved account via <see cref="IsAccountAwaitingApproval"/>.
    /// </param>
    /// <param name="provisionedAccessDuration">
    /// The role-mapped fixed access duration (#1146). When a brand-new account is created on this login - the
    /// CREATE ARM ONLY - its canonical link is stamped with a deadline of the link-write instant plus this
    /// duration. Every other arm ignores it: an existing link resolved by a later login is left exactly as it
    /// was, which is what makes the deadline stamped once rather than slid forward on every visit, and an
    /// ADOPTED account is not a provisioning event, so it is not given a lifetime it never agreed to. Default
    /// null (no deadline), so a provider mapping no role provisions byte-identically to before.
    /// </param>
    /// <param name="syncUsername">
    /// The provider's SyncUsernameFromProvider policy (#1138): when an EXISTING link resolves an account
    /// whose Jellyfin name no longer matches the name the login presents, rename that account to follow the
    /// identity provider. The RESOLVE ARM only - a created account already carries the presented name, and an
    /// adopted one was selected BY its name. Default off, in which case the resolved account's name is never
    /// touched, which is what every deployment does today.
    /// </param>
    /// <param name="provisioningProfile">
    /// The provisioning-profile name the login's roles selected (#1106). Like the duration above this is the
    /// CREATE ARM ONLY: it decides which policy a brand-new account is written from, and every other arm
    /// ignores it, so a later login can never re-apply a template over an administrator's per-user edit. It
    /// arrives as a NAME and is resolved against the profile set inside this service's own locked
    /// configuration read, so the set and the name pointing into it are read together. Default null, in which
    /// case the provider's own default resolution (#1105) decides - which is every login before this existed.
    /// </param>
    /// <returns>The resolved Jellyfin user id.</returns>
    internal async Task<Guid> ResolveOrCreateAsync(ProviderMode mode, string provider, string canonicalKey, string username, bool allowExistingAccountLink, AdoptionGate adoptionGate = default, string? issuer = null, bool provisionDisabled = false, TimeSpan? provisionedAccessDuration = null, bool syncUsername = false, string? provisioningProfile = null)
    {
        // Defense in depth (#95, #155): a login that resolved no stable identity key (OpenID sub /
        // SAML NameID) or no username must never create, adopt, or look up an account. Both callbacks
        // reject such logins before calling here; this belt keeps the invariant if a caller forgets.
        if (string.IsNullOrWhiteSpace(canonicalKey) || string.IsNullOrWhiteSpace(username))
        {
            throw new AccountLinkForbiddenException("The SSO login did not resolve an identity; refusing to create or link an account.");
        }

        // Read candidates -> refuse a repoint -> maybe migrate/stamp -> resolve -> act. The two locked
        // transactions (the candidate read and, on the legacy path, the migrate-and-resolve) stay whole
        // inside their own helpers; each fail-closed branch keeps its verbatim log line one level down.
        var candidates = ReadResolutionCandidates(mode, provider, canonicalKey, username, issuer);

        RefuseRepointedIssuer(candidates, mode, provider, username);

        // The account currently bearing the display name, resolved once (outside the config lock - it is
        // a user-manager read, not a config read). It is both the same-name adoption candidate for the
        // Resolve gate below AND, when it IS the legacy link's target, the proof that following the legacy
        // username key is still true same-name matching rather than handing over an account that was
        // renamed away from this name (#361). A legacy link whose target no longer holds the name is left
        // for the terminal branches to label (a fresh-account orphan, or a reject), never followed.
        var existingAccount = _userManager.GetUserByName(username);
        Guid? existingAccountUserId = existingAccount?.Id;
        bool legacyNameStillHeldByTarget = candidates.LegacyLink.HasValue && existingAccountUserId == candidates.LegacyLink;

        var (linkedUserId, migrateLegacy) = AccountLinkResolver.ResolveCanonicalLink(candidates.SubjectLink, candidates.LegacyLink, legacyNameStillHeldByTarget, allowExistingAccountLink);
        if (migrateLegacy)
        {
            // Migration fires only when the account currently bearing the name IS the legacy target
            // (legacyNameStillHeldByTarget), so that target is exactly existingAccount (non-null here).
            linkedUserId = MigrateLegacyLinkIfEligible(mode, provider, canonicalKey, username, issuer, existingAccount!);
        }
        else if (candidates.SubjectLink.HasValue && candidates.SubjectIssuer == IssuerBinding.Absent)
        {
            // Trust-on-first-use migration (#186): the resolved subject link carries no stored issuer - it
            // was minted before this store existed, or by a null-issuer path. The provider is unchanged
            // (we did not hit the mismatch refusal above), so the login's issuer IS the one the link was
            // minted under; stamp it now so a later same-URL issuer swap is caught. No lockout on upgrade:
            // an existing user's first post-upgrade login stamps and proceeds. Skipped when the login
            // carries no issuer - there is nothing safe to bind to, so the link stays un-stamped.
            StampIssuer(mode, provider, canonicalKey, issuer);
        }

        // A legacy link that survives here un-migrated (flag off - or flag on but the name no longer
        // resolves to the recorded target, #354/#361) is not logged at this point: its terminal outcome
        // decides the right message. It splits into a refusal (the name is still taken) or a
        // fresh-account creation (the name was freed by a rename), and only the outcome
        // branch below can label it accurately - the fresh-account case is a SUCCESSFUL login that
        // silently orphans the original account, not a "refused" one, so a single pre-gate line would
        // mislabel exactly the event an operator most needs to see. Each terminal branch emits its one
        // line through the shared once-per-interval gate (#362): a hot login loop for a not-yet-migrated
        // user is bounded to one warning per interval instead of one per attempt, so an upgrade window is
        // a heartbeat naming who still needs migrating rather than a flood. Only the WARNING FREQUENCY is
        // throttled - the refusal throw and the fresh-account creation still run on every login.

        // Adoption of a pre-existing unlinked account still matches on the display name resolved above.
        var decision = AccountLinkResolver.Resolve(linkedUserId, existingAccountUserId, allowExistingAccountLink);
        switch (decision.Action)
        {
            case AccountLinkAction.UseExistingLink:
                // The one arm where the two names can have drifted apart: the subject resolved an account
                // that already existed under whatever name it was created with, and the identity provider
                // may have renamed the person since.
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

    // Reads both candidate links (subject-keyed and legacy username-keyed) AND the subject link's issuer
    // binding in ONE pass under the config lock, so the whole verdict is linearized against a concurrent
    // migration or issuer stamp/repoint.
    //
    // The link is keyed on the stable identity. A legacy OpenID link (#155) was keyed on the mutable
    // username instead; when no subject-keyed link exists yet but a legacy one resolves, the caller
    // adopts and re-keys it, locking it to the subject so a later provider-side rename cannot detach it.
    // Because the legacy key is a name the identity provider controls, following it is name-based account
    // matching, so it honors AllowExistingAccountLink exactly like same-named adoption (#354): with the
    // flag off, a login whose preferred_username points at another user's entry is refused by the
    // adoption gate instead of being handed that account. Even with the flag on it is followed ONLY while
    // the recorded target still bears the name (#361); a target renamed away from it is not handed over
    // on the strength of a stale name key. Only OpenID differs key from name; SAML passes key == name.
    // Both candidates are read in ONE pass under the config lock: with separate reads, a concurrent
    // login's migration could commit between them, so this login would see the subject key before the
    // re-key and the legacy key after it, resolve neither, and bounce a legitimate user off the adoption
    // gate with a spurious 403. A link whose target user was deleted counts as absent (dangling links are
    // dead, not identities).
    private ResolutionCandidates ReadResolutionCandidates(ProviderMode mode, string provider, string canonicalKey, string username, string? issuer)
    {
        return _configStore.Read(configuration =>
        {
            // The login callbacks resolve the provider before calling, so it is normally present and
            // enabled. If it was deleted OR DISABLED in the race between that lookup and here, fail
            // CLOSED: refuse rather than fall through to the adoption gate, whose create/adopt arms
            // would otherwise mint a session with the provider's pre-delete/pre-disable settings (#373,
            // #380 - a missing provider must never default the login to valid, and the same holds for a
            // disabled one). Residual window, documented honestly: the mint itself always runs OUTSIDE
            // the config lock, so a delete/disable after the LAST guarded transaction of any arm - this
            // single read on the UseExistingLink path, the link write on adopt/create, the migration on
            // the legacy path - still mints once. The guards move the final checkpoint later; #343's
            // "disabling takes effect immediately" stays best-effort for an in-flight request unless the
            // lock were held through minting.
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

            // Classify the subject link's issuer binding in the SAME locked read (#186), so the verdict
            // cannot tear against a concurrent stamp or repoint. NotBound unless a subject link resolved
            // for an OpenID provider.
            var issuerVerdict = bySubject is null
                ? IssuerBinding.NotBound
                : ClassifyIssuer(configuration, mode, provider, canonicalKey, issuer);
            return new ResolutionCandidates(bySubject, byName, issuerVerdict);
        });
    }

    // Non-inert issuer binding (#186): the subject-keyed link this identity resolves to was minted under a
    // DIFFERENT issuer than the login now presents - an admin repointed the provider entry at another
    // identity provider behind the same discovery URL, or (with the URL edited) the belt has not yet run.
    // Refuse rather than map this login onto the old link's account; a colliding `sub` from a new IdP
    // (realistic for short numeric subjects like "1") no longer inherits the old user. Fail closed,
    // self-healing: the admin re-establishes the link, or an endpoint edit clears the stale links
    // (ServerManagedFields belt). This is the check that MUST fire at runtime - the prior review rejected
    // an inert take; a rejection test pins that it does. A login with no issuer while the link has one
    // lands here too (ClassifyIssuer treats it as a mismatch), so a token omitting `iss` cannot slip past
    // a stamped binding.
    private void RefuseRepointedIssuer(ResolutionCandidates candidates, ProviderMode mode, string provider, string username)
    {
        if (candidates.SubjectLink.HasValue && candidates.SubjectIssuer == IssuerBinding.Mismatch)
        {
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "OpenID login for {Name} via {Mode}/{Provider} refused: the account link's stored issuer does not match the login's issuer (the provider entry may have been repointed at a different identity provider). Re-establish the link via the admin endpoints.",
                    username?.ReplaceLineEndings(string.Empty),
                    mode.ToToken(),
                    provider?.ReplaceLineEndings(string.Empty));
            }

            throw new AccountLinkForbiddenException("The account link was minted under a different issuer; refusing to resolve it after an apparent provider repoint.");
        }
    }

    // The #155 legacy re-key, gated by the admin refusal and folded into ONE config transaction (#363).
    // Returns the authoritative user id the identity now resolves to (the value the login binds to), or
    // throws when an administrator target must not be adopted by name. The name contains "Migrate", so the
    // #363 conformance rule pins its Guid? return type.
    private Guid? MigrateLegacyLinkIfEligible(ProviderMode mode, string provider, string canonicalKey, string username, string? issuer, User existingAccount)
    {
        // The legacy re-key is name-based account matching too (#218): migration fires only when the
        // account currently bearing the name IS the legacy target (legacyNameStillHeldByTarget), so
        // that target is exactly existingAccount. Apply the admin refusal here as well - an attacker
        // presenting a new subject with a victim admin's preferred_username would otherwise re-key the
        // admin's legacy link onto their own subject and take the account over. Admin-only gate
        // (AdoptionGate.None): the verified-email requirement is deliberately not applied to the
        // re-key, which continues a relationship established under the pre-#155 scheme rather than
        // forming a new one. Link an admin account explicitly via the admin endpoint instead.
        if (AdoptionEligibilityResolver.Resolve(existingAccount.HasPermission(PermissionKind.IsAdministrator), AdoptionGate.None) != AdoptionVerdict.Allow)
        {
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "SSO login for {Name} via {Mode}/{Provider} refused: a legacy username-keyed link points at an administrator account, which is not adopted by name. Link it explicitly via the admin endpoints.",
                    username?.ReplaceLineEndings(string.Empty),
                    mode.ToToken(),
                    provider?.ReplaceLineEndings(string.Empty));
            }

            throw new AccountLinkForbiddenException();
        }

        // Re-key the legacy link AND re-resolve the identity in ONE config transaction (#363), then
        // bind the login to the value that transaction returns. The candidate resolution above was a
        // separate lock acquisition, so a concurrent login could migrate this same identity between
        // that snapshot and the re-key; taking the authoritative mapping from inside the re-key
        // transaction - rather than the pre-migration snapshot's linkedUserId - closes that window
        // instead of reasoning about its (previously argued-benign) safety. A concurrent winner's live
        // subject link is used as-is; the deleted-target edge resolves to null so the login falls
        // through to the create/adopt gate rather than binding to a dead account.
        var migratedUserId = MigrateAndResolveCanonicalLink(mode, provider, canonicalKey, username, issuer);
        if (_logger.IsEnabled(LogLevel.Information))
        {
            _logger.LogInformation(
                "Migrated {Mode}/{Provider} canonical link from the legacy username key to the stable subject key.",
                mode.ToToken(),
                provider?.ReplaceLineEndings(string.Empty));
        }

        return migratedUserId;
    }

    // Renames a resolved account to follow its identity provider (#1138), and returns that account either
    // way. Off by default; every early return below leaves the account exactly as it was and still yields a
    // successful login, because a display name that has drifted is cosmetic and refusing the login over it
    // would be far more expensive than the mismatch.
    //
    // THE INVARIANT THIS MUST NOT BREAK is that the subject is the key. The account is already resolved
    // when this runs - it is passed in by id - so nothing here can change WHICH account a login reaches. The
    // name follows the account; it never selects one. That is why this is a rename and not a lookup.
    //
    // The guards, in the order they fail:
    //
    // - The presented name is sanitized through the same map a provisioned name takes (#1137), so a rename
    //   cannot put a name onto an account that Jellyfin's own check would have refused at creation, and a
    //   name with nothing usable left in it renames nothing.
    // - A name already held by a DIFFERENT account is left alone. The host would refuse the collision
    //   anyway, but refusing it here is what keeps the two accounts' names from depending on which of them
    //   logged in last, and it is the case where swallowing the host's error would look like a silent
    //   no-op with no reason recorded.
    // - A rename that throws for any other reason is logged and swallowed.
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
                    provider.ReplaceLineEndings(string.Empty));
            }

            return userId;
        }

        // BOUND AT RUNTIME, NOT AT COMPILE TIME, and HostRename says why: `IUserManager.RenameUser` takes
        // (User, string) up to 10.11.8 and (Guid, string, string) from 10.11.9 on, so a direct call to
        // either one breaks the floor build or the shipping build. This is the same divergence
        // `SsoOnlyLoginService.AllUsers` already answers the same way.
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
                // The host's own refusal, unwrapped. Without this the log below records a
                // TargetInvocationException where the reason belongs, and the reason is the whole value of
                // logging it: an admin needs to read "that name is taken", not "reflection threw".
                ExceptionDispatchInfo.Capture(wrapped.InnerException).Throw();
                throw;
            }

            // Both known shapes return Task. A shape that does not is awaited as nothing rather than
            // refused, because the rename has already happened by then and failing here would log a
            // failure for work that succeeded.
            if (returned is Task rename)
            {
                await rename.ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            // Deliberately broad. The host decides what a legal name is and what it throws when it is not,
            // and this plugin compiles against an interface that promises neither; letting any of it escape
            // would turn a cosmetic mismatch into a failed login, which is the one outcome this feature must
            // never cause. The account keeps its old name and the reason is on the record.
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    ex,
                    "SSO login via {Mode}/{Provider}: renaming the linked account to follow the identity provider failed; it keeps its current name and the login continues.",
                    mode.ToToken(),
                    provider.ReplaceLineEndings(string.Empty));
            }

            return userId;
        }

        SsoAudit.AccountRenamed(_logger, mode == ProviderMode.Oid ? "OpenID" : "SAML", provider, currentName, desiredName);
        return userId;
    }

    // Adopts the pre-existing account that shares the display name, after clearing the eligibility gate.
    // existingAccount is non-null (the caller passes it only when a named account resolved), so the admin
    // read cannot NRE.
    private Guid AdoptExistingAccount(ProviderMode mode, string provider, string canonicalKey, string username, string? issuer, User existingAccount, AdoptionGate adoptionGate, Guid candidateUserId)
    {
        // Same-name adoption trusts the identity provider to make usernames unique and
        // non-reassignable (#218): a new principal asserting an existing user's name is otherwise
        // routed straight to that account. Before writing the link, clear the eligibility gate -
        // an administrator target is never adopted by name (link it explicitly via the admin
        // endpoint), and a provider that requires a verified email must have carried
        // email_verified == true. Fail closed: a refusal writes no link and emits no adoption audit.
        var verdict = AdoptionEligibilityResolver.Resolve(
            existingAccount.HasPermission(PermissionKind.IsAdministrator),
            adoptionGate);
        if (verdict != AdoptionVerdict.Allow)
        {
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "SSO login for {Name} via {Mode}/{Provider} refused adoption of a pre-existing account: {Reason}.",
                    username?.ReplaceLineEndings(string.Empty),
                    mode.ToToken(),
                    provider?.ReplaceLineEndings(string.Empty),
                    DescribeAdoptionRefusal(verdict));
            }

            throw new AccountLinkForbiddenException();
        }

        // Atomic check-then-link (#133): if a concurrent first-login already linked this
        // identity, that winner is used and no second write or duplicate audit occurs. The link
        // write also stamps the login's issuer (#186), so the adopted link is issuer-bound.
        var (adoptedUserId, wrote) = LinkCanonicalIfAbsent(mode, provider, canonicalKey, candidateUserId, issuer);
        if (wrote)
        {
            SsoAudit.AccountAdopted(_logger, mode == ProviderMode.Oid ? "OpenID" : "SAML", provider, username);
            SsoMetrics.AccountProvisioned(ProvisioningOutcome.Adopted);
        }

        return adoptedUserId;
    }

    // Maps an adoption refusal verdict to a fixed, non-PII reason phrase for the log line above. The
    // AdoptionVerdict is a reason CODE (RefusePrivileged / RefuseUnverifiedEmail), never an email or any
    // user data - but logging the enum value directly makes CodeQL's cs/exposure-of-private-information
    // heuristic trip on the "Email" in the RefuseUnverifiedEmail member name (a false positive, latent on
    // main and surfaced only once the log moved into this small helper where the flow is interprocedural).
    // Returning a literal phrase per arm keeps the refusal reason in the audit line - and reads clearer than
    // the raw enum name - while cutting the data flow the heuristic followed. The Allow arm is unreachable
    // (the caller logs only on a refusal); it is a belt for a future verdict value.
    private static string DescribeAdoptionRefusal(AdoptionVerdict verdict) => verdict switch
    {
        AdoptionVerdict.RefusePrivileged => "the target account is an administrator; link it explicitly via the admin endpoints",
        AdoptionVerdict.RefuseUnverifiedEmail => "the provider requires a verified email for adoption and the login carried none",
        _ => "the account is not eligible for name-based adoption",
    };

    // Provisions a fresh Jellyfin account for this identity and links it on the subject key, warning first
    // when a now-orphaned legacy link is being left behind. When provisionDisabled is set (the provider's
    // ProvisionNewUsersDisabled policy, #737), the brand-new account is created disabled and persisted here
    // so it exists inert for an administrator to approve; the caller then refuses the login without minting.
    private async Task<Guid> CreateNewAccountAsync(ProviderMode mode, string provider, string canonicalKey, string username, string? issuer, Guid? legacyLink, bool provisionDisabled, TimeSpan? provisionedAccessDuration, string? provisioningProfile)
    {
        // Resolved FIRST, ahead of the orphan warning below (#1137). That warning states that a fresh
        // account is being provisioned and the legacy target is now orphaned; a refusal after it would
        // leave both halves of that sentence untrue in the log, on the one line an operator recovers from.
        var provisionedName = ResolveProvisionedName(mode, provider, username);

        if (legacyLink.HasValue && _legacyLinkWarnGate.TryEnter(_clock()))
        {
            // The dangerous, previously-silent case (#354/#361): a legacy username-keyed link
            // exists and its target still exists, but no live account bears the name anymore (the
            // account was renamed on the Jellyfin side), so the legacy link was NOT followed -
            // whether adoption is off, or on but the name no longer resolves to the recorded target
            // (#361, the stale-name superset the flag-on arm used to hand over). We are about to
            // provision a FRESH account under this subject, leaving the original - the one the
            // legacy key points at - orphaned from this identity. This warning is the single
            // observable signal of that outcome; recover by linking the original account to this
            // subject via the admin endpoints. See the upgrade runbook in the Provider-Setup wiki
            // page (https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Provider-Setup). Throttled
            // through the shared once-per-interval gate (#362) so a login loop cannot flood it; the
            // account is still provisioned on every login regardless of whether the line is emitted.
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "SSO login for {Name} via {Mode}/{Provider}: a legacy username-keyed link exists but no live account bears the name (it was renamed on the Jellyfin side), so a fresh account is being provisioned and the original account is now orphaned. Re-link it to this subject via the admin endpoints.",
                    username.ReplaceLineEndings(string.Empty),
                    mode.ToToken(),
                    provider.ReplaceLineEndings(string.Empty));
            }
        }

        if (_logger.IsEnabled(LogLevel.Information))
        {
            _logger.LogInformation("SSO user {Name} doesn't exist, creating...", provisionedName.ReplaceLineEndings(string.Empty));
        }

        var user = await _userManager.CreateUserAsync(provisionedName).ConfigureAwait(false);
        user.AuthenticationProviderId = SsoManagedProviderId.Value;

        // #1139: counted where the account comes into existence, not at the pending-approval audit below.
        // That line fires only for a provider that holds new accounts for approval, so counting there would
        // report zero creations on every server that does not - the majority - while accounts were being made
        // on each of them.
        SsoMetrics.AccountProvisioned(ProvisioningOutcome.Created);

        // The provider's static provisioning template (#1099), applied HERE and only here: this is the one
        // arm on which an account is brand new, which is what lets an administrator's later per-user edit
        // survive every subsequent login. It writes only the fields the template names, so a provider
        // carrying none provisions byte-identically to before. Ahead of the pending-approval branch below so
        // an account created inert already carries its policy when an administrator comes to enable it,
        // rather than getting it on a first login that may never happen.
        ProvisioningPolicy.ApplyAtProvisioning(user, ProvisioningTemplateFor(mode, provider, provisioningProfile));
        // https://jonathancrozier.com/blog/how-to-generate-a-cryptographically-secure-random-string-in-dot-net-with-c-sharp
        user.Password = _cryptoProvider.CreatePasswordHash(Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))).ToString();

        if (provisionDisabled)
        {
            // Pending-approval provisioning (#737): create the account inert. IsDisabled is otherwise never
            // written by this plugin and is barred from SSO role mapping (PermissionRolePolicy) precisely so
            // no login can disable an EXISTING account; this is the one sanctioned write, and it targets ONLY
            // a brand-new account on this create arm - never an existing or adopted one. The normal path lets
            // the session minter persist the account; this deferred path short-circuits before the mint, so it
            // must persist the disabled flag (and this account's SSO provider id / password) itself. No
            // permissions are applied - the account carries Jellyfin's default new-user policy until an
            // administrator enables it. The caller reads the disabled state and refuses the login.
            user.SetPermission(PermissionKind.IsDisabled, true);
            var persisted = false;
            try
            {
                await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
                persisted = true;
            }
            finally
            {
                if (!persisted)
                {
                    // If persisting the disabled flag failed, the just-created account would otherwise survive
                    // ENABLED and link-less, and a later login could adopt it (with AllowExistingAccountLink on)
                    // and mint a session - defeating the hold. Roll it back so the login fails closed with no
                    // orphan. The original failure still propagates out of this finally.
                    await _userManager.DeleteUserAsync(user.Id).ConfigureAwait(false);
                }
            }

            // Audited here, at the actual provisioning event, so the line fires exactly once (not on every
            // later refused login of the now-pending account) and is always accurate - the completion-path
            // gate that refuses the login covers any disabled account, including one an admin disabled, so
            // auditing there would mislabel a deliberate ban as a fresh provisioning.
            SsoAudit.ProvisionedPendingApproval(_logger, mode == ProviderMode.Oid ? "OpenID" : "SAML", provider, provisionedName);
        }

        // Atomic check-then-link (#133): if a concurrent first-login for the same identity
        // linked meanwhile, use its account - this freshly created user is left unlinked rather
        // than overwriting the winner's link (a rare, benign orphan, not a duplicate login). The
        // link write stamps the login's issuer (#186), so the new link is issuer-bound.
        // The role-mapped access duration (#1146) travels with the link write and is stamped only when THIS
        // call actually wrote the link, in the same transaction. That placement is the whole guarantee: the
        // #133 race loser writes no link and therefore stamps no deadline over the winner's, and a deadline
        // can only ever come into existence beside a live link, which is what bounds the map.
        var (effectiveUserId, _) = LinkCanonicalIfAbsent(mode, provider, canonicalKey, user.Id, issuer, provisionedAccessDuration);
        return effectiveUserId;
    }

    // The provider's provisioning template (#1099), read under the config lock in its own short transaction
    // rather than threaded down from the caller, so the create arm reads the configuration that is live when
    // the account is actually made. A missing provider, or one stored with a null config object (#350),
    // carries no template and writes nothing - the same fail-closed skip every other read here uses. Which
    // template a provider gets - its named profile or its own inline one (#1105) - is ProvisioningPolicy's
    // rule, resolved inside the same transaction so the profile set and the name pointing at it are read
    // together and a concurrent save cannot be seen half-applied.
    private ProvisioningPolicyTemplate? ProvisioningTemplateFor(ProviderMode mode, string provider, string? provisioningProfile)
    {
        var resolution = _configStore.Read(configuration => ProvisioningPolicy.TemplateFor(configuration, ProviderConfigFor(configuration, mode, provider), provisioningProfile));

        // The previously silent arm (#1106). A name that resolves to nothing writes NO policy and never
        // falls back - deliberately, because falling back would hand the group an administrator singled out
        // for a narrower profile the wider one instead. What that costs is visibility: the account comes out
        // carrying Jellyfin's bare new-user defaults, which is byte-identical to a provider that configured
        // no template at all, so without this line nothing anywhere says a configured name failed to
        // resolve. Warning rather than error: the login succeeded and the account exists, and what is asked
        // for is a configuration repair. Emitted only here, on the create arm, so it fires once per account
        // rather than on every login of one.
        if (resolution.UnresolvedProfile is not null && _logger.IsEnabled(LogLevel.Warning))
        {
            _logger.LogWarning(
                "SSO provisioning via {Mode}/{Provider}: provisioning profile {Profile} ({Source}) is not defined, so the new account was created with NO provisioning policy. The resolution deliberately does not fall back; define that profile or remove the reference.",
                mode.ToToken(),
                provider.ReplaceLineEndings(string.Empty),
                resolution.UnresolvedProfile.ReplaceLineEndings(string.Empty),
                resolution.SelectedByRole ? "selected by a role mapping" : "the provider default");
        }

        return resolution.Template;
    }

    // The stored provider object the read above resolves its template from, or null when the provider is
    // gone or was stored with a null config object (#350).
    private static ProviderConfigBase? ProviderConfigFor(PluginConfiguration configuration, ProviderMode mode, string provider) =>
        mode switch
        {
            ProviderMode.Saml => configuration.SamlConfigs.TryGetValue(provider, out var saml) ? saml : null,
            ProviderMode.Oid => configuration.OidConfigs.TryGetValue(provider, out var oid) ? oid : null,
            _ => null,
        };

    // The name a BRAND-NEW account is created under (#1137). Jellyfin's CreateUserAsync throws for a name
    // outside its own character set, so an IdP that emits one (the 9p4#199 shape) used to fail the login
    // with a host-shaped error and no actionable signal; sanitizing here turns that into a first login that
    // succeeds under a normalized name. This runs on the CREATE arm only and touches nothing else: the link
    // key stays the subject, and the raw IdP name is still what the legacy username key, the same-name
    // lookup and the adoption comparison above are made against. That divergence is deliberate. Sanitizing
    // the value those reads use would re-point an existing legacy link and change which account a login
    // resolves to, which is exactly what #829 forbids this issue from doing; and it cannot strand this
    // account, because every later login for the same identity resolves through the subject-keyed link
    // written below rather than by name.
    private string ResolveProvisionedName(ProviderMode mode, string provider, string username)
    {
        if (!ProvisionedUsername.TrySanitize(username, out var provisionedName))
        {
            // Nothing Jellyfin would accept survived. Refuse with a named plugin-side reason rather than
            // letting CreateUserAsync throw a host-shaped error, and never invent a substitute name - an
            // account an administrator sees has to come from something the identity provider actually sent.
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "SSO login via {Mode}/{Provider} refused: the identity provider's username has no character Jellyfin accepts in an account name, so no account can be provisioned for it.",
                    mode.ToToken(),
                    provider?.ReplaceLineEndings(string.Empty));
            }

            throw new AccountLinkForbiddenException("The SSO username contains no character Jellyfin accepts in an account name; refusing to provision an account under an invented name.");
        }

        if (string.Equals(provisionedName, username, StringComparison.Ordinal))
        {
            // Unchanged, so the name-taken check the caller already made still stands and no second lookup
            // is made. A login whose name needs no sanitization therefore takes byte-for-byte the pre-#1137
            // path, which is what the regression test over the existing flow pins.
            return provisionedName;
        }

        if (_userManager.GetUserByName(provisionedName) != null)
        {
            // The normalized name is already worn by an account this identity has not proved it owns.
            // Adopting it would be a name-keyed match on a value the plugin invented rather than one the
            // provider sent, which is the takeover shape #829 rules out; appending a suffix would hand an
            // administrator an account name nobody chose. Refuse instead, and name both spellings so the
            // operator can rename one side.
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "SSO login for {Name} via {Mode}/{Provider} refused: the name normalizes to {Provisioned}, which an existing Jellyfin account already bears. Rename that account or the identity provider's username.",
                    username?.ReplaceLineEndings(string.Empty),
                    mode.ToToken(),
                    provider?.ReplaceLineEndings(string.Empty),
                    provisionedName.ReplaceLineEndings(string.Empty));
            }

            throw new AccountLinkForbiddenException("The sanitized SSO username is already taken by another Jellyfin account; refusing to adopt it by name.");
        }

        if (_logger.IsEnabled(LogLevel.Information))
        {
            _logger.LogInformation(
                "SSO username {Name} via {Mode}/{Provider} carries characters Jellyfin does not accept in an account name; provisioning as {Provisioned}. The account link is keyed on the provider subject, so the rename does not affect which account later logins resolve to.",
                username?.ReplaceLineEndings(string.Empty),
                mode.ToToken(),
                provider?.ReplaceLineEndings(string.Empty),
                provisionedName.ReplaceLineEndings(string.Empty));
        }

        return provisionedName;
    }

    /// <summary>
    /// Whether the resolved account is disabled and so must not be issued a session - a brand-new user
    /// provisioned pending approval (ProvisionNewUsersDisabled, #737) or an account an administrator disabled.
    /// A read-only check the completion path uses to refuse the login with an "awaiting approval" message
    /// instead of attempting to mint (which would fail on a disabled user). A user that vanished between
    /// resolution and here is left to the minter's own null guard (its AuthenticationException), not
    /// mislabelled as pending approval.
    /// </summary>
    /// <param name="userId">The resolved Jellyfin user id.</param>
    /// <returns><see langword="true"/> when the account exists and is disabled.</returns>
    internal bool IsAccountAwaitingApproval(Guid userId)
    {
        var user = _userManager.GetUserById(userId);
        return user is not null && user.HasPermission(PermissionKind.IsDisabled);
    }

    /// <summary>
    /// Whether the resolved account holds <see cref="PermissionKind.IsAdministrator"/>. The read the
    /// mass-lockout guard (T-D1) is made from where a caller has to decide BEFORE acting rather than learn
    /// it from a refusal - the account-expiry gate (#1144) has to let an administrator log in rather than
    /// merely leave it enabled, so it cannot infer the guard from a disable that returned false. Basis is
    /// the RESOLVED account, never the identity provider's admin claim, which is the same basis the disable
    /// paths use. A user that vanished between resolution and here reports false, so the guard opens no door
    /// for an account that is not there.
    /// </summary>
    /// <param name="userId">The resolved Jellyfin user id.</param>
    /// <returns><see langword="true"/> when the account exists and is an administrator.</returns>
    internal bool IsAccountAdministrator(Guid userId)
    {
        var user = _userManager.GetUserById(userId);
        return user is not null && user.HasPermission(PermissionKind.IsAdministrator);
    }

    /// <summary>
    /// Login-time deprovisioning (#831): when an SSO login is DENIED by the role allow-list, disable the
    /// existing linked Jellyfin account so a user offboarded at the identity provider loses Jellyfin access
    /// immediately, rather than keeping any session until a role change would otherwise apply. Opt-in per
    /// provider (<see cref="ProviderConfigBase.DisableAccountOnRoleDenied"/>).
    /// <para>
    /// GUARD - the mass-lockout defense (T-D1): an <see cref="PermissionKind.IsAdministrator"/> account is
    /// NEVER disabled by this path, which also covers the SSO-only break-glass admin (itself an admin). So a
    /// misconfigured allow-list, or an identity provider that transiently drops group claims and denies every
    /// login, can strand at most the non-admin accounts - an administrator (and the break-glass door) always
    /// remains to recover. It acts only on the EXISTING subject-keyed canonical link; a first-time denied
    /// login resolves no account and disables nothing. An already-disabled account is a no-op (not re-audited).
    /// </para>
    /// </summary>
    /// <param name="mode">The provider protocol.</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="canonicalKey">The identity's stable subject key (OpenID sub / SAML NameID) whose login was denied.</param>
    /// <param name="issuer">The denied login's token issuer (OpenID only; null for SAML), checked against the link's stored issuer binding (#186) so a colliding subject from a repointed identity provider cannot disable the prior provider's account.</param>
    /// <returns><see langword="true"/> when an enabled non-admin account was actually disabled (so the caller audits it); otherwise <see langword="false"/>.</returns>
    internal async Task<bool> DisableDeniedAccountAsync(ProviderMode mode, string provider, string? canonicalKey, string? issuer = null) =>
        await DisableLinkedAccountAsync(mode, provider, canonicalKey, issuer, enforceIssuerBinding: true).ConfigureAwait(false) is not null;

    /// <summary>
    /// Login-time enforcement of an account-expiry deadline (#1144): when a login carries an expiry instant
    /// at or before now, disable the existing linked Jellyfin account so a time-limited or guest identity
    /// loses Jellyfin access at its deadline rather than for as long as its tokens happen to live. Opt-in per
    /// provider (<see cref="ProviderConfigBase.AccountExpiryClaim"/>).
    /// <para>
    /// One rule, one implementation: this shares every safety property of
    /// <see cref="DisableDeniedAccountAsync"/> - the same mass-lockout guard (T-D1), the same issuer binding
    /// (#186), the same never-create/never-adopt resolution, the same no-op on an already-disabled account -
    /// because it is the same code, and a second copy would be a second place for the guard to be dropped
    /// from. The two names exist because the two callers mean different things by disabling, and each owes
    /// its own audit line.
    /// </para>
    /// </summary>
    /// <param name="mode">The provider protocol.</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="canonicalKey">The identity's stable subject key (OpenID sub / SAML NameID) whose deadline has passed.</param>
    /// <param name="issuer">The login's token issuer (OpenID only; null for SAML), checked against the link's stored issuer binding (#186).</param>
    /// <returns><see langword="true"/> when an enabled non-admin account was actually disabled (so the caller audits it once, at the transition); otherwise <see langword="false"/>.</returns>
    internal async Task<bool> DisableExpiredAccountAsync(ProviderMode mode, string provider, string? canonicalKey, string? issuer = null) =>
        await DisableLinkedAccountAsync(mode, provider, canonicalKey, issuer, enforceIssuerBinding: true).ConfigureAwait(false) is not null;

    /// <summary>
    /// Between-logins enforcement of an account-expiry deadline (#1145): the background sweep's disable, for
    /// a link whose persisted deadline has passed with no intervening login. Returns the account it actually
    /// disabled so the caller can revoke exactly that user's tokens, which a boolean could not name.
    /// <para>
    /// Same body, same mass-lockout guard (T-D1), same never-create/never-adopt resolution, same no-op on an
    /// already-disabled account as the two login paths above. It differs in ONE respect and the difference is
    /// deliberate: the issuer binding (#186) is not applied, because there is no incoming login to bind
    /// against. That check exists to stop a login whose subject collides with a link stamped for a DIFFERENT
    /// identity provider from acting on the prior provider's account; a sweep reads the stored link by its own
    /// stored key and has no second party to confuse it with, so comparing the stored issuer with itself would
    /// be a tautology, while passing a null issuer would instead classify every properly bound link as a
    /// Mismatch and silently exempt exactly the links that are correctly stamped.
    /// </para>
    /// </summary>
    /// <param name="mode">The provider protocol the link belongs to.</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="canonicalKey">The stable subject key whose persisted deadline has passed.</param>
    /// <returns>The Jellyfin user id disabled by this call, or <see langword="null"/> when nothing was disabled (no live link, deleted user, administrator, or already disabled).</returns>
    internal Task<Guid?> DisableExpiredAccountBySweepAsync(ProviderMode mode, string provider, string? canonicalKey) =>
        DisableLinkedAccountAsync(mode, provider, canonicalKey, issuer: null, enforceIssuerBinding: false);

    /// <summary>
    /// Persists the account-expiry instant a login carried for one canonical link (#1145), in its own config
    /// transaction. Idempotent and last-writer-wins: the identity provider is authoritative about its own
    /// deadline, so a login carrying a moved instant moves the stored one.
    /// <para>
    /// Written only when the link still exists, which is what bounds the map: an entry can only be created
    /// beside a live link, and <see cref="TryRemoveLink"/> / <see cref="RemoveUserEverywhere"/> take it away
    /// with that link. Nothing else may write here - the map is withheld from JSON precisely so a config PUT
    /// cannot forge a PAST instant for a guessed subject and have the sweep disable that account.
    /// </para>
    /// </summary>
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

    /// <summary>
    /// Stamps the instant of a successful SSO login against the canonical link it resolved (#1120), so the
    /// administrator roster can answer "last SSO login" without any event log being kept.
    /// <para>
    /// Bounded by construction, which is the whole design: an entry is only ever written beside a live link,
    /// so the map's cardinality is the link map's, a repeat login overwrites one value rather than appending,
    /// and <see cref="TryRemoveLink"/> / <see cref="RemoveUserEverywhere"/> take the entry away with the link.
    /// </para>
    /// <para>
    /// Coarse on purpose. An established user's repeat login pays no configuration persist today, and this is
    /// the login hot path, so a write-through stamp would add one write per login to the file that carries
    /// every provider secret envelope and every link map. The stamp is therefore only rewritten once it has
    /// aged past <see cref="ProviderConfigBase.LastSsoLoginGranularity"/>: the value is accurate to that
    /// resolution and never fresher, and the roster's wording has to promise no more than that.
    /// </para>
    /// </summary>
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

        // Decided under a locked READ so the common case - an established user logging in again inside the
        // granularity window - reaches no write at all. The decision and the write are two lock acquisitions
        // deliberately: the field is last-writer-wins by definition, so the worst a login racing another can
        // produce is one redundant write of an equivalent instant, and there is nothing a single held lock
        // would protect. A stored instant in the FUTURE (a config restored from a machine whose clock ran
        // ahead, or a clock stepped back) is also due, because `now - stored` is negative there and a stamp
        // that is never overdue would be frozen forever.
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

        // AVAILABILITY. This is bookkeeping for a roster column and it runs AFTER the session has been minted,
        // so a configuration persist that throws - a read-only or full volume being the ordinary way - must not
        // turn a login that has already succeeded into an error the user sees, which is what an escaping
        // exception here would do. It is deliberately swallowed to a warning: the cost of the failure is a
        // stale "last SSO login", and letting it out would trade a cosmetic gap for SSO refusing every login
        // on the server. The deadline writer above is deliberately NOT given the same treatment, because a
        // lost deadline is lost ENFORCEMENT rather than a lost display.
        try
        {
            _configStore.Mutate(configuration =>
            {
                // Re-tested inside the write lock rather than trusted from the read above: an unlink landing
                // between the two acquisitions must not resurrect a stamp for a subject that no longer holds
                // a link, which is the bound every other guarantee here rests on.
                if (TryGetProvider(configuration, mode, provider, out var config) && config.CanonicalLinks.ContainsKey(canonicalKey))
                {
                    config.CanonicalLinkLastLogins[canonicalKey] = nowUtc;
                }
            });
        }
        catch (Exception ex)
        {
            // The provider only, never the subject: this names whose bookkeeping failed and nothing that
            // identifies the account, which is the rule the audit trail already holds itself to. Line endings
            // are stripped AT the call rather than in a helper, because the sanitizer does not survive one.
            _logger.LogWarning(
                ex,
                "[SSO] Could not record the last SSO login for provider {Provider}. The login itself succeeded; the roster timestamp is stale.",
                provider?.ReplaceLineEndings(string.Empty));
        }
    }

    /// <summary>
    /// The canonical links whose persisted deadline is at or before <paramref name="nowUtc"/>, across the
    /// providers of both protocols, materialized in one locked pass (#1145).
    /// </summary>
    /// <remarks>
    /// A candidate list, not a verdict. Whether an entry may be acted on at all is decided in ONE place, by
    /// <see cref="DisableExpiredAccountBySweepAsync"/>, which re-resolves the link under the config lock and
    /// applies every guard - including <c>requireEnabled</c>, so a provider an administrator switched off is
    /// left alone: its logins are already refused, and reading that switch as permission to disable its whole
    /// userbase unattended is the opposite of what it says. Re-stating that test here would be a second place
    /// for it to drift out of and could not be proven independently, so this walk does not carry it. A
    /// deadline whose link has gone IS skipped here, because without a link there is no account to name. The
    /// pass is a bounded walk over the persisted maps and contacts no identity provider.
    /// </remarks>
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
                // A provider stored with a null config object (reachable via the null-body add, #350) holds
                // nothing to sweep; skipped rather than dereferenced, as everywhere else in this file.
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

    // The shared body of every disable-a-linked-account path above. Kept private and unnamed for any caller
    // so none can acquire a guard another lacks: PermissionRolePolicy bars IsDisabled from SSO role mapping
    // precisely so no login can disable an account, and these are its sanctioned exceptions (#831, #1144,
    // #1145, alongside #737). The exceptions sharing one body is what keeps that policy's invariant readable
    // - the guard below is stated once and cannot be present in one exception and absent in another. Returns
    // the disabled user id rather than a flag so the sweep can revoke that one account's tokens; the
    // login-path wrappers project it back to the boolean they have always returned.
    private async Task<Guid?> DisableLinkedAccountAsync(ProviderMode mode, string provider, string? canonicalKey, string? issuer, bool enforceIssuerBinding)
    {
        if (string.IsNullOrWhiteSpace(canonicalKey))
        {
            return null;
        }

        // Resolve the existing subject-keyed link under the config lock; never a create, never the legacy
        // name-keyed path (a denial must not adopt or mint). A disabled provider fails the read closed.
        // The issuer binding is enforced exactly as on the mint path (RefuseRepointedIssuer, #186): a
        // Mismatch means the denied login's subject collides with a link stamped for a DIFFERENT issuer
        // (a repointed provider), so the resolved account belongs to someone else - never disable it.
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

        // THE GUARD: an administrator is never disabled by SSO denial (covers the break-glass admin), so this
        // path can never strand the server. An already-disabled account is left untouched (no re-audit).
        if (user.HasPermission(PermissionKind.IsAdministrator) || user.HasPermission(PermissionKind.IsDisabled))
        {
            return null;
        }

        user.SetPermission(PermissionKind.IsDisabled, true);
        await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
        return userId;
    }

    // Logs the name-taken refusal (distinguishing a pending migratable legacy link from an ordinary #95
    // collision) and RETURNS the exception the caller throws, so the terminal switch arm reads as the
    // refusal it is. The refusal throws on every login; only the WARNING is throttled through the shared
    // once-per-interval gate (#362) so a login loop for a not-yet-migrated user cannot flood the log.
    private AccountLinkForbiddenException RejectNameTaken(Guid? legacyLink, ProviderMode mode, string provider, string username)
    {
        if (legacyLink.HasValue)
        {
            // Refused, but specifically because a legacy username-keyed link (#354) is pending
            // and a live account still bears the name - the migratable case, distinct from an
            // ordinary #95 name collision. Throttled through the shared once-per-interval gate
            // (#362) so a login loop for a not-yet-migrated user cannot flood it; the refusal
            // still throws on every login regardless of whether this line is emitted.
            if (_legacyLinkWarnGate.TryEnter(_clock()))
            {
                if (_logger.IsEnabled(LogLevel.Warning))
                {
                    _logger.LogWarning(
                        "SSO login for {Name} via {Mode}/{Provider} refused: a legacy username-keyed link is pending but AllowExistingAccountLink is off and a live account still bears the name. Enable AllowExistingAccountLink (a short controlled window) or link the account via the admin endpoints to migrate it.",
                        username?.ReplaceLineEndings(string.Empty),
                        mode.ToToken(),
                        provider?.ReplaceLineEndings(string.Empty));
                }
            }
        }
        else
        {
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "SSO login for {Name} via {Mode}/{Provider} refused: a pre-existing unlinked Jellyfin account exists and AllowExistingAccountLink is disabled for this provider.",
                    username?.ReplaceLineEndings(string.Empty),
                    mode.ToToken(),
                    provider?.ReplaceLineEndings(string.Empty));
            }
        }

        return new AccountLinkForbiddenException();
    }

    /// <summary>
    /// Creates a manual canonical link (admin/self linking) from a provider-side identity to a Jellyfin
    /// user, under the config lock. HTTP-free: the controller maps the returned result to a response.
    /// </summary>
    /// <param name="mode">The protocol the operation applies to, parsed once at the controller boundary (#369).</param>
    /// <param name="provider">The provider the link belongs to.</param>
    /// <param name="providerUserId">The provider-side identity key (OpenID sub / SAML NameID).</param>
    /// <param name="jellyfinUserId">The Jellyfin user to link the identity to.</param>
    /// <param name="issuer">The OpenID id_token issuer to issuer-bind the new link to (#186); null for SAML or an unauthenticated admin link, which leaves the link un-stamped (trust-on-first-use applies on its first login).</param>
    /// <returns>The write outcome.</returns>
    internal CanonicalLinkWriteResult TryCreateLink(ProviderMode mode, string provider, string providerUserId, Guid jellyfinUserId, string? issuer = null)
        => WriteLink(mode, provider, providerUserId, jellyfinUserId, issuer, refuseRebind: false);

    /// <summary>
    /// Creates a canonical link for a provisioning tool that holds no identity-provider response (#1133),
    /// under the config lock. Same write as <see cref="TryCreateLink"/> with one difference, and the
    /// difference is the whole point of the entry point: a key already held by a different Jellyfin user is
    /// refused rather than repointed.
    /// </summary>
    /// <remarks>
    /// The rebind refusal cannot be an extra check at the HTTP boundary. A read of the link map followed by
    /// a write is two transactions, and a login completing between them would be silently overwritten by
    /// the caller that read first. So the check lives inside the same <c>Mutate</c> as the write, which is
    /// what makes "nothing was written" true of the conflict rather than merely likely.
    /// <para>
    /// <see cref="TryCreateLink"/> keeps its repoint on purpose and is not narrowed here. Its callers reach
    /// it only after the human whose identity is being linked has completed a live flow at the identity
    /// provider, so the subject presented there is one the caller demonstrably controls. This entry point
    /// has no such proof behind it - an administrator credential is all it asks for - which is exactly why
    /// the two differ.
    /// </para>
    /// </remarks>
    /// <param name="mode">The protocol the operation applies to, parsed once at the controller boundary (#369).</param>
    /// <param name="provider">The provider the link belongs to.</param>
    /// <param name="providerUserId">The provider-side identity key (OpenID sub / SAML NameID).</param>
    /// <param name="jellyfinUserId">The Jellyfin user to link the identity to.</param>
    /// <returns>The write outcome, including <see cref="CanonicalLinkWriteResult.ConflictingUser"/>.</returns>
    internal CanonicalLinkWriteResult TryPreprovisionLink(ProviderMode mode, string provider, string providerUserId, Guid jellyfinUserId)
        => WriteLink(mode, provider, providerUserId, jellyfinUserId, issuer: null, refuseRebind: true);

    /// <summary>
    /// The one canonical-link write, shared by the two entry points above so the fail-closed empty-key
    /// guard, the provider lookup and the issuer stamp cannot drift between them.
    /// </summary>
    /// <param name="mode">The protocol the operation applies to.</param>
    /// <param name="provider">The provider the link belongs to.</param>
    /// <param name="providerUserId">The provider-side identity key.</param>
    /// <param name="jellyfinUserId">The Jellyfin user to link the identity to.</param>
    /// <param name="issuer">The OpenID id_token issuer to bind the new link to (#186), or null.</param>
    /// <param name="refuseRebind">Whether a key already held by another Jellyfin user is refused instead of repointed.</param>
    /// <returns>The write outcome.</returns>
    private CanonicalLinkWriteResult WriteLink(ProviderMode mode, string provider, string providerUserId, Guid jellyfinUserId, string? issuer, bool refuseRebind)
    {
        // Fail closed (#95), linking-side choke point: an SSO identity that did not resolve must not
        // create a link - an empty or whitespace key would persist a dead link no login can ever redeem.
        // Checked BEFORE the provider lookup so the two refusals keep their distinct response bodies
        // ("did not resolve an identity" vs "no matching provider"); reordering is observable.
        if (string.IsNullOrWhiteSpace(providerUserId))
        {
            return CanonicalLinkWriteResult.EmptyKey;
        }

        return _configStore.Mutate(configuration =>
        {
            // Link creation is a GRANT of future login capability, and both callers (the self-or-admin
            // link endpoints) already gate Enabled at the controller - so requiring it here too costs no
            // reachable workflow and closes the same mid-flight-disable window the login-path write guard
            // closes (#380): without it, a link could still be written for a provider disabled between
            // the controller gate and this transaction, surviving a cleanup sweep and minting on
            // re-enable. Steady-state result is unchanged (UnknownProvider, as the controller yields).
            if (!TryGetLinks(configuration, mode, provider, requireEnabled: true, out var links))
            {
                return CanonicalLinkWriteResult.UnknownProvider;
            }

            // The rebind refusal (#1133). Re-pointing an identity-provider subject at a second account is
            // how a crafted provisioning call would move somebody else's identity onto an account it
            // controls, so the pre-provision entry point refuses it and leaves the existing link intact.
            // Repeating the SAME mapping is not a rebind and stays a success, so a tool that retries a
            // request whose response it never saw does not have to distinguish the two.
            if (refuseRebind && links.TryGetValue(providerUserId, out var held) && held != jellyfinUserId)
            {
                return CanonicalLinkWriteResult.ConflictingUser;
            }

            links[providerUserId] = jellyfinUserId;
            StampIssuerInPlace(configuration, mode, provider, providerUserId, issuer);
            return CanonicalLinkWriteResult.Created;
        });
    }

    /// <summary>
    /// Removes a manual canonical link, but only when it is registered to the given Jellyfin user, under
    /// the config lock. HTTP-free: the controller maps the returned result to a response. The find,
    /// ownership check, and removal are one read-modify-write so they cannot interleave with a concurrent
    /// write to the same map.
    /// </summary>
    /// <param name="mode">The protocol the operation applies to, parsed once at the controller boundary (#369).</param>
    /// <param name="provider">The provider the link belongs to.</param>
    /// <param name="canonicalName">The provider-side identity key whose link is removed.</param>
    /// <param name="jellyfinUserId">The Jellyfin user the link must belong to.</param>
    /// <returns>The remove outcome, plus whether the user retains any other link (#468).</returns>
    internal CanonicalLinkRemoval TryRemoveLink(ProviderMode mode, string provider, string canonicalName, Guid jellyfinUserId)
    {
        // Kept as ONE Mutate (find, ownership check, remove, and the last-link check cannot interleave). A
        // no-result outcome still persists the unchanged config. For NotFound / Mismatch that already
        // matched the old controller code (its mutate callback ran to completion and persisted a no-op);
        // for UnknownProvider it is a deliberate small delta - the old code threw KeyNotFoundException out
        // of the callback before the persist, so the unknown-provider DELETE did not write, whereas this
        // returns UnknownProvider normally and Mutate<T> then persists. The config content and the HTTP
        // response are byte-identical either way, it is admin-gated, and it adds no new capability (the
        // valid-provider + bogus-name DELETE already forced the same no-op write). A read-probe-then-
        // mutate would avoid the write but reintroduce the resolve/act race this deliberately excludes.
        return _configStore.Mutate(configuration =>
        {
            // Removal REVOKES a grant, so it must keep working on a disabled provider -
            // disable-then-clean-up is the normal workflow, and gating a revocation on Enabled would
            // fail-open nothing while blocking exactly that cleanup (#380). Only absence is unknown here.
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

            links.Remove(canonicalName);

            // Drop the OpenID issuer entry alongside the link (#186), so the issuer map does not accumulate
            // orphans and a later re-link of the same sub is not judged against a stale binding. No-op for SAML.
            RemoveIssuer(configuration, mode, provider, canonicalName);

            // Drop the persisted expiry deadline alongside the link (#1145), for the same reason and on both
            // protocols: an orphan deadline is unreachable bookkeeping, and a later re-link of the same
            // subject must start with no deadline rather than inherit the removed link's.
            RemoveDeadline(configuration, mode, provider, canonicalName);

            // Drop the last-SSO-login stamp alongside the link (#1120). Unlinking IS the erasure route an
            // administrator has for that personal data, so a stamp that survived the unlink would be login
            // history retained for a subject the server no longer knows, and a re-link of the same subject
            // would report a "last SSO login" that belongs to the previous holder of the key.
            RemoveLastSsoLogin(configuration, mode, provider, canonicalName);

            // Whether the user keeps any other canonical link across ALL providers, read in the SAME
            // transaction as the removal (#468): computing it here rather than in a second lock acquisition
            // means a concurrent link add/remove cannot interleave between the remove and the check and
            // mislead the controller's last-link revocation decision. Fail toward availability at the exact
            // boundary - the user is deemed to still have SSO access unless this proves otherwise.
            var retainsAnyLink = UserHasAnyLink(configuration, jellyfinUserId);
            return new CanonicalLinkRemoval(CanonicalLinkRemoveResult.Removed, retainsAnyLink);
        });
    }

    /// <summary>
    /// Projects, for one protocol, a provider -> [canonical keys linked to this user] map, materialized
    /// under the config lock. Each provider's matches are realized with <c>ToList</c> (#157/F-10) so the
    /// result is a detached snapshot that cannot tear against a concurrent login writing a link during
    /// JSON serialization.
    /// </summary>
    /// <param name="mode">The protocol the operation applies to, parsed once at the controller boundary (#369).</param>
    /// <param name="jellyfinUserId">The Jellyfin user whose links are listed.</param>
    /// <returns>A provider -> link-key-list map.</returns>
    internal SerializableDictionary<string, IEnumerable<string>> LinksByUser(ProviderMode mode, Guid jellyfinUserId)
    {
        return _configStore.Read(configuration =>
        {
            // Both arms project (name, links) tuples through ProviderConfigBase.CanonicalLinks, so the
            // per-mode twin queries are one shape. A provider stored with a null config object (reachable
            // today via #350's null-body add) yields null links and is skipped rather than dereferenced -
            // same fail-closed treatment TryGetLinks gives it, so the read side cannot NRE into a 500 on
            // a state the write side can produce.
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

    /// <summary>
    /// Removes every canonical link pointing at the given user across all SAML and OpenID providers, so
    /// an SSO login no longer resolves to the account. Runs under the config lock and returns the number
    /// of links removed.
    /// </summary>
    /// <param name="userId">The Jellyfin user whose links are revoked.</param>
    /// <returns>The number of links removed.</returns>
    internal int RemoveUserEverywhere(Guid userId)
    {
        return _configStore.Mutate(configuration =>
        {
            int removed = 0;

            // One loop over both protocols' providers (covariant Concat over the shared base). Skip a
            // provider stored with a null config object (reachable via #350); it holds no links to revoke,
            // and dereferencing it would NRE into a 500 - the same fail-closed skip TryGetLinks uses.
            foreach (var config in configuration.SamlConfigs.Values.Concat<ProviderConfigBase>(configuration.OidConfigs.Values))
            {
                if (config?.CanonicalLinks is { } links)
                {
                    removed += CanonicalLinkRevoker.RemoveUser(links, userId);
                }

                // Prune orphaned OpenID issuer entries (#186): after the revoke, any issuer keyed on a sub
                // no longer present in the links map is dead weight and must not linger to spuriously bind
                // (or refuse) a future re-link of that sub. SAML has no issuer map.
                if (config is OidConfig oid && oid.CanonicalLinks is { } liveLinks)
                {
                    foreach (var staleKey in oid.CanonicalLinkIssuers.Keys.Where(k => !liveLinks.ContainsKey(k)).ToList())
                    {
                        oid.CanonicalLinkIssuers.Remove(staleKey);
                    }
                }

                // The same prune for the expiry deadlines (#1145), on BOTH protocols - unlike the issuer map
                // this one exists for SAML too. An orphan here is worse than dead weight: it would name a
                // subject whose link was just revoked, so a re-link of that subject would arrive already
                // expired and be disabled by the next sweep tick.
                if (config?.CanonicalLinks is { } remaining)
                {
                    foreach (var staleKey in config.CanonicalLinkDeadlines.Keys.Where(k => !remaining.ContainsKey(k)).ToList())
                    {
                        config.CanonicalLinkDeadlines.Remove(staleKey);
                    }

                    // And the last-SSO-login stamps (#1120), on both protocols for the same reason the
                    // deadlines are: this path removes the links directly rather than through TryRemoveLink,
                    // so it needs its own prune, and the admin Unregister is the erasure route the retention
                    // promise names. A stamp left behind here would be login history for an account whose
                    // links were just revoked, with nothing left in the roster to reach it by.
                    foreach (var staleKey in config.CanonicalLinkLastLogins.Keys.Where(k => !remaining.ContainsKey(k)).ToList())
                    {
                        config.CanonicalLinkLastLogins.Remove(staleKey);
                    }
                }
            }

            return removed;
        });
    }

    // Whether any SAML or OpenID provider still holds a canonical link pointing at the user, read under the
    // caller's already-held config lock (#468). A provider stored with a null config object (reachable via
    // the null-body add, #350) holds no links and is skipped rather than dereferenced - the same fail-closed
    // treatment TryGetLinks / RemoveUserEverywhere give it. Short-circuits on the first match. Static and
    // parameterized on the live configuration so it composes inside an existing Read/Mutate transaction
    // without taking the lock again.
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

    /// <summary>
    /// Whether the SSO identity may still mint a session for the given user: the provider exists and is
    /// enabled, its canonical-links map still holds <paramref name="canonicalKey"/> pointing at
    /// <paramref name="userId"/>, and that user still exists. Read under the config lock, so it is
    /// linearized against a concurrent revocation (<see cref="RemoveUserEverywhere"/> /
    /// <see cref="TryRemoveLink"/>) or a mid-flight provider disable.
    /// </summary>
    /// <remarks>
    /// The in-flight revocation gate (#232): a login resolves the account under the config lock but the
    /// session mint runs after the lock is released, so an admin Unregister (or a link delete, or a
    /// provider disable) that lands in that gap would otherwise still mint a session for the just-revoked
    /// identity. The mint flow re-reads this predicate twice - before applying the user side effects (so a
    /// revoked login persists no grants) and again as the last check before the mint (so a revocation
    /// landing mid-mint still yields no session). The final check does not close the race outright - a
    /// revocation committing between it and the mint call still mints once - but it shrinks the window to
    /// that single unavoidable gap (the mint cannot be held under the lock, which is async). Every unknown
    /// resolves to false (missing/whitespace key, missing or disabled provider, missing/mismatched link,
    /// deleted target), so it is fail closed.
    /// </remarks>
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

    // Atomically links canonicalKey to candidateUserId unless a live link already exists for it (#133).
    // The existence check and the write are ONE Mutate read-modify-write, so two concurrent first-logins
    // for the same identity cannot both write or both adopt: the loser observes the winner's link and
    // reports WroteLink=false (so the caller does not re-emit the adoption audit). The link write goes
    // straight into the config (no discarded ActionResult), so a failure to persist propagates rather
    // than falling through as a successful adoption.
    private (Guid EffectiveUserId, bool WroteLink) LinkCanonicalIfAbsent(ProviderMode mode, string provider, string canonicalKey, Guid candidateUserId, string? issuer, TimeSpan? provisionedAccessDuration = null)
    {
        return _configStore.Mutate(configuration =>
        {
            // The login path resolved the provider before reaching here. If it was deleted or disabled
            // in the race since, fail CLOSED: refuse rather than return a session with no link written
            // (#373, #380). A freshly created user may be left orphaned, the same benign outcome as the
            // #133 race loser.
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

                // A link written under this login carries this login's issuer (#186). The #133 race loser
                // (wroteLink == false) uses the winner's already-stamped link, so it stamps nothing.
                StampIssuerInPlace(configuration, mode, provider, canonicalKey, issuer);

                // A link written by a PROVISIONING login carries the role-mapped access deadline (#1146),
                // anchored to this instant. Only the create arm passes a duration - adoption passes none - and
                // only the writer reaches here, so a second login of the same account resolves the existing
                // link, never re-enters this branch, and leaves the recorded deadline exactly where it is. A
                // sliding deadline is the one defect this direction of the feature can have, and this is the
                // single place it is prevented rather than a rule restated at each caller.
                StampProvisionedDeadlineInPlace(configuration, mode, provider, canonicalKey, provisionedAccessDuration);
            }

            return (effectiveUserId, wroteLink);
        });
    }

    // Re-keys a canonical link from the legacy username key to the stable subject key (#155) AND returns
    // the authoritative user id the identity now resolves to, in ONE config transaction (#363). The
    // caller resolved the candidates in an earlier lock acquisition, so folding the re-key and the
    // re-resolution into this single transaction - and having the caller bind to the returned id rather
    // than that earlier snapshot - removes the window a concurrent login could interpose in between the
    // snapshot and the re-key. Idempotent under concurrency: if the legacy key is already gone (a
    // concurrent login migrated first) the move is a no-op, and a LIVE subject key is never overwritten -
    // only a dangling one (its target user deleted), which would otherwise block the hand-off on every
    // subsequent login. Returns null only when neither key resolves a live account (the dangling edge), so
    // the login fails closed into the create/adopt gate rather than binding to a dead account.
    private Guid? MigrateAndResolveCanonicalLink(ProviderMode mode, string provider, string canonicalKey, string legacyKey, string? issuer)
    {
        return _configStore.Mutate<Guid?>(configuration =>
        {
            // The candidate-resolving read passed the provider enabled; if it was deleted or disabled in
            // the window since, fail CLOSED: throw rather than no-op, because the caller would otherwise
            // bind to the pre-window legacy id and mint a session for a provider that no longer exists or
            // was just switched off (#373, #380).
            if (!TryGetLinks(configuration, mode, provider, requireEnabled: true, out var links))
            {
                throw new AccountLinkForbiddenException("The SSO provider is no longer configured or is disabled; refusing to migrate the account link.");
            }

            // Re-key only a legacy entry that still needs it: the subject key must be absent or dangling
            // (never overwrite a live subject link a concurrent login already established). When we re-key,
            // the identity now resolves subject-keyed to the legacy target, so that IS the authoritative id
            // - returning the moved value (rather than re-reading and filtering) preserves the prior
            // behaviour on the deleted-mid-migration race, where the caller bound to the legacy id and
            // failed closed downstream.
            if (links.TryGetValue(legacyKey, out var legacyUserId)
                && (!links.TryGetValue(canonicalKey, out var subjectUserId) || _userManager.GetUserById(subjectUserId) == null))
            {
                links.Remove(legacyKey);
                links[canonicalKey] = legacyUserId;

                // The re-keyed link is a fresh subject-keyed link written under THIS login, so stamp its
                // issuer (#186). The legacy key carried no issuer (it predates the store); the new key is
                // bound to the login that migrated it, matching the create/adopt write paths.
                StampIssuerInPlace(configuration, mode, provider, canonicalKey, issuer);
                return legacyUserId;
            }

            // Nothing to migrate: a concurrent login already re-keyed, or the legacy key is gone. Bind to
            // the authoritative subject link, treating a dangling one (target deleted) as absent.
            return links.TryGetValue(canonicalKey, out var live) && _userManager.GetUserById(live) != null
                ? live
                : (Guid?)null;
        });
    }

    // The provider's canonical-links map via TryGetValue rather than the throwing indexer, so an unknown
    // provider on the reachable admin link/unlink paths is a false return the caller maps to
    // UnknownProvider - finishing the #241 removal of KeyNotFoundException-as-control-flow. Returns true
    // and a non-null map only when the provider exists AND has a config object; a missing provider - or a
    // null-valued entry (reachable today via the null-body add, #350) - returns false, so the caller fails
    // closed (UnknownProvider on admin paths, a reject on login paths) instead of dereferencing null. With
    // requireEnabled, a DISABLED provider is treated like an absent one - every GRANT path (the login
    // guards and the link-create write) passes true so a provider disabled mid-flight is rejected exactly
    // like a deleted one (#380), while removal passes false because revoking must keep working on a
    // disabled provider (disable-then-clean-up). The map is
    // self-healing (CanonicalLinks lazily creates and stores it), so mutating the returned map persists
    // directly; callers must hold the config lock (Read / Mutate) while touching it. The mode is the typed
    // ProviderMode the controller parsed once at the HTTP boundary (#369), so both dispatch arms are reached
    // only with a validated value; the default throw stays as a belt against an out-of-range enum value.
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

    // Generic over the provider config type (both maps hold ProviderConfigBase since #204), so the SAML
    // and OpenID arms are one body: a missing provider or a null-valued entry returns false; with
    // requireEnabled a disabled provider also returns false. Reads Enabled only after links != null has
    // proven config non-null.
    private static bool TryGetLinks<T>(SerializableDictionary<string, T> configs, string provider, bool requireEnabled, [NotNullWhen(true)] out SerializableDictionary<string, Guid>? links)
        where T : ProviderConfigBase
    {
        var ok = configs.TryGetValue(provider, out var config);
        links = config?.CanonicalLinks;
        return ok && links != null && (!requireEnabled || config?.Enabled == true);
    }

    // The provider config object itself, for the server-managed map that hangs off it and is not the links
    // map (the deadlines, #1145). Same fail-closed shape as TryGetLinks: a missing provider, or an entry
    // stored with a null config object (#350), returns false rather than being dereferenced. Callers must
    // hold the config lock; the maps are self-healing, so mutating the returned object's map persists.
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

    // Drops a link's persisted expiry deadline within the caller's already-held config transaction (#1145),
    // called alongside a link removal so the deadline map does not outlive the links it keys off. Without it
    // a re-link of the same subject would inherit the previous holder's deadline and be swept immediately.
    private static void RemoveDeadline(PluginConfiguration configuration, ProviderMode mode, string provider, string canonicalKey)
    {
        if (TryGetProvider(configuration, mode, provider, out var config))
        {
            config.CanonicalLinkDeadlines.Remove(canonicalKey);
        }
    }

    // Drops a link's last-SSO-login stamp within the caller's already-held config transaction (#1120), called
    // alongside a link removal. Kept as its own named step beside RemoveDeadline rather than folded into it,
    // because the two are removed for different reasons: an orphan deadline is bookkeeping the sweep would act
    // on, an orphan stamp is retained personal data whose erasure route was just taken.
    private static void RemoveLastSsoLogin(PluginConfiguration configuration, ProviderMode mode, string provider, string canonicalKey)
    {
        if (TryGetProvider(configuration, mode, provider, out var config))
        {
            config.CanonicalLinkLastLogins.Remove(canonicalKey);
        }
    }

    // Classifies an OpenID subject link's issuer binding against the login's issuer, read under the caller's
    // config lock (#186). SAML (and any non-OID mode) is NotBound - issuer binding is OpenID only. For OID:
    // Absent when the link has no stored issuer yet (legacy/un-stamped, eligible for trust-on-first-use);
    // Match when the stored issuer ordinally equals the login's; Mismatch otherwise. A blank stored value is
    // treated as Absent (never written blank; defensive). The Mismatch arm INCLUDES the case where the login
    // carries no issuer while the link has one, so a token that omits `iss` cannot slip past a stamped
    // binding - fail closed.
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

    // Trust-on-first-use stamp of an OpenID link that has no stored issuer yet (#186), in its own config
    // transaction. OID-only and non-blank-issuer-only. Idempotent: writes only when the link still exists AND
    // its issuer is still absent, so a concurrent login that already stamped is not overwritten. A no-op for
    // SAML or a blank issuer (nothing safe to bind to) - the link stays un-stamped rather than binding to an
    // empty value.
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

    // Stamps (overwriting) an OpenID link's issuer within the caller's ALREADY-HELD config transaction (#186),
    // called right after a link WRITE (adopt / create / migrate / manual link) so the fresh link carries the
    // issuer it was minted under. Overwrites any stale value - a link just (re)written under this login belongs
    // to this login's issuer. A no-op for SAML or a blank issuer.
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

    // Stamps the role-mapped access deadline beside a link this transaction just wrote (#1146), inside the
    // caller's config lock so the deadline and the link it describes land together or not at all. Called
    // from the create arm only; every other caller passes null and this is a no-op.
    //
    // The clock read is the instance clock, so the suite can pin the anchor instead of racing the wall
    // clock. Both protocols are handled - unlike the issuer stamp, which is OpenID-only - because the map it
    // writes into is carried by ProviderConfigBase and is swept for both.
    //
    // The duration is re-checked against the same bounds the policy and the save-time validator apply,
    // because the guard has to sit where the arithmetic is: DateTime.AddHours THROWS past DateTime.MaxValue,
    // and a value hand-edited into the config XML reaches this line without passing the save path at all. A
    // duration outside the bounds stamps NOTHING rather than throwing, so the login still succeeds and the
    // account simply carries no deadline - which is exactly what the same provider does today.
    private void StampProvisionedDeadlineInPlace(PluginConfiguration configuration, ProviderMode mode, string provider, string canonicalKey, TimeSpan? provisionedAccessDuration)
    {
        if (provisionedAccessDuration is not { } duration
            || duration <= TimeSpan.Zero
            || duration > TimeSpan.FromHours(GuestAccessDurationRoleMap.MaxDurationHours))
        {
            return;
        }

        if (TryGetProvider(configuration, mode, provider, out var config))
        {
            config.CanonicalLinkDeadlines[canonicalKey] = _clock().ToUniversalTime() + duration;
        }
    }

    // Drops an OpenID link's issuer entry within the caller's already-held config transaction (#186), called
    // alongside a link removal so the issuer map does not accumulate orphans. A no-op for SAML.
    private static void RemoveIssuer(PluginConfiguration configuration, ProviderMode mode, string provider, string canonicalKey)
    {
        if (mode == ProviderMode.Oid
            && configuration.OidConfigs.TryGetValue(provider, out var config)
            && config?.CanonicalLinkIssuers is { } issuers)
        {
            issuers.Remove(canonicalKey);
        }
    }

    // The result of the single under-lock candidate read: the subject-keyed link (if live), the legacy
    // username-keyed link (if live), and the subject link's issuer binding against the login (#186) - all
    // resolved in one locked pass so the orchestrator acts on a self-consistent snapshot.
    private readonly record struct ResolutionCandidates(Guid? SubjectLink, Guid? LegacyLink, IssuerBinding SubjectIssuer);
}
