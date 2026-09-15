// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Cryptography;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Session;

/// <summary>
/// One pass of the migration that shuts the manual-login door on accounts provisioned before the plugin
/// started shutting it (#1440): every SSO-linked Jellyfin account with no stored password is given an
/// unguessable one.
/// </summary>
/// <remarks>
/// <para>
/// WHY THERE IS A POPULATION AT ALL. Jellyfin creates a user with no password, and a user with no password
/// accepts the EMPTY password on the ordinary login form. The create arm has minted a random one since the
/// upstream fix released in v3.5.0.0; every release up to and including v3.4.0.2 created the account and
/// stamped it onto a provider id resolving to no password provider, and nothing more. That stamp alone shut
/// the door - until a provider's <c>DefaultProvider</c> was configured, at which point the mint repointed
/// the account at a real password provider and left the empty password behind it. Those accounts are still
/// on upgraded servers today; the create-arm fix does not reach one of them, because it only ever runs when
/// an account is new.
/// </para>
/// <para>
/// WHAT IT WILL NOT DO. It never touches <c>AuthenticationProviderId</c>. Repointing an account an
/// administrator deliberately routed somewhere would be this sweep deciding how somebody else's users log
/// in, unattended and at boot; writing the password shuts the empty-password door on its own and is the
/// smaller of the two acts. It never touches an account that already has a password, so a real one an
/// administrator set is not replaced, and it creates, adopts, disables and deletes nothing.
/// </para>
/// <para>
/// WHAT IT COSTS SOMEBODY. An account whose owner signs in by leaving the password box empty loses that,
/// and it is the whole point rather than a side effect: the population is exactly the accounts anybody on
/// the network can already sign into. The identity provider still works, and the audit line says how many
/// were sealed so an operator who is surprised can find out why.
/// </para>
/// <para>
/// Idempotent, so running it on every boot rather than once ever needs no persisted "already done" flag:
/// the second pass finds every linked account already holding a password and writes nothing.
/// </para>
/// </remarks>
internal sealed class PasswordlessLinkedAccountSweep
{
    private readonly CanonicalLinkService _canonicalLinks;
    private readonly IUserManager _userManager;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordlessLinkedAccountSweep"/> class.
    /// </summary>
    /// <param name="canonicalLinks">The canonical-link store, which owns the only reliable answer to which accounts this plugin manages.</param>
    /// <param name="userManager">The Jellyfin user manager, used to resolve and persist each account.</param>
    /// <param name="cryptoProvider">Jellyfin's crypto provider, so a sealed account's password is hashed exactly as a real one is.</param>
    /// <param name="logger">The logger the audit line is written to.</param>
    internal PasswordlessLinkedAccountSweep(CanonicalLinkService canonicalLinks, IUserManager userManager, ICryptoProvider cryptoProvider, ILogger logger)
    {
        _canonicalLinks = canonicalLinks ?? throw new ArgumentNullException(nameof(canonicalLinks));
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Runs one pass and returns how many accounts it sealed.
    /// </summary>
    /// <returns>The number of accounts given a password by this pass.</returns>
    internal async Task<int> SweepAsync()
    {
        var sealedAccounts = 0;

        // Collected across the pass and written ONCE (#1733). A write per account would be a whole
        // configuration serialization and persist per account, on the startup path of exactly the upgraded
        // servers this pass exists for - at the measured cost of a write on a large store that is minutes of
        // blocked startup for a population in the thousands. What a single write costs instead is a window,
        // and it is wider than "the process died": anything thrown out of the loop below - a failing
        // account persist is the ordinary case - abandons this map along with the pass, so every account
        // this pass had already sealed AND persisted stays sealed and unrecorded. Those accounts read as
        // "holds its own password", which is the same answer every account gave before this change and the
        // safe direction, and they join the residual named at the guard rather than being lost. Narrowing
        // that window means per-account resilience in this loop, which is a change to what a failed pass
        // does rather than to what this record says, and it is its own issue.
        var minted = new Dictionary<Guid, string>();

        // EVERY ACCOUNT THE HOST ANSWERED FOR, kept so the reclaim below asks it about as few accounts as
        // possible. A record whose account still holds a link is answered here for free, and on a healthy
        // server that is nearly all of them.
        var resolved = new HashSet<Guid>();

        foreach (var userId in _canonicalLinks.LinkedUserIds())
        {
            // A link can outlive the account it points at, which is nothing to do rather than something to
            // force - and it must not throw out of a pass that still has other accounts to walk after it.
            if (_userManager.GetUserById(userId) is not { } user)
            {
                continue;
            }

            resolved.Add(user.Id);

            // The one test that decides the population, and it is a state rather than a history: whatever
            // wrote the account, an empty stored password is the door. A password already there is left
            // alone, so an administrator who set a real one keeps it.
            if (!string.IsNullOrEmpty(user.Password))
            {
                continue;
            }

            user.Password = ProvisionedPassword.Mint(_cryptoProvider);

            // AND RECORDED (#1733), collected here and written below. Without the record this pass seals an
            // account and leaves nothing able to tell that seal from a password its owner chose, which is
            // the ambiguity the record exists to end - and this pass reaches the OLDER accounts, the ones
            // most likely to include the last administrator on an upgraded server.
            minted[user.Id] = user.Password;

            await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
            sealedAccounts++;
        }

        // THE ONE PLACE A RECORD IS EVER RECLAIMED, and the reason this pass is where it happens. The
        // account-deletion consumer drops a record when the host reports the deletion, which reaches
        // nothing for an account deleted while the plugin was not loaded - and no roster row, endpoint or
        // other sweep can see a record, so without this the map would keep an entry for such an account for
        // ever. Every key whose account no longer resolves is dropped, which is the same "a link can
        // outlive the account it points at" reading the loop above opens with.
        //
        // ASKED ABOUT AS FEW ACCOUNTS AS POSSIBLE, because `GetUserById` is a database read on the builds
        // this plugin targets rather than a cache hit - a query per record at every boot is the cost the
        // single configuration write above refuses to pay one line earlier. Every record whose account the
        // loop already resolved is answered for free, so what is asked here is the records whose account
        // holds no link, which is the population the reclaim is hunting in the first place.
        //
        // ONE ROSTER QUERY WOULD BE CHEAPER AND IS NOT AVAILABLE. `IUserManager.GetUsersIds()` answers it
        // in one call on 10.11.11 and on 12.0.0, and the DECLARED targetAbi floor is 10.11.0, where that
        // interface carries neither `GetUsersIds` nor `GetUsers` - which is why the SSO-only enforcement
        // reaches the roster by reflection and fails closed when it is absent. The ABI floor build in CI is
        // what said so; it is not a reading of the packages this machine happens to hold.
        //
        // AND NOTHING IS RECLAIMED UNLESS THE HOST ANSWERED AT LEAST ONCE, which is the floor this needs:
        // "not found" and "not answering" are the same silence, the loop above already reads that silence
        // as "a link outlived its account" and skips, and reading it as "deleted" here would drop every
        // record on the server in one write on a boot where the user store is simply not ready. That
        // direction is not self-healing - this pass records only what it SEALS and it seals nothing that
        // already holds a password, so nothing would ever write those records back and the refusal would
        // silently stop firing for every account it was written for.
        //
        // Resolved OUTSIDE the configuration lock and applied inside it, so the host's user store is never
        // asked a question while this plugin holds its own lock.
        var orphaned = resolved.Count > 0
            ? _canonicalLinks.ProvisionedPasswordAccounts()
                .Where(account => !resolved.Contains(account) && _userManager.GetUserById(account) is null)
                .ToList()
            : new List<Guid>();

        if (minted.Count > 0 || orphaned.Count > 0)
        {
            _canonicalLinks.UpdateProvisionedPasswords(minted, orphaned);
        }

        // Audited once for the pass rather than once per account: the line carries a count and nothing that
        // identifies which accounts were reachable (T-I1). Silent when there was nothing to seal, so the
        // overwhelming majority of servers - every one provisioned since v3.5.0.0 - see nothing at all.
        if (sealedAccounts > 0)
        {
            SsoAudit.PasswordlessAccountsSealed(_logger, sealedAccounts);
        }

        return sealedAccounts;
    }
}
