// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
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

        foreach (var userId in _canonicalLinks.LinkedUserIds())
        {
            // A link can outlive the account it points at, which is nothing to do rather than something to
            // force - and it must not throw out of a pass that still has other accounts to walk after it.
            if (_userManager.GetUserById(userId) is not { } user)
            {
                continue;
            }

            // The one test that decides the population, and it is a state rather than a history: whatever
            // wrote the account, an empty stored password is the door. A password already there is left
            // alone, so an administrator who set a real one keeps it.
            if (!string.IsNullOrEmpty(user.Password))
            {
                continue;
            }

            user.Password = ProvisionedPassword.Mint(_cryptoProvider);
            await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
            sealedAccounts++;
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
