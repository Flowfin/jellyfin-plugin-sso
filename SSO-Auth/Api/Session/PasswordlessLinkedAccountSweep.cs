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

/// <summary>One pass that gives every SSO-linked account with no stored password an unguessable one, so the empty-password door shuts (#1440).</summary>
/// <remarks>
/// It never touches the provider id or an account that already holds a password, and it is idempotent, so it runs at
/// every boot without a flag. See <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model#password-less-sso-accounts-are-sealed-at-start-up"/>.
/// </remarks>
internal sealed class PasswordlessLinkedAccountSweep
{
    private readonly CanonicalLinkService _canonicalLinks;
    private readonly IUserManager _userManager;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly ILogger _logger;

    /// <summary>Initializes a new instance of the <see cref="PasswordlessLinkedAccountSweep"/> class.</summary>
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

    /// <summary>Runs one pass and returns how many accounts it sealed.</summary>
    /// <returns>The number of accounts given a password by this pass.</returns>
    internal async Task<int> SweepAsync()
    {
        var sealedAccounts = 0;

        // Collected across the pass and written once, because a persist per account is minutes of blocked startup on a large store (#1733).
        var minted = new Dictionary<Guid, string>();

        // Every account the host answered for, so the reclaim below asks about as few accounts as possible.
        var resolved = new HashSet<Guid>();

        foreach (var userId in _canonicalLinks.LinkedUserIds())
        {
            // A link can outlive the account it points at.
            if (_userManager.GetUserById(userId) is not { } user)
            {
                continue;
            }

            resolved.Add(user.Id);

            // An empty stored password is the door, whatever wrote the account; a password already there is kept.
            if (!string.IsNullOrEmpty(user.Password))
            {
                continue;
            }

            user.Password = ProvisionedPassword.Mint(_cryptoProvider);

            // Recorded, so a seal can be told from a password the owner chose (#1733).
            minted[user.Id] = user.Password;

            await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
            sealedAccounts++;
        }

        // The one place a record is reclaimed, for accounts deleted while the plugin was not loaded; nothing is reclaimed unless the host answered at least once, or a user store that is not ready would drop every record.
        var orphaned = resolved.Count > 0
            ? _canonicalLinks.ProvisionedPasswordAccounts()
                .Where(account => !resolved.Contains(account) && _userManager.GetUserById(account) is null)
                .ToList()
            : new List<Guid>();

        if (minted.Count > 0 || orphaned.Count > 0)
        {
            _canonicalLinks.UpdateProvisionedPasswords(minted, orphaned);
        }

        // One line per pass carrying a count and no account, and silent when nothing was sealed.
        if (sealedAccounts > 0)
        {
            SsoAudit.PasswordlessAccountsSealed(_logger, sealedAccounts);
        }

        return sealedAccounts;
    }
}
