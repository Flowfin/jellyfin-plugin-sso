// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// What the roster needs to know about one Jellyfin account beyond its id (#1529), resolved once per
/// account by the caller that holds the user manager. Null is the resolver's answer for an id no account
/// answers to, which the roster keeps as an orphan row rather than dropping.
/// </summary>
/// <param name="Username">The account's current username.</param>
/// <param name="IsDisabled">Whether the account is currently disabled, whoever disabled it and for whatever reason.</param>
internal readonly record struct LinkedAccountState(string Username, bool IsDisabled);

/// <summary>
/// Inverts the canonical-link maps into the administrator's roster (#1119): the maps are stored per
/// provider, keyed by identity, and the question an administrator asks is the other way round - which
/// accounts are linked, and to what.
/// </summary>
/// <remarks>
/// It walks the same <see cref="LinkExport.Rows"/> sequence the portable export does, so the two cannot
/// disagree about which providers are readable or which links exist. What differs is what each does with a
/// link whose user id resolves to no account: the export drops it, because nothing could restore it, and
/// this keeps it, because an orphaned link is exactly what an administrator opens the roster to find. As
/// with the export, no provider configuration field is copied, so no client secret, signing key or
/// certificate can reach the output by construction.
/// </remarks>
internal static class LinkRoster
{
    /// <summary>
    /// Builds the roster from the live configuration. Call it under the config lock (through
    /// <c>ReadConfiguration</c>) so both link maps are read atomically against each other.
    /// </summary>
    /// <param name="live">The live plugin configuration to read.</param>
    /// <param name="resolve">Resolves a Jellyfin user id to what the roster needs to know about its account, or null when no such account exists.</param>
    /// <returns>The roster document.</returns>
    internal static LinkRosterDocument Build(PluginConfiguration live, Func<Guid, LinkedAccountState?> resolve)
    {
        ArgumentNullException.ThrowIfNull(live);
        ArgumentNullException.ThrowIfNull(resolve);

        var document = new LinkRosterDocument();
        var byUser = new Dictionary<Guid, (LinkedAccount Account, bool IsDisabled)>();

        foreach (var row in LinkExport.Rows(live))
        {
            if (!byUser.TryGetValue(row.UserId, out var entry))
            {
                // Resolved once per account rather than once per link: an account linked to four providers
                // is one user-manager read, and the answer cannot differ between its own rows.
                var state = resolve(row.UserId);
                var account = new LinkedAccount
                {
                    UserId = row.UserId,
                    Username = state?.Username,
                    AccountExists = state is not null,
                };
                entry = (account, state is { IsDisabled: true });
                byUser[row.UserId] = entry;

                // Added on first sight, so the accounts come out in the order their first link is walked
                // and a reader gets a stable list rather than a dictionary's enumeration order.
                document.Accounts.Add(account);
            }

            entry.Account.Links.Add(new LinkedAccountEntry
            {
                Protocol = row.Protocol,
                Provider = row.Provider,
                CanonicalName = row.CanonicalName,
                LastSsoLoginUtc = row.LastSsoLoginUtc,

                // OFFERED ONLY WHILE THE ACCOUNT IS STILL DISABLED (#1637). The record says what this plugin
                // did at provisioning; the flag says what is true now, and an account somebody has since
                // enabled is not waiting for anything. The approve action reads the same flag before it
                // acts, so this is the page agreeing with the action rather than a rule of its own - and
                // it keeps a working account off a list of accounts that cannot sign in. An orphan row
                // resolves to no state and is offered nothing: there is no account left to enable.
                PendingApprovalSinceUtc = entry.IsDisabled ? row.PendingApprovalSinceUtc : null,
            });
        }

        return document;
    }
}
