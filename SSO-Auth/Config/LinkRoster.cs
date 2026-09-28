// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>What the roster needs to know about one Jellyfin account beyond its id, resolved once per account (#1529).</summary>
/// <param name="Username">The account's current username.</param>
/// <param name="IsDisabled">Whether the account is currently disabled, whoever disabled it.</param>
internal readonly record struct LinkedAccountState(string Username, bool IsDisabled);

/// <summary>Inverts the canonical-link maps into the administrator's roster: which accounts are linked, and to what (#1119).</summary>
/// <remarks>
/// It walks the same rows the export does and keeps the orphan the export drops, because an orphaned link is what a
/// roster is opened to find. See <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Linked-Accounts"/>.
/// </remarks>
internal static class LinkRoster
{
    /// <summary>Builds the roster from the live configuration; call it under the config lock.</summary>
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
                // Resolved once per account rather than once per link.
                var state = resolve(row.UserId);
                var account = new LinkedAccount
                {
                    UserId = row.UserId,
                    Username = state?.Username,
                    AccountExists = state is not null,
                };
                entry = (account, state is { IsDisabled: true });
                byUser[row.UserId] = entry;

                // Added on first sight, so the list order is the walk order rather than a dictionary's.
                document.Accounts.Add(account);
            }

            entry.Account.Links.Add(new LinkedAccountEntry
            {
                Protocol = row.Protocol,
                Provider = row.Provider,
                CanonicalName = row.CanonicalName,
                LastSsoLoginUtc = row.LastSsoLoginUtc,

                // Offered only while the account is still disabled, which is the flag the approve action reads too (#1637).
                PendingApprovalSinceUtc = entry.IsDisabled ? row.PendingApprovalSinceUtc : null,
            });
        }

        return document;
    }
}
