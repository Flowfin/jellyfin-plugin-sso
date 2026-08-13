// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;

namespace Jellyfin.Plugin.SSO_Auth.Config;

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
    /// <param name="resolveUsername">Resolves a Jellyfin user id to its username, or null when no such account exists.</param>
    /// <returns>The roster document.</returns>
    internal static LinkRosterDocument Build(PluginConfiguration live, Func<Guid, string?> resolveUsername)
    {
        ArgumentNullException.ThrowIfNull(live);
        ArgumentNullException.ThrowIfNull(resolveUsername);

        var document = new LinkRosterDocument();
        var byUser = new Dictionary<Guid, LinkedAccount>();

        foreach (var row in LinkExport.Rows(live))
        {
            if (!byUser.TryGetValue(row.UserId, out var account))
            {
                // Resolved once per account rather than once per link: an account linked to four providers
                // is one user-manager read, and the answer cannot differ between its own rows.
                var username = resolveUsername(row.UserId);
                account = new LinkedAccount
                {
                    UserId = row.UserId,
                    Username = username,
                    AccountExists = username is not null,
                };
                byUser[row.UserId] = account;

                // Added on first sight, so the accounts come out in the order their first link is walked
                // and a reader gets a stable list rather than a dictionary's enumeration order.
                document.Accounts.Add(account);
            }

            account.Links.Add(new LinkedAccountEntry
            {
                Protocol = row.Protocol,
                Provider = row.Provider,
                CanonicalName = row.CanonicalName,
            });
        }

        return document;
    }
}
