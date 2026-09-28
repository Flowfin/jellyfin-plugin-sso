// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.ObjectModel;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>The administrator's view of every Jellyfin account that holds an SSO link, one row per account (#1119).</summary>
/// <remarks>Unlike the export it carries the user id and reports an absent account rather than dropping the row. See <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Linked-Accounts#what-a-row-says"/>.</remarks>
public class LinkRosterDocument
{
    /// <summary>Gets the linked accounts, one entry per Jellyfin user id at least one canonical link points at.</summary>
    public Collection<LinkedAccount> Accounts { get; } = new();
}

/// <summary>One Jellyfin account and every SSO link that resolves to it.</summary>
public class LinkedAccount
{
    /// <summary>Gets or sets the Jellyfin user id the links are stored against, the only identifier an orphaned row has.</summary>
    public Guid UserId { get; set; }

    /// <summary>Gets or sets the account's display name, or null when no account with this id exists any more.</summary>
    public string? Username { get; set; }

    /// <summary>Gets or sets a value indicating whether an account with this id still exists, so an orphan does not read as a nameless account.</summary>
    public bool AccountExists { get; set; }

    /// <summary>Gets the links resolving to this account, across both protocols and every provider.</summary>
    public Collection<LinkedAccountEntry> Links { get; } = new();
}

/// <summary>One link on a roster row: which provider issued the identity, and the canonical name it is known by.</summary>
public class LinkedAccountEntry
{
    /// <summary>Gets or sets the protocol the provider speaks, because the two protocols keep separate provider namespaces.</summary>
    public string? Protocol { get; set; }

    /// <summary>Gets or sets the provider this link belongs to.</summary>
    public string? Provider { get; set; }

    /// <summary>Gets or sets the canonical name the link is keyed by: the provider's stable subject, or the username an older link fell back to.</summary>
    public string? CanonicalName { get; set; }

    /// <summary>Gets or sets the last successful SSO login through this link in UTC, or null when none has been recorded (#1120).</summary>
    /// <remarks>Accurate to the granularity the stamp is coalesced at, so read it as "not later than". See <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Linked-Accounts#the-last-login-stamp-is-coarse-on-purpose"/>.</remarks>
    public DateTime? LastSsoLoginUtc { get; set; }

    /// <summary>Gets or sets the instant this plugin provisioned the linked account disabled and awaiting approval, or null when the row may not be offered for approval (#1529).</summary>
    /// <remarks>Non-null means exactly that the approve action will accept the row. See <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Linked-Accounts#waiting-for-approval"/>.</remarks>
    public DateTime? PendingApprovalSinceUtc { get; set; }
}
