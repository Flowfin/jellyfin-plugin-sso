// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.ObjectModel;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// The administrator's view of every Jellyfin account that holds an SSO link (#1119), one row per account
/// rather than one per link, so an account linked to two providers reads as one account with two links.
/// </summary>
/// <remarks>
/// Deliberately not the same document as <see cref="LinkExportDocument"/>, and the difference is the point
/// rather than an oversight. That one is a portable snapshot meant to be restored somewhere, so it is keyed
/// by username and drops a link whose user id resolves to nothing. This one is a report on the state of
/// THIS server, where a link pointing at an account that no longer exists is the single most useful thing
/// it can show, so it carries the user id and reports the account as absent instead of dropping the row.
/// It is a JSON-only transport shape and is never persisted to the config XML, so it carries no
/// XML-serialization attributes.
/// </remarks>
public class LinkRosterDocument
{
    /// <summary>
    /// Gets the linked accounts, one entry per Jellyfin user id that at least one canonical link points
    /// at. An account holding no link is absent: the roster answers "who is linked", and listing every
    /// unlinked account would bury that answer under the whole user table.
    /// </summary>
    public Collection<LinkedAccount> Accounts { get; } = new();
}

/// <summary>
/// One Jellyfin account and every SSO link that resolves to it.
/// </summary>
public class LinkedAccount
{
    /// <summary>
    /// Gets or sets the Jellyfin user id the links are stored against. It is the only identifier an
    /// orphaned row has, and the value an administrator needs in order to act on one.
    /// </summary>
    public Guid UserId { get; set; }

    /// <summary>
    /// Gets or sets the account's display name, or null when no account with this id exists any more.
    /// </summary>
    public string? Username { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether an account with this id still exists. An orphaned link is
    /// reported rather than dropped, and this flag is what says so: a null username alone would read as a
    /// nameless account rather than an absent one.
    /// </summary>
    public bool AccountExists { get; set; }

    /// <summary>Gets the links resolving to this account, across both protocols and every provider.</summary>
    public Collection<LinkedAccountEntry> Links { get; } = new();
}

/// <summary>
/// One link on a roster row: which provider issued the identity, and the canonical name it is known by.
/// </summary>
public class LinkedAccountEntry
{
    /// <summary>
    /// Gets or sets the protocol the provider speaks. The two protocols keep separate provider namespaces,
    /// so an entry naming only the provider would be ambiguous on a server where an OpenID and a SAML
    /// provider share a name.
    /// </summary>
    public string? Protocol { get; set; }

    /// <summary>Gets or sets the provider this link belongs to.</summary>
    public string? Provider { get; set; }

    /// <summary>
    /// Gets or sets the canonical name the link is keyed by: the identity provider's stable subject for
    /// this user, or the username it fell back to for a link made before subjects were required.
    /// </summary>
    public string? CanonicalName { get; set; }
}
