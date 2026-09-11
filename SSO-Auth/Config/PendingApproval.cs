// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// One record that this plugin provisioned a linked account disabled and awaiting an administrator
/// (#1529): which account it did that to, and when.
/// </summary>
/// <remarks>
/// THE ACCOUNT IS HALF THE RECORD, and it is written here rather than left implied by the map's key
/// because the key is an identity-provider subject and a subject does not hold the same account for ever.
/// A link whose target account was deleted counts as absent everywhere in this plugin, so the next login
/// for that subject writes the key again - at a DIFFERENT account, by adoption or by a fresh provisioning.
/// A mark carrying only an instant would survive that hand-off and go on describing whichever account the
/// key now names, which is how a record of what this plugin DID turns back into the guess it exists to
/// replace. Written beside the instant, the account is the thing a reader compares: a mark whose account
/// is no longer the one the link points at describes nothing, and says so.
/// <para>
/// A plain XML-serializable class (public parameterless ctor + get/set), because it is stored as the value
/// of a <see cref="SerializableDictionary{TKey,TValue}"/> on <see cref="ProviderConfigBase"/> - the shape
/// <see cref="LogoutSession"/> already takes there. It holds no secret: a user id and an instant, both of
/// which the administrator-only roster row beside it already carries.
/// </para>
/// </remarks>
public class PendingApproval
{
    /// <summary>
    /// Gets or sets the Jellyfin account this plugin provisioned disabled and awaiting approval, as it
    /// stood when the link was written. A mark is only about this account: when the link it is keyed
    /// under points somewhere else, the mark is stale by definition and no reader may act on it.
    /// </summary>
    public Guid UserId { get; set; }

    /// <summary>
    /// Gets or sets the instant the account was provisioned, in UTC. The PROVISIONING instant rather than
    /// the approval's, so a reader can see how long somebody has been waiting, which is the question an
    /// approval list is opened with.
    /// </summary>
    public DateTime SinceUtc { get; set; }
}
