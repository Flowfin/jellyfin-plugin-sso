// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>One record that this plugin provisioned a linked account disabled and awaiting an administrator: which account, and when (#1529).</summary>
/// <remarks>
/// The account is half the record, because a subject whose account was deleted is re-linked at another account and
/// a mark carrying only an instant would follow it. See
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Linked-Accounts#waiting-for-approval"/>.
/// </remarks>
public class PendingApproval
{
    /// <summary>Gets or sets the account this plugin provisioned disabled, as it stood when the link was written.</summary>
    public Guid UserId { get; set; }

    /// <summary>Gets or sets the provisioning instant in UTC, so a reader can see how long somebody has been waiting.</summary>
    public DateTime SinceUtc { get; set; }

    /// <summary>The record this provider holds for one canonical link, or null when none still describes the account the link points at.</summary>
    /// <remarks>The one home for the rule, so the roster and the approve action cannot disagree.</remarks>
    /// <param name="config">The provider configuration holding both maps.</param>
    /// <param name="canonicalName">The identity key the link is stored under.</param>
    /// <returns>The live record, or <see langword="null"/>.</returns>
    internal static PendingApproval? Live(ProviderConfigBase config, string? canonicalName)
    {
        ArgumentNullException.ThrowIfNull(config);

        if (string.IsNullOrEmpty(canonicalName))
        {
            return null;
        }

        return config.CanonicalLinkPendingApprovals.TryGetValue(canonicalName, out var record)
            && record is not null
            && config.CanonicalLinks.TryGetValue(canonicalName, out var linked)
            && record.UserId == linked
                ? record
                : null;
    }
}
