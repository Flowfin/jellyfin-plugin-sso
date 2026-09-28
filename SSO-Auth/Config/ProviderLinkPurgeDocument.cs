// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>What a per-provider bulk unlink removed, answered to the caller (#1519).</summary>
/// <remarks>Counts only, because an answer naming the unlinked accounts would be a roster export behind a delete verb.</remarks>
public class ProviderLinkPurgeDocument
{
    /// <summary>Gets or sets how many canonical links were removed, which equals the count the caller sent because a mismatch is a refusal.</summary>
    public int Removed { get; set; }

    /// <summary>Gets or sets how many accounts were left with no SSO link and had their tokens revoked, the same scope the single unlink revokes at (#468).</summary>
    public int SignedOut { get; set; }
}
