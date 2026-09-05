// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// What a per-provider bulk unlink removed (#1519), answered to the caller.
/// </summary>
/// <remarks>
/// It reports COUNTS and nothing else. The action reads canonical names and account ids to do its work and
/// writes none of them here: an endpoint that answered with the accounts it had just unlinked would be a
/// roster export behind a delete verb, and the elevated caller already has the link roster route if that is
/// what they want. A JSON-only transport shape, never persisted to the config XML, so it carries no
/// XML-serialization attributes - the same shape <see cref="LinkImportResultDocument"/> takes.
/// </remarks>
public class ProviderLinkPurgeDocument
{
    /// <summary>
    /// Gets or sets how many canonical links were removed. It equals the count the caller sent, because a
    /// count that did not match is a refusal rather than a partial run - so this is the confirmation that
    /// the number the operator was shown is the number that went.
    /// </summary>
    public int Removed { get; set; }

    /// <summary>
    /// Gets or sets how many accounts were left holding no canonical SSO link at all and had their live
    /// tokens revoked. Always at most <see cref="Removed"/>, and smaller whenever an account held several
    /// of the removed links or still holds one on another provider - those accounts keep their sessions,
    /// which is the same scope the single unlink revokes at (#468).
    /// </summary>
    public int SignedOut { get; set; }
}
