// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// Why a discovery read came back unavailable, for the surfaces that have to tell an operator what to do
/// about it (#1064). The login path does not branch on this - it fails closed on any value - so the reason
/// exists for the admin Test-connection probe, whose one job is to answer "why did this break".
/// <para>
/// It carries no provider-authored text. Each value maps to a constant the operator also sees in the server
/// log, so the two read the same; WHICH member repeated stays in the log entry alone.
/// </para>
/// </summary>
internal enum OidcDiscoveryRefusal
{
    /// <summary>
    /// The read failed for a reason no screen named: unreachable, refused by the discovery policy, over the
    /// outbound size bound, or a document the identity library itself would not accept. This is the default,
    /// so a result that was never given a reason reports the generic cause rather than a specific wrong one.
    /// </summary>
    Unnamed = 0,

    /// <summary>The response was refused by <see cref="RepeatedMemberScreen"/> for naming a JSON member twice.</summary>
    RepeatedMember = 1,

    /// <summary>The response was refused by <see cref="RepeatedMemberScreen"/> because its body could not be inspected as JSON.</summary>
    Uninspectable = 2,
}
