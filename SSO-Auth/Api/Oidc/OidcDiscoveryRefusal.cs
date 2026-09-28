// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>Why a discovery read came back unavailable, for the admin Test-connection probe (#1064); the login path fails closed on any value and never branches on it.</summary>
/// <remarks>It carries no provider-authored text: each value maps to a constant the operator also sees in the server log, and the one value an administrator acts on, the published issuer behind <see cref="IssuerMismatch"/>, travels beside it on <see cref="OidcDiscoveryResult.PublishedIssuer"/>.</remarks>
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

    /// <summary>
    /// The document was read and the discovery policy refused the issuer it publishes, because it is not the
    /// configured endpoint (#1837). Decided by the policy's own comparison, never by the library's error text.
    /// </summary>
    IssuerMismatch = 3,
}
