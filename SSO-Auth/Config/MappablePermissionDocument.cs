// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// The permission names an administrator may put in a <c>PermissionRoleMappings</c> entry or in a
/// provisioning template's permission list (#1484), so a page offering them has ONE producer to read
/// instead of a second copy of the vocabulary.
/// </summary>
/// <remarks>
/// <para>
/// NAMES ONLY, and they are the same names on every installation: the set is Jellyfin's own
/// <c>PermissionKind</c> minus the permissions this plugin refuses to map generically, both compiled in.
/// Nothing here is a fact about the server that answers - no provider, no account, no configured value -
/// which is why it is the least sensitive document this controller returns.
/// </para>
/// <para>
/// It is nonetheless elevation-gated like its neighbours, because the only caller it exists for is the
/// admin configuration page and an unauthenticated route would be a new anonymous surface bought for
/// nothing.
/// </para>
/// </remarks>
public class MappablePermissionDocument
{
    /// <summary>
    /// Gets the mappable permission names, in ordinal order. Ordered rather than enum-declaration order so
    /// a consumer can render them without sorting and the answer does not move when upstream reorders the
    /// enum.
    /// </summary>
    public IReadOnlyList<string> Permissions { get; init; } = new List<string>();
}
