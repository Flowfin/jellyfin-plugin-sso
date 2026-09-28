// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>The permission names an administrator may map, so the settings page reads one producer instead of keeping a copy (#1484).</summary>
/// <remarks>Names only and the same on every installation, so it is the least sensitive document the controller returns.</remarks>
public class MappablePermissionDocument
{
    /// <summary>Gets the mappable permission names, in ordinal order so the answer does not move when upstream reorders the enum.</summary>
    public IReadOnlyList<string> Permissions { get; init; } = new List<string>();
}
