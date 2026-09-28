// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Jellyfin.Plugin.SSO_Auth.Api.Authz;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>Builds the published vocabulary of permission names an administrator may map (#1484).</summary>
/// <remarks>The names come from the classification the save refuses by, so the vocabulary and the refusal cannot disagree.</remarks>
internal static class MappablePermissions
{
    /// <summary>Builds the published vocabulary.</summary>
    /// <returns>The mappable permission names, in ordinal order.</returns>
    internal static MappablePermissionDocument Build() =>
        new MappablePermissionDocument { Permissions = PermissionRolePolicy.MappablePermissionNames() };
}
