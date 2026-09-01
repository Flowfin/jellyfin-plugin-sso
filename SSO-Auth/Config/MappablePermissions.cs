// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Jellyfin.Plugin.SSO_Auth.Api.Authz;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// Builds the published vocabulary of permission names an administrator may map (#1484), so a page offering
/// them reads ONE producer instead of keeping a second copy of the set.
/// </summary>
/// <remarks>
/// <para>
/// REUSES THE SAVE-TIME CLASSIFICATION RATHER THAN RESTATING IT, the way
/// <see cref="ProviderCheck"/> reuses the save gate. The names come from
/// <see cref="PermissionRolePolicy.MappablePermissionNames"/>, which is the classification
/// <see cref="ProviderConfigValidator.ValidatePermissionRoleMappings"/> refuses by, so the vocabulary and the
/// refusal cannot disagree - a name this publishes is a name the save accepts, on the same commit, without
/// anybody keeping the two in step.
/// </para>
/// <para>
/// A copy of the list on the page would drift in three directions and each is silent: a permission Jellyfin
/// adds is mappable on the server and invisible on the page, one Jellyfin removes stays offerable and is
/// refused at save - which is the failure a picker exists to prevent, moved rather than removed - and a name
/// added to the dedicated set keeps being offered until somebody remembers the second list.
/// </para>
/// <para>
/// It takes no configuration, because the set is a fact about the two compiled vocabularies and not about
/// this server.
/// </para>
/// </remarks>
internal static class MappablePermissions
{
    /// <summary>
    /// Builds the published vocabulary.
    /// </summary>
    /// <returns>The mappable permission names, in ordinal order.</returns>
    internal static MappablePermissionDocument Build() =>
        new MappablePermissionDocument { Permissions = PermissionRolePolicy.MappablePermissionNames() };
}
