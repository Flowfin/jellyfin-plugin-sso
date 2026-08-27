// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api.Authz;

/// <summary>
/// Reduces a login's roles to the NAME of the provisioning profile (#1105) its brand-new account is created
/// from (#1106). The configured rows are ordered and the FIRST one whose roles the login holds wins; a login
/// matching no row resolves null, which leaves the provider's own default resolution (#1105) exactly as it
/// was.
/// </summary>
/// <remarks>
/// First-row-wins rather than any reduction over the matches, because the alternatives all need a comparison
/// this map has no basis for. Two profiles are two permission sets, not two points on a scale, so there is no
/// "most restrictive" to pick the way <see cref="GuestAccessDurationPolicy"/> picks the shortest duration.
/// The administrator states the precedence by ordering the rows, and the order they wrote is the order that
/// runs.
/// <para>
/// It returns a NAME rather than a template because the profile set lives on the plugin configuration while
/// this sees only the provider, and because the name has to be resolved inside the same locked read that
/// resolves the provider - otherwise a concurrent save could be observed half-applied. Turning the name into
/// a policy is <see cref="ProvisioningPolicy.TemplateFor(PluginConfiguration, ProviderConfigBase, string)"/>'s
/// job, one layer down, and a name that resolves to nothing writes NO policy there rather than falling back.
/// </para>
/// <para>
/// The roles are the ones the login already produced - the same values <see cref="PermissionRolePolicy"/>,
/// <see cref="ParentalRatingPolicy"/> and <see cref="GuestAccessDurationPolicy"/> are handed - so no second
/// role read is added to either protocol, and a role claim the extractor refused (#216) reaches here as an
/// empty set and selects nothing.
/// </para>
/// </remarks>
internal static class ProvisioningProfilePolicy
{
    /// <summary>
    /// The provisioning-profile name the login's roles select, or null when the provider configures no rows
    /// or none of them matched (fall through to the provider's own default resolution).
    /// </summary>
    /// <param name="roles">The login's role values.</param>
    /// <param name="config">The provider configuration carrying the rows.</param>
    /// <returns>The first matched row's profile name, or null when nothing applies.</returns>
    internal static string? Resolve(IEnumerable<string> roles, ProviderConfigBase config)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(roles);

        // No rows configured (the default): this provider selects no profile by role, so a provisioning
        // login resolves its policy exactly as it did before #1106. There is deliberately NO master switch
        // beside the map - an empty map already means off, and a second switch would be a second place for
        // the feature to be silently half-enabled from. The same reasoning #1146 wrote down.
        if (config.ProvisioningProfileRoleMappings is null)
        {
            return null;
        }

        var loginRoles = roles as IReadOnlyCollection<string> ?? new List<string>(roles);

        foreach (var mapping in config.ProvisioningProfileRoleMappings)
        {
            // A null row, or one naming no profile, selects nothing and is SKIPPED rather than thrown on:
            // both are refused at config-save validation, so what is left is a configuration file edited by
            // hand around the validator, and there a single bad row must not 500 a login. Skipping is also
            // the fail-closed direction here - the row grants nothing and the walk continues to the next.
            if (mapping is null
                || string.IsNullOrWhiteSpace(mapping.Profile)
                || !MatchesAnyRole(mapping.Roles, loginRoles))
            {
                continue;
            }

            // First match wins, so the walk stops here. A login holding both a "staff" and a "guest" role
            // gets whichever the administrator listed first, and re-ordering the rows is the whole of how
            // that precedence is changed.
            return mapping.Profile.Trim();
        }

        return null;
    }

    // A login holding any of the row's roles matches. The configured role is trimmed and compared ordinally
    // to the (verbatim) login roles, null-safe - the same matching every other role policy uses.
    private static bool MatchesAnyRole(string[]? mappingRoles, IReadOnlyCollection<string> loginRoles)
    {
        if (mappingRoles is null)
        {
            return false;
        }

        foreach (var role in mappingRoles)
        {
            var trimmed = role?.Trim();
            if (string.IsNullOrEmpty(trimmed))
            {
                continue;
            }

            foreach (var loginRole in loginRoles)
            {
                if (string.Equals(loginRole, trimmed, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }
}
