// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api.Authz;

/// <summary>
/// Reduces a login's roles to a fixed access duration (#1146), the relative counterpart of the absolute
/// expiry claim read by <c>AccountExpiryInstant</c>. Each configured mapping whose roles the login holds
/// contributes its duration, and the MOST RESTRICTIVE (shortest) wins - never the longest. A login that
/// matches no mapping yields null, so nothing is stamped and the account has no deadline at all.
/// </summary>
/// <remarks>
/// It returns a DURATION rather than an instant on purpose: the deadline is anchored to the moment the
/// account is actually provisioned, which this pure function has no business knowing and which is decided
/// one layer down, inside the same locked transaction that writes the link. Resolving an instant here would
/// anchor it to whenever the protocol layer happened to run instead.
/// <para>
/// The roles are the ones the login already produced - the same values <see cref="PermissionRolePolicy"/>
/// and <see cref="ParentalRatingPolicy"/> are handed - so no second role read is added to either protocol,
/// and a role claim the extractor refused (#216) reaches here as an empty set and maps nothing.
/// </para>
/// </remarks>
internal static class GuestAccessDurationPolicy
{
    /// <summary>
    /// The access duration the login's roles resolve to, or null when no mapping is configured or none
    /// matched (provision with no deadline).
    /// </summary>
    /// <param name="roles">The login's role values.</param>
    /// <param name="config">The provider configuration carrying the mappings.</param>
    /// <returns>The shortest matched duration, or null when nothing applies.</returns>
    internal static TimeSpan? Resolve(IEnumerable<string> roles, ProviderConfigBase config)
    {
        // No mappings configured (the default): this provider grants no time-limited access, so a
        // provisioning login stamps nothing and behaves byte-for-byte as it did before #1146. There is
        // deliberately NO master switch beside the map - an empty map already means off, and a second
        // switch would be a second place for the feature to be silently half-enabled from.
        if (config.GuestAccessDurationRoleMappings is null)
        {
            return null;
        }

        var loginRoles = roles as IReadOnlyCollection<string> ?? new List<string>(roles);

        TimeSpan? shortest = null;
        foreach (var mapping in config.GuestAccessDurationRoleMappings)
        {
            // A null entry, a non-positive duration, or one beyond the guard contributes nothing. All three
            // are rejected at config-save validation; at runtime they are SKIPPED rather than thrown on, so
            // a single bad entry hand-written into the config XML cannot 500 a login - and the out-of-range
            // skip is what keeps DateTime.AddHours below from throwing at the stamp.
            if (mapping is null
                || mapping.DurationHours <= 0
                || mapping.DurationHours > GuestAccessDurationRoleMap.MaxDurationHours
                || !MatchesAnyRole(mapping.Roles, loginRoles))
            {
                continue;
            }

            // Shortest-wins: a login holding both a "trial" and a "guest" role ends up on the stricter of
            // the two rather than having the looser one extend it. Consistent with the parent's rule that
            // expiry disables and never silently extends (#832).
            var candidate = TimeSpan.FromHours(mapping.DurationHours);
            shortest = shortest is { } current && current <= candidate ? current : candidate;
        }

        return shortest;
    }

    // A login holding any of the mapping's roles matches. The configured role is trimmed and compared
    // ordinally to the (verbatim) login roles, null-safe - the same matching every other role policy uses.
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
