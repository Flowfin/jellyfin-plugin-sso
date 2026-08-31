// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api.Authz;

/// <summary>
/// Reduces a login's roles to a SyncPlay access level (#827), the enumerated-policy counterpart of the
/// scalar <see cref="ParentalRatingPolicy"/> and the boolean <see cref="PermissionRolePolicy"/>. When
/// <c>EnableSyncPlayAccessRoles</c> is on, each configured mapping whose roles the login holds contributes
/// its level and the MOST RESTRICTIVE one wins - never the loosest. A login that matches no mapping (or the
/// feature being off) yields null, so the mint leaves the account's existing level untouched: an unmapped or
/// malformed claim never widens SyncPlay access.
/// <para>
/// SyncPlay is not a <c>PermissionKind</c>, so <see cref="PermissionRolePolicy"/> cannot express it however
/// it is spelled: it is a three-valued level on the account
/// (<see cref="SyncPlayUserAccessType"/>), which is why it needs a reducer of its own.
/// </para>
/// </summary>
internal static class SyncPlayAccessPolicy
{
    /// <summary>
    /// The SyncPlay access level the login's roles resolve to, or null when the feature is off or no mapping
    /// matched (leave the existing level untouched).
    /// </summary>
    /// <param name="roles">The login's role values.</param>
    /// <param name="config">The provider configuration carrying the mappings.</param>
    /// <returns>The most restrictive matched level, or null when nothing applies.</returns>
    internal static SyncPlayUserAccessType? Resolve(IEnumerable<string> roles, ProviderConfigBase config)
    {
        // Master switch off (the default) or no mappings configured: SSO manages no SyncPlay level, so the
        // mint leaves User.SyncPlayAccess exactly as it was - byte-for-byte the pre-#827 behavior.
        if (!config.EnableSyncPlayAccessRoles || config.SyncPlayAccessRoleMappings is null)
        {
            return null;
        }

        var loginRoles = roles as IReadOnlyCollection<string> ?? new List<string>(roles);

        SyncPlayUserAccessType? resolved = null;
        foreach (var mapping in config.SyncPlayAccessRoleMappings)
        {
            // Fail closed toward the LESS permissive outcome: a null entry, an entry naming no roles and an
            // entry whose level does not parse all contribute nothing (each is rejected at config-save
            // validation; at runtime we skip rather than throw so a single bad entry cannot 500 the login).
            if (mapping is null || !MatchesAnyRole(mapping.Roles, loginRoles) || !TryParseAccess(mapping.Access, out var level))
            {
                continue;
            }

            // Most-restrictive-wins, so a login matching several groups never ends up looser than the
            // strictest group allows - the same direction #736 chose for a ceiling.
            resolved = resolved is { } current && Restrictiveness(current) >= Restrictiveness(level) ? current : level;
        }

        return resolved;
    }

    /// <summary>
    /// Parses a configured SyncPlay level name, refusing anything that is not a DECLARED member of
    /// <see cref="SyncPlayUserAccessType"/>.
    /// </summary>
    /// <param name="access">The configured level name.</param>
    /// <param name="level">The parsed level when the name is a declared member.</param>
    /// <returns>True when the name parsed to a declared member.</returns>
    internal static bool TryParseAccess(string? access, out SyncPlayUserAccessType level)
    {
        // ignoreCase: false matches the SubtitleMode idiom already in the tree - a configured level is an
        // exact enum name, so a lowercase spelling is a mis-set to be reported rather than guessed at.
        // The two checks after it are what MEASUREMENT added rather than reasoning: Enum.TryParse also
        // accepts a bare numeral, and the two arms of that fail differently. "57" parses to an undeclared
        // (SyncPlayUserAccessType)57 - IsDefined refuses it. "1" parses to a declared member and IsDefined
        // waves it through, so the name round-trip is what refuses it: a numeral pins the configuration to
        // the ORDER upstream happens to declare the enum in, and a reorder there would silently change what
        // an administrator's stored level means. A level is a NAME here, and it is one because a run said
        // IsDefined alone was not enough.
        return Enum.TryParse(access, ignoreCase: false, out level)
            && Enum.IsDefined(level)
            && string.Equals(level.ToString(), access, StringComparison.Ordinal);
    }

    // How restrictive a level is, LARGER being stricter. Declared here rather than read off the enum's
    // numeric values on purpose: SyncPlayUserAccessType runs the other way round (CreateAndJoinGroups = 0 is
    // the LOOSEST and None = 2 the strictest), so the Math.Min shape ParentalRatingPolicy uses for a score
    // would silently resolve a multi-role login to the WIDEST access its groups allow. An unranked value
    // cannot reach here - Resolve admits only declared members - and the default arm is the fail-closed one
    // anyway, so a member added upstream is treated as maximally restrictive until it is ranked by hand.
    private static int Restrictiveness(SyncPlayUserAccessType level) => level switch
    {
        SyncPlayUserAccessType.CreateAndJoinGroups => 0,
        SyncPlayUserAccessType.JoinGroups => 1,
        SyncPlayUserAccessType.None => 2,
        _ => int.MaxValue,
    };

    // A login holding any of the mapping's roles matches. The configured role is trimmed and compared
    // ordinally to the (verbatim) login roles, null-safe - the same matching the sibling policies use.
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
