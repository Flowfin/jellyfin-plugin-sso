// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api.Authz;

/// <summary>Maps the roles of a verified login to the generic Jellyfin permission grants they produce under the provider configuration (#164), the boolean <see cref="PermissionKind"/> surface beyond <see cref="RolePrivilegeMapper"/>.</summary>
/// <remarks>
/// The mapping is default-deny and authoritative: for every listed permission the grant is true when the login
/// carries a matching role and false otherwise, and an unlisted permission is never emitted, so Jellyfin's own
/// default governs it. The four permissions with dedicated flows are refused (<see cref="DedicatedPermissions"/>)
/// so each has one authoritative source, and <see cref="PermissionKind.IsDisabled"/> is refused because no SSO
/// role mapping may ever disable an account (#165); save-time validation refuses them and login grants nothing.
/// </remarks>
internal static class PermissionRolePolicy
{
    // The permissions the generic map may never set. The first four already have a dedicated configuration
    // surface - mapping them here would create a second, conflicting authoritative source. IsDisabled is
    // excluded for a stronger reason (#165, Finding H1): no SSO role mapping may ever disable an account, or
    // an admin could map a role to IsDisabled and a single SSO login would lock the account (including the
    // break-glass admin) out - a whole-org lockout / recovery-defeat vector. Excluding it here makes it
    // rejected fail-closed at config-save and a no-op grant at runtime, so IsDisabled is never in the mint's
    // grant list.
    private static readonly HashSet<PermissionKind> DedicatedPermissions = new()
    {
        PermissionKind.IsAdministrator,
        PermissionKind.EnableAllFolders,
        PermissionKind.EnableLiveTvAccess,
        PermissionKind.EnableLiveTvManagement,
        PermissionKind.IsDisabled,
    };

    /// <summary>
    /// The validity of a configured permission name.
    /// </summary>
    internal enum PermissionNameStatus
    {
        /// <summary>A known, mappable permission.</summary>
        Valid,

        /// <summary>The name is null, empty, or whitespace.</summary>
        Empty,

        /// <summary>The name does not name any <see cref="PermissionKind"/> (or is mis-cased / numeric).</summary>
        Unknown,

        /// <summary>The name is a dedicated permission managed by its own configuration field/flow.</summary>
        Dedicated,
    }

    /// <summary>Evaluates the generic permission grants the given roles produce under the given configuration.</summary>
    /// <param name="roles">The roles extracted from the verified login (OpenID claims or SAML attributes).</param>
    /// <param name="config">The provider configuration.</param>
    /// <returns>One grant per configured, resolvable permission in first-appearance order, each emitted at most once with repeated entries OR-ed; empty when the master switch is off or nothing is configured.</returns>
    internal static IReadOnlyList<PermissionGrant> Map(IEnumerable<string> roles, ProviderConfigBase config)
    {
        // Master switch off (the default) or no mappings configured: SSO manages no extra permissions, so
        // the mint touches none of them - byte-for-byte the pre-#164 behavior.
        if (!config.EnablePermissionRoles || config.PermissionRoleMappings is null)
        {
            return Array.Empty<PermissionGrant>();
        }

        var loginRoles = roles as IReadOnlyCollection<string> ?? roles.ToList();

        // Accumulate OR-ing duplicates while preserving first-appearance order, so the result is
        // deterministic and never applies the same permission twice with conflicting values.
        var granted = new Dictionary<PermissionKind, bool>();
        var order = new List<PermissionKind>();
        foreach (var mapping in config.PermissionRoleMappings)
        {
            // Fail closed: a null entry, a blank/unknown name, or a dedicated permission grants nothing.
            // These are rejected at config-save validation; at runtime we still skip rather than throw so a
            // single bad entry cannot 500 the whole login path.
            if (mapping is null || !TryResolvePermission(mapping.Permission, out var kind))
            {
                continue;
            }

            var matches = MatchesAnyRole(mapping.Roles, loginRoles);
            if (granted.TryGetValue(kind, out var existing))
            {
                granted[kind] = existing || matches;
            }
            else
            {
                granted[kind] = matches;
                order.Add(kind);
            }
        }

        var result = new List<PermissionGrant>(order.Count);
        foreach (var kind in order)
        {
            result.Add(new PermissionGrant(kind, granted[kind]));
        }

        return result;
    }

    /// <summary>
    /// Classifies a configured permission name for fail-closed validation.
    /// </summary>
    /// <param name="permissionName">The configured permission name.</param>
    /// <returns>Whether the name is valid, and if not, why.</returns>
    internal static PermissionNameStatus Classify(string? permissionName)
    {
        if (string.IsNullOrWhiteSpace(permissionName))
        {
            return PermissionNameStatus.Empty;
        }

        var trimmed = permissionName.Trim();

        // Ordinal, case-sensitive, name-exact parse: Enum.TryParse alone would also accept a numeric string
        // ("11") or a mis-cased name, so require the parsed value's canonical name to equal the input. That
        // makes an unknown, numeric, or mis-cased name fail closed (grants nothing) and the mapping
        // deterministic.
        if (!Enum.TryParse(trimmed, out PermissionKind parsed)
            || !string.Equals(Enum.GetName(parsed), trimmed, StringComparison.Ordinal))
        {
            return PermissionNameStatus.Unknown;
        }

        return DedicatedPermissions.Contains(parsed)
            ? PermissionNameStatus.Dedicated
            : PermissionNameStatus.Valid;
    }

    /// <summary>The permission names an administrator may put in a mapping or a provisioning template (#1484): every declared <see cref="PermissionKind"/> that <see cref="Classify"/> answers <see cref="PermissionNameStatus.Valid"/> for, in ordinal order.</summary>
    /// <remarks>Derived through <see cref="Classify"/> rather than listed, so the vocabulary offered cannot disagree with the save-time refusal when upstream adds or removes a member.</remarks>
    /// <returns>The mappable permission names.</returns>
    internal static IReadOnlyList<string> MappablePermissionNames() =>
        Enum.GetNames<PermissionKind>()
            .Where(name => Classify(name) == PermissionNameStatus.Valid)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

    /// <summary>
    /// Resolves a configured permission name to its <see cref="PermissionKind"/> when it is valid and
    /// mappable, failing closed (returns false, grants nothing) for a blank, unknown, or dedicated name.
    /// </summary>
    /// <param name="permissionName">The configured permission name.</param>
    /// <param name="kind">The resolved permission when valid; otherwise the enum default.</param>
    /// <returns>Whether the name resolved to a mappable permission.</returns>
    internal static bool TryResolvePermission(string? permissionName, out PermissionKind kind)
    {
        if (Classify(permissionName) == PermissionNameStatus.Valid
            && Enum.TryParse(permissionName!.Trim(), out PermissionKind parsed))
        {
            kind = parsed;
            return true;
        }

        kind = default;
        return false;
    }

    // Whether the login carries any of the configured roles. The configured (trusted, admin-authored) role
    // is trimmed before comparison; the IdP-supplied role is compared raw and ordinal, so there is no
    // whitespace-injection vector - mirroring the folder-role comparison hardening (#367). Null-safe both
    // ways: a null role array or a null entry is simply not a match, never a NullReferenceException, so an
    // admin misconfiguration fails closed (grants nothing) instead of throwing.
    private static bool MatchesAnyRole(string[]? configuredRoles, IReadOnlyCollection<string> loginRoles)
    {
        if (configuredRoles is null)
        {
            return false;
        }

        foreach (var configured in configuredRoles)
        {
            if (configured is null)
            {
                continue;
            }

            var trimmed = configured.Trim();

            // A configured entry that trims to empty grants nothing (#935): a blank IdP role (a terminal
            // array element "" or, since #934, an object-map property named "") must never satisfy a
            // mapping - the same blank-skip RolePrivilegeMapper.IsOnList and ParentalRatingPolicy apply.
            if (trimmed.Length == 0)
            {
                continue;
            }

            foreach (var role in loginRoles)
            {
                if (string.Equals(role, trimmed, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }
}
