// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Session;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>Why a break-glass admin does or does not satisfy the survivor guard; a code for the audit trail, never a username.</summary>
internal enum SsoOnlyGuardVerdict
{
    /// <summary>The designated account is an enabled administrator with a working password login - activation is safe.</summary>
    Allow,

    /// <summary>No break-glass admin was designated (blank username).</summary>
    NoBreakGlassDesignated,

    /// <summary>The designated username resolves to no account.</summary>
    BreakGlassNotFound,

    /// <summary>The designated account is not an administrator (the exemption cannot grant admin).</summary>
    BreakGlassNotAdministrator,

    /// <summary>The designated administrator is disabled, so it cannot log in.</summary>
    BreakGlassDisabled,

    /// <summary>The designated administrator has no usable password login path, a password this plugin minted included (#1746).</summary>
    BreakGlassNoPasswordLogin,
}

/// <summary>The resolved login state of a candidate break-glass administrator, snapshotted so the guard stays pure.</summary>
/// <param name="Exists">Whether an account with the designated username exists at all.</param>
/// <param name="IsAdministrator">Whether that account is an administrator; the exemption spares an existing admin and never grants admin.</param>
/// <param name="IsEnabled">Whether the account is enabled.</param>
/// <param name="HasUsablePasswordLogin">Whether the account routes to the password provider and holds a password somebody was shown (#1746).</param>
internal readonly record struct BreakGlassAdminState(bool Exists, bool IsAdministrator, bool IsEnabled, bool HasUsablePasswordLogin);

/// <summary>The fail-closed activation interlock for SSO-only login: <c>DisablePasswordLogin</c> turns on only with a provable break-glass administrator (#165).</summary>
/// <remarks>Pure: the caller resolves the account into a <see cref="BreakGlassAdminState"/>. See <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/SSO-Only-Login-Design"/>.</remarks>
internal static class SsoOnlyLoginGuard
{
    /// <summary>The single non-enumerating refusal message every rejected activation surfaces; it names the fix without naming any account.</summary>
    /// <remarks>The minted-password remedy is named because an account this plugin provisioned looks to an operator as though it has a password (#1746).</remarks>
    internal const string PublicRefusalMessage =
        "Cannot enable SSO-only login: no administrator would keep a working password login path. Designate an existing, enabled administrator account that still has a password as the break-glass admin first - and note that a password this server generated for an account is not one anybody can sign in with, so an account this plugin created needs a password set on it from the Jellyfin dashboard before it can serve as the break-glass administrator.";

    /// <summary>Classifies whether the resolved break-glass admin satisfies the survivor guard; every missing condition is its own refusal.</summary>
    /// <remarks>An SSO link is not accepted as the survivor, because its usability depends on the identity provider being up.</remarks>
    /// <param name="breakGlassUsername">The designated break-glass admin username (may be blank).</param>
    /// <param name="breakGlass">The resolved login state of that account.</param>
    /// <returns>The guard verdict.</returns>
    internal static SsoOnlyGuardVerdict Evaluate(string? breakGlassUsername, BreakGlassAdminState breakGlass)
    {
        if (string.IsNullOrWhiteSpace(breakGlassUsername))
        {
            return SsoOnlyGuardVerdict.NoBreakGlassDesignated;
        }

        if (!breakGlass.Exists)
        {
            return SsoOnlyGuardVerdict.BreakGlassNotFound;
        }

        if (!breakGlass.IsAdministrator)
        {
            return SsoOnlyGuardVerdict.BreakGlassNotAdministrator;
        }

        if (!breakGlass.IsEnabled)
        {
            return SsoOnlyGuardVerdict.BreakGlassDisabled;
        }

        if (!breakGlass.HasUsablePasswordLogin)
        {
            return SsoOnlyGuardVerdict.BreakGlassNoPasswordLogin;
        }

        return SsoOnlyGuardVerdict.Allow;
    }

    /// <summary>Throws a non-enumerating <see cref="ArgumentException"/> when the break-glass admin does not satisfy the guard, before anything is persisted.</summary>
    /// <param name="breakGlassUsername">The designated break-glass admin username.</param>
    /// <param name="breakGlass">The resolved login state of that account.</param>
    /// <exception cref="ArgumentException">The activation would strand the last admin.</exception>
    internal static void AssertCanActivate(string breakGlassUsername, BreakGlassAdminState breakGlass)
    {
        if (Evaluate(breakGlassUsername, breakGlass) != SsoOnlyGuardVerdict.Allow)
        {
            throw new ArgumentException(PublicRefusalMessage, nameof(breakGlassUsername));
        }
    }

    /// <summary>Whether SSO-only enforcement applies to the account: the mode is on and the account is not the break-glass admin.</summary>
    /// <remarks>The one predicate the sweep, the login path and the disable side share, so the exemption is defined once.</remarks>
    /// <param name="configuration">The live plugin configuration.</param>
    /// <param name="username">The account username under consideration.</param>
    /// <returns>True when the account must be kept off the password provider.</returns>
    internal static bool IsEnforcedNonExempt(PluginConfiguration configuration, string username)
        => configuration is { DisablePasswordLogin: true }
           && !IsBreakGlass(configuration, username);

    /// <summary>Decides the authentication provider id an SSO login writes for the account (#165, #690).</summary>
    /// <remarks>
    /// With the mode on, the break-glass admin is pinned to the password provider and only an account still on that
    /// provider is moved, matching the sweep, so no account is repointed without being tracked.
    /// </remarks>
    /// <param name="configuration">The live plugin configuration.</param>
    /// <param name="username">The account username completing the SSO login.</param>
    /// <param name="currentProviderId">The account's current <c>AuthenticationProviderId</c>.</param>
    /// <param name="configuredDefaultProvider">The provider config's own <c>DefaultProvider</c>, applied only while the mode is off.</param>
    /// <returns>The provider id to write, or the configured default when the mode is off.</returns>
    internal static string? ResolveLoginProvider(PluginConfiguration configuration, string username, string currentProviderId, string? configuredDefaultProvider)
    {
        if (configuration is not { DisablePasswordLogin: true })
        {
            return configuredDefaultProvider;
        }

        if (IsBreakGlass(configuration, username))
        {
            return SsoAuthenticationProviders.DefaultPasswordProviderId;
        }

        // The same test the enable sweep gates its repoint on, so the two can never disagree (#690).
        return SsoAuthenticationProviders.IsDefaultPasswordProvider(currentProviderId)
            ? SsoAuthenticationProviders.SsoProviderId
            : currentProviderId;
    }

    /// <summary>Whether the username is the designated break-glass admin, compared case-insensitively like Jellyfin's account names.</summary>
    /// <param name="configuration">The live plugin configuration.</param>
    /// <param name="username">The account username under consideration.</param>
    /// <returns>True when the account is the exempt break-glass admin.</returns>
    internal static bool IsBreakGlass(PluginConfiguration configuration, string username)
        => !string.IsNullOrWhiteSpace(configuration?.BreakGlassAdminUsername)
           && string.Equals(configuration!.BreakGlassAdminUsername, username, StringComparison.OrdinalIgnoreCase);
}
