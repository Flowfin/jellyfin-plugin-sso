// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;

namespace Jellyfin.Plugin.SSO_Auth.Api.Session;

/// <summary>The two provider ids the SSO-only login feature moves accounts between, named once so the sweep, the guard and the login path agree (#165).</summary>
/// <remarks>
/// A provider id that resolves to no registered provider makes Jellyfin reject every password for that account. See
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/SSO-Only-Login-Design"/>.
/// </remarks>
internal static class SsoAuthenticationProviders
{
    /// <summary>Jellyfin's built-in password provider; restoring it is the reversible off-switch and never touches a password hash.</summary>
    internal const string DefaultPasswordProviderId = "Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider";

    /// <summary>Gets the provider id that disables password login: the pinned literal the link service stamps on created accounts, so a type move never orphans them (#837).</summary>
    internal static string SsoProviderId => SsoManagedProviderId.Value;

    /// <summary>Whether the given provider id is the plugin's SSO (password-disabling) provider.</summary>
    /// <param name="authenticationProviderId">The account's <c>AuthenticationProviderId</c>.</param>
    /// <returns>True when the id routes to no password provider (SSO-only for that account).</returns>
    internal static bool IsSsoProvider(string authenticationProviderId)
        => string.Equals(authenticationProviderId, SsoProviderId, StringComparison.Ordinal);

    /// <summary>Whether the given provider id is Jellyfin's built-in password provider.</summary>
    /// <param name="authenticationProviderId">The account's <c>AuthenticationProviderId</c>.</param>
    /// <returns>True when native password login is routed through core's default provider.</returns>
    internal static bool IsDefaultPasswordProvider(string authenticationProviderId)
        => string.Equals(authenticationProviderId, DefaultPasswordProviderId, StringComparison.Ordinal);
}
