// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Api.Linking;

/// <summary>
/// The single <c>User.AuthenticationProviderId</c> value the plugin stamps on the accounts it manages
/// (#133) and that the SSO-only feature (#165) uses to detect them. It is a Jellyfin identifier that
/// resolves to no registered <c>IAuthenticationProvider</c>, so core substitutes its
/// <c>InvalidAuthenticationProvider</c> and every password attempt on such an account is rejected.
/// </summary>
internal static class SsoManagedProviderId
{
    /// <summary>Gets the pinned provider-id string written to <c>User.AuthenticationProviderId</c> and persisted in Jellyfin's user database.</summary>
    /// <remarks>It must never change, because every account provisioned by an earlier version carries it and both the stamp and the SSO-only detector compare against it; a fixed literal rather than <c>typeof(SSOController).FullName</c>, so a move of that type (#807) cannot stop recognising existing accounts. A conformance test pins it.</remarks>
    internal const string Value = "Jellyfin.Plugin.SSO_Auth.Api.SSOController";
}
