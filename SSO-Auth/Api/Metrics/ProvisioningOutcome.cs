// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Api.Metrics;

/// <summary>
/// What an SSO login did about the Jellyfin account behind it (#1139). The two are worth telling apart on a
/// dashboard: a rise in <see cref="Created"/> is a deployment growing, and a rise in <see cref="Adopted"/> on
/// a server that expects none is a provider allowed to claim accounts it should not be claiming.
/// </summary>
internal enum ProvisioningOutcome
{
    /// <summary>An existing Jellyfin account was linked to the identity for the first time.</summary>
    Adopted,

    /// <summary>A new Jellyfin account was created for the identity.</summary>
    Created,
}
