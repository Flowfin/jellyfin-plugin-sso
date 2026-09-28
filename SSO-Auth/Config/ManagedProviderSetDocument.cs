// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>What the settings page is told about declarative management: the providers and profiles a source decided on this boot (#1102, #1104).</summary>
/// <remarks>Names only, and the unit is the provider, as on <see cref="DeclarativeManagedProviders"/>. See <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Config-as-code#what-the-settings-page-shows"/>.</remarks>
public class ManagedProviderSetDocument
{
    /// <summary>Gets the OpenID providers a declarative source decided, keyed as in <see cref="PluginConfiguration.OidConfigs"/>.</summary>
    public IReadOnlyList<string> OidConfigs { get; init; } = new List<string>();

    /// <summary>Gets the SAML providers a declarative source decided, keyed as in <see cref="PluginConfiguration.SamlConfigs"/>.</summary>
    public IReadOnlyList<string> SamlConfigs { get; init; } = new List<string>();

    /// <summary>Gets the provisioning profiles a declarative source defined, keyed as in <see cref="PluginConfiguration.ProvisioningProfiles"/> (#1498).</summary>
    public IReadOnlyList<string> ProvisioningProfiles { get; init; } = new List<string>();
}
