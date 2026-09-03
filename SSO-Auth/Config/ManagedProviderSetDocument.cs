// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// What the admin surface is told about declarative management (#1102): which providers a mounted document
/// or the environment decided on this boot, so the config page can show that they are managed rather than
/// letting an admin type into a form the next start will win back (#1104).
/// </summary>
/// <remarks>
/// <para>
/// NAMES ONLY. The document carries no field value, no secret and no reference, because everything it would
/// have to name to carry one is already available - and already redacted - through
/// <c>GET /sso/Config/Export</c>. There is nothing here an administrator could not read anyway, and nothing
/// that becomes sensitive if the report is logged or pasted into an issue.
/// </para>
/// <para>
/// The unit is the provider rather than the field, for the reason set out on
/// <see cref="DeclarativeManagedProviders"/>: the merge replaces a named provider whole, so every one of its
/// fields is decided by the source. A consumer renders the whole provider as managed; there is no honest
/// subset to render.
/// </para>
/// <para>
/// Both lists are empty when no declarative source is configured, which is the answer an installation built
/// before those sources existed gets, and it is a report rather than an error.
/// </para>
/// </remarks>
public class ManagedProviderSetDocument
{
    /// <summary>
    /// Gets the OpenID providers a declarative source decided, keyed as they are in
    /// <see cref="PluginConfiguration.OidConfigs"/> so a consumer can match them without a second lookup.
    /// </summary>
    public IReadOnlyList<string> OidConfigs { get; init; } = new List<string>();

    /// <summary>
    /// Gets the SAML providers a declarative source decided, keyed as they are in
    /// <see cref="PluginConfiguration.SamlConfigs"/>.
    /// </summary>
    public IReadOnlyList<string> SamlConfigs { get; init; } = new List<string>();

    /// <summary>
    /// Gets the provisioning profiles a declarative source defined (#1498), keyed as they are in
    /// <see cref="PluginConfiguration.ProvisioningProfiles"/>. A managed profile is frozen the way a managed
    /// provider is - the save keeps the stored value and records the ignored write - so the profile editor
    /// has to be told, or an administrator edits a policy the server will not take.
    /// </summary>
    public IReadOnlyList<string> ProvisioningProfiles { get; init; } = new List<string>();
}
