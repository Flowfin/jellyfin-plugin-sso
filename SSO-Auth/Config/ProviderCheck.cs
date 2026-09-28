// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>Answers, for every configured provider at once, whether a login against it would get past the configuration (#1084).</summary>
/// <remarks>
/// The invalid-value half of a row is the save gate run over a snapshot holding that one provider, so a rule added
/// there is reported here; the empty-field half is this check's own, because a half-filled provider saves fine. See
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#configuration-check-admin"/>.
/// </remarks>
internal static class ProviderCheck
{
    /// <summary>The OpenID settings without which a login cannot start, by property name, which is also the settings page's field id.</summary>
    internal static readonly string[] OidRequiredFields = { "OidEndpoint", "OidClientId" };

    /// <summary>The SAML settings without which a login cannot start or its response be verified; the page prefixes each id with <c>saml-</c>.</summary>
    internal static readonly string[] SamlRequiredFields = { "SamlEndpoint", "SamlClientId", "SamlCertificate" };

    /// <summary>Builds the aggregate report over a configuration snapshot.</summary>
    /// <param name="config">The configuration to evaluate; never modified.</param>
    /// <param name="configurationUnreadable">Whether the stored configuration could not be read at start, so these rows describe a default one (#1543).</param>
    /// <returns>One row per configured provider, OpenID first, in configuration order.</returns>
    internal static ProviderCheckDocument Build(PluginConfiguration config, bool configurationUnreadable)
    {
        ArgumentNullException.ThrowIfNull(config);

        var rows = new List<ProviderCheckResult>();

        foreach (var kvp in config.OidConfigs ?? new SerializableDictionary<string, OidConfig>())
        {
            rows.Add(Row("OpenID", kvp.Key, kvp.Value, OidRequiredFields, Snapshot(config, oid: kvp)));
        }

        foreach (var kvp in config.SamlConfigs ?? new SerializableDictionary<string, SamlConfig>())
        {
            rows.Add(Row("SAML", kvp.Key, kvp.Value, SamlRequiredFields, Snapshot(config, saml: kvp)));
        }

        return new ProviderCheckDocument { Providers = rows, ConfigurationUnreadable = configurationUnreadable };
    }

    // One provider plus the shared profile set, passed as its own live argument so the new-name rule stays off an existing name.
    private static PluginConfiguration Snapshot(
        PluginConfiguration config,
        KeyValuePair<string, OidConfig>? oid = null,
        KeyValuePair<string, SamlConfig>? saml = null)
    {
        var snapshot = new PluginConfiguration { ProvisioningProfiles = config.ProvisioningProfiles };
        if (oid is { } o)
        {
            snapshot.OidConfigs[o.Key] = o.Value;
        }

        if (saml is { } s)
        {
            snapshot.SamlConfigs[s.Key] = s.Value;
        }

        return snapshot;
    }

    private static ProviderCheckResult Row(
        string protocol,
        string provider,
        ProviderConfigBase? config,
        string[] requiredFields,
        PluginConfiguration snapshot)
    {
        var missing = config is null
            ? requiredFields.ToList()
            : requiredFields.Where(field => string.IsNullOrWhiteSpace(Read(config, field))).ToList();
        var problem = Refusal(snapshot);

        return new ProviderCheckResult
        {
            Protocol = protocol,
            Provider = provider,
            Enabled = config?.Enabled == true,
            MissingFields = missing,
            Problem = problem,
            Ready = missing.Count == 0 && problem is null,
        };
    }

    // Reflection, so the declared names the page resolves to labels are the names read; an unknown name throws rather than reads as filled.
    private static string? Read(ProviderConfigBase config, string field)
    {
        var property = config.GetType().GetProperty(field, BindingFlags.Public | BindingFlags.Instance)
            ?? throw new InvalidOperationException($"{config.GetType().Name} declares no '{field}' property.");
        return property.PropertyType == typeof(string)
            ? property.GetValue(config) as string
            : throw new InvalidOperationException($"{config.GetType().Name}.{field} is not a string setting.");
    }

    // The save path's message, taken whole, so the check and the save cannot disagree about one provider.
    private static string? Refusal(PluginConfiguration snapshot)
    {
        try
        {
            ProviderConfigValidator.Validate(snapshot, snapshot);
            return null;
        }
        catch (ArgumentException ex)
        {
            return ex.Message;
        }
    }
}
