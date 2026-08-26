// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// Answers, for every configured provider at once, whether a login against it would get past the
/// configuration (#1084). Restores the aggregate "Configuration check" the redesigned settings page dropped,
/// and does it on the server so the answer is the same one the save path would give.
/// </summary>
/// <remarks>
/// <para>
/// REUSES THE SAVE GATE RATHER THAN RESTATING IT. The invalid-value half of a row is
/// <see cref="ProviderConfigValidator.Validate"/> run over a snapshot holding that one provider, so a rule
/// added to the save path is reported here on the same commit and a rule this file does not know about is
/// still caught. Nothing here re-implements a predicate.
/// </para>
/// <para>
/// One message per provider, because that is all the save gate produces: it refuses on the first invalid
/// rule it meets. A row saying "and three more" would be claiming a completeness the refusal does not have.
/// </para>
/// <para>
/// THE PROFILE SET IS CONFIGURATION-WIDE AND IS REPORTED ON EVERY PROVIDER. The snapshot carries the real
/// <see cref="PluginConfiguration.ProvisioningProfiles"/>, both because a provider naming a profile is only
/// valid if that profile exists, and because a broken profile set refuses every provider's save until it is
/// fixed. Reporting it once per provider is that state stated rather than softened.
/// </para>
/// <para>
/// The empty-required-field half is not the save gate's, because the save gate does not have one: a
/// half-filled provider persists fine and fails at login instead. That is exactly the failure this check
/// exists to surface before a user meets it.
/// </para>
/// </remarks>
internal static class ProviderCheck
{
    /// <summary>
    /// The OpenID settings without which a login cannot start, by property name. Each name is ALSO the id
    /// the settings page gives that field, which is what lets the page resolve a reported name to its own
    /// localized label; <c>ArchitectureConformanceTests</c> pins both halves of that agreement.
    /// </summary>
    internal static readonly string[] OidRequiredFields = { "OidEndpoint", "OidClientId" };

    /// <summary>
    /// The SAML settings without which a login cannot start or its response be verified. The settings page
    /// prefixes each of these ids with <c>saml-</c>; that prefix is the page's, not the property's.
    /// </summary>
    internal static readonly string[] SamlRequiredFields = { "SamlEndpoint", "SamlClientId", "SamlCertificate" };

    /// <summary>
    /// Builds the aggregate report over a configuration snapshot.
    /// </summary>
    /// <param name="config">The configuration to evaluate; never modified.</param>
    /// <returns>One row per configured provider, OpenID first, in configuration order.</returns>
    internal static ProviderCheckDocument Build(PluginConfiguration config)
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

        return new ProviderCheckDocument { Providers = rows };
    }

    // A configuration carrying exactly one provider plus the shared profile set, so the whole-config
    // validator can be asked about that provider alone. It is passed as its own `live` argument on purpose:
    // that makes every provider here an EXISTING one, which is what it is, so the new-name rule stays off a
    // name the identity provider already has registered - the same exemption a real save gets.
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

    // The value of a required setting, read by the name the list above declares. Reflection rather than a
    // switch: the declared names are what the page resolves to labels and what the conformance test compares
    // against the form, so a name nobody reads through would be free to be wrong. A name that resolves to no
    // string property throws here rather than silently reporting the field as filled in - fail closed, and
    // pinned by a test so the throw is never met at runtime.
    private static string? Read(ProviderConfigBase config, string field)
    {
        var property = config.GetType().GetProperty(field, BindingFlags.Public | BindingFlags.Instance)
            ?? throw new InvalidOperationException($"{config.GetType().Name} declares no '{field}' property.");
        return property.PropertyType == typeof(string)
            ? property.GetValue(config) as string
            : throw new InvalidOperationException($"{config.GetType().Name}.{field} is not a string setting.");
    }

    // What the save path would say about this provider, or null where it would say nothing.
    //
    // The message is taken WHOLE and unedited, tail included. ArgumentException.Message appends
    // "(Parameter 'x')" wherever a parameter name was given, which is not pretty in front of an
    // administrator - and the admin write paths already answer a refused save with exactly that string
    // (SSOController's BadRequest(ex.Message) arms). Tidying it here would make the check and the save
    // disagree about one provider in the one respect this report exists to get right, so the tidying, if it
    // is wanted, belongs at the message rather than at one of its two readers.
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
