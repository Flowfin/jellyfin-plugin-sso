// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// The environment half of the declarative provider configuration (#1097): the same document
/// <see cref="DeclarativeProviderConfig"/> reads from a mounted file, expressed as environment variables
/// and applied through the same <see cref="DeclarativeProviderConfig.ApplyDocument"/>. It ships alone - a
/// deployment that sets variables and mounts no file is fully configured, and one that sets none is
/// byte-identical to an installation built before this existed.
/// </summary>
/// <remarks>
/// <para>
/// A variable names a path into the document, with <c>__</c> between the steps, which is the hierarchy
/// separator ASP.NET Core's own environment configuration provider uses and the one an operator writing a
/// compose file or a Kubernetes manifest already knows:
/// </para>
/// <code>
/// JELLYFIN_SSO_CONFIG__OidConfigs__keycloak__OidClientId=jellyfin
/// JELLYFIN_SSO_CONFIG__OidConfigs__keycloak__Roles__0=media
/// JELLYFIN_SSO_CONFIG__EnableRateLimit=true
/// </code>
/// <para>
/// The steps are resolved against the configuration model itself rather than against a hand-written table
/// of field names, so a field cannot be silently unconfigurable: a property added to
/// <see cref="OidConfig"/> or <see cref="SamlConfig"/> is addressable the day it is added, under its own
/// name, without an edit here. A step names a property (matched without regard to case, like the file
/// source), a dictionary key (taken verbatim, so a provider may be called anything), or a list index (from
/// zero). That the whole settable provider surface really is reachable is not a claim made here - it is
/// derived by walking the model in
/// <c>EveryProviderFieldTheModelCarries_IsReachableFromTheEnvironment</c>.
/// </para>
/// <para>
/// The surface is the two provider maps and nothing else, which is exactly what a declarative apply reaches:
/// <see cref="ConfigImport"/> deliberately leaves the rate-limit tuning and the SSO-only globals to the
/// settings page. A variable naming one of those is REFUSED rather than accepted and dropped, so the
/// environment never looks applied where it changed nothing.
/// </para>
/// <para>
/// A PROVIDER IS DECLARED WHOLE, exactly as it is in the mounted file, because the apply merges by provider
/// and not by field. Naming one field of a provider that already exists therefore leaves its other fields at
/// their defaults rather than at what was there before - and on an OpenID provider a blanked endpoint or
/// client id is a repoint, which clears that provider's account links and stored secret through the belt
/// <see cref="ServerManagedFields"/> already carries (#186). Declare every field of a provider the
/// environment owns. What is left alone is a provider the environment does not name at all.
/// </para>
/// <para>
/// THE WHOLE SOURCE IS REFUSED AS A UNIT, and an unrecognised variable under the prefix is a refusal rather
/// than something skipped. A typo is the ordinary failure here - the names are long and nothing completes
/// them - and a skipped variable leaves a provider carrying half of what the deployment asked for, which is
/// worse than one that does not start at all. So a step that names no property, a property withheld from
/// this boundary, an index that leaves a hole in a list, and a value that is not of the field's type each
/// reject everything and leave the stored configuration untouched.
/// </para>
/// <para>
/// A property the JSON boundary withholds (<c>[JsonIgnore]</c>: the canonical link maps, the issuer
/// bindings, the SSO-only bookkeeping) is refused by name instead of being accepted and dropped. Those are
/// server-managed and are re-injected by <see cref="ServerManagedFields"/> on every write path, so a
/// variable aimed at one would otherwise be accepted, written into the document, and silently discarded by
/// the deserializer - the exact shape of a configuration that looks applied and is not.
/// </para>
/// <para>
/// A secret IS spelled out here, unlike in the mounted file. #1096 refuses a value in the file and takes a
/// reference instead, because the file is an artefact a deployment keeps beside its other tracked
/// configuration, and one of the two reference forms that rule points at is an environment variable. This
/// IS that environment variable, so requiring a reference from a variable to another variable would buy
/// nothing.
/// </para>
/// <para>
/// PRECEDENCE: the environment is applied after the mounted file, so where both name the same field the
/// environment wins, and both win over what is stored. It is a merge on the same terms the file source
/// already carries - a provider neither source names is left exactly as it is - because both go through one
/// <see cref="ConfigImport"/>. The two are applied separately rather than merged into one document, so a
/// refused environment leaves an accepted file standing rather than taking it down with it; each source is
/// atomic in itself and neither is half-applied.
/// </para>
/// <para>
/// Nothing here throws. This runs while the plugin is being constructed, where a throw takes the plugin, and
/// with it every SSO login on the server, offline over a configuration mistake.
/// </para>
/// <para>
/// One shape is out of reach and is stated rather than worked around: a provider whose NAME contains a
/// double underscore cannot be addressed, because the name would be indistinguishable from two steps. Such
/// a provider is configured from the mounted file or from the settings page.
/// </para>
/// </remarks>
internal static class DeclarativeEnvironmentConfig
{
    /// <summary>
    /// The prefix every variable of this source carries. Deliberately not a prefix of
    /// <see cref="DeclarativeProviderConfig.SourcePathVariable"/> and not prefixed BY it: that variable ends
    /// in a single underscore before <c>FILE</c>, this one in the double underscore that starts a path, so
    /// neither can ever be read as the other.
    /// </summary>
    internal const string Prefix = "JELLYFIN_SSO_CONFIG__";

    /// <summary>The separator between the steps of a path, and the same one ASP.NET Core uses.</summary>
    internal const string Separator = "__";

    /// <summary>
    /// The only two members of the configuration a declarative apply reaches, read straight off
    /// <see cref="ConfigImport"/>'s own behaviour rather than restated from it in prose.
    /// </summary>
    internal static readonly string[] DeclaredSurface = [nameof(PluginConfiguration.OidConfigs), nameof(PluginConfiguration.SamlConfigs)];

    /// <summary>
    /// Reads the process environment and applies whatever it declares to <paramref name="store"/>.
    /// </summary>
    /// <param name="store">The configuration store to apply through.</param>
    /// <param name="logger">The logger a rejection is reported on.</param>
    /// <param name="revealStoredSecret">Recovers the plaintext of a secret as the store holds it (#1096); null skips that comparison.</param>
    /// <returns>What the load did.</returns>
    internal static DeclarativeLoadOutcome ApplyFromEnvironment(
        ProviderConfigStore store,
        ILogger? logger,
        Func<string?, string?>? revealStoredSecret = null)
    {
        try
        {
            return Apply(store, ReadProcessEnvironment(), logger, revealStoredSecret);
        }
#pragma warning disable CA1031 // Do not catch general exception types
        catch (Exception ex)
#pragma warning restore CA1031
        {
            // The same instrument, and for the same reason, as the file source's outer catch: this is called
            // from the plugin's constructor, so anything escaping fails the plugin load and takes every SSO
            // login on the server offline. The typed refusals inside Apply name what was reasoned about;
            // this names what was not, and refuses to let a configuration source decide whether the plugin
            // exists.
            if (logger?.IsEnabled(LogLevel.Error) == true)
            {
                logger.LogError(
                    ex,
                    "The declarative SSO configuration from the environment could not be applied and nothing was changed. The plugin is running on its stored configuration.");
            }

            return DeclarativeLoadOutcome.Rejected;
        }
    }

    /// <summary>
    /// Applies what <paramref name="environment"/> declares, reading the variables from a supplied map so the
    /// outcome can be driven without touching the process environment.
    /// </summary>
    /// <param name="store">The configuration store to apply through.</param>
    /// <param name="environment">The variables, including ones this source does not own.</param>
    /// <param name="logger">The logger a rejection is reported on.</param>
    /// <param name="revealStoredSecret">Recovers the plaintext of a secret as the store holds it (#1096); null skips that comparison.</param>
    /// <returns>What the load did.</returns>
    internal static DeclarativeLoadOutcome Apply(
        ProviderConfigStore store,
        IEnumerable<KeyValuePair<string, string?>> environment,
        ILogger? logger,
        Func<string?, string?>? revealStoredSecret = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(environment);

        // Ordinal ordering, so two runs of the same environment build the same document and a rejection names
        // the same variable each time. A dictionary's enumeration order is not a promise anybody made.
        var declared = environment
            .Where(entry => entry.Key.StartsWith(Prefix, StringComparison.Ordinal))
            .OrderBy(entry => entry.Key, StringComparer.Ordinal)
            .ToList();

        if (declared.Count == 0)
        {
            return DeclarativeLoadOutcome.NotConfigured;
        }

        var root = new JsonObject();
        foreach (var entry in declared)
        {
            if (!TryPlace(root, entry.Key, entry.Value, out var rejection))
            {
                return DeclarativeProviderConfig.Reject(logger, Prefix, rejection);
            }
        }

        if (FirstHoleInAList(root, Prefix) is { } hole)
        {
            return DeclarativeProviderConfig.Reject(logger, Prefix, hole);
        }

        PluginConfiguration? configuration;
        try
        {
            configuration = root.Deserialize<PluginConfiguration>();
        }
        catch (JsonException)
        {
            // The reason is deliberately not the exception's own message. Every leaf above was written as the
            // JSON kind its field is, so reaching here is a fault in this file rather than in the operator's
            // variables - and a deserializer message can quote the document, which on this source is where the
            // secrets are. The refusal says which source refused and nothing about what it held.
            return DeclarativeProviderConfig.Reject(logger, Prefix, "the variables did not describe a configuration this plugin can read");
        }
        catch (NotSupportedException)
        {
            return DeclarativeProviderConfig.Reject(logger, Prefix, "the variables did not describe a configuration this plugin can read");
        }

        if (configuration is null)
        {
            return DeclarativeProviderConfig.Reject(logger, Prefix, "the variables produced no configuration");
        }

        return DeclarativeProviderConfig.ApplyDocument(
            store,
            new ConfigExportDocument { FormatVersion = ConfigExport.FormatVersion, Configuration = configuration },
            Prefix,
            logger,
            revealStoredSecret);
    }

    /// <summary>
    /// Resolves one step of a path against the type it is being read out of, which is the whole of the naming
    /// scheme. Public to the tests so the reachability of every field the model carries is derived rather
    /// than asserted.
    /// </summary>
    /// <param name="container">The type the step is resolved inside.</param>
    /// <param name="step">The step: a property name, a dictionary key, or a list index.</param>
    /// <param name="addressed">The type the step addresses, with any nullable wrapper removed.</param>
    /// <param name="canonical">The step as the document spells it: a property's own casing, or the key or index verbatim.</param>
    /// <param name="rejection">Why the step could not be resolved.</param>
    /// <returns><see langword="true"/> when the step addresses something settable.</returns>
    internal static bool TryResolveStep(Type container, string step, out Type addressed, out string canonical, out string? rejection)
    {
        ArgumentNullException.ThrowIfNull(container);
        addressed = typeof(object);
        canonical = step;
        rejection = null;

        if (ValueTypeOfDictionary(container) is { } value)
        {
            // A dictionary key is taken verbatim and is never matched against anything, because it names a
            // provider the operator chose and this source has no opinion about what those are called.
            addressed = Unwrap(value);
            return true;
        }

        if (ElementTypeOfList(container) is { } element)
        {
            if (!int.TryParse(step, NumberStyles.None, CultureInfo.InvariantCulture, out var index) || index < 0)
            {
                rejection = $"'{step}' is not a list index";
                return false;
            }

            addressed = Unwrap(element);
            return true;
        }

        if (container == typeof(PluginConfiguration) && !DeclaredSurface.Contains(step, StringComparer.OrdinalIgnoreCase))
        {
            // The declarative apply reaches the two provider maps and nothing else. ConfigImport deliberately
            // leaves the rate-limit tuning and the SSO-only globals alone - instance-local operational state
            // with no blank-means-keep signal, and the SSO-only mode additionally needs a user manager to
            // prove a surviving password door. A variable naming one of them would be accepted, written into
            // the document and then dropped by the apply, which is the silently-unconfigurable field this
            // source exists to make impossible. So it is refused, and the refusal says where the setting does
            // live.
            rejection = $"'{step}' is not applied by the declarative configuration; only {string.Join(" and ", DeclaredSurface)} are, and the rate-limit and SSO-only settings are changed on the settings page";
            return false;
        }

        var property = container
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .FirstOrDefault(candidate => string.Equals(candidate.Name, step, StringComparison.OrdinalIgnoreCase));

        if (property is null || property.SetMethod is null || !property.SetMethod.IsPublic)
        {
            rejection = $"'{step}' names no field of {container.Name}";
            return false;
        }

        if (property.GetCustomAttribute<JsonIgnoreAttribute>() is not null)
        {
            // Refused by name rather than accepted and dropped. These are the server-managed fields, and a
            // variable aimed at one would otherwise look applied and change nothing at all.
            rejection = $"'{property.Name}' is managed by the server and cannot be set from the environment";
            return false;
        }

        addressed = Unwrap(property.PropertyType);

        // The property's OWN casing reaches the document, not the operator's. A variable may be spelled in
        // any case, exactly like a member of the mounted file, and what is built is spelled once.
        canonical = property.Name;
        return true;
    }

    // Walks the path and writes the value at its end, creating the objects and lists it passes through. The
    // walk and the type resolution are the same ones the reachability test drives, so what the test proves is
    // reachable is what this places.
    private static bool TryPlace(JsonObject root, string variable, string? value, out string rejection)
    {
        rejection = string.Empty;
        var path = variable[Prefix.Length..];
        var steps = path.Split(Separator, StringSplitOptions.None);
        if (steps.Length == 0 || steps.Any(string.IsNullOrEmpty))
        {
            rejection = $"'{variable}' names no path into the configuration";
            return false;
        }

        JsonNode container = root;
        var containerType = typeof(PluginConfiguration);

        for (var i = 0; i < steps.Length; i++)
        {
            if (!TryResolveStep(containerType, steps[i], out var addressed, out var canonical, out var stepRejection))
            {
                rejection = $"'{variable}': {stepRejection}";
                return false;
            }

            if (i == steps.Length - 1)
            {
                if (!TryLeaf(addressed, value, out var leaf, out var leafRejection))
                {
                    rejection = $"'{variable}': {leafRejection}";
                    return false;
                }

                Place(container, canonical, leaf);
                return true;
            }

            var existing = Read(container, canonical);
            if (existing is null)
            {
                existing = ElementTypeOfList(addressed) is null ? new JsonObject() : (JsonNode)new JsonArray();
                Place(container, canonical, existing);
            }

            container = existing;
            containerType = addressed;
        }

        rejection = $"'{variable}' names no path into the configuration";
        return false;
    }

    // A list built out of indices can be given 2 without 0 and 1. Deserializing that would hand the model a
    // list with nulls in it, which is a different configuration from the one the operator wrote and reads as
    // an empty role rather than as a mistake, so the hole is a refusal.
    private static string? FirstHoleInAList(JsonNode node, string path)
    {
        switch (node)
        {
            case JsonArray array:
                for (var i = 0; i < array.Count; i++)
                {
                    if (array[i] is null)
                    {
                        return $"'{path}{Separator}{i.ToString(CultureInfo.InvariantCulture)}' is missing, so the list it belongs to has a hole in it";
                    }

                    if (FirstHoleInAList(array[i]!, $"{path}{Separator}{i.ToString(CultureInfo.InvariantCulture)}") is { } nested)
                    {
                        return nested;
                    }
                }

                return null;

            case JsonObject obj:
                foreach (var member in obj)
                {
                    if (member.Value is not null && FirstHoleInAList(member.Value, $"{path}{Separator}{member.Key}") is { } nested)
                    {
                        return nested;
                    }
                }

                return null;

            default:
                return null;
        }
    }

    // The value at the end of a path, turned into the JSON kind the field is. A string that does not spell a
    // number or a boolean is refused here rather than reaching the deserializer, so the message names the
    // variable instead of a JSON path nobody wrote.
    private static bool TryLeaf(Type addressed, string? value, out JsonNode? leaf, out string rejection)
    {
        leaf = null;
        rejection = string.Empty;

        if (addressed == typeof(string))
        {
            leaf = JsonValue.Create(value);
            return true;
        }

        if (addressed == typeof(bool))
        {
            if (!bool.TryParse(value, out var parsed))
            {
                rejection = "expected true or false";
                return false;
            }

            leaf = JsonValue.Create(parsed);
            return true;
        }

        if (addressed == typeof(int))
        {
            if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
            {
                rejection = "expected a whole number";
                return false;
            }

            leaf = JsonValue.Create(parsed);
            return true;
        }

        // No other leaf kind exists in the model today, and the reachability test fails the build if one
        // arrives, so this is a refusal rather than a silent pass.
        rejection = $"a {addressed.Name} cannot be written as a single variable";
        return false;
    }

    private static void Place(JsonNode container, string step, JsonNode? value)
    {
        if (container is JsonArray array)
        {
            var index = int.Parse(step, NumberStyles.None, CultureInfo.InvariantCulture);
            while (array.Count <= index)
            {
                array.Add(null);
            }

            array[index] = value;
            return;
        }

        ((JsonObject)container)[step] = value;
    }

    private static JsonNode? Read(JsonNode container, string step)
    {
        if (container is JsonArray array)
        {
            var index = int.Parse(step, NumberStyles.None, CultureInfo.InvariantCulture);
            return index < array.Count ? array[index] : null;
        }

        return ((JsonObject)container).TryGetPropertyValue(step, out var existing) ? existing : null;
    }

    private static Type Unwrap(Type type) => Nullable.GetUnderlyingType(type) ?? type;

    private static Type? ValueTypeOfDictionary(Type type)
    {
        for (var candidate = type; candidate is not null; candidate = candidate.BaseType)
        {
            if (candidate.IsGenericType
                && candidate.GetGenericTypeDefinition() == typeof(Dictionary<,>)
                && candidate.GetGenericArguments()[0] == typeof(string))
            {
                return candidate.GetGenericArguments()[1];
            }
        }

        return null;
    }

    private static Type? ElementTypeOfList(Type type)
    {
        if (type == typeof(string) || ValueTypeOfDictionary(type) is not null)
        {
            return null;
        }

        if (type.IsArray)
        {
            return type.GetElementType();
        }

        if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(List<>))
        {
            return type.GetGenericArguments()[0];
        }

        return null;
    }

    private static IEnumerable<KeyValuePair<string, string?>> ReadProcessEnvironment()
    {
        foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            if (entry.Key is string name)
            {
                yield return new KeyValuePair<string, string?>(name, entry.Value as string);
            }
        }
    }
}
