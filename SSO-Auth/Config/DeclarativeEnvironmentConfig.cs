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

/// <summary>The environment half of the declarative provider configuration: the same document as the mounted file, spelled as variables (#1097).</summary>
/// <remarks>
/// A variable names a path into the two provider maps with <c>__</c> between the steps, resolved against the model
/// itself; the whole source is refused as a unit on any step it cannot place, and it is applied after the file. See
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Config-as-code#the-same-example-as-environment-variables"/>.
/// </remarks>
internal static class DeclarativeEnvironmentConfig
{
    /// <summary>The prefix every variable of this source carries; its double underscore keeps it from ever reading as <see cref="DeclarativeProviderConfig.SourcePathVariable"/>.</summary>
    internal const string Prefix = "JELLYFIN_SSO_CONFIG__";

    /// <summary>The separator between the steps of a path, and the same one ASP.NET Core uses.</summary>
    internal const string Separator = "__";

    /// <summary>The only two members of the configuration a declarative apply reaches.</summary>
    internal static readonly string[] DeclaredSurface = [nameof(PluginConfiguration.OidConfigs), nameof(PluginConfiguration.SamlConfigs)];

    /// <summary>Reads the process environment and applies whatever it declares to <paramref name="store"/>.</summary>
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
            // Called from the plugin constructor, where an escaping exception takes every SSO login offline.
            if (logger?.IsEnabled(LogLevel.Error) == true)
            {
                logger.LogError(
                    ex,
                    "The declarative SSO configuration from the environment could not be applied and nothing was changed. The plugin is running on its stored configuration.");
            }

            return DeclarativeLoadOutcome.Rejected;
        }
    }

    /// <summary>Applies what <paramref name="environment"/> declares, reading the variables from a supplied map.</summary>
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

        // Ordinal ordering, so two runs build the same document and a rejection names the same variable.
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
            // Not the exception's message: a deserializer message can quote the document, which here holds the secrets.
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

    /// <summary>Resolves one step of a path against the type it is read out of, which is the whole of the naming scheme.</summary>
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
            // A dictionary key names a provider the operator chose, so it is taken verbatim.
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
            // A variable the apply would drop is refused rather than left looking applied, and the refusal says where the setting lives.
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
            // A server-managed field is refused by name rather than accepted and dropped.
            rejection = $"'{property.Name}' is managed by the server and cannot be set from the environment";
            return false;
        }

        addressed = Unwrap(property.PropertyType);

        // The property's own casing reaches the document, whatever case the variable used.
        canonical = property.Name;
        return true;
    }

    // Walks the path and writes the value at its end, creating the objects and lists it passes through.
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

    // An index given without its predecessors would deserialize to a list with nulls in it, so the hole is a refusal.
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

    // The value at the end of a path as the JSON kind its field is, refused here so the message names the variable.
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

        // No other leaf kind exists in the model, and the reachability test fails when one arrives.
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
