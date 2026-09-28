// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>Turns the <c>Env</c> and <c>File</c> secret references in a declarative document into the secrets themselves, and refuses an inline secret (#1096).</summary>
/// <remarks>
/// Every failure rejects the document rather than resolving to a blank, because a blank secret is kept rather than
/// applied; a refusal names the reference and never its value. See
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Config-as-code#secrets-are-references-not-values"/>.
/// </remarks>
internal static class DeclarativeSecretReference
{
    /// <summary>The suffix naming the environment variable that holds a secret field's value.</summary>
    internal const string EnvironmentSuffix = "Env";

    /// <summary>The suffix naming the path of the file that holds a secret field's value.</summary>
    internal const string FileSuffix = "File";

    private const string ConfigurationMember = "Configuration";

    private static readonly string[] OidSecretFields = { "OidSecret" };
    private static readonly string[] SamlSecretFields = { "SamlSigningKeyPfx", "SamlRolloverSigningKeyPfx" };

    /// <summary>Resolves every secret reference in <paramref name="documentText"/> into the document, or refuses it.</summary>
    /// <param name="documentText">The declarative document as read from its source.</param>
    /// <param name="readEnvironmentVariable">Reads a named environment variable; null or blank means unset.</param>
    /// <param name="readReferenceFile">Reads a referenced file; null means it could not be read at all.</param>
    /// <param name="resolvedText">The document with each reference replaced by its secret, or the input unchanged when it carries none.</param>
    /// <param name="rejection">Why the document was refused, naming the reference and never its value.</param>
    /// <returns>True when the document may go on to the deserializer.</returns>
    internal static bool TryResolve(
        string documentText,
        Func<string, string?> readEnvironmentVariable,
        Func<string, string?> readReferenceFile,
        out string resolvedText,
        out string? rejection)
    {
        ArgumentNullException.ThrowIfNull(readEnvironmentVariable);
        ArgumentNullException.ThrowIfNull(readReferenceFile);

        resolvedText = documentText;
        rejection = null;

        JsonNode? root;
        try
        {
            root = JsonNode.Parse(documentText);
        }
        catch (JsonException)
        {
            // Syntax is the deserializer's refusal to make, two steps later with a better message.
            return true;
        }

        if (root is not JsonObject document)
        {
            return true;
        }

        if (!TryMember(document, ConfigurationMember, out var configurationKey, out rejection))
        {
            return false;
        }

        if (configurationKey is null || document[configurationKey] is not JsonObject configuration)
        {
            return true;
        }

        var rewritten = false;
        if (!TryResolveMap(configuration, "OidConfigs", OidSecretFields, readEnvironmentVariable, readReferenceFile, ref rewritten, out rejection)
            || !TryResolveMap(configuration, "SamlConfigs", SamlSecretFields, readEnvironmentVariable, readReferenceFile, ref rewritten, out rejection))
        {
            return false;
        }

        if (rewritten)
        {
            resolvedText = document.ToJsonString();
        }

        return true;
    }

    private static bool TryResolveMap(
        JsonObject configuration,
        string mapMember,
        string[] secretFields,
        Func<string, string?> readEnvironmentVariable,
        Func<string, string?> readReferenceFile,
        ref bool rewritten,
        out string? rejection)
    {
        if (!TryMember(configuration, mapMember, out var mapKey, out rejection))
        {
            return false;
        }

        if (mapKey is null || configuration[mapKey] is not JsonObject providers)
        {
            return true;
        }

        foreach (var provider in providers)
        {
            if (provider.Value is not JsonObject fields)
            {
                continue;
            }

            if (!TryResolveProvider(fields, provider.Key, secretFields, readEnvironmentVariable, readReferenceFile, ref rewritten, out rejection))
            {
                return false;
            }
        }

        return true;
    }

    private static bool TryResolveProvider(
        JsonObject fields,
        string providerName,
        string[] secretFields,
        Func<string, string?> readEnvironmentVariable,
        Func<string, string?> readReferenceFile,
        ref bool rewritten,
        out string? rejection)
    {
        if (!TryRefuseForeignReferences(fields, providerName, secretFields, out rejection))
        {
            return false;
        }

        foreach (var secretField in secretFields)
        {
            if (!TryMember(fields, secretField, out var secretKey, out rejection)
                || !TryMember(fields, secretField + EnvironmentSuffix, out var environmentKey, out rejection)
                || !TryMember(fields, secretField + FileSuffix, out var fileKey, out rejection))
            {
                return false;
            }

            if (secretKey is not null && !IsBlank(fields[secretKey]))
            {
                rejection = $"provider '{providerName}' writes '{secretField}' out in full; name it with '{secretField}{EnvironmentSuffix}' or '{secretField}{FileSuffix}' instead, so the secret stays out of the document";
                return false;
            }

            if (environmentKey is null && fileKey is null)
            {
                continue;
            }

            if (environmentKey is not null && fileKey is not null)
            {
                rejection = $"provider '{providerName}' names both '{secretField}{EnvironmentSuffix}' and '{secretField}{FileSuffix}', so which one supplies '{secretField}' is undecided";
                return false;
            }

            var referenceMember = environmentKey ?? fileKey!;
            var referenceText = Text(fields[referenceMember]);
            if (referenceText is null)
            {
                rejection = $"provider '{providerName}' names '{referenceMember}' without saying what it points at";
                return false;
            }

            string? resolved;
            if (environmentKey is not null)
            {
                resolved = Text(readEnvironmentVariable(referenceText));
                if (resolved is null)
                {
                    rejection = $"provider '{providerName}' points '{secretField}' at the environment variable '{referenceText}', which is not set";
                    return false;
                }
            }
            else
            {
                resolved = ReadFile(readReferenceFile, providerName, secretField, referenceText, out rejection);
                if (resolved is null)
                {
                    return false;
                }
            }

            fields.Remove(referenceMember);
            fields[secretKey ?? secretField] = JsonValue.Create(resolved);
            rewritten = true;
        }

        return true;
    }

    // A secret member of the other protocol is refused rather than ignored, because its author believes a secret was supplied.
    private static bool TryRefuseForeignReferences(JsonObject fields, string providerName, string[] secretFields, out string? rejection)
    {
        rejection = null;
        foreach (var foreign in ForeignSecretMembers(secretFields))
        {
            if (!TryMember(fields, foreign, out var key, out rejection))
            {
                return false;
            }

            if (key is not null)
            {
                rejection = $"provider '{providerName}' names '{foreign}', which is not a secret of this provider's protocol";
                return false;
            }
        }

        return true;
    }

    private static IEnumerable<string> ForeignSecretMembers(string[] own)
    {
        foreach (var field in OidSecretFields)
        {
            foreach (var member in ForeignMembersOf(field, own))
            {
                yield return member;
            }
        }

        foreach (var field in SamlSecretFields)
        {
            foreach (var member in ForeignMembersOf(field, own))
            {
                yield return member;
            }
        }
    }

    private static IEnumerable<string> ForeignMembersOf(string field, string[] own)
    {
        if (Array.IndexOf(own, field) >= 0)
        {
            yield break;
        }

        yield return field;
        yield return field + EnvironmentSuffix;
        yield return field + FileSuffix;
    }

    private static string? ReadFile(
        Func<string, string?> readReferenceFile,
        string providerName,
        string secretField,
        string path,
        out string? rejection)
    {
        rejection = null;
        var content = readReferenceFile(path);
        if (content is null)
        {
            rejection = $"provider '{providerName}' points '{secretField}' at the file '{path}', which could not be read";
            return null;
        }

        var trimmed = content.Trim();
        if (trimmed.Length == 0)
        {
            rejection = $"provider '{providerName}' points '{secretField}' at the file '{path}', which holds nothing";
            return null;
        }

        return trimmed;
    }

    // A blank string and a non-string are both null: neither can name a variable, a path or a secret.
    private static string? Text(JsonNode? node)
        => node is JsonValue value && value.TryGetValue<string>(out var text) ? Text(text) : null;

    private static string? Text(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

    // A member holding a number or an object is not blank, or it would walk past the inline refusal.
    private static bool IsBlank(JsonNode? node)
        => node is null || (node is JsonValue value && value.TryGetValue<string>(out var text) && string.IsNullOrWhiteSpace(text));

    // Case-insensitive like the deserializer, and two members differing only in case are refused rather than picked between.
    private static bool TryMember(JsonObject owner, string name, out string? key, out string? rejection)
    {
        key = null;
        rejection = null;
        foreach (var property in owner)
        {
            if (!string.Equals(property.Key, name, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (key is not null)
            {
                rejection = $"the member '{name}' appears more than once differing only in case, so which of them decides the field is the parser's choice rather than the document's";
                return false;
            }

            key = property.Key;
        }

        return true;
    }
}
