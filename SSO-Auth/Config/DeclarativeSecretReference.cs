// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Jellyfin.Plugin.SSO_Auth.Config;

/// <summary>
/// Turns the secret REFERENCES in a declarative provider document into the secrets themselves, immediately
/// before the document is deserialized (#1096), and refuses a document that writes a secret out in full.
/// </summary>
/// <remarks>
/// <para>
/// The document the loader applies (#1095) is a file on a mounted volume, and the deployment shape it exists
/// for keeps that file in version control. A client secret or a SAML signing key written into it is therefore
/// a secret in a repository, in a backup and in every image layer that copied it, and the plugin's own
/// at-rest encryption cannot reach any of those. So an inline secret is REFUSED here rather than accepted
/// with a warning: a warning at boot is read by nobody, and the value is already committed by the time it
/// would be printed.
/// </para>
/// <para>
/// Two reference forms, one per deployment habit, each spelled as the field name it fills plus a suffix, so a
/// reader of the document can see which secret is being named:
/// </para>
/// <list type="bullet">
/// <item><c>&lt;field&gt;Env</c> names an environment variable, which is how a compose file or a Kubernetes
/// <c>env</c> block hands a value to a container.</item>
/// <item><c>&lt;field&gt;File</c> names a path to read, which is the docker-secret and projected-volume
/// habit, and the reason a container secret usually arrives as a file rather than as a variable.</item>
/// </list>
/// <para>
/// The three fields are the three the JSON boundary already treats as write-only through
/// <see cref="WriteOnlySecretConverter"/>: <c>OidSecret</c> on an OpenID provider, and
/// <c>SamlSigningKeyPfx</c> plus <c>SamlRolloverSigningKeyPfx</c> on a SAML one. That is not a coincidence
/// to be kept in step by hand - those are exactly the values an export refuses to emit, so they are exactly
/// the values a document has no legitimate way to carry in full.
/// </para>
/// <para>
/// FAIL-CLOSED IN ONE DIRECTION. Every failure this pass can meet - an inline secret, both forms on one
/// field, a reference to a variable that is not set, a file that cannot be read or that is empty - rejects
/// the document, which the loader turns into a rejection of the whole load. None of them resolves to a blank
/// secret. That difference matters more than it looks: a blank secret is KEPT rather than applied by
/// <see cref="ServerManagedFields"/>, so the server would carry on with its previous secret and the operator
/// would be told nothing, at boot, on the surface they are least likely to be watching.
/// </para>
/// <para>
/// A refusal names the REFERENCE - the variable name, the path, the field - and never what it resolved to,
/// so a rejection is diagnosable from a log without the log becoming the leak this exists to prevent.
/// </para>
/// <para>
/// Every member lookup here is case-insensitive, because the deserializer that reads the document afterwards
/// is. Two members differing only in case would leave that deserializer choosing which one fills the field,
/// and on these fields the choice is a secret, so the document is refused rather than one of them being
/// picked - the same posture the loader already takes on a member repeated exactly.
/// </para>
/// <para>
/// A file's content is trimmed. A secret file written by a shell redirect, by a projected volume or by a text
/// editor ends in a newline, and a client secret carrying a trailing newline fails at the token endpoint with
/// an error nobody traces back to the file. The cost is stated rather than hidden: a secret whose real value
/// begins or ends with whitespace cannot be delivered by the file form and has to use the variable form.
/// </para>
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

    /// <summary>
    /// Resolves every secret reference in <paramref name="documentText"/> into the document, or refuses it.
    /// </summary>
    /// <param name="documentText">The declarative document as read from its source.</param>
    /// <param name="readEnvironmentVariable">Reads a named environment variable; null or blank means unset.</param>
    /// <param name="readReferenceFile">Reads a referenced file; null means it could not be read at all.</param>
    /// <param name="resolvedText">
    /// The document with each reference replaced by the secret it named and the reference members removed;
    /// the input unchanged when the document carries no reference.
    /// </param>
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
            // Syntax is the deserializer's refusal to make, and it makes it two steps later with a better
            // message. This pass decides secrets, and a document it cannot parse carries none it can see.
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

    // A secret member belonging to the OTHER protocol - the field itself or either of its reference forms -
    // is refused rather than ignored. Every other misspelling in this document is a silent no-op, which the
    // loader discloses; these are not allowed to be, because the operator who wrote one believes a secret has
    // been supplied, and the provider would come up on whatever was stored before: working, and not from the
    // file they are reading. The bare field is in the list for the second reason too - a secret written into
    // the document under a name that happens to do nothing is still a secret in the document.
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

    // A blank string and a non-string both come back as null, so a caller never has to ask which of the two
    // it met: neither can name a variable, a path or a secret.
    private static string? Text(JsonNode? node)
        => node is JsonValue value && value.TryGetValue<string>(out var text) ? Text(text) : null;

    private static string? Text(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

    // Only an absent member, a JSON null, or a string of whitespace count as "carries no secret". A member
    // holding a number or an object is NOT blank: it says something, this pass cannot say it is not a secret,
    // and treating it as absent would let a document past the inline refusal.
    private static bool IsBlank(JsonNode? node)
        => node is null || (node is JsonValue value && value.TryGetValue<string>(out var text) && string.IsNullOrWhiteSpace(text));

    // Case-insensitive, and it reports the KEY rather than the value so the caller can rewrite or remove the
    // member it found. Two members differing only in case leave the deserializer picking one, and on these
    // fields that pick is a secret, so the document is refused instead.
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
