// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// The duplicate-property gate every provider-supplied JSON document passes before the plugin reads it
/// (#1005). A repeated property name is accepted by every JSON reader this plugin depends on, each of which
/// silently keeps the LAST occurrence, so one document can mean two things: the reader that indexes a name
/// sees the last value while the reader that enumerates the object sees both. Measured on both target
/// frameworks — <c>JsonDocument</c> keeps both properties and indexes the last, Newtonsoft keeps one,
/// <c>JsonWebToken</c> and Duende's <c>JsonWebKeySet</c> keep the last — so an authorization server can
/// hand one body to two consumers that disagree about it. Refusing the document outright is the only reading
/// on which they cannot disagree.
///
/// This is deliberately a raw <see cref="Utf8JsonReader"/> walk rather than a
/// <c>JsonSerializerOptions</c> setting. The plugin binds the HOST's System.Text.Json — .NET 9's in the
/// Jellyfin 10.11 line, .NET 10's in the 12.0 line — and the <c>Strict</c> preset with its
/// <c>AllowDuplicateProperties</c> switch exists only on the latter: referencing it fails the net9.0 build
/// with CS0117. A tokenizer carries no duplicate policy of its own, so this one code path reaches the same
/// decision on both targets, and that decision does not move when the host's System.Text.Json does.
/// </summary>
internal static class StrictJson
{
    // Matches the System.Text.Json reader default rather than raising it. The gate must never accept a
    // document its consumers would refuse to read, and a deeper document is refused here as unverifiable
    // rather than waved through unchecked.
    private const int MaxDepth = 64;

    /// <summary>
    /// Reports whether <paramref name="json"/> repeats a property name within one object, at any depth.
    /// </summary>
    /// <param name="json">The raw document, as received from the provider.</param>
    /// <returns>
    /// <c>false</c> only when the document is provably free of repeated property names — which includes a
    /// null, empty or whitespace input, since it carries no properties to repeat and every caller already
    /// has its own branch for an absent document. <c>true</c> for a repeat at any depth, and for a document
    /// that cannot be tokenized (malformed, truncated, or nested past <see cref="MaxDepth"/>): a document the
    /// gate could not clear is refused, never waved through. Names are compared ordinally, because JSON
    /// member names are case-sensitive and every consumer of these documents compares them ordinally too;
    /// they are compared AFTER unescaping, so a name spelled with a <c>\u</c> escape counts as the same name
    /// as its plain spelling. Never throws.
    /// </returns>
    internal static bool HasDuplicateProperty(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return false;
        }

        // One name set per object scope, pushed and popped with the braces: sibling objects legitimately
        // reuse names (every JWKS key entry repeats "kty" and "kid"), and a single document-wide set would
        // refuse every real discovery document while claiming to have found an attack.
        var scopes = new Stack<HashSet<string>>();
        try
        {
            var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(json), new JsonReaderOptions { MaxDepth = MaxDepth });
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                        scopes.Push(new HashSet<string>(StringComparer.Ordinal));
                        break;

                    case JsonTokenType.EndObject:
                        scopes.Pop();
                        break;

                    case JsonTokenType.PropertyName:
                        if (!scopes.Peek().Add(reader.GetString() ?? string.Empty))
                        {
                            return true;
                        }

                        break;

                    default:
                        break;
                }
            }
        }
        catch (JsonException)
        {
            return true;
        }

        return false;
    }
}
