// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;

namespace Jellyfin.Plugin.SSO_Auth.Api.Localization;

/// <summary>
/// Minimal string localizer for the plugin's user-facing served surfaces, in Jellyfin's own idiom
/// (#913). It loads flat per-culture key→value JSON catalogs - embedded resources named by BCP-47
/// culture, the shape of Jellyfin core's
/// <c>Emby.Server.Implementations/Localization/Core/&lt;culture&gt;.json</c> - and resolves a key
/// through a fallback chain that never blanks: the requested culture, then its base language, then
/// English (the invariant fallback), then the key itself. The plugin cannot register its catalogs into
/// core's <c>ILocalizationManager</c> (core owns that surface), so it keeps its own; the format and the
/// <c>GetString(key, culture)</c> lookup mirror Jellyfin so a translator sees a familiar file.
///
/// Catalogs are DATA and are treated fail-closed: a catalog that is missing, is not a JSON object, is not
/// a flat string→string map, or carries a null value is skipped at load (its keys fall through the chain
/// to English), never fatal. No user-controlled value is ever used as a key.
/// </summary>
internal static class SsoLocalizer
{
    /// <summary>
    /// The invariant fallback culture. Every key is guaranteed to exist here, so the chain never blanks.
    /// </summary>
    internal const string FallbackCulture = "en";

    private const string ResourcePrefix = "Jellyfin.Plugin.SSO_Auth.Localization.";
    private const string ResourceSuffix = ".json";

    // culture (lower-invariant) -> (key -> non-null value). Immutable snapshot built once at load.
    private static readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> CatalogsByCulture = Load();

    /// <summary>Gets the BCP-47 cultures that loaded a valid catalog (lower-invariant). For tests/diagnostics.</summary>
    internal static IReadOnlyCollection<string> AvailableCultures => CatalogsByCulture.Keys.ToArray();

    /// <summary>
    /// Resolves every catalog key into <paramref name="culture"/> and returns the complete key→value map,
    /// for a client that renders a page's own text (#913): the server owns the culture fallback, the client
    /// just applies concrete strings. Keyed on the English baseline, which holds every key.
    /// </summary>
    /// <param name="culture">The requested culture, or null for English.</param>
    /// <returns>Every key resolved to a concrete string in the requested culture.</returns>
    internal static IReadOnlyDictionary<string, string> ResolvedCatalog(string? culture)
    {
        var resolved = new Dictionary<string, string>(StringComparer.Ordinal);
        if (CatalogsByCulture.TryGetValue(FallbackCulture, out var english))
        {
            foreach (var key in english.Keys)
            {
                resolved[key] = GetString(key, culture);
            }
        }

        return resolved;
    }

    /// <summary>
    /// Gets the localized value for <paramref name="key"/> in <paramref name="culture"/>, falling back to
    /// the base language, then English, then the key itself. Never returns null or empty for a key present
    /// in the English catalog; returns the key verbatim when it is defined nowhere.
    /// </summary>
    /// <param name="key">The catalog key. Never a user-controlled value.</param>
    /// <param name="culture">The requested BCP-47 culture, or null/empty to use the fallback.</param>
    /// <returns>The best available translation, or the key itself.</returns>
    internal static string GetString(string key, string? culture)
    {
        ArgumentNullException.ThrowIfNull(key);

        foreach (var candidate in CultureFallbackChain(culture))
        {
            if (CatalogsByCulture.TryGetValue(candidate, out var catalog)
                && catalog.TryGetValue(key, out var value))
            {
                return value;
            }
        }

        // Defined nowhere: return the key so a missing translation is visible, never a blank.
        return key;
    }

    /// <summary>
    /// Localizes a canonical English message into <paramref name="culture"/> by finding its catalog key.
    /// Returns the message unchanged when it is not a catalog value (for example an identity-provider-
    /// interpolated error), so a non-catalog string is never dropped. This localizes a message that has
    /// already been produced in English - the wire form stays English; only a re-render (the browser error
    /// page) swaps in the translation.
    /// </summary>
    /// <param name="englishMessage">The English message to localize.</param>
    /// <param name="culture">The requested culture, or null/empty to keep English.</param>
    /// <returns>The localized message, or the input unchanged when it is not a known English catalog value.</returns>
    internal static string LocalizeEnglish(string englishMessage, string? culture)
    {
        ArgumentNullException.ThrowIfNull(englishMessage);

        if (string.IsNullOrEmpty(culture))
        {
            return englishMessage;
        }

        var key = KeyForEnglishValue(englishMessage);
        return key is null ? englishMessage : GetString(key, culture);
    }

    /// <summary>Whether <paramref name="englishMessage"/> is a known English catalog value (so it will localize).</summary>
    /// <param name="englishMessage">The candidate English message.</param>
    /// <returns>True when the message is present as an English catalog value.</returns>
    internal static bool IsLocalizableEnglish(string englishMessage)
    {
        ArgumentNullException.ThrowIfNull(englishMessage);
        return KeyForEnglishValue(englishMessage) is not null;
    }

    // Reverse-map an English message to its catalog key by scanning the English baseline. The catalog is a
    // handful of entries and this runs only on an error re-render, so a linear scan is cheaper than carrying
    // a second index; the catalog conformance test forbids duplicate English values, so the first match is
    // the only match.
    private static string? KeyForEnglishValue(string englishMessage)
    {
        if (CatalogsByCulture.TryGetValue(FallbackCulture, out var english))
        {
            foreach (var (key, value) in english)
            {
                if (string.Equals(value, englishMessage, StringComparison.Ordinal))
                {
                    return key;
                }
            }
        }

        return null;
    }

    // The requested culture, then its base language ("de-CH" -> "de"), then English - lower-invariant,
    // de-duplicated in order.
    private static IEnumerable<string> CultureFallbackChain(string? culture)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var candidate in Candidates(culture))
        {
            var normalized = candidate.ToLowerInvariant();
            if (seen.Add(normalized))
            {
                yield return normalized;
            }
        }
    }

    private static IEnumerable<string> Candidates(string? culture)
    {
        if (!string.IsNullOrWhiteSpace(culture))
        {
            var trimmed = culture.Trim();
            yield return trimmed;

            var dash = trimmed.IndexOf('-', StringComparison.Ordinal);
            if (dash > 0)
            {
                yield return trimmed[..dash];
            }
        }

        yield return FallbackCulture;
    }

    private static Dictionary<string, IReadOnlyDictionary<string, string>> Load()
    {
        var result = new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.Ordinal);
        var assembly = typeof(SsoLocalizer).Assembly;

        foreach (var resourceName in assembly.GetManifestResourceNames())
        {
            if (!resourceName.StartsWith(ResourcePrefix, StringComparison.Ordinal)
                || !resourceName.EndsWith(ResourceSuffix, StringComparison.Ordinal))
            {
                continue;
            }

            var culture = resourceName[ResourcePrefix.Length..^ResourceSuffix.Length].ToLowerInvariant();
            var catalog = TryReadCatalog(assembly, resourceName);
            if (catalog != null)
            {
                result[culture] = catalog;
            }
        }

        return result;
    }

    // A catalog is DATA: a stream that is missing, is not a JSON object, is not a flat string->string map,
    // or carries a null value is skipped (its keys fall through the chain to English), never fatal.
    private static Dictionary<string, string>? TryReadCatalog(Assembly assembly, string resourceName)
    {
        try
        {
            using var stream = assembly.GetManifestResourceStream(resourceName);
            if (stream == null)
            {
                return null;
            }

            using var reader = new StreamReader(stream);
            var parsed = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.ReadToEnd());
            if (parsed == null || parsed.Values.Any(value => value == null))
            {
                return null;
            }

            return parsed;
        }
        catch (JsonException)
        {
            // Malformed catalog (not an object, wrong value shape): fail closed to the fallback chain.
            return null;
        }
    }
}
