// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using Jellyfin.Plugin.SSO_Auth.Api.Localization;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Conformance guard for the localization catalogs (#913). English is the invariant baseline that the
/// fallback chain terminates on, so every embedded catalog must be a flat string→string map with no blank
/// values, and every non-English catalog must carry EXACTLY the English key set — a missing key would blank
/// (it falls back, but a translator's catalog claiming completeness must be complete), an orphan key is dead
/// data. This is the standing drift guard for when the full language set lands (a later sub-unit).
/// </summary>
public class LocalizationCatalogTests
{
    private const string ResourcePrefix = "Jellyfin.Plugin.SSO_Auth.Localization.";
    private const string ResourceSuffix = ".json";
    private const string EnglishResource = ResourcePrefix + "en" + ResourceSuffix;

    // Any type in the plugin assembly anchors GetManifestResourceStream to the resource-bearing assembly.
    private static readonly Assembly PluginAssembly = typeof(SsoLocalizer).Assembly;

    private static IEnumerable<string> CatalogResources() =>
        PluginAssembly.GetManifestResourceNames()
            .Where(name => name.StartsWith(ResourcePrefix, System.StringComparison.Ordinal)
                && name.EndsWith(ResourceSuffix, System.StringComparison.Ordinal));

    // `data-i18n="key"` and the allowlisted attribute form `data-i18n-title="key"`.
    private static readonly Regex MarkupKeyPattern = new(@"data-i18n(?:-[a-z-]+)?=""(?<key>[^""]+)""", RegexOptions.Compiled);

    // t("key", …) / tr("key", …) — the lookbehind keeps it off identifiers that merely end in t (parseInt(…)).
    private static readonly Regex ScriptKeyPattern = new(@"(?<![A-Za-z0-9_.])tr?\(\s*""(?<key>[^""]+)""", RegexOptions.Compiled);

    // The assets that CONSUME the catalog. Excluded are the vendored Jellyfin client bundles (third-party
    // code that never carries our markers, and a minified bundle only invites false positives) and i18n.js
    // itself — it DEFINES the mechanism, so its documentation spells out the marker forms literally.
    private static readonly string[] NonConsumingAssets = ["Web.ApiClient.js", "Web.jellyfin-apiClient.esm.min.js", "Web.i18n.js"];

    private static IEnumerable<string> FirstPartyWebAssets() =>
        PluginAssembly.GetManifestResourceNames()
            .Where(name => name.EndsWith(".html", System.StringComparison.Ordinal) || name.EndsWith(".js", System.StringComparison.Ordinal))
            .Where(name => !NonConsumingAssets.Any(excluded => name.EndsWith(excluded, System.StringComparison.Ordinal)));

    private static string ReadResourceText(string resourceName)
    {
        using var stream = PluginAssembly.GetManifestResourceStream(resourceName);
        Assert.NotNull(stream);
        using var reader = new StreamReader(stream!);
        return reader.ReadToEnd();
    }

    private static Dictionary<string, string> ReadCatalog(string resourceName)
    {
        using var stream = PluginAssembly.GetManifestResourceStream(resourceName);
        Assert.NotNull(stream);
        using var reader = new StreamReader(stream!);
        var parsed = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.ReadToEnd());
        Assert.NotNull(parsed);
        return parsed!;
    }

    [Fact]
    public void EveryKeyReferencedByTheWebAssets_ExistsInTheEnglishCatalog()
    {
        // #913: the client-rendered pages carry only KEYS — `data-i18n="key"` / `data-i18n-<attr>="key"` in
        // the markup, and t("key", …) / tr("key", …) in the scripts. A key with no catalog entry silently
        // degrades (the element keeps its built-in English, or t() falls back), so the drift is invisible in
        // review and in the browser. This scans the EMBEDDED assets — exactly what ships — so a renamed
        // catalog key or a typo'd marker is a red build rather than a page that quietly stops localizing.
        var englishKeys = ReadCatalog(EnglishResource).Keys.ToHashSet(System.StringComparer.Ordinal);
        var missing = new List<string>();

        foreach (var resource in FirstPartyWebAssets())
        {
            var content = ReadResourceText(resource);
            var referenced = MarkupKeyPattern.Matches(content)
                .Concat(ScriptKeyPattern.Matches(content))
                .Select(match => match.Groups["key"].Value);

            foreach (var key in referenced.Where(key => !englishKeys.Contains(key)))
            {
                missing.Add($"{resource}: '{key}'");
            }
        }

        Assert.True(missing.Count == 0, "These i18n keys are referenced by a web asset but absent from the English catalog: " + string.Join(" | ", missing));
    }

    [Fact]
    public void EnglishCatalog_ExistsAndIsNonEmpty()
    {
        Assert.Contains(EnglishResource, CatalogResources());
        Assert.NotEmpty(ReadCatalog(EnglishResource));
    }

    [Fact]
    public void EveryCatalog_HasNoBlankValues()
    {
        foreach (var resource in CatalogResources())
        {
            Assert.All(
                ReadCatalog(resource),
                entry => Assert.False(
                    string.IsNullOrWhiteSpace(entry.Value),
                    $"{resource}: key '{entry.Key}' has a blank value"));
        }
    }

    [Fact]
    public void EnglishCatalog_HasNoDuplicateValues()
    {
        // The browser error page localizes a canonical English message by reverse-mapping it to its key
        // (SsoLocalizer.LocalizeEnglish). A duplicate English value would make that mapping ambiguous, so
        // the English baseline must keep its values one-to-one with its keys.
        var english = ReadCatalog(EnglishResource);
        var duplicates = english.Values
            .GroupBy(value => value, System.StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .ToList();

        Assert.True(duplicates.Count == 0, "duplicate English values: " + string.Join(" | ", duplicates));
    }

    [Fact]
    public void EveryNonEnglishCatalog_HasExactlyTheEnglishKeySet()
    {
        var englishKeys = ReadCatalog(EnglishResource).Keys.ToHashSet();

        foreach (var resource in CatalogResources().Where(name => name != EnglishResource))
        {
            var keys = ReadCatalog(resource).Keys.ToHashSet();

            var missing = englishKeys.Except(keys).ToList();
            var orphan = keys.Except(englishKeys).ToList();

            Assert.True(missing.Count == 0, $"{resource}: missing keys: {string.Join(", ", missing)}");
            Assert.True(orphan.Count == 0, $"{resource}: orphan keys not in English: {string.Join(", ", orphan)}");
        }
    }
}
