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
/// values, and every non-English catalog must carry EXACTLY the English key set - a missing key would blank
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

    // t("key", …) / tr("key", …) - the lookbehind keeps it off identifiers that merely end in t (parseInt(…)).
    private static readonly Regex ScriptKeyPattern = new(@"(?<![A-Za-z0-9_.])tr?\(\s*""(?<key>[^""]+)""", RegexOptions.Compiled);

    // The inline English default each script call carries: tr("key", "English", …) puts it second, while
    // t("key", params, "English") puts it third (after a params object or `undefined`).
    private static readonly Regex ScriptDefaultPattern = new(
        @"(?<![A-Za-z0-9_.])(?:tr\(\s*""(?<key>[^""]+)""\s*,\s*""(?<english>[^""]*)""" +
        @"|t\(\s*""(?<key>[^""]+)""\s*,\s*(?:\{[^}]*\}|undefined)\s*,\s*""(?<english>[^""]*)"")",
        RegexOptions.Compiled);

    // A marked element's built-in text: everything from the marker's closing '>' to the next tag. Prettier
    // may put the '>' on its own line and split the closing tag, so the text is whitespace-collapsed before
    // it is compared.
    private static readonly Regex MarkupTextPattern = new(@"data-i18n=""(?<key>[^""]+)""[^>]*>(?<text>[^<]*)<", RegexOptions.Compiled);

    // A text-marked element together with its tag name, so the element's own content can be located.
    private static readonly Regex MarkedElementPattern = new(@"<(?<tag>[a-z0-9]+)(?:\s[^>]*?)?\sdata-i18n=""(?<key>[^""]+)""[^>]*>", RegexOptions.Compiled);

    // The catalog namespaces the web assets own; everything else is server-side (see the orphan test).
    private static readonly string[] UiKeyPrefixes = ["config.", "link."];

    private const string ResourcePrefixWeb = "Jellyfin.Plugin.SSO_Auth.Web.";

    private static string CollapseWhitespace(string text) => Regex.Replace(text, @"\s+", " ").Trim();

    // The assets that CONSUME the catalog. Excluded are the vendored Jellyfin client bundles (third-party
    // code that never carries our markers, and a minified bundle only invites false positives) and i18n.js
    // itself - it DEFINES the mechanism, so its documentation spells out the marker forms literally.
    private static readonly string[] NonConsumingAssets = ["Web.ApiClient.js", "Web.jellyfin-apiClient.esm.min.js", "Web.i18n.js"];

    // Every scan below asserts the ABSENCE of offenders - except UiCatalogKeys_AreAllReferencedBySomeWebAsset,
    // which inverts: with no assets nothing is referenced, so every UI key becomes an orphan and it fails
    // loudly. All the others would be trivially green on an empty list while inspecting nothing, so a dropped
    // EmbeddedResource entry or a renamed file would silently retire them. The floor therefore belongs here,
    // once, for every consumer - the one scan that does not need it is also the one it cannot hurt.
    private static List<string> FirstPartyWebAssets()
    {
        var assets = PluginAssembly.GetManifestResourceNames()
            .Where(name => name.EndsWith(".html", System.StringComparison.Ordinal) || name.EndsWith(".js", System.StringComparison.Ordinal))
            .Where(name => !NonConsumingAssets.Any(excluded => name.EndsWith(excluded, System.StringComparison.Ordinal)))
            .ToList();

        Assert.True(assets.Count > 0, "no first-party web asset is embedded - every scan but the orphan check would pass without inspecting anything");
        return assets;
    }

    // A pattern that matches nothing is as vacuous as an empty asset list: the marker and t()/tr() syntaxes
    // are preconditions of the scans rather than guarantees (a formatter emitting single-quoted attributes
    // would break the markers), so a scan asserting the absence of offenders also pins that its pattern still
    // matches something.
    private static List<(string Resource, string Content, Match Match)> ScanWebAssets(Regex pattern, string scan) =>
        ScanForMatches(FirstPartyWebAssets(), pattern, scan);

    // The markup scans narrow to the HTML assets, which needs its own floor: a non-empty asset list says
    // nothing about the HTML subset surviving.
    private static List<(string Resource, string Content, Match Match)> ScanHtmlAssets(Regex pattern, string scan)
    {
        var assets = FirstPartyWebAssets()
            .Where(name => name.EndsWith(".html", System.StringComparison.Ordinal))
            .ToList();
        Assert.True(assets.Count > 0, $"no embedded HTML asset was found - the {scan} scan would pass without inspecting anything");

        return ScanForMatches(assets, pattern, scan);
    }

    private static List<(string Resource, string Content, Match Match)> ScanForMatches(List<string> assets, Regex pattern, string scan)
    {
        var inspected = assets
            .Select(resource => (Resource: resource, Content: ReadResourceText(resource)))
            .SelectMany(asset => pattern.Matches(asset.Content).Select(match => (asset.Resource, asset.Content, Match: match)))
            .ToList();

        Assert.True(inspected.Count > 0, $"the {scan} scan matched nothing - the pattern or the embedded assets have drifted");
        return inspected;
    }

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
        // #913: the client-rendered pages carry only KEYS - `data-i18n="key"` / `data-i18n-<attr>="key"` in
        // the markup, and t("key", …) / tr("key", …) in the scripts. A key with no catalog entry silently
        // degrades (the element keeps its built-in English, or t() falls back), so the drift is invisible in
        // review and in the browser. This scans the EMBEDDED assets - exactly what ships - so a renamed
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
    public void AttributeLocalization_StaysRestrictedToInertAttributes()
    {
        // The applier can set ATTRIBUTES from the catalog (data-i18n-<attr>), which is only safe because the
        // target is an allowlist of inert, user-visible attributes: a generic setter - or a widened list -
        // would let markup drive href, src, style, or an event handler through the same path. That is a
        // security property, so it is pinned here rather than left to review: both the allowlist itself and
        // every marker the shipped markup actually uses.
        var applier = ReadResourceText(ResourcePrefixWeb + "i18n.js");
        var declared = Regex.Match(applier, @"LOCALIZABLE_ATTRIBUTES\s*=\s*\[(?<list>[^\]]*)\]");
        Assert.True(declared.Success, "i18n.js must declare a LOCALIZABLE_ATTRIBUTES allowlist");

        var allowed = Regex.Matches(declared.Groups["list"].Value, @"""(?<name>[^""]+)""")
            .Select(match => match.Groups["name"].Value)
            .ToHashSet(System.StringComparer.Ordinal);

        Assert.Equal(new[] { "aria-label", "placeholder", "title" }, allowed.OrderBy(name => name, System.StringComparer.Ordinal));

        var offenders = FirstPartyWebAssets()
            .SelectMany(resource => Regex.Matches(ReadResourceText(resource), @"data-i18n-(?<attr>[a-z-]+)=")
                .Select(match => match.Groups["attr"].Value)
                .Where(attribute => !allowed.Contains(attribute))
                .Select(attribute => $"{resource}: data-i18n-{attribute}"))
            .ToList();

        Assert.True(offenders.Count == 0, "These markers localize an attribute outside the inert allowlist: " + string.Join(" | ", offenders));
    }

    [Fact]
    public void MarkupBuiltInEnglish_MatchesTheCatalog()
    {
        // A marked element keeps its built-in English until the catalog resolves, and permanently if the
        // fetch fails - so that text is a SECOND copy of the wording. If the two drift, an admin whose
        // catalog loaded sees different text from one whose fetch failed, with nothing to signal which is
        // current. Pin them equal; the built-in text stays the authoritative offline rendering.
        var english = ReadCatalog(EnglishResource);
        var mismatches = new List<string>();

        foreach (var (resource, _, match) in ScanHtmlAssets(MarkupTextPattern, "built-in English"))
        {
            var key = match.Groups["key"].Value;
            var builtIn = CollapseWhitespace(match.Groups["text"].Value);
            if (english.TryGetValue(key, out var catalogValue) && !string.Equals(catalogValue, builtIn, System.StringComparison.Ordinal))
            {
                mismatches.Add($"{resource}: '{key}' markup \"{builtIn}\" != catalog \"{catalogValue}\"");
            }
        }

        Assert.True(mismatches.Count == 0, "These built-in English strings have drifted from the catalog: " + string.Join(" | ", mismatches));
    }

    [Fact]
    public void TextMarkers_OnlySitOnElementsWithoutChildMarkup()
    {
        // `data-i18n` REPLACES the element's textContent, so every child element inside a marked element is
        // destroyed the moment the catalog resolves - and on the configuration page those children are
        // load-bearing: the required asterisk and the "(optional)" hint live INSIDE their field label, and a
        // link or a <code> sample carries meaning of its own inside a description. Such a marker renders
        // correctly while the catalog is unreachable and silently strips the markup once it loads, which is
        // exactly the kind of drift review does not catch. A text marker therefore belongs only on an
        // element whose content is a single text node; a label that wraps child markup needs the marker on
        // the text-bearing child, not on the label.
        var problems = new List<string>();

        foreach (var (resource, content, match) in ScanHtmlAssets(MarkedElementPattern, "text-marker"))
        {
            var key = match.Groups["key"].Value;
            var contentStart = match.Index + match.Length;
            var closing = content.IndexOf("</" + match.Groups["tag"].Value, contentStart, System.StringComparison.Ordinal);

            // No `</tag` after the marker at all: usually a void element, which has no text node for the
            // applier to write, but equally unbalanced markup, where the string would land on an element that
            // swallowed the rest of the document. Both are wrong and neither is child markup, so the case
            // carries its own diagnosis - the child-markup branch cannot express it, and cannot even detect
            // it reliably: the remainder of a file usually contains a '<', but not after the last element.
            // Both diagnoses go into ONE list and ONE assertion so that a run reports every offender at once;
            // two sequential assertions would hide the second class behind the first.
            if (closing < 0)
            {
                problems.Add($"{resource}: '{key}' - no closing tag, so the marker delimits no text to localize");
            }
            else if (content[contentStart..closing].Contains('<'))
            {
                problems.Add($"{resource}: '{key}' - child markup would be replaced with plain text");
            }
        }

        Assert.True(problems.Count == 0, "These text markers do not sit on an element whose content is a single text node: " + string.Join(" | ", problems));
    }

    [Fact]
    public void UiCatalogKeys_AreAllReferencedBySomeWebAsset()
    {
        // The reverse of the forward parity check: a UI key nothing references is dead data that a
        // translator still has to carry, and it hides a dropped marker (the string silently stops being
        // localized while the catalog still claims to cover it). Scoped to the namespaces the web assets
        // own - the error.*/page.* keys are server-side, reached from C# either by key or, for the login
        // rejection bodies, by reverse VALUE lookup, so a key-reference scan cannot see them.
        var referenced = FirstPartyWebAssets()
            .SelectMany(resource =>
            {
                var content = ReadResourceText(resource);
                return MarkupKeyPattern.Matches(content).Concat(ScriptKeyPattern.Matches(content))
                    .Select(match => match.Groups["key"].Value);
            })
            .ToHashSet(System.StringComparer.Ordinal);

        var orphans = ReadCatalog(EnglishResource).Keys
            .Where(key => UiKeyPrefixes.Any(prefix => key.StartsWith(prefix, System.StringComparison.Ordinal)))
            .Where(key => !referenced.Contains(key))
            .OrderBy(key => key, System.StringComparer.Ordinal)
            .ToList();

        Assert.True(orphans.Count == 0, "These UI catalog keys are referenced by no web asset: " + string.Join(", ", orphans));
    }

    [Fact]
    public void ScriptEnglishDefaults_MatchTheCatalog()
    {
        // A string the scripts build themselves carries its English inline as the fallback, so it still reads
        // properly when the catalog cannot be fetched. That default is a SECOND copy of the wording, and a
        // reword of one copy alone is invisible: the page would show one wording offline and another online.
        // Pin them equal - this is the drift class an earlier sub-unit's review found on the linking page.
        var english = ReadCatalog(EnglishResource);
        var mismatches = new List<string>();

        foreach (var (resource, _, match) in ScanWebAssets(ScriptDefaultPattern, "inline English default"))
        {
            var key = match.Groups["key"].Value;
            var inline = match.Groups["english"].Value;
            if (english.TryGetValue(key, out var catalogValue) && !string.Equals(catalogValue, inline, System.StringComparison.Ordinal))
            {
                mismatches.Add($"{resource}: '{key}' inline \"{inline}\" != catalog \"{catalogValue}\"");
            }
        }

        Assert.True(mismatches.Count == 0, "These inline English defaults have drifted from the catalog: " + string.Join(" | ", mismatches));
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
