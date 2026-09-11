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
/// data. Which cultures ship is declared by <c>CommittedCultures</c> rather than read off the catalogs, so
/// a catalog cannot be lost, or arrive unread, without a check saying so (#1154).
/// </summary>
public class LocalizationCatalogTests
{
    private const string ResourcePrefix = "Jellyfin.Plugin.SSO_Auth.Localization.";
    private const string ResourceSuffix = ".json";
    private const string EnglishResource = ResourcePrefix + "en" + ResourceSuffix;

    // THE COMMITTED CULTURE SET, stated here and NOT derived from the catalogs on disk. The catalogs are
    // what these checks are about, so an expectation read out of them would be deleted along with the file
    // it was meant to protect, and the suite would stay green through the loss. A culture belongs on this
    // list once a person has read its catalog (#1154), so the list grows by a change that adds a name here
    // beside the file, never by a file arriving on its own.
    private static readonly string[] CommittedCultures = ["de", "en"];

    // Any type in the plugin assembly anchors GetManifestResourceStream to the resource-bearing assembly.
    private static readonly Assembly PluginAssembly = typeof(SsoLocalizer).Assembly;

    private static IEnumerable<string> CatalogResources() =>
        PluginAssembly.GetManifestResourceNames()
            .Where(name => name.StartsWith(ResourcePrefix, System.StringComparison.Ordinal)
                && name.EndsWith(ResourceSuffix, System.StringComparison.Ordinal));

    // The placeholder form i18n.js substitutes in format(): /\{(\w+)\}/g.
    private static readonly Regex PlaceholderPattern = new(@"\{(?<name>\w+)\}", RegexOptions.Compiled);

    // `data-i18n="key"` and the allowlisted attribute form `data-i18n-title="key"`.
    private static readonly Regex MarkupKeyPattern = new(@"data-i18n(?:-[a-z-]+)?=""(?<key>[^""]+)""", RegexOptions.Compiled);

    // A key a script names, in the two call shapes plus the DECLARED one (#1602). The lookbehind keeps
    // t("key", …) / tr("key", …) off identifiers that merely end in t (parseInt(…)). The provider templates
    // are object literals built when the module loads, before the localization module has resolved, so a
    // call there would freeze the English default into the object for the life of the page. Each template
    // carries its key beside the English instead - `noteKey` next to `note` - and the lookup happens where
    // the template is rendered, which is a reference this pattern has to be able to see.
    private static readonly Regex ScriptKeyPattern = new(
        @"(?<![A-Za-z0-9_.])tr?\(\s*""(?<key>[^""]+)""" +
        @"|\w+Key\s*:\s*""(?<key>[a-z0-9_]+\.[a-z0-9_.]+)""",
        RegexOptions.Compiled);

    // The inline English default each script call carries: tr("key", "English", …) puts it second, while
    // t("key", params, "English") puts it third (after a params object or `undefined`). The declared shape
    // puts it in the property beside the key, and it is included here rather than left out: the default is
    // a second copy of the wording wherever it lives, and the drift this rule exists to refuse does not
    // care which shape carried it.
    private static readonly Regex ScriptDefaultPattern = new(
        @"(?<![A-Za-z0-9_.])(?:tr\(\s*""(?<key>[^""]+)""\s*,\s*""(?<english>[^""]*)""" +
        @"|t\(\s*""(?<key>[^""]+)""\s*,\s*(?:\{[^}]*\}|undefined)\s*,\s*""(?<english>[^""]*)"")" +
        @"|\w+Key\s*:\s*""(?<key>[a-z0-9_]+\.[a-z0-9_.]+)""\s*,\s*\w+\s*:\s*""(?<english>[^""]*)""",
        RegexOptions.Compiled);

    // A marked element's built-in text: everything from the marker's closing '>' to the next tag. Prettier
    // may put the '>' on its own line and split the closing tag, so the text is whitespace-collapsed before
    // it is compared.
    private static readonly Regex MarkupTextPattern = new(@"data-i18n=""(?<key>[^""]+)""[^>]*>(?<text>[^<]*)<", RegexOptions.Compiled);

    // A text-marked element together with its tag name, so the element's own content can be located.
    private static readonly Regex MarkedElementPattern = new(@"<(?<tag>[a-z0-9]+)(?:\s[^>]*?)?\sdata-i18n=""(?<key>[^""]+)""[^>]*>", RegexOptions.Compiled);

    // A parts-marked element together with its tag name (#1529). Same shape as the text marker above; the
    // content behind it is walked rather than matched, because a sentence that holds markup is exactly the
    // case `[^<]*` cannot describe.
    private static readonly Regex PartsElementPattern = new(@"<(?<tag>[a-z0-9]+)(?:\s[^>]*?)?\sdata-i18n-parts=""(?<key>[^""]+)""[^>]*>", RegexOptions.Compiled);

    // Any tag, so the content of a parts element can be walked with a depth counter.
    private static readonly Regex AnyTagPattern = new(@"<(?<closing>/?)(?<tag>[a-z0-9]+)(?<attrs>[^>]*?)(?<selfClosing>/?)>", RegexOptions.Compiled);

    // The elements that never close, so a walk must not expect a closing tag for them.
    private static readonly string[] VoidElements = ["br", "hr", "img", "input", "link", "meta", "wbr", "source", "area", "base", "col", "embed", "param", "track"];

    // A numbered slot in a parts value, which is what distinguishes one from an ordinary catalog entry.
    private static readonly Regex PlaceholderIndexPattern = new(@"\{(?<index>\d+)\}", RegexOptions.Compiled);

    // A script element with its content, so markup can be inspected without reading JavaScript.
    private static readonly Regex ScriptBlockPattern = new(@"<script\b[^>]*>.*?</script>", RegexOptions.Compiled | RegexOptions.Singleline | RegexOptions.IgnoreCase);

    // A `${…}` template placeholder of the shape the upstream markup used for its own substitution pass.
    private static readonly Regex TemplatePlaceholderPattern = new(@"\$\{[^}]*\}", RegexOptions.Compiled);

    // The catalog namespaces the web assets own; everything else is server-side (see the orphan test).
    private static readonly string[] UiKeyPrefixes = ["config.", "link."];

    private const string ResourcePrefixWeb = "Jellyfin.Plugin.SSO_Auth.Web.";

    private static string CollapseWhitespace(string text) => Regex.Replace(text, @"\s+", " ").Trim();

    /*
     * Turns the named entities this markup uses into the characters a browser would show.
     *
     * The catalogs hold TEXT, because the applier writes through createTextNode and a catalog row saying
     * `&mdash;` would put those eight characters on the screen. The markup holds ENTITIES, because that is
     * how an em dash has always been written here. So the two are only comparable once one side is
     * decoded, and decoding the markup is the side that does not change what ships.
     *
     * `&amp;` is decoded LAST and that order is the whole correctness of this: decoding it first would
     * turn `&amp;lt;` into `&lt;` and then into `<`, inventing markup out of text that said the opposite.
     * The table is the five entities these templates actually use rather than a general decoder, because a
     * general one is a dependency and a wrong general one is worse than none.
     */
    private static string DecodeEntities(string text) => text
        .Replace("&lt;", "<", System.StringComparison.Ordinal)
        .Replace("&gt;", ">", System.StringComparison.Ordinal)
        .Replace("&mdash;", "—", System.StringComparison.Ordinal)
        .Replace("&rarr;", "→", System.StringComparison.Ordinal)
        .Replace("&amp;", "&", System.StringComparison.Ordinal);

    /*
     * Reads a parts element the way `applyParts` in i18n.js sees it, and reports what it found.
     *
     * The assembled string is what the catalog value has to equal: every direct child element becomes
     * `{n}` in document order, and the text between them is kept with its whitespace collapsed. The whole
     * result is trimmed, because the markup's own indentation before the first child and after the last is
     * not part of the sentence.
     *
     * `nested` names a direct child that itself contains an element. Such a child is not wrong for the
     * APPLIER - it moves whole nodes and never looks inside one - but it is wrong for a translator, who
     * gets a slot whose content they cannot see and cannot reorder within. The rule below refuses it, and
     * this walk is what lets it say which child.
     */
    private static (string Assembled, int Slots, List<string> Nested) AssembleParts(string content, int contentStart, string outerTag)
    {
        var assembled = new System.Text.StringBuilder();
        var nested = new List<string>();
        var depth = 0;
        var slots = 0;
        var at = contentStart;
        string? openChild = null;

        foreach (Match tag in AnyTagPattern.Matches(content, contentStart))
        {
            if (depth == 0)
            {
                assembled.Append(Regex.Replace(content[at..tag.Index], @"\s+", " "));
            }

            at = tag.Index + tag.Length;
            var name = tag.Groups["tag"].Value;
            var closing = tag.Groups["closing"].Value.Length > 0;
            var selfClosing = tag.Groups["selfClosing"].Value.Length > 0 || VoidElements.Contains(name);

            if (closing)
            {
                if (depth == 0)
                {
                    // The outer element's own closing tag: the content ends here.
                    Assert.Equal(outerTag, name);
                    break;
                }

                depth--;
                if (depth == 0)
                {
                    openChild = null;
                }
            }
            else if (selfClosing)
            {
                if (depth == 0)
                {
                    assembled.Append('{').Append(slots++).Append('}');
                }
            }
            else
            {
                if (depth == 0)
                {
                    assembled.Append('{').Append(slots++).Append('}');
                    openChild = name;
                }
                else if (openChild is not null)
                {
                    nested.Add(openChild);
                    openChild = null;
                }

                depth++;
            }
        }

        return (DecodeEntities(CollapseWhitespace(assembled.ToString())), slots, nested);
    }

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

        // `data-i18n-parts` borrows the SHAPE of an attribute marker and is not one: it names no attribute,
        // it is handled by its own branch of the applier, and the scan below would otherwise read it as a
        // request to localize an attribute called "parts" (#1529). Excluded here by name, and the gap that
        // opens is closed immediately afterwards rather than trusted: the branch that handles it must set no
        // attribute at all, and it must build nothing from the catalog except a text node.
        const string PartsMarker = "parts";
        var partsBranch = Regex.Match(applier, @"function applyParts\b(?<body>[\s\S]*?)\n\}");
        Assert.True(partsBranch.Success, "i18n.js must declare applyParts, which the parts marker is excluded on the strength of");
        Assert.DoesNotContain("setAttribute", partsBranch.Groups["body"].Value, System.StringComparison.Ordinal);
        Assert.DoesNotContain("innerHTML", partsBranch.Groups["body"].Value, System.StringComparison.Ordinal);
        Assert.Contains("createTextNode", partsBranch.Groups["body"].Value, System.StringComparison.Ordinal);

        var offenders = FirstPartyWebAssets()
            .SelectMany(resource => Regex.Matches(ReadResourceText(resource), @"data-i18n-(?<attr>[a-z-]+)=")
                .Select(match => match.Groups["attr"].Value)
                .Where(attribute => !allowed.Contains(attribute) && !string.Equals(attribute, PartsMarker, System.StringComparison.Ordinal))
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
            var builtIn = DecodeEntities(CollapseWhitespace(match.Groups["text"].Value));
            if (english.TryGetValue(key, out var catalogValue) && !string.Equals(catalogValue, builtIn, System.StringComparison.Ordinal))
            {
                mismatches.Add($"{resource}: '{key}' markup \"{builtIn}\" != catalog \"{catalogValue}\"");
            }
        }

        Assert.True(mismatches.Count == 0, "These built-in English strings have drifted from the catalog: " + string.Join(" | ", mismatches));
    }

    [Fact]
    public void PartsBuiltInEnglish_MatchesTheCatalogAndNamesEveryChild()
    {
        // A parts marker localizes a sentence that HOLDS markup, which the text marker above cannot: it
        // assigns textContent and would delete the `<code>` sample out of the middle of a sentence about
        // recovering from a lockout. So the catalog value carries `{0}`, `{1}` for the children and the
        // applier writes only the text between them (#1529).
        //
        // Three things have to hold, and all three are the same failure seen from different sides. The
        // assembled English must equal the catalog value, for the reason the text-marker rule states: the
        // markup's own English is the offline rendering and a drift means two readers see two sentences.
        // Every child must be named exactly once, because a value naming fewer leaves a `<code>` out of
        // the translated sentence and a value naming more asks for a node that does not exist - in both
        // cases applyParts refuses and the whole sentence silently stays English. And no child may itself
        // contain an element, because a slot a translator cannot see inside is a slot they cannot place.
        var english = ReadCatalog(EnglishResource);
        var problems = new List<string>();

        foreach (var (resource, content, match) in ScanHtmlAssets(PartsElementPattern, "parts-marker"))
        {
            var key = match.Groups["key"].Value;
            var (assembled, slots, nested) = AssembleParts(content, match.Index + match.Length, match.Groups["tag"].Value);

            if (nested.Count > 0)
            {
                problems.Add($"{resource}: '{key}' - the child <{string.Join(">, <", nested)}> holds markup of its own, so its slot cannot be read or placed by a translator");
            }

            if (!english.TryGetValue(key, out var catalogValue))
            {
                // Absence is the orphan check's finding, not this one's.
                continue;
            }

            if (!string.Equals(catalogValue, assembled, System.StringComparison.Ordinal))
            {
                problems.Add($"{resource}: '{key}' markup \"{assembled}\" != catalog \"{catalogValue}\"");
            }

            var named = PlaceholderIndexPattern.Matches(catalogValue).Select(m => int.Parse(m.Groups["index"].Value, System.Globalization.CultureInfo.InvariantCulture)).ToList();
            if (named.Count != slots || named.Distinct().Count() != slots || named.Any(index => index >= slots))
            {
                problems.Add($"{resource}: '{key}' has {slots} child element(s) and its catalog value names [{string.Join(", ", named)}], so applyParts would refuse it and the sentence would stay English");
            }
        }

        Assert.True(problems.Count == 0, "These parts markers do not describe the element they sit on: " + string.Join(" | ", problems));
    }

    [Fact]
    public void EveryNonEnglishCatalog_NamesTheSameSlotsAsTheEnglishOne()
    {
        // A translation may REORDER the slots - that is the point of the mechanism, since German does not
        // put the pieces of a sentence where English does - but it may not add, drop, or repeat one. Any of
        // those makes applyParts refuse, and a refusal leaves the reader with the English sentence while
        // every other string around it is translated, which reads as a bug in the page rather than in a
        // catalog row (#1529).
        var english = ReadCatalog(EnglishResource);
        var slotted = english
            .Where(entry => PlaceholderIndexPattern.IsMatch(entry.Value))
            .ToDictionary(entry => entry.Key, entry => PlaceholderIndexPattern.Matches(entry.Value).Select(m => m.Groups["index"].Value).OrderBy(index => index, System.StringComparer.Ordinal).ToList(), System.StringComparer.Ordinal);

        var problems = new List<string>();
        foreach (var culture in CommittedCultures.Where(name => !string.Equals(name, "en", System.StringComparison.Ordinal)))
        {
            var other = ReadCatalog(ResourcePrefix + culture + ResourceSuffix);
            foreach (var (key, indexes) in slotted)
            {
                if (!other.TryGetValue(key, out var value))
                {
                    // A missing key is the key-set rule's finding, not this one's.
                    continue;
                }

                var theirs = PlaceholderIndexPattern.Matches(value).Select(m => m.Groups["index"].Value).OrderBy(index => index, System.StringComparer.Ordinal).ToList();
                if (!theirs.SequenceEqual(indexes, System.StringComparer.Ordinal))
                {
                    problems.Add($"{culture}: '{key}' names [{string.Join(", ", theirs)}] where English names [{string.Join(", ", indexes)}]");
                }
            }
        }

        Assert.True(problems.Count == 0, "These translations do not name the same slots as the English value: " + string.Join(" | ", problems));
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
    public void ShippedMarkup_CarriesNoUnsubstitutedTemplatePlaceholder()
    {
        // `title="${Add}"` and `>${Help}</a>` sat in the configuration page, carried over from the upstream
        // markup and its substitution pass. Nothing on this side substitutes them, so the browser rendered
        // the literal text `${Add}` as a button tooltip and `${Help}` as a link label (#1011). Review does
        // not catch it because the shape reads like a binding some layer resolves, and the localization
        // scans above cannot see it either - an unmarked placeholder references no catalog key, so it is
        // invisible to every key-parity check. Scoped to the HTML assets, and to the markup OUTSIDE
        // <script>, because `${…}` inside a script is an ordinary JavaScript template literal and this rule
        // must not forbid one.
        var html = FirstPartyWebAssets()
            .Where(name => name.EndsWith(".html", System.StringComparison.Ordinal))
            .ToList();
        Assert.True(html.Count > 0, "no embedded HTML asset was found - the placeholder scan would pass without inspecting anything");

        var offenders = html
            .SelectMany(resource => TemplatePlaceholderPattern
                .Matches(ScriptBlockPattern.Replace(ReadResourceText(resource), string.Empty))
                .Select(match => $"{resource}: {match.Value}"))
            .ToList();

        Assert.True(offenders.Count == 0, "These template placeholders reach the browser as literal text: " + string.Join(" | ", offenders));
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

    [Fact]
    public void EveryCommittedCulture_ShipsACatalog()
    {
        var shipped = CatalogResources().ToHashSet(System.StringComparer.Ordinal);

        var absent = CommittedCultures
            .Select(culture => ResourcePrefix + culture + ResourceSuffix)
            .Where(resource => !shipped.Contains(resource))
            .ToList();

        Assert.True(absent.Count == 0, "committed cultures shipping no catalog: " + string.Join(", ", absent));
    }

    [Fact]
    public void EveryShippedCatalog_IsACommittedCulture()
    {
        var committed = CommittedCultures
            .Select(culture => ResourcePrefix + culture + ResourceSuffix)
            .ToHashSet(System.StringComparer.Ordinal);

        var undeclared = CatalogResources()
            .Where(resource => !committed.Contains(resource))
            .ToList();

        Assert.True(undeclared.Count == 0, "catalogs no one is recorded as having read: " + string.Join(", ", undeclared));
    }

    [Fact]
    public void TheLocalizer_LoadsExactlyTheCommittedCultures()
    {
        // The two checks above read the embedded RESOURCE. SsoLocalizer skips a catalog that is not a flat
        // string→string map, so a file can be shipped, pass both of them, and still not exist at runtime -
        // its keys silently fall through the chain to English. This is the same set seen from the side the
        // served surfaces actually use.
        Assert.Equal(
            CommittedCultures.OrderBy(culture => culture, System.StringComparer.Ordinal).ToList(),
            SsoLocalizer.AvailableCultures.OrderBy(culture => culture, System.StringComparer.Ordinal).ToList());
    }

    [Fact]
    public void EveryNonEnglishCatalog_CarriesTheEnglishPlaceholdersPerKey()
    {
        // i18n.js substitutes `{name}` from a params object and leaves an unknown name verbatim, so a
        // translation that drops a placeholder loses the value it was carrying and one that renames it
        // prints the brace form at the user. Neither is a missing key, so the key-set guard cannot see it.
        var english = ReadCatalog(EnglishResource);
        var faults = new List<string>();

        foreach (var resource in CatalogResources().Where(name => name != EnglishResource))
        {
            foreach (var entry in ReadCatalog(resource))
            {
                if (!english.TryGetValue(entry.Key, out var englishValue))
                {
                    // An orphan key is the key-set guard's finding; reporting it twice hides this one.
                    continue;
                }

                var expected = Placeholders(englishValue);
                var actual = Placeholders(entry.Value);
                if (!expected.SetEquals(actual))
                {
                    faults.Add(
                        $"{resource}: key '{entry.Key}' carries [{string.Join(",", actual.Order(System.StringComparer.Ordinal))}]"
                        + $", English carries [{string.Join(",", expected.Order(System.StringComparer.Ordinal))}]");
                }
            }
        }

        Assert.True(faults.Count == 0, "placeholder drift: " + string.Join(" | ", faults));
    }

    private static HashSet<string> Placeholders(string value) =>
        PlaceholderPattern.Matches(value)
            .Select(match => match.Groups["name"].Value)
            .ToHashSet(System.StringComparer.Ordinal);
}
