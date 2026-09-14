// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using Jellyfin.Plugin.SSO_Auth.Api.Localization;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <content>
/// Conformance rules for the Test-connection verdict (#1728): the probe answers with catalogue keys and never
/// with prose, and the key vocabulary and the catalogues name exactly the same rows.
/// </content>
public partial class ArchitectureConformanceTests
{
    // The files that build a Test-connection result: the probe, and the result vocabulary beside it. A verdict
    // added as a sentence would be written in one of these, so these are the ones read.
    private static readonly string[] TestVerdictSources =
    [
        "SSO-Auth/Api/Http/ProviderConnectionTester.cs",
        "SSO-Auth/Api/Provider/ProviderTestResult.cs",
        "SSO-Auth/Api/Provider/ProviderTestFact.cs",
        "SSO-Auth/Api/Provider/ProviderTestKeys.cs",
    ];

    // A double-quoted literal with its escapes, interpolated or verbatim included. The prose shape is a space
    // inside it: a catalogue key, a format specifier and a JSON member name carry none, and every sentence does.
    private static readonly Regex TestVerdictLiteral = new(@"\$?@?""(?:[^""\\]|\\.)*""", RegexOptions.Compiled);

    // The catalogue namespace the probe's vocabulary owns; the UI-side rules leave it to this one.
    private const string TestVerdictNamespace = "test.";

    [Fact]
    public void TheTestConnectionProbe_AnswersWithCatalogueKeysAndNeverWithProse()
    {
        // #1728. The verdict of a Test Connection is built on the other side of an HTTP call, so no scan of the
        // browser bundle can see it: tools/ui-untranslated.js reads the web sources, and a sentence the server
        // returns is never in them. That is how the verdict stayed English on a German dashboard while every
        // localization gate was green, and it is the shape that would keep surviving - every verdict string the
        // tester adds is invisible to the gate that guards the page. This is the gate on the server side of the
        // call: a literal with a space in it, in any of the files that build the result, is refused. Comments are
        // stripped first, because these files carry paragraphs of reasoning with sentences in them.
        var offenders = new List<string>();
        foreach (var relative in TestVerdictSources)
        {
            var source = WithoutCSharpComments(File.ReadAllText(Path.Combine(RepoTree.Root, relative)));
            offenders.AddRange(
                TestVerdictLiteral.Matches(source)
                    .Select(literal => literal.Value)
                    .Where(literal => literal.Contains(' ', StringComparison.Ordinal))
                    .Select(literal => relative + ": " + literal));
        }

        Assert.True(
            offenders.Count == 0,
            "The Test-connection probe answers with catalogue keys, never with a sentence: the page renders a key in the administrator's language and a sentence built here would be English on every dashboard (#1728). Add a row to en.json and de.json and a constant to ProviderTestKeys instead. Prose literals: " + string.Join(" | ", offenders));
    }

    [Fact]
    public void EveryTestConnectionKey_IsARowInEveryCatalogue_AndEveryTestRowIsAKey()
    {
        // #1728, both directions. A constant the catalogue does not carry would render on the page as its own
        // key - visible rather than blank, but wrong - and a test.* row no constant names is dead data a
        // translator still has to carry. The UI-side reference rules in LocalizationCatalogTests cover the
        // config.* and link.* namespaces by scanning the web assets for literal keys; the probe's keys are
        // chosen by the server and reach the page as data, so no scan of the assets can see them, and this
        // pin holds the vocabulary to the catalogue by reflection instead. Every non-English catalogue must
        // carry a row that DIFFERS from the English one: the localizer falls back to English for a missing
        // row, so an equal string is a row nobody translated wearing the clothes of one.
        var constants = typeof(ProviderTestKeys)
            .GetFields(BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static)
            .Where(field => field.IsLiteral && field.FieldType == typeof(string))
            .Select(field => (string)field.GetRawConstantValue()!)
            .OrderBy(key => key, StringComparer.Ordinal)
            .ToList();

        Assert.True(constants.Count >= 20, $"The reflection over ProviderTestKeys found only {constants.Count} constants; it has stopped seeing the vocabulary and this rule would pass over nothing.");
        Assert.All(constants, key => Assert.StartsWith(TestVerdictNamespace, key, StringComparison.Ordinal));

        var otherCultures = SsoLocalizer.AvailableCultures
            .Where(culture => !string.Equals(culture, SsoLocalizer.FallbackCulture, StringComparison.Ordinal))
            .ToList();
        Assert.NotEmpty(otherCultures);

        var missing = new List<string>();
        foreach (var key in constants)
        {
            var english = SsoLocalizer.GetString(key, SsoLocalizer.FallbackCulture);
            if (string.Equals(english, key, StringComparison.Ordinal))
            {
                missing.Add(SsoLocalizer.FallbackCulture + ": " + key);
            }

            foreach (var culture in otherCultures)
            {
                var translated = SsoLocalizer.GetString(key, culture);
                if (string.Equals(translated, key, StringComparison.Ordinal) || string.Equals(translated, english, StringComparison.Ordinal))
                {
                    missing.Add(culture + ": " + key);
                }
            }
        }

        Assert.True(missing.Count == 0, "These Test-connection keys have no translated row (the localizer would fall back to English or to the key itself): " + string.Join(", ", missing));

        var orphans = SsoLocalizer.ResolvedCatalog(SsoLocalizer.FallbackCulture).Keys
            .Where(key => key.StartsWith(TestVerdictNamespace, StringComparison.Ordinal))
            .Except(constants, StringComparer.Ordinal)
            .OrderBy(key => key, StringComparer.Ordinal)
            .ToList();

        Assert.True(orphans.Count == 0, "These test.* catalogue rows are named by no ProviderTestKeys constant, so nothing can ever render them: " + string.Join(", ", orphans));
    }

    // Replaces comment CONTENT with spaces, keeping every line and column in place, and walks string and
    // character literals so a `//` inside one is not read as a comment. Verbatim strings double their quotes
    // and ordinary ones escape with a backslash; both are honoured so a literal cannot end early.
    private static string WithoutCSharpComments(string source)
    {
        var output = new StringBuilder(source.Length);
        var index = 0;
        while (index < source.Length)
        {
            var current = source[index];
            if (current == '"' || current == '\'')
            {
                var verbatim = current == '"' && index > 0 && source[index - 1] == '@';
                output.Append(current);
                index++;
                while (index < source.Length)
                {
                    var next = source[index];
                    output.Append(next);
                    index++;
                    if (next == '\\' && !verbatim && index < source.Length)
                    {
                        output.Append(source[index]);
                        index++;
                        continue;
                    }

                    if (next == current)
                    {
                        if (verbatim && index < source.Length && source[index] == '"')
                        {
                            output.Append('"');
                            index++;
                            continue;
                        }

                        break;
                    }
                }

                continue;
            }

            if (current == '/' && index + 1 < source.Length && source[index + 1] == '/')
            {
                while (index < source.Length && source[index] != '\n')
                {
                    output.Append(' ');
                    index++;
                }

                continue;
            }

            if (current == '/' && index + 1 < source.Length && source[index + 1] == '*')
            {
                output.Append("  ");
                index += 2;
                while (index < source.Length && !(source[index] == '*' && index + 1 < source.Length && source[index + 1] == '/'))
                {
                    output.Append(source[index] == '\n' ? '\n' : ' ');
                    index++;
                }

                output.Append("  ");
                index += 2;
                continue;
            }

            output.Append(current);
            index++;
        }

        return output.ToString();
    }
}
