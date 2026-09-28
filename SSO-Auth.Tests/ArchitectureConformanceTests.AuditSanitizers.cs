// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <content>
/// Conformance rules for the two inline log sanitizers. The first (#1555) is the audit emitter's: every
/// foreign value the audit trail prints carries BOTH of them, spelled out at the logging call. The second
/// (#1557) is the log FILE's: every foreign value ANY logging call in the plugin prints carries both, so
/// no ordinary line can hand an unanchored search a record the audit emitter never wrote. The handful of
/// values that deliberately carry only the line-ending strip are named here rather than being noticed as
/// an absence.
/// </content>
public partial class ArchitectureConformanceTests
{
    // Lines this plugin composed for itself, where the exact text is the actionable content and no untrusted
    // party can write it; composedRefusal is the sentence whose foreign parts were already substituted where
    // they entered it, so substituting it whole would rewrite the plugin own truncation marker (#1566).
    private static readonly string[] AuditValuesPrintedExactly =
    {
        "configurationFilePath",
        "preservedCopyPath",
        "markerPath",
        "source",
        "sourcePath",
        "installLocations",
        "composedRefusal",
    };

    private const string LineEndingSanitizer = "ReplaceLineEndings(string.Empty)";
    private const string RecordMarkerSanitizer = "Replace('[', '(')";

    [Fact]
    public void EveryForeignValueTheAuditTrailPrints_CarriesBothInlineSanitizers()
    {
        // A conformance rule rather than a row per emitter, because a payload-driven test reaches two or three
        // of around 68 sanitized arguments and the rest could lose the substitution with the suite green
        // (#1555). It reads the source, because the sanitizer cs/log-forging can see is the one written inline
        // in the argument list, and a helper doing the same work would satisfy reflection while breaking that.
        // The emitter is one partial class over several files, so every SsoAudit file is read.
        var sanitizedLines = Directory
            .EnumerateFiles(Path.Combine(RepoTree.Root, "SSO-Auth", "Api", "Audit"), "SsoAudit*.cs")
            .Order(StringComparer.Ordinal)
            .SelectMany(path => File.ReadLines(path)
                .Select((line, index) => (File: Path.GetFileName(path), Line: line, Number: index + 1)))
            .Where(l => l.Line.Contains(LineEndingSanitizer, StringComparison.Ordinal))
            .ToList();
        var offenders = new List<string>();

        foreach (var (file, line, lineNumber) in sanitizedLines)
        {
            var exempt = AuditValuesPrintedExactly.Any(value =>
                line.Contains(value + "?." + LineEndingSanitizer, StringComparison.Ordinal)
                || line.Contains(value + "." + LineEndingSanitizer, StringComparison.Ordinal));

            var substituted = line.Contains(LineEndingSanitizer + "." + RecordMarkerSanitizer, StringComparison.Ordinal);

            if (exempt == substituted)
            {
                offenders.Add(
                    file + ":" + lineNumber.ToString(System.Globalization.CultureInfo.InvariantCulture)
                    + (exempt
                        ? " prints a value this rule names as printed exactly, and substitutes its bracket anyway"
                        : " sanitizes a foreign value's line endings without substituting its record-marker bracket")
                    + ": " + line.Trim());
            }
        }

        Assert.True(
            offenders.Count == 0,
            "Every foreign value SsoAudit prints carries the line-ending strip AND the record-marker "
            + "substitution, inline at the logging call (#1555); the values printed exactly are named in "
            + "AuditValuesPrintedExactly and carry only the first. These lines break that: "
            + string.Join(" | ", offenders));
    }

    [Fact]
    public void TheAuditEmitter_IsTheOnlyPlaceThatWritesTheRecordMarker()
    {
        // The substitution is only worth anything while ONE emitter, the SsoAudit partials, can write the marker: a second writer with
        // a foreign value in its template would reopen the hole from a direction this rule cannot see. The
        // marker WAS plantable through ordinary plugin log lines that are not audit entries at all, which
        // #1557 closed with the tree-wide rule below rather than with this one - but a second EMITTER of the
        // marker itself is this rule's subject, because it would be claiming to be the audit trail.
        var sources = Directory
            .EnumerateFiles(Path.Combine(RepoTree.Root, "SSO-Auth"), "*.cs", SearchOption.AllDirectories)
            .Where(file => File.ReadAllText(file).Contains("\"[SSO Audit] ", StringComparison.Ordinal))
            .Select(file => Path.GetRelativePath(RepoTree.Root, file).Replace(Path.DirectorySeparatorChar, '/'))
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        Assert.Equal(
            new[]
            {
                "SSO-Auth/Api/Audit/SsoAudit.Accounts.cs",
                "SSO-Auth/Api/Audit/SsoAudit.Configuration.cs",
                "SSO-Auth/Api/Audit/SsoAudit.Links.cs",
                "SSO-Auth/Api/Audit/SsoAudit.Logout.cs",
                "SSO-Auth/Api/Session/SsoOnlyReconciliationService.cs",
            },
            sources);
    }

    [Fact]
    public void EveryForeignValueAnyPluginLogLinePrints_CarriesBothInlineSanitizers()
    {
        // #1557. The emitter rule above makes the audit entries sound; an ordinary plugin line carrying a
        // foreign value under the line-ending strip alone still hands an unanchored search a forged record, and
        // the OpenID callback error_description is reachable with no credential. So the rule holds over every
        // logging call: each strip carries the bracket substitution behind it, the population is derived from
        // the source, and the exact-print exemption is the emitter list. A value logged with no sanitizer at
        // all is cs/log-forging subject rather than this rule. Why the residual is not closed by widening it,
        // with the census: <see href="https://github.com/Flowfin/jellyfin-plugin-sso/issues/1564"/>.
        var offenders = new List<string>();
        var strips = 0;

        foreach (var file in Directory.EnumerateFiles(Path.Combine(RepoTree.Root, "SSO-Auth"), "*.cs", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(RepoTree.Root, file).Replace(Path.DirectorySeparatorChar, '/');
            if (relative.StartsWith("SSO-Auth/bin/", StringComparison.Ordinal) || relative.StartsWith("SSO-Auth/obj/", StringComparison.Ordinal))
            {
                continue;
            }

            var text = File.ReadAllText(file);
            var spans = LoggingCallSpans(text);
            var at = 0;
            while ((at = text.IndexOf(LineEndingSanitizer, at, StringComparison.Ordinal)) >= 0)
            {
                var end = at + LineEndingSanitizer.Length;
                var start = at;
                if (spans.Any(span => start > span.Start && start < span.End))
                {
                    strips++;
                    var receiver = text[Math.Max(0, start - 40)..start];
                    var exempt = AuditValuesPrintedExactly.Any(value => IsWholeReceiver(receiver, value));
                    var substituted = string.CompareOrdinal(text, end, "." + RecordMarkerSanitizer, 0, RecordMarkerSanitizer.Length + 1) == 0;

                    if (exempt == substituted)
                    {
                        var lineNumber = text.AsSpan(0, start).Count('\n') + 1;
                        offenders.Add(
                            relative + ":" + lineNumber.ToString(System.Globalization.CultureInfo.InvariantCulture)
                            + (exempt
                                ? " prints a value this rule names as printed exactly, and substitutes its bracket anyway"
                                : " logs a foreign value with the line-ending strip alone"));
                    }
                }

                at = end;
            }
        }

        // Sentinel against a vacuous pass: the scan must still be finding the emitter's own arguments, or the
        // span walker has stopped recognising logging calls and every file passes for the wrong reason.
        Assert.True(strips > 100, "The logging-call scan found only " + strips.ToString(System.Globalization.CultureInfo.InvariantCulture) + " sanitized arguments; it has stopped seeing the calls it exists to judge.");

        Assert.True(
            offenders.Count == 0,
            "Every foreign value ANY plugin log line prints carries the line-ending strip AND the record-marker "
            + "substitution, inline at the logging call (#1557); the values printed exactly are named in "
            + "AuditValuesPrintedExactly and carry only the first. These lines break that: "
            + string.Join(" | ", offenders));
    }

    /// <summary>
    /// Whether the text before a sanitizer ends in exactly <paramref name="value"/> as a whole identifier
    /// followed by <c>.</c> or <c>?.</c>. A plain suffix test would also exempt <c>someResource.</c> for the
    /// value <c>source</c>, in the direction that lets a strip-alone value pass.
    /// </summary>
    private static bool IsWholeReceiver(string receiver, string value)
    {
        foreach (var access in new[] { "?.", "." })
        {
            var suffix = value + access;
            if (receiver.EndsWith(suffix, StringComparison.Ordinal))
            {
                var before = receiver.Length - suffix.Length - 1;
                return before < 0 || !(char.IsLetterOrDigit(receiver[before]) || receiver[before] == '_');
            }
        }

        return false;
    }

    /// <summary>
    /// The character ranges of every <c>.Log&lt;Level&gt;(...)</c> and bare <c>.Log(...)</c> argument list in a
    /// source text, found by walking from the opening parenthesis to its match while skipping string literals,
    /// character literals and both comment forms, so a parenthesis inside a message template or a remark does
    /// not end the span early.
    /// </summary>
    private static List<(int Start, int End)> LoggingCallSpans(string text)
    {
        var spans = new List<(int Start, int End)>();
        foreach (Match call in Regex.Matches(text, @"\.Log(Trace|Debug|Information|Warning|Error|Critical)?\s*\("))
        {
            var i = call.Index + call.Length;
            var depth = 1;
            while (i < text.Length && depth > 0)
            {
                var c = text[i];
                if (c == '"')
                {
                    var verbatim = i > 0 && (text[i - 1] == '@' || (i > 1 && text[i - 1] == '$' && text[i - 2] == '@'));
                    i++;
                    while (i < text.Length)
                    {
                        if (text[i] == '\\' && !verbatim)
                        {
                            i += 2;
                            continue;
                        }

                        if (text[i] == '"')
                        {
                            if (verbatim && i + 1 < text.Length && text[i + 1] == '"')
                            {
                                i += 2;
                                continue;
                            }

                            break;
                        }

                        i++;
                    }

                    i++;
                    continue;
                }

                if (c == '\'')
                {
                    i++;
                    while (i < text.Length && text[i] != '\'')
                    {
                        i += text[i] == '\\' ? 2 : 1;
                    }

                    i++;
                    continue;
                }

                if (c == '/' && i + 1 < text.Length && text[i + 1] == '/')
                {
                    while (i < text.Length && text[i] != '\n')
                    {
                        i++;
                    }

                    continue;
                }

                if (c == '/' && i + 1 < text.Length && text[i + 1] == '*')
                {
                    var close = text.IndexOf("*/", i + 2, StringComparison.Ordinal);
                    i = close < 0 ? text.Length : close + 2;
                    continue;
                }

                depth += c == '(' ? 1 : c == ')' ? -1 : 0;
                i++;
            }

            spans.Add((call.Index, i));
        }

        return spans;
    }
}
