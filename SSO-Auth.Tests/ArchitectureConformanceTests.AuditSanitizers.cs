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
    // The values a line prints EXACTLY on purpose, because the plugin composed them for itself and the exact
    // text is the actionable content of the entry. The unreadable-configuration lines tell an operator which
    // file to move out of the way, and the declarative-write lines tell them which mounted document to edit;
    // a data directory whose name carries a bracket would otherwise be named as a path that does not exist,
    // in the one line written for a total lockout. No untrusted party can write any of them, so the bracket
    // substitution buys nothing here and costs the whole point of the line.
    //
    // composedRefusal is the one value of a different kind (#1566): a sentence this plugin composed whose
    // foreign parts were substituted where they entered it, in LinkImport.Describe and
    // OidcConfiguredIssuer.Echo. Substituting the sentence whole rewrote the plugin's own "[truncated]"
    // marker, so the log disagreed with the answer on the wire about one refusal.
    private static readonly string[] AuditValuesPrintedExactly =
    {
        "configurationFilePath",
        "preservedCopyPath",
        "markerPath",
        "source",
        "sourcePath",
        "composedRefusal",
    };

    private const string LineEndingSanitizer = "ReplaceLineEndings(string.Empty)";
    private const string RecordMarkerSanitizer = "Replace('[', '(')";

    [Fact]
    public void EveryForeignValueTheAuditTrailPrints_CarriesBothInlineSanitizers()
    {
        // The property this locks in is #1555's, and the reason it is a conformance rule rather than a row
        // per emitter is the count: the trail has ~30 entries and around 68 sanitized arguments, of which a
        // test driving a forging payload can realistically cover two or three. Everything else could lose
        // the substitution - or arrive without it, in an entry added next month - with the whole suite
        // green, which is precisely the state the issue found the file in for the line-ending strip's
        // younger sibling.
        //
        // It reads the SOURCE rather than reflecting over the assembly on purpose. The rule is about the
        // expression being written inline at the logging call, because the sanitizer that CodeQL's
        // cs/log-forging taint tracking can see is the one in the argument list; a compiled method body
        // cannot answer that question, and a helper doing the same work would satisfy reflection while
        // breaking the property the repo keeps this shape for.
        var path = Path.Combine(RepoTree.Root, "SSO-Auth", "Api", "Audit", "SsoAudit.cs");
        var offenders = new List<string>();

        var lineNumber = 0;
        foreach (var line in File.ReadLines(path))
        {
            lineNumber++;
            if (!line.Contains(LineEndingSanitizer, StringComparison.Ordinal))
            {
                continue;
            }

            var exempt = AuditValuesPrintedExactly.Any(value =>
                line.Contains(value + "?." + LineEndingSanitizer, StringComparison.Ordinal)
                || line.Contains(value + "." + LineEndingSanitizer, StringComparison.Ordinal));

            var substituted = line.Contains(LineEndingSanitizer + "." + RecordMarkerSanitizer, StringComparison.Ordinal);

            if (exempt == substituted)
            {
                offenders.Add(
                    "SsoAudit.cs:" + lineNumber.ToString(System.Globalization.CultureInfo.InvariantCulture)
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
        // The substitution is only worth anything while ONE file can write the marker: a second writer with
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
            new[] { "SSO-Auth/Api/Audit/SsoAudit.cs", "SSO-Auth/Api/Session/SsoOnlyReconciliationService.cs" },
            sources);
    }

    [Fact]
    public void EveryForeignValueAnyPluginLogLinePrints_CarriesBothInlineSanitizers()
    {
        // #1557. The emitter rule above makes the audit trail's OWN entries sound and stops there; the thing an
        // operator actually searches is the whole log file, and an ordinary plugin line carrying a foreign
        // value under the line-ending strip alone still hands an unanchored search a record the emitter never
        // wrote. The OpenID callback error is the one reachable without any credential: `error_description`
        // is attacker-chosen on a crafted redirect, and it was rendered verbatim on one physical line.
        //
        // The rule therefore holds over EVERY logging call in the plugin, not one file: inside a
        // `.Log<Level>(...)` argument list, each line-ending strip carries the bracket substitution right
        // behind it, so no line can be added next month with the older sibling alone. The population is
        // derived from the source rather than listed, and the exact-print exemption is the same list the
        // emitter rule uses, for the same reason: those are paths this server composed for itself.
        //
        // WHAT THE RULE CAN SEE IS THE VALUE ALREADY MARKED FOREIGN BY THE STRIP. A value logged with no
        // sanitizer at all is not this rule's subject and never was: that is CodeQL's cs/log-forging query,
        // which is why both sanitizers stay spelled out inline at the call rather than behind a helper.
        //
        // WHY THAT RESIDUAL IS NOT CLOSED BY WIDENING THIS RULE (#1564), measured rather than supposed. On 4.4
        // at 0c32770c the tree held 127 logging calls with 219 arguments past the template: 128 carried both
        // sanitizers, 16 the strip alone (every one of them named in AuditValuesPrintedExactly), and 71 neither.
        // Of the 71, every string-typed value is the plugin's own - a protocol label, a reason code, an enum
        // token, a constant sentence, an embedded resource path, a record whose ToString redacts itself - and
        // the rest are counts, booleans, Guids and durations. The one foreign value among them is the repeated
        // JSON member name in RepeatedMemberScreen, neutralised by hand and pinned by its own payload row. What
        // separates a constant label from a foreign name is the value's type and where it came from, and
        // neither is in the text of one argument, so a widened text rule would refuse the 71 and pass the
        // seventy-second the moment it looked like a label. A semantic pass could tell them apart, at the
        // cost of compiling the plugin inside this test; the population it would guard is a dozen
        // string-valued arguments, and that price was not paid. The census is reproduced by counting the
        // arguments inside LoggingCallSpans the way this rule does and sorting them by whether they contain
        // LineEndingSanitizer and RecordMarkerSanitizer; the classification of the 71 was by hand.
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
