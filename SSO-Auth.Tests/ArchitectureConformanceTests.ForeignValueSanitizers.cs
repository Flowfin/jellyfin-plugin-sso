// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <content>
/// Conformance rule for the record-marker substitution EVERYWHERE ELSE (#1557). Its sibling rule holds the
/// audit emitter to it; this one holds every other file the plugin logs from, because the thing an operator
/// searches is the log FILE and a forged record planted through an ordinary warning reads exactly like one
/// planted through an audit entry.
/// </content>
public partial class ArchitectureConformanceTests
{
    // The values printed EXACTLY outside the audit emitter, for the same reason the emitter has its own
    // list: the plugin composed them for itself, no untrusted party can write one, and the exact text is
    // the actionable content of the line. A mounted declarative source is named so an operator can go and
    // edit that document; a path with a substituted bracket is a path that does not exist. The identifier
    // is matched with its receiver dot, and the rule requires an exempt value to carry NO substitution -
    // the half the exemption exists for.
    private static readonly string[] ForeignValueExemptions =
    {
        "sourcePath",
    };

    // The SENTENCES this plugin composed, whose foreign parts are substituted where those parts enter the
    // sentence rather than over the whole of it. Substituting a composed message rewrites the plugin's own
    // words alongside the foreign ones - it took an opening bracket out of the very message that lists the
    // characters a provider name may not contain, and it rewrote the path in the line telling an operator
    // which mounted document to edit. So these lines strip and do not substitute, on purpose, and each one
    // is only correct because something upstream already substituted: the validator echoes, LinkImport's
    // entry description, OidcConfiguredIssuer's echo, and the two refusal composers below.
    private static readonly string[] ComposedMessages =
    {
        "ex.Message?.",
        "ex.Message.",
    };

    // The same class one step further: a sentence built by a named helper on the same line, where the
    // helper substitutes the foreign parts it is handed.
    private static readonly string[] ComposedByHelper =
    {
        "ManagedProviderRefusal(",
        "ManagedProfileRefusal(",
    };

    // The files this rule does NOT read, each for a reason that is not "it would fail".
    private static readonly string[] SanitizerRuleSkips =
    {
        // The emitter has its own rule, with its own exemption list and its own adjacency requirement.
        "SSO-Auth/Api/Audit/SsoAudit.cs",
    };

    [Fact]
    public void EveryForeignValueThePluginLogs_CarriesTheRecordMarkerSubstitution()
    {
        // WHY A RULE AND NOT ROWS. #1555 made the audit emitter unable to print a foreign value that
        // reproduces "[SSO Audit] ". It did not reach the ninety-odd other places this plugin puts an
        // identity-provider- or request-supplied value into a log line under the line-ending strip alone,
        // and the marker survives verbatim in every one of them - so an unanchored search over the log file
        // still reports a login that never happened. Driving each site with a forging payload is worth
        // doing and is done for the sites an attacker reaches cheapest; it cannot be the thing that holds
        // the property, because the ninety-first site added next month would arrive unguarded with the
        // whole suite green. That is the state #1555 found the emitter in.
        //
        // IT READS THE SOURCE for the same reason its sibling does: the property is that the expression is
        // written inline in the argument, which is the form CodeQL's cs/log-forging taint tracking can
        // follow. A compiled method body cannot answer that, and a helper doing the same work would satisfy
        // reflection while breaking the shape the repository keeps this for.
        //
        // IT PAIRS RATHER THAN COUNTS PRESENCE. A line routinely prints several foreign values, so one of
        // them losing its substitution hides behind its neighbours under any check that asks only whether
        // the substitution appears somewhere on the line. That is not hypothetical - it is how the first
        // version of this rule passed a mutation that took the substitution off the OpenID callback's
        // error_description, which shares its line with the provider and the error code. So the strip is
        // required to be IMMEDIATELY FOLLOWED by the substitution, and the two counts must be equal.
        //
        // WHAT IT STILL CANNOT SEE, stated rather than left to be discovered: a foreign value logged with
        // NO strip at all is invisible to it, because the strip is what it keys on. Two such values were
        // found by hand while this rule was being written - the repeated-member name, neutralised by a
        // character-category filter instead, and the configured default provider, which carried neither
        // sanitizer - and both are fixed here. A THIRD, added tomorrow, would pass. That gap is #1564.
        var offenders = new List<string>();

        foreach (var file in Directory
            .EnumerateFiles(Path.Combine(RepoTree.Root, "SSO-Auth"), "*.cs", SearchOption.AllDirectories)
            .Where(file => !IsGenerated(file))
            .OrderBy(name => name, StringComparer.Ordinal))
        {
            var relative = Path.GetRelativePath(RepoTree.Root, file).Replace(Path.DirectorySeparatorChar, '/');
            if (SanitizerRuleSkips.Contains(relative, StringComparer.Ordinal))
            {
                continue;
            }

            offenders.AddRange(LineOffenders(relative, File.ReadLines(file)));
        }

        Assert.True(
            offenders.Count == 0,
            "Every identity-provider- or request-supplied value this plugin puts in a log line carries the "
            + "record-marker substitution immediately after the line-ending strip, inline in the argument "
            + "(#1557); the values printed exactly are named in ForeignValueExemptions and carry neither "
            + "more nor less. These lines break that: " + string.Join(" | ", offenders));
    }

    private static IEnumerable<string> LineOffenders(string relative, IEnumerable<string> lines)
    {
        var lineNumber = 0;
        foreach (var line in lines)
        {
            lineNumber++;

            // A comment discussing either sanitizer is prose about the rule, not a subject of it. This file
            // and the ones it judges talk about these expressions constantly, and a rule that made a
            // sentence unwritable would be repaired by weakening it.
            var code = line.TrimStart();
            if (code.StartsWith("//", StringComparison.Ordinal))
            {
                continue;
            }

            var stripped = Occurrences(line, LineEndingSanitizer);
            if (stripped == 0)
            {
                continue;
            }

            // A value printed exactly is exempt wherever it strips; a composed message is exempt only on the
            // strip that is NOT followed by a substitution, so a line mixing one with an ordinary foreign
            // value still has to substitute the ordinary one.
            var exempt = ForeignValueExemptions.Sum(value =>
                Occurrences(line, value + "?." + LineEndingSanitizer)
                + Occurrences(line, value + "." + LineEndingSanitizer))
                + ComposedMessages.Sum(receiver =>
                    Occurrences(line, receiver + LineEndingSanitizer)
                    - Occurrences(line, receiver + LineEndingSanitizer + "." + RecordMarkerSanitizer))
                + ComposedByHelper.Sum(call => Occurrences(line, call));

            // The pair, not the substitution anywhere on the line.
            var paired = Occurrences(line, LineEndingSanitizer + "." + RecordMarkerSanitizer);
            if (paired == stripped - exempt)
            {
                continue;
            }

            yield return relative + ":" + lineNumber.ToString(CultureInfo.InvariantCulture)
                + " strips " + (stripped - exempt).ToString(CultureInfo.InvariantCulture)
                + " foreign value(s) and substitutes " + paired.ToString(CultureInfo.InvariantCulture)
                + " of them: " + line.Trim();
        }
    }

    // Generated sources are build state rather than authored code; a security gate whose input changes with
    // the last build is a gate nobody can read.
    private static bool IsGenerated(string file)
    {
        var path = file.Replace(Path.DirectorySeparatorChar, '/');
        return path.Contains("/obj/", StringComparison.Ordinal) || path.Contains("/bin/", StringComparison.Ordinal);
    }

    private static int Occurrences(string text, string needle)
    {
        var found = 0;
        var at = 0;
        while ((at = text.IndexOf(needle, at, StringComparison.Ordinal)) >= 0)
        {
            found++;
            at += needle.Length;
        }

        return found;
    }
}
