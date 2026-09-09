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
    // edit that document; a path with a substituted bracket is a path that does not exist.
    private static readonly string[] ForeignValueExemptions =
    {
        "sourcePath",
    };

    // The files this rule does NOT read line by line, each for a reason that is not "it would fail".
    private static readonly string[] SanitizerRuleSkips =
    {
        // The emitter has its own rule, with its own exemption list and its own adjacency requirement.
        "SSO-Auth/Api/Audit/SsoAudit.cs",
    };

    // The one file that spells the two sanitizers APART, declared here with its reason rather than noticed
    // as an absence. The discovery reader substitutes on the provider's error BEFORE truncating it, because
    // the plugin's OWN truncation marker opens with a square bracket and a substitution over the composed
    // argument would rewrite the plugin's text instead of the provider's. It is still checked, one rung
    // weaker: every statement that strips must substitute at least as often as it strips.
    private static readonly string[] SanitizersSpelledApart =
    {
        "SSO-Auth/Api/Oidc/OidcDiscoveryReader.cs",
    };

    [Fact]
    public void EveryForeignValueThePluginLogs_CarriesTheRecordMarkerSubstitution()
    {
        // WHY A RULE AND NOT ROWS. #1555 made the audit emitter unable to print a foreign value that
        // reproduces "[SSO Audit] ". It did not reach the ninety-odd other places this plugin puts an
        // identity-provider- or request-supplied value into a log line under the line-ending strip alone,
        // and the marker survives verbatim in every one of them - so an unanchored search over the log file
        // still reports a login that never happened. Driving each site with a forging payload is worth
        // doing and is done for the four an attacker reaches without a credential; it cannot be the thing
        // that holds the property, because the ninety-first site added next month would arrive unguarded
        // with the whole suite green. That is the state #1555 found the emitter in.
        //
        // IT READS THE SOURCE for the same reason its sibling does: the property is that the expression is
        // written inline in the argument, which is the form CodeQL's cs/log-forging taint tracking can
        // follow. A compiled method body cannot answer that, and a helper doing the same work would satisfy
        // reflection while breaking the shape the repository keeps this for.
        //
        // WHAT IT CANNOT SEE, stated rather than left to be discovered: it matches text. A value sanitized
        // through some third spelling would pass it, and in the one file that spells the two apart the
        // check falls back to counting, which a statement carrying two foreign values and one doubled
        // substitution could satisfy while leaving one of them unsubstituted. Both are narrower holes than
        // the one the rule closes, and neither is reachable without writing an unusual line on purpose.
        var offenders = new List<string>();

        foreach (var file in Directory
            .EnumerateFiles(Path.Combine(RepoTree.Root, "SSO-Auth"), "*.cs", SearchOption.AllDirectories)
            .OrderBy(name => name, StringComparer.Ordinal))
        {
            var relative = Path.GetRelativePath(RepoTree.Root, file).Replace(Path.DirectorySeparatorChar, '/');
            if (SanitizerRuleSkips.Contains(relative, StringComparer.Ordinal))
            {
                continue;
            }

            if (SanitizersSpelledApart.Contains(relative, StringComparer.Ordinal))
            {
                offenders.AddRange(CountedOffenders(relative, File.ReadAllText(file)));
                continue;
            }

            offenders.AddRange(LineOffenders(relative, File.ReadLines(file)));
        }

        Assert.True(
            offenders.Count == 0,
            "Every identity-provider- or request-supplied value this plugin puts in a log line carries the "
            + "record-marker substitution beside the line-ending strip, inline in the argument (#1557); the "
            + "values printed exactly are named in ForeignValueExemptions and the one file that spells the "
            + "two apart is named in SanitizersSpelledApart. These break that: "
            + string.Join(" | ", offenders));
    }

    // The ordinary form: the two sanitizers are written together, so a line carrying one carries the other -
    // COUNTED rather than merely present, because a single line routinely prints several foreign values and
    // one of them losing its substitution would otherwise hide behind its neighbours. That is not
    // hypothetical: it is how the first version of this rule passed a mutation that took the substitution off
    // the OpenID callback's error_description, which shares its line with the provider and the error code.
    private static IEnumerable<string> LineOffenders(string relative, IEnumerable<string> lines)
    {
        var lineNumber = 0;
        foreach (var line in lines)
        {
            lineNumber++;
            var stripped = Occurrences(line, LineEndingSanitizer);
            if (stripped == 0)
            {
                continue;
            }

            var exempt = ForeignValueExemptions.Sum(value =>
                Occurrences(line, value + "?." + LineEndingSanitizer)
                + Occurrences(line, value + "." + LineEndingSanitizer));

            var substituted = Occurrences(line, RecordMarkerSanitizer);
            if (substituted >= stripped - exempt)
            {
                continue;
            }

            yield return relative + ":" + lineNumber.ToString(CultureInfo.InvariantCulture)
                + " strips " + (stripped - exempt).ToString(CultureInfo.InvariantCulture)
                + " foreign value(s) and substitutes " + substituted.ToString(CultureInfo.InvariantCulture)
                + " record-marker bracket(s): " + line.Trim();
        }
    }

    // The declared departure's weaker form: count per statement instead of per line.
    private static IEnumerable<string> CountedOffenders(string relative, string source)
    {
        foreach (var statement in source.Split(';'))
        {
            var stripped = Occurrences(statement, LineEndingSanitizer);
            if (stripped == 0)
            {
                continue;
            }

            var exempt = ForeignValueExemptions.Sum(value =>
                Occurrences(statement, value + "?." + LineEndingSanitizer)
                + Occurrences(statement, value + "." + LineEndingSanitizer));

            var substituted = Occurrences(statement, RecordMarkerSanitizer);
            if (substituted < stripped - exempt)
            {
                yield return relative + ": "
                    + (stripped - exempt).ToString(CultureInfo.InvariantCulture) + " foreign value(s) stripped, "
                    + substituted.ToString(CultureInfo.InvariantCulture) + " substituted: "
                    + Excerpt(statement);
            }
        }
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

    private static string Excerpt(string statement)
    {
        var flat = string.Join(' ', statement.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line => line.Trim()));
        return flat.Length > 160 ? string.Concat(flat.AsSpan(flat.Length - 160), " <- statement ends here") : flat;
    }
}
