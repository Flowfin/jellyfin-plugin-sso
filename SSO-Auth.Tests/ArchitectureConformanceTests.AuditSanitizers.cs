// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <content>
/// Conformance rule for the audit emitter's two inline sanitizers (#1555): every foreign value the audit
/// trail prints carries BOTH of them, spelled out at the logging call, and the handful of values that
/// deliberately carry only one are named here rather than being noticed as an absence.
/// </content>
public partial class ArchitectureConformanceTests
{
    // The values a line prints EXACTLY on purpose, because the plugin composed them for itself and the exact
    // text is the actionable content of the entry. The unreadable-configuration lines tell an operator which
    // file to move out of the way, and the declarative-write lines tell them which mounted document to edit;
    // a data directory whose name carries a bracket would otherwise be named as a path that does not exist,
    // in the one line written for a total lockout. No untrusted party can write any of them, so the bracket
    // substitution buys nothing here and costs the whole point of the line.
    private static readonly string[] AuditValuesPrintedExactly =
    {
        "configurationFilePath",
        "preservedCopyPath",
        "markerPath",
        "source",
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
        // marker is plantable today through ordinary plugin log lines that are not audit entries at all -
        // that is #1557 and is deliberately not this rule's subject - but a second EMITTER of the marker
        // itself is, because it would be claiming to be the audit trail.
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
}
