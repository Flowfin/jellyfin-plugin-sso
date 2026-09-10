// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <content>
/// Conformance rule for the restart claim the settings surface used to carry (#1573).
/// </content>
public partial class ArchitectureConformanceTests
{
    // The claim, in the two spellings this tree carried it in. A phrase list rather than the word
    // "restart", because a restart is a real instruction in one place and the rule must not refuse it:
    // the total-lockout recovery on the legacy page tells an administrator to stop Jellyfin, edit
    // config.xml and restart, and that one is true - the flag is reconciled against the user database on
    // startup, which is the whole point of that paragraph.
    private static readonly string[] RestartClaims =
    {
        "requires a restart",
        "restart of Jellyfin to take effect",
        "restart Jellyfin to take effect",
    };

    [Fact]
    public void NoServedAssetClaimsThatSavingNeedsARestart()
    {
        // #1573, and the reason it is a rule rather than a deletion is that the sentence was in the markup
        // for years and reads as harmless. It is not harmless and it was not true.
        //
        // Nothing in this plugin holds a configuration snapshot: no field anywhere is of type
        // PluginConfiguration, and the call sites either fetch the live object at the moment they need it
        // or take it as a parameter. A save writes the file and then mutates that live object in place,
        // so the next request reads the new value and there is no path by which it could read the old
        // one. The one component that reaches into Jellyfin's own state - the login-page branding - is
        // subscribed to the configuration-changed event rather than read once at startup. There is no
        // setting on the restart side of the line.
        //
        // What the sentence cost is the half that makes this worth pinning: a Jellyfin restart drops every
        // playing session and every connected client, and the footer asked for one after every save.
        var offenders = new List<string>();

        foreach (var file in Directory.EnumerateFiles(Path.Combine(RepoTree.Root, "SSO-Auth", "Web")))
        {
            var name = Path.GetFileName(file);
            if (!name.EndsWith(".html", StringComparison.Ordinal)
                && !name.EndsWith(".js", StringComparison.Ordinal)
                && !name.EndsWith(".css", StringComparison.Ordinal))
            {
                continue;
            }

            var lineNumber = 0;
            foreach (var line in File.ReadLines(file))
            {
                lineNumber++;
                var claim = RestartClaims.FirstOrDefault(
                    phrase => line.Contains(phrase, StringComparison.OrdinalIgnoreCase));
                if (claim is null)
                {
                    continue;
                }

                // The reasoning left where the sentence was is allowed to quote it. A comment cannot
                // reach an administrator, and a rule that refused the explanation would take the record
                // of why the sentence is gone along with the sentence.
                var trimmed = line.TrimStart();
                if (trimmed.StartsWith("//", StringComparison.Ordinal)
                    || trimmed.StartsWith("*", StringComparison.Ordinal)
                    || trimmed.StartsWith("/*", StringComparison.Ordinal)
                    || InsideMarkupComment(file, lineNumber))
                {
                    continue;
                }

                offenders.Add(
                    name + ":" + lineNumber.ToString(System.Globalization.CultureInfo.InvariantCulture)
                    + ": " + line.Trim());
            }
        }

        Assert.True(
            offenders.Count == 0,
            "No served asset tells an administrator that a saved change needs a restart (#1573): a save "
            + "mutates the live configuration in place and every reader takes it from there, while a "
            + "Jellyfin restart drops every playing session on the server. These lines break that: "
            + string.Join(" | ", offenders));
    }

    /// <summary>
    /// Whether a line of an HTML file sits inside a markup comment.
    /// </summary>
    /// <remarks>
    /// Counted rather than matched per line, because the reasoning this rule exempts is a paragraph and
    /// the phrase it quotes is in the middle of it. An odd number of opened-and-not-closed comments before
    /// the line means it is inside one.
    /// </remarks>
    /// <param name="file">The file to read.</param>
    /// <param name="lineNumber">The one-based line to judge.</param>
    /// <returns>True when that line is inside a markup comment.</returns>
    private static bool InsideMarkupComment(string file, int lineNumber)
    {
        if (!file.EndsWith(".html", StringComparison.Ordinal))
        {
            return false;
        }

        var before = string.Join("\n", File.ReadLines(file).Take(lineNumber - 1));
        var opened = before.Split("<!--").Length - 1;
        var closed = before.Split("-->").Length - 1;
        return opened > closed;
    }
}
