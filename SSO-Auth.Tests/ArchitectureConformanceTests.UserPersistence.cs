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
/// The rule that generalises #1440: the two account fields whose absence from the DATABASE is a login-security
/// defect are written and saved in one method, never written here and left for some other method to save.
/// </content>
public partial class ArchitectureConformanceTests
{
    // The two fields, and the reason the rule stops at two rather than covering every User member. Both decide
    // whether the ordinary Jellyfin login form opens an SSO account: AuthenticationProviderId routes the
    // account away from the native password provider, and Password is the stored hash the empty password is
    // checked against. An unsaved write to either leaves an account reachable without the identity provider,
    // which is #1440. A permission or a preference that fails to persist is a wrong policy on the next login,
    // not an open door, so it is outside this rule rather than forgotten by it.
    private static readonly string[] DoorFields = new[] { "AuthenticationProviderId", "Password" };

    [Fact]
    public void EveryLoginDoorFieldIsSavedInTheMethodThatWritesIt()
    {
        // #1440 was not a missing write: both writes were there and neither was durable, because the create arm
        // mutated the returned object while the save sat in another method on another instance. Every unit test
        // asserted on the object it held, so the suite was blind for the life of the defect. The shape is write
        // here and hope somebody else saves, refused at the one place it is visible without running anything.
        // It reads source order rather than execution order and does not follow the object into a helper, so a
        // correct helper is refused here, which is the false refusal it accepts for having no quiet failure.
        var apiRoot = Path.Combine(RepoTree.Root, "SSO-Auth", "Api");
        var write = new Regex(@"^\s*(?<obj>[A-Za-z_][A-Za-z0-9_]*)\.(?<field>" + string.Join("|", DoorFields) + @")\s*=\s*[^=]", RegexOptions.None, TimeSpan.FromSeconds(5));
        var offenders = new List<string>();
        var covered = new List<string>();

        foreach (var src in Directory.EnumerateFiles(apiRoot, "*.cs", SearchOption.AllDirectories).OrderBy(p => p, StringComparer.Ordinal))
        {
            var lines = File.ReadAllLines(src);
            foreach (var (start, end) in MethodBodies(lines))
            {
                for (var i = start; i <= end; i++)
                {
                    var match = write.Match(lines[i]);
                    if (!match.Success)
                    {
                        continue;
                    }

                    var obj = match.Groups["obj"].Value;
                    var saved = false;
                    for (var j = i + 1; j <= end; j++)
                    {
                        if (lines[j].Contains("UpdateUserAsync(" + obj + ")", StringComparison.Ordinal))
                        {
                            saved = true;
                            break;
                        }
                    }

                    var site = Path.GetRelativePath(RepoTree.Root, src).Replace(Path.DirectorySeparatorChar, '/') + ":" + (i + 1).ToString(System.Globalization.CultureInfo.InvariantCulture)
                        + " writes " + obj + "." + match.Groups["field"].Value;
                    (saved ? covered : offenders).Add(site);
                }
            }
        }

        // The rule is worth nothing if it walks an empty population - a rename of either field, or a change of
        // formatting that defeats the method split, would leave it silently passing over nothing at all.
        Assert.True(
            covered.Count + offenders.Count >= 7,
            "expected at least the 7 known login-door writes under SSO-Auth/Api, found " + (covered.Count + offenders.Count).ToString(System.Globalization.CultureInfo.InvariantCulture) + ": " + string.Join("; ", covered.Concat(offenders)));

        Assert.True(
            offenders.Count == 0,
            "a login-door field is written in a method that does not save the same object (#1440/#1450): " + string.Join("; ", offenders));
    }

    // Method bodies, split on the one thing StyleCop guarantees in this tree: a member sits at four-space
    // indentation and closes with a brace alone at four-space indentation. Cheaper than a parser and exact
    // enough for the population above, and the count assertion in the caller is what notices if it ever stops
    // being exact.
    private static IEnumerable<(int Start, int End)> MethodBodies(string[] lines)
    {
        var open = -1;
        for (var i = 0; i < lines.Length; i++)
        {
            if (lines[i] == "    {")
            {
                open = i;
            }
            else if (lines[i] == "    }" && open >= 0)
            {
                yield return (open, i);
                open = -1;
            }
        }
    }
}
