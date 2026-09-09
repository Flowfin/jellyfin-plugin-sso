// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The plugin's served admin assets, read from the tree, for the conformance rules that pin the settings
/// surface against the server (#1527).
/// </summary>
/// <remarks>
/// <para>
/// One page and one script became five pages and six scripts, and every rule that read the two by name
/// would otherwise have to choose a page - which is the wrong question for almost all of them. What those
/// rules assert is that a field, a marker class or a call EXISTS on the settings surface, and the surface
/// is now the five pages together. So the markup here is the five pages concatenated and the script is the
/// shared core.
/// </para>
/// <para>
/// CONCATENATION IS NOT A WEAKENING, AND THE REASON IS THAT SOMETHING ELSE ANSWERS THE OTHER HALF. A
/// concatenated read cannot tell a control on the right page from the same control on the wrong one; that
/// question is <c>tools/ui-mock-fields.js</c>'s, which reconciles every one of the 123 controls against
/// the tab <c>docs/ui/mock/FIELDS.md</c> names for it and refuses a control on no page, on two pages, or
/// on a page the table does not name. Splitting the question that way keeps each rule asking one thing:
/// the rules below ask whether the surface still carries a field, and the tool asks where it is.
/// </para>
/// <para>
/// The pages are joined with a newline so a construct cannot be formed across a file boundary out of two
/// halves that are each harmless - a regex spanning the join would otherwise match text no browser ever
/// sees.
/// </para>
/// </remarks>
internal static class WebAssets
{
    // The five registered configuration pages, in the order SSOPlugin.GetPages registers them. The order
    // is not load-bearing for any rule below; it is kept so a failure message reads in tab order.
    private static readonly string[] PageFiles =
    {
        "configPage.html",
        "providersPage.html",
        "accountsPage.html",
        "policiesPage.html",
        "serverPage.html",
    };

    /// <summary>
    /// Gets the whole admin settings surface: the five configuration pages, concatenated.
    /// </summary>
    /// <returns>The markup of all five pages.</returns>
    internal static string Markup() => string.Join("\n", PageFiles.Select(Page));

    /// <summary>
    /// Gets the markup of one configuration page, for a rule that is genuinely about that page.
    /// </summary>
    /// <param name="file">The page's file name under <c>SSO-Auth/Web</c>.</param>
    /// <returns>The markup of that page.</returns>
    internal static string Page(string file) =>
        File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Web", file));

    /// <summary>
    /// Gets the shared page script - every behaviour the five pages have. The five page modules beside it
    /// hold no behaviour at all: each one loads this and hands it the view.
    /// </summary>
    /// <returns>The source of <c>sso-core.js</c>.</returns>
    internal static string Script() => Page("sso-core.js");

    /// <summary>
    /// Gets the five page modules, keyed by file name, for the rules that pin their shape.
    /// </summary>
    /// <returns>The five page controller modules.</returns>
    internal static IReadOnlyDictionary<string, string> PageModules() =>
        new[] { "overview.js", "providers.js", "accounts.js", "policies.js", "server.js" }
            .ToDictionary(file => file, Page);
}
