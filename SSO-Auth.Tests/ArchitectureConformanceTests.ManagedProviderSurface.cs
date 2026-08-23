// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <content>
/// Conformance rules for the "managed by file" state in the admin page (#1104): the page and the report it
/// reads have to keep agreeing about the route, the member names and the markup it paints into. None of
/// this runs in a browser, so a drift between the two sides is otherwise found by an administrator meeting
/// an editable form over a provider the server will not let them change.
/// </content>
public partial class ArchitectureConformanceTests
{
    private static string ConfigJs() =>
        File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "config.js"));

    private static string ConfigPageHtml() =>
        File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "configPage.html"));

    [Fact]
    public void ConfigPage_ReadsTheManagedSet_FromTheRouteTheServerServes()
    {
        // The route is a string on both sides and nothing compiles the pair together. Spelled wrong, the
        // fetch rejects, the page's failure arm records nothing as managed, and every managed provider then
        // renders as an ordinary editable form - which is exactly the state #1104 exists to end, arrived at
        // silently. The controller side is read off the attribute rather than pasted, so renaming the route
        // reddens this instead of half-renaming the feature.
        var route = typeof(Jellyfin.Plugin.SSO_Auth.Api.Http.SSOController)
            .GetMethod(nameof(Jellyfin.Plugin.SSO_Auth.Api.Http.SSOController.ManagedProviders), BindingFlags.Public | BindingFlags.Instance)!
            .GetCustomAttributes(typeof(Microsoft.AspNetCore.Mvc.HttpGetAttribute), false)
            .Cast<Microsoft.AspNetCore.Mvc.HttpGetAttribute>()
            .Single()
            .Template;

        Assert.Equal("Config/Managed", route);
        Assert.Contains("\"sso/" + route + "\"", ConfigJs(), StringComparison.Ordinal);
    }

    [Fact]
    public void ConfigPage_ReadsExactlyTheMembersTheReportDeclares()
    {
        // This is the drift guard #1104 asks for, in the shape the server can actually honour. Its own
        // Done-when asks that every FIELD name the server can report resolve to a marked field in the form;
        // the server reports PROVIDER names instead, because the declarative merge replaces a named provider
        // whole (measured on #1102), so there is no field list to resolve. What can still drift is the pair
        // of member names, and a member read under the wrong spelling is undefined rather than an error:
        // the page would quietly find nothing managed.
        var declared = typeof(ManagedProviderSetDocument)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        Assert.Equal(new[] { "OidConfigs", "SamlConfigs" }, declared);

        var js = ConfigJs();
        foreach (var member in declared)
        {
            Assert.Contains("report." + member, js, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void ConfigPage_PaintsTheManagedNoteIntoElementsThatExist()
    {
        // config.js addresses the note by id. An id that no element carries is not an error in a browser -
        // querySelector answers null and the helper's null check swallows it - so the form would be frozen
        // with no explanation anywhere on the page, which reads as a broken settings page rather than as a
        // managed provider.
        var html = ConfigPageHtml();
        var js = ConfigJs();

        foreach (var id in new[] { "sso-managed-note", "saml-managed-note" })
        {
            Assert.Contains("\"" + id + "\"", js, StringComparison.Ordinal);
            Assert.Contains("id=\"" + id + "\"", html, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void EveryControlTheManagedStateExempts_IsAnElementInTheForms()
    {
        // The exemption list is what stays usable on a managed provider. A stale id there is not inert: the
        // control it named is renamed rather than gone, so it is now disabled with everything else and the
        // administrator loses the read action - a connection test on the one provider they cannot edit - with
        // nothing saying why. Derived from the source rather than restated, so the list and the markup cannot
        // drift apart quietly.
        var js = ConfigJs();
        var html = ConfigPageHtml();

        var start = js.IndexOf("managedReadOnlyActions: [", StringComparison.Ordinal);
        Assert.True(start >= 0, "config.js no longer declares managedReadOnlyActions.");
        var end = js.IndexOf("],", start, StringComparison.Ordinal);
        var block = js.Substring(start, end - start);

        var ids = block
            .Split('"')
            .Where((_, index) => index % 2 == 1)
            .ToList();

        Assert.NotEmpty(ids);
        foreach (var id in ids)
        {
            Assert.Contains("id=\"" + id + "\"", html, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void TheManagedNoteText_IsACatalogKeyThatExists()
    {
        // #1104 asks for the note text to be an i18n key rather than a literal. The key is looked up at
        // runtime with a built-in English default, so a key absent from the catalog is invisible: the page
        // renders the English and no localized installation ever shows a translated sentence.
        var js = ConfigJs();
        Assert.Contains("\"config.managed_by_file_note\"", js, StringComparison.Ordinal);

        using var catalog = JsonDocument.Parse(
            File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Localization", "en.json")));

        Assert.True(
            catalog.RootElement.TryGetProperty("config.managed_by_file_note", out var value),
            "SSO-Auth/Localization/en.json carries no config.managed_by_file_note entry.");
        Assert.False(string.IsNullOrWhiteSpace(value.GetString()));
    }
}
