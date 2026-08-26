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
/// Conformance rules for the aggregate configuration check (#1084). The evaluation is executed by
/// <see cref="ProviderCheckTests"/>; what these rules cover is everything BETWEEN the server and the page,
/// which no suite here can run - the button, the route string, the member names and the field ids all live
/// in a browser. A drift in any of them is otherwise found by an administrator pressing Check and reading a
/// list that is silently wrong rather than one that is missing.
/// </content>
public partial class ArchitectureConformanceTests
{
    [Fact]
    public void ConfigPage_RunsTheCheck_AgainstTheRouteTheServerServes()
    {
        // The route is a string on both sides and nothing compiles the pair together. Spelled wrong, the
        // fetch rejects and the page reports "could not run the check" forever - a feature that looks broken
        // rather than one that is absent. Read off the attribute rather than pasted, so renaming the route
        // reddens this instead of half-renaming the feature.
        var route = typeof(Jellyfin.Plugin.SSO_Auth.Api.Http.SSOController)
            .GetMethod(nameof(Jellyfin.Plugin.SSO_Auth.Api.Http.SSOController.CheckProviders), BindingFlags.Public | BindingFlags.Instance)!
            .GetCustomAttributes(typeof(Microsoft.AspNetCore.Mvc.HttpGetAttribute), false)
            .Cast<Microsoft.AspNetCore.Mvc.HttpGetAttribute>()
            .Single()
            .Template;

        Assert.Equal("Config/Check", route);
        Assert.Contains("\"sso/" + route + "\"", ConfigJs(), StringComparison.Ordinal);
    }

    [Fact]
    public void ConfigPage_ReadsExactlyTheMembersTheCheckReportDeclares()
    {
        // A member read under the wrong spelling is undefined in a browser rather than an error, and every
        // one of these decides what a row SAYS: a misread Ready flags every provider, a misread MissingFields
        // reports a broken provider as fine. So each declared member has to be named by the page.
        var declared = typeof(ProviderCheckResult)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        Assert.Equal(
            new[] { "Enabled", "MissingFields", "Problem", "Protocol", "Provider", "Ready" },
            declared);

        var js = ConfigJs();
        foreach (var member in declared)
        {
            Assert.Contains("row." + member, js, StringComparison.Ordinal);
        }

        Assert.Contains("report.Providers", js, StringComparison.Ordinal);
    }

    [Fact]
    public void EveryRequiredFieldTheCheckCanReport_IsAFieldTheFormCarries()
    {
        // The drift guard the aggregate check owes, and it is the one #1104 could not have: this report DOES
        // name fields. Each name is a property on the provider type AND the id of that field on the settings
        // page, which is what lets the page resolve a reported name to the form's own localized label instead
        // of carrying a second copy of every label. A name that resolves to no element renders as the bare id
        // in front of an administrator - readable, but the wrong word - and a renamed form field is exactly
        // how that happens. Derived from the source on both sides, so neither can move alone.
        var html = ConfigPageHtml();

        foreach (var field in ProviderCheck.OidRequiredFields)
        {
            Assert.Contains("id=\"" + field + "\"", html, StringComparison.Ordinal);
        }

        foreach (var field in ProviderCheck.SamlRequiredFields)
        {
            Assert.Contains("id=\"saml-" + field + "\"", html, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void TheReportedRequiredFields_AreTheOnesThePerProviderPanelCallsRequired()
    {
        // Two answers to one question have to agree. The per-provider readiness panel (#1083) reads its own
        // required list out of the DOM; this check reads the configuration. An administrator who sees a
        // provider called ready in the editor and flagged in the aggregate list has no way to tell which one
        // is lying, so the two lists are pinned to each other here rather than kept in step by hand.
        //
        // The panel's list carries the provider-name field as well, which the server cannot report on: the
        // name is the dictionary KEY rather than a property, so a provider with no name does not exist to be
        // reported. That one id is subtracted rather than the comparison being loosened.
        var js = ConfigJs();

        Assert.Equal(
            ProviderCheck.OidRequiredFields.OrderBy(f => f, StringComparer.Ordinal),
            RequiredIds(js, "oid:").Where(id => id != "OidProviderName").OrderBy(f => f, StringComparer.Ordinal));

        Assert.Equal(
            ProviderCheck.SamlRequiredFields.Select(f => "saml-" + f).OrderBy(f => f, StringComparer.Ordinal),
            RequiredIds(js, "saml:").Where(id => id != "saml-provider-name").OrderBy(f => f, StringComparer.Ordinal));
    }

    [Fact]
    public void TheCheckAction_IsBoundAndPaintsIntoElementsThatExist()
    {
        // config.js addresses the button and the result list by id. An id no element carries is not an error
        // in a browser: querySelector answers null, and either the binding throws during page setup - taking
        // every later binding on the page with it - or the handler silently paints nowhere.
        var js = ConfigJs();
        var html = ConfigPageHtml();

        foreach (var id in new[] { "CheckAllProviders", "sso-config-check-result" })
        {
            Assert.Contains("\"#" + id + "\"", js, StringComparison.Ordinal);
            Assert.Contains("id=\"" + id + "\"", html, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void TheCheckHandler_WritesNoProviderFieldAndNoToggle()
    {
        // The acceptance clause that a run leaves every provider's form values and toggles byte-identical,
        // held where it can actually be broken. The server side cannot break it - the route is a pure read -
        // but the handler runs inside the page that owns every field, so a later "fix it for me" convenience
        // would break it here and nowhere else. Anything that assigns `.value`, `.checked` or `.disabled`
        // inside this handler is refused; reading them is untouched.
        var js = ConfigJs();
        var start = js.IndexOf("  checkAllProviders: (page) => {", StringComparison.Ordinal);
        Assert.True(start >= 0, "config.js no longer declares checkAllProviders.");
        var end = js.IndexOf("\n  renderTestMessage:", start, StringComparison.Ordinal);
        Assert.True(end > start, "checkAllProviders is no longer followed by renderTestMessage; re-anchor this rule.");

        var body = js.Substring(start, end - start);
        foreach (var write in new[] { ".value =", ".checked =", ".disabled =" })
        {
            Assert.DoesNotContain(write, body, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void TheCheckAlwaysDisclosesThatReachabilityWasNotChecked()
    {
        // A negative disclosure that is easy to drop and expensive to lose. This check makes no request to
        // any identity provider, so a list with nothing flagged says the CONFIGURATION is complete and
        // nothing at all about whether the provider answers. Without the sentence, an administrator reads
        // silence as reachability - the one wrong conclusion this action can produce - and the fix is not to
        // start probing: both Test routes share one throttle bucket, so a fan-out over many providers empties
        // it and reports working providers as broken.
        var js = ConfigJs();
        var start = js.IndexOf("  checkAllProviders: (page) => {", StringComparison.Ordinal);
        Assert.True(start >= 0, "config.js no longer declares checkAllProviders.");
        var end = js.IndexOf("\n  renderTestMessage:", start, StringComparison.Ordinal);
        var body = js.Substring(start, end - start);

        Assert.Contains("\"config.check_reachability\"", body, StringComparison.Ordinal);
        Assert.DoesNotContain("sso/OID/Test/", body, StringComparison.Ordinal);
        Assert.DoesNotContain("sso/SAML/Test/", body, StringComparison.Ordinal);

        using var catalog = JsonDocument.Parse(
            File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Localization", "en.json")));

        Assert.True(
            catalog.RootElement.TryGetProperty("config.check_reachability", out var value),
            "SSO-Auth/Localization/en.json carries no config.check_reachability entry.");
        Assert.False(string.IsNullOrWhiteSpace(value.GetString()));
    }

    // The ids one readiness spec (#1083) calls required, read out of config.js rather than restated. The
    // spec is a literal object, so its `requiredIds: [...]` array is located from the protocol key above it.
    private static string[] RequiredIds(string js, string specKey)
    {
        var spec = js.IndexOf("    " + specKey, StringComparison.Ordinal);
        Assert.True(spec >= 0, "config.js no longer declares a readiness spec for " + specKey);
        var start = js.IndexOf("requiredIds: [", spec, StringComparison.Ordinal);
        Assert.True(start >= 0, "The " + specKey + " readiness spec no longer declares requiredIds.");
        var end = js.IndexOf(']', start);

        return js.Substring(start, end - start)
            .Split('"')
            .Where((_, index) => index % 2 == 1)
            .ToArray();
    }
}
