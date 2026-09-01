// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <content>
/// Conformance rules for the admin linked-accounts panel (#1121). The panel is browser code, and this tree
/// carries no JavaScript runtime and no DOM, so nothing here executes it - these rules read it as text.
/// That is a real bound and it is the reason each rule below pins a STRUCTURAL property that a wrong edit
/// cannot satisfy by accident: which literal is posted, which call happens before which, and which branch
/// creates the control. Behaviour the reading cannot reach is argued in the pull request instead of being
/// claimed here.
/// </content>
public partial class ArchitectureConformanceTests
{
    private static string LinkedAccountsScript()
        => File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "config.js"));

    private static string LinkedAccountsMarkup()
        => File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Web", "configPage.html"));

    private static IReadOnlyDictionary<string, string> LinkedAccountsEnglishCatalog()
        => JsonSerializer.Deserialize<Dictionary<string, string>>(
            File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Localization", "en.json")))!;

    // The text of one property on the ssoConfigurationPage object literal: from its arrow-function opener to
    // the next "  }," at the object's own two-space indent. Every closure inside a property is indented
    // deeper, so the terminator cannot be hit early.
    private static string LinkedAccountsFunctionBody(string js, string opener)
    {
        var start = js.IndexOf(opener, StringComparison.Ordinal);
        Assert.True(start >= 0, $"config.js no longer declares '{opener}' - the linked-accounts panel rules cannot read it.");

        var end = js.IndexOf("\n  },", start, StringComparison.Ordinal);
        Assert.True(end > start, $"config.js: could not find the end of '{opener}'.");

        return js[start..end];
    }

    [Fact]
    public void LinkedAccountsRevoke_PostsThePinnedDefaultPasswordProviderId()
    {
        // The Unregister endpoint PERSISTS whatever the caller sends as the provider onto the account
        // (SSOController.Unregister: user.AuthenticationProviderId = provider), so a wrong string does not
        // fail the request. It routes that account to core's InvalidAuthenticationProvider, which refuses
        // every password, and neither the page nor the log would report it - the account is simply one
        // nobody can sign into any more. #837 pinned the server-side literal for the same class of failure;
        // this pins the page's copy against it, so the two cannot drift.
        var js = LinkedAccountsScript();

        var declared = Regex.Match(js, @"const DEFAULT_PASSWORD_PROVIDER_ID\s*=\s*""(?<id>[^""]+)"";");
        Assert.True(declared.Success, "config.js must declare a DEFAULT_PASSWORD_PROVIDER_ID constant for the linked-accounts revoke.");
        Assert.Equal(SsoAuthenticationProviders.DefaultPasswordProviderId, declared.Groups["id"].Value);

        // The revoke must SEND that constant rather than a literal of its own: a second copy is the drift
        // the pin exists to prevent, and it would be invisible in review because both spellings look right.
        var revoke = LinkedAccountsFunctionBody(js, "revokeLinkedAccount: (page, username) => {");
        Assert.Contains("JSON.stringify(DEFAULT_PASSWORD_PROVIDER_ID)", revoke, StringComparison.Ordinal);
        Assert.DoesNotContain("Jellyfin.Server.Implementations", revoke, StringComparison.Ordinal);
    }

    [Fact]
    public void LinkedAccountsPanel_RendersWithoutInnerHtml()
    {
        // Every cell the panel paints carries attacker-influenced text: a canonical name is whatever the
        // identity provider put in its subject claim, and a username reaches the roster from account
        // creation. linking.js already holds this line for the self-service page; the admin page is the
        // higher-value target, because it is the one an administrator opens with elevation (#221).
        var js = LinkedAccountsScript();
        var panel = js[js.IndexOf("loadLinkedAccounts: (page) => {", StringComparison.Ordinal)..
                       js.IndexOf("renderTransferMessage: (container, message) => {", StringComparison.Ordinal)];

        Assert.True(panel.Length > 0, "the linked-accounts panel functions were not found in config.js");
        Assert.DoesNotContain("innerHTML", panel, StringComparison.Ordinal);
        Assert.DoesNotContain("insertAdjacentHTML", panel, StringComparison.Ordinal);
        Assert.DoesNotContain("outerHTML", panel, StringComparison.Ordinal);

        // The pin is only worth anything while the renderer still writes text at all: a rewrite that stopped
        // using textContent would satisfy the three absences above without rendering anything safely.
        Assert.Contains("textContent", panel, StringComparison.Ordinal);
    }

    [Fact]
    public void LinkedAccountsRow_OffersNoRevokeWhereTheAccountIsGone()
    {
        // The roster deliberately keeps a link whose user id resolves to no account - it is the single most
        // useful thing the report can show, and it is invisible from every other surface. Unregister,
        // though, resolves the account BY USERNAME and answers 404 before it does anything, so a revoke
        // wired onto those rows would fail on exactly the rows an administrator opens this panel to find,
        // and on no others. The row therefore carries an explanation instead of a control that cannot work.
        var row = LinkedAccountsFunctionBody(
            LinkedAccountsScript(),
            "renderLinkedAccountRow: (page, account) => {");

        var branch = row.IndexOf("if (exists) {", StringComparison.Ordinal);
        Assert.True(branch >= 0, "renderLinkedAccountRow must branch on whether the account still exists.");

        var otherwise = row.IndexOf("} else {", branch, StringComparison.Ordinal);
        Assert.True(otherwise > branch, "renderLinkedAccountRow must render something on the orphaned branch rather than nothing.");

        var present = row[branch..otherwise];
        var absent = row[otherwise..];

        Assert.Contains("createElement(\"button\")", present, StringComparison.Ordinal);
        Assert.DoesNotContain("createElement(\"button\")", absent, StringComparison.Ordinal);
        Assert.DoesNotContain("revokeLinkedAccount", absent, StringComparison.Ordinal);
        Assert.Contains("config.linked_accounts_orphan_note", absent, StringComparison.Ordinal);
    }

    [Fact]
    public void LinkedAccountsRevoke_ConfirmsBeforeItRequests()
    {
        // The revoke removes an account's links from every provider, ends every session it holds on every
        // device, and rewrites its login routing. It is not undone by a reload, so the confirmation is the
        // only thing between a misclick and all three - and a confirmation that runs AFTER the request is
        // decoration. Order is the property, so order is what is pinned.
        var revoke = LinkedAccountsFunctionBody(
            LinkedAccountsScript(),
            "revokeLinkedAccount: (page, username) => {");

        var confirm = revoke.IndexOf("window.confirm(", StringComparison.Ordinal);
        var request = revoke.IndexOf("ApiClient.fetch(", StringComparison.Ordinal);

        Assert.True(confirm >= 0, "the linked-accounts revoke must confirm before it acts.");
        Assert.True(request >= 0, "the linked-accounts revoke must reach the server through ApiClient.fetch.");
        Assert.True(confirm < request, "the linked-accounts revoke asks for confirmation only after it has already sent the request.");

        // A declined confirmation must return without requesting anything.
        Assert.Contains("return Promise.resolve();", revoke[confirm..request], StringComparison.Ordinal);
    }

    [Fact]
    public void LinkedAccountsRevokeConfirmation_NamesThePasswordLoginConsequence()
    {
        // Decided on #1121: warn, name the consequence, and proceed - rather than refusing the revoke while
        // SSO-only login is on, which would remove the control on exactly the servers where cutting one
        // account off matters most. The warning is what buys that decision, so its content is a property of
        // the change rather than wording: an administrator reading "revoke" expects the account to end up
        // with LESS access, and this one hands it back native password login. The catalog is where the
        // sentence lives, so the catalog is what is read.
        var english = LinkedAccountsEnglishCatalog();

        Assert.True(
            english.TryGetValue("config.linked_accounts_revoke_confirm", out var confirmation),
            "the linked-accounts revoke confirmation must exist in the English catalog.");

        Assert.Contains("password", confirmation, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("SSO-only", confirmation, StringComparison.Ordinal);
        Assert.Contains("not changed", confirmation, StringComparison.Ordinal);

        // The durability caveat belongs to the panel's own help text rather than to the confirmation: a
        // revoke does not stop re-adoption where a provider allows existing-account linking, so an
        // administrator who is not told that would read the cut as permanent when it is not.
        Assert.True(english.TryGetValue("config.linked_accounts_help", out var help));
        Assert.Contains("Allow Existing Account Link", help, StringComparison.Ordinal);
        Assert.Contains("re-adopted", help, StringComparison.Ordinal);
    }

    [Fact]
    public void LinkedAccountsPanel_ReusesTheExistingRoutesAndAddsNone()
    {
        // The panel is presentation only. It reads the elevation-gated aggregate roster and drives the
        // EXISTING Unregister endpoint, which is where the elevation policy, the "unregister" rate-limit
        // class, the removal across both protocols and the token revoke all live. A second revoke path -
        // or a route that skipped the limiter - would put the heaviest control on this page outside every
        // guard the endpoint already carries.
        var js = LinkedAccountsScript();
        var markup = LinkedAccountsMarkup();

        Assert.Contains("ApiClient.getUrl(\"sso/Links/Roster\")", js, StringComparison.Ordinal);
        Assert.Contains("ApiClient.getUrl(\"sso/Unregister/\" + encodeURIComponent(username))", js, StringComparison.Ordinal);

        // Exactly one CALL onto the revoke route in the whole page script: a second one is a second path.
        // Matched on the request construction rather than on the route string, so a comment naming the route
        // is not counted as a caller.
        Assert.Single(Regex.Matches(js, @"getUrl\(\s*""sso/Unregister/"));

        // The regions the panel paints into must exist, or every render silently targets null.
        Assert.Contains("id=\"LinkedAccountsResult\"", markup, StringComparison.Ordinal);
        Assert.Contains("id=\"LinkedAccountsRevokeResult\"", markup, StringComparison.Ordinal);
        Assert.Contains("id=\"RefreshLinkedAccounts\"", markup, StringComparison.Ordinal);
    }
}
