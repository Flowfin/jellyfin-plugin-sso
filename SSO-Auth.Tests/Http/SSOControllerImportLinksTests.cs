// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of what the link-import endpoint ANSWERS (#1520). The importer's own rules are covered
/// in <see cref="LinkImportTests"/>; what these pin is the property that surface had none of - a restore
/// that rebound nothing must not be indistinguishable from one that rebound everything.
///
/// It stood indistinguishable long enough to matter. The endpoint answered <c>204 No Content</c> whatever
/// the number was, so #1517 - a document arriving with its entries dropped - restored nothing, answered
/// success and left every account unlinked from <c>4.3.0-beta.43</c> onward, with the count reaching only
/// an audit line nobody reads mid-migration. These assertions are on the answer for that reason: an
/// operator holding the backup file must be able to see the number without the server log.
/// </summary>
[Collection("SSOController")]
public class SSOControllerImportLinksTests
{
    private static readonly Guid TargetAlice = Guid.Parse("7a19e700-0000-0000-0000-00000000000a");
    private static readonly Guid TargetBob = Guid.Parse("7a19e700-0000-0000-0000-00000000000b");

    [Fact]
    public async Task TheImport_AnswersHowManyLinksItRebound()
    {
        var harness = Harness();

        var result = Restore(await harness.Controller.ImportLinks(TwoLinks()).ConfigureAwait(true));

        Assert.Equal(2, result.Restored);
        Assert.Equal(
            new[] { "OpenID/idp:1", "SAML/adfs:1" },
            result.Providers.Select(entry => $"{entry.Protocol}/{entry.Provider}:{entry.Links}").ToArray());

        // The count has to be the truth about the write rather than a count of what was posted, so the
        // stored table is read back: a body claiming two while the map holds none is the exact failure
        // #1517 was, one field further along.
        Assert.Equal(TargetAlice, harness.Configuration.OidConfigs["idp"].CanonicalLinks["sub-alice"]);
        Assert.Equal(TargetBob, harness.Configuration.SamlConfigs["adfs"].CanonicalLinks["nameid-bob"]);
    }

    [Fact]
    public async Task AnImportThatRestoredNothing_IsDistinguishableFromOneThatRestoredEverything()
    {
        // The whole point of the issue, asserted as the comparison rather than as two separate numbers:
        // before this change both calls produced a 204 with an empty body, so no caller could tell them
        // apart and the settings page printed one fixed sentence over both.
        var harness = Harness();

        var everything = Restore(await harness.Controller.ImportLinks(TwoLinks()).ConfigureAwait(true));
        var nothing = Restore(await harness.Controller.ImportLinks(new LinkExportDocument { FormatVersion = LinkExport.FormatVersion }).ConfigureAwait(true));

        Assert.Equal(2, everything.Restored);
        Assert.Equal(0, nothing.Restored);
        Assert.Empty(nothing.Providers);
        Assert.NotEqual(everything.Restored, nothing.Restored);
    }

    [Fact]
    public async Task AConfigurationExportPostedHere_AnswersThatItRestoredNothing()
    {
        // One of the three inputs #1520 measured against a running server. The two documents both declare
        // FormatVersion 1 and nothing else separates them, so the version gate passes and the wrong file
        // is applied as an empty one. The import is still right to apply it - it contradicts nothing - and
        // the zero in the answer is the only thing that tells the operator they posted the wrong export.
        var harness = Harness();

        var result = Restore(await harness.Controller.ImportLinks(new LinkExportDocument { FormatVersion = ConfigExport.FormatVersion }).ConfigureAwait(true));

        Assert.Equal(0, result.Restored);
        Assert.Empty(harness.Configuration.OidConfigs["idp"].CanonicalLinks);
    }

    private static LinkImportResultDocument Restore(ActionResult answer) =>
        Assert.IsType<LinkImportResultDocument>(Assert.IsType<OkObjectResult>(answer).Value);

    private static LinkExportDocument TwoLinks() => new()
    {
        FormatVersion = LinkExport.FormatVersion,
        Links = new Collection<LinkExportEntry>
        {
            new() { Protocol = LinkExport.OpenIdProtocol, Provider = "idp", CanonicalName = "sub-alice", Username = "alice" },
            new() { Protocol = LinkExport.SamlProtocol, Provider = "adfs", CanonicalName = "nameid-bob", Username = "bob" },
        },
    };

    private static SsoControllerHarness Harness()
    {
        var harness = new SsoControllerHarness(configuration =>
        {
            configuration.OidConfigs["idp"] = new OidConfig { Enabled = true };
            configuration.SamlConfigs["adfs"] = new SamlConfig { Enabled = true };
        });

        harness.UserManager.GetUserByName("alice").Returns(TestUsers.Named("alice", TargetAlice));
        harness.UserManager.GetUserByName("bob").Returns(TestUsers.Named("bob", TargetBob));
        return harness;
    }
}
