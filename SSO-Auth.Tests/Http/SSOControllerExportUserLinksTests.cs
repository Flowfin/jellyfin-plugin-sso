// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the per-subject link export (#1091). The document shape and the builder's own rules
/// belong to <see cref="LinkExportTests"/> and <see cref="SSOControllerExportLinksTests"/>; what these pin is
/// the property that makes this endpoint worth having separately from the whole-table export - it answers for
/// the requested account and for nobody else. An operator producing a data-subject access response must not
/// have to receive every other account's linkages and redact them by hand, and a filter that leaked one
/// neighbouring row would defeat the reason the route exists.
/// </summary>
[Collection("SSOController")]
public class SSOControllerExportUserLinksTests
{
    private static readonly Guid Alice = Guid.Parse("a11ce000-0000-0000-0000-000000000001");
    private static readonly Guid Bob = Guid.Parse("b0b00000-0000-0000-0000-000000000002");

    [Fact]
    public void TheExport_CarriesBothProtocolsForTheRequestedAccount()
    {
        var harness = Harness();
        harness.UserManager.GetUserById(Alice).Returns(TestUsers.Named("alice", Alice));

        var document = Document(harness.Controller.ExportUserLinks(Alice));

        Assert.Equal(LinkExport.FormatVersion, document.FormatVersion);
        Assert.Equal(
            new[] { ("OpenID", "idp", "sub-alice"), ("SAML", "adfs", "alice@example.test") },
            document.Links
                .Select(link => (link.Protocol!, link.Provider!, link.CanonicalName!))
                .OrderBy(entry => entry.Item1, StringComparer.Ordinal)
                .ToArray());
        Assert.All(document.Links, link => Assert.Equal("alice", link.Username));
    }

    [Fact]
    public void AnotherAccountsLinks_AreAbsent()
    {
        // The whole point of the per-subject route. Bob's account resolves perfectly well through the same
        // user manager, so nothing about the environment excludes his row - only the requested id does.
        var harness = Harness();
        harness.UserManager.GetUserById(Alice).Returns(TestUsers.Named("alice", Alice));
        harness.UserManager.GetUserById(Bob).Returns(TestUsers.Named("bob", Bob));

        var document = Document(harness.Controller.ExportUserLinks(Alice));

        Assert.DoesNotContain("sub-bob", document.Links.Select(link => link.CanonicalName));
        Assert.Equal(2, document.Links.Count);
    }

    [Fact]
    public void AnAccountWithNoLinks_ExportsAnEmptyDocument()
    {
        // "We hold nothing for this person" is an answer an access request needs, and it is not the same
        // answer as "no such account" - an empty document is the honest one, not a 404.
        var harness = Harness();
        var unlinked = Guid.Parse("c0ffee00-0000-0000-0000-000000000003");
        harness.UserManager.GetUserById(unlinked).Returns(TestUsers.Named("carol", unlinked));

        var document = Document(harness.Controller.ExportUserLinks(unlinked));

        Assert.Empty(document.Links);
    }

    [Fact]
    public void AnUnknownUserId_IsNotFound()
    {
        // The harness's user manager answers null for an id it was never told about. Exporting an empty
        // document for it would tell an operator the account holds no linkages, when the truth is that the
        // account does not exist.
        var harness = Harness();

        Assert.IsType<NotFoundObjectResult>(harness.Controller.ExportUserLinks(Bob));
    }

    private static LinkExportDocument Document(ActionResult result) =>
        Assert.IsType<LinkExportDocument>(Assert.IsType<OkObjectResult>(result).Value);

    private static SsoControllerHarness Harness()
    {
        return new SsoControllerHarness(configuration =>
        {
            configuration.OidConfigs["idp"] = new OidConfig
            {
                Enabled = true,
                CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-alice"] = Alice, ["sub-bob"] = Bob },
            };
            configuration.SamlConfigs["adfs"] = new SamlConfig
            {
                Enabled = true,
                CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice@example.test"] = Alice },
            };
        });
    }
}
