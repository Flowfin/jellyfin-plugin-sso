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
/// In-process tests of the link-export endpoint (#1126). The builder's own rules are covered in
/// <see cref="LinkExportTests"/>; what these pin is the wiring the builder cannot prove about itself - that
/// the username really comes from Jellyfin's user manager rather than from anything stored beside the link.
/// </summary>
[Collection("SSOController")]
public class SSOControllerExportLinksTests
{
    private static readonly Guid Alice = Guid.Parse("a11ce000-0000-0000-0000-000000000001");
    private static readonly Guid Ghost = Guid.Parse("9057c000-0000-0000-0000-000000000003");

    [Fact]
    public void TheExport_ResolvesUsernamesThroughTheUserManager()
    {
        var harness = Harness();
        harness.UserManager.GetUserById(Alice).Returns(TestUsers.Named("alice", Alice));

        var document = Assert.IsType<LinkExportDocument>(Assert.IsType<OkObjectResult>(harness.Controller.ExportLinks()).Value);

        var link = Assert.Single(document.Links);
        Assert.Equal("alice", link.Username);
        Assert.Equal("sub-alice", link.CanonicalName);
        Assert.Equal("idp", link.Provider);
        Assert.Equal(LinkExport.FormatVersion, document.FormatVersion);
    }

    [Fact]
    public void ALinkTheUserManagerNoLongerKnows_IsAbsentFromTheExport()
    {
        // The harness's user manager answers null for an id it was never told about, which is exactly the
        // state a rebuilt user database leaves behind. Without the drop, the document would carry a row
        // naming an account that does not exist.
        var harness = Harness(withGhost: true);
        harness.UserManager.GetUserById(Alice).Returns(TestUsers.Named("alice", Alice));

        var document = Assert.IsType<LinkExportDocument>(Assert.IsType<OkObjectResult>(harness.Controller.ExportLinks()).Value);

        Assert.Equal(new[] { "sub-alice" }, document.Links.Select(link => link.CanonicalName));
    }

    private static SsoControllerHarness Harness(bool withGhost = false)
    {
        return new SsoControllerHarness(configuration =>
        {
            var links = new SerializableDictionary<string, Guid> { ["sub-alice"] = Alice };
            if (withGhost)
            {
                links["sub-ghost"] = Ghost;
            }

            configuration.OidConfigs["idp"] = new OidConfig { Enabled = true, CanonicalLinks = links };
        });
    }
}
