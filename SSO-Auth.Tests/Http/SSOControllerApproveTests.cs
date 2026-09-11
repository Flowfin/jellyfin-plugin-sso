// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the approve endpoint (#1529) via <see cref="SsoControllerHarness"/>. The endpoint
/// ENABLES a Jellyfin account on an administrator credential, so the tests are built around what it refuses
/// and what it leaves in the trail: the service's own tests prove the decision, and these prove the HTTP
/// boundary carries each decision out unchanged - the status a page reads, the audit line an operator
/// reads, and the subject that reaches neither.
/// </summary>
[Collection("SSOController")]
public class SSOControllerApproveTests
{
    private static readonly Guid Alice = Guid.Parse("a11ce000-0000-0000-0000-000000000001");
    private static readonly DateTime Now = new(2026, 9, 11, 9, 0, 0, DateTimeKind.Utc);

    [Fact]
    public async Task ARecordedAccount_IsEnabled_AndAudited_WithoutTheCanonicalSubject()
    {
        // The one arm that grants. The line names the actor, the account and the provider, and withholds
        // the subject on purpose: it is the one member of the request that identifies a real person at the
        // identity provider (T-I1).
        var harness = Harness();
        var alice = Recorded(harness, disabled: true, admin: false);

        Assert.IsType<NoContentResult>(await harness.Controller.ApproveProvisionedAccount("oid", "idp", "sub-alice"));

        Assert.False(alice.HasPermission(PermissionKind.IsDisabled));
        Assert.Empty(harness.Configuration.OidConfigs["idp"].CanonicalLinkPendingApprovals);
        var entry = Assert.Single(harness.ControllerLog.Entries, e => e.Message.Contains("Account approved", StringComparison.Ordinal));
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("[SSO Audit]", entry.Message, StringComparison.Ordinal);
        Assert.Contains("OpenID", entry.Message, StringComparison.Ordinal);
        Assert.Contains(Alice.ToString(), entry.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("sub-alice", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADisabledAccountWithNoRecord_IsNotFound_AndWritesNoAuditLine()
    {
        // The account an administrator disabled on purpose, seen from the boundary: a 404 that says where
        // such an account is enabled, no permission written, and no "approved" line in the trail for an
        // account nobody approved.
        var harness = Harness();
        var alice = Recorded(harness, disabled: true, admin: false);
        harness.Configuration.OidConfigs["idp"].CanonicalLinkPendingApprovals.Clear();

        var result = await harness.Controller.ApproveProvisionedAccount("oid", "idp", "sub-alice");

        Assert.Equal(404, Assert.IsType<NotFoundObjectResult>(result).StatusCode);
        Assert.True(alice.HasPermission(PermissionKind.IsDisabled));
        Assert.DoesNotContain(harness.ControllerLog.Entries, e => e.Message.Contains("Account approved", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnAdministrator_IsForbidden_WithTheBodyThePageTellsApart()
    {
        var harness = Harness();
        var alice = Recorded(harness, disabled: true, admin: true);

        var result = await harness.Controller.ApproveProvisionedAccount("oid", "idp", "sub-alice");

        var forbidden = Assert.IsType<ObjectResult>(result);
        Assert.Equal(403, forbidden.StatusCode);
        Assert.Contains("administrator", Assert.IsType<string>(forbidden.Value), StringComparison.OrdinalIgnoreCase);
        Assert.True(alice.HasPermission(PermissionKind.IsDisabled));
    }

    [Fact]
    public async Task AnUnknownMode_IsRefused_BeforeAnythingIsRead()
    {
        var harness = Harness();
        Recorded(harness, disabled: true, admin: false);

        var result = await harness.Controller.ApproveProvisionedAccount("ldap", "idp", "sub-alice");

        Assert.Equal(400, Assert.IsType<BadRequestObjectResult>(result).StatusCode);
        Assert.Single(harness.Configuration.OidConfigs["idp"].CanonicalLinkPendingApprovals);
    }

    [Fact]
    public async Task AnUnknownProvider_IsRefused_AndChangesNothing()
    {
        var harness = Harness();
        var alice = Recorded(harness, disabled: true, admin: false);

        var result = await harness.Controller.ApproveProvisionedAccount("oid", "nope", "sub-alice");

        Assert.Equal(400, Assert.IsType<BadRequestObjectResult>(result).StatusCode);
        Assert.True(alice.HasPermission(PermissionKind.IsDisabled));
        Assert.Single(harness.Configuration.OidConfigs["idp"].CanonicalLinkPendingApprovals);
    }

    [Fact]
    public async Task TheSamlArm_ActsOnTheSamlProvider()
    {
        // Both protocols funnel through one service call; the boundary's only protocol-specific act is the
        // audit label, which is asserted so a SAML approval is not written up as an OpenID one.
        var harness = Harness();
        var alice = TestUsers.Named("alice", Alice);
        alice.SetPermission(PermissionKind.IsDisabled, true);
        harness.UserManager.GetUserById(Alice).Returns(alice);
        var saml = harness.Configuration.SamlConfigs["sp"];
        saml.CanonicalLinks["nameid-alice"] = Alice;
        saml.CanonicalLinkPendingApprovals["nameid-alice"] = new PendingApproval { UserId = Alice, SinceUtc = Now };

        Assert.IsType<NoContentResult>(await harness.Controller.ApproveProvisionedAccount("saml", "sp", "nameid-alice"));

        Assert.False(alice.HasPermission(PermissionKind.IsDisabled));
        Assert.Empty(saml.CanonicalLinkPendingApprovals);
        var entry = Assert.Single(harness.ControllerLog.Entries, e => e.Message.Contains("Account approved", StringComparison.Ordinal));
        Assert.Contains("SAML", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnEmptyCanonicalName_NamesNoRecord()
    {
        // An empty key names nothing, so it is the same 404 an unrecorded identity gets - never an
        // exception from a dictionary asked about an empty key, and never an answer about some other row.
        var harness = Harness();
        Recorded(harness, disabled: true, admin: false);

        var result = await harness.Controller.ApproveProvisionedAccount("oid", "idp", string.Empty);

        Assert.Equal(404, Assert.IsType<NotFoundObjectResult>(result).StatusCode);
        Assert.Single(harness.Configuration.OidConfigs["idp"].CanonicalLinkPendingApprovals);
    }

    // --- helpers ---

    private static SsoControllerHarness Harness()
    {
        return new SsoControllerHarness(configuration =>
        {
            configuration.OidConfigs["idp"] = new OidConfig { Enabled = true };
            configuration.SamlConfigs["sp"] = new SamlConfig { Enabled = true };
        });
    }

    // One OpenID provider holding alice's link and this plugin's record of having provisioned her inert.
    private static Jellyfin.Database.Implementations.Entities.User Recorded(SsoControllerHarness harness, bool disabled, bool admin)
    {
        var alice = TestUsers.Named("alice", Alice);
        alice.SetPermission(PermissionKind.IsDisabled, disabled);
        alice.SetPermission(PermissionKind.IsAdministrator, admin);
        harness.UserManager.GetUserById(Alice).Returns(alice);
        var config = harness.Configuration.OidConfigs["idp"];
        config.CanonicalLinks["sub-alice"] = Alice;
        config.CanonicalLinkPendingApprovals["sub-alice"] = new PendingApproval { UserId = Alice, SinceUtc = Now };
        return alice;
    }
}
