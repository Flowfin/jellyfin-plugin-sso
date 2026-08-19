// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the pre-provision link write (#1133) via <see cref="SsoControllerHarness"/>. The
/// endpoint grants an identity-provider subject the ability to sign in as a named Jellyfin account on an
/// administrator credential alone, with no identity-provider response redeemed behind it, so the tests are
/// built around the refusals rather than around the happy path: what it must NOT write is the whole reason
/// this is a separate entry point from the self-service link write next to it.
/// </summary>
[Collection("SSOController")]
public class SSOControllerPreprovisionLinkTests
{
    private static readonly Guid Alice = Guid.Parse("a11ce000-0000-0000-0000-000000000001");
    private static readonly Guid Bob = Guid.Parse("b0b00000-0000-0000-0000-000000000002");

    [Fact]
    public async Task AFreshMapping_IsWritten()
    {
        var harness = Harness();
        Account(harness, Alice, "alice");

        Assert.IsType<NoContentResult>(await harness.Controller.PreprovisionCanonicalLink("oid", "idp", Alice, "sub-alice"));

        Assert.Equal(Alice, harness.Configuration.OidConfigs["idp"].CanonicalLinks["sub-alice"]);
    }

    [Fact]
    public async Task TheSameMappingPostedTwice_IsIdempotent()
    {
        // A provisioning tool that retried a request whose response it never saw must not be told its own
        // earlier success is a conflict, or it reports a failure for an account that IS linked.
        var harness = Harness();
        Account(harness, Alice, "alice");

        await harness.Controller.PreprovisionCanonicalLink("oid", "idp", Alice, "sub-alice");

        Assert.IsType<NoContentResult>(await harness.Controller.PreprovisionCanonicalLink("oid", "idp", Alice, "sub-alice"));
        Assert.Equal(Alice, harness.Configuration.OidConfigs["idp"].CanonicalLinks["sub-alice"]);
    }

    [Fact]
    public async Task TheSameSubjectPointedAtASecondAccount_IsRefused_AndTheFirstLinkSurvives()
    {
        // The load-bearing refusal. Without it this endpoint moves an identity-provider subject off the
        // account holding it and onto one the caller names, which is how a crafted provisioning call takes
        // over another person's identity. Delete the refuseRebind arm in CanonicalLinkService and this is
        // the test that goes red.
        var harness = Harness();
        Account(harness, Alice, "alice");
        Account(harness, Bob, "bob");
        await harness.Controller.PreprovisionCanonicalLink("oid", "idp", Alice, "sub-alice");

        var result = await harness.Controller.PreprovisionCanonicalLink("oid", "idp", Bob, "sub-alice");

        Assert.IsType<ConflictObjectResult>(result);
        Assert.Equal(Alice, harness.Configuration.OidConfigs["idp"].CanonicalLinks["sub-alice"]);
    }

    [Fact]
    public async Task AConflict_WritesNoAuditLine()
    {
        // The audit line says a grant was made. A refused write made none, and a line claiming otherwise
        // sends an operator hunting for a link that does not exist.
        var harness = Harness();
        Account(harness, Alice, "alice");
        Account(harness, Bob, "bob");
        await harness.Controller.PreprovisionCanonicalLink("oid", "idp", Alice, "sub-alice");

        await harness.Controller.PreprovisionCanonicalLink("oid", "idp", Bob, "sub-alice");

        // Counted rather than asserted absent, because the first write legitimately logged one: what must
        // not happen is a SECOND line for the write that was refused.
        Assert.Single(harness.ControllerLog.Entries.FindAll(entry => entry.Message.Contains("pre-provisioned", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task AnUnknownProvider_IsRefused()
    {
        var harness = Harness();
        Account(harness, Alice, "alice");

        Assert.IsType<BadRequestObjectResult>(await harness.Controller.PreprovisionCanonicalLink("oid", "nosuch", Alice, "sub-alice"));
    }

    [Fact]
    public async Task ADisabledProvider_IsRefused()
    {
        // A link written on a disabled provider survives the disable and mints a login the moment the
        // provider is turned back on, which is the mid-flight-disable window the service write guard closes
        // (#380). The pre-provision path must not open it again.
        var harness = Harness(configure: configuration => configuration.OidConfigs["idp"].Enabled = false);
        Account(harness, Alice, "alice");

        Assert.IsType<BadRequestObjectResult>(await harness.Controller.PreprovisionCanonicalLink("oid", "idp", Alice, "sub-alice"));
        Assert.False(harness.Configuration.OidConfigs["idp"].CanonicalLinks.ContainsKey("sub-alice"));
    }

    [Fact]
    public async Task AnUnknownUserId_IsNotFound_AndWritesNothing()
    {
        // The endpoint links an account a provisioning tool has already created. A link against a GUID no
        // account holds is unreachable bookkeeping no login can redeem, and it is invisible on every
        // per-user listing.
        var harness = Harness();

        Assert.IsType<NotFoundObjectResult>(await harness.Controller.PreprovisionCanonicalLink("oid", "idp", Alice, "sub-alice"));
        Assert.False(harness.Configuration.OidConfigs["idp"].CanonicalLinks.ContainsKey("sub-alice"));
    }

    [Fact]
    public async Task AnEmptyCanonicalName_IsRefused()
    {
        // Fail closed (#95): a blank key persists a dead link no login can ever redeem.
        var harness = Harness();
        Account(harness, Alice, "alice");

        Assert.IsType<BadRequestObjectResult>(await harness.Controller.PreprovisionCanonicalLink("oid", "idp", Alice, "   "));
        Assert.Empty(harness.Configuration.OidConfigs["idp"].CanonicalLinks);
    }

    [Fact]
    public async Task TheSamlArm_WritesToTheSamlProvider()
    {
        // The mode token is parsed at the boundary and threaded inward; with the SAML arm broken the write
        // lands on the OpenID map or nowhere, and both are silent at the HTTP boundary.
        var harness = Harness();
        Account(harness, Alice, "alice");

        Assert.IsType<NoContentResult>(await harness.Controller.PreprovisionCanonicalLink("saml", "sp", Alice, "nameid-alice"));

        Assert.Equal(Alice, harness.Configuration.SamlConfigs["sp"].CanonicalLinks["nameid-alice"]);
        Assert.Empty(harness.Configuration.OidConfigs["idp"].CanonicalLinks);
    }

    [Fact]
    public async Task ASuccessfulWrite_IsAudited_WithoutTheCanonicalSubject()
    {
        // The grant is made on an administrator credential with nothing from the identity provider behind
        // it, so it must leave a trail. The subject is withheld from that trail on purpose: it is the one
        // member of the request that identifies a real person at the identity provider (T-I1).
        var harness = Harness();
        Account(harness, Alice, "alice");

        await harness.Controller.PreprovisionCanonicalLink("oid", "idp", Alice, "sub-alice");

        var entry = Assert.Single(harness.ControllerLog.Entries, e => e.Message.Contains("pre-provisioned", StringComparison.Ordinal));
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("[SSO Audit]", entry.Message, StringComparison.Ordinal);
        Assert.Contains("OpenID", entry.Message, StringComparison.Ordinal);
        Assert.Contains(Alice.ToString(), entry.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("sub-alice", entry.Message, StringComparison.Ordinal);
    }

    // --- helpers ---

    private static SsoControllerHarness Harness(Action<PluginConfiguration>? configure = null)
    {
        return new SsoControllerHarness(configuration =>
        {
            configuration.OidConfigs["idp"] = new OidConfig { Enabled = true };
            configuration.SamlConfigs["sp"] = new SamlConfig { Enabled = true };
            configure?.Invoke(configuration);
        });
    }

    private static void Account(SsoControllerHarness harness, Guid id, string name)
    {
        harness.UserManager.GetUserById(id).Returns(TestUsers.Named(name, id));
    }
}
