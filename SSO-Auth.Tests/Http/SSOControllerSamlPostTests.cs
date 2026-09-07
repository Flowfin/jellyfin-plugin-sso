// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Api.Events;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Events;
using MediaBrowser.Controller.Events.Authentication;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the SAML assertion-consumer callback (<c>SamlPost</c>) via
/// <see cref="SsoControllerHarness"/>, using <see cref="SamlTestFactory"/> to produce a real, signed
/// response so the actual signature-validation path runs. They cover the guard branches (disabled
/// provider, invalid signature, role not allowed) and the happy path, where a valid signed assertion
/// renders the intermediate auth page (an HTML <see cref="ContentResult"/> that later posts to SamlAuth).
/// </summary>
[Collection("SSOController")]
public class SSOControllerSamlPostTests
{
    [Fact]
    public async Task SamlPost_DisabledProvider_Returns400()
    {
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig { Enabled = false });

        var result = await harness.Controller.SamlCallback("adfs", formSamlResponse: "irrelevant");

        // Shares the unknown-provider body now (the unique "No active providers found" wording is
        // retired), so a disabled provider cannot be told apart from an unknown one (#318).
        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("No matching provider found", content.Content);
    }

    [Fact]
    public async Task SamlPost_SignedByAnotherCertificate_Returns400()
    {
        var fixture = SamlTestFactory.Create();
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            // The provider trusts a different certificate, so the real signature check must reject it.
            SamlCertificate = SamlFixture.ForeignCertificateBase64(),
        });

        var result = await harness.Controller.SamlCallback("adfs", formSamlResponse: fixture.EncodeResponse());

        Assert.Equal(400, Assert.IsType<ContentResult>(result).StatusCode);
    }

    [Fact]
    public async Task SamlPost_RoleNotAllowed_Returns401()
    {
        var fixture = SamlTestFactory.Create(role: "jellyfin-users");
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = fixture.CertificateBase64,
            DoNotValidateAudience = true, // audience validation is covered separately
            Roles = new[] { "only-admins" },
        });

        var result = await harness.Controller.SamlCallback("adfs", formSamlResponse: fixture.EncodeResponse());

        Assert.Equal(401, Assert.IsType<ContentResult>(result).StatusCode);
    }


    [Fact]
    public async Task SamlPost_RoleNotAllowed_PublishesTheHostDenialNamingTheProviderAndReason()
    {
        // #1142 on the SAML leg, the mirror of the OpenID case: the role-refused login publishes Jellyfin's
        // own authentication-failed event, which is the only event type a configured webhook destination can
        // receive. The provider and a fixed reason ride in the client and device fields; nothing about the
        // person travels - the NameID this branch has in hand is exactly what must not leave the machine.
        var fixture = SamlTestFactory.Create(nameId: "alice", role: "jellyfin-users");
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = fixture.CertificateBase64,
            DoNotValidateAudience = true,
            Roles = new[] { "only-admins" },
        });

        var result = await harness.Controller.SamlCallback("adfs", formSamlResponse: fixture.EncodeResponse());

        Assert.Equal(401, Assert.IsType<ContentResult>(result).StatusCode);
        var published = Assert.IsType<AuthenticationRequestEventArgs>(
            harness.EventManager.ReceivedCalls()
                .Single(c => string.Equals(c.GetMethodInfo().Name, "PublishAsync", StringComparison.Ordinal))
                .GetArguments()[0]);
        Assert.Equal("SSO/adfs", published.App);
        Assert.Equal(SsoLoginEvents.RoleDeniedReason, published.DeviceName);
        Assert.Equal(string.Empty, published.Username);
        Assert.DoesNotContain("alice", published.DeviceName + published.App + published.Username, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SamlPost_SignedByAnotherCertificate_PublishesNoDenial()
    {
        // The one-change neighbour: a rejection that is NOT the role gate publishes nothing. Without this the
        // suite could not tell a publish bound to the allow-list from one bound to any 4xx the callback gives.
        var fixture = SamlTestFactory.Create();
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = SamlFixture.ForeignCertificateBase64(),
        });

        _ = await harness.Controller.SamlCallback("adfs", formSamlResponse: fixture.EncodeResponse());

        await harness.EventManager.DidNotReceive().PublishAsync(Arg.Any<AuthenticationRequestEventArgs>());
    }

    [Fact]
    public async Task SamlPost_RoleDeniedWithDeprovisionOn_DisablesTheLinkedNonAdmin()
    {
        // #831 end-to-end on the SAML leg: a signed assertion whose role is not on the allow-list is denied,
        // and with the opt-in on the account already linked under this NameID is disabled - the mirror of the
        // OpenID deprovisioning path, pinned directly because the SAML callback resolves the subject key (the
        // NameID) on its own denied branch.
        var linked = Guid.Parse("77777777-7777-7777-7777-777777777777");
        var user = TestUsers.Named("alice", linked);
        var fixture = SamlTestFactory.Create(nameId: "alice", role: "jellyfin-users");
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = fixture.CertificateBase64,
            DoNotValidateAudience = true,
            Roles = new[] { "only-admins" },
            DisableAccountOnRoleDenied = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = linked },
        });
        harness.UserManager.GetUserById(linked).Returns(user);

        var result = await harness.Controller.SamlCallback("adfs", formSamlResponse: fixture.EncodeResponse());

        Assert.Equal(401, Assert.IsType<ContentResult>(result).StatusCode); // still a clean denial
        Assert.True(user.HasPermission(PermissionKind.IsDisabled)); // the revoked account is deprovisioned
        await harness.UserManager.Received(1).UpdateUserAsync(user);
    }

    [Fact]
    public async Task SamlPost_RoleDeniedWithDeprovisionOff_LeavesTheLinkedAccountEnabled()
    {
        // #831 default (opt-in off) on the SAML leg - the sibling of the OpenID OFF case, added for #928
        // protocol parity: the same role-denied assertion must NOT disable the linked account when the
        // toggle is off (the default). Deprovisioning is strictly opt-in, so an existing deployment sees no
        // behavior change and a transient IdP role glitch cannot silently lock users out.
        var linked = Guid.Parse("77777777-7777-7777-7777-777777777777");
        var user = TestUsers.Named("alice", linked);
        var fixture = SamlTestFactory.Create(nameId: "alice", role: "jellyfin-users");
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = fixture.CertificateBase64,
            DoNotValidateAudience = true,
            Roles = new[] { "only-admins" },
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice"] = linked },
        });
        harness.UserManager.GetUserById(linked).Returns(user);

        var result = await harness.Controller.SamlCallback("adfs", formSamlResponse: fixture.EncodeResponse());

        Assert.Equal(401, Assert.IsType<ContentResult>(result).StatusCode); // still a clean denial
        Assert.False(user.HasPermission(PermissionKind.IsDisabled)); // untouched - deprovisioning is opt-in
        await harness.UserManager.DidNotReceive().UpdateUserAsync(user);
    }

    [Fact]
    public async Task SamlPost_ValidSignedResponse_RendersTheAuthPage()
    {
        var fixture = SamlTestFactory.Create(nameId: "alice");
        var harness = new SsoControllerHarness(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            Enabled = true,
            SamlCertificate = fixture.CertificateBase64,
            DoNotValidateAudience = true,
        });

        var result = await harness.Controller.SamlCallback("adfs", formSamlResponse: fixture.EncodeResponse());

        // A valid assertion renders the intermediate HTML auth page (which then posts to SamlAuth).
        var page = Assert.IsType<ContentResult>(result);
        Assert.Equal("text/html", page.ContentType);
        Assert.False(string.IsNullOrEmpty(page.Content));
        // The page is served with the hardened CSP the auth page sets.
        Assert.True(harness.Controller.Response.Headers.ContainsKey("Content-Security-Policy"));
    }
}
