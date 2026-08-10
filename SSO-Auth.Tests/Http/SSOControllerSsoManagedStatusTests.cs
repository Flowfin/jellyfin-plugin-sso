// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the per-account SSO-managed report (#1136) via <see cref="SsoControllerHarness"/>.
/// The endpoint exists because "holds a link" and "cannot log in with a password" are different facts that
/// a caller previously had to infer from two link maps, so the tests are built around the four combinations
/// where that inference goes wrong, rather than around a happy path.
/// </summary>
[Collection("SSOController")]
public class SSOControllerSsoManagedStatusTests
{
    private static readonly Guid Alice = Guid.Parse("a11ce000-0000-0000-0000-000000000001");
    private static readonly Guid Bob = Guid.Parse("b0b00000-0000-0000-0000-000000000002");

    private const string PasswordProviderId = "Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider";

    [Fact]
    public void SsoStampedAccountHoldingALink_ReportsBothFacts()
    {
        var harness = Harness(oidLinks: new Dictionary<string, Guid> { ["sub-alice"] = Alice });
        StampedUser(harness, Alice, SsoManagedProviderId.Value);

        var report = Report(harness, Alice);

        Assert.True(report.GetProperty("PasswordLoginDisabled").GetBoolean());
        Assert.True(report.GetProperty("HasCanonicalLink").GetBoolean());
    }

    [Fact]
    public void SsoStampedAccountWithNoLinkLeft_StillReportsPasswordLoginDisabled()
    {
        // The state an account is left in after every link is removed without the provider id being put
        // back. Reading "has links" as "password login is off" gets this one wrong in the safe direction;
        // reading it the other way round gets the next test wrong in the unsafe one.
        var harness = Harness();
        StampedUser(harness, Alice, SsoManagedProviderId.Value);

        var report = Report(harness, Alice);

        Assert.True(report.GetProperty("PasswordLoginDisabled").GetBoolean());
        Assert.False(report.GetProperty("HasCanonicalLink").GetBoolean());
    }

    [Fact]
    public void PasswordAccountHoldingALink_ReportsPasswordLoginStillEnabled()
    {
        // The combination this endpoint exists for: the account can sign in through the identity provider
        // AND with its Jellyfin password. A caller that offered no password field here would be hiding a
        // credential that still works.
        var harness = Harness(oidLinks: new Dictionary<string, Guid> { ["sub-alice"] = Alice });
        StampedUser(harness, Alice, PasswordProviderId);

        var report = Report(harness, Alice);

        Assert.False(report.GetProperty("PasswordLoginDisabled").GetBoolean());
        Assert.True(report.GetProperty("HasCanonicalLink").GetBoolean());
    }

    [Fact]
    public void PlainPasswordAccount_ReportsNeitherFact()
    {
        var harness = Harness();
        StampedUser(harness, Alice, PasswordProviderId);

        var report = Report(harness, Alice);

        Assert.False(report.GetProperty("PasswordLoginDisabled").GetBoolean());
        Assert.False(report.GetProperty("HasCanonicalLink").GetBoolean());
    }

    [Fact]
    public void ALinkOnASamlProviderAlone_IsReported()
    {
        // The link test is an OR over both protocols. With the SAML arm removed this is the case that goes
        // red, so the arm is proven rather than merely present.
        var harness = Harness(samlLinks: new Dictionary<string, Guid> { ["nameid-alice"] = Alice });
        StampedUser(harness, Alice, PasswordProviderId);

        Assert.True(Report(harness, Alice).GetProperty("HasCanonicalLink").GetBoolean());
    }

    [Fact]
    public void ALinkBelongingToAnotherAccount_IsNotReportedAsThisOnes()
    {
        // A provider carrying links is not the same as this user carrying one. Without the per-user filter
        // every account on a server with any link at all would report as linked.
        var harness = Harness(oidLinks: new Dictionary<string, Guid> { ["sub-bob"] = Bob });
        StampedUser(harness, Alice, PasswordProviderId);

        Assert.False(Report(harness, Alice).GetProperty("HasCanonicalLink").GetBoolean());
    }

    [Fact]
    public void AnUnknownUserId_IsNotFound_RatherThanAnAccountWithNothingSet()
    {
        // "This account uses a password" and "there is no such account" are different answers and a caller
        // that cannot tell them apart offers a password field for an account it will fail to find.
        var harness = Harness();

        var result = harness.Controller.SsoManagedStatus(Alice);

        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public void TheReport_CarriesTheTwoFactsAndNothingElse()
    {
        // The response is what leaves the server, so the bound on it is a bound on the whole payload rather
        // than on the members somebody remembered to check. A provider secret sits in the configuration this
        // action reads through, which is what makes the absence assertion meaningful.
        const string Secret = "provider-secret-that-must-never-leave";
        var harness = Harness(
            oidLinks: new Dictionary<string, Guid> { ["sub-alice"] = Alice },
            configure: configuration => configuration.OidConfigs["idp"].OidSecret = Secret);
        StampedUser(harness, Alice, SsoManagedProviderId.Value);

        var body = JsonSerializer.Serialize(Assert.IsType<OkObjectResult>(harness.Controller.SsoManagedStatus(Alice)).Value);

        Assert.Equal(
            new[] { "HasCanonicalLink", "PasswordLoginDisabled" },
            JsonDocument.Parse(body).RootElement.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal));
        Assert.DoesNotContain(Secret, body, StringComparison.Ordinal);
        Assert.DoesNotContain("sub-alice", body, StringComparison.Ordinal);
    }

    // --- helpers ---

    private static SsoControllerHarness Harness(
        IDictionary<string, Guid>? oidLinks = null,
        IDictionary<string, Guid>? samlLinks = null,
        Action<PluginConfiguration>? configure = null)
    {
        return new SsoControllerHarness(configuration =>
        {
            configuration.OidConfigs["idp"] = new OidConfig
            {
                Enabled = true,
                CanonicalLinks = Map(oidLinks),
            };
            configuration.SamlConfigs["saml"] = new SamlConfig
            {
                Enabled = true,
                CanonicalLinks = Map(samlLinks),
            };
            configure?.Invoke(configuration);
        });
    }

    private static SerializableDictionary<string, Guid> Map(IDictionary<string, Guid>? links)
    {
        var map = new SerializableDictionary<string, Guid>();
        foreach (var link in links ?? new Dictionary<string, Guid>())
        {
            map[link.Key] = link.Value;
        }

        return map;
    }

    private static void StampedUser(SsoControllerHarness harness, Guid id, string authenticationProviderId)
    {
        var user = TestUsers.Named("alice", id);
        user.AuthenticationProviderId = authenticationProviderId;
        harness.UserManager.GetUserById(id).Returns(user);
    }

    private static JsonElement Report(SsoControllerHarness harness, Guid id)
    {
        var value = Assert.IsType<OkObjectResult>(harness.Controller.SsoManagedStatus(id)).Value;
        return JsonDocument.Parse(JsonSerializer.Serialize(value)).RootElement;
    }
}
