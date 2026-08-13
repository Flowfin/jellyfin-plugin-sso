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
/// In-process tests of the linked-account roster (#1119). Two properties carry the endpoint: an account
/// linked to several providers is ONE row rather than one row per link, and a link whose user id resolves
/// to no account is reported rather than dropped. The second is what separates this document from the
/// portable export, which drops exactly that row on purpose, so it is asserted here rather than left to be
/// inferred from the builder they share.
/// </summary>
[Collection("SSOController")]
public class SSOControllerLinkRosterTests
{
    private static readonly Guid Alice = Guid.Parse("a11ce000-0000-0000-0000-000000000001");
    private static readonly Guid Bob = Guid.Parse("b0b00000-0000-0000-0000-000000000002");
    private static readonly Guid Ghost = Guid.Parse("9057c000-0000-0000-0000-000000000003");

    [Fact]
    public void AnAccountLinkedToTwoProviders_IsOneRowWithTwoLinks()
    {
        var harness = Harness();
        Know(harness, Alice, "alice");
        Know(harness, Bob, "bob");

        var alice = Assert.Single(Roster(harness).Accounts, account => account.UserId == Alice);

        Assert.Equal("alice", alice.Username);
        Assert.True(alice.AccountExists);
        Assert.Equal(
            new[] { ("OpenID", "idp", "sub-alice"), ("SAML", "adfs", "alice@example.test") },
            alice.Links
                .Select(link => (link.Protocol!, link.Provider!, link.CanonicalName!))
                .OrderBy(entry => entry.Item1, StringComparer.Ordinal)
                .ToArray());
    }

    [Fact]
    public void AnAccountWithNoLink_IsAbsent()
    {
        // The roster answers "who is linked". A server's whole user list is not the answer, and an
        // administrator reading one to find the other is the work this endpoint exists to remove.
        var harness = Harness();
        Know(harness, Alice, "alice");
        Know(harness, Bob, "bob");
        var unlinked = Guid.Parse("c0ffee00-0000-0000-0000-000000000004");
        Know(harness, unlinked, "carol");

        Assert.DoesNotContain(unlinked, Roster(harness).Accounts.Select(account => account.UserId));
    }

    [Fact]
    public void ALinkTheUserManagerNoLongerKnows_IsReportedNotDropped()
    {
        // The harness's user manager answers null for an id it was never told about, which is the state a
        // deleted account leaves behind. Dropping the row would hide the one thing no other surface shows.
        var harness = Harness(withGhost: true);
        Know(harness, Alice, "alice");
        Know(harness, Bob, "bob");

        var ghost = Assert.Single(Roster(harness).Accounts, account => account.UserId == Ghost);

        Assert.False(ghost.AccountExists);
        Assert.Null(ghost.Username);
        Assert.Equal("sub-ghost", Assert.Single(ghost.Links).CanonicalName);
    }

    [Fact]
    public void TheRosterCarriesNoProviderConfiguration()
    {
        // The roster is assembled from the link maps alone. Nothing copies a provider field, so a client
        // secret cannot ride along - this pins that the seeded secret is nowhere in the serialized answer,
        // which is the form a leak would actually take.
        var harness = Harness(secret: "super-secret-value");
        Know(harness, Alice, "alice");
        Know(harness, Bob, "bob");

        var json = System.Text.Json.JsonSerializer.Serialize(Roster(harness));

        Assert.DoesNotContain("super-secret-value", json, StringComparison.Ordinal);
    }

    private static LinkRosterDocument Roster(SsoControllerHarness harness) =>
        Assert.IsType<LinkRosterDocument>(Assert.IsType<OkObjectResult>(harness.Controller.LinkedAccountRoster()).Value);

    private static void Know(SsoControllerHarness harness, Guid id, string name) =>
        harness.UserManager.GetUserById(id).Returns(TestUsers.Named(name, id));

    private static SsoControllerHarness Harness(bool withGhost = false, string? secret = null)
    {
        return new SsoControllerHarness(configuration =>
        {
            var oidLinks = new SerializableDictionary<string, Guid> { ["sub-alice"] = Alice, ["sub-bob"] = Bob };
            if (withGhost)
            {
                oidLinks["sub-ghost"] = Ghost;
            }

            configuration.OidConfigs["idp"] = new OidConfig
            {
                Enabled = true,
                OidSecret = secret,
                CanonicalLinks = oidLinks,
            };
            configuration.SamlConfigs["adfs"] = new SamlConfig
            {
                Enabled = true,
                CanonicalLinks = new SerializableDictionary<string, Guid> { ["alice@example.test"] = Alice },
            };
        });
    }
}
