// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Reflection;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Http;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Api;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the per-provider bulk unlink (#1519), the way back from a link import that restored
/// the wrong document. The action can take every account on a server off SSO in one call, so what is pinned
/// here is the gate rather than the happy path: elevation, an unknown provider, the caller-supplied count
/// checked server-side, and the mass-lockout refusal (T-D1) with each of the three things that count as a
/// way in for an administrator - a link on another provider, a usable password, and - the one a reader gets
/// wrong - a password that is NOT usable because SSO-only login has taken that door away from every account
/// but the break-glass admin.
/// </summary>
[Collection("SSOController")]
public class SSOControllerPurgeProviderLinksTests
{
    private static readonly Guid AliceId = Guid.Parse("cccccccc-0000-0000-0000-000000000001");
    private static readonly Guid BobId = Guid.Parse("cccccccc-0000-0000-0000-000000000002");
    private static readonly Guid RootId = Guid.Parse("cccccccc-0000-0000-0000-000000000003");

    [Fact]
    public void PurgeProviderLinks_RequiresElevation()
    {
        // It acts on accounts the caller does not own, so no per-user authorization check can stand in for
        // the elevation gate - there is no single subject to check against (STRIDE S, #1519).
        var authorize = typeof(SSOController).GetMethod(nameof(SSOController.PurgeProviderLinks))!.GetCustomAttribute<AuthorizeAttribute>();

        Assert.NotNull(authorize);
        Assert.Equal(Policies.RequiresElevation, authorize!.Policy);
    }

    [Fact]
    public async Task PurgeProviderLinks_UnknownMode_IsRefused()
    {
        var harness = new SsoControllerHarness();

        var result = await harness.Controller.PurgeProviderLinks("ldap", "keycloak", 0);

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task PurgeProviderLinks_UnknownProvider_IsRefused_AndTouchesNothing()
    {
        // A name that resolves to no configured provider must refuse rather than fall through to an empty
        // match that reports success on the wrong table (STRIDE T).
        var harness = SeedProvider(links: 2);

        var result = await harness.Controller.PurgeProviderLinks("oid", "not-configured", 2);

        Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal(2, LinkCount(harness));
    }

    [Fact]
    public async Task PurgeProviderLinks_CountTheCallerDidNotExpect_IsRefused_AndTouchesNothing()
    {
        // The confirmation is a server-side precondition, not a browser dialog: a call written against a
        // stale page refuses instead of removing a different number of links than the operator was shown.
        var harness = SeedProvider(links: 3);

        var result = await harness.Controller.PurgeProviderLinks("oid", "keycloak", 2);

        var conflict = Assert.IsType<ObjectResult>(result);
        Assert.Equal(409, conflict.StatusCode);
        Assert.Contains("holds 3 link(s)", conflict.Value?.ToString(), StringComparison.Ordinal);
        Assert.Equal(3, LinkCount(harness));
    }

    [Fact]
    public async Task PurgeProviderLinks_MatchingCount_RemovesEveryLink_AndAnswersWhatItDid()
    {
        var harness = SeedProvider(links: 3);

        var result = await harness.Controller.PurgeProviderLinks("oid", "keycloak", 3);

        var document = Assert.IsType<ProviderLinkPurgeDocument>(Assert.IsType<OkObjectResult>(result).Value);
        Assert.Equal(3, document.Removed);
        Assert.Equal(0, LinkCount(harness));
    }

    [Fact]
    public async Task PurgeProviderLinks_TakesTheIssuerDeadlineAndLastLoginStampsWithTheLinks()
    {
        // The stamps are keyed on the links; leaving one behind would judge a re-link of the same subject
        // against a stale issuer binding (#186), expire it on the next sweep tick (#1145), or report a
        // "last SSO login" that belongs to the previous holder of the key (#1120).
        var harness = SeedProvider(links: 1);
        SSOPlugin.Instance.MutateConfiguration(c =>
        {
            var config = c.OidConfigs["keycloak"];
            config.CanonicalLinkIssuers["sub-0"] = "https://idp.example";
            config.CanonicalLinkDeadlines["sub-0"] = DateTime.UtcNow.AddDays(1);
            config.CanonicalLinkLastLogins["sub-0"] = DateTime.UtcNow;
        });

        await harness.Controller.PurgeProviderLinks("oid", "keycloak", 1);

        SSOPlugin.Instance.ReadConfiguration(c =>
        {
            var config = c.OidConfigs["keycloak"];
            Assert.Empty(config.CanonicalLinks);
            Assert.Empty(config.CanonicalLinkIssuers);
            Assert.Empty(config.CanonicalLinkDeadlines);
            Assert.Empty(config.CanonicalLinkLastLogins);
            return 0;
        });
    }

    [Fact]
    public async Task PurgeProviderLinks_SignsOutOnlyTheAccountsLeftWithNoLinkAnywhere()
    {
        // The same scope the single unlink revokes at (#468): an account that keeps a link on another
        // provider still has a working SSO identity, so revoking it would be an unscoped mass-logout with
        // no security gain.
        var harness = new SsoControllerHarness(c =>
        {
            c.OidConfigs["keycloak"] = new OidConfig
            {
                CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-alice"] = AliceId, ["sub-bob"] = BobId },
            };
            c.SamlConfigs["adfs"] = new SamlConfig
            {
                CanonicalLinks = new SerializableDictionary<string, Guid> { ["nameid-bob"] = BobId },
            };
        });
        SeedUser(harness, "alice", AliceId);
        SeedUser(harness, "bob", BobId);

        var result = await harness.Controller.PurgeProviderLinks("oid", "keycloak", 2);

        var document = Assert.IsType<ProviderLinkPurgeDocument>(Assert.IsType<OkObjectResult>(result).Value);
        Assert.Equal(2, document.Removed);
        Assert.Equal(1, document.SignedOut);
        await harness.SessionManager.Received(1).RevokeUserTokens(AliceId, null);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(BobId, null);
    }

    [Fact]
    public async Task PurgeProviderLinks_ThatWouldTakeAnAdministratorsLastWayIn_IsRefused_AndTouchesNothing()
    {
        // T-D1 on this surface. The administrator signs in through this provider alone and holds no usable
        // password, so emptying the table would lock the server's own administration out - and the run
        // REFUSES rather than quietly keeping that one link, which would leave the provider not empty while
        // the answer said it was.
        var harness = SeedProvider(links: 1);
        SeedAdminLinkedTo(harness, "root", RootId, "sub-root", withPassword: false);

        var result = await harness.Controller.PurgeProviderLinks("oid", "keycloak", 2);

        var conflict = Assert.IsType<ObjectResult>(result);
        Assert.Equal(409, conflict.StatusCode);
        Assert.Contains("root", conflict.Value?.ToString(), StringComparison.Ordinal);
        Assert.Equal(2, LinkCount(harness));
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string>());
    }

    [Fact]
    public async Task PurgeProviderLinks_WithAnAdministratorWhoCanStillUseAPassword_Proceeds()
    {
        // The falsifier for the refusal above: one field changes - the administrator has a usable password
        // door - and the same call goes through. Without it the guard could be refusing for any reason.
        var harness = SeedProvider(links: 1);
        SeedAdminLinkedTo(harness, "root", RootId, "sub-root", withPassword: true);

        var result = await harness.Controller.PurgeProviderLinks("oid", "keycloak", 2);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal(0, LinkCount(harness));
    }

    [Fact]
    public async Task PurgeProviderLinks_WithAnAdministratorLinkedToAnotherProvider_Proceeds()
    {
        // The second way in: a link on another provider. The administrator loses the keycloak link and can
        // still sign in through adfs, so this run takes nobody's last door.
        var harness = SeedProvider(links: 1);
        SeedAdminLinkedTo(harness, "root", RootId, "sub-root", withPassword: false);
        SSOPlugin.Instance.MutateConfiguration(c => c.SamlConfigs["adfs"] = new SamlConfig
        {
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["nameid-root"] = RootId },
        });

        var result = await harness.Controller.PurgeProviderLinks("oid", "keycloak", 2);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal(0, LinkCount(harness));
    }

    [Fact]
    public async Task PurgeProviderLinks_UnderSsoOnlyLogin_DoesNotCountANonExemptAdministratorsPassword()
    {
        // The reading a hand-written guard gets wrong. The administrator routes to the built-in password
        // provider and carries a stored password, so the account-side reading says "has a password door" -
        // but SSO-only login is on and this account is not the designated break-glass admin, so that door is
        // shut for it. Counting it would strand exactly the administrator the mode was configured to keep
        // out of the password path.
        var harness = SeedProvider(links: 1);
        SeedAdminLinkedTo(harness, "root", RootId, "sub-root", withPassword: true);
        SSOPlugin.Instance.MutateConfiguration(c =>
        {
            c.DisablePasswordLogin = true;
            c.BreakGlassAdminUsername = "somebody-else";
        });

        var result = await harness.Controller.PurgeProviderLinks("oid", "keycloak", 2);

        Assert.Equal(409, Assert.IsType<ObjectResult>(result).StatusCode);
        Assert.Equal(2, LinkCount(harness));
    }

    [Fact]
    public async Task PurgeProviderLinks_UnderSsoOnlyLogin_CountsTheBreakGlassAdministratorsPassword()
    {
        // The other half of the same rule, so the test above cannot pass merely because the mode flag
        // refuses everything: the break-glass admin is the one account whose password door the mode leaves
        // standing, and the purge goes through.
        var harness = SeedProvider(links: 1);
        SeedAdminLinkedTo(harness, "root", RootId, "sub-root", withPassword: true);
        SSOPlugin.Instance.MutateConfiguration(c =>
        {
            c.DisablePasswordLogin = true;
            c.BreakGlassAdminUsername = "root";
        });

        var result = await harness.Controller.PurgeProviderLinks("oid", "keycloak", 2);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal(0, LinkCount(harness));
    }

    [Fact]
    public async Task PurgeProviderLinks_WithADisabledAdministrator_Proceeds()
    {
        // A disabled account already has no way in, so this run takes nothing from it. Refusing here would
        // make a disabled administrator a permanent block on an action that exists to unstick a server.
        var harness = SeedProvider(links: 1);
        var root = SeedAdminLinkedTo(harness, "root", RootId, "sub-root", withPassword: false);
        root.SetPermission(PermissionKind.IsDisabled, true);

        var result = await harness.Controller.PurgeProviderLinks("oid", "keycloak", 2);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal(0, LinkCount(harness));
    }

    [Fact]
    public async Task PurgeProviderLinks_OnADisabledProvider_StillRemoves()
    {
        // Removal REVOKES a grant, so it must keep working on a disabled provider - disable-then-clean-up is
        // the workflow this action exists for (#380).
        var harness = SeedProvider(links: 2);
        SSOPlugin.Instance.MutateConfiguration(c => c.OidConfigs["keycloak"].Enabled = false);

        var result = await harness.Controller.PurgeProviderLinks("oid", "keycloak", 2);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal(0, LinkCount(harness));
    }

    [Fact]
    public async Task PurgeProviderLinks_AuditsBothTheActAndTheRefusal()
    {
        // A bulk removal must not reach an operator as N indistinguishable per-user lines with no statement
        // of the act, and a blocked mass-lockout must leave a trail of its own (T-R1).
        var harness = SeedProvider(links: 2);

        await harness.Controller.PurgeProviderLinks("oid", "keycloak", 1);
        await harness.Controller.PurgeProviderLinks("oid", "keycloak", 2);

        var log = string.Join("\n", harness.ControllerLog.Records.ConvertAll(r => r.Message));
        Assert.Contains("Bulk unlink REFUSED", log, StringComparison.Ordinal);
        Assert.Contains("CountMismatch", log, StringComparison.Ordinal);
        Assert.Contains("Every canonical link on", log, StringComparison.Ordinal);
    }

    // A provider carrying `links` canonical links, each on its own account, none of them an administrator.
    private static SsoControllerHarness SeedProvider(int links)
    {
        var harness = new SsoControllerHarness(c =>
        {
            var config = new OidConfig { CanonicalLinks = new SerializableDictionary<string, Guid>() };
            for (var i = 0; i < links; i++)
            {
                config.CanonicalLinks["sub-" + i.ToString(System.Globalization.CultureInfo.InvariantCulture)] = Guid.NewGuid();
            }

            c.OidConfigs["keycloak"] = config;
        });

        return harness;
    }

    // An administrator whose only link is the given one on keycloak, with or without a usable password door.
    private static User SeedAdminLinkedTo(SsoControllerHarness harness, string name, Guid id, string canonicalName, bool withPassword)
    {
        SSOPlugin.Instance.MutateConfiguration(c => c.OidConfigs["keycloak"].CanonicalLinks[canonicalName] = id);

        var user = SeedUser(harness, name, id);
        user.SetPermission(PermissionKind.IsAdministrator, true);
        if (withPassword)
        {
            user.AuthenticationProviderId = SsoAuthenticationProviders.DefaultPasswordProviderId;
            user.Password = "hash-" + name;
        }

        return user;
    }

    private static User SeedUser(SsoControllerHarness harness, string name, Guid id)
    {
        var user = TestUsers.Named(name, id);
        harness.UserManager.GetUserById(id).Returns(user);
        harness.UserManager.GetUserByName(name).Returns(user);
        return user;
    }

    private static int LinkCount(SsoControllerHarness harness)
        => SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["keycloak"].CanonicalLinks.Count);
}
