// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Identity;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Controller.Session;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The approve action (#1529): what it may act on, what it does, and what it refuses.
/// <para>
/// It exists because the Jellyfin disabled flag does not say who set it. The action therefore acts on this
/// plugin's own RECORD of having provisioned an account inert and never on the flag, and the test that
/// carries the whole feature is the negative one: an account an administrator disabled deliberately has no
/// record, so this route cannot see it, cannot list it and cannot enable it. Delete the record check and
/// that row goes red while every positive one stays green.
/// </para>
/// <para>
/// The second property is that approving GRANTS NOTHING BUT THE ENABLE. The provisioning policy decided the
/// account's permissions when it created it; an approve that also granted would be a second provisioning
/// policy that nobody configured, in a button. The third is the state re-read: a record says what was true
/// at provisioning, and each way it can have become false since has its own arm here.
/// </para>
/// </summary>
public class PendingApprovalActionTests
{
    private static readonly Guid Pending = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid Other = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly DateTime Now = new(2026, 9, 11, 9, 0, 0, DateTimeKind.Utc);

    [Fact]
    public async Task AnAccountThisPluginProvisionedInert_IsEnabled()
    {
        var (service, config, users) = Build();
        var user = Recorded(users, config, disabled: true, admin: false);

        var (outcome, approved) = await service.ApproveProvisionedAccountAsync(ProviderMode.Oid, "kc", "sub-1");

        Assert.Equal(PendingApprovalResult.Approved, outcome);
        Assert.Equal(Pending, approved);
        Assert.False(user.HasPermission(PermissionKind.IsDisabled));
        await users.Received(1).UpdateUserAsync(user);

        // The record goes with the act it described: the account is no longer waiting, so leaving it would
        // keep an enabled account on a list of accounts that cannot sign in.
        Assert.Empty(config.CanonicalLinkPendingApprovals);
    }

    [Fact]
    public async Task ADisabledAccountWithNoRecord_IsInvisibleToThisRoute()
    {
        // THE ROW THE FEATURE IS FOR. This is the account an administrator disabled on purpose: linked,
        // disabled, and never provisioned inert by this plugin. The flag alone cannot tell it apart from the
        // row above, which is why this route never reads the flag to decide.
        var (service, config, users) = Build();
        var user = Recorded(users, config, disabled: true, admin: false);
        config.CanonicalLinkPendingApprovals.Clear();

        var (outcome, _) = await service.ApproveProvisionedAccountAsync(ProviderMode.Oid, "kc", "sub-1");

        Assert.Equal(PendingApprovalResult.NotPending, outcome);
        Assert.True(user.HasPermission(PermissionKind.IsDisabled));
        await users.DidNotReceive().UpdateUserAsync(Arg.Any<User>());
    }

    [Fact]
    public async Task ARecordNamingAnotherAccount_IsNotActedOn()
    {
        // The rebind case, from the acting side. The record is about an account this key no longer points
        // at, so it says nothing about the account it would enable - and the account it would enable is
        // whoever holds the key now.
        var (service, config, users) = Build();
        var user = Recorded(users, config, disabled: true, admin: false);
        config.CanonicalLinkPendingApprovals["sub-1"] = new PendingApproval { UserId = Other, SinceUtc = Now };

        var (outcome, _) = await service.ApproveProvisionedAccountAsync(ProviderMode.Oid, "kc", "sub-1");

        Assert.Equal(PendingApprovalResult.NotPending, outcome);
        Assert.True(user.HasPermission(PermissionKind.IsDisabled));
    }

    [Fact]
    public async Task AnAdministrator_IsRefused_AndKeepsItsRecord()
    {
        // T-D1 read from the other direction: the guard that keeps this plugin from DISABLING an
        // administrator has a twin that keeps it from ENABLING one. Re-admitting an administrator is the one
        // mistake on this page that the same page cannot walk back. The record is true and stays; what is
        // refused is this route acting on it.
        var (service, config, users) = Build();
        var user = Recorded(users, config, disabled: true, admin: true);

        var (outcome, _) = await service.ApproveProvisionedAccountAsync(ProviderMode.Oid, "kc", "sub-1");

        Assert.Equal(PendingApprovalResult.Administrator, outcome);
        Assert.True(user.HasPermission(PermissionKind.IsDisabled));
        Assert.Single(config.CanonicalLinkPendingApprovals);
        await users.DidNotReceive().UpdateUserAsync(Arg.Any<User>());
    }

    [Fact]
    public async Task AnAccountEnabledSinceItWasProvisioned_LosesTheRecordAndIsNotRe_enabled()
    {
        // #1637: an administrator can enable the account in the Jellyfin dashboard, which this plugin does
        // not see. The record is then false, and the danger is not this call - it is the NEXT one, after
        // somebody disables that account as a sanction. Observed here, the record goes.
        var (service, config, users) = Build();
        var user = Recorded(users, config, disabled: false, admin: false);

        var (outcome, _) = await service.ApproveProvisionedAccountAsync(ProviderMode.Oid, "kc", "sub-1");

        Assert.Equal(PendingApprovalResult.AlreadyEnabled, outcome);
        Assert.Empty(config.CanonicalLinkPendingApprovals);
        await users.DidNotReceive().UpdateUserAsync(user);
    }

    [Fact]
    public async Task ARecordWhoseAccountIsGone_IsCleared()
    {
        var (service, config, users) = Build();
        Recorded(users, config, disabled: true, admin: false);
        users.GetUserById(Pending).Returns((User?)null);

        var (outcome, _) = await service.ApproveProvisionedAccountAsync(ProviderMode.Oid, "kc", "sub-1");

        Assert.Equal(PendingApprovalResult.AccountGone, outcome);
        Assert.Empty(config.CanonicalLinkPendingApprovals);
    }

    [Fact]
    public async Task AnUnknownProvider_IsItsOwnAnswer_AndChangesNothing()
    {
        // Distinct from NotPending on purpose: collapsing the two would make the endpoint answer the same
        // way for a provider that does not exist and an identity that is not pending, which is how a
        // refusal becomes an oracle for provider names.
        var (service, config, users) = Build();
        Recorded(users, config, disabled: true, admin: false);

        var (outcome, _) = await service.ApproveProvisionedAccountAsync(ProviderMode.Oid, "nope", "sub-1");

        Assert.Equal(PendingApprovalResult.UnknownProvider, outcome);
        Assert.Single(config.CanonicalLinkPendingApprovals);
    }

    [Fact]
    public async Task ApprovingGrantsNothingButTheEnable()
    {
        // The provisioning policy decided this account's permissions. An approve that also granted would be
        // a second provisioning policy in a button, configured by nobody, and the administrator pressing it
        // would have no way to know what it handed out.
        var (service, config, users) = Build();
        var user = Recorded(users, config, disabled: true, admin: false);
        user.SetPermission(PermissionKind.EnableAllFolders, false);
        user.SetPermission(PermissionKind.EnableRemoteAccess, false);
        user.SetPermission(PermissionKind.EnableLiveTvAccess, false);

        await service.ApproveProvisionedAccountAsync(ProviderMode.Oid, "kc", "sub-1");

        Assert.False(user.HasPermission(PermissionKind.IsDisabled));
        Assert.False(user.HasPermission(PermissionKind.IsAdministrator));
        Assert.False(user.HasPermission(PermissionKind.EnableAllFolders));
        Assert.False(user.HasPermission(PermissionKind.EnableRemoteAccess));
        Assert.False(user.HasPermission(PermissionKind.EnableLiveTvAccess));
    }

    [Fact]
    public async Task ASuccessfulLogin_ClearsAStandingRecord()
    {
        // The second observation point for #1637, and the one that does not need an administrator to press
        // anything: a minted session proves the account is past the pending-approval gate, so a record still
        // standing on it is false. Without this, an account enabled by hand and later sanctioned would be
        // offered for approval again.
        var config = new OidConfig { Enabled = true };
        var (service, users, _) = BuildLogin(config);
        var user = TestUsers.Named("alice", Pending);
        users.GetUserById(Pending).Returns(user);
        users.GetUserByName("alice").Returns(user);
        config.CanonicalLinks["sub-1"] = Pending;
        config.CanonicalLinkPendingApprovals["sub-1"] = new PendingApproval { UserId = Pending, SinceUtc = Now };

        await service.CompleteAsync(Identity(), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        Assert.Empty(config.CanonicalLinkPendingApprovals);
    }

    [Fact]
    public async Task ARefusedLoginOfAPendingAccount_LeavesItsRecordStanding()
    {
        // The other half of the placement, and the one that would silently empty the approval list: the
        // pending account's own repeated logins are REFUSED at the gate, so they must not clear the record
        // that puts it on the list. A clear written before the gate rather than after it turns every login
        // attempt by a waiting user into a removal of their own row.
        var config = new OidConfig { Enabled = true };
        var (service, users, _) = BuildLogin(config);
        var user = TestUsers.Named("alice", Pending);
        user.SetPermission(PermissionKind.IsDisabled, true);
        users.GetUserById(Pending).Returns(user);
        users.GetUserByName("alice").Returns(user);
        config.CanonicalLinks["sub-1"] = Pending;
        config.CanonicalLinkPendingApprovals["sub-1"] = new PendingApproval { UserId = Pending, SinceUtc = Now };

        await service.CompleteAsync(Identity(), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        Assert.Single(config.CanonicalLinkPendingApprovals);
    }

    [Fact]
    public void TheRosterOffersExactlyWhatTheActionWouldAccept()
    {
        // One rule, two readers. A row the page presents as waiting and a call the action refuses would be
        // the same defect seen from either side, so both ask PendingApproval.Live and this pins that they
        // agree on the three shapes that differ: recorded and live, recorded about another account, and not
        // recorded at all.
        var configuration = new PluginConfiguration();
        var config = new OidConfig();
        configuration.OidConfigs["kc"] = config;
        config.CanonicalLinks["live"] = Pending;
        config.CanonicalLinks["moved"] = Pending;
        config.CanonicalLinks["plain"] = Pending;
        config.CanonicalLinkPendingApprovals["live"] = new PendingApproval { UserId = Pending, SinceUtc = Now };
        config.CanonicalLinkPendingApprovals["moved"] = new PendingApproval { UserId = Other, SinceUtc = Now };

        var links = Assert.Single(LinkRoster.Build(configuration, _ => "alice").Accounts).Links;

        Assert.Equal(Now, Assert.Single(links, l => l.CanonicalName == "live").PendingApprovalSinceUtc);
        Assert.Null(Assert.Single(links, l => l.CanonicalName == "moved").PendingApprovalSinceUtc);
        Assert.Null(Assert.Single(links, l => l.CanonicalName == "plain").PendingApprovalSinceUtc);
        Assert.NotNull(PendingApproval.Live(config, "live"));
        Assert.Null(PendingApproval.Live(config, "moved"));
        Assert.Null(PendingApproval.Live(config, "plain"));
    }

    // One provider holding one linked account, recorded as provisioned inert by this plugin.
    private static User Recorded(IUserManager users, OidConfig config, bool disabled, bool admin)
    {
        var user = TestUsers.Named("alice", Pending);
        user.SetPermission(PermissionKind.IsDisabled, disabled);
        user.SetPermission(PermissionKind.IsAdministrator, admin);
        users.GetUserById(Pending).Returns(user);
        config.CanonicalLinks["sub-1"] = Pending;
        config.CanonicalLinkPendingApprovals["sub-1"] = new PendingApproval { UserId = Pending, SinceUtc = Now };
        return user;
    }

    private static (CanonicalLinkService Service, OidConfig Config, IUserManager Users) Build()
    {
        var configuration = new PluginConfiguration();
        var config = new OidConfig { Enabled = true };
        configuration.OidConfigs["kc"] = config;
        var users = Substitute.For<IUserManager>();
        var store = new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger());
        return (new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger(), clock: () => Now), config, users);
    }

    private static AuthResponse Response() =>
        new AuthResponse { AppName = "app", AppVersion = "1", DeviceID = "d", DeviceName = "dev" };

    private static VerifiedIdentity Identity() =>
        TestIdentities.Oidc("kc", new OidcAuthorizeStateBuilder.OidcAuthorizeState(
            Username: "alice",
            Subject: "sub-1",
            Issuer: null,
            EmailVerified: null,
            Valid: true,
            Admin: false,
            EnableLiveTv: false,
            EnableLiveTvManagement: false,
            Folders: new List<string>(),
            AvatarUrl: null,
            ExpiresAtUtc: null));

    private static (LoginCompletionService Service, IUserManager Users, PluginConfiguration Configuration) BuildLogin(OidConfig config)
    {
        var configuration = new PluginConfiguration();
        configuration.OidConfigs["kc"] = config;
        var users = Substitute.For<IUserManager>();
        var sessions = Substitute.For<ISessionManager>();
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());
        var store = new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger());
        var canonicalLinks = new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger(), clock: () => Now);
        var avatar = new AvatarService(users, Substitute.For<IProviderManager>(), Substitute.For<IServerConfigurationManager>(), new CapturingLogger(), "test-agent");
        var minter = new SessionMinter(users, avatar, sessions, new CapturingLogger());
        var ssoOnly = new SsoOnlyLoginService(users, store, new CapturingLogger());
        return (new LoginCompletionService(canonicalLinks, minter, ssoOnly, store, sessions, new CapturingLogger()), users, configuration);
    }
}
