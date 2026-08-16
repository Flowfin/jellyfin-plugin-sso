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
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Login-time enforcement of a provider's account-expiry deadline (#1144): an identity whose expiry instant
/// has passed gets no session, its linked account is disabled and its live tokens are revoked. Both halves
/// matter and they fail differently. Refusing the mint alone leaves a token issued before the deadline
/// working until it expires on its own, which is "time-limited" in name only; revoking alone leaves the
/// account able to log straight back in.
/// <para>
/// THE GUARD IS THE POINT OF THIS FILE, and it is a mass-lockout defence (T-D1) rather than a courtesy.
/// An identity provider that starts emitting a past instant, or a claim mapped to the wrong attribute,
/// hits every account at once. An administrator is therefore exempt from the whole gate and not merely from
/// the disable: <see cref="ExpiredDeadline_OnAnAdministrator_LeavesItEnabled_AndLogsIn"/> requires the
/// administrator to LOG IN, because an admin who is left enabled but refused cannot reach the settings page
/// that would repair the configuration. Deleting the exemption in
/// <c>LoginCompletionService.EnforceAccountExpiryAsync</c> turns that row red.
/// </para>
/// <para>
/// The claim being CONFIGURED is what arms the gate, and a configured claim that produced no readable
/// instant is the case both careless answers get wrong. Treating it as unlimited hands a transient identity
/// provider change the same outcome as an account with no deadline; treating it as expired hands that same
/// transient change the same outcome as a real expiry, and disables accounts over it. This refuses the one
/// login and touches nothing, which is the only answer that stays reversible.
/// </para>
/// </summary>
public class AccountExpiryEnforcementTests
{
    private const string ExpiryClaim = "access_expires";

    // The fixed part of the audit line SsoAudit.AccountExpired emits, matched rather than reproduced so a
    // reworded message fails one place instead of eight.
    private const string ExpiryAuditMarker = "disabled by account expiry";
    private static readonly Guid Linked = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly DateTime Past = new(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime Future = new(2999, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    [Fact]
    public async Task ExpiredDeadline_DisablesTheAccount_RevokesItsTokens_AndMintsNoSession()
    {
        var (service, config, users, sessions, audit) = Build();
        var user = LinkedUser(users, config, admin: false);

        var result = await service.CompleteAsync(
            OidcIdentity(Past), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        Assert.Equal(StatusCodes.Status403Forbidden, Assert.IsType<ContentResult>(result).StatusCode);
        Assert.True(user.HasPermission(PermissionKind.IsDisabled));
        await sessions.Received(1).RevokeUserTokens(Linked, null);
        await sessions.DidNotReceive().AuthenticateDirect(Arg.Any<AuthenticationRequest>());
        Assert.Single(audit.Entries, e => e.Message.Contains(ExpiryAuditMarker, StringComparison.Ordinal));
    }

    [Fact]
    public async Task TheAuditLine_NamesTheProvider_AndNeitherTheSubjectNorTheDeadline()
    {
        // T-I1: the trail an operator reads must carry the protocol and provider and nothing an identity
        // provider chose. The deadline is excluded with them, because an instant is as identifying as the
        // subject once it is rare.
        var (service, config, users, _, audit) = Build();
        LinkedUser(users, config, admin: false);

        await service.CompleteAsync(OidcIdentity(Past), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        var line = Assert.Single(audit.Entries, e => e.Message.Contains(ExpiryAuditMarker, StringComparison.Ordinal)).Message;
        Assert.Contains("kc", line, StringComparison.Ordinal);
        Assert.DoesNotContain("sub-1", line, StringComparison.Ordinal);
        Assert.DoesNotContain("2000", line, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExpiredDeadline_OnAnAdministrator_LeavesItEnabled_AndLogsIn()
    {
        // THE GUARD. Not "is not disabled" but "logs in": the recovery route this defence exists to keep
        // open runs through the admin's own session, so an administrator refused at the door is stranded
        // just as surely as one whose account was disabled.
        var (service, config, users, sessions, audit) = Build();
        var admin = LinkedUser(users, config, admin: true);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        var result = await service.CompleteAsync(
            OidcIdentity(Past), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        Assert.IsType<OkObjectResult>(result);
        Assert.False(admin.HasPermission(PermissionKind.IsDisabled));
        await sessions.Received(1).AuthenticateDirect(Arg.Any<AuthenticationRequest>());
        await sessions.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string?>());
        Assert.DoesNotContain(audit.Entries, e => e.Message.Contains(ExpiryAuditMarker, StringComparison.Ordinal));
    }

    [Fact]
    public async Task ASecondExpiredLogin_RefusesWithoutReAuditingOrRevokingAgain()
    {
        // A refused identity keeps trying. The disable, the audit line and the revocation are transition
        // events, so a login loop must not flood the trail or re-revoke on every attempt - and it must not
        // fall through to the pending-approval message either, which would tell an expired user to wait for
        // an approval nobody is going to give.
        var (service, config, users, sessions, audit) = Build();
        var user = LinkedUser(users, config, admin: false);

        await service.CompleteAsync(OidcIdentity(Past), Response(), config, AdoptionGate.None, () => "203.0.113.9");
        var second = await service.CompleteAsync(OidcIdentity(Past), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        Assert.Equal(StatusCodes.Status403Forbidden, Assert.IsType<ContentResult>(second).StatusCode);
        Assert.Contains("expired", Assert.IsType<ContentResult>(second).Content!, StringComparison.OrdinalIgnoreCase);
        Assert.True(user.HasPermission(PermissionKind.IsDisabled));
        await sessions.Received(1).RevokeUserTokens(Linked, null);
        Assert.Single(audit.Entries, e => e.Message.Contains(ExpiryAuditMarker, StringComparison.Ordinal));
    }

    [Fact]
    public async Task ADeadlineInTheFuture_LogsInAndChangesNothing()
    {
        var (service, config, users, sessions, audit) = Build();
        var user = LinkedUser(users, config, admin: false);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        var result = await service.CompleteAsync(
            OidcIdentity(Future), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        Assert.IsType<OkObjectResult>(result);
        Assert.False(user.HasPermission(PermissionKind.IsDisabled));
        await sessions.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string?>());
        Assert.DoesNotContain(audit.Entries, e => e.Message.Contains(ExpiryAuditMarker, StringComparison.Ordinal));
    }

    [Fact]
    public async Task AConfiguredClaimThatProducedNoInstant_RefusesTheLogin_AndDisablesNothing()
    {
        // Fail closed on the session, reversible on the account. A missing or unreadable value cannot be
        // told apart from an identity provider that changed its claim shape this morning, so it must not
        // grant access and must not spend a disable on the guess.
        var (service, config, users, sessions, audit) = Build();
        var user = LinkedUser(users, config, admin: false);

        var result = await service.CompleteAsync(
            OidcIdentity(null), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        Assert.Equal(StatusCodes.Status403Forbidden, Assert.IsType<ContentResult>(result).StatusCode);
        Assert.False(user.HasPermission(PermissionKind.IsDisabled));
        await sessions.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string?>());
        await sessions.DidNotReceive().AuthenticateDirect(Arg.Any<AuthenticationRequest>());
        Assert.DoesNotContain(audit.Entries, e => e.Message.Contains(ExpiryAuditMarker, StringComparison.Ordinal));
    }

    [Fact]
    public async Task WithNoExpiryClaimConfigured_AnInstantInThePastIsIgnored()
    {
        // The opt-in floor, and the row that keeps the feature from reaching a deployment that did not ask
        // for it. The identity carries a past instant; the provider configures no claim, so the whole gate
        // is off and the login takes its pre-#1144 path.
        var (service, config, users, sessions, _) = Build(expiryClaim: null);
        var user = LinkedUser(users, config, admin: false);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        var result = await service.CompleteAsync(
            OidcIdentity(Past), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        Assert.IsType<OkObjectResult>(result);
        Assert.False(user.HasPermission(PermissionKind.IsDisabled));
        await sessions.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string?>());
    }

    [Fact]
    public async Task AFirstLoginThatIsAlreadyExpired_ProvisionsTheAccountInert_AndMintsNothing()
    {
        // Recorded because it is the arm a reader would guess wrong. The gate runs after resolve-or-create,
        // so an identity arriving already past its deadline DOES get a Jellyfin account, and that account is
        // disabled in the same request and never issued a session. Refusing before the resolve instead would
        // give the gate no account to disable and no administrator exemption to read, so this is the price of
        // both; what matters is that it fails closed, which the mint assertion below is what pins.
        var (service, config, users, sessions, audit) = Build();
        var created = TestUsers.Named("alice", Linked);
        users.GetUserByName("alice").Returns((User?)null);
        users.CreateUserAsync("alice").Returns(created);
        users.GetUserById(Linked).Returns(created);

        var result = await service.CompleteAsync(
            OidcIdentity(Past), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        Assert.Equal(StatusCodes.Status403Forbidden, Assert.IsType<ContentResult>(result).StatusCode);
        Assert.True(created.HasPermission(PermissionKind.IsDisabled));
        await sessions.DidNotReceive().AuthenticateDirect(Arg.Any<AuthenticationRequest>());
        Assert.Single(audit.Entries, e => e.Message.Contains(ExpiryAuditMarker, StringComparison.Ordinal));
    }

    [Fact]
    public async Task TheSamlPathIsEnforcedIdentically()
    {
        // Both protocols funnel through the one completion tail, so the deadline is enforced once rather
        // than per protocol. This row is what would go red if the enforcement were ever moved up into the
        // OpenID flow service, where SAML would silently stop being covered.
        var config = new SamlConfig { Enabled = true, AccountExpiryClaim = ExpiryClaim };
        var audit = new CapturingLogger();
        var (service, users, sessions) = BuildFor(c => c.SamlConfigs["idp"] = config, audit);
        var user = TestUsers.Named("bob", Linked);
        users.GetUserById(Linked).Returns(user);
        config.CanonicalLinks["bob"] = Linked;

        var identity = TestIdentities.Saml(
            "idp",
            "bob",
            new SamlAuthorizeStateBuilder.SamlAuthorizeState(
                Admin: false, EnableLiveTv: false, EnableLiveTvManagement: false, Folders: new List<string>()),
            Past);

        var result = await service.CompleteAsync(identity, Response(), config, AdoptionGate.None, () => "203.0.113.9");

        Assert.Equal(StatusCodes.Status403Forbidden, Assert.IsType<ContentResult>(result).StatusCode);
        Assert.True(user.HasPermission(PermissionKind.IsDisabled));
        await sessions.Received(1).RevokeUserTokens(Linked, null);
        Assert.Single(audit.Entries, e => e.Message.Contains(ExpiryAuditMarker, StringComparison.Ordinal));
    }

    // --- helpers ---

    private static AuthResponse Response() =>
        new AuthResponse { AppName = "app", AppVersion = "1", DeviceID = "d", DeviceName = "dev" };

    private static VerifiedIdentity OidcIdentity(DateTime? expiresAtUtc) =>
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
            ExpiresAtUtc: expiresAtUtc));

    private static (LoginCompletionService Service, OidConfig Config, IUserManager Users, ISessionManager Sessions, CapturingLogger Audit) Build(string? expiryClaim = ExpiryClaim)
    {
        var config = new OidConfig { Enabled = true, AccountExpiryClaim = expiryClaim };
        var audit = new CapturingLogger();
        var (service, users, sessions) = BuildFor(c => c.OidConfigs["kc"] = config, audit);
        return (service, config, users, sessions, audit);
    }

    private static (LoginCompletionService Service, IUserManager Users, ISessionManager Sessions) BuildFor(Action<PluginConfiguration> seed, CapturingLogger audit)
    {
        var configuration = new PluginConfiguration();
        seed(configuration);
        var users = Substitute.For<IUserManager>();
        var sessions = Substitute.For<ISessionManager>();
        var store = new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger());
        var canonicalLinks = new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger());
        var avatar = new AvatarService(users, Substitute.For<IProviderManager>(), Substitute.For<IServerConfigurationManager>(), new CapturingLogger(), "test-agent");
        var minter = new SessionMinter(users, avatar, sessions, new CapturingLogger());
        var ssoOnly = new SsoOnlyLoginService(users, store, new CapturingLogger());
        return (new LoginCompletionService(canonicalLinks, minter, ssoOnly, store, sessions, audit), users, sessions);
    }

    // An account that already exists and is already linked, so every row below acts on a resolved link
    // rather than on a first login: this path must never create or adopt an account, only act on one the
    // identity has already proved it owns.
    private static User LinkedUser(IUserManager users, ProviderConfigBase config, bool admin)
    {
        var user = TestUsers.Named("alice", Linked);
        user.SetPermission(PermissionKind.IsAdministrator, admin);
        users.GetUserById(Linked).Returns(user);
        config.CanonicalLinks["sub-1"] = Linked;
        return user;
    }
}
