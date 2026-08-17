// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Identity;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
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
/// The provisioning half of guest/trial access (#1146): a role-mapped duration becomes a deadline on the
/// canonical link, stamped ONCE, at the moment the account is created, and never again.
/// <para>
/// The stamped-once rule carries the whole feature. A deadline re-anchored on every login would move forward
/// faster than it is reached for anyone who keeps using their account, so a "24-hour trial" would in practice
/// be unlimited access for exactly the users a time limit exists to bound - and nothing would look wrong:
/// the account stays enabled, the map stays populated, and the sweep simply never finds a due entry.
/// <see cref="ASecondLoginDaysLater_LeavesTheRecordedDeadlineExactlyWhereItWas"/> is the row that refuses it.
/// </para>
/// <para>
/// Enforcement is deliberately absent from this file. The deadline this writes is read by the between-logins
/// sweep (#1145) and by the login-time gate (#1144), both already covered by their own suites; what is new
/// here is only where the instant comes from.
/// </para>
/// </summary>
public class GuestAccessDurationProvisioningTests
{
    private const string Subject = "sub-guest";
    private static readonly Guid Provisioned = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly Guid Existing = Guid.Parse("33333333-3333-3333-3333-333333333333");

    // A fixed anchor, so the assertion is an equality against a computed instant rather than a tolerance
    // around the wall clock. A test that asserted "roughly now plus a day" would pass a stamp anchored to
    // the wrong moment by seconds, which is the sort of drift a clock injection exists to make visible.
    private static readonly DateTime Anchor = new(2026, 3, 1, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public async Task AFirstLoginHoldingAMappedRole_ProvisionsWithADeadlineOfNowPlusTheDuration()
    {
        var config = GuestProvider(Map(24, "guest"));
        var harness = Provisioning(config);

        await harness.Login(Identity(config, duration: TimeSpan.FromHours(24)));

        Assert.Equal(Anchor.AddHours(24), config.CanonicalLinkDeadlines[Subject]);
    }

    [Fact]
    public async Task ASecondLoginDaysLater_LeavesTheRecordedDeadlineExactlyWhereItWas()
    {
        // The sliding-window defect, pinned. The second login resolves the link the first one wrote, so it
        // never reaches the stamp - if it did, the deadline would be five days later than the trial allows
        // and would keep moving for as long as the user kept coming back.
        var config = GuestProvider(Map(24, "guest"));
        var harness = Provisioning(config);
        await harness.Login(Identity(config, duration: TimeSpan.FromHours(24)));
        var stamped = config.CanonicalLinkDeadlines[Subject];

        harness.Now = Anchor.AddDays(5);
        await harness.Login(Identity(config, duration: TimeSpan.FromHours(24)));

        Assert.Equal(stamped, config.CanonicalLinkDeadlines[Subject]);
        Assert.Equal(Anchor.AddHours(24), config.CanonicalLinkDeadlines[Subject]);
    }

    [Fact]
    public async Task ALoginHoldingTwoMappedRoles_TakesTheShorterDuration()
    {
        var config = GuestProvider(Map(720, "guest"), Map(24, "trial"));
        var harness = Provisioning(config);

        // The duration the protocol layer resolves for these roles, resolved through the real policy rather
        // than hand-picked, so this row would also go red if the reducer stopped preferring the shorter one.
        var resolved = Jellyfin.Plugin.SSO_Auth.Api.Authz.GuestAccessDurationPolicy.Resolve(new[] { "guest", "trial" }, config);
        await harness.Login(Identity(config, resolved));

        Assert.Equal(Anchor.AddHours(24), config.CanonicalLinkDeadlines[Subject]);
    }

    [Fact]
    public async Task ALoginCarryingBothAMappedRoleAndAnAbsoluteClaim_TakesTheClaimsInstant()
    {
        // The identity provider is the authority on a date it emitted, so the absolute source wins. Written
        // as a single test rather than two because what matters is that ONE of the two instants lands: a
        // change that let both write would leave the outcome depending on which ran last.
        var claimInstant = new DateTime(2027, 6, 1, 0, 0, 0, DateTimeKind.Utc);
        var config = GuestProvider(Map(24, "guest"));
        config.AccountExpiryClaim = "access_expires";
        var harness = Provisioning(config);

        await harness.Login(Identity(config, duration: TimeSpan.FromHours(24), expiresAtUtc: claimInstant));

        Assert.Equal(claimInstant, config.CanonicalLinkDeadlines[Subject]);
        Assert.NotEqual(Anchor.AddHours(24), config.CanonicalLinkDeadlines[Subject]);
    }

    [Fact]
    public async Task AnAlreadyExpiredClaimOnAProvisioningLogin_LeavesNoFutureDeadlineBehind()
    {
        // The row above passes for the wrong reason on its own, and this is the one that pins the rule.
        // Where the claim resolves a FUTURE instant, the enforcement gate overwrites whatever the group
        // stamped, so the outcome is right whether or not the sources are ordered - measured by deleting the
        // condition and watching that row stay green.
        //
        // A PAST instant separates them. The gate disables the account and records nothing, so a group
        // duration allowed through would be the only writer, and the just-expired account would be left
        // holding a deadline a day into the future: an account the plugin refused would look, to the sweep
        // and to anyone reading the config, like one with access until tomorrow.
        var config = GuestProvider(Map(24, "guest"));
        config.AccountExpiryClaim = "access_expires";
        var harness = Provisioning(config);

        await harness.Login(Identity(config, duration: TimeSpan.FromHours(24), expiresAtUtc: Anchor.AddDays(-1)));

        Assert.Empty(config.CanonicalLinkDeadlines);
    }

    [Fact]
    public async Task AProviderWithNoDurationMappings_ProvisionsWithNoDeadlineAtAll()
    {
        // The no-change row. Every existing deployment is this one, and a deadline appearing here would be a
        // time limit nobody configured, on an account that should keep working forever.
        var config = new OidConfig { Enabled = true, OidEndpoint = "https://idp/.well-known" };
        var harness = Provisioning(config);

        await harness.Login(Identity(config, duration: null));

        Assert.Equal(Provisioned, config.CanonicalLinks[Subject]);
        Assert.Empty(config.CanonicalLinkDeadlines);
    }

    [Fact]
    public async Task ALoginHoldingNoMappedRole_ProvisionsWithNoDeadline()
    {
        var config = GuestProvider(Map(24, "guest"));
        var harness = Provisioning(config);

        await harness.Login(Identity(config, Jellyfin.Plugin.SSO_Auth.Api.Authz.GuestAccessDurationPolicy.Resolve(new[] { "staff" }, config)));

        Assert.Equal(Provisioned, config.CanonicalLinks[Subject]);
        Assert.Empty(config.CanonicalLinkDeadlines);
    }

    [Fact]
    public async Task AnADOPTEDAccountIsNotGivenALifetime()
    {
        // Adoption takes over an account that already existed with its own history; it is not a provisioning
        // event, and stamping there would put an expiry on somebody's established account because their IdP
        // happened to list them in a guest group. The duration is passed exactly as on the create arm, so
        // this row goes red the moment the stamp is moved up to cover both.
        var config = GuestProvider(Map(24, "guest"));
        config.AllowExistingAccountLink = true;
        var harness = Provisioning(config, adoptable: TestUsers.Named("alice", Existing));

        await harness.Login(Identity(config, duration: TimeSpan.FromHours(24)));

        Assert.Equal(Existing, config.CanonicalLinks[Subject]);
        Assert.Empty(config.CanonicalLinkDeadlines);
    }

    [Fact]
    public async Task TheSamlPathStampsIdentically()
    {
        // Both protocols funnel through the one completion tail and the one create arm, so the stamp is
        // written once rather than per protocol. This row is what would go red if it were ever moved up into
        // the OpenID flow service, where SAML would silently stop being covered.
        var config = new SamlConfig
        {
            Enabled = true,
            SamlEndpoint = "https://idp/saml",
            GuestAccessDurationRoleMappings = new List<GuestAccessDurationRoleMap> { Map(24, "guest") },
        };
        var harness = Provisioning(configuration => configuration.SamlConfigs["idp"] = config, adoptable: null);

        var identity = TestIdentities.Saml(
            "idp",
            Subject,
            new SamlAuthorizeStateBuilder.SamlAuthorizeState(
                Admin: false,
                EnableLiveTv: false,
                EnableLiveTvManagement: false,
                Folders: new List<string>(),
                GuestAccessDuration: TimeSpan.FromHours(24)));
        await harness.Login(identity, config);

        Assert.Equal(Anchor.AddHours(24), config.CanonicalLinkDeadlines[Subject]);
    }

    private static GuestAccessDurationRoleMap Map(int hours, params string[] roles)
        => new GuestAccessDurationRoleMap { DurationHours = hours, Roles = roles };

    private static OidConfig GuestProvider(params GuestAccessDurationRoleMap[] maps) => new OidConfig
    {
        Enabled = true,
        OidEndpoint = "https://idp/.well-known",
        GuestAccessDurationRoleMappings = new List<GuestAccessDurationRoleMap>(maps),
    };

    private static VerifiedIdentity Identity(ProviderConfigBase config, TimeSpan? duration, DateTime? expiresAtUtc = null)
        => TestIdentities.Oidc("kc", new OidcAuthorizeStateBuilder.OidcAuthorizeState(
            Username: "alice",
            Subject: Subject,
            Issuer: null,
            EmailVerified: null,
            Valid: true,
            Admin: false,
            EnableLiveTv: false,
            EnableLiveTvManagement: false,
            Folders: new List<string>(),
            AvatarUrl: null,
            ExpiresAtUtc: expiresAtUtc,
            GuestAccessDuration: duration));

    private static Harness Provisioning(OidConfig config, User? adoptable = null)
        => Provisioning(configuration => configuration.OidConfigs["kc"] = config, adoptable, config);

    private static Harness Provisioning(Action<PluginConfiguration> register, User? adoptable)
        => Provisioning(register, adoptable, null);

    // One completion path over a real ProviderConfigStore and a real CanonicalLinkService, with only the
    // Jellyfin host substituted. The clock is injected because the assertion is an exact instant: with the
    // wall clock the anchor could only be checked to a tolerance, and a stamp taken at the wrong moment - at
    // the callback rather than at the link write - would sit inside any tolerance loose enough to be stable.
    private static Harness Provisioning(Action<PluginConfiguration> register, User? adoptable, ProviderConfigBase? defaultConfig)
    {
        var configuration = new PluginConfiguration();
        register(configuration);

        var users = Substitute.For<IUserManager>();
        var sessions = Substitute.For<ISessionManager>();
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        var harness = new Harness { Now = Anchor };

        users.GetUserByName("alice").Returns(adoptable);
        users.GetUserByName(Subject).Returns(adoptable);
        var created = TestUsers.Named("alice", Provisioned);
        users.CreateUserAsync(Arg.Any<string>()).Returns(created);
        users.GetUserById(Provisioned).Returns(created);
        if (adoptable is not null)
        {
            users.GetUserById(Existing).Returns(adoptable);
        }

        var store = new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger());
        var canonicalLinks = new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger(), clock: () => harness.Now);
        var avatar = new AvatarService(users, Substitute.For<IProviderManager>(), Substitute.For<IServerConfigurationManager>(), new CapturingLogger(), "test-agent");
        var minter = new SessionMinter(users, avatar, sessions, new CapturingLogger());
        var ssoOnly = new SsoOnlyLoginService(users, store, new CapturingLogger());

        harness.Service = new LoginCompletionService(canonicalLinks, minter, ssoOnly, store, sessions, new CapturingLogger());
        harness.DefaultConfig = defaultConfig;
        return harness;
    }

    private sealed class Harness
    {
        internal LoginCompletionService Service { get; set; } = null!;

        internal ProviderConfigBase? DefaultConfig { get; set; }

        internal DateTime Now { get; set; }

        internal Task Login(VerifiedIdentity identity, ProviderConfigBase? config = null)
            => Service.CompleteAsync(
                identity,
                new AuthResponse { AppName = "app", AppVersion = "1", DeviceID = "d", DeviceName = "dev" },
                config ?? DefaultConfig!,
                AdoptionGate.None,
                () => "203.0.113.9");
    }
}
