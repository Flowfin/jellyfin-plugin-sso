// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Serialization;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
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
/// Role-selected provisioning profiles (#1106): which named profile (#1105) a brand-new account is created
/// from is decided from the roles the identity provider already sent for that login, by an ordered map on
/// the provider.
/// <para>
/// The resolution order is the thing under test and it is stated once, here: the FIRST row whose roles the
/// login holds wins, else the provider's own default profile, else the provider's inline template, else no
/// policy at all. Order matters because two profiles are two permission sets rather than two points on a
/// scale - there is no "most restrictive" to reduce to the way #1146 reduces durations to the shortest - so
/// the administrator states the precedence by ordering the rows, and
/// <see cref="ALoginMatchingTwoRows_TakesTheEarlierRow"/> is what would go red if that stopped being true.
/// </para>
/// <para>
/// The security-relevant half is that a row whose profile no longer resolves writes NO policy and never
/// falls back. That is stricter than it looks: a row exists to send one group somewhere NARROWER than the
/// provider default, so a fallback would hand exactly those accounts the wider policy the administrator had
/// moved them off - silently, at account creation, with nothing but a log line to say so. The save path
/// refuses a dangling row, and
/// <see cref="ARowNamingAMissingProfile_WritesNoPolicy_AndNeverFallsBackToTheProviderDefault"/> covers the
/// configuration file edited by hand around it.
/// </para>
/// <para>
/// The compatibility half is <see cref="AProviderWithNoRows_ProvisionsExactlyAsItDidBefore"/> and
/// <see cref="AConfigWrittenBeforeRoleRowsExisted_LoadsAndProvisionsUnchanged"/>: an empty map is the whole
/// of "off", so every installation that configured none provisions byte-identically to before this existed.
/// </para>
/// </summary>
public class ProvisioningProfileRoleSelectionTests
{
    private static readonly Guid Created = Guid.Parse("66666666-6666-6666-6666-666666666666");

    // The resolver: the pure question, asked without a login path around it (#1106 Surfaces).

    [Fact]
    public void ALoginHoldingAMappedRole_SelectsThatRowsProfile()
    {
        var config = new OidConfig
        {
            ProvisioningProfileRoleMappings = new List<ProvisioningProfileRoleMap>
            {
                new ProvisioningProfileRoleMap { Profile = "guest", Roles = new[] { "guest" } },
            },
        };

        Assert.Equal("guest", ProvisioningProfilePolicy.Resolve(new[] { "guest" }, config));
    }

    [Fact]
    public void ALoginHoldingNoMappedRole_SelectsNothing()
    {
        // Null rather than a name, so the caller falls through to the provider's own default resolution
        // (#1105) instead of this map deciding for a login it was never written for.
        var config = new OidConfig
        {
            ProvisioningProfileRoleMappings = new List<ProvisioningProfileRoleMap>
            {
                new ProvisioningProfileRoleMap { Profile = "guest", Roles = new[] { "guest" } },
            },
        };

        Assert.Null(ProvisioningProfilePolicy.Resolve(new[] { "staff", "media" }, config));
    }

    [Fact]
    public void ALoginMatchingTwoRows_TakesTheEarlierRow()
    {
        // The clause that pins the documented order. A login in both groups must land on the row the
        // administrator listed first; anything that iterated to the end, or reduced over the matches, would
        // return "staff" here and this is the only test that would notice.
        var config = new OidConfig
        {
            ProvisioningProfileRoleMappings = new List<ProvisioningProfileRoleMap>
            {
                new ProvisioningProfileRoleMap { Profile = "guest", Roles = new[] { "guest" } },
                new ProvisioningProfileRoleMap { Profile = "staff", Roles = new[] { "staff" } },
            },
        };

        Assert.Equal("guest", ProvisioningProfilePolicy.Resolve(new[] { "staff", "guest" }, config));
    }

    [Fact]
    public void ReorderingTheRows_ReversesWhichOneWins()
    {
        // The other direction of the same property: the order is the administrator's statement of precedence
        // and nothing else decides it. Without this, a resolver that always returned the alphabetically first
        // profile would pass the test above.
        var config = new OidConfig
        {
            ProvisioningProfileRoleMappings = new List<ProvisioningProfileRoleMap>
            {
                new ProvisioningProfileRoleMap { Profile = "staff", Roles = new[] { "staff" } },
                new ProvisioningProfileRoleMap { Profile = "guest", Roles = new[] { "guest" } },
            },
        };

        Assert.Equal("staff", ProvisioningProfilePolicy.Resolve(new[] { "staff", "guest" }, config));
    }

    [Fact]
    public void ANullOrProfilelessRow_IsSkippedRatherThanThrownOn_AndTheWalkContinues()
    {
        // Both states are refused at save, so they only arrive in a hand-edited configuration. There a single
        // dead row must not 500 a login: it selects nothing and the next row still gets its turn.
        var config = new OidConfig
        {
            ProvisioningProfileRoleMappings = new List<ProvisioningProfileRoleMap>
            {
                null!,
                new ProvisioningProfileRoleMap { Profile = "   ", Roles = new[] { "guest" } },
                new ProvisioningProfileRoleMap { Profile = "guest", Roles = new[] { "guest" } },
            },
        };

        Assert.Equal("guest", ProvisioningProfilePolicy.Resolve(new[] { "guest" }, config));
    }

    [Fact]
    public void ABlankConfiguredRole_NeverMatches()
    {
        // The #935 blank-skip every other role policy applies. A blank entry hand-written into the config XML
        // must not satisfy a row, or a provider would select a profile for every login that sent any role.
        var config = new OidConfig
        {
            ProvisioningProfileRoleMappings = new List<ProvisioningProfileRoleMap>
            {
                new ProvisioningProfileRoleMap { Profile = "guest", Roles = new[] { "  " } },
            },
        };

        Assert.Null(ProvisioningProfilePolicy.Resolve(new[] { "guest", string.Empty }, config));
    }

    [Fact]
    public void NoRowsConfigured_SelectsNothing()
    {
        Assert.Null(ProvisioningProfilePolicy.Resolve(new[] { "guest" }, new OidConfig()));
    }

    // The create arm: the same question asked through the service that actually makes the account.

    [Fact]
    public async Task ARoleSelectedProfile_ProvisionsFromThatProfile()
    {
        // Done-when 1, first half: a login carrying role "guest" provisions from the "guest" profile even
        // though the provider's own default sends everybody else to "default".
        var configuration = new PluginConfiguration();
        configuration.ProvisioningProfiles["default"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 9 };
        configuration.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 1 };
        configuration.OidConfigs["kc"] = new OidConfig { Enabled = true, ProvisioningProfile = "default" };
        var (service, users) = BuildFor(configuration);
        var created = Provisionable(users, "alice", Created);

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false, provisioningProfile: "guest");

        Assert.Equal(1, created.MaxActiveSessions);
    }

    [Fact]
    public async Task ALoginSelectingNoProfile_ProvisionsFromTheProviderDefault()
    {
        // Done-when 1, second half. The unmatched login is the common case - most logins hold none of the
        // mapped roles - so this is the arm that must stay exactly what #1105 left.
        var configuration = new PluginConfiguration();
        configuration.ProvisioningProfiles["default"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 9 };
        configuration.OidConfigs["kc"] = new OidConfig { Enabled = true, ProvisioningProfile = "default" };
        var (service, users) = BuildFor(configuration);
        var created = Provisionable(users, "alice", Created);

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false, provisioningProfile: null);

        Assert.Equal(9, created.MaxActiveSessions);
    }

    [Fact]
    public async Task ARowNamingAMissingProfile_WritesNoPolicy_AndNeverFallsBackToTheProviderDefault()
    {
        // The fail-closed clause, and the one this issue's third Done-when originally asked for the opposite
        // of. The provider default here is deliberately WIDE (9 sessions) and the selected profile is gone.
        // Falling back would hand the guest group the staff policy at the moment the account is created,
        // which is the failure #1105 already refuses one level up, reached through a role instead.
        var configuration = new PluginConfiguration();
        configuration.ProvisioningProfiles["default"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 9 };
        configuration.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            ProvisioningProfile = "default",
            ProvisioningPolicyTemplate = null,
        };
        var (service, users) = BuildFor(configuration);
        var created = Provisionable(users, "alice", Created);
        var before = created.MaxActiveSessions;

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false, provisioningProfile: "deleted-profile");

        Assert.Equal(before, created.MaxActiveSessions);
        Assert.NotEqual(9, created.MaxActiveSessions);
    }

    [Fact]
    public async Task ARoleSelectedProfile_NeverFallsBackToTheProvidersInlineTemplate()
    {
        // The same one-way rule against the other fallback target. A provider may legitimately carry rows AND
        // an inline template - that is "guest goes narrow, everyone else gets the house default" - so the
        // inline block is reachable, but only by a login that matched NO row.
        var configuration = new PluginConfiguration();
        configuration.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate { MaxActiveSessions = 7 },
        };
        var (service, users) = BuildFor(configuration);
        var created = Provisionable(users, "alice", Created);
        var before = created.MaxActiveSessions;

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false, provisioningProfile: "deleted-profile");

        Assert.Equal(before, created.MaxActiveSessions);
        Assert.NotEqual(7, created.MaxActiveSessions);
    }

    [Fact]
    public async Task AProviderWithNoRows_ProvisionsExactlyAsItDidBefore()
    {
        // Done-when 4. An empty map is the whole of "off", so the inline template still decides and nothing
        // about the account changes.
        var configuration = new PluginConfiguration();
        configuration.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate { MaxActiveSessions = 4 },
        };
        var (service, users) = BuildFor(configuration);
        var created = Provisionable(users, "alice", Created);

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(4, created.MaxActiveSessions);
    }

    // The whole path. Everything above tests one joint; these two test that the joints are connected.
    //
    // They exist because of a measured gap rather than for symmetry: with the resolver, the create arm and
    // both validator doors all covered, severing the one line in LoginCompletionService that hands the
    // selected name down left the ENTIRE suite green. A feature that resolves a profile correctly and then
    // drops it on the floor is indistinguishable, to every other test here, from one that works.

    [Fact]
    public async Task AnOidcLoginCarryingTheSelection_ProvisionsFromIt_AllTheWayThroughTheCompletionPath()
    {
        // Builder state -> ValidatedLogin -> VerifiedIdentity -> LoginCompletionService -> the create arm.
        // The provider default is deliberately the WIDER policy, so a path that lost the selection anywhere
        // between the two ends comes out at 9 rather than 1 and this goes red.
        var config = new OidConfig { Enabled = true, ProvisioningProfile = "default" };
        var (service, _, users, sessions) = BuildCompletion(c =>
        {
            c.ProvisioningProfiles["default"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 9 };
            c.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 1 };
            c.OidConfigs["kc"] = config;
        });
        var created = Provisionable(users, "alice", Created);
        users.GetUserByName("alice").Returns((User?)null);
        users.GetUserById(Created).Returns(created);
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        await service.CompleteAsync(
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
                ProvisioningProfile: "guest")),
            new AuthResponse { AppName = "app", AppVersion = "1", DeviceID = "d", DeviceName = "dev" },
            config,
            AdoptionGate.None,
            () => "203.0.113.9");

        Assert.Equal(1, created.MaxActiveSessions);
    }

    [Fact]
    public void TheOidcBuilder_ResolvesTheSelectionFromTheLoginsRoles()
    {
        // The other end of the same wire: the builder has to put the resolved name ON the state, or the
        // completion path above would faithfully carry a null. Asked through the real builder with a real
        // role claim rather than by constructing the state by hand.
        var config = new OidConfig
        {
            Roles = new[] { "media" },
            RoleClaim = "roles",
            ProvisioningProfileRoleMappings = new List<ProvisioningProfileRoleMap>
            {
                new ProvisioningProfileRoleMap { Profile = "guest", Roles = new[] { "guest" } },
            },
        };

        var state = OidcAuthorizeStateBuilder.Build(
            new[] { new Claim("roles", "guest"), new Claim("sub", "sub-1") },
            config);

        Assert.Equal("guest", state.ProvisioningProfile);
    }

    [Fact]
    public void TheSamlBuilder_ResolvesTheSelectionFromTheLoginsRoles()
    {
        // The SAML builder is a separate function, so a resolution wired into only the OpenID one would pass
        // every other test in this file.
        var config = new SamlConfig
        {
            ProvisioningProfileRoleMappings = new List<ProvisioningProfileRoleMap>
            {
                new ProvisioningProfileRoleMap { Profile = "guest", Roles = new[] { "guest" } },
            },
        };

        var state = SamlAuthorizeStateBuilder.Build(new[] { "guest" }, config);

        Assert.Equal("guest", state.ProvisioningProfile);
    }

    // The save path: the states the resolver above is only tolerant of because this refuses them.

    [Fact]
    public void ARowNamingAProfileTheConfigurationDoesNotDefine_IsRefusedOnSave()
    {
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["kc"] = new OidConfig
        {
            ProvisioningProfileRoleMappings = new List<ProvisioningProfileRoleMap>
            {
                new ProvisioningProfileRoleMap { Profile = "guest", Roles = new[] { "guest" } },
            },
        };

        var error = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.Validate(incoming, new PluginConfiguration()));
        Assert.Contains("does not define", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ARowNamingNoProfile_IsRefusedOnSave()
    {
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["kc"] = new OidConfig
        {
            ProvisioningProfileRoleMappings = new List<ProvisioningProfileRoleMap>
            {
                new ProvisioningProfileRoleMap { Profile = "  ", Roles = new[] { "guest" } },
            },
        };

        var error = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.Validate(incoming, new PluginConfiguration()));
        Assert.Contains("naming no profile", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ARowListingNoRoles_IsRefusedOnSave()
    {
        // A row that can never match is dead configuration that reads like a rule, which is exactly what the
        // parental-rating map refuses for the same reason. A row whose every entry is blank is the same state
        // written differently, because the runtime matcher skips blank entries.
        var incoming = new PluginConfiguration();
        incoming.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 1 };
        incoming.OidConfigs["kc"] = new OidConfig
        {
            ProvisioningProfileRoleMappings = new List<ProvisioningProfileRoleMap>
            {
                new ProvisioningProfileRoleMap { Profile = "guest", Roles = new[] { "   " } },
            },
        };

        var error = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.Validate(incoming, new PluginConfiguration()));
        Assert.Contains("lists no roles", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ASamlProvidersRows_AreJudgedByTheSameRule()
    {
        // The SAML map is a separate loop in Validate, so a check wired into only the OpenID arm would pass
        // every test above and leave SAML unguarded.
        var incoming = new PluginConfiguration();
        incoming.SamlConfigs["idp"] = new SamlConfig
        {
            ProvisioningProfileRoleMappings = new List<ProvisioningProfileRoleMap>
            {
                new ProvisioningProfileRoleMap { Profile = "guest", Roles = new[] { "guest" } },
            },
        };

        var error = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.Validate(incoming, new PluginConfiguration()));
        Assert.Contains("SAML provider", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AValidRowSet_SavesWithoutComplaint()
    {
        // The negative of every refusal above: the shape an administrator actually writes must pass, or the
        // guards would be refusing the feature rather than its misconfigurations.
        var incoming = new PluginConfiguration();
        incoming.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 1 };
        incoming.OidConfigs["kc"] = new OidConfig
        {
            ProvisioningProfileRoleMappings = new List<ProvisioningProfileRoleMap>
            {
                new ProvisioningProfileRoleMap { Profile = "guest", Roles = new[] { "guest" } },
            },
        };

        ProviderConfigValidator.Validate(incoming, new PluginConfiguration());
    }

    // Persistence.

    [Fact]
    public void TheRows_SurviveAConfigurationRoundTrip()
    {
        var configuration = new PluginConfiguration();
        configuration.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 1 };
        configuration.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            ProvisioningProfileRoleMappings = new List<ProvisioningProfileRoleMap>
            {
                new ProvisioningProfileRoleMap { Profile = "guest", Roles = new[] { "guest", "trial" } },
                new ProvisioningProfileRoleMap { Profile = "staff", Roles = new[] { "staff" } },
            },
        };

        var reloaded = Deserialize<PluginConfiguration>(Serialize(configuration));

        var rows = reloaded.OidConfigs["kc"].ProvisioningProfileRoleMappings!;
        Assert.Equal(2, rows.Count);

        // The ORDER survives, not merely the members: the order is the precedence, so a serializer that
        // reordered them would silently change which profile a login in both groups gets.
        Assert.Equal("guest", rows[0].Profile);
        Assert.Equal("staff", rows[1].Profile);
        Assert.Equal(new[] { "guest", "trial" }, rows[0].Roles);
    }

    [Fact]
    public async Task AConfigWrittenBeforeRoleRowsExisted_LoadsAndProvisionsUnchanged()
    {
        // The upgrade case, taken from the real serializer rather than a hand-typed literal: a stored config
        // XML with no ProvisioningProfileRoleMappings element must come back configuring no rows and
        // provision exactly as it did, from the provider's own inline template.
        //
        // What comes back is an EMPTY LIST rather than null, which is worth pinning rather than asserting
        // away: XmlSerializer materialises the collection member even though the element is absent, so "off"
        // has two spellings in practice and the resolver has to answer the same to both. The assertion below
        // is therefore on what the resolver DOES with the reloaded provider, not on which of the two
        // spellings the serializer happened to produce - an assertion on null alone would have gone red here
        // for a difference no login can observe.
        var written = new PluginConfiguration();
        written.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate { MaxActiveSessions = 4 },
        };
        var legacyXml = Serialize(written);
        Assert.DoesNotContain("ProvisioningProfileRoleMappings", legacyXml, StringComparison.Ordinal);

        var reloaded = Deserialize<PluginConfiguration>(legacyXml);
        var (service, users) = BuildFor(reloaded);
        var created = Provisionable(users, "alice", Created);

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Empty(reloaded.OidConfigs["kc"].ProvisioningProfileRoleMappings!);
        Assert.Null(ProvisioningProfilePolicy.Resolve(new[] { "guest" }, reloaded.OidConfigs["kc"]));
        Assert.Equal(4, created.MaxActiveSessions);
    }

    private static string Serialize<T>(T value)
    {
        var serializer = new XmlSerializer(typeof(T));
        using var writer = new StringWriter();
        serializer.Serialize(writer, value);
        return writer.ToString();
    }

    private static T Deserialize<T>(string xml)
    {
        var serializer = new XmlSerializer(typeof(T));
        using var reader = XmlReader.Create(new StringReader(xml));
        return (T)serializer.Deserialize(reader)!;
    }

    private static (CanonicalLinkService Service, IUserManager Users) BuildFor(PluginConfiguration configuration)
    {
        var users = Substitute.For<IUserManager>();
        var store = new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger());
        return (new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger()), users);
    }

    // The full completion path, wired exactly as LoginCompletionServiceTests wires it. A real AvatarService
    // (deps stubbed) is safe here because a null AvatarUrl early-returns, so no network is reached.
    private static (LoginCompletionService Service, PluginConfiguration Config, IUserManager Users, ISessionManager Sessions) BuildCompletion(Action<PluginConfiguration> seed)
    {
        var cfg = new PluginConfiguration();
        seed(cfg);
        var users = Substitute.For<IUserManager>();
        var sessions = Substitute.For<ISessionManager>();
        var store = new ProviderConfigStore(() => cfg, _ => { }, new CapturingLogger());
        var canonicalLinks = new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger());
        var avatar = new AvatarService(users, Substitute.For<IProviderManager>(), Substitute.For<IServerConfigurationManager>(), new CapturingLogger(), "test-agent");
        var minter = new SessionMinter(users, avatar, sessions, new CapturingLogger());
        var ssoOnly = new SsoOnlyLoginService(users, store, new CapturingLogger());
        return (new LoginCompletionService(canonicalLinks, minter, ssoOnly, store, sessions, new CapturingLogger()), cfg, users, sessions);
    }

    private static User Provisionable(IUserManager users, string username, Guid id)
    {
        var user = new User(username, "SSO-Auth", "SSO-Auth") { Id = id };
        users.CreateUserAsync(username).Returns(Task.FromResult(user));
        return user;
    }
}
