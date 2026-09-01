// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The per-provider provisioning template (#1099): a static policy written onto a BRAND-NEW SSO account at
/// creation and never re-applied.
/// <para>
/// "Never re-applied" is the whole contract and the reason this is a separate mechanism from the role
/// mappings rather than another entry in them. Those are authoritative and re-asserted every login, because
/// a role the identity provider withdrew has to withdraw its permission. A template is a starting point, so
/// an administrator's later per-user edit has to survive;
/// <see cref="ASecondLogin_LeavesAnAdministratorsLaterEdit_Intact"/> is what would go red if the write ever
/// moved onto a path that runs more than once.
/// </para>
/// <para>
/// The second thing pinned here is what a template may NOT write.
/// <see cref="ATemplateNamingADedicatedPermission_IsRefusedAtSaveAndWritesNothing"/> covers both halves,
/// because a config file edited by hand around the validator still reaches the writer, and a template that
/// could grant IsAdministrator or set IsDisabled would be a second, unaudited route to the two permissions
/// the plugin guards hardest.
/// </para>
/// </summary>
public class ProvisioningPolicyTemplateTests
{
    private static readonly Guid Created = Guid.Parse("33333333-3333-3333-3333-333333333333");

    [Fact]
    public async Task ANewAccount_ComesOutWithExactlyTheTemplatedFields()
    {
        var (service, config, users) = Build();
        config.ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate
        {
            Permissions = new List<ProvisionedPermissionEntry>
            {
                new ProvisionedPermissionEntry { Permission = nameof(PermissionKind.EnableContentDownloading), Granted = true },
                new ProvisionedPermissionEntry { Permission = nameof(PermissionKind.EnableRemoteAccess), Granted = false },
            },
            RemoteClientBitrateLimit = 8_000_000,
            MaxActiveSessions = 3,
        };
        var created = Provisionable(users, "alice");

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.True(created.HasPermission(PermissionKind.EnableContentDownloading));
        Assert.False(created.HasPermission(PermissionKind.EnableRemoteAccess));
        Assert.Equal(8_000_000, created.RemoteClientBitrateLimit);
        Assert.Equal(3, created.MaxActiveSessions);
    }

    [Fact]
    public async Task AProviderWithNoTemplate_ProvisionsExactlyAsBefore()
    {
        // The regression that matters most, because it is every existing installation. A provider that never
        // sets a template must reach CreateUserAsync and leave the account carrying Jellyfin's own new-user
        // defaults, untouched by anything this issue added.
        var (service, _, users) = Build();
        var created = Provisionable(users, "alice");
        var before = (created.RemoteClientBitrateLimit, created.MaxActiveSessions, created.HasPermission(PermissionKind.EnableContentDownloading));

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(before, (created.RemoteClientBitrateLimit, created.MaxActiveSessions, created.HasPermission(PermissionKind.EnableContentDownloading)));
    }

    [Fact]
    public async Task AnUnlistedField_IsLeftAtJellyfinsOwnDefault()
    {
        // Opt-in per FIELD, not per template. Setting one permission must not drag the numeric ceilings
        // along with it, or a provider that wanted to grant downloads would silently also pin every new
        // account's session count.
        var (service, config, users) = Build();
        config.ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate
        {
            Permissions = new List<ProvisionedPermissionEntry>
            {
                new ProvisionedPermissionEntry { Permission = nameof(PermissionKind.EnableContentDownloading), Granted = true },
            },
        };
        var created = Provisionable(users, "alice");
        created.MaxActiveSessions = 7;

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.True(created.HasPermission(PermissionKind.EnableContentDownloading));
        Assert.Equal(7, created.MaxActiveSessions);
    }

    [Fact]
    public async Task ASecondLogin_LeavesAnAdministratorsLaterEdit_Intact()
    {
        // THE CONTRACT. The first login provisions and templates; the administrator then changes one of the
        // templated fields by hand; the second login resolves through the existing subject link and must not
        // touch it. Moving the write to any path that runs per login turns this row red.
        var (service, config, users) = Build();
        config.ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate { MaxActiveSessions = 3 };
        var created = Provisionable(users, "alice");

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);
        Assert.Equal(3, created.MaxActiveSessions);

        created.MaxActiveSessions = 99;
        var second = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(Created, second);
        Assert.Equal(99, created.MaxActiveSessions);
        await users.Received(1).CreateUserAsync("alice");
    }

    [Fact]
    public async Task ATemplateNamingADedicatedPermission_IsRefusedAtSaveAndWritesNothing()
    {
        // Both halves, because they fail differently. The validator is what an administrator meets; the
        // writer's skip is what a config file edited around the validator meets, and only the second one
        // stands between a hand-written template and an SSO-provisioned administrator.
        Assert.Throws<ArgumentException>(() => ProviderConfigValidator.ValidateProvisioningTemplate(
            "OpenID",
            "kc",
            new ProvisioningPolicyTemplate
            {
                Permissions = new List<ProvisionedPermissionEntry>
                {
                    new ProvisionedPermissionEntry { Permission = nameof(PermissionKind.IsAdministrator), Granted = true },
                },
            }));

        var (service, config, users) = Build();
        config.ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate
        {
            Permissions = new List<ProvisionedPermissionEntry>
            {
                new ProvisionedPermissionEntry { Permission = nameof(PermissionKind.IsAdministrator), Granted = true },
                new ProvisionedPermissionEntry { Permission = nameof(PermissionKind.IsDisabled), Granted = true },
                new ProvisionedPermissionEntry { Permission = "NotAPermission", Granted = true },
                new ProvisionedPermissionEntry { Permission = null, Granted = true },
                null!,
            },
        };
        var created = Provisionable(users, "alice");

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.False(created.HasPermission(PermissionKind.IsAdministrator));
        Assert.False(created.HasPermission(PermissionKind.IsDisabled));
    }

    [Theory]
    [InlineData(-1, null)]
    [InlineData(null, -1)]
    public void ANegativeCeiling_IsRefusedAtSave(int? bitrate, int? sessions)
    {
        // Refused rather than clamped: an administrator who typed a negative number finds out at save,
        // instead of a value silently becoming something else and being wondered about later.
        Assert.Throws<ArgumentException>(() => ProviderConfigValidator.ValidateProvisioningTemplate(
            "SAML",
            "idp",
            new ProvisioningPolicyTemplate { RemoteClientBitrateLimit = bitrate, MaxActiveSessions = sessions }));
    }

    [Fact]
    public async Task ZeroIsAValidCeiling_AndIsWritten_NotTreatedAsUnset()
    {
        // Jellyfin reads zero as "no limit" and "unlimited", so it is a value an administrator can mean and
        // it has to reach the account. Two ways to lose it and this covers both: refusing it at save, and
        // the subtler one where the writer tests truthiness instead of presence and quietly skips it, which
        // leaves the account on whatever Jellyfin defaulted to while the config page shows a zero.
        ProviderConfigValidator.ValidateProvisioningTemplate(
            "SAML",
            "idp",
            new ProvisioningPolicyTemplate { RemoteClientBitrateLimit = 0, MaxActiveSessions = 0 });

        var (service, config, users) = Build();
        config.ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate { RemoteClientBitrateLimit = 0, MaxActiveSessions = 0 };
        var created = Provisionable(users, "alice");
        created.RemoteClientBitrateLimit = 5;
        created.MaxActiveSessions = 7;

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(0, created.RemoteClientBitrateLimit);
        Assert.Equal(0, created.MaxActiveSessions);
    }

    [Fact]
    public void ANullTemplate_PassesValidation()
    {
        ProviderConfigValidator.ValidateProvisioningTemplate("OpenID", "kc", null);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AnInvalidTemplate_IsRefusedByTheWholeConfigSave_OnBothProtocols(bool openId)
    {
        // The predicate being right is worth nothing if the save never calls it, and a check reachable only
        // from its own unit test is exactly the shape that gets quietly unwired. This goes through the
        // whole-config entry point the config-page save runs, once per protocol, so dropping either call
        // site is caught rather than left to be noticed by an administrator whose template did nothing.
        var incoming = new PluginConfiguration();
        var template = new ProvisioningPolicyTemplate { MaxActiveSessions = -1 };
        if (openId)
        {
            incoming.OidConfigs["kc"] = new OidConfig { ProvisioningPolicyTemplate = template };
        }
        else
        {
            incoming.SamlConfigs["idp"] = new SamlConfig { ProvisioningPolicyTemplate = template };
        }

        Assert.Throws<ArgumentException>(() => ProviderConfigValidator.Validate(incoming, new PluginConfiguration()));
    }

    [Fact]
    public async Task TheSamlArmIsTemplatedToo()
    {
        var configuration = new PluginConfiguration();
        var config = new SamlConfig
        {
            Enabled = true,
            ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate { MaxActiveSessions = 2 },
        };
        configuration.SamlConfigs["idp"] = config;
        var (service, users) = BuildFor(configuration);
        var created = Provisionable(users, "bob");

        await service.ResolveOrCreateAsync(ProviderMode.Saml, "idp", "nameid-1", "bob", allowExistingAccountLink: false);

        Assert.Equal(2, created.MaxActiveSessions);
    }

    [Fact]
    public async Task ANewAccount_ComesOutWithExactlyTheTemplatedPlaybackDefaults()
    {
        // The playback block (#1100). These are columns on the account like the two ceilings above rather
        // than permissions, so they ride the same create-arm write and inherit the same "never re-applied"
        // contract instead of needing a second one.
        var (service, config, users) = Build();
        config.ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate
        {
            AudioLanguagePreference = "eng",
            SubtitleLanguagePreference = "ger",
            SubtitleMode = nameof(SubtitlePlaybackMode.Smart),
            PlayDefaultAudioTrack = true,
            RememberAudioSelections = false,
            RememberSubtitleSelections = true,
        };
        var created = Provisionable(users, "alice");

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal("eng", created.AudioLanguagePreference);
        Assert.Equal("ger", created.SubtitleLanguagePreference);
        Assert.Equal(SubtitlePlaybackMode.Smart, created.SubtitleMode);
        Assert.True(created.PlayDefaultAudioTrack);
        Assert.False(created.RememberAudioSelections);
        Assert.True(created.RememberSubtitleSelections);
    }

    [Fact]
    public async Task AnUnsetPlaybackField_IsLeftAtJellyfinsOwnDefault()
    {
        // Opt-in per field here too: naming an audio language must not drag the other five along and
        // flatten preferences the administrator never mentioned.
        var (service, config, users) = Build();
        config.ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate { AudioLanguagePreference = "eng" };
        var created = Provisionable(users, "alice");
        created.SubtitleLanguagePreference = "fre";
        created.SubtitleMode = SubtitlePlaybackMode.Always;
        created.RememberAudioSelections = true;

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal("eng", created.AudioLanguagePreference);
        Assert.Equal("fre", created.SubtitleLanguagePreference);
        Assert.Equal(SubtitlePlaybackMode.Always, created.SubtitleMode);
        Assert.True(created.RememberAudioSelections);
    }

    [Fact]
    public async Task FalseIsAMeaningfulPreference_AndIsWritten_NotTreatedAsUnset()
    {
        // The bool twin of the zero-ceiling row above, and the reason all three of these are nullable
        // bools. A writer testing truthiness instead of presence would skip a deliberate false, leaving
        // Jellyfin's own default standing while the config shows the box cleared.
        var (service, config, users) = Build();
        config.ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate
        {
            PlayDefaultAudioTrack = false,
            RememberAudioSelections = false,
            RememberSubtitleSelections = false,
        };
        var created = Provisionable(users, "alice");
        created.PlayDefaultAudioTrack = true;
        created.RememberAudioSelections = true;
        created.RememberSubtitleSelections = true;

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.False(created.PlayDefaultAudioTrack);
        Assert.False(created.RememberAudioSelections);
        Assert.False(created.RememberSubtitleSelections);
    }

    [Fact]
    public async Task ASecondLogin_LeavesALaterPlaybackEdit_Intact()
    {
        // The same contract the row above pins for the policy fields, asserted for the playback block,
        // since these are the fields a USER is most likely to change for themselves after provisioning.
        var (service, config, users) = Build();
        config.ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate
        {
            AudioLanguagePreference = "eng",
            SubtitleMode = nameof(SubtitlePlaybackMode.Smart),
        };
        var created = Provisionable(users, "alice");

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);
        Assert.Equal("eng", created.AudioLanguagePreference);

        created.AudioLanguagePreference = "jpn";
        created.SubtitleMode = SubtitlePlaybackMode.None;
        var second = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(Created, second);
        Assert.Equal("jpn", created.AudioLanguagePreference);
        Assert.Equal(SubtitlePlaybackMode.None, created.SubtitleMode);
        await users.Received(1).CreateUserAsync("alice");
    }

    [Theory]
    [InlineData("NotAMode")]
    [InlineData("smart")]
    [InlineData("")]
    public async Task AnUnknownSubtitleMode_IsRefusedAtSaveAndWritesNothing(string mode)
    {
        // Both halves again, and the lowercase row is the one-character mistake somebody actually makes:
        // the parse is deliberately case-SENSITIVE, so "smart" is refused rather than quietly accepted.
        // The writer's skip is what a config file edited around the validator meets, and without it an
        // unparsable name would land on the enum's zero value - a real mode the administrator never chose.
        Assert.Throws<ArgumentException>(() => ProviderConfigValidator.ValidateProvisioningTemplate(
            "OpenID",
            "kc",
            new ProvisioningPolicyTemplate { SubtitleMode = mode }));

        var (service, config, users) = Build();
        config.ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate { SubtitleMode = mode };
        var created = Provisionable(users, "alice");
        created.SubtitleMode = SubtitlePlaybackMode.Always;

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(SubtitlePlaybackMode.Always, created.SubtitleMode);
    }

    [Theory]
    [InlineData("57")]
    [InlineData("1")]
    public async Task ANumericSubtitleMode_IsRefusedAtSaveAndWritesNothing(string mode)
    {
        // #1482: Enum.TryParse also accepts a bare NUMERAL, and the two rows fail differently. "57" parsed
        // to an undeclared (SubtitlePlaybackMode)57 and landed on a brand-new account from a save that
        // reported success. "1" parses to a DECLARED member, so IsDefined waves it through and only the name
        // round-trip refuses it - a numeral pins the stored preference to the order upstream declares the
        // enum in, and a reorder there would silently change what the administrator configured.
        //
        // The account is pre-set to OnlyForced, which is neither of the two values these rows would parse to,
        // so the writer's skip is asserted on both rows rather than only on the undeclared one. Somebody
        // reading Jellyfin's own API, where the mode is a number on the wire, is how a numeral gets typed in.
        Assert.Throws<ArgumentException>(() => ProviderConfigValidator.ValidateProvisioningTemplate(
            "OpenID",
            "kc",
            new ProvisioningPolicyTemplate { SubtitleMode = mode }));

        var (service, config, users) = Build();
        config.ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate { SubtitleMode = mode };
        var created = Provisionable(users, "alice");
        created.SubtitleMode = SubtitlePlaybackMode.OnlyForced;

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(SubtitlePlaybackMode.OnlyForced, created.SubtitleMode);
    }

    [Fact]
    public void EverySubtitleModeJellyfinDefines_IsAccepted_AndTheRefusalNamesRealOnes()
    {
        // Derived from the enum rather than from a list written out here, so a mode Jellyfin adds is
        // accepted the day it lands instead of being refused by a vocabulary that drifted.
        foreach (var mode in Enum.GetValues<SubtitlePlaybackMode>())
        {
            ProviderConfigValidator.ValidateProvisioningTemplate(
                "OpenID",
                "kc",
                new ProvisioningPolicyTemplate { SubtitleMode = mode.ToString() });
        }

        // The refusal message offers examples, and an example that does not parse would send an
        // administrator round the loop a second time. Nothing else checks a string inside a message.
        foreach (var example in new[] { "Default", "Always", "OnlyForced", "Smart" })
        {
            Assert.True(Enum.TryParse<SubtitlePlaybackMode>(example, out _), example);
        }
    }

    [Fact]
    public void ANullSubtitleMode_PassesValidation_BecauseUnsetIsHowAFieldIsDeclined()
    {
        ProviderConfigValidator.ValidateProvisioningTemplate(
            "SAML",
            "idp",
            new ProvisioningPolicyTemplate { AudioLanguagePreference = "eng", SubtitleMode = null });
    }

    // --- helpers ---

    private static (CanonicalLinkService Service, OidConfig Config, IUserManager Users) Build()
    {
        var configuration = new PluginConfiguration();
        var config = new OidConfig { Enabled = true };
        configuration.OidConfigs["kc"] = config;
        var (service, users) = BuildFor(configuration);
        return (service, config, users);
    }

    private static (CanonicalLinkService Service, IUserManager Users) BuildFor(PluginConfiguration configuration)
    {
        var users = Substitute.For<IUserManager>();
        var store = new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger());
        return (new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger()), users);
    }

    // A name nothing holds yet, so the resolver takes the create arm rather than adopting or refusing.
    private static User Provisionable(IUserManager users, string username)
    {
        var created = TestUsers.Named(username, Created);
        users.GetUserByName(username).Returns((User?)null);
        users.CreateUserAsync(username).Returns(created);
        users.GetUserById(Created).Returns(created);
        return created;
    }
}
