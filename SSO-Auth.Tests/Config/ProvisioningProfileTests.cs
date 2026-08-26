// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Serialization;
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
/// Named provisioning profiles (#1105): a provisioning template (#1099/#1100) stops being one inline block
/// per provider and can instead live in the configuration under a name that several providers point at.
/// <para>
/// Two properties are what make this safe rather than merely convenient, and both are pinned here. The first
/// is that a profile is judged by exactly the checks an inline template is - a profile naming
/// <c>IsDisabled</c> or <c>IsAdministrator</c> is refused at save, so the new surface is not a second,
/// unaudited route to the permissions the plugin guards hardest. The second is that the resolution is
/// one-way: a name that resolves to nothing writes NO policy and does not fall back to the inline template,
/// so a configuration edited by hand around the validator can never hand a brand-new account the very
/// permission set the administrator replaced.
/// </para>
/// <para>
/// The third is a compatibility one. A provider that names no profile keeps its inline template, which is
/// every provider written before this existed, and
/// <see cref="AConfigWrittenBeforeProfilesExisted_LoadsAndProvisionsUnchanged"/> is what would go red if
/// that stopped being true.
/// </para>
/// </summary>
public class ProvisioningProfileTests
{
    private static readonly Guid Created = Guid.Parse("44444444-4444-4444-4444-444444444444");
    private static readonly Guid CreatedB = Guid.Parse("55555555-5555-5555-5555-555555555555");

    [Fact]
    public async Task AProviderNamingAProfile_ProvisionsFromThatProfile()
    {
        var configuration = new PluginConfiguration();
        configuration.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate
        {
            Permissions = new List<ProvisionedPermissionEntry>
            {
                new ProvisionedPermissionEntry { Permission = nameof(PermissionKind.EnableContentDownloading), Granted = true },
            },
            MaxActiveSessions = 2,
        };
        configuration.OidConfigs["kc"] = new OidConfig { Enabled = true, ProvisioningProfile = "guest" };
        var (service, users) = BuildFor(configuration);
        var created = Provisionable(users, "alice", Created);

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.True(created.HasPermission(PermissionKind.EnableContentDownloading));
        Assert.Equal(2, created.MaxActiveSessions);
    }

    [Fact]
    public async Task TwoProvidersOnDifferentProfiles_EachProvisionFromItsOwn()
    {
        // The whole point of a named set: one policy per profile, not one per installation. If the resolution
        // ever read the first profile in the set, or the first provider's, both accounts would come out the
        // same and only a test with TWO of each would notice.
        var configuration = new PluginConfiguration();
        configuration.ProvisioningProfiles["default"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 5 };
        configuration.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 1 };
        configuration.OidConfigs["staff"] = new OidConfig { Enabled = true, ProvisioningProfile = "default" };
        configuration.OidConfigs["visitors"] = new OidConfig { Enabled = true, ProvisioningProfile = "guest" };
        var (service, users) = BuildFor(configuration);
        var staff = Provisionable(users, "alice", Created);
        var visitor = Provisionable(users, "bob", CreatedB);

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "staff", "sub-1", "alice", allowExistingAccountLink: false);
        await service.ResolveOrCreateAsync(ProviderMode.Oid, "visitors", "sub-2", "bob", allowExistingAccountLink: false);

        Assert.Equal(5, staff.MaxActiveSessions);
        Assert.Equal(1, visitor.MaxActiveSessions);
    }

    [Fact]
    public async Task AProviderNamingNoProfile_KeepsProvisioningFromItsInlineTemplate()
    {
        // Every installation that configured a template before profiles existed. The inline block stays
        // authoritative for a provider that names no profile, so this change is opt-in per provider.
        var configuration = new PluginConfiguration();
        configuration.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 1 };
        configuration.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate { MaxActiveSessions = 7 },
        };
        var (service, users) = BuildFor(configuration);
        var created = Provisionable(users, "alice", Created);

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(7, created.MaxActiveSessions);
    }

    [Fact]
    public async Task AProfileNameThatResolvesToNothing_WritesNoPolicy_AndNeverFallsBackToTheInlineTemplate()
    {
        // The state the validator refuses twice over (a dangling name, and a name beside an inline template),
        // so it can only arrive in a configuration file edited by hand around the save path. The fail-closed
        // answer is to write nothing: falling back would give the account exactly the permissions the
        // administrator took the provider off when they pointed it at a profile.
        var configuration = new PluginConfiguration();
        configuration.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            ProvisioningProfile = "deleted-profile",
            ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate
            {
                Permissions = new List<ProvisionedPermissionEntry>
                {
                    new ProvisionedPermissionEntry { Permission = nameof(PermissionKind.EnableContentDownloading), Granted = true },
                },
                MaxActiveSessions = 9,
            },
        };
        var (service, users) = BuildFor(configuration);
        var created = Provisionable(users, "alice", Created);
        var before = (created.MaxActiveSessions, created.HasPermission(PermissionKind.EnableContentDownloading));

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(before, (created.MaxActiveSessions, created.HasPermission(PermissionKind.EnableContentDownloading)));
    }

    [Fact]
    public async Task AProfileNamingADedicatedPermission_WritesNothingEvenWhenItReachesTheWriter()
    {
        // The save refuses this shape, so it can only arrive in a configuration file edited by hand. The
        // second line of defence is the writer's own refusal (#1099, #165 Finding H1), and this proves the
        // profile route inherits it rather than reaching the account around it: a template that could set
        // IsDisabled would make every account a provider creates arrive disabled, and one that could grant
        // IsAdministrator would be an unaudited second route to administrator.
        var configuration = new PluginConfiguration();
        configuration.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate
        {
            Permissions = new List<ProvisionedPermissionEntry>
            {
                new ProvisionedPermissionEntry { Permission = nameof(PermissionKind.IsDisabled), Granted = true },
                new ProvisionedPermissionEntry { Permission = nameof(PermissionKind.IsAdministrator), Granted = true },
            },
        };
        configuration.OidConfigs["kc"] = new OidConfig { Enabled = true, ProvisioningProfile = "guest" };
        var (service, users) = BuildFor(configuration);
        var created = Provisionable(users, "alice", Created);

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.False(created.HasPermission(PermissionKind.IsDisabled));
        Assert.False(created.HasPermission(PermissionKind.IsAdministrator));
    }

    [Fact]
    public void AProviderNamingAProfileTheConfigurationDoesNotDefine_IsRefusedAtSave()
    {
        var incoming = new PluginConfiguration();
        incoming.OidConfigs["kc"] = new OidConfig { Enabled = true, ProvisioningProfile = "guest" };

        var error = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.Validate(incoming, new PluginConfiguration()));

        Assert.Contains("guest", error.Message, StringComparison.Ordinal);
        Assert.Contains("does not define", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ASamlProviderNamingAProfileTheConfigurationDoesNotDefine_IsRefusedAtSave()
    {
        // Both protocols carry the field, so both save loops have to refuse it; a rule wired into one only
        // would leave the SAML half persisting a provider that provisions nothing.
        var incoming = new PluginConfiguration();
        incoming.SamlConfigs["idp"] = new SamlConfig { Enabled = true, ProvisioningProfile = "guest" };

        var error = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.Validate(incoming, new PluginConfiguration()));

        Assert.Contains("SAML provider 'idp'", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AProviderNamingAProfileWhileCarryingAnInlineTemplate_IsRefusedAtSave()
    {
        // Two account-creation policies on one provider, with nothing on the page saying which one wins. The
        // resolution has an answer (the profile), but an administrator reading the configuration cannot see
        // it, so the save refuses rather than picking silently.
        var incoming = new PluginConfiguration();
        incoming.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 1 };
        incoming.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            ProvisioningProfile = "guest",
            ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate { MaxActiveSessions = 7 },
        };

        var error = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.Validate(incoming, new PluginConfiguration()));

        Assert.Contains("also carries its own inline provisioning template", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(nameof(PermissionKind.IsDisabled))]
    [InlineData(nameof(PermissionKind.IsAdministrator))]
    [InlineData("EnableNothingAtAll")]
    public void AProfileNamingAPermissionTheInlineSurfaceRefuses_IsRefusedTheSameWay(string permission)
    {
        // The property that keeps this from being a bypass. The dedicated permissions and IsDisabled are
        // refused on the inline template (#1099, #165 Finding H1); a profile is judged by the same checks, so
        // the named surface cannot grant what the inline one may not. It is refused with no provider pointing
        // at the profile at all, because a profile is persisted whether or not it is in use yet.
        var incoming = new PluginConfiguration();
        incoming.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate
        {
            Permissions = new List<ProvisionedPermissionEntry>
            {
                new ProvisionedPermissionEntry { Permission = permission, Granted = true },
            },
        };

        var error = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.Validate(incoming, new PluginConfiguration()));

        Assert.Contains("Provisioning profile 'guest'", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AProfileWithABlankName_IsRefusedAtSave()
    {
        // A profile no provider could ever point at, persisted as dead configuration; refused so the
        // administrator finds out at save rather than wondering why selecting it does nothing.
        var incoming = new PluginConfiguration();
        incoming.ProvisioningProfiles["   "] = new ProvisioningPolicyTemplate { MaxActiveSessions = 1 };

        var error = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.Validate(incoming, new PluginConfiguration()));

        Assert.Contains("blank name", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheProfileSetAndTheNamePointingAtIt_SurviveTheConfigXmlRoundTrip()
    {
        // The plugin base persists and reloads through XmlSerializer, so a member that does not survive that
        // trip is configured once and gone on the next restart - which for this pair would silently turn a
        // provider on a guest policy into one that provisions nothing.
        var configuration = new PluginConfiguration();
        configuration.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate
        {
            Permissions = new List<ProvisionedPermissionEntry>
            {
                new ProvisionedPermissionEntry { Permission = nameof(PermissionKind.EnableContentDownloading), Granted = true },
            },
            MaxActiveSessions = 2,
            SubtitleMode = nameof(SubtitlePlaybackMode.Smart),
        };
        configuration.OidConfigs["kc"] = new OidConfig { Enabled = true, ProvisioningProfile = "guest" };

        var reloaded = Deserialize<PluginConfiguration>(Serialize(configuration));

        Assert.Equal("guest", reloaded.OidConfigs["kc"].ProvisioningProfile);
        var profile = reloaded.ProvisioningProfiles["guest"];
        Assert.Equal(2, profile.MaxActiveSessions);
        Assert.Equal(nameof(SubtitlePlaybackMode.Smart), profile.SubtitleMode);
        Assert.Equal(nameof(PermissionKind.EnableContentDownloading), Assert.Single(profile.Permissions!).Permission);
    }

    [Fact]
    public async Task AConfigWrittenBeforeProfilesExisted_LoadsAndProvisionsUnchanged()
    {
        // The upgrade case, taken from the real serializer rather than a hand-typed literal: a stored config
        // XML with no ProvisioningProfiles element at all must deserialize (XmlSerializer runs the
        // parameterless constructor, so the set comes back empty rather than null) and provision exactly as
        // it did before, from the provider's own inline template.
        var written = new PluginConfiguration();
        written.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate { MaxActiveSessions = 4 },
        };
        var legacyXml = Serialize(written)
            .Replace("<ProvisioningProfiles />", string.Empty, StringComparison.Ordinal)
            .Replace("<ProvisioningProfiles/>", string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain("ProvisioningProfile", legacyXml, StringComparison.Ordinal);

        var reloaded = Deserialize<PluginConfiguration>(legacyXml);
        var (service, users) = BuildFor(reloaded);
        var created = Provisionable(users, "alice", Created);

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Empty(reloaded.ProvisioningProfiles);
        Assert.Equal(4, created.MaxActiveSessions);
    }

    [Fact]
    public void TheProfileSet_TravelsWithAnExportAndImport()
    {
        // A document carrying a provider whose profile it left behind would be refused on import by the
        // validator - fail closed, but it would make the export useless - so the set travels with it.
        var source = new PluginConfiguration();
        source.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 1 };
        source.OidConfigs["kc"] = new OidConfig
        {
            OidEndpoint = "https://idp.example.com/.well-known/openid-configuration",
            OidClientId = "client-1",
            Enabled = true,
            ProvisioningProfile = "guest",
        };
        var target = new PluginConfiguration();

        ConfigImport.Apply(target, WireRoundTrip(ConfigExport.Build(source)));

        Assert.Equal("guest", target.OidConfigs["kc"].ProvisioningProfile);
        Assert.Equal(1, target.ProvisioningProfiles["guest"].MaxActiveSessions);
    }

    [Fact]
    public void AnImport_LeavesAProfileOnlyTheTargetDefines_Untouched()
    {
        // Upsert, like the provider merge: an import is a merge, so a policy this instance defines and the
        // document says nothing about must not disappear underneath the providers still pointing at it.
        var source = new PluginConfiguration();
        source.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 1 };
        var target = new PluginConfiguration();
        target.ProvisioningProfiles["staff"] = new ProvisioningPolicyTemplate { MaxActiveSessions = 9 };

        ConfigImport.Apply(target, WireRoundTrip(ConfigExport.Build(source)));

        Assert.Equal(9, target.ProvisioningProfiles["staff"].MaxActiveSessions);
        Assert.Equal(1, target.ProvisioningProfiles["guest"].MaxActiveSessions);
    }

    private static ConfigExportDocument WireRoundTrip(ConfigExportDocument document) =>
        JsonSerializer.Deserialize<ConfigExportDocument>(JsonSerializer.Serialize(document))!;

    private static string Serialize<T>(T value)
    {
        var serializer = new XmlSerializer(typeof(T));
        using var writer = new StringWriter();
        serializer.Serialize(writer, value);
        return writer.ToString();
    }

    // Deserializes through the XmlReader overload with DTD processing prohibited (the hardened CA5369
    // pattern), mirroring how the production config is only ever read through an XmlReader.
    private static T Deserialize<T>(string xml)
    {
        var serializer = new XmlSerializer(typeof(T));
        using var stringReader = new StringReader(xml);
        using var xmlReader = XmlReader.Create(
            stringReader,
            new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
        return (T)serializer.Deserialize(xmlReader)!;
    }

    private static (CanonicalLinkService Service, IUserManager Users) BuildFor(PluginConfiguration configuration)
    {
        var users = Substitute.For<IUserManager>();
        var store = new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger());
        return (new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger()), users);
    }

    // A name nothing holds yet, so the resolver takes the create arm rather than adopting or refusing.
    private static User Provisionable(IUserManager users, string username, Guid id)
    {
        var created = TestUsers.Named(username, id);
        users.GetUserByName(username).Returns((User?)null);
        users.CreateUserAsync(username).Returns(created);
        users.GetUserById(id).Returns(created);
        return created;
    }
}
