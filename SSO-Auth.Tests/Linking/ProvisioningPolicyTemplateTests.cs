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
    public void ZeroIsAValidCeiling_AndIsNotUnset()
    {
        // Jellyfin reads zero as "no limit" on both fields, so it is a value an administrator can mean.
        // Rejecting it, or folding it into unset, would make that setting unreachable through a template.
        ProviderConfigValidator.ValidateProvisioningTemplate(
            "SAML",
            "idp",
            new ProvisioningPolicyTemplate { RemoteClientBitrateLimit = 0, MaxActiveSessions = 0 });
    }

    [Fact]
    public void ANullTemplate_PassesValidation()
    {
        ProviderConfigValidator.ValidateProvisioningTemplate("OpenID", "kc", null);
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
