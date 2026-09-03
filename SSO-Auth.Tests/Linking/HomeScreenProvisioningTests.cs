// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The home-screen seed (#1101) on the create arm. Three things are pinned here that the writer's own tests
/// cannot see: the layout is written only after the account row is persisted, a failure in the
/// display-preferences store is logged and never reaches the login, and the write runs on the create arm
/// only, so a second login of the same subject writes no second layout. The validator half sits beside the
/// writer half for each refusal, as the other template tests do, because the two fail differently: the
/// validator is what an administrator meets, the writer's skip is what a configuration edited around it
/// meets.
/// </summary>
public class HomeScreenProvisioningTests
{
    private static readonly Guid Created = Guid.Parse("77777777-7777-7777-7777-777777777777");
    private static readonly List<string> Layout = ["SmallLibraryTiles", "Resume", "NextUp"];

    [Fact]
    public async Task ANewAccount_GetsTheTemplatedLayout_InTheWebClientsDocument()
    {
        var (service, config, users, store, _) = Build();
        config.ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate { HomeSections = Layout };
        Provisionable(users, "alice");

        var id = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(Created, id);
        var document = Assert.Single(store.Documents).Value;
        Assert.Equal((Created, HomeScreenPolicy.UserSettingsItemId, HomeScreenPolicy.WebClient), (document.UserId, document.ItemId, document.Client));
        Assert.Equal(HomeScreenPolicy.SlotCount, document.HomeSections.Count);
        Assert.Equal(
            new[] { HomeSectionType.SmallLibraryTiles, HomeSectionType.Resume, HomeSectionType.NextUp },
            document.HomeSections.OrderBy(s => s.Order).Take(3).Select(s => s.Type));
    }

    [Fact]
    public async Task TheSamlArm_SeedsTheLayoutToo()
    {
        var configuration = new PluginConfiguration();
        configuration.SamlConfigs["idp"] = new SamlConfig
        {
            Enabled = true,
            ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate { HomeSections = Layout },
        };
        var store = new FakeDisplayPreferencesManager();
        var (service, users, _, _) = BuildFor(configuration, store);
        Provisionable(users, "bob");

        await service.ResolveOrCreateAsync(ProviderMode.Saml, "idp", "nameid-1", "bob", allowExistingAccountLink: false);

        Assert.Single(store.Documents);
    }

    [Fact]
    public async Task ANamedProfile_CarriesTheLayoutLikeAnyOtherField()
    {
        // Resolution is ProvisioningPolicy's and is not re-tested here; this pins only that the new member
        // rides it, so a profile can carry a layout without a second resolution path.
        var configuration = new PluginConfiguration();
        configuration.OidConfigs["kc"] = new OidConfig { Enabled = true, ProvisioningProfile = "guest" };
        configuration.ProvisioningProfiles["guest"] = new ProvisioningPolicyTemplate { HomeSections = Layout };
        var store = new FakeDisplayPreferencesManager();
        var (service, users, _, _) = BuildFor(configuration, store);
        Provisionable(users, "alice");

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Single(store.Documents);
    }

    [Fact]
    public async Task AProviderNamingNoLayout_NeverTouchesTheStore()
    {
        // The Done-when clause about an empty block: no row is created, and the store is not even read,
        // because the host's read is what creates the row.
        var (service, config, users, store, _) = Build();
        config.ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate { MaxActiveSessions = 2, HomeSections = [] };
        Provisionable(users, "alice");

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(0, store.Reads);
        Assert.Empty(store.Documents);
    }

    [Fact]
    public async Task TheLayoutIsWrittenOnlyAfterTheAccountIsPersisted()
    {
        // Sequencing, pinned from inside the persist: when the account row is being written the store has
        // not been read yet. A failure thrown in here propagates out of UpdateUserAsync, which the create
        // arm answers by deleting the account and failing the login, so a wrong order fails this test
        // loudly rather than by a count that happens to match.
        var (service, config, users, store, _) = Build();
        config.ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate { HomeSections = Layout };
        var created = Provisionable(users, "alice");
        users.When(u => u.UpdateUserAsync(created)).Do(_ => Assert.Equal(0, store.Reads));

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        await users.Received(1).UpdateUserAsync(created);
        Assert.Equal(1, store.Reads);
    }

    [Fact]
    public async Task AStoreFailure_IsLogged_AndTheLoginSucceedsWithThePersistedAccount()
    {
        // THE ISOLATION CLAUSE. The account exists and is persisted before the layout is attempted, so a
        // store that is down costs the layout and nothing else: the login completes, the account is not
        // rolled back, and the warning names the account so an operator can seed it by hand.
        var (service, config, users, store, log) = Build();
        config.ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate { HomeSections = Layout };
        var created = Provisionable(users, "alice");
        store.Failure = new InvalidOperationException("display-preferences store is down");

        var id = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(Created, id);
        await users.Received(1).UpdateUserAsync(created);
        await users.DidNotReceive().DeleteUserAsync(Arg.Any<Guid>());
        Assert.Empty(store.Documents);
        Assert.Contains(log.Records, r => r.Level == LogLevel.Warning
            && r.Exception is InvalidOperationException
            && r.Message.Contains("alice", StringComparison.Ordinal)
            && r.Message.Contains("home-screen layout could not be written", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ASecondLogin_WritesNoSecondLayout()
    {
        // The template contract, on this surface: the first login provisions and seeds, the second resolves
        // through the subject link and touches the layout the user may have changed by hand not at all.
        var (service, config, users, store, _) = Build();
        config.ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate { HomeSections = Layout };
        Provisionable(users, "alice");

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);
        Assert.Equal(1, store.Updates);
        var second = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(Created, second);
        Assert.Equal(1, store.Reads);
        Assert.Equal(1, store.Updates);
        await users.Received(1).CreateUserAsync("alice");
    }

    [Fact]
    public async Task WithoutAStore_ALayoutIsWarnedAbout_AndTheLoginSucceeds()
    {
        // The between-logins sweeps construct this service with no store because they never reach the
        // create arm. A caller that does reach it without one is a wiring mistake, and it is reported
        // rather than thrown: the account still comes out, without its layout, and the log says why.
        var configuration = new PluginConfiguration();
        configuration.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate { HomeSections = Layout },
        };
        var (service, users, _, log) = BuildFor(configuration, store: null);
        Provisionable(users, "alice");

        var id = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(Created, id);
        Assert.Contains(log.Entries, e => e.Level == LogLevel.Warning && e.Message.Contains("no display-preferences store", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("nextup")]
    [InlineData("7")]
    [InlineData("")]
    [InlineData("Folders")]
    public async Task AnUnknownSectionName_IsRefusedAtSaveAndWritesNothing(string name)
    {
        var refusal = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.ValidateProvisioningTemplate(
            "OpenID",
            "kc",
            new ProvisioningPolicyTemplate { HomeSections = ["Resume", name] }));
        Assert.Contains($"'{name}'", refusal.Message, StringComparison.Ordinal);
        Assert.Contains("HomeSectionType", refusal.Message, StringComparison.Ordinal);

        var (service, config, users, store, _) = Build();
        config.ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate { HomeSections = ["Resume", name] };
        Provisionable(users, "alice");

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(0, store.Reads);
    }

    [Fact]
    public async Task MoreSectionsThanTheClientRenders_IsRefusedAtSaveAndWritesNothing()
    {
        var names = Enumerable.Repeat("Resume", HomeScreenPolicy.SlotCount + 1).ToList();
        var refusal = Assert.Throws<ArgumentException>(() => ProviderConfigValidator.ValidateProvisioningTemplate(
            "SAML",
            "idp",
            new ProvisioningPolicyTemplate { HomeSections = names }));
        Assert.Contains($"lists {names.Count} home-screen sections, more than the {HomeScreenPolicy.SlotCount} slots", refusal.Message, StringComparison.Ordinal);

        var (service, config, users, store, _) = Build();
        config.ProvisioningPolicyTemplate = new ProvisioningPolicyTemplate { HomeSections = names };
        Provisionable(users, "alice");

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(0, store.Reads);
    }

    [Fact]
    public void TheProfileSurface_RefusesTheSameList()
    {
        // One implementation for both surfaces, so a profile cannot carry a layout the inline surface
        // refuses by name.
        var profiles = new SerializableDictionary<string, ProvisioningPolicyTemplate>
        {
            ["guest"] = new ProvisioningPolicyTemplate { HomeSections = ["nextup"] },
        };

        Assert.Throws<ArgumentException>(() => ProviderConfigValidator.ValidateProvisioningProfiles(profiles));
    }

    [Fact]
    public void EveryDeclaredSection_PassesValidation_AndAnEmptyListIsUnset()
    {
        ProviderConfigValidator.ValidateProvisioningTemplate("OpenID", "kc", new ProvisioningPolicyTemplate { HomeSections = Enum.GetNames<HomeSectionType>().ToList() });
        ProviderConfigValidator.ValidateProvisioningTemplate("OpenID", "kc", new ProvisioningPolicyTemplate { HomeSections = [] });
        ProviderConfigValidator.ValidateProvisioningTemplate("OpenID", "kc", new ProvisioningPolicyTemplate { HomeSections = null });
    }

    // --- helpers ---

    private static (CanonicalLinkService Service, OidConfig Config, IUserManager Users, FakeDisplayPreferencesManager Store, CapturingLogger Log) Build()
    {
        var configuration = new PluginConfiguration();
        var config = new OidConfig { Enabled = true };
        configuration.OidConfigs["kc"] = config;
        var (service, users, store, log) = BuildFor(configuration, new FakeDisplayPreferencesManager());
        return (service, config, users, store!, log);
    }

    private static (CanonicalLinkService Service, IUserManager Users, FakeDisplayPreferencesManager? Store, CapturingLogger Log) BuildFor(PluginConfiguration configuration, FakeDisplayPreferencesManager? store)
    {
        var users = Substitute.For<IUserManager>();
        var log = new CapturingLogger();
        var configStore = new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger());
        return (new CanonicalLinkService(users, new FakeCryptoProvider(), configStore, log, displayPreferences: store), users, store, log);
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
