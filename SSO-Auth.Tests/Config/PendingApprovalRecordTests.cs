// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Xml.Serialization;
using Jellyfin.Data;
using Jellyfin.Data.Enums;
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
/// The pending-approval record (#1529): that it says what this plugin DID rather than what it can guess,
/// that it cannot outlive the link that gives it meaning, and that it cannot follow a key onto an account
/// it was never written about.
/// <para>
/// The whole reason the record exists is that a disabled account is a Jellyfin PERMISSION and the permission
/// does not say who set it. Three accounts wear the same flag - one provisioned inert by this plugin seconds
/// ago, one disabled by an administrator as a sanction, one disabled long ago and forgotten - and a surface
/// offering to approve "the disabled accounts" would offer to undo the second. So the tests below assert the
/// NEGATIVE cases as hard as the positive one: a provisioning that was not inert leaves nothing behind, and
/// the race loser that abandons its account leaves nothing either.
/// </para>
/// <para>
/// The second property is the bound, and it has two halves because the key is bounded by the link map while
/// the ACCOUNT behind that key is not. Every route that removes a link is asserted to remove the record;
/// every route that WRITES one over an existing key is asserted to clear it, because a link whose target was
/// deleted counts as absent and the next login for that subject writes the key at another account. The last
/// test is the backstop under both: a record naming an account the link no longer points at is reported as
/// no record at all, so a write path that forgets is a tidiness defect and not an offer to enable somebody
/// else's account. Each is driven through the route rather than read off the code.
/// </para>
/// </summary>
public class PendingApprovalRecordTests
{
    private static readonly Guid User = Guid.Parse("33333333-3333-3333-3333-333333333333");
    private static readonly Guid Other = Guid.Parse("44444444-4444-4444-4444-444444444444");
    private static readonly Guid Deleted = Guid.Parse("55555555-5555-5555-5555-555555555555");
    private static readonly DateTime Now = new(2026, 9, 11, 9, 0, 0, DateTimeKind.Utc);

    [Fact]
    public async Task AProvisioningThatCreatesTheAccountInert_RecordsTheAccountAndTheInstant()
    {
        // The call site. Without it the map is a field nothing fills and the accounts page has no list. The
        // account is asserted beside the instant because it is the half that makes the record refutable: an
        // instant alone would describe whichever account the key came to name later.
        var config = new OidConfig { Enabled = true, EnableAuthorization = true, ProvisionNewUsersDisabled = true };
        var (service, users, configuration) = BuildLogin(config);
        Provisionable(users);

        await service.CompleteAsync(Identity(), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        var record = Assert.Single(config.CanonicalLinkPendingApprovals).Value;
        Assert.Equal("sub-1", Assert.Single(config.CanonicalLinkPendingApprovals).Key);
        Assert.Equal(User, record.UserId);
        Assert.Equal(Now, record.SinceUtc);
        Assert.NotNull(configuration);
    }

    [Fact]
    public async Task AnOrdinaryProvisioning_RecordsNothing()
    {
        // The negative that carries the feature. An account created ENABLED is not waiting for anybody, and a
        // record for it would put a working account on an approval list - where pressing the button is a no-op
        // and the list stops meaning what it says.
        var config = new OidConfig { Enabled = true, EnableAuthorization = true, ProvisionNewUsersDisabled = false };
        var (service, users, _) = BuildLogin(config);
        Provisionable(users);

        await service.CompleteAsync(Identity(), Response(), config, AdoptionGate.None, () => "203.0.113.9");

        Assert.Empty(config.CanonicalLinkPendingApprovals);
    }

    [Fact]
    public void ARecordIsRemovedWithItsLink()
    {
        // Every route that removes a link must remove the record, because the record is an OFFER TO ENABLE and
        // an offer whose link is gone points at an account with no SSO route left. This drives the unlink
        // rather than reading it.
        var config = new OidConfig { Enabled = true };
        var configuration = Holding(config, "sub-1", User);

        var service = BuildLinks(configuration, out var users);
        users.GetUserById(User).Returns(TestUsers.Named("alice", User));

        service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", User);

        Assert.Empty(config.CanonicalLinkPendingApprovals);
    }

    [Fact]
    public void AProviderPurge_TakesEveryRecordWithTheLinks()
    {
        // The purge empties the link map wholesale, so it empties this one in the same transaction. Nothing
        // survives a provider whose links are gone: a record left here would name a provider that can no
        // longer explain why anybody is inert.
        var config = new OidConfig { Enabled = true };
        var configuration = new PluginConfiguration();
        configuration.OidConfigs["kc"] = config;
        config.CanonicalLinkPendingApprovals["sub-gone"] = Record(User);

        var service = BuildLinks(configuration, out var users);
        users.GetUserById(Arg.Any<Guid>()).Returns((Jellyfin.Database.Implementations.Entities.User?)null);

        service.TryPurgeProviderLinks(ProviderMode.Oid, "kc", 0, System.Array.Empty<AccountDoors>());

        Assert.Empty(config.CanonicalLinkPendingApprovals);
    }

    [Fact]
    public void ARecordWhoseLinkTheUnregisterRevoked_IsPrunedAndItsNeighbourIsNot()
    {
        // The bulk route removes links directly rather than through the single unlink, so it carries its own
        // prune - and a record missed there would be exactly the standing offer this map must not become.
        // The neighbour is asserted as hard as the removal: this prune is keyed, not a sweep, so revoking one
        // account's links must not empty the approval list for everybody else.
        var config = new OidConfig { Enabled = true };
        var configuration = Holding(config, "sub-1", User);
        config.CanonicalLinks["sub-other"] = Other;
        config.CanonicalLinkPendingApprovals["sub-other"] = Record(Other);

        var service = BuildLinks(configuration, out var users);
        users.GetUserById(Arg.Any<Guid>()).Returns((Jellyfin.Database.Implementations.Entities.User?)null);

        service.RemoveUserEverywhere(User);

        Assert.False(config.CanonicalLinkPendingApprovals.ContainsKey("sub-1"));
        Assert.True(config.CanonicalLinkPendingApprovals.ContainsKey("sub-other"));
    }

    [Fact]
    public async Task TheRaceLoser_RecordsNothing()
    {
        // #133 read as this map sees it. Two first logins for one identity run at once; the loser finds the
        // winner's link already written, keeps the account it created, and writes no link - so it must write
        // no record either, or it would offer an administrator the account it just abandoned. The property
        // lives in WHERE the record is written (inside the branch only the writer enters), which is exactly
        // the kind of placement that survives a refactor only if something drives it: the winner's link is
        // planted from inside CreateUserAsync, which is the window the race actually opens.
        var config = new OidConfig { Enabled = true, AllowExistingAccountLink = false };
        var configuration = new PluginConfiguration();
        configuration.OidConfigs["kc"] = config;

        var service = BuildLinks(configuration, out var users);
        var created = TestUsers.Named("alice", User);
        users.GetUserByName(Arg.Any<string>()).Returns((Jellyfin.Database.Implementations.Entities.User?)null);
        users.GetUserById(User).Returns(created);
        users.GetUserById(Other).Returns(TestUsers.Named("alice", Other));
        users.CreateUserAsync(Arg.Any<string>()).Returns(_ =>
        {
            config.CanonicalLinks["sub-1"] = Other;
            return Task.FromResult(created);
        });

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false, provisionDisabled: true);

        Assert.Equal(Other, resolved);
        Assert.Equal(Other, config.CanonicalLinks["sub-1"]);
        Assert.Empty(config.CanonicalLinkPendingApprovals);
    }

    [Fact]
    public async Task AnAdoptionOverADanglingLink_DropsTheRecordItFound()
    {
        // THE ONE THIS FEATURE TURNS ON, and the one the removal routes alone do not cover. The account this
        // plugin provisioned inert was DELETED rather than unlinked - which is the only rejection route an
        // administrator has today - so the link dangles and its record stands. A dangling link counts as
        // absent, so the next login for the same subject writes the key again, and here it writes it at an
        // account that already existed. Inheriting the record would put somebody else's account on the
        // approval list, including one an administrator disabled deliberately, which is precisely the
        // privilege escalation this map exists to prevent, arrived at from the other side.
        var config = new OidConfig { Enabled = true, AllowExistingAccountLink = true };
        var configuration = Holding(config, "sub-1", Deleted);

        var service = BuildLinks(configuration, out var users);
        users.GetUserById(Deleted).Returns((Jellyfin.Database.Implementations.Entities.User?)null);
        users.GetUserByName("alice").Returns(TestUsers.Named("alice", Other));
        users.GetUserById(Other).Returns(TestUsers.Named("alice", Other));

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: true);

        Assert.Equal(Other, resolved);
        Assert.Equal(Other, config.CanonicalLinks["sub-1"]);
        Assert.Empty(config.CanonicalLinkPendingApprovals);
    }

    [Fact]
    public async Task ALegacyMigration_DropsTheRecordsOnBothKeys()
    {
        // The #155 re-key moves a link from the legacy username key onto the subject key, overwriting the
        // subject key only when it dangles. Both keys lose their record for the same reason the adoption
        // above does: neither write is this plugin provisioning an account inert, and the account the
        // dangling record was written about is gone.
        var config = new OidConfig { Enabled = true, AllowExistingAccountLink = true };
        var configuration = Holding(config, "sub-1", Deleted);
        config.CanonicalLinks["alice"] = Other;
        config.CanonicalLinkPendingApprovals["alice"] = Record(Other);

        var service = BuildLinks(configuration, out var users);
        users.GetUserById(Deleted).Returns((Jellyfin.Database.Implementations.Entities.User?)null);
        users.GetUserByName("alice").Returns(TestUsers.Named("alice", Other));
        users.GetUserById(Other).Returns(TestUsers.Named("alice", Other));

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: true);

        Assert.Equal(Other, resolved);
        Assert.Equal(Other, config.CanonicalLinks["sub-1"]);
        Assert.Empty(config.CanonicalLinkPendingApprovals);
    }

    [Fact]
    public void AManualLink_DropsTheRecordTheKeyHeld()
    {
        // The admin/self link endpoint repoints a key on purpose, so it is the second route that can land on
        // a key carrying a record. A manual link is nobody's provisioning, so whatever the key was recorded
        // as before goes with the link it described.
        var config = new OidConfig { Enabled = true };
        var configuration = Holding(config, "sub-1", User);

        var service = BuildLinks(configuration, out var users);
        users.GetUserById(Arg.Any<Guid>()).Returns(TestUsers.Named("alice", Other));

        Assert.Equal(CanonicalLinkWriteResult.Created, service.TryCreateLink(ProviderMode.Oid, "kc", "sub-1", Other));

        Assert.Equal(Other, config.CanonicalLinks["sub-1"]);
        Assert.Empty(config.CanonicalLinkPendingApprovals);
    }

    [Fact]
    public void AnOrdinarySave_KeepsTheRecords()
    {
        // The records are withheld from JSON, so a configuration-page save arrives with the map empty. Without
        // the preserve, an unrelated settings change would silently empty the approval list - and the
        // accounts waiting on it would simply stop being offered, with nothing saying why.
        var live = new OidConfig { OidEndpoint = "https://id.example.com" };
        live.CanonicalLinkPendingApprovals["sub-1"] = Record(User);
        var incoming = new OidConfig { OidEndpoint = "https://id.example.com" };

        ServerManagedFields.Preserve(incoming, live);

        Assert.True(incoming.CanonicalLinkPendingApprovals.ContainsKey("sub-1"));
    }

    [Fact]
    public void ARepointDropsTheRecordsWithTheLinks()
    {
        // A repoint re-identifies the provider, so a record carried across it would say this plugin
        // provisioned an account inert for an identity the NEW provider has never seen - and that record is
        // what makes the account approvable. Dropped with its link, the account stops being offered, which is
        // the safe direction for a surface that grants access.
        var live = new OidConfig { OidEndpoint = "https://id.example.com" };
        live.CanonicalLinkPendingApprovals["sub-1"] = Record(User);
        var incoming = new OidConfig { OidEndpoint = "https://other.example.com" };

        ServerManagedFields.Preserve(incoming, live);

        Assert.Empty(incoming.CanonicalLinkPendingApprovals);
    }

    [Fact]
    public void TheRecordIsWithheldFromJson_AndSurvivesTheXmlRoundTrip()
    {
        // The JsonIgnore is load-bearing here in a way it is not on the neighbouring maps: a config PUT that
        // could forge an entry would make an account approvable that this plugin never provisioned, which is
        // the same escalation as the stale record, reached from the other side. The XML half is asserted in
        // the same test because the value is a class rather than an instant, so that it round-trips at all is
        // a property of this change and not of the dictionary it is stored in.
        var config = new OidConfig
        {
            OidClientId = "client",
            CanonicalLinkPendingApprovals = new SerializableDictionary<string, PendingApproval> { ["sub-secret"] = Record(User) },
        };

        var json = System.Text.Json.JsonSerializer.Serialize(config);
        Assert.DoesNotContain("CanonicalLinkPendingApprovals", json, StringComparison.Ordinal);
        Assert.DoesNotContain("sub-secret", json, StringComparison.Ordinal);

        var serializer = new XmlSerializer(typeof(OidConfig));
        using var writer = new System.IO.StringWriter();
        serializer.Serialize(writer, config);
        var xml = writer.ToString();
        Assert.Contains("CanonicalLinkPendingApprovals", xml, StringComparison.Ordinal);

        using var reader = new System.IO.StringReader(xml);
        using var xmlReader = System.Xml.XmlReader.Create(
            reader,
            new System.Xml.XmlReaderSettings { DtdProcessing = System.Xml.DtdProcessing.Prohibit, XmlResolver = null });
        var back = (OidConfig)serializer.Deserialize(xmlReader)!;

        Assert.Equal(User, back.CanonicalLinkPendingApprovals["sub-secret"].UserId);
        Assert.Equal(Now, back.CanonicalLinkPendingApprovals["sub-secret"].SinceUtc.ToUniversalTime());
    }

    [Fact]
    public void APostedRecordIsDropped()
    {
        // The forge, driven rather than argued. The test above asserts the map does not LEAVE over the JSON
        // boundary; this one asserts it cannot ARRIVE over it, which is the direction the escalation runs:
        // a body naming an account and an instant would make that account approvable from the accounts page
        // without this plugin ever having provisioned it inert. JsonIgnore suppresses both directions, and
        // the value being a class rather than an instant does not change that - which is worth a row,
        // because it is the kind of thing a converter added later could quietly change.
        var posted = System.Text.Json.JsonSerializer.Deserialize<OidConfig>(
            """{"OidClientId":"client","CanonicalLinkPendingApprovals":{"sub-forged":{"UserId":"33333333-3333-3333-3333-333333333333","SinceUtc":"2026-09-11T09:00:00Z"}}}""")!;

        Assert.Equal("client", posted.OidClientId);
        Assert.Empty(posted.CanonicalLinkPendingApprovals);
    }

    [Fact]
    public void TheRosterReportsTheRecordAndItsAbsence()
    {
        // The page reads the roster, so the record has to survive the trip. Both answers are asserted: an
        // unrecorded link must report null rather than a default instant a reader would render as a date in
        // year one, because null is what tells the page NOT to offer the row.
        var configuration = new PluginConfiguration();
        var config = new OidConfig();
        configuration.OidConfigs["kc"] = config;
        config.CanonicalLinks["sub-pending"] = User;
        config.CanonicalLinks["sub-ordinary"] = User;
        config.CanonicalLinkPendingApprovals["sub-pending"] = Record(User);

        var document = LinkRoster.Build(configuration, _ => "alice");

        var links = Assert.Single(document.Accounts).Links;
        Assert.Equal(Now, Assert.Single(links, l => l.CanonicalName == "sub-pending").PendingApprovalSinceUtc);
        Assert.Null(Assert.Single(links, l => l.CanonicalName == "sub-ordinary").PendingApprovalSinceUtc);
    }

    [Fact]
    public void TheRosterRefusesARecordThatNamesAnotherAccount()
    {
        // THE BACKSTOP UNDER EVERY WRITE ROUTE, present and future. The record above is about a different
        // account than the link now points at, so it describes nothing that is true of this row and the
        // roster reports none. It is what keeps a write path that forgets to clear a record from becoming a
        // page that offers to enable an account nobody provisioned inert - fail closed, at the cost of an
        // administrator enabling one account by hand.
        var configuration = new PluginConfiguration();
        var config = new OidConfig();
        configuration.OidConfigs["kc"] = config;
        config.CanonicalLinks["sub-1"] = User;
        config.CanonicalLinkPendingApprovals["sub-1"] = Record(Other);

        var document = LinkRoster.Build(configuration, _ => "alice");

        Assert.Null(Assert.Single(Assert.Single(document.Accounts).Links).PendingApprovalSinceUtc);
    }

    private static PendingApproval Record(Guid userId) => new PendingApproval { UserId = userId, SinceUtc = Now };

    // A provider holding one link and the record that goes with it, which is the state every rebind test
    // starts from.
    private static PluginConfiguration Holding(OidConfig config, string canonicalName, Guid userId)
    {
        var configuration = new PluginConfiguration();
        configuration.OidConfigs["kc"] = config;
        config.CanonicalLinks[canonicalName] = userId;
        config.CanonicalLinkPendingApprovals[canonicalName] = Record(userId);
        return configuration;
    }

    // An account the provisioning arm can actually create: no existing user answers the name, and the
    // created one comes back so the disabled flag has somewhere to land.
    private static void Provisionable(IUserManager users)
    {
        var created = TestUsers.Named("alice", User);
        users.GetUserByName(Arg.Any<string>()).Returns((Jellyfin.Database.Implementations.Entities.User?)null);
        users.GetUserById(User).Returns(created);
        users.CreateUserAsync(Arg.Any<string>()).Returns(Task.FromResult(created));
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

    private static CanonicalLinkService BuildLinks(PluginConfiguration configuration, out IUserManager users)
    {
        users = Substitute.For<IUserManager>();
        var store = new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger());
        return new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger(), clock: () => Now);
    }

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
