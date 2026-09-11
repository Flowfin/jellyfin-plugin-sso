// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// A canonical key that changes hands forgets its previous holder (#1638). The two server-managed maps
/// beside the links - the provisioned access deadlines (#1146) and the last-SSO-login stamps (#1120) - were
/// pruned on every route that removes a link and by none of the routes that write one over a key already
/// holding an entry. A key can change hands without ever being removed: a link whose target account was
/// deleted counts as absent, so the next login for that subject writes the key again at a different
/// account, and what the key held before followed it there.
/// <para>
/// The deadline is the one with teeth. The sweep reads a deadline's account off the CURRENT link map, so an
/// inherited past deadline disables the account that just arrived, for an expiry nobody granted it. The
/// stamp is one account's data on another's roster row. Each write route is driven below rather than read,
/// because a removal-only rule looks correct right up to the write that inherits, which is how the first
/// version of the pending-approval record shipped and was caught (#1529).
/// </para>
/// </summary>
public class ReboundKeyTests
{
    private static readonly Guid Deleted = Guid.Parse("55555555-5555-5555-5555-555555555555");
    private static readonly Guid Other = Guid.Parse("44444444-4444-4444-4444-444444444444");
    private static readonly Guid Created = Guid.Parse("33333333-3333-3333-3333-333333333333");
    private static readonly DateTime Now = new(2026, 9, 11, 9, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime Past = new(2026, 9, 10, 9, 0, 0, DateTimeKind.Utc);

    [Fact]
    public async Task AnAdoptionOverADanglingLink_ForgetsTheDeadlineAndTheStamp()
    {
        // THE CHAIN #1638 NAMES. A guest account was provisioned with four hours, expired, was swept
        // disabled, and then deleted by an administrator. Its link dangles and its past deadline stands.
        // The same subject logs in again and is adopted into an existing account; that account must not
        // inherit an expiry that already passed.
        var (service, config, users) = Build();
        Dangling(config, users);
        users.GetUserByName("alice").Returns(TestUsers.Named("alice", Other));
        users.GetUserById(Other).Returns(TestUsers.Named("alice", Other));

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: true);

        Assert.Equal(Other, resolved);
        Assert.Equal(Other, config.CanonicalLinks["sub-1"]);
        Assert.Empty(config.CanonicalLinkDeadlines);
        Assert.Empty(config.CanonicalLinkLastLogins);
    }

    [Fact]
    public async Task TheSweepNoLongerSeesTheInheritedDeadline()
    {
        // The consequence, driven end to end: after the adoption above, the sweep's own read names nothing,
        // where before it named the new account under the old deadline.
        var (service, config, users) = Build();
        Dangling(config, users);
        users.GetUserByName("alice").Returns(TestUsers.Named("alice", Other));
        users.GetUserById(Other).Returns(TestUsers.Named("alice", Other));

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: true);

        Assert.Empty(service.ExpiredLinks(Now));
        Assert.NotNull(config);
    }

    [Fact]
    public async Task AProvisioningWithADuration_OverADanglingLink_ReplacesTheDeadline()
    {
        // The positive direction of the set-or-clear: a fresh provisioning that DOES carry a duration writes
        // its own deadline over the stale one, anchored now, rather than keeping the previous holder's.
        var (service, config, users) = Build();
        Dangling(config, users);
        Provisionable(users);

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false, provisionedAccessDuration: TimeSpan.FromHours(4));

        Assert.Equal(Created, config.CanonicalLinks["sub-1"]);
        Assert.Equal(Now + TimeSpan.FromHours(4), config.CanonicalLinkDeadlines["sub-1"]);
        Assert.Empty(config.CanonicalLinkLastLogins);
    }

    [Fact]
    public async Task AProvisioningWithoutADuration_OverADanglingLink_LeavesNoDeadline()
    {
        // The negative that carries the fix: a fresh provisioning with no duration removes the stale
        // deadline rather than returning early past it, which is what the stamp used to do.
        var (service, config, users) = Build();
        Dangling(config, users);
        Provisionable(users);

        await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false);

        Assert.Equal(Created, config.CanonicalLinks["sub-1"]);
        Assert.Empty(config.CanonicalLinkDeadlines);
    }

    [Fact]
    public void AManualLink_ForgetsBothForTheKeyItRepoints()
    {
        // The self-service and administrator link write repoints a key on purpose, so it is the second route
        // that can land on a key carrying both entries; neither is this account's.
        var (service, config, users) = Build();
        config.CanonicalLinks["sub-1"] = Deleted;
        config.CanonicalLinkDeadlines["sub-1"] = Past;
        config.CanonicalLinkLastLogins["sub-1"] = Past;
        users.GetUserById(Arg.Any<Guid>()).Returns(TestUsers.Named("alice", Other));

        Assert.Equal(CanonicalLinkWriteResult.Created, service.TryCreateLink(ProviderMode.Oid, "kc", "sub-1", Other));

        Assert.Equal(Other, config.CanonicalLinks["sub-1"]);
        Assert.Empty(config.CanonicalLinkDeadlines);
        Assert.Empty(config.CanonicalLinkLastLogins);
    }

    [Fact]
    public void AManualLinkRepeatingTheSameMapping_KeepsEverythingTheAccountHad()
    {
        // THE ROW THE SECURITY REVIEW ASKED FOR. A time-limited account can reach the self-service link
        // write for its OWN subject and its OWN account; if that write took the deadline with it, a guest
        // could shed their time limit by re-linking themselves, and the sweep would never name them again.
        // The key does not change hands here, so nothing the account had goes: not the deadline, not the
        // last login, not a pending-approval record.
        var (service, config, users) = Build();
        config.CanonicalLinks["sub-1"] = Other;
        config.CanonicalLinkDeadlines["sub-1"] = Now + TimeSpan.FromHours(2);
        config.CanonicalLinkLastLogins["sub-1"] = Past;
        config.CanonicalLinkPendingApprovals["sub-1"] = new PendingApproval { UserId = Other, SinceUtc = Past };
        users.GetUserById(Other).Returns(TestUsers.Named("alice", Other));

        Assert.Equal(CanonicalLinkWriteResult.Created, service.TryCreateLink(ProviderMode.Oid, "kc", "sub-1", Other));
        Assert.Equal(CanonicalLinkWriteResult.Created, service.TryPreprovisionLink(ProviderMode.Oid, "kc", "sub-1", Other));

        Assert.Equal(Other, config.CanonicalLinks["sub-1"]);
        Assert.Equal(Now + TimeSpan.FromHours(2), config.CanonicalLinkDeadlines["sub-1"]);
        Assert.Equal(Past, config.CanonicalLinkLastLogins["sub-1"]);
        Assert.Equal(Other, config.CanonicalLinkPendingApprovals["sub-1"].UserId);
        Assert.Single(service.ExpiredLinks(Now + TimeSpan.FromHours(3)));
    }

    [Fact]
    public async Task ALegacyMigration_ForgetsBothOnBothKeys()
    {
        // The #155 re-key moves the link off the legacy username key onto the subject key, overwriting the
        // subject key only when it dangles. Both keys lose both entries: the dangling one's were a deleted
        // account's, and the legacy key has no link left to explain an entry.
        var (service, config, users) = Build();
        Dangling(config, users);
        config.CanonicalLinks["alice"] = Other;
        config.CanonicalLinkDeadlines["alice"] = Past;
        config.CanonicalLinkLastLogins["alice"] = Past;
        users.GetUserByName("alice").Returns(TestUsers.Named("alice", Other));
        users.GetUserById(Other).Returns(TestUsers.Named("alice", Other));

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: true);

        Assert.Equal(Other, resolved);
        Assert.Equal(Other, config.CanonicalLinks["sub-1"]);
        Assert.False(config.CanonicalLinks.ContainsKey("alice"));
        Assert.Empty(config.CanonicalLinkDeadlines);
        Assert.Empty(config.CanonicalLinkLastLogins);
    }

    [Fact]
    public async Task ASecondLoginOfALinkedAccount_LeavesBothExactlyWhereTheyWere()
    {
        // The bound the fix must not cross: an established account's repeat login resolves its live link and
        // never enters the write, so neither its deadline nor its stamp moves. The sliding deadline is the
        // one defect the other direction of this change could have.
        var (service, config, users) = Build();
        config.CanonicalLinks["sub-1"] = Other;
        config.CanonicalLinkDeadlines["sub-1"] = Now + TimeSpan.FromDays(3);
        config.CanonicalLinkLastLogins["sub-1"] = Past;
        users.GetUserById(Other).Returns(TestUsers.Named("alice", Other));

        var resolved = await service.ResolveOrCreateAsync(ProviderMode.Oid, "kc", "sub-1", "alice", allowExistingAccountLink: false, provisionedAccessDuration: TimeSpan.FromHours(1));

        Assert.Equal(Other, resolved);
        Assert.Equal(Now + TimeSpan.FromDays(3), config.CanonicalLinkDeadlines["sub-1"]);
        Assert.Equal(Past, config.CanonicalLinkLastLogins["sub-1"]);
    }

    // A link whose account was deleted, with the entries the deleted account left behind under its key.
    private static void Dangling(OidConfig config, IUserManager users)
    {
        config.CanonicalLinks["sub-1"] = Deleted;
        config.CanonicalLinkDeadlines["sub-1"] = Past;
        config.CanonicalLinkLastLogins["sub-1"] = Past;
        users.GetUserById(Deleted).Returns((User?)null);
    }

    // An account the provisioning arm can create: no existing user answers the name, and the created one
    // comes back by id.
    private static void Provisionable(IUserManager users)
    {
        var created = TestUsers.Named("alice", Created);
        users.GetUserByName(Arg.Any<string>()).Returns((User?)null);
        users.GetUserById(Created).Returns(created);
        users.CreateUserAsync(Arg.Any<string>()).Returns(Task.FromResult(created));
    }

    private static (CanonicalLinkService Service, OidConfig Config, IUserManager Users) Build()
    {
        var configuration = new PluginConfiguration();
        var config = new OidConfig { Enabled = true, AllowExistingAccountLink = true };
        configuration.OidConfigs["kc"] = config;
        var users = Substitute.For<IUserManager>();
        var store = new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger());
        return (new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger(), clock: () => Now), config, users);
    }
}
