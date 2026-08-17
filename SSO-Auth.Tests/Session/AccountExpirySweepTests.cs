// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Between-logins enforcement of a persisted account-expiry deadline (#1145): a sweep tick disables every
/// SSO-linked account whose stored deadline has passed and revokes that account's tokens, so access ends on
/// the deadline for a user who never attempts another login.
/// <para>
/// This is the half login-time enforcement (#1144) cannot reach. That gate only fires when the expired user
/// comes back; a guest who simply stops logging in keeps an enabled account, any long-lived token and - with
/// <c>DisablePasswordLogin</c> off - a password door, for as long as those happen to last. Deleting the
/// sweep call in <see cref="AccountExpirySweep.SweepAsync"/> reddens most of this file.
/// </para>
/// <para>
/// THE GUARD is the point of <see cref="AnAdministratorPastItsDeadline_IsLeftEnabled"/> and it matters more
/// here than on the login path, because nobody is watching. An identity provider that started emitting a
/// past instant has, by the time a tick runs, already had every affected deadline written to disk, so the
/// tick is where a mass lockout would actually land. Deleting the administrator check inside the shared
/// disable body turns that row red.
/// </para>
/// </summary>
public class AccountExpirySweepTests
{
    private static readonly Guid Linked = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly DateTime Past = new(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime Future = new(2999, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    // The fixed part of the audit line SsoAudit.AccountExpiredBySweep emits, matched rather than reproduced
    // so a reworded message fails one place instead of eight.
    private const string SweepAuditMarker = "background expiry sweep";

    [Fact]
    public async Task AnExpiredDeadline_WithNoInterveningLogin_DisablesTheAccount_AndRevokesItsTokens()
    {
        // The headline Done-when. Both halves are required and they fail differently: leaving the account
        // enabled means the deadline did nothing, and leaving the tokens alive means a session minted before
        // the deadline outlives it, which is time-limited in name only.
        var (sweep, config, users, sessions, audit) = Build();
        var user = LinkedUser(users, config, admin: false, deadline: Past);

        var disabled = await sweep.SweepAsync();

        Assert.Equal(1, disabled);
        Assert.True(user.HasPermission(PermissionKind.IsDisabled));
        await sessions.Received(1).RevokeUserTokens(Linked, null);
        Assert.Single(audit.Entries, e => e.Message.Contains(SweepAuditMarker, StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnAdministratorPastItsDeadline_IsLeftEnabled()
    {
        // THE GUARD (T-D1). A bad claim mapping expires every account at once, and the tick runs unattended;
        // an administrator disabled here has nobody left to repair the configuration.
        var (sweep, config, users, sessions, audit) = Build();
        var admin = LinkedUser(users, config, admin: true, deadline: Past);

        var disabled = await sweep.SweepAsync();

        Assert.Equal(0, disabled);
        Assert.False(admin.HasPermission(PermissionKind.IsDisabled));
        await sessions.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string?>());
        Assert.DoesNotContain(audit.Entries, e => e.Message.Contains(SweepAuditMarker, StringComparison.Ordinal));
    }

    [Fact]
    public async Task ADeadlineStillInTheFuture_TouchesNothing()
    {
        var (sweep, config, users, sessions, audit) = Build();
        var user = LinkedUser(users, config, admin: false, deadline: Future);

        Assert.Equal(0, await sweep.SweepAsync());
        Assert.False(user.HasPermission(PermissionKind.IsDisabled));
        await sessions.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string?>());
        Assert.Empty(audit.Entries);
    }

    [Fact]
    public async Task ASecondTick_NeitherReAuditsNorReRevokes()
    {
        // Idempotence, and it is what keeps a permanently expired link from costing one audit line and one
        // revoke every hour for the life of the server. The second tick finds the account already disabled,
        // the shared disable body returns null, and neither side effect runs again.
        var (sweep, config, users, sessions, audit) = Build();
        LinkedUser(users, config, admin: false, deadline: Past);

        Assert.Equal(1, await sweep.SweepAsync());
        Assert.Equal(0, await sweep.SweepAsync());

        await sessions.Received(1).RevokeUserTokens(Linked, null);
        Assert.Single(audit.Entries, e => e.Message.Contains(SweepAuditMarker, StringComparison.Ordinal));
    }

    [Fact]
    public async Task ADeadlineOnADisabledProvider_TouchesNothing()
    {
        // A provider an administrator switched off already refuses every login for it. Reading that as
        // permission to disable its whole userbase while nobody is watching is the opposite of what the
        // switch says. The refusal is the shared disable body's requireEnabled resolve rather than a second
        // test in the walk, which is why removing that argument - and nothing in the sweep - reddens this.
        var (sweep, config, users, sessions, _) = Build();
        var user = LinkedUser(users, config, admin: false, deadline: Past);
        config.Enabled = false;

        Assert.Equal(0, await sweep.SweepAsync());
        Assert.False(user.HasPermission(PermissionKind.IsDisabled));
        await sessions.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string?>());
    }

    [Fact]
    public async Task ADeadlineWhoseLinkIsGone_DisablesNobody()
    {
        // A stale deadline must never name an account it no longer describes. The link is what says which
        // account the deadline belongs to; without it there is nothing to act on, whatever the map still says.
        var (sweep, config, users, sessions, _) = Build();
        var user = LinkedUser(users, config, admin: false, deadline: Past);
        config.CanonicalLinks.Remove("sub-1");

        Assert.Equal(0, await sweep.SweepAsync());
        Assert.False(user.HasPermission(PermissionKind.IsDisabled));
        await sessions.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string?>());
    }

    [Fact]
    public async Task AnIssuerBoundOpenIdLink_IsStillSwept()
    {
        // The one deliberate difference from the login-path disable, pinned so it cannot be "fixed" back.
        // The issuer binding (#186) refuses a login whose issuer does not match the link's stored one; a
        // sweep carries no login and therefore no issuer, and applying the check with a null issuer would
        // classify every correctly stamped link as a Mismatch - silently exempting exactly the links that
        // are properly bound, which is the population the feature is for.
        var (sweep, config, users, sessions, _) = Build();
        var user = LinkedUser(users, config, admin: false, deadline: Past);
        config.CanonicalLinkIssuers["sub-1"] = "https://idp.example";

        Assert.Equal(1, await sweep.SweepAsync());
        Assert.True(user.HasPermission(PermissionKind.IsDisabled));
        await sessions.Received(1).RevokeUserTokens(Linked, null);
    }

    [Fact]
    public async Task TheAuditLine_NamesTheProvider_AndNeitherTheSubjectNorTheDeadline()
    {
        // T-I1, the same bound the login-time line holds to: the trail carries the protocol and the provider
        // name and nothing an identity provider chose. The instant is excluded with the subject, because an
        // instant is as identifying as a subject once it is rare.
        var (sweep, config, users, _, audit) = Build();
        LinkedUser(users, config, admin: false, deadline: Past);

        await sweep.SweepAsync();

        var line = Assert.Single(audit.Entries, e => e.Message.Contains(SweepAuditMarker, StringComparison.Ordinal)).Message;
        Assert.Contains("kc", line, StringComparison.Ordinal);
        Assert.Contains("OpenID", line, StringComparison.Ordinal);
        Assert.DoesNotContain("sub-1", line, StringComparison.Ordinal);
        Assert.DoesNotContain("2000", line, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheSamlPathIsSweptIdentically()
    {
        // One sweep over both protocols rather than one per protocol, so SAML cannot silently stop being
        // covered. This row is what would go red if the walk were ever narrowed to the OpenID providers.
        var configuration = new PluginConfiguration();
        var config = new SamlConfig { Enabled = true, AccountExpiryClaim = "access_expires" };
        configuration.SamlConfigs["idp"] = config;
        var (sweep, users, sessions, audit) = BuildFor(configuration);

        var user = TestUsers.Named("bob", Linked);
        users.GetUserById(Linked).Returns(user);
        config.CanonicalLinks["nameid-1"] = Linked;
        config.CanonicalLinkDeadlines["nameid-1"] = Past;

        Assert.Equal(1, await sweep.SweepAsync());
        Assert.True(user.HasPermission(PermissionKind.IsDisabled));
        await sessions.Received(1).RevokeUserTokens(Linked, null);
        Assert.Contains(audit.Entries, e => e.Message.Contains("SAML", StringComparison.Ordinal) && e.Message.Contains(SweepAuditMarker, StringComparison.Ordinal));
    }

    [Fact]
    public async Task OneExpiredLinkAmongUnexpiredOnes_LeavesTheOthersAlone()
    {
        // The tick is a filter, not a purge. A provider that carries a mix must come out with exactly the
        // past-deadline account disabled, which is the row that would go red if the comparison were ever
        // inverted or dropped.
        var untouched = Guid.Parse("22222222-2222-2222-2222-222222222222");
        var (sweep, config, users, sessions, _) = Build();
        var expiredUser = LinkedUser(users, config, admin: false, deadline: Past);
        var futureUser = TestUsers.Named("carol", untouched);
        users.GetUserById(untouched).Returns(futureUser);
        config.CanonicalLinks["sub-2"] = untouched;
        config.CanonicalLinkDeadlines["sub-2"] = Future;

        Assert.Equal(1, await sweep.SweepAsync());
        Assert.True(expiredUser.HasPermission(PermissionKind.IsDisabled));
        Assert.False(futureUser.HasPermission(PermissionKind.IsDisabled));
        await sessions.DidNotReceive().RevokeUserTokens(untouched, Arg.Any<string?>());
    }

    // --- helpers ---

    private static (AccountExpirySweep Sweep, OidConfig Config, IUserManager Users, ISessionManager Sessions, CapturingLogger Audit) Build()
    {
        var configuration = new PluginConfiguration();
        var config = new OidConfig { Enabled = true, AccountExpiryClaim = "access_expires" };
        configuration.OidConfigs["kc"] = config;
        var (sweep, users, sessions, audit) = BuildFor(configuration);
        return (sweep, config, users, sessions, audit);
    }

    private static (AccountExpirySweep Sweep, IUserManager Users, ISessionManager Sessions, CapturingLogger Audit) BuildFor(PluginConfiguration configuration)
    {
        var users = Substitute.For<IUserManager>();
        var sessions = Substitute.For<ISessionManager>();
        var audit = new CapturingLogger();
        var store = new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger());
        var canonicalLinks = new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger());
        return (new AccountExpirySweep(canonicalLinks, sessions, audit), users, sessions, audit);
    }

    // An account that already exists, is already linked, and already carries a persisted deadline - the
    // state a previous login left behind. The sweep must never create or adopt anything; it only acts on
    // what a login already wrote.
    private static User LinkedUser(IUserManager users, ProviderConfigBase config, bool admin, DateTime deadline)
    {
        var user = TestUsers.Named("alice", Linked);
        user.SetPermission(PermissionKind.IsAdministrator, admin);
        users.GetUserById(Linked).Returns(user);
        config.CanonicalLinks["sub-1"] = Linked;
        config.CanonicalLinkDeadlines["sub-1"] = deadline;
        return user;
    }
}
