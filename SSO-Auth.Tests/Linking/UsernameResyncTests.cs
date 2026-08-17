// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
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
using NSubstitute.ExceptionExtensions;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Opt-in username re-sync (#1138): with the provider flag on, a login whose identity-provider username has
/// changed renames the linked Jellyfin account to follow it.
/// <para>
/// The invariant every row here is written around is that THE SUBJECT STAYS THE KEY. Resolution is keyed on
/// the OpenID <c>sub</c> / SAML <c>NameID</c> (#155, #186); the account is already resolved by the time the
/// rename runs, so nothing in this feature can change which account a login reaches. A test that asserted a
/// rename by looking the account up BY NAME would not be able to tell that apart from a name-keyed lookup
/// sneaking back in, which is why every assertion here is against the resolved id.
/// </para>
/// <para>
/// The second thing the rows pin is that the feature can never cost a login. A drifted display name is
/// cosmetic; a refused login is not, so every failure path leaves the old name in place and still mints.
/// </para>
/// </summary>
public class UsernameResyncTests
{
    private const string Subject = "sub-1";
    private static readonly Guid Linked = Guid.Parse("44444444-4444-4444-4444-444444444444");
    private static readonly Guid Other = Guid.Parse("55555555-5555-5555-5555-555555555555");

    [Fact]
    public async Task WithTheFlagOn_ADriftedNameIsRenamedToFollowTheProvider()
    {
        var config = Provider(sync: true);
        var (service, users, _, _) = Build(config, currentName: "alice.old");

        await Login(service, config, presentedName: "alice.new");

        await users.Received(1).RenameUser(Linked, "alice.old", "alice.new");
    }

    [Fact]
    public async Task WithTheFlagOff_TheNameIsLeftAlone()
    {
        // The default, and every deployment that exists today. Off means the resolved account is not touched
        // at all, not that a rename is attempted and declined.
        var config = Provider(sync: false);
        var (service, users, _, _) = Build(config, currentName: "alice.old");

        await Login(service, config, presentedName: "alice.new");

        await users.DidNotReceive().RenameUser(Arg.Any<Guid>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task AMatchingName_RenamesNothing()
    {
        // A no-op guard rather than a cosmetic one. Without it every login of every user under this flag
        // would issue a rename to the name the account already has, and each one would write an audit line
        // saying an account was renamed when nothing was.
        var config = Provider(sync: true);
        var (service, users, _, audit) = Build(config, currentName: "alice");

        await Login(service, config, presentedName: "alice");

        await users.DidNotReceive().RenameUser(Arg.Any<Guid>(), Arg.Any<string>(), Arg.Any<string>());
        Assert.DoesNotContain(audit.Entries, e => e.Message.Contains("renamed", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ANameHeldByADifferentAccount_LeavesBothNamesAlone_AndStillMints()
    {
        // The collision the issue asks about. Jellyfin would refuse the rename anyway, but refusing it here
        // is what stops two accounts' names depending on which of them logged in last, and it keeps the
        // reason on the record instead of swallowing a host error as a silent no-op.
        var config = Provider(sync: true);
        var (service, users, sessions, _) = Build(config, currentName: "alice.old");
        users.GetUserByName("alice.new").Returns(TestUsers.Named("alice.new", Other));

        await Login(service, config, presentedName: "alice.new");

        await users.DidNotReceive().RenameUser(Arg.Any<Guid>(), Arg.Any<string>(), Arg.Any<string>());
        await sessions.Received(1).AuthenticateDirect(Arg.Any<AuthenticationRequest>());
    }

    [Fact]
    public async Task ANameHeldByTheSameAccount_IsNotTreatedAsACollision()
    {
        // The near-miss inside the collision guard: a name lookup that resolves back to the account being
        // renamed is not another account. A guard written as a null check rather than an id comparison
        // passes every row above and silently disables the feature for anyone the host indexes by both names.
        var config = Provider(sync: true);
        var (service, users, _, _) = Build(config, currentName: "alice.old");
        users.GetUserByName("alice.new").Returns(TestUsers.Named("alice.new", Linked));

        await Login(service, config, presentedName: "alice.new");

        await users.Received(1).RenameUser(Linked, "alice.old", "alice.new");
    }

    [Fact]
    public async Task ARenameThatThrows_IsSwallowed_AndTheLoginStillSucceeds()
    {
        // The rule that makes this feature safe to turn on. The host owns what a legal name is and this
        // plugin compiles against an interface that promises nothing about what it throws, so anything
        // escaping here would turn a cosmetic mismatch into a login outage for one user.
        var config = Provider(sync: true);
        var (service, users, sessions, audit) = Build(config, currentName: "alice.old");
        users.RenameUser(Linked, "alice.old", "alice.new").ThrowsAsync(new InvalidOperationException("host said no"));

        await Login(service, config, presentedName: "alice.new");

        await sessions.Received(1).AuthenticateDirect(Arg.Any<AuthenticationRequest>());
        Assert.Contains(audit.Entries, e => e.Message.Contains("keeps its current name", StringComparison.Ordinal));
    }

    [Fact]
    public async Task TheNewNameIsSanitizedTheSameWayAProvisionedOneIs()
    {
        // A rename must not be able to put a name onto an account that the host would have refused at
        // creation. The sanitizer drops what Jellyfin's own check rejects, so the account follows the
        // provider as far as the host allows and no further.
        var config = Provider(sync: true);
        var (service, users, _, _) = Build(config, currentName: "alice.old");

        await Login(service, config, presentedName: "ali/ce?new");

        await users.Received(1).RenameUser(Linked, "alice.old", "alicenew");
    }

    [Fact]
    public async Task ANameWithNothingUsableLeft_RenamesNothing()
    {
        var config = Provider(sync: true);
        var (service, users, sessions, _) = Build(config, currentName: "alice.old");

        await Login(service, config, presentedName: "///");

        await users.DidNotReceive().RenameUser(Arg.Any<Guid>(), Arg.Any<string>(), Arg.Any<string>());
        await sessions.Received(1).AuthenticateDirect(Arg.Any<AuthenticationRequest>());
    }

    [Fact]
    public async Task TheRenameIsAudited_WithBothNames()
    {
        // Without the pair of names in the trail, an account an operator is looking for has silently become
        // a different row in the user list with nothing saying why.
        var config = Provider(sync: true);
        var (service, _, _, audit) = Build(config, currentName: "alice.old");

        await Login(service, config, presentedName: "alice.new");

        var line = Assert.Single(audit.Entries, e => e.Message.Contains("[SSO Audit]", StringComparison.Ordinal)
            && e.Message.Contains("renamed", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("alice.old", line.Message, StringComparison.Ordinal);
        Assert.Contains("alice.new", line.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheSamlPathFollowsTheSameRule()
    {
        // Both protocols funnel through the one completion tail, so the rename lives there once rather than
        // per protocol. This row is what would go red if it were ever moved up into the OpenID flow service.
        var config = new SamlConfig { Enabled = true, SamlEndpoint = "https://idp/saml", SyncUsernameFromProvider = true };
        var users = Substitute.For<IUserManager>();
        var sessions = Substitute.For<ISessionManager>();
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());
        var account = TestUsers.Named("bob.old", Linked);
        users.GetUserById(Linked).Returns(account);
        config.CanonicalLinks["bob.new"] = Linked;

        var configuration = new PluginConfiguration();
        configuration.SamlConfigs["idp"] = config;
        var service = Compose(configuration, users, sessions, new CapturingLogger());

        var identity = TestIdentities.Saml(
            "idp",
            "bob.new",
            new SamlAuthorizeStateBuilder.SamlAuthorizeState(false, false, false, new List<string>()));
        await service.CompleteAsync(identity, Response(), config, AdoptionGate.None, () => "203.0.113.9");

        await users.Received(1).RenameUser(Linked, "bob.old", "bob.new");
    }

    private static OidConfig Provider(bool sync) => new OidConfig
    {
        Enabled = true,
        OidEndpoint = "https://idp/.well-known/openid-configuration",
        SyncUsernameFromProvider = sync,
    };

    private static Task Login(LoginCompletionService service, ProviderConfigBase config, string presentedName)
        => service.CompleteAsync(Identity(presentedName), Response(), config, AdoptionGate.None, () => "203.0.113.9");

    private static AuthResponse Response()
        => new AuthResponse { AppName = "app", AppVersion = "1", DeviceID = "d", DeviceName = "dev" };

    private static VerifiedIdentity Identity(string presentedName)
        => TestIdentities.Oidc("kc", new OidcAuthorizeStateBuilder.OidcAuthorizeState(
            Username: presentedName,
            Subject: Subject,
            Issuer: null,
            EmailVerified: null,
            Valid: true,
            Admin: false,
            EnableLiveTv: false,
            EnableLiveTvManagement: false,
            Folders: new List<string>(),
            AvatarUrl: null));

    // A login that resolves an EXISTING subject-keyed link, which is the only arm the rename runs on. The
    // link is seeded under the subject rather than under any name, so a rename that started depending on a
    // name lookup would stop resolving here at all.
    private static (LoginCompletionService Service, IUserManager Users, ISessionManager Sessions, CapturingLogger Audit) Build(OidConfig config, string currentName)
    {
        var configuration = new PluginConfiguration();
        configuration.OidConfigs["kc"] = config;

        var users = Substitute.For<IUserManager>();
        var sessions = Substitute.For<ISessionManager>();
        sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(new AuthenticationResult());

        var account = TestUsers.Named(currentName, Linked);
        users.GetUserById(Linked).Returns(account);
        users.GetUserByName(Arg.Any<string>()).Returns((User?)null);
        config.CanonicalLinks[Subject] = Linked;

        var audit = new CapturingLogger();
        return (Compose(configuration, users, sessions, audit), users, sessions, audit);
    }

    private static LoginCompletionService Compose(PluginConfiguration configuration, IUserManager users, ISessionManager sessions, CapturingLogger audit)
    {
        var store = new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger());
        var canonicalLinks = new CanonicalLinkService(users, new FakeCryptoProvider(), store, audit);
        var avatar = new AvatarService(users, Substitute.For<IProviderManager>(), Substitute.For<IServerConfigurationManager>(), new CapturingLogger(), "test-agent");
        var minter = new SessionMinter(users, avatar, sessions, new CapturingLogger());
        var ssoOnly = new SsoOnlyLoginService(users, store, new CapturingLogger());
        return new LoginCompletionService(canonicalLinks, minter, ssoOnly, store, sessions, audit);
    }
}
