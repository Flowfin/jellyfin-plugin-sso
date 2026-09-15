// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Who else on this server holds the administrator permission (#1732), the roster the self-unlink guard
/// asks for before it lets an administrator remove their own last way in.
/// </summary>
/// <remarks>
/// THE SET IS DERIVED FROM THE ACCOUNTS AND NOT FROM A LINK TABLE, which is the whole difference from the
/// bulk unlink's <c>DescribeAccountDoors</c> beside it. An administrator who holds no link at all is
/// exactly the answer that decides this question - either they sign in some other way or the server has
/// nobody left - and a set drawn from one provider's links could not contain them.
/// </remarks>
public class AdministratorRosterTests
{
    private static readonly Guid RootId = Guid.Parse("eeeeeeee-0000-0000-0000-000000000001");
    private static readonly Guid AliceId = Guid.Parse("eeeeeeee-0000-0000-0000-000000000002");
    private static readonly Guid BobId = Guid.Parse("eeeeeeee-0000-0000-0000-000000000003");

    [Fact]
    public void TheCallerIsNotInTheirOwnRoster()
    {
        // The subtraction is the question. An administrator counted among the accounts that could undo
        // their own removal answers "somebody is left" on every server with exactly one administrator,
        // which is the population the rule exists for.
        var service = Build(Admin("root", RootId));

        Assert.Empty(service.DescribeAdministratorsOtherThan(RootId));
    }

    [Fact]
    public void AnotherAdministratorIsNamedWithTheDoorsTheTreeCanRead()
    {
        var service = Build(Admin("root", RootId), Admin("alice", AliceId));

        var others = service.DescribeAdministratorsOtherThan(RootId);

        var alice = Assert.Single(others);
        Assert.Equal(AliceId, alice.UserId);
        Assert.Equal("alice", alice.Username);
        Assert.True(alice.IsAdministrator);
        Assert.False(alice.IsDisabled);
    }

    [Fact]
    public void AnAccountThatIsNotAnAdministrator_IsNotNamed()
    {
        // The falsifier for the arm above: one permission changes and the same account is gone. A roster
        // that counted ordinary users would report a way in on every server with a second account, and the
        // guard would be off everywhere.
        var service = Build(Admin("root", RootId), Ordinary("bob", BobId));

        Assert.Empty(service.DescribeAdministratorsOtherThan(RootId));
    }

    [Fact]
    public void AnAdministratorWhoseOnlyPasswordIsMinted_IsNamedWithNoPasswordDoor()
    {
        // #1746, and the reason this roster reports doors rather than a permission list. Every account this
        // plugin provisions on a server whose provider DefaultProvider names the built-in password provider
        // looks exactly like an administrator holding a password: the right provider id and a non-empty
        // stored hash. What is behind that hash is 64 CSPRNG bytes nobody was shown.
        var alice = Admin("alice", AliceId);
        var service = Build(c => ProvisionedPassword.Record(c, AliceId, alice.Password!), Admin("root", RootId), alice);

        var named = Assert.Single(service.DescribeAdministratorsOtherThan(RootId));

        Assert.True(named.RoutesToPasswordProvider);
        Assert.False(named.HoldsAPasswordSomebodySet);
    }

    [Fact]
    public void AnAdministratorWhosePasswordWasReplacedAfterwards_IsNamedWithADoor()
    {
        // The falsifier for the arm above, one write apart from it: the record still names this account and
        // the stored password is no longer the one it recorded. A reading that answered from the record's
        // PRESENCE would report no door here for ever, and every guard downstream would count an
        // administrator who does hold a way in as one who does not.
        var alice = Admin("alice", AliceId);
        var service = Build(c => ProvisionedPassword.Record(c, AliceId, alice.Password!), Admin("root", RootId), alice);
        alice.Password = "the-hash-of-a-password-its-owner-chose";

        var named = Assert.Single(service.DescribeAdministratorsOtherThan(RootId));

        Assert.True(named.HoldsAPasswordSomebodySet);
    }

    [Fact]
    public void ADisabledAdministrator_IsNotNamed()
    {
        // A disabled account has no way in for anybody to take, so counting it would make an empty roster
        // look populated - which is the direction that costs the server rather than a call.
        var service = Build(Admin("root", RootId), Disabled("alice", AliceId));

        Assert.Empty(service.DescribeAdministratorsOtherThan(RootId));
    }

    [Fact]
    public void AServerThatCannotBeEnumerated_Throws_RatherThanAnsweringAnEmptyRoster()
    {
        // Fail closed on the one build this plugin cannot survey. `AllUsers` binds whichever accessor the
        // loaded Jellyfin exposes, and a build exposing neither must not read as a server with no other
        // administrator that also has no way to be asked: the caller turns this into the refusal, and an
        // empty list returned here would instead turn the guard OFF on exactly that build.
        var users = Substitute.For<IUserManager>();
        users.GetUsers().Returns((IReadOnlyList<User>?)null);
        var store = new ProviderConfigStore(() => new PluginConfiguration(), _ => { }, new CapturingLogger());
        var service = new SsoOnlyLoginService(users, store, new CapturingLogger());

        Assert.Throws<InvalidOperationException>(() => service.DescribeAdministratorsOtherThan(RootId));
    }

    private static User Admin(string name, Guid id)
    {
        var user = Ordinary(name, id);
        user.SetPermission(PermissionKind.IsAdministrator, true);
        return user;
    }

    private static User Disabled(string name, Guid id)
    {
        var user = Admin(name, id);
        user.SetPermission(PermissionKind.IsDisabled, true);
        return user;
    }

    private static User Ordinary(string name, Guid id)
    {
        var user = new User(name, "SSO-Auth", "Default") { Id = id, Password = "hash-" + name };
        user.AuthenticationProviderId = SsoAuthenticationProviders.DefaultPasswordProviderId;
        return user;
    }

    private static SsoOnlyLoginService Build(params User[] allUsers) => Build(seed: null, allUsers);

    private static SsoOnlyLoginService Build(Action<PluginConfiguration>? seed, params User[] allUsers)
    {
        var users = Substitute.For<IUserManager>();
        users.GetUsers().Returns(allUsers.ToList());
        foreach (var user in allUsers)
        {
            users.GetUserById(user.Id).Returns(user);
        }

        var configuration = new PluginConfiguration();
        seed?.Invoke(configuration);
        var store = new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger());
        return new SsoOnlyLoginService(users, store, new CapturingLogger());
    }
}
