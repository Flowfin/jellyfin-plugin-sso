// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The safety net under the per-provider bulk unlink (#1519). The gate refuses a run that would leave an
/// administrator with no way to sign in, and it judges accounts resolved before the removal took the
/// configuration lock; an account can lose a way in inside that window without any link moving, and no
/// link-table comparison can see it. So the same question is asked once more afterwards, and what it names
/// reaches the operator as an Error line rather than as a locked-out administrator at their next sign-in.
/// <para>
/// A unit, because the branch it reports on is by construction unreachable through the endpoint on a
/// server nothing else is writing to: the gate has already refused every account this could name. What
/// makes it fire is a concurrent change, which is exactly what a test cannot stage through one HTTP call.
/// </para>
/// </summary>
public class AdministratorsWithNoWayInTests
{
    private static readonly Guid RootId = Guid.Parse("dddddddd-0000-0000-0000-000000000001");
    private static readonly Guid AliceId = Guid.Parse("dddddddd-0000-0000-0000-000000000002");

    [Fact]
    public void AnAdministratorHoldingNoLinkAtAll_IsNamed()
    {
        var service = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });

        var named = service.AdministratorsWithNoWayIn(new[] { Admin("root", RootId) });

        Assert.Equal(new[] { "root" }, named);
    }

    [Fact]
    public void AnAdministratorStillLinkedToAnEnabledProvider_IsNot()
    {
        // The falsifier: one thing changes - a live link somewhere - and the same account is silent.
        var service = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-root"] = RootId },
        });

        Assert.Empty(service.AdministratorsWithNoWayIn(new[] { Admin("root", RootId) }));
    }

    [Fact]
    public void AnAdministratorWhoseOnlyLinkIsOnADisabledProvider_IsNamed()
    {
        // The reading the whole guard turns on, in its after-the-fact form: a login resolves a link only on
        // an enabled provider, so a link left on one somebody switched off is not a way in.
        var service = Build(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = false,
            CanonicalLinks = new SerializableDictionary<string, Guid> { ["sub-root"] = RootId },
        });

        Assert.Equal(new[] { "root" }, service.AdministratorsWithNoWayIn(new[] { Admin("root", RootId) }));
    }

    [Fact]
    public void ANonAdministratorAndADisabledAdministrator_AreNotNamed()
    {
        // This line exists for the accounts that keep a server administrable. An ordinary account without a
        // link is the normal outcome of the run, and a disabled administrator had no way in before it.
        var service = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });
        var alice = new AccountDoors(AliceId, "alice", IsAdministrator: false, IsDisabled: false, RoutesToPasswordProvider: true, HasStoredPassword: true);
        var disabled = new AccountDoors(RootId, "root", IsAdministrator: true, IsDisabled: true, RoutesToPasswordProvider: false, HasStoredPassword: false);

        Assert.Empty(service.AdministratorsWithNoWayIn(new[] { alice, disabled }));
    }

    [Fact]
    public void AStoredPasswordDoesNotKeepAnAdministratorOutOfTheLine()
    {
        // The same reading the gate takes: this plugin mints an unguessable password onto the accounts it
        // provisions (#1440) and records nowhere which those were, so a non-empty stored password proves
        // nothing about whether anybody can sign in with it.
        var service = Build(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });
        var withPassword = new AccountDoors(RootId, "root", IsAdministrator: true, IsDisabled: false, RoutesToPasswordProvider: true, HasStoredPassword: true);

        Assert.Equal(new[] { "root" }, service.AdministratorsWithNoWayIn(new[] { withPassword }));
    }

    private static AccountDoors Admin(string name, Guid id)
        => new(id, name, IsAdministrator: true, IsDisabled: false, RoutesToPasswordProvider: false, HasStoredPassword: false);

    private static CanonicalLinkService Build(Action<PluginConfiguration> configure)
    {
        var configuration = new PluginConfiguration();
        configure(configuration);
        var store = new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger());

        return new CanonicalLinkService(
            Substitute.For<IUserManager>(),
            new FakeCryptoProvider(),
            store,
            new CapturingLogger(),
            new IntervalGate(TimeSpan.FromMinutes(1)));
    }
}
