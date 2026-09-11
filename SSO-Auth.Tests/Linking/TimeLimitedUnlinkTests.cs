// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// A time-limited link is not its holder's to remove (#1647). The provisioned access deadline (#1146) lives
/// on the link and the unlink prunes it with the link; a re-login then adopts the account by name with no
/// duration wherever the provider allows adoption. Left open, the self-service unlink was a guest's exit
/// from the very limit that admitted them. So the removal asks who is asking, inside the transaction that
/// removes, and a link carrying a deadline goes only on an administrator's word.
/// </summary>
public class TimeLimitedUnlinkTests
{
    private static readonly Guid Holder = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly DateTime Now = new(2026, 9, 11, 9, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void TheHolder_IsRefused_AndNothingIsTouched()
    {
        var (service, config) = Build(deadline: true);

        var removal = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Holder);

        Assert.Equal(CanonicalLinkRemoveResult.TimeLimited, removal.Result);
        // A no-op outcome, so the retains flag is the undefined-and-false the record's contract names for
        // every outcome but Removed; the controller reads it only on Removed, and this pins that shape.
        Assert.False(removal.UserRetainsAnyLink);
        Assert.Equal(Holder, config.CanonicalLinks["sub-1"]);
        Assert.True(config.CanonicalLinkDeadlines.ContainsKey("sub-1"));
    }

    [Fact]
    public void AnAdministrator_RemovesIt_AndTheDeadlineWithIt()
    {
        var (service, config) = Build(deadline: true);

        var removal = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Holder, callerIsAdministrator: true);

        Assert.Equal(CanonicalLinkRemoveResult.Removed, removal.Result);
        Assert.Empty(config.CanonicalLinks);
        Assert.Empty(config.CanonicalLinkDeadlines);
    }

    [Fact]
    public void TheHolderOfAnOrdinaryLink_StillRemovesIt()
    {
        // The bound: a link with no deadline is the holder's to remove, exactly as before this rule.
        var (service, config) = Build(deadline: false);

        var removal = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Holder);

        Assert.Equal(CanonicalLinkRemoveResult.Removed, removal.Result);
        Assert.Empty(config.CanonicalLinks);
    }

    [Fact]
    public void TheRefusalComesAfterTheOwnershipCheck()
    {
        // A caller who does not own the link is told so, not told about a deadline they cannot see: the
        // deadline is a fact about somebody else's link, and the ownership refusal already fails closed.
        var (service, config) = Build(deadline: true);

        var removal = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Guid.NewGuid());

        Assert.Equal(CanonicalLinkRemoveResult.Mismatch, removal.Result);
        Assert.Equal(Holder, config.CanonicalLinks["sub-1"]);
    }

    [Fact]
    public void ADisabledProvider_StillRefusesTheHolder()
    {
        // The removal keeps working on a disabled provider on purpose (#380: disable-then-clean-up), and so
        // must the refusal: the deadline is read through the provider lookup that ignores Enabled, so a
        // provider switched off does not turn into the holder's exit. This is the one arm a later edit to
        // the lookup could open without a test noticing.
        var (service, config) = Build(deadline: true, enabled: false);

        var removal = service.TryRemoveLink(ProviderMode.Oid, "kc", "sub-1", Holder);

        Assert.Equal(CanonicalLinkRemoveResult.TimeLimited, removal.Result);
        Assert.Equal(Holder, config.CanonicalLinks["sub-1"]);
    }

    [Fact]
    public void TheSamlArm_RefusesTheHolderIdentically()
    {
        // Both protocols funnel through the one removal; the deadline map exists on SAML too (#1146), so
        // the refusal has to as well.
        var configuration = new PluginConfiguration();
        var config = new SamlConfig { Enabled = true };
        config.CanonicalLinks["nameid-1"] = Holder;
        config.CanonicalLinkDeadlines["nameid-1"] = Now + TimeSpan.FromHours(4);
        configuration.SamlConfigs["idp"] = config;
        var users = Substitute.For<IUserManager>();
        var store = new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger());
        var service = new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger(), clock: () => Now);

        Assert.Equal(CanonicalLinkRemoveResult.TimeLimited, service.TryRemoveLink(ProviderMode.Saml, "idp", "nameid-1", Holder).Result);
        Assert.Equal(CanonicalLinkRemoveResult.Removed, service.TryRemoveLink(ProviderMode.Saml, "idp", "nameid-1", Holder, callerIsAdministrator: true).Result);
        Assert.Empty(config.CanonicalLinkDeadlines);
    }

    private static (CanonicalLinkService Service, OidConfig Config) Build(bool deadline, bool enabled = true)
    {
        var configuration = new PluginConfiguration();
        var config = new OidConfig { Enabled = enabled };
        config.CanonicalLinks["sub-1"] = Holder;
        if (deadline)
        {
            config.CanonicalLinkDeadlines["sub-1"] = Now + TimeSpan.FromHours(4);
        }

        configuration.OidConfigs["kc"] = config;
        var users = Substitute.For<IUserManager>();
        users.GetUserById(Holder).Returns(TestUsers.Named("alice", Holder));
        var store = new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger());
        return (new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger(), clock: () => Now), config);
    }
}
