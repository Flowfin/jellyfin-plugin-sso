// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading.Tasks;
using Jellyfin.Data.Events.Users;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Events;
using MediaBrowser.Model.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The one host-facing seam of #1649, read back the way the host reads it: the event manager resolves every
/// <see cref="IEventConsumer{T}"/> from a scope of the container the registrator filled, through the public
/// constructor no other test runs, and the resolved instance prunes the plugin's LIVE store. It runs in the
/// non-parallel collection because it stands a real plugin instance up, which makes the plugin being up a
/// fact of this test rather than of whatever ran before it in the process.
/// </summary>
[Collection("SSOController")]
public class DeletedAccountLinkPrunerWiringTests
{
    [Fact]
    public async Task TheHostResolvesTheConsumer_FromWhatTheRegistratorRegistered_AndItPrunesTheLiveStore()
    {
        // Built the way the outbound-client test builds it, with the host services the constructor asks for
        // supplied as the host supplies them. The link is seeded in the plugin instance's own store, so what
        // the event removes is what a real deletion would find, not a fixture handed to a constructor.
        var gone = Guid.NewGuid();
        _ = new SsoControllerHarness(configuration =>
        {
            var oid = new OidConfig { Enabled = true };
            oid.CanonicalLinks["sub-gone"] = gone;
            configuration.OidConfigs["kc"] = oid;
        });
        var log = new CapturingLogger();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ILogger<DeletedAccountLinkPruner>>(new TypedLogger<DeletedAccountLinkPruner>(log));
        services.AddSingleton(Substitute.For<MediaBrowser.Controller.Library.IUserManager>());
        services.AddSingleton<ICryptoProvider>(new FakeCryptoProvider());
        new SsoOnlyServiceRegistrator().RegisterServices(services, Substitute.For<IServerApplicationHost>());
        await using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        var consumer = Assert.Single(scope.ServiceProvider.GetServices<IEventConsumer<UserDeletedEventArgs>>());
        Assert.IsType<DeletedAccountLinkPruner>(consumer);

        await consumer.OnEvent(new UserDeletedEventArgs(TestUsers.Named("alice", gone)));

        // The link is gone from the live store, and the one line about it came through the logger the
        // container wired: the wiring claim made real, not inferred from a type check.
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs["kc"].CanonicalLinks.ContainsKey("sub-gone")));
        var entry = Assert.Single(log.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("[SSO Audit]", entry.Message, StringComparison.Ordinal);
        Assert.Contains("OpenID 'kc'", entry.Message, StringComparison.Ordinal);
    }
}
