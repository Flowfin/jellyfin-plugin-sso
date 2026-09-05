// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// End-to-end cover for #1521, one level above <see cref="ProviderConfigStoreTests"/>: those exercise the
/// store against a persist delegate a test wrote, and these run the real one, so what is pinned here is
/// the whole road to disk - <c>MutateConfiguration</c>, the store, the secret-protection bridge and the
/// plugin base class - rather than the store's half of it.
/// <para>
/// The failure is the one a migration produces and nothing else does: the mutation is valid, the write is
/// not. Measured on 2026-09-05, <c>BasePlugin&lt;T&gt;.UpdateConfiguration</c> assigns
/// <c>Configuration</c> BEFORE it serializes, so a write that threw left the plugin running on settings
/// that are not on disk - the live configuration ahead of the file that both imports promise is atomic.
/// The plugin now writes through <c>SaveConfiguration</c>, which is the write alone.
/// </para>
/// <para>
/// In the <c>SSOController</c> collection because constructing a plugin sets the static
/// <see cref="SSOPlugin.Instance"/> every other test in that collection reads.
/// </para>
/// </summary>
[Collection("SSOController")]
public class FailedPersistTests
{
    [Fact]
    public void AMutationWhoseWriteFails_LeavesTheServerOnTheStoredConfiguration()
    {
        var (plugin, xml) = Plugin(stored => stored.OidConfigs["kept"] = new OidConfig { OidClientId = "client-1" });
        var live = plugin.Configuration;
        Fail(xml, "read-only volume");

        Assert.Throws<IOException>(() => plugin.MutateConfiguration(configuration =>
        {
            configuration.OidConfigs["arrived"] = new OidConfig();
            configuration.OidConfigs["kept"].OidClientId = "overwritten";
        }));

        // Nothing reached the XML, so nothing may be live: an operator who reads the 500 and retries
        // must not be logging in against a provider table only this process knows about, and the next
        // unrelated save must not commit it for them.
        Assert.False(plugin.Configuration.OidConfigs.ContainsKey("arrived"));
        Assert.Equal("client-1", plugin.Configuration.OidConfigs["kept"].OidClientId);

        // And it is still the same configuration object, which is what every reader in the plugin holds.
        Assert.Same(live, plugin.Configuration);
    }

    [Fact]
    public void AMutationWhoseWriteSucceeds_TakesEffect()
    {
        // The positive control: the guard above bites on a failed write and on nothing else. Without
        // this, a plugin that discarded every mutation would satisfy the test above.
        var (plugin, _) = Plugin(_ => { });
        var live = plugin.Configuration;

        plugin.MutateConfiguration(configuration => configuration.OidConfigs["arrived"] = new OidConfig { OidClientId = "client-2" });

        Assert.Equal("client-2", plugin.Configuration.OidConfigs["arrived"].OidClientId);
        Assert.Same(live, plugin.Configuration);
    }

    [Fact]
    public void AConfigPageSaveWhoseWriteFails_LeavesTheServerOnTheStoredConfiguration()
    {
        // The config-page save enters through the override rather than through Mutate, and it broke the
        // same promise more loudly: the posted configuration became live before the serializer was ever
        // called, so a full disk left the whole settings page applied to a server that had not stored a
        // byte of it.
        var (plugin, xml) = Plugin(stored => stored.OidConfigs["kept"] = new OidConfig { OidClientId = "client-1" });
        Fail(xml, "no space left on device");

        var posted = new PluginConfiguration();
        posted.OidConfigs["kept"] = new OidConfig { OidClientId = "posted" };
        posted.DisablePasswordLogin = true;

        Assert.Throws<IOException>(() => plugin.UpdateConfiguration(posted));

        Assert.Equal("client-1", plugin.Configuration.OidConfigs["kept"].OidClientId);
        Assert.False(plugin.Configuration.DisablePasswordLogin);
    }

    [Fact]
    public void AConfigPageSaveWhoseWriteSucceeds_TakesEffect()
    {
        var (plugin, _) = Plugin(stored => stored.OidConfigs["kept"] = new OidConfig { OidClientId = "client-1" });
        var live = plugin.Configuration;

        var posted = new PluginConfiguration();
        posted.OidConfigs["kept"] = new OidConfig { OidClientId = "posted" };

        plugin.UpdateConfiguration(posted);

        Assert.Equal("posted", plugin.Configuration.OidConfigs["kept"].OidClientId);
        Assert.Same(live, plugin.Configuration);
    }

    [Fact]
    public void ConfigurationChanged_IsRaisedByAWriteThatReturned_AndByNothingElse()
    {
        // The base-class update this plugin replaced raised this event as part of persisting, so the
        // replacement owes it too - and owes it only where the state is durable. A subscriber that
        // learned of a change the disk refused would push it on to whoever it notifies.
        var (plugin, xml) = Plugin(_ => { });
        var raised = 0;
        plugin.ConfigurationChanged += (_, _) => raised++;

        plugin.MutateConfiguration(configuration => configuration.EnableSingleLogout = true);
        Assert.Equal(1, raised);

        Fail(xml, "read-only volume");
        Assert.Throws<IOException>(() => plugin.MutateConfiguration(configuration => configuration.EnableSingleLogout = false));
        Assert.Equal(1, raised);
    }

    [Fact]
    public void AConfigurationChangedSubscriberThatThrows_CannotUndoTheWriteItIsBeingToldAbout()
    {
        // The event is raised from inside the store's persist delegate, and the store rolls a write back
        // on ANY exception out of that delegate. So a subscriber that throws would have reverted the live
        // configuration away from a file that already has the change - the exact divergence #1521 exists
        // to abolish, arriving through the fix for it. ConfigurationChanged is a public settable property
        // on the base class, so who subscribes is not a closed set.
        var (plugin, _) = Plugin(_ => { });
        plugin.ConfigurationChanged += (_, _) => throw new InvalidOperationException("a subscriber failed");

        plugin.MutateConfiguration(configuration => configuration.EnableSingleLogout = true);

        Assert.True(plugin.Configuration.EnableSingleLogout);
    }

    [Fact]
    public void AConfigurationChangedSubscriber_SeesTheSavedConfiguration_NotThePreviousOne()
    {
        // The base-class update assigned before it raised, so a subscriber that re-reads the plugin saw
        // the new state. Writing the file first moved the raise after the write; the adoption has to move
        // with it, or a caching subscriber refreshes itself from the configuration that was just replaced.
        var (plugin, _) = Plugin(stored => stored.OidConfigs["kept"] = new OidConfig { OidClientId = "client-1" });
        string? seen = null;
        plugin.ConfigurationChanged += (_, _) => seen = plugin.ReadConfiguration(c => c.OidConfigs["kept"].OidClientId);

        var posted = new PluginConfiguration();
        posted.OidConfigs["kept"] = new OidConfig { OidClientId = "posted" };
        plugin.UpdateConfiguration(posted);

        Assert.Equal("posted", seen);
    }

    private static (SSOPlugin Plugin, IXmlSerializer Xml) Plugin(Action<PluginConfiguration> stored)
    {
        var root = Path.Combine(Path.GetTempPath(), "sso-persist-" + Guid.NewGuid());
        var appPaths = Substitute.For<IApplicationPaths>();
        appPaths.PluginConfigurationsPath.Returns(root);
        appPaths.PluginsPath.Returns(Path.Combine(root, "plugins"));

        var configuration = new PluginConfiguration();
        stored(configuration);

        var xml = Substitute.For<IXmlSerializer>();
        xml.DeserializeFromFile(Arg.Any<Type>(), Arg.Any<string>()).Returns(configuration);

        var plugin = new SSOPlugin(appPaths, xml, Substitute.For<ILogger<SSOPlugin>>());
        _ = plugin.Configuration; // load it before the serializer is told to fail
        return (plugin, xml);
    }

    // Turns the write half of the mocked serializer into the failure a full disk or a read-only volume
    // produces. The read half keeps working, which is what makes this a WRITE failure rather than a
    // plugin that could never load.
    private static void Fail(IXmlSerializer xml, string reason) =>
        xml.When(x => x.SerializeToFile(Arg.Any<object>(), Arg.Any<string>())).Do(_ => throw new IOException(reason));
}
