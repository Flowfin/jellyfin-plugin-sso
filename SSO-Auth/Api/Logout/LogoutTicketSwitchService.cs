// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Model.Plugins;
using Microsoft.Extensions.Hosting;

namespace Jellyfin.Plugin.SSO_Auth.Api.Logout;

/// <summary>Empties the one-time logout-ticket store at the moment Single Logout is switched off (#1793), as a hosted service subscribed to the plugin's <c>ConfigurationChanged</c> event.</summary>
/// <remarks>
/// The store's sweep runs only from the mint and the redeem, and with the switch off neither is reached, so
/// every outstanding entry would keep a live access token in memory until a visitor arrived; turning the switch
/// off is what an operator does during an incident, which is the one moment those tokens should not wait. Fail-safe
/// like <see cref="LoginButtons.LoginButtonManager"/>: it reads the just-saved configuration, touches no lock, and a
/// save that leaves the switch on empties nothing.
/// </remarks>
internal sealed class LogoutTicketSwitchService : IHostedService
{
    private EventHandler<BasePluginConfiguration>? _handler;

    /// <summary>
    /// Subscribes to configuration changes at host start.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token (unused; the subscription is immediate).</param>
    /// <returns>A completed task.</returns>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var plugin = SSOPlugin.Instance;
        if (plugin is null)
        {
            return Task.CompletedTask;
        }

        _handler = (_, configuration) => OnConfigurationChanged(configuration as PluginConfiguration);
        plugin.ConfigurationChanged += _handler;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Unsubscribes from configuration changes on shutdown.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A completed task.</returns>
    public Task StopAsync(CancellationToken cancellationToken)
    {
        var plugin = SSOPlugin.Instance;
        if (plugin is not null && _handler is not null)
        {
            plugin.ConfigurationChanged -= _handler;
            _handler = null;
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Empties the ticket store when the just-saved configuration has Single Logout off; does nothing otherwise.
    /// </summary>
    /// <param name="configuration">The configuration that was just saved, or null when the event carried another type.</param>
    internal static void OnConfigurationChanged(PluginConfiguration? configuration)
    {
        if (configuration is { EnableSingleLogout: false })
        {
            LogoutTicketService.ClearOutstanding();
        }
    }
}
