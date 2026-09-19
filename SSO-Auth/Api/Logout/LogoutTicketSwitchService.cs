// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Model.Plugins;
using Microsoft.Extensions.Hosting;

namespace Jellyfin.Plugin.SSO_Auth.Api.Logout;

/// <summary>
/// Empties the one-time logout-ticket store at the moment Single Logout is switched off (#1793). Registered
/// as a hosted service by <see cref="SsoOnlyServiceRegistrator"/> and subscribed to the plugin's
/// <c>ConfigurationChanged</c> event the way <see cref="LoginButtons.LoginButtonManager"/> is.
/// <para>
/// WHY A SUBSCRIPTION AND NOT ONLY THE SWEEP. The store's sweep runs from the mint and from the redeem, and
/// nothing else. The mint returns before it once the feature is off, and the redeem is reached only when
/// somebody presents a ticket - so with the switch off the store's liveness depended on traffic from a
/// caller who is not signed in, and every outstanding entry kept a live access token and its account's slot
/// until such a request arrived or the process ended. Turning the switch off is what an operator does during
/// an incident, which is the one moment those tokens should not sit in memory for want of a visitor. The
/// redeem refuses and empties the store under the switch too, so a ticket in flight at the save is refused
/// either way; this subscription is what makes the emptying happen at the save rather than at the next
/// request.
/// </para>
/// </summary>
/// <remarks>
/// Fail-safe like its sibling: the handler reads the just-saved configuration it is handed and touches no
/// lock, and the store's clear cannot throw. A save that leaves the switch ON empties nothing, because an
/// unrelated configuration write must not refuse a sign-out already under way.
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
