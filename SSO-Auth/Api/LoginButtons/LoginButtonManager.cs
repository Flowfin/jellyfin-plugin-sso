// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Model.Branding;
using MediaBrowser.Model.Plugins;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.LoginButtons;

/// <summary>Keeps Jellyfin's login-page branding disclaimer in sync with the configured providers (#722): at host start and on every configuration change it rebuilds the managed button block and splices it into <c>BrandingOptions.LoginDisclaimer</c>, or removes the region when management is off.</summary>
/// <remarks>The handler reads the just-saved configuration the <c>ConfigurationChanged</c> event hands it and never re-enters the plugin's config lock; the branding write goes to a different store, so it cannot re-trigger the handler, is made only when the merge changes the disclaimer, and every error is logged and swallowed so a sync problem can never block a save, a login or startup.</remarks>
internal sealed class LoginButtonManager : IHostedService
{
    private const string BrandingConfigKey = "branding";

    private readonly IServerConfigurationManager _serverConfigurationManager;
    private readonly ILogger<LoginButtonManager> _logger;
    private EventHandler<BasePluginConfiguration>? _handler;

    /// <summary>
    /// Initializes a new instance of the <see cref="LoginButtonManager"/> class.
    /// </summary>
    /// <param name="serverConfigurationManager">The server configuration manager (owns the branding config).</param>
    /// <param name="logger">The logger.</param>
    public LoginButtonManager(IServerConfigurationManager serverConfigurationManager, ILogger<LoginButtonManager> logger)
    {
        _serverConfigurationManager = serverConfigurationManager ?? throw new ArgumentNullException(nameof(serverConfigurationManager));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Subscribes to configuration changes and runs an initial sync at host start.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token (unused; the sync is short and idempotent).</param>
    /// <returns>A completed task.</returns>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var plugin = SSOPlugin.Instance;
        if (plugin is null)
        {
            return Task.CompletedTask;
        }

        _handler = (_, configuration) => Sync(configuration as PluginConfiguration);
        plugin.ConfigurationChanged += _handler;

        // Initial reconciliation at startup: read once under the config lock (no save is in progress here, so
        // there is no reentrancy) so a disclaimer left stale by an out-of-band config.xml edit is corrected.
        try
        {
            Sync(plugin.ReadConfiguration(configuration => configuration));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Initial login-page button sync at startup failed; skipping.");
        }

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

    private void Sync(PluginConfiguration? configuration)
    {
        if (configuration is null)
        {
            return;
        }

        try
        {
            var block = LoginButtonInjector.BuildBlock(LoginButtonBuilder.Build(configuration));

            var branding = (BrandingOptions)_serverConfigurationManager.GetConfiguration(BrandingConfigKey);
            var current = branding.LoginDisclaimer;
            var merged = LoginButtonInjector.Merge(current, block);

            // Guard the write: an unrelated config change (or a login's canonical-link write) whose button set
            // is unchanged leaves the disclaimer identical, so no branding save happens.
            if (!string.Equals(current ?? string.Empty, merged, StringComparison.Ordinal))
            {
                branding.LoginDisclaimer = merged;
                _serverConfigurationManager.SaveConfiguration(BrandingConfigKey, branding);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to sync the managed login-page buttons into the branding login disclaimer.");
        }
    }
}
