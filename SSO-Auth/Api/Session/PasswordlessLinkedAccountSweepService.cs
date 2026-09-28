// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Cryptography;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Session;

/// <summary>Drives <see cref="PasswordlessLinkedAccountSweep"/> once at host start (#1440).</summary>
/// <remarks>A one-shot service like <see cref="SsoOnlyReconciliationService"/>, and fail-safe: a repair must not stop the server from starting.</remarks>
internal sealed class PasswordlessLinkedAccountSweepService : IHostedService
{
    private readonly IUserManager _userManager;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly ILogger<PasswordlessLinkedAccountSweepService> _logger;

    /// <summary>Initializes a new instance of the <see cref="PasswordlessLinkedAccountSweepService"/> class.</summary>
    /// <param name="userManager">The Jellyfin user manager, resolved from the host DI container.</param>
    /// <param name="cryptoProvider">The Jellyfin crypto provider that hashes the password the sweep mints.</param>
    /// <param name="logger">The logger.</param>
    public PasswordlessLinkedAccountSweepService(IUserManager userManager, ICryptoProvider cryptoProvider, ILogger<PasswordlessLinkedAccountSweepService> logger)
    {
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>Runs the one-shot sweep at host start.</summary>
    /// <param name="cancellationToken">A cancellation token, unused because the pass is a bounded walk.</param>
    /// <returns>A task that completes when the pass has finished.</returns>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var plugin = SSOPlugin.Instance;
        if (plugin is null)
        {
            // Without the plugin there are no links to read.
            return;
        }

        try
        {
            var canonicalLinks = new CanonicalLinkService(_userManager, _cryptoProvider, plugin.ConfigStore, _logger);
            await new PasswordlessLinkedAccountSweep(canonicalLinks, _userManager, _cryptoProvider, _logger).SweepAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Disclosed, so an operator knows the door may still be open and the repair is a password set by hand.
            _logger.LogError(ex, "The startup sweep for password-less SSO-linked accounts failed; skipping. Accounts provisioned by an old plugin version may still accept an empty password on the ordinary login form.");
        }
    }

    /// <summary>No-op on shutdown.</summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A completed task.</returns>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
