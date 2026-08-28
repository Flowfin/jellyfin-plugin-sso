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

/// <summary>
/// Drives <see cref="PasswordlessLinkedAccountSweep"/> once at host start (#1440), so a server upgrading
/// from a plugin version that provisioned accounts without a password stops offering those accounts to the
/// ordinary login form.
/// </summary>
/// <remarks>
/// <para>
/// A one-shot <see cref="IHostedService"/> rather than a timer, matching
/// <see cref="SsoOnlyReconciliationService"/>: what it repairs is a state a PAST plugin version wrote, and
/// nothing running today can create another one. The pass is idempotent, so needing it to run at every boot
/// rather than exactly once buys correctness without a persisted flag - and a boot is also the one moment a
/// restored backup from an old server is guaranteed to pass through.
/// </para>
/// <para>
/// Fail-safe: any error is logged and swallowed. Sealing an old account is a repair, and a repair that can
/// stop the server from starting is worse than the hole it closes; the disclosure in the log is what tells
/// an operator the door is still open.
/// </para>
/// </remarks>
internal sealed class PasswordlessLinkedAccountSweepService : IHostedService
{
    private readonly IUserManager _userManager;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly ILogger<PasswordlessLinkedAccountSweepService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordlessLinkedAccountSweepService"/> class.
    /// </summary>
    /// <param name="userManager">The Jellyfin user manager, resolved from the host DI container.</param>
    /// <param name="cryptoProvider">The Jellyfin crypto provider that hashes the password the sweep mints.</param>
    /// <param name="logger">The logger.</param>
    public PasswordlessLinkedAccountSweepService(IUserManager userManager, ICryptoProvider cryptoProvider, ILogger<PasswordlessLinkedAccountSweepService> logger)
    {
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Runs the one-shot sweep at host start.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token (unused; the pass is a bounded walk over the persisted link maps).</param>
    /// <returns>A task that completes when the pass has finished.</returns>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var plugin = SSOPlugin.Instance;
        if (plugin is null)
        {
            // The plugin is constructed during plugin load, before host services start, so this is normally
            // set. Without it there are no links to read and therefore no account to name - skip rather
            // than throw.
            return;
        }

        try
        {
            var canonicalLinks = new CanonicalLinkService(_userManager, _cryptoProvider, plugin.ConfigStore, _logger);
            await new PasswordlessLinkedAccountSweep(canonicalLinks, _userManager, _cryptoProvider, _logger).SweepAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Disclosed rather than swallowed silently: an operator reading this line knows the
            // empty-password door may still be open on accounts an old version provisioned, and that the
            // repair is to set a password on them by hand.
            _logger.LogError(ex, "The startup sweep for password-less SSO-linked accounts failed; skipping. Accounts provisioned by an old plugin version may still accept an empty password on the ordinary login form.");
        }
    }

    /// <summary>
    /// No-op on shutdown.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A completed task.</returns>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
