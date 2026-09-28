// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Cryptography;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Session;

/// <summary>Drives <see cref="AccountExpirySweep"/> on an hourly timer for as long as the server runs (#1145).</summary>
/// <remarks>A hosted service like the plugin's other background components, and fail-safe: one bad tick never ends the loop.</remarks>
internal sealed class AccountExpirySweepService : IHostedService, IDisposable
{
    // Hours are the meaningful resolution of an account lifetime, and the login path covers an earlier return.
    private static readonly TimeSpan Period = TimeSpan.FromHours(1);

    private readonly IUserManager _userManager;
    private readonly ISessionManager _sessionManager;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly ILogger<AccountExpirySweepService> _logger;
    private readonly CancellationTokenSource _stopping = new();
    private Task? _loop;

    /// <summary>Initializes a new instance of the <see cref="AccountExpirySweepService"/> class.</summary>
    /// <param name="userManager">The Jellyfin user manager, resolved from the host DI container.</param>
    /// <param name="sessionManager">The Jellyfin session manager, used to revoke a disabled account's tokens.</param>
    /// <param name="cryptoProvider">The Jellyfin crypto provider the canonical-link store is built with; the sweep itself mints nothing.</param>
    /// <param name="logger">The logger.</param>
    public AccountExpirySweepService(IUserManager userManager, ISessionManager sessionManager, ICryptoProvider cryptoProvider, ILogger<AccountExpirySweepService> logger)
    {
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        _sessionManager = sessionManager ?? throw new ArgumentNullException(nameof(sessionManager));
        _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>Starts the periodic sweep; the first tick fires after one period rather than at boot.</summary>
    /// <param name="cancellationToken">The host's start token.</param>
    /// <returns>A completed task.</returns>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        _loop = RunAsync(_stopping.Token);
        return Task.CompletedTask;
    }

    /// <summary>Signals the loop to stop and waits for the in-flight tick to finish.</summary>
    /// <param name="cancellationToken">The host's shutdown token, which bounds the wait.</param>
    /// <returns>A task that completes when the loop has stopped.</returns>
    public async Task StopAsync(CancellationToken cancellationToken)
    {
        await _stopping.CancelAsync().ConfigureAwait(false);
        if (_loop is { } loop)
        {
            // The host's token bounds the wait, and an abandoned pass is redone after the next start.
            await loop.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <inheritdoc />
    public void Dispose() => _stopping.Dispose();

    /// <summary>One tick, separated from the loop so the suite can run it without waiting out a period.</summary>
    /// <returns>A task that completes when the pass has finished or has been logged as failed.</returns>
    internal async Task TickAsync()
    {
        if (SSOPlugin.Instance is not { } plugin)
        {
            return;
        }

        try
        {
            var canonicalLinks = new CanonicalLinkService(_userManager, _cryptoProvider, plugin.ConfigStore, _logger);
            await new AccountExpirySweep(canonicalLinks, _sessionManager, _logger).SweepAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Account-expiry sweep tick failed; no account was disabled by it. The next tick retries.");
        }
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(Period);
        while (await SafeWaitAsync(timer, cancellationToken).ConfigureAwait(false))
        {
            await TickAsync().ConfigureAwait(false);
        }
    }

    // A cancelled PeriodicTimer throws, and a shutdown is not an error.
    private static async Task<bool> SafeWaitAsync(PeriodicTimer timer, CancellationToken cancellationToken)
    {
        try
        {
            return await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }
}
