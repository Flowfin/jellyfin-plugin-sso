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

/// <summary>
/// Drives <see cref="AccountExpirySweep"/> on a timer for as long as the server runs (#1145). An
/// <see cref="IHostedService"/> rather than an <c>IScheduledTask</c>, matching the plugin's two existing
/// background components (<see cref="SsoOnlyReconciliationService"/> and the login-button manager) - the
/// plugin has no scheduled task and this is not the change that introduces one.
/// <para>
/// Fail-safe throughout: a tick that throws is logged and swallowed, and the loop keeps its cadence, because
/// an expiry sweep is enforcement of a deadline that has already passed and must never be able to take the
/// server down or stop itself permanently over one bad pass.
/// </para>
/// </summary>
internal sealed class AccountExpirySweepService : IHostedService, IDisposable
{
    // Hourly. The deadline it enforces is an account-lifetime instant configured by an administrator, so the
    // meaningful resolution is hours rather than seconds, and the login path already covers the case where
    // the expired user comes back before the next tick. A shorter period would buy nothing an operator can
    // perceive and would walk the config maps sixty times as often.
    private static readonly TimeSpan Period = TimeSpan.FromHours(1);

    private readonly IUserManager _userManager;
    private readonly ISessionManager _sessionManager;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly ILogger<AccountExpirySweepService> _logger;
    private readonly CancellationTokenSource _stopping = new();
    private Task? _loop;

    /// <summary>
    /// Initializes a new instance of the <see cref="AccountExpirySweepService"/> class.
    /// </summary>
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

    /// <summary>
    /// Starts the periodic sweep. Returns as soon as the loop is running; the first tick fires after one
    /// period rather than at boot, so a restart cannot add a sweep to whatever else start-up is doing.
    /// </summary>
    /// <param name="cancellationToken">The host's start token.</param>
    /// <returns>A completed task.</returns>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        _loop = RunAsync(_stopping.Token);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Signals the loop to stop and waits for the in-flight tick to finish.
    /// </summary>
    /// <param name="cancellationToken">The host's shutdown token, which bounds the wait.</param>
    /// <returns>A task that completes when the loop has stopped.</returns>
    public async Task StopAsync(CancellationToken cancellationToken)
    {
        await _stopping.CancelAsync().ConfigureAwait(false);
        if (_loop is { } loop)
        {
            // Never let shutdown hang on the sweep: the host's own token bounds the wait, and the tick is
            // idempotent, so a pass abandoned here is simply redone after the next start.
            await loop.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <inheritdoc />
    public void Dispose() => _stopping.Dispose();

    /// <summary>
    /// One tick, separated from the loop so the suite can run it without waiting out a period.
    /// </summary>
    /// <remarks>
    /// Nothing is reported here on success. Every account the pass disables already writes its own
    /// <c>[SSO Audit]</c> line, and a second count line beside them would say nothing an operator cannot
    /// read off those.
    /// </remarks>
    /// <returns>A task that completes when the pass has finished or has been logged as failed.</returns>
    internal async Task TickAsync()
    {
        // No configuration to sweep. Skip this tick rather than throw; the plugin is constructed during
        // plugin load, so this is normally set well before the first period elapses.
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
            // Fail-safe: one bad pass must not end the loop. The next tick retries from the persisted state,
            // and the deadlines it enforces are still on disk.
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

    // The cancellation of a PeriodicTimer surfaces as an exception rather than as a false, and a shutdown is
    // not an error; this turns it back into the loop-ending false the caller reads.
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
