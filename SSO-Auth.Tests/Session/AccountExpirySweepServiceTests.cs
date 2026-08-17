// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Cryptography;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The timer around the account-expiry sweep (#1145). What is worth pinning here is not the cadence but the
/// two ways this component can hurt a server it is supposed to be quietly protecting: by refusing to shut
/// down, and by ending its own loop over one bad pass.
/// </summary>
public class AccountExpirySweepServiceTests
{
    [Fact]
    public async Task StartThenStop_CompletesRatherThanHangingOnTheTimer()
    {
        // A hosted service whose StopAsync waits on a period-long timer holds up every server shutdown for
        // as long as that period. Cancellation of the wait is a shutdown rather than an error, so the loop
        // has to read it as "stop" instead of letting it escape.
        var service = Build();

        await service.StartAsync(CancellationToken.None);
        await service.StopAsync(CancellationToken.None);

        service.Dispose();
    }

    [Fact]
    public async Task StopWithoutStart_IsANoOp()
    {
        // The host can stop a service it never started when an earlier one fails to start. Nothing to wait
        // on must not become a null dereference at exactly the moment start-up is already going badly.
        var service = Build();

        await service.StopAsync(CancellationToken.None);

        service.Dispose();
    }

    [Fact]
    public async Task ATickWithNoPluginInstance_DoesNothingAndThrowsNothing()
    {
        // With no plugin there is no configuration to sweep and therefore no deadline to read. The tick
        // returns rather than throwing: an exception here would be logged once an hour, forever, on a server
        // where nothing is wrong.
        var service = Build();

        await service.TickAsync();

        service.Dispose();
    }

    // The logger is the repo's own typed wrapper rather than a substitute: the service is internal, so a
    // dynamic proxy over ILogger<AccountExpirySweepService> cannot be generated for it.
    private static AccountExpirySweepService Build() =>
        new AccountExpirySweepService(
            Substitute.For<IUserManager>(),
            Substitute.For<ISessionManager>(),
            Substitute.For<ICryptoProvider>(),
            new TypedLogger<AccountExpirySweepService>(new CapturingLogger()));
}
