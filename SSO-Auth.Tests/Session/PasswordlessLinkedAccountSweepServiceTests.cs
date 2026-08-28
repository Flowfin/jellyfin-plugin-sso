// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Cryptography;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The host-start wrapper around the password-less account sweep (#1440). What is worth pinning here is not
/// that it sweeps - that is the pass's own suite - but the two ways a start-up repair can hurt a server it
/// exists to protect: by throwing out of start-up, and by dereferencing something that is not there yet.
/// </summary>
public class PasswordlessLinkedAccountSweepServiceTests
{
    [Fact]
    public async Task StartWithNoPluginInstance_DoesNothingAndThrowsNothing()
    {
        // Host services start after plugin load, so the instance is normally set - but a start that throws
        // here takes the whole server down for a repair of accounts an old version created. With no plugin
        // there is no link map to read and therefore no account to name, which is a return rather than an
        // error.
        var service = Build();

        await service.StartAsync(CancellationToken.None);
    }

    [Fact]
    public async Task StopWithoutStart_IsANoOp()
    {
        // The host can stop a service it never started when an earlier one fails to start. Nothing to wait
        // on must not become a null dereference at exactly the moment start-up is already going badly.
        var service = Build();

        await service.StopAsync(CancellationToken.None);
    }

    [Fact]
    public void EveryDependencyIsRequiredAtConstruction()
    {
        // A null here would surface as a NullReferenceException inside a start-up repair, where the stack
        // says nothing about which dependency the composition root failed to supply.
        var users = Substitute.For<IUserManager>();
        var crypto = Substitute.For<ICryptoProvider>();
        var logger = new TypedLogger<PasswordlessLinkedAccountSweepService>(new CapturingLogger());

        Assert.Throws<ArgumentNullException>(() => new PasswordlessLinkedAccountSweepService(null!, crypto, logger));
        Assert.Throws<ArgumentNullException>(() => new PasswordlessLinkedAccountSweepService(users, null!, logger));
        Assert.Throws<ArgumentNullException>(() => new PasswordlessLinkedAccountSweepService(users, crypto, null!));
    }

    // The logger is the repo's own typed wrapper rather than a substitute: the service is internal, so a
    // dynamic proxy over ILogger<PasswordlessLinkedAccountSweepService> cannot be generated for it.
    private static PasswordlessLinkedAccountSweepService Build() =>
        new PasswordlessLinkedAccountSweepService(
            Substitute.For<IUserManager>(),
            Substitute.For<ICryptoProvider>(),
            new TypedLogger<PasswordlessLinkedAccountSweepService>(new CapturingLogger()));
}
