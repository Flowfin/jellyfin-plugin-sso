// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Pins the SSO-only guard on the config-import persistence path (#165, criterion 3 / T-T2): a document
/// asserting <c>DisablePasswordLogin</c> must prove a surviving admin login path or the whole import is
/// rejected fail-closed before anything is merged. The SSO-only globals themselves are instance-local and
/// are never applied by an import (like the rate-limit settings) - import VALIDATES the assertion but does
/// not flip the target's mode; the operator enables it through the elevated SSO-Only endpoints.
/// </summary>
public class SsoOnlyConfigImportTests
{
    private static readonly Guid RootId = Guid.Parse("bbbbbbbb-0000-0000-0000-000000000001");

    private static ConfigExportDocument DocumentAsserting(bool disablePasswordLogin, string? breakGlass)
        => new()
        {
            FormatVersion = ConfigExport.FormatVersion,
            Configuration = new PluginConfiguration
            {
                DisablePasswordLogin = disablePasswordLogin,
                BreakGlassAdminUsername = breakGlass,
            },
        };

    private static BreakGlassAdminState QualifiedAdmin(string name)
        => new(Exists: true, IsAdministrator: true, IsEnabled: true, HasUsablePasswordLogin: true);

    [Fact]
    public void Import_AssertingSsoOnly_WithNoSafeAdmin_IsRejected_AndAppliesNothing()
    {
        // The central lockout-via-import branch: a document turns SSO-only on but no break-glass admin can be
        // proven (the resolver reports no qualifying account), so the whole import throws before merging.
        var target = new PluginConfiguration();
        var document = DocumentAsserting(disablePasswordLogin: true, breakGlass: "ghost");

        var ex = Assert.Throws<ArgumentException>(() => ConfigImport.Apply(target, document, _ => default));

        Assert.StartsWith(SsoOnlyLoginGuard.PublicRefusalMessage, ex.Message, StringComparison.Ordinal);
        Assert.False(target.DisablePasswordLogin);
        Assert.True(string.IsNullOrEmpty(target.BreakGlassAdminUsername));
    }

    [Fact]
    public void Import_AssertingSsoOnly_WithNullResolver_FailsClosed()
    {
        // Belt: no resolver at all cannot be read as "safe" - an unresolved account fails the guard closed.
        var target = new PluginConfiguration();
        var document = DocumentAsserting(disablePasswordLogin: true, breakGlass: "root");

        Assert.Throws<ArgumentException>(() => ConfigImport.Apply(target, document));
        Assert.False(target.DisablePasswordLogin);
    }

    [Fact]
    public void Import_AssertingSsoOnly_WithSafeAdmin_DoesNotThrow_ButStillDoesNotFlipTheMode()
    {
        // Even with a provable safe admin, import validates but does not APPLY the operational mode (it has
        // no IUserManager to run the per-user enforcement sweep) - the target's own state is unchanged.
        var target = new PluginConfiguration();
        var document = DocumentAsserting(disablePasswordLogin: true, breakGlass: "root");

        Assert.Null(Record.Exception(() => ConfigImport.Apply(target, document, QualifiedAdmin)));
        Assert.False(target.DisablePasswordLogin);
    }

    [Fact]
    public void Import_NotAssertingSsoOnly_ImportsNormally()
    {
        // A document that does not turn SSO-only on never trips the guard, regardless of the resolver.
        var target = new PluginConfiguration();
        var document = DocumentAsserting(disablePasswordLogin: false, breakGlass: null);

        Assert.Null(Record.Exception(() => ConfigImport.Apply(target, document, _ => default)));
        Assert.False(target.DisablePasswordLogin);
    }

    [Fact]
    public async Task Import_RunsTheRealResolverInsideTheMutation_AndStillRefusesASealedBreakGlassAccount()
    {
        // THE ONLY READ-INSIDE-A-MUTATION IN THE TREE, and every other case in this file stubs the resolver
        // past it. The controller hands `DescribeBreakGlass` to `Apply` from inside `MutateConfiguration`,
        // and since #1746 that resolver takes the configuration lock itself to ask whether the named
        // account's password is one this plugin minted. The lock is reentrant today, so the nesting is an
        // ordinary call - but a store that ever swapped it for a non-reentrant primitive would hang this
        // route while holding the lock every login takes, and nothing else in the suite drives the real
        // resolver through a real mutation.
        //
        // THE WAIT IS BOUNDED SO THAT REGRESSION ARRIVES AS A RED AND NOT AS A STALLED SUITE. A test that
        // detects a deadlock by deadlocking reports it as the whole in-process run hanging until whatever
        // is above it gives up, which names nothing; the bound turns it into one failing test naming a
        // TimeoutException where an ArgumentException was expected. The budget is far above the work - the
        // same body takes well under a second - so a loaded machine does not turn it into a flake. The
        // mutation runs on another thread on purpose: what is being proved is that ONE thread may re-enter
        // the lock, and a bounded wait is only possible from a thread that is not the one waiting.
        var root = new User("root", "SSO-Auth", "Default") { Id = RootId, Password = "hash-root" };
        root.AuthenticationProviderId = SsoAuthenticationProviders.DefaultPasswordProviderId;
        root.SetPermission(PermissionKind.IsAdministrator, true);

        var live = new PluginConfiguration();
        ProvisionedPassword.Record(live, RootId, root.Password);
        var store = new ProviderConfigStore(() => live, _ => { }, new CapturingLogger());
        var users = Substitute.For<IUserManager>();
        users.GetUserByName("root").Returns(root);
        var service = new SsoOnlyLoginService(users, store, new CapturingLogger());
        var document = DocumentAsserting(disablePasswordLogin: true, breakGlass: "root");

        var exception = await Assert.ThrowsAsync<ArgumentException>(() =>
            Task.Run(
                    () => store.Mutate(configuration => ConfigImport.Apply(configuration, document, service.DescribeBreakGlass)),
                    TestContext.Current.CancellationToken)
                .WaitAsync(TimeSpan.FromSeconds(60), TestContext.Current.CancellationToken));

        Assert.StartsWith(SsoOnlyLoginGuard.PublicRefusalMessage, exception.Message, StringComparison.Ordinal);
        Assert.False(live.DisablePasswordLogin);
    }
}
