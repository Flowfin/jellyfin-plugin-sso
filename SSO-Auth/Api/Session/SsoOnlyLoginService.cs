// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Session;

/// <summary>The outcome of an SSO-only activation attempt: the guard verdict and, on success, how many accounts the sweep repointed.</summary>
/// <param name="Verdict">The guard verdict.</param>
/// <param name="RepointedCount">Accounts repointed to the SSO provider on a successful activation; zero on every refusal.</param>
/// <param name="BreakGlassAdmin">The account's own canonical username on success, for the audit line; null on refusal.</param>
internal readonly record struct SsoOnlyEnableOutcome(SsoOnlyGuardVerdict Verdict, int RepointedCount, string? BreakGlassAdmin);

/// <summary>The login-path re-assertion for a resolved account: the provider id the mint persists, and whether the account is the break-glass admin under an active mode (#165).</summary>
/// <param name="DefaultProvider">The provider id to persist, or the configured default when the mode is off.</param>
/// <param name="IsBreakGlassAdmin">True only when the account is the break-glass admin and the mode is on, so the mint keeps its recovery state.</param>
internal readonly record struct SsoOnlyLoginDecision(string? DefaultProvider, bool IsBreakGlassAdmin);

/// <summary>The per-user enforcement of SSO-only login: the last-admin guard, the sweep off the password provider, and its lossless reversal (#165).</summary>
/// <remarks>
/// Each account's provider id is the only lever Jellyfin offers; only routing is ever written, never a password hash
/// or a permission. See <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/SSO-Only-Login-Design"/>.
/// </remarks>
internal sealed class SsoOnlyLoginService
{
    private readonly IUserManager _userManager;
    private readonly ProviderConfigStore _configStore;
    private readonly ILogger _logger;

    /// <summary>Initializes a new instance of the <see cref="SsoOnlyLoginService"/> class.</summary>
    /// <param name="userManager">The Jellyfin user manager used to enumerate and re-route accounts.</param>
    /// <param name="configStore">The provider configuration store owning the SSO-only mode flags and their lock.</param>
    /// <param name="logger">The logger.</param>
    internal SsoOnlyLoginService(IUserManager userManager, ProviderConfigStore configStore, ILogger logger)
    {
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        _configStore = configStore ?? throw new ArgumentNullException(nameof(configStore));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>Resolves an account by username into the <see cref="BreakGlassAdminState"/> the guard consumes; a missing account fails closed.</summary>
    /// <remarks>A password this plugin minted is not a door (#1746); an account sealed by a version that kept no record still reads as holding one.</remarks>
    /// <param name="username">The candidate break-glass admin username.</param>
    /// <returns>The resolved login state.</returns>
    internal BreakGlassAdminState DescribeBreakGlass(string? username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return default;
        }

        var user = _userManager.GetUserByName(username);
        if (user is null)
        {
            return default;
        }

        // The minted-password read is last, so an account failing the free tests never pays the login path's lock.
        var usablePasswordLogin = SsoAuthenticationProviders.IsDefaultPasswordProvider(user.AuthenticationProviderId)
            && !string.IsNullOrEmpty(user.Password)
            && !_configStore.Read(configuration => ProvisionedPassword.IsTheOnlyPassword(configuration, user));

        return new BreakGlassAdminState(
            Exists: true,
            IsAdministrator: user.HasPermission(PermissionKind.IsAdministrator),
            IsEnabled: !user.HasPermission(PermissionKind.IsDisabled),
            HasUsablePasswordLogin: usablePasswordLogin);
    }

    /// <summary>Resolves the named accounts into what the tree can read about their ways in, for the bulk unlink's mass-lockout guard (#1519).</summary>
    /// <remarks>Every account is resolved before the lock and judged in one acquisition; an id that resolves to nothing is reported as disabled rather than dropped.</remarks>
    /// <param name="userIds">The accounts to resolve, as the link-table snapshot named them.</param>
    /// <returns>One entry per requested id, in the order asked.</returns>
    internal IReadOnlyList<AccountDoors> DescribeAccountDoors(IReadOnlyList<Guid> userIds)
    {
        ArgumentNullException.ThrowIfNull(userIds);

        // The id travels with its account, so an unresolvable id still knows which one it was under the lock.
        var resolved = new List<(Guid Id, User? User)>(userIds.Count);
        foreach (var userId in userIds)
        {
            resolved.Add((userId, _userManager.GetUserById(userId)));
        }

        return _configStore.Read(configuration =>
        {
            var doors = new List<AccountDoors>(resolved.Count);
            foreach (var (userId, user) in resolved)
            {
                doors.Add(user is null
                    ? new AccountDoors(userId, string.Empty, IsAdministrator: false, IsDisabled: true, RoutesToPasswordProvider: false, HoldsAPasswordSomebodySet: false)
                    : Describe(configuration, user));
            }

            return (IReadOnlyList<AccountDoors>)doors;
        });
    }

    /// <summary>Resolves every enabled administrator except one into what the tree can read about their ways in, for the self-unlink guard (#1732).</summary>
    /// <remarks>Derived from the accounts rather than a link table, because an administrator with no link is exactly the answer that matters; a cold walk the caller gates.</remarks>
    /// <param name="excluded">The caller, whose own ways in are not what this question is about.</param>
    /// <returns>One entry per other enabled administrator; empty where there is none.</returns>
    /// <exception cref="InvalidOperationException">The loaded Jellyfin build exposes no all-users accessor, which the caller treats as nobody being left.</exception>
    internal IReadOnlyList<AccountDoors> DescribeAdministratorsOtherThan(Guid excluded)
    {
        // The walk stays outside the lock and the judging goes inside it, once for the whole set.
        var administrators = AllUsers()
            .Where(user => user.Id != excluded
                && user.HasPermission(PermissionKind.IsAdministrator)
                && !user.HasPermission(PermissionKind.IsDisabled))
            .ToList();

        return _configStore.Read(configuration =>
            (IReadOnlyList<AccountDoors>)administrators.Select(user => Describe(configuration, user)).ToList());
    }

    // One home for what a password door is, so the two callers cannot drift apart; the facts stay apart and the caller ANDs them (#1746).
    private static AccountDoors Describe(PluginConfiguration configuration, User user) =>
        new(
            user.Id,
            user.Username,
            user.HasPermission(PermissionKind.IsAdministrator),
            user.HasPermission(PermissionKind.IsDisabled),
            SsoAuthenticationProviders.IsDefaultPasswordProvider(user.AuthenticationProviderId),
            !string.IsNullOrEmpty(user.Password) && !ProvisionedPassword.IsTheOnlyPassword(configuration, user));

    /// <summary>Re-asserts SSO-only enforcement for a resolved login, judged on the resolved account so the login path and the sweep agree (#165, #690).</summary>
    /// <remarks>A non-exempt account still on the password provider is tracked before the mint repoints it, so the off-switch restores exactly what the mode moved.</remarks>
    /// <param name="userId">The Jellyfin user id the login resolved to.</param>
    /// <param name="configuredDefaultProvider">The provider config's own <c>DefaultProvider</c>, used unchanged while the mode is off.</param>
    /// <returns>The provider id to persist and whether this is the break-glass admin under an active mode.</returns>
    internal SsoOnlyLoginDecision ResolveLoginEnforcement(Guid userId, string? configuredDefaultProvider)
    {
        // One locked read for the common paths, so only a first-time repoint pays a persist.
        var (decision, shouldTrack) = _configStore.Read(configuration =>
        {
            var resolved = _userManager.GetUserById(userId);
            if (resolved is null)
            {
                // Deleted since resolution; the mint fails closed on the null user.
                return (new SsoOnlyLoginDecision(configuredDefaultProvider, false), false);
            }

            var provider = SsoOnlyLoginGuard.ResolveLoginProvider(configuration, resolved.Username, resolved.AuthenticationProviderId, configuredDefaultProvider);
            var modeOn = configuration is { DisablePasswordLogin: true };
            var isBreakGlass = modeOn && SsoOnlyLoginGuard.IsBreakGlass(configuration, resolved.Username);

            // Tracked only when this login moves the account off the password provider, and never twice.
            var track = modeOn
                && !isBreakGlass
                && SsoAuthenticationProviders.IsDefaultPasswordProvider(resolved.AuthenticationProviderId)
                && !configuration.SsoOnlyRepointedUserIds.Contains(userId);

            return (new SsoOnlyLoginDecision(provider, isBreakGlass), track);
        });

        if (shouldTrack)
        {
            // Tracked before the mint repoints, so a crash leaves tracked-but-not-moved, which the restore no-ops; a Disable racing the mint is an accepted residual on one non-break-glass account.
            _configStore.Mutate(configuration =>
            {
                if (!configuration.SsoOnlyRepointedUserIds.Contains(userId))
                {
                    configuration.SsoOnlyRepointedUserIds.Add(userId);
                }
            });
        }

        return decision;
    }

    /// <summary>Turns SSO-only login on with the given break-glass admin; the guard runs first and a refusal persists nothing.</summary>
    /// <param name="breakGlassUsername">The account to designate as the always-password-capable break-glass admin.</param>
    /// <returns>The guard verdict and, on success, the number of accounts repointed.</returns>
    internal async Task<SsoOnlyEnableOutcome> TryEnableAsync(string breakGlassUsername)
    {
        var resolved = _userManager.GetUserByName(breakGlassUsername);
        var verdict = SsoOnlyLoginGuard.Evaluate(breakGlassUsername, DescribeBreakGlass(breakGlassUsername));
        if (verdict != SsoOnlyGuardVerdict.Allow)
        {
            return new SsoOnlyEnableOutcome(verdict, 0, null);
        }

        // The account's own casing, so the exempt check and the audit line are unambiguous; the guard proved it exists.
        var canonicalUsername = resolved!.Username;
        _configStore.Mutate(configuration =>
        {
            configuration.DisablePasswordLogin = true;
            configuration.BreakGlassAdminUsername = canonicalUsername;
        });

        int repointed;
        try
        {
            repointed = await SweepEnableAsync(canonicalUsername).ConfigureAwait(false);
        }
        catch
        {
            // The mode is never left recorded on with enforcement unapplied; a partial sweep is tracked and restored at boot.
            _configStore.Mutate(configuration => configuration.DisablePasswordLogin = false);
            throw;
        }

        return new SsoOnlyEnableOutcome(SsoOnlyGuardVerdict.Allow, repointed, canonicalUsername);
    }

    /// <summary>Re-designates the break-glass admin; the new target must itself satisfy the guard, so the exemption can never grant admin.</summary>
    /// <remarks>While the mode is on no other account holds a usable password, so the designation is changed with the mode off.</remarks>
    /// <param name="breakGlassUsername">The new break-glass admin username.</param>
    /// <returns>The guard verdict and the account's canonical username on success.</returns>
    internal SsoOnlyEnableOutcome TryDesignateBreakGlass(string breakGlassUsername)
    {
        var resolved = _userManager.GetUserByName(breakGlassUsername);
        var verdict = SsoOnlyLoginGuard.Evaluate(breakGlassUsername, DescribeBreakGlass(breakGlassUsername));
        if (verdict != SsoOnlyGuardVerdict.Allow)
        {
            return new SsoOnlyEnableOutcome(verdict, 0, null);
        }

        var canonicalUsername = resolved!.Username;
        _configStore.Mutate(configuration => configuration.BreakGlassAdminUsername = canonicalUsername);
        return new SsoOnlyEnableOutcome(SsoOnlyGuardVerdict.Allow, 0, canonicalUsername);
    }

    /// <summary>Turns SSO-only login off and restores password routing for every account the mode repointed, and nothing else.</summary>
    /// <returns>The number of accounts whose provider routing was restored.</returns>
    internal async Task<int> DisableAsync()
    {
        _configStore.Mutate(configuration => configuration.DisablePasswordLogin = false);
        return await RestoreRepointedAccountsAsync().ConfigureAwait(false);
    }

    /// <summary>Boot-time reconciliation of the user database to the flag, which is what makes the total-lockout recovery through the config file work (#165).</summary>
    /// <returns>The number of accounts restored.</returns>
    internal async Task<int> ReconcileOnStartupAsync()
    {
        var (modeOn, trackedCount) = _configStore.Read(
            configuration => (configuration.DisablePasswordLogin, configuration.SsoOnlyRepointedUserIds.Count));
        if (modeOn || trackedCount == 0)
        {
            return 0;
        }

        return await RestoreRepointedAccountsAsync().ConfigureAwait(false);
    }

    // Each account is tracked before it is repointed, so the persisted set is always a superset of the accounts moved.
    private async Task<int> SweepEnableAsync(string breakGlassUsername)
    {
        var repointed = 0;
        foreach (var user in AllUsers())
        {
            if (IsBreakGlass(user.Username, breakGlassUsername))
            {
                continue;
            }

            if (!SsoAuthenticationProviders.IsDefaultPasswordProvider(user.AuthenticationProviderId))
            {
                continue;
            }

            var id = user.Id;
            _configStore.Mutate(configuration =>
            {
                if (!configuration.SsoOnlyRepointedUserIds.Contains(id))
                {
                    configuration.SsoOnlyRepointedUserIds.Add(id);
                }
            });

            user.AuthenticationProviderId = SsoAuthenticationProviders.SsoProviderId;
            await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
            repointed++;
        }

        return repointed;
    }

    // The all-users accessor differs across the supported Jellyfin range, so it is bound at runtime on this cold path (#142).
    private IEnumerable<User> AllUsers()
    {
        var manager = (object)_userManager;
        var type = manager.GetType();

        var accessor = type.GetMethod("GetUsers", Type.EmptyTypes)?.Invoke(manager, null)
            ?? type.GetProperty("Users")?.GetValue(manager);

        // A missing accessor throws rather than reading as an empty server, which would report enable as a success that enforced nothing.
        return accessor as IEnumerable<User>
            ?? throw new InvalidOperationException(
                "IUserManager exposes neither GetUsers() nor a Users property on this Jellyfin build; "
                + "cannot enumerate accounts to enforce SSO-only login.");
    }

    // Scoped to the tracked set, so the plugin's own SSO-created accounts are never handed a password door.
    private async Task<int> RestoreRepointedAccountsAsync()
    {
        var trackedIds = _configStore.Read(configuration => configuration.SsoOnlyRepointedUserIds.ToList());
        int restored = 0;
        foreach (var id in trackedIds)
        {
            var user = _userManager.GetUserById(id);
            if (user is not null && SsoAuthenticationProviders.IsSsoProvider(user.AuthenticationProviderId))
            {
                user.AuthenticationProviderId = SsoAuthenticationProviders.DefaultPasswordProviderId;
                await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
                restored++;
            }
        }

        _configStore.Mutate(configuration => configuration.SsoOnlyRepointedUserIds.Clear());
        return restored;
    }

    private static bool IsBreakGlass(string username, string breakGlassUsername)
        => string.Equals(username, breakGlassUsername, StringComparison.OrdinalIgnoreCase);
}
