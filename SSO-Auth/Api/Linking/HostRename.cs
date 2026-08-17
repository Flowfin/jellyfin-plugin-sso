// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Reflection;
using Jellyfin.Database.Implementations.Entities;
using MediaBrowser.Controller.Library;

namespace Jellyfin.Plugin.SSO_Auth.Api.Linking;

/// <summary>
/// Binds whichever <c>RenameUser</c> the loaded Jellyfin server actually exposes.
/// </summary>
/// <remarks>
/// <para>
/// <c>IUserManager</c>'s rename method diverged inside the supported range, in the same way its all-users
/// accessor did (see <c>SsoOnlyLoginService.AllUsers</c>). Measured against the tags:
/// </para>
/// <code>
/// v10.11.0 .. v10.11.8   Task RenameUser(User user, string newName)
/// v10.11.9 .. v10.11.11  Task RenameUser(Guid userId, string oldName, string newName)
/// </code>
/// <para>
/// v10.11.8 was published on 2026-04-05 and v10.11.9 on 2026-05-21, and the repository declares
/// <c>targetAbi: "10.11.0.0"</c>. So a source reference to either shape breaks one of the two builds: the
/// three-argument form fails the floor build, which is the proof that the shipped artifact would
/// <c>MissingMethod</c> on an early 10.11 server, and the two-argument form fails the shipping build.
/// Binding at runtime is what keeps one binary loadable across all twelve patch releases.
/// </para>
/// <para>
/// THE COST IS NOTHING THAT MATTERS HERE. The lookup runs on a login only when the feature is enabled for
/// that provider AND the presented name differs from the account's, which is once per rename rather than
/// once per login.
/// </para>
/// <para>
/// AND THE FAILURE IS ALREADY BOUNDED. The caller wraps this in a deliberately broad catch that logs and
/// swallows, because a display name that has drifted is cosmetic and refusing a login over it would cost
/// far more than the mismatch. A server exposing neither shape therefore behaves exactly as one where the
/// feature is switched off: the account keeps its name, the login proceeds, and the reason is on the record.
/// </para>
/// </remarks>
internal static class HostRename
{
    /// <summary>The sentence a server exposing neither shape is refused with.</summary>
    /// <remarks>
    /// It names both signatures, because the admin reading it in a log needs to know what their server was
    /// asked for rather than that something reflective did not work.
    /// </remarks>
    internal const string NeitherShape =
        "IUserManager on this Jellyfin build exposes neither RenameUser(Guid, string, string) nor "
        + "RenameUser(User, string), so the linked account cannot be renamed to follow its provider.";

    /// <summary>
    /// Picks the rename method this server exposes and the arguments it takes, or <c>null</c> where it
    /// exposes neither.
    /// </summary>
    /// <remarks>
    /// Separated from the call so that both arms can be proved without a Jellyfin server: a test hands this
    /// a type declaring one shape or the other and reads back which was chosen. The alternative - asserting
    /// through a fake <c>IUserManager</c> - can only ever exercise the shape this assembly compiled against,
    /// which is the one arm that was never in doubt.
    /// </remarks>
    /// <param name="manager">The runtime type of the user manager the host supplied.</param>
    /// <param name="account">The resolved account, for the two-argument shape.</param>
    /// <param name="userId">The resolved account's id, for the three-argument shape.</param>
    /// <param name="currentName">The name the account holds now.</param>
    /// <param name="desiredName">The name the provider presented, already sanitized.</param>
    /// <returns>The method and its arguments, or <c>null</c>.</returns>
    internal static (MethodInfo Method, object?[] Arguments)? Resolve(
        Type manager, User? account, Guid userId, string currentName, string desiredName)
    {
        ArgumentNullException.ThrowIfNull(manager);

        // The current line first, so the common case costs one lookup and the older shape is reached only
        // where the newer one is absent.
        var byIdAndBothNames = manager.GetMethod(
            "RenameUser", new[] { typeof(Guid), typeof(string), typeof(string) });
        if (byIdAndBothNames is not null)
        {
            return (byIdAndBothNames, new object?[] { userId, currentName, desiredName });
        }

        var byUserAndNewName = manager.GetMethod("RenameUser", new[] { typeof(User), typeof(string) });
        if (byUserAndNewName is not null)
        {
            return (byUserAndNewName, new object?[] { account, desiredName });
        }

        return null;
    }
}
