// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Reflection;
using Jellyfin.Database.Implementations.Entities;
using MediaBrowser.Controller.Library;

namespace Jellyfin.Plugin.SSO_Auth.Api.Linking;

/// <summary>Binds whichever <c>RenameUser</c> the loaded Jellyfin server actually exposes.</summary>
/// <remarks>
/// The <c>IUserManager</c> rename method changed shape inside the supported range, from <c>(User, string)</c> up
/// to v10.11.8 to <c>(Guid, string, string)</c> from v10.11.9, so a source reference to either breaks one of the
/// two builds and binding at runtime keeps one binary loadable across the whole line. The lookup runs once per
/// rename rather than per login, and the caller swallows a failure, because a drifted display name is cosmetic.
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

    /// <summary>Picks the rename method this server exposes and the arguments it takes, or <c>null</c> where it exposes neither.</summary>
    /// <remarks>Separated from the call so both arms can be proved without a Jellyfin server; a fake <c>IUserManager</c> can only exercise the shape this assembly compiled against.</remarks>
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
