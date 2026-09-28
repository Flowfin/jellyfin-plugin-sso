// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

// The following code is a derivative work of the code from the Jellyfin project,
// which is licensed GPLv2. This code therefore is also licensed under the terms
// of the GNU Public License, verison 2.
// https://github.com/jellyfin/jellyfin/blob/a60cb280a3d31ba19ffb3a94cf83ef300a7473b7/Jellyfin.Api/Helpers/RequestHelpers.cs#L63-L77

// Use of this relatively small snippet complies with fair use
// See https://www.gnu.org/licenses/gpl-faq.en.html#SourceCodeInDocumentation
// These helpers were not published within a Nuget package, so it was neccessary to re-implement.

using System;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using MediaBrowser.Controller.Net;
using Microsoft.AspNetCore.Http;

namespace Jellyfin.Plugin.SSO_Auth.Api.Http;

/// <summary>
/// Request Extensions. Internal like the rest of the helper surface - its only member is internal, so
/// nothing public was ever exposed either way (#671).
/// </summary>
internal static class RequestHelpers
{
    /// <summary>
    /// Checks if the user can update an entry.
    /// </summary>
    /// <param name="authContext">Instance of the <see cref="IAuthorizationContext"/> interface.</param>
    /// <param name="requestContext">The <see cref="HttpRequest"/>.</param>
    /// <param name="userId">The user id.</param>
    /// <returns>A <see cref="bool"/> whether the user can update the entry.</returns>
    internal static async Task<bool> AssertCanUpdateUser(IAuthorizationContext authContext, HttpRequest requestContext, Guid userId)
    {
        if (authContext is null)
        {
            return false;
        }

        var auth = await authContext.GetAuthorizationInfo(requestContext).ConfigureAwait(false);

        // Fail closed on an unresolved caller: a null authorization result or unauthenticated request
        // is an explicit deny, not a NullReferenceException that would surface as a 500. Every real
        // caller sits behind [Authorize], so this only guards the ambiguous/misconfigured case.
        if (auth?.User is not { } authenticatedUser)
        {
            return false;
        }

        // Updating the record of another user requires an administrator; every caller edits user
        // preferences, so the upstream restrictUserPreferences flag is folded in as always-on here.
        return (userId.Equals(auth.UserId) || authenticatedUser.HasPermission(PermissionKind.IsAdministrator))
            && authenticatedUser.EnableUserPreferenceAccess;
    }

    /// <summary>
    /// Whether the caller behind the request is an administrator, read from the resolved account and never
    /// from anything the request asserts about itself (#1647). Fail-closed on an unresolved caller, for the
    /// same reason <see cref="AssertCanUpdateUser"/> is: the answer gates a removal a non-administrator may
    /// not make, so an ambiguous caller is not one.
    /// </summary>
    /// <param name="authContext">Instance of the <see cref="IAuthorizationContext"/> interface.</param>
    /// <param name="requestContext">The <see cref="HttpRequest"/>.</param>
    /// <returns>A <see cref="bool"/> whether the caller holds <see cref="PermissionKind.IsAdministrator"/>.</returns>
    internal static async Task<bool> IsAdministrator(IAuthorizationContext authContext, HttpRequest requestContext)
    {
        if (authContext is null)
        {
            return false;
        }

        var auth = await authContext.GetAuthorizationInfo(requestContext).ConfigureAwait(false);
        return auth?.User is { } authenticatedUser && authenticatedUser.HasPermission(PermissionKind.IsAdministrator);
    }

    /// <summary>Whether the caller behind the request is the account being acted on (#1732), read from the resolved caller and never from the route value alone.</summary>
    /// <remarks>It separates an administrator tidying somebody else's link from one removing their own, and fails closed on an unresolved caller because the answer narrows an exemption. An API key is not the holder of any account and not an unresolved caller either (#1741): the host admits it with no user behind it, and reading it as unresolved refused the documented automation path.</remarks>
    /// <param name="authContext">Instance of the <see cref="IAuthorizationContext"/> interface.</param>
    /// <param name="requestContext">The <see cref="HttpRequest"/>.</param>
    /// <param name="userId">The account the request acts on.</param>
    /// <returns>True when the resolved caller is that account, or when the caller cannot be resolved; false for an API key.</returns>
    internal static async Task<bool> CallerIsTheHolder(IAuthorizationContext authContext, HttpRequest requestContext, Guid userId)
    {
        if (authContext is null)
        {
            return true;
        }

        var auth = await authContext.GetAuthorizationInfo(requestContext).ConfigureAwait(false);
        if (auth is { IsApiKey: true })
        {
            return false;
        }

        return auth?.User is not { } authenticatedUser || authenticatedUser.Id.Equals(userId);
    }

    /// <summary>Whether the caller behind the request has no password to sign in with (#1720, #1733): it asks for the positive evidence, an account on Jellyfin's built-in password provider holding a password this plugin did not mint, and answers true for everything else.</summary>
    /// <remarks>
    /// The test is for the one provider that definitely takes a password, because an id naming no registered
    /// provider refuses every password too; an account on a third-party password provider is refused although its
    /// password works, a refusal rather than a lockout, and an account sealed by a version that kept no record reads as having a door.
    /// </remarks>
    /// <param name="authContext">Instance of the <see cref="IAuthorizationContext"/> interface.</param>
    /// <param name="requestContext">The <see cref="HttpRequest"/>.</param>
    /// <param name="holdsOnlyAMintedPassword">Reads the minted-password record for a resolved account (#1733); passed in so this helper stays a reading of the request and a test can hand it either answer.</param>
    /// <returns>True when the caller's account accepts no password, or when the caller cannot be resolved.</returns>
    internal static async Task<bool> CallerHasNoPasswordDoor(IAuthorizationContext authContext, HttpRequest requestContext, Func<User, bool> holdsOnlyAMintedPassword)
    {
        // A missing detector is a wiring fault rather than an ambiguous caller, and it is refused here
        // rather than defaulted either way: defaulting to false would silently restore the #1733 gap on
        // every server, and defaulting to true would refuse every self-unlink on the planet.
        ArgumentNullException.ThrowIfNull(holdsOnlyAMintedPassword);

        if (authContext is null)
        {
            return true;
        }

        var auth = await authContext.GetAuthorizationInfo(requestContext).ConfigureAwait(false);
        return auth?.User is not { } authenticatedUser
            || !SsoAuthenticationProviders.IsDefaultPasswordProvider(authenticatedUser.AuthenticationProviderId)
            || holdsOnlyAMintedPassword(authenticatedUser);
    }
}
