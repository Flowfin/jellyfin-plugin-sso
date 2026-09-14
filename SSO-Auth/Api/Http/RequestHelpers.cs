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

    /// <summary>
    /// Whether the caller behind the request has no password to sign in with, read from the resolved
    /// account's authentication provider (#1720). It asks for the POSITIVE evidence - the account routes
    /// to Jellyfin's built-in password provider - and answers true for everything else.
    /// </summary>
    /// <remarks>
    /// THE CALLER'S OWN ACCOUNT IS THE SUBJECT, and on the route that reads this it is also the account
    /// being changed: <see cref="AssertCanUpdateUser"/> admits a non-administrator only for their own
    /// user id, and an administrator is exempt from the rule this answers. Reading the caller rather than
    /// looking the target id up again means there is no unresolved-account case to decide - the caller is
    /// resolved or the request was already refused.
    /// <para>
    /// THE TEST IS FOR THE ONE PROVIDER THAT DEFINITELY TAKES A PASSWORD, NOT AGAINST THE ONE THAT
    /// DEFINITELY DOES NOT, and the difference is the whole reach of this rule. Asking whether the id
    /// equals this plugin's would answer "has a password" for every OTHER id as well - and an id naming
    /// no registered provider is exactly the state that refuses every password, which core substitutes
    /// its <c>InvalidAuthenticationProvider</c> for. A provider's free-text <c>DefaultProvider</c> is
    /// written verbatim onto the account at every login, so a typo, a plugin somebody uninstalled, or any
    /// hand-set value produces that state without anybody choosing it.
    /// </para>
    /// <para>
    /// WHAT IT COSTS IS A REFUSAL AND NOT A LOCKOUT, stated rather than hidden: an account routed to a
    /// THIRD-PARTY password provider - an LDAP plugin, say - reads here as having no password door and
    /// has its last-link self-unlink refused although its password works. The way out is one call (link
    /// another provider first, or ask an administrator), and the refusal says so. The other direction
    /// costs the account.
    /// </para>
    /// <para>
    /// WHAT IT STILL CANNOT SEE is the account ON the password provider whose password nobody holds, and
    /// that gap is a real one rather than a technicality. This plugin mints an unguessable password onto
    /// every account it provisions and never records which, so a stored hash is a credential somebody has
    /// or a seal nobody can open and the two are the same bytes. Where a provider's <c>DefaultProvider</c>
    /// names the built-in password provider - which the settings page offers as a common choice - every
    /// account it provisions lands in exactly that state, and this reading answers "has a door" for all
    /// of them, so the rule above does not reach them at all.
    /// <para>
    /// THE NEIGHBOURING GUARD DECIDED THE SAME AMBIGUITY THE OTHER WAY and is not precedent for this one.
    /// The administrator-stranding guard in <c>CanonicalLinkService</c> refuses to count a stored password
    /// as a way in at all, and says why in its own words. It can afford that because its subject is a
    /// mass action an administrator takes, where a refusal costs one call; this rule sits on the only
    /// control a user has over their own links, where the same reading would refuse every last-link
    /// self-unlink on every server. Which of the two this rule should follow is a decision rather than a
    /// reading, and it is #1733.
    /// </para>
    /// </para>
    /// <para>
    /// Fail-closed on an unresolved caller, for the same reason <see cref="IsAdministrator"/> is: the
    /// answer gates a removal that can leave an account unreachable, and an ambiguous caller is treated
    /// as the case that costs the account rather than the one that costs a call.
    /// </para>
    /// </remarks>
    /// <param name="authContext">Instance of the <see cref="IAuthorizationContext"/> interface.</param>
    /// <param name="requestContext">The <see cref="HttpRequest"/>.</param>
    /// <returns>True when the caller's account accepts no password, or when the caller cannot be resolved.</returns>
    internal static async Task<bool> CallerHasNoPasswordDoor(IAuthorizationContext authContext, HttpRequest requestContext)
    {
        if (authContext is null)
        {
            return true;
        }

        var auth = await authContext.GetAuthorizationInfo(requestContext).ConfigureAwait(false);
        return auth?.User is not { } authenticatedUser
            || !SsoAuthenticationProviders.IsDefaultPasswordProvider(authenticatedUser.AuthenticationProviderId);
    }
}
