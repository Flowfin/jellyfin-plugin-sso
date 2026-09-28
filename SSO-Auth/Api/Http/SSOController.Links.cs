// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Mime;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Events;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Metrics;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Api;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Events;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Net;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Http;

/// <summary>The account-link administration endpoints: create, approve, remove, purge and list links.</summary>
public partial class SSOController
{
    /// <summary>
    /// Removes a user from SSO auth and switches it back to another auth provider. Requires administrator privileges.
    /// </summary>
    /// <param name="username">The username to switch to the new provider.</param>
    /// <param name="provider">The new provider to switch to.</param>
    /// <returns>Whether this API endpoint succeeded.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("Unregister/{username}")]
    public async Task<ActionResult> Unregister(string username, [FromBody] string provider)
    {
        // Throttle after the elevation guard, before any work (#516): the [Authorize] filter rejects a
        // non-elevated caller before the body runs, so an unauthorized request is refused (401/403) and never
        // reaches - or is judged by - the limiter (no rate-limit oracle). Once past it, the shared gate caps
        // how fast an authorized admin can drive this heavy revoke, which removes the user's canonical links
        // everywhere, persists a provider switch, and revokes the user's active sessions (#440). Its own
        // "unregister" class carries an independent budget, so it neither starves nor is starved by the
        // link/unlink write surface's "link" bucket (#382) or the anonymous login flows.
        if (RateLimitCheck(SsoRateLimitClass.Unregister) is { } throttled)
        {
            return throttled;
        }

        var user = _userManager.GetUserByName(username);
        if (user is null)
        {
            return NotFound();
        }

        // Whether the caller is revoking their own account and whether anybody would be left (#1741): this route
        // removes every link, repoints the account and ends its sessions in one call, so it takes the self-service
        // unlink's reading (#1732) over the same facts before anything is removed: the caller is the account, it
        // accepts no password, the revoke takes a way in, and no other enabled administrator holds a link that can
        // sign them in. An API key is not the holder; the survey and the removal are two transactions, so the window
        // costs one allowed removal, and a link on a switched-off provider is a way in again once it is switched on.
        var callerIsTheHolder = await RequestHelpers.CallerIsTheHolder(_authContext, HttpContext.Request, user.Id).ConfigureAwait(false);
        if (callerIsTheHolder
            && await RequestHelpers.CallerHasNoPasswordDoor(_authContext, HttpContext.Request, _canonicalLinks.HoldsOnlyAProvisionedPassword).ConfigureAwait(false)
            && _canonicalLinks.UserHoldsAnEnabledLink(user.Id)
            && !AnotherAdministratorKeepsAWayIn(user.Id))
        {
            return RefuseStrandingUnregister(user.Id);
        }

        // SSO login resolves through the per-provider CanonicalLinks maps, not AuthenticationProviderId,
        // so revoking SSO means removing this user's canonical links from every provider - otherwise the
        // account would still sign in via SSO (#213). Done under the config lock. NOTE: with a provider's
        // AllowExistingAccountLink enabled, the same-named account can be re-adopted on the next SSO login,
        // so a hard revoke there also needs the local account disabled or renamed; with the fail-closed
        // default (adoption off) the revoke is durable.
        var revoked = _canonicalLinks.RemoveUserEverywhere(user.Id);

        // Switch the account back to the requested auth provider and PERSIST it - the previous version set
        // this in memory only and never called UpdateUserAsync, so the switch was silently discarded.
        user.AuthenticationProviderId = provider;
        await _userManager.UpdateUserAsync(user).ConfigureAwait(false);

        // Terminate the user's already-established sessions so a hard revoke also invalidates tokens minted
        // before it (#440). Removing the links only fails FUTURE logins closed; a token issued earlier stays
        // valid until it expires. Scoped strictly to this one user's id; null revokes all of their tokens,
        // including the caller's own when an administrator revokes their own account. That press reaches
        // this line only where the revoke takes no way in or another administrator was seen to keep one
        // (#1741, the guard above, within the window it names): the durable revoke above is why ending the
        // session is COMPLETE, and the guard is why it is safe, which are two different claims. Runs LAST,
        // after the link removal and provider switch are both persisted, so
        // if the revoke throws the unregister is already complete rather than left half-done. Complement to
        // the #232 in-flight re-check, not a substitute: this kills existing sessions, #232 closes the mint race.
        await _sessionManager.RevokeUserTokens(user.Id, null).ConfigureAwait(false);

        if (_logger.IsEnabled(LogLevel.Information))
        {
            _logger.LogInformation("Unregistered SSO for user {UserId}: removed {Count} canonical link(s) and revoked active tokens.", user.Id, revoked);
        }

        return Ok();
    }

    /// <summary>Pre-provisions a canonical link from an identity-provider subject to an existing Jellyfin account (#1133), with no identity-provider response in the request, so an invite-born account is SSO-linked before its first login; elevation-gated.</summary>
    /// <remarks>The self-service link write redeems a live authorize state or a signed assertion, so a tool holding only an administrator credential cannot drive it; this is that write without the round trip, differing in one behaviour: a subject already linked to a different account is refused with 409. Repeating the same mapping succeeds, and the link is written unstamped by the issuer binding (#186), taken on the first real login.</remarks>
    /// <param name="mode">The mode of the function; SAML or OID.</param>
    /// <param name="provider">The provider the link belongs to.</param>
    /// <param name="jellyfinUserId">The existing Jellyfin account the identity is linked to.</param>
    /// <param name="canonicalName">The provider-side identity key: the OpenID stable subject claim, or the SAML NameID.</param>
    /// <returns>No content on success, 400 on an empty key or an unknown provider, 404 when no such Jellyfin account exists, 409 when the identity is already linked elsewhere.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("Links/Preprovision/{mode}/{provider}/{jellyfinUserId}")]
    [Consumes(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> PreprovisionCanonicalLink([FromRoute] string mode, [FromRoute] string provider, [FromRoute] Guid jellyfinUserId, [FromBody] string canonicalName)
    {
        // Throttle after the elevation guard, before any work (#382, #516): the [Authorize] filter refuses a
        // non-elevated caller before the body runs, so an unauthorized request never reaches the limiter and
        // there is no rate-limit oracle. Past it, this shares the "link" bucket with the self-service link
        // and unlink writes, because it drives the same config-XML persist under the global lock.
        if (RateLimitCheck(SsoRateLimitClass.Link) is { } throttled)
        {
            return throttled;
        }

        // A user id nobody holds is a 404 rather than a link written against a GUID that resolves to no
        // account: the endpoint exists to link an account a provisioning tool has ALREADY created, and a
        // link to a non-existent account is unreachable bookkeeping that no login can ever redeem.
        if (_userManager.GetUserById(jellyfinUserId) is null)
        {
            return NotFound("No Jellyfin account exists with that user id.");
        }

        if (RefuseUnknownMode(mode, out var parsed) is { } unknownMode)
        {
            return unknownMode;
        }

        var result = _canonicalLinks.TryPreprovisionLink(parsed, provider, canonicalName, jellyfinUserId);
        if (result == CanonicalLinkWriteResult.Created)
        {
            SsoAudit.LinkPreprovisioned(
                _logger,
                await ResolveActorAsync().ConfigureAwait(false),
                parsed == ProviderMode.Oid ? OpenIdProtocol : SamlProtocol,
                provider,
                jellyfinUserId);
        }

        return FlowResponses.MapCanonicalLinkWrite(result);
    }

    /// <summary>Approves an account this plugin provisioned disabled and awaiting an administrator (#1529): enables that one account and changes nothing else; elevation-gated.</summary>
    /// <remarks>It acts only on this plugin's own record of having provisioned the account inert, never on the disabled flag, which does not say who set it or why; an identity this plugin did not provision inert is a 404. The canonical name travels in the body, because a subject or NameID may contain a slash.</remarks>
    /// <param name="mode">The mode of the function; SAML or OID.</param>
    /// <param name="provider">The provider the account was provisioned from.</param>
    /// <param name="canonicalName">The provider-side identity key: the OpenID stable subject claim, or the SAML NameID.</param>
    /// <returns>No content when the account was enabled, or when the record was stale and was cleared; 400 on an unknown provider, 404 when this plugin holds no such record, 403 when the recorded account is an administrator.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("Links/Approve/{mode}/{provider}")]
    [Consumes(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> ApproveProvisionedAccount([FromRoute] string mode, [FromRoute] string provider, [FromBody] string canonicalName)
    {
        // Throttle after the elevation guard, before any work (#382, #516), in the same bucket as the link
        // writes: this drives the same config-XML persist under the global lock, and it is an existence
        // oracle for provisioned identities in exactly the way the unlink beside it is.
        if (RateLimitCheck(SsoRateLimitClass.Link) is { } throttled)
        {
            return throttled;
        }

        if (RefuseUnknownMode(mode, out var parsed) is { } unknownMode)
        {
            return unknownMode;
        }

        var (outcome, userId) = await _canonicalLinks.ApproveProvisionedAccountAsync(parsed, provider, canonicalName).ConfigureAwait(false);
        if (outcome == PendingApprovalResult.Approved)
        {
            // Audited only on the arm that actually granted something. The two arms that merely cleared a
            // record changed no access, and a line for them would put "account approved" in the trail for an
            // account nobody approved.
            SsoAudit.AccountApproved(
                _logger,
                await ResolveActorAsync().ConfigureAwait(false),
                parsed == ProviderMode.Oid ? OpenIdProtocol : SamlProtocol,
                provider,
                userId);
        }

        return FlowResponses.MapPendingApproval(outcome);
    }

    /// <summary>
    /// Create a canonical link for a given user. Must be performed by the user being changed, or admin.
    /// </summary>
    /// <param name="mode">The mode of the function; SAML or OID.</param>
    /// <param name="provider">The name of the provider to link to a jellyfin account.</param>
    /// <param name="jellyfinUserId">The user ID within jellyfin to link to the provider.</param>
    /// <param name="authResponse">The client information to authenticate the user with.</param>
    /// <returns>Whether this API endpoint succeeded.</returns>
    [Authorize]
    [HttpPost("{mode}/Link/{provider}/{jellyfinUserId}")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> AddCanonicalLink([FromRoute] string mode, [FromRoute] string provider, [FromRoute] Guid jellyfinUserId, [FromBody] AuthResponse authResponse)
    {
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, "User is not allowed to link SSO providers.");
        }

        // Throttle after the caller-authz guard (#382): the 403 stays first so an unauthorized caller is
        // refused before the limiter is consulted (no rate-limit oracle), then the shared gate caps how fast
        // an authorized caller can drive the config-XML disk writes this write surface performs. "link" is a
        // distinct endpoint class, so its budget is independent of the anonymous login flows.
        if (RateLimitCheck(SsoRateLimitClass.Link) is { } throttled)
        {
            return throttled;
        }

        if (RefuseUnknownMode(mode, out var parsed) is { } unknownMode)
        {
            return unknownMode;
        }

        return parsed switch
        {
            ProviderMode.Saml => SamlLink(provider, jellyfinUserId, authResponse),
            ProviderMode.Oid => OidLink(provider, jellyfinUserId, authResponse),
            _ => throw new ArgumentOutOfRangeException(nameof(mode)),
        };
    }

    /// <summary>
    /// Unregisters a given mapping from id within provider to user.
    /// </summary>
    /// <param name="mode">The mode of the function; SAML or OID.</param>
    /// <param name="provider">The name of the provider from which the link should be removed.</param>
    /// <param name="jellyfinUserId">The user ID within jellyfin to unlink from the provider.</param>
    /// <param name="canonicalName">The provider-side canonical name (the identity's stable subject for OpenID, or the SAML NameID) whose link to the Jellyfin user should be removed.</param>
    /// <returns>Whether this API endpoint succeeded.</returns>
    [Authorize]
    [HttpDelete("{mode}/Link/{provider}/{jellyfinUserId}/{canonicalName}")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> DeleteCanonicalLink([FromRoute] string mode, [FromRoute] string provider, [FromRoute] Guid jellyfinUserId, [FromRoute] string canonicalName)
    {
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, "Current user is not allowed to unlink SSO providers for user ID.");
        }

        // Throttle after the caller-authz guard (#382): a name-miss DELETE still runs a full persist under the
        // global config lock, so this endpoint is capped too. It shares the "link" budget with AddCanonicalLink
        // - one bucket per client for the whole link/unlink write surface - while the 403 stays first.
        if (RateLimitCheck(SsoRateLimitClass.Link) is { } throttled)
        {
            return throttled;
        }

        if (RefuseUnknownMode(mode, out var parsed) is { } unknownMode)
        {
            return unknownMode;
        }

        // Whether the caller is an administrator decides one thing inside the removal (#1647): a link that
        // carries a provisioned access deadline is removed only on an administrator's word, because the
        // holder's own unlink followed by a re-login is otherwise an exit from the limit that admitted
        // them. Read from the resolved account, never from the request, and passed in rather than decided
        // here so the check sits in the same transaction as the removal it gates.
        var callerIsAdministrator = await RequestHelpers.IsAdministrator(_authContext, HttpContext.Request).ConfigureAwait(false);

        // Whether the caller's account has a password door at all (#1720), for the holder's own last-link removal,
        // read at the boundary from the same resolved account because the link service holds no user manager. The
        // stamp test is the one the SSO-only feature and the managed-status report use, and since #1746 the
        // activation guard discounts a minted password too, so the two agree. The minted-password reading (#1733)
        // is handed in as a delegate, invoked last, so the boundary can be tested with either answer.
        var passwordLoginDisabled = await RequestHelpers.CallerHasNoPasswordDoor(
            _authContext,
            HttpContext.Request,
            _canonicalLinks.HoldsOnlyAProvisionedPassword).ConfigureAwait(false);

        // WHETHER THE CALLER IS ACTING ON THEIR OWN ACCOUNT (#1732), which is what narrows the exemption
        // #1720 gave an administrator. That exemption was decided for an administrator acting on somebody
        // ELSE's link; this page acts on the caller's own, so an administrator who opens it is one press
        // from the lockout the guard exists for.
        var callerIsTheHolder = await RequestHelpers.CallerIsTheHolder(_authContext, HttpContext.Request, jellyfinUserId).ConfigureAwait(false);

        // AND WHETHER ANYBODY WOULD BE LEFT TO UNDO IT. Asked only where all THREE cheap facts already hold,
        // because answering it walks every account on the server AND takes the configuration lock every
        // login takes. An administrator whose own account accepts a password can never reach this refusal,
        // so on an ordinary server the rule is inert and must cost nothing; leaving that condition out made
        // every self-delete pay the survey, including one that turns out to name no link at all.
        var anotherAdministratorKeepsAWayIn = callerIsAdministrator
            && callerIsTheHolder
            && passwordLoginDisabled
            && AnotherAdministratorKeepsAWayIn(jellyfinUserId);

        var removal = _canonicalLinks.TryRemoveLink(parsed, provider, canonicalName, jellyfinUserId, callerIsAdministrator, passwordLoginDisabled, callerIsTheHolder, anotherAdministratorKeepsAWayIn);

        // Tokens are revoked only when this unlink removed the last canonical link (#468), the state matching
        // Unregister's hard lockdown, because removing links only fails future logins closed; a user unlinking a
        // secondary provider keeps a working identity, so revoking there would be a self-inflicted mass-logout.
        // Scoped to this one user id, after the removal is persisted; per-provider disable deliberately does not
        // revoke, because Jellyfin attributes no live session to its originating provider.
        if (removal is { Result: CanonicalLinkRemoveResult.Removed, UserRetainsAnyLink: false })
        {
            await _sessionManager.RevokeUserTokens(jellyfinUserId, null).ConfigureAwait(false);
            if (_logger.IsEnabled(LogLevel.Information))
            {
                _logger.LogInformation("Removed the last SSO link for user {UserId} and revoked their active tokens.", jellyfinUserId);
            }
        }

        return removal.Result switch
        {
            CanonicalLinkRemoveResult.Removed => Ok(),
            CanonicalLinkRemoveResult.NotFound => NotFound("No SSO link is registered for that canonical name."),
            CanonicalLinkRemoveResult.Mismatch => StatusCode(StatusCodes.Status409Conflict, "jellyfin UID does not match id registered to that canonical name."),
            CanonicalLinkRemoveResult.UnknownProvider => BadRequest(NoMatchingProviderMessage),
            CanonicalLinkRemoveResult.TimeLimited => StatusCode(StatusCodes.Status403Forbidden, "This SSO link carries an access deadline and can be removed only by an administrator."),
            CanonicalLinkRemoveResult.WouldStrandAccount => RefuseStrandingSelfUnlink(jellyfinUserId, callerIsAdministrator && callerIsTheHolder),
            _ => throw new InvalidOperationException($"Unhandled canonical-link remove result: {removal.Result}"),
        };
    }

    // The holder's own last-link removal, refused because it would leave them unable to sign in (#1720), audited as
    // a refusal. The message names the three facts the decision asked for and no provider or subject, because a
    // bare 403 on an offered button reads as a broken page; an administrator removing their own gets the other
    // sentence (#1732), keeping the opening clause the page matches on. Since #1733 it names the account rather
    // than the server and the remedy that ends the state for both populations, a password set on the account, and
    // it says what was measured, a link on an enabled provider, rather than that nobody else can sign in.
    private ObjectResult RefuseStrandingSelfUnlink(Guid jellyfinUserId, bool callerIsTheLastAdministrator)
    {
        SsoAudit.SelfUnlinkRefusedWouldStrand(_logger, jellyfinUserId);
        var sentence = callerIsTheLastAdministrator
            ? "This is the last SSO link that can sign you in, and no other administrator on this server holds an SSO link that can sign them in either, so removing it could leave this server with no administrator able to reach it. Ask another administrator to remove it for you, or link another provider to your account first and then remove this one."
            : "This is the last SSO link that can sign you in, and this account has no password anybody can sign in with, so removing it would leave you unable to sign in at all. Link another provider first and then remove this one, or ask an administrator to set a password on this account and switch it back to password sign-in.";
        return StatusCode(StatusCodes.Status403Forbidden, sentence);
    }

    // Audited as a refusal, like the self-service refusal above. The sentence says what was measured, no other
    // administrator holds an SSO link that can sign them in, and names the remedies: another administrator performs
    // the revoke or is linked first, and since #1733 a real password set on the account, which ends the refusal
    // because the recorded digest stops matching; linking another provider is not offered, because this route removes every link.
    private ObjectResult RefuseStrandingUnregister(Guid jellyfinUserId)
    {
        SsoAudit.UnregisterRefusedWouldStrandServer(_logger, jellyfinUserId);
        return StatusCode(
            StatusCodes.Status403Forbidden,
            "This would remove every SSO link that can sign you in, and no other administrator on this server holds an SSO link that can sign them in either, so it could leave this server with no administrator able to reach it. Ask another administrator to revoke your SSO links for you, link another administrator account to a provider first and then revoke your own, or set a password on an administrator account from the Jellyfin dashboard - a password this server generated for an account is not one anybody can sign in with, so setting one is what gives this server a way back in.");
    }

    // Whether an administrator other than this one can still sign in (#1732, #1741), measured as the bulk unlink's
    // guard measures it: a link on an enabled provider, never a stored password, and the subtraction makes it one
    // question. A server that cannot be surveyed answers no, because reading a missing accessor as an empty roster
    // would switch the guard off on the one build it cannot survey; the throw arrives wrapped in
    // TargetInvocationException, so the catch is broad, as the sweep in TryEnableAsync catches the same surface.
    private bool AnotherAdministratorKeepsAWayIn(Guid caller)
    {
        try
        {
            var others = _ssoOnly.DescribeAdministratorsOtherThan(caller);
            return others.Count > _canonicalLinks.AdministratorsWithNoWayIn(others).Count;
        }
#pragma warning disable CA1031 // The whole point is that no reachable failure of the survey may be read as "somebody else can get in".
        catch (Exception exception)
#pragma warning restore CA1031
        {
            _logger.LogWarning(exception, "Could not survey the other administrator accounts, so the removal is judged as though none of them could sign in.");
            return false;
        }
    }

    /// <summary>Removes every canonical link one provider holds, the way back from a link import that restored the wrong document (#1519); elevation-gated.</summary>
    /// <remarks>
    /// The import merges and never removes, so this is the smallest true way back, touching no account, permission
    /// or password. It can take every account off SSO in one call, so the caller sends the count it was shown, and
    /// the run refuses an unknown provider, a count that differs at the lock, a table that moved, or an administrator left with no way in; only accounts whose last link this removes are signed out (#468).
    /// </remarks>
    /// <param name="mode">The mode of the function; SAML or OID.</param>
    /// <param name="provider">The provider whose links are all removed.</param>
    /// <param name="expectedLinkCount">The number of links the caller was shown and expects to remove; the run refuses when the provider holds a different number.</param>
    /// <returns>What was removed, or the refusal that stopped it.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpDelete("{mode}/Links/{provider}/{expectedLinkCount}")]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> PurgeProviderLinks([FromRoute] string mode, [FromRoute] string provider, [FromRoute] int expectedLinkCount)
    {
        // Throttle after the elevation guard (#382): [Authorize] refuses a non-elevated caller before this
        // body runs, so there is no rate-limit oracle. Past it, this shares the "link" bucket with the
        // single link writes and the import, because it is the same config-XML persist under the global
        // lock - and here every refusal pays that persist too, so an unthrottled caller could drive the
        // disk write with nothing but wrong counts.
        if (RateLimitCheck(SsoRateLimitClass.Link) is { } throttled)
        {
            return throttled;
        }

        if (RefuseUnknownMode(mode, out var parsed) is { } unknownMode)
        {
            return unknownMode;
        }

        var protocol = parsed == ProviderMode.Oid ? OpenIdProtocol : SamlProtocol;

        // Resolved BEFORE anything is changed, and once. Reading the caller's own name goes to the
        // authorization context, which can throw; doing it after the removal would turn that throw into a
        // 500 on a run whose links are already gone and which then has no audit line at all - the one path
        // where the trail matters most. The SSO-only endpoints resolve it up front for the same reason.
        var actor = await ResolveActorAsync().ConfigureAwait(false);

        // Two steps on purpose, and the split answers two different problems. The survey is a READ: it names
        // every account holding a link on this provider under the config lock, so those accounts can be
        // resolved through the user manager with the lock RELEASED - a provider can carry thousands of links,
        // and a user-manager call per link inside the lock would block every login for the duration. It also
        // answers the two refusals a stale page actually produces without entering a mutation at all, because
        // every return out of one persists the configuration file even when it changed nothing, and this
        // plugin's write is not atomic (#1532): a wrong count is the NORMAL outcome here and must not spend
        // a rewrite of SSO-Auth.xml. The authoritative checks stay inside the purge below.
        var survey = _canonicalLinks.SurveyProviderLinks(parsed, provider);
        var doors = survey.ProviderExists ? _ssoOnly.DescribeAccountDoors(survey.LinkedUsers) : Array.Empty<AccountDoors>();
        var outcome = Screen(survey, expectedLinkCount)
            ?? _canonicalLinks.TryPurgeProviderLinks(parsed, provider, expectedLinkCount, doors);

        if (outcome.Result != ProviderLinkPurgeResult.Purged)
        {
            // A blocked mass-lockout leaves a trail (T-R1), exactly as a blocked SSO-only activation does.
            // The reason is the verdict's own enum name - a fixed constant, never request input - so the
            // audit line cannot be written by the caller.
            SsoAudit.ProviderLinksPurgeRefused(_logger, actor, protocol, provider, outcome.Result.ToString());
        }

        if (RefusePurge(outcome, expectedLinkCount) is { } refused)
        {
            return refused;
        }

        // AFTER the removal is persisted, so a revoke that throws leaves the unlink already complete rather
        // than half-done - the ordering DeleteCanonicalLink takes for the same reason. Scoped strictly to
        // the accounts this run left with no canonical link anywhere; null revokes all of that account's
        // tokens, which is the terminal "can no longer SSO in at all" state (#468). One account's revoke
        // fault must not abort the rest: the links are already gone for every one of them, so stopping here
        // would leave the remaining accounts holding live tokens with nothing recording why.
        var signedOut = 0;
        foreach (var userId in outcome.RevokedUserIds)
        {
            try
            {
                await _sessionManager.RevokeUserTokens(userId, null).ConfigureAwait(false);
                signedOut++;
                if (_logger.IsEnabled(LogLevel.Information))
                {
                    _logger.LogInformation("Removed the last SSO link for user {UserId} in a bulk unlink and revoked their active tokens.", userId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Revoking tokens after a bulk unlink failed for user {UserId}; its links are removed and it may hold a live session, and the remaining accounts are still signed out.", userId);
            }
        }

        SsoAudit.ProviderLinksPurged(_logger, actor, protocol, provider, outcome.RemovedLinks, outcome.RevokedUserIds.Count, signedOut);

        // The gate judged accounts read before the removal took the lock, and an account can lose its password door
        // in that window without any link moving, so the same question is asked once more against what is true
        // now; it cannot undo the removal, but it turns a silent lockout into a line an operator can act on. Every
        // account the guard judged, because one keeping a link on a disabled provider is not signed out (#468) yet
        // is exactly the case this net exists for, and only where the run took something, so the disable-then-clean-up workflow raises no false alarm.
        AuditAdministratorsLeftWithoutAWayIn(outcome, doors, protocol, provider);

        return Ok(new ProviderLinkPurgeDocument { Removed = outcome.RemovedLinks, SignedOut = signedOut });
    }

    // The refusal body per purge verdict, or null when the purge ran. The stranded names are the way out and are
    // capped like the link import's own refusal, so a roster-sized body cannot be driven by one request.
    private ObjectResult? RefusePurge(ProviderLinkPurgeOutcome outcome, int expectedLinkCount)
    {
        switch (outcome.Result)
        {
            case ProviderLinkPurgeResult.UnknownProvider:
                return BadRequest(NoMatchingProviderMessage);

            case ProviderLinkPurgeResult.CountMismatch:
                return StatusCode(
                    StatusCodes.Status409Conflict,
                    FormattableString.Invariant($"This provider holds {outcome.ActualLinkCount} link(s), not the {expectedLinkCount} this request expects. Reload the page and run it again against the current number."));

            case ProviderLinkPurgeResult.LinkTableChanged:
                return StatusCode(
                    StatusCodes.Status409Conflict,
                    "The link table changed while this request was checking which accounts would be left without a way to sign in. Nothing was removed; run it again.");

            case ProviderLinkPurgeResult.WouldStrandAdministrator:
                // The names are the way out, which is why they are in the refusal: an operator who is only
                // told "an administrator would be stranded" has to guess which account to give a password
                // to. The caller is an elevated administrator, who can already list every account on this
                // server, so this discloses nothing the roster does not - and it is a REFUSAL, so it names
                // accounts nothing was done to.
                // Capped, like the link import's own refusal: a server where many accounts hold
                // administrator would otherwise make this body as long as the roster, on one request.
                var overflow = outcome.StrandedAdministrators.Count - NamedStrandedAdministrators;
                var stranded = string.Join(", ", outcome.StrandedAdministrators.Take(NamedStrandedAdministrators)).ReplaceLineEndings(string.Empty)
                    + (overflow > 0 ? FormattableString.Invariant($" and {overflow} more") : string.Empty);
                return StatusCode(
                    StatusCodes.Status409Conflict,
                    "This would take the last way in from these administrator accounts: " + stranded + ". A stored password does not count as a way in here, because this plugin mints an unusable one onto the accounts it provisions and cannot tell the two apart. Link each of them to another enabled provider, or unlink it deliberately through the single-link route, then run this again. Nothing was removed.");

            case ProviderLinkPurgeResult.Purged:
                return null;

            default:
                throw new InvalidOperationException($"Unhandled provider-link purge result: {outcome.Result}");
        }
    }

    // The gate judged accounts read before the removal took the lock, so the same question is asked once more
    // against what is true now; it cannot undo the removal, but it turns a silent lockout into a line an operator
    // can act on. Only where the run took something, so the disable-then-clean-up workflow raises no false alarm.
    private void AuditAdministratorsLeftWithoutAWayIn(ProviderLinkPurgeOutcome outcome, IReadOnlyList<AccountDoors> doors, string protocol, string provider)
    {
        var doorless = outcome.TargetWasEnabled
            ? _canonicalLinks.AdministratorsWithNoWayIn(doors)
            : Array.Empty<string>();
        if (doorless.Count == 0)
        {
            return;
        }

        var overflowing = doorless.Count - NamedStrandedAdministrators;
        var named = string.Join(", ", doorless.Take(NamedStrandedAdministrators))
            + (overflowing > 0 ? FormattableString.Invariant($" and {overflowing} more") : string.Empty);
        SsoAudit.ProviderLinksPurgeStrandedAdministrator(_logger, protocol, provider, named);
    }

    /// <summary>
    /// Gets all the saml links for a user.
    /// </summary>
    /// <param name="jellyfinUserId">The user ID within jellyfin for which to return the links.</param>
    /// <returns>A dictionary of provider : link mappings.</returns>
    [Authorize]
    [HttpGet("saml/links/{jellyfinUserId}")]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult<SerializableDictionary<string, IEnumerable<string>>>> GetSamlLinksByUser(Guid jellyfinUserId)
    {
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, "Non-admin is not allowed to query other user's mappings.");
        }

        return _canonicalLinks.LinksByUser(ProviderMode.Saml, jellyfinUserId);
    }

    /// <summary>
    /// Gets all the oid links for a user.
    /// </summary>
    /// <param name="jellyfinUserId">The user ID within jellyfin for which to return the links.</param>
    /// <returns>A dictionary of provider : link mappings.</returns>
    [Authorize]
    [HttpGet("oid/links/{jellyfinUserId}")]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult<SerializableDictionary<string, IEnumerable<string>>>> GetOidLinksByUser(Guid jellyfinUserId)
    {
        if (!await RequestHelpers.AssertCanUpdateUser(_authContext, HttpContext.Request, jellyfinUserId).ConfigureAwait(false))
        {
            return StatusCode(StatusCodes.Status403Forbidden, "Non-admin is not allowed to query other user's mappings.");
        }

        return _canonicalLinks.LinksByUser(ProviderMode.Oid, jellyfinUserId);
    }

    /// <summary>Validates a SAML link request and creates the link if it is valid; the redeem lives on the flow service and the controller keeps the caller-authz guard (#160).</summary>
    /// <param name="provider">The provider to authenticate against.</param>
    /// <param name="jellyfinUserId">The ID of the account to be linked to the provider; must be performed by this user, or an admin.</param>
    /// <param name="response">The data passed to the client to ensure it is the right one.</param>
    /// <returns>JSON for the client to populate information with.</returns>
    private ActionResult SamlLink(string provider, Guid jellyfinUserId, AuthResponse response) =>
        _saml.Link(provider, jellyfinUserId, response, Request);

    /// <summary>Validates an OIDC link request and creates the link if it is valid; the redeem lives on the flow service and the controller keeps the caller-authz guard and hands the binding cookie in (#160).</summary>
    /// <param name="provider">The provider to authenticate against.</param>
    /// <param name="jellyfinUserId">The ID of the account to be linked to the provider; must be performed by this user, or an admin.</param>
    /// <param name="response">The data passed to the client to ensure it is the right one.</param>
    /// <returns>JSON for the client to populate information with.</returns>
    private ActionResult OidLink(string provider, Guid jellyfinUserId, AuthResponse response) =>
        _oidc.Link(provider, jellyfinUserId, response, Request.Cookies[AuthorizeStateBinding.CookieName]);

    // The refusals the survey can answer on its own, so a stale page does not spend a rewrite of the
    // configuration file to be told its number is old (#1519). Null means nothing here decides it and the
    // purge runs, where both of these are checked again under the lock that removes - this is a cheaper
    // path to the same answer, never the authority for it.
    private static ProviderLinkPurgeOutcome? Screen(ProviderLinkSurvey survey, int expectedLinkCount)
    {
        if (!survey.ProviderExists)
        {
            return ProviderLinkPurgeOutcome.Refusing(ProviderLinkPurgeResult.UnknownProvider, 0);
        }

        return survey.LinkCount == expectedLinkCount
            ? null
            : ProviderLinkPurgeOutcome.Refusing(ProviderLinkPurgeResult.CountMismatch, survey.LinkCount);
    }
}
