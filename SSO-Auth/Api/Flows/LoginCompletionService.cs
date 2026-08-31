// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Identity;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Logout;
using Jellyfin.Plugin.SSO_Auth.Api.Metrics;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Flows;

/// <summary>
/// The one shared completion path both protocols funnel into once their validation has produced a
/// <see cref="VerifiedIdentity"/> (#473): resolve-or-create the account, build the session parameters, and
/// mint the session under the in-flight revocation gate, then audit and map to a <see cref="LoginOutcome"/>.
/// Extracting it here (#160, #318 step 11) leaves the controller's two callbacks a single delegation each,
/// and keeps the whole tail - every decision from a resolved identity to a minted session - in one flow-tier
/// collaborator rather than inline on the controller.
/// </summary>
/// <remarks>
/// The entrypoint takes a <see cref="VerifiedIdentity"/> and nothing rawer, so the compile-time "no mint
/// without validation" property the keystone establishes is preserved across the extraction: there is no
/// overload that accepts an unvalidated response. This flow tier holds no <c>HttpContext</c> dependency -
/// the controller passes the normalized client remote endpoint in as a resolver (#177), exactly as it does
/// for <see cref="SessionMinter"/>.
/// </remarks>
internal sealed class LoginCompletionService
{
    private readonly CanonicalLinkService _canonicalLinks;
    private readonly SessionMinter _sessionMinter;
    private readonly SsoOnlyLoginService _ssoOnly;
    private readonly ProviderConfigStore _configStore;
    private readonly ISessionManager _sessionManager;
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="LoginCompletionService"/> class, wiring the account-
    /// linking, session-minting, SSO-only-enforcement and configuration collaborators the login tail needs.
    /// </summary>
    /// <param name="canonicalLinks">The account-linking workflow (resolve/adopt/create).</param>
    /// <param name="sessionMinter">The session minter run under the in-flight revocation gate.</param>
    /// <param name="ssoOnly">The SSO-only login enforcement service.</param>
    /// <param name="configStore">The provider configuration store.</param>
    /// <param name="sessionManager">Jellyfin session manager, used to revoke an account's live tokens when the account-expiry gate disables it (#1144); without it a token minted before the deadline would outlive it.</param>
    /// <param name="logger">The logger.</param>
    internal LoginCompletionService(CanonicalLinkService canonicalLinks, SessionMinter sessionMinter, SsoOnlyLoginService ssoOnly, ProviderConfigStore configStore, ISessionManager sessionManager, ILogger logger)
    {
        _canonicalLinks = canonicalLinks ?? throw new ArgumentNullException(nameof(canonicalLinks));
        _sessionMinter = sessionMinter ?? throw new ArgumentNullException(nameof(sessionMinter));
        _ssoOnly = ssoOnly ?? throw new ArgumentNullException(nameof(ssoOnly));
        _configStore = configStore ?? throw new ArgumentNullException(nameof(configStore));
        _sessionManager = sessionManager ?? throw new ArgumentNullException(nameof(sessionManager));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Completes a login from its fully-verified identity: resolve-or-create the account, build the session
    /// parameters, and mint the session under the in-flight revocation gate. Taking a
    /// <see cref="VerifiedIdentity"/> - the only type either protocol can produce, and only after full
    /// validation - is what makes minting from a raw, unvalidated response a compile error: there is no
    /// overload that accepts anything else. The only per-protocol input left is the adoption gate (OpenID may
    /// require a verified email #218; SAML passes <see cref="AdoptionGate.None"/>), so it is a parameter;
    /// every other divergence collapsed into the identity's own fields (its link namespace, audit label,
    /// subject, username, privileges).
    /// </summary>
    /// <param name="identity">The fully-verified login identity and privileges (#473).</param>
    /// <param name="response">The client's auth request context (app/device), carried into the session mint.</param>
    /// <param name="config">The provider configuration governing authorization/folder/default-provider grants.</param>
    /// <param name="adoptionGate">The extra proof a same-named adoption must clear (#218).</param>
    /// <param name="remoteEndPointResolver">Resolves the normalized client IP for the activity log (#177); the controller reads it from <c>HttpContext</c> and passes it in so this tier stays HttpContext-free. Evaluated at the original point inside the minter - after avatar/persistence, and not at all on the fail-closed path.</param>
    /// <param name="logoutContext">The optional Single Logout material captured at the callback (the OpenID id_token/sid or the SAML SessionIndex, #727); persisted after the mint only when <c>EnableSingleLogout</c> is on. Null (the default) skips the capture.</param>
    /// <returns>The HTTP result for the completed (or refused) login.</returns>
    internal async Task<ActionResult> CompleteAsync(
        VerifiedIdentity identity,
        AuthResponse response,
        ProviderConfigBase config,
        AdoptionGate adoptionGate,
        Func<string> remoteEndPointResolver,
        LogoutContext? logoutContext = null)
    {
        Guid userId;
        try
        {
            userId = await _canonicalLinks.ResolveOrCreateAsync(
                identity.LinkMode,
                identity.Provider,
                identity.Subject,
                identity.Username,
                config.AllowExistingAccountLink,
                adoptionGate,
                identity.Issuer,
                config.ProvisionNewUsersDisabled,
                // The role-mapped access duration (#1146), handed down so the create arm can anchor a
                // deadline to the exact moment it writes the link. THE RESOLUTION ORDER IS STATED HERE, once
                // and in one expression: an absolute instant the identity provider emitted (#1143) wins, so
                // the relative source is passed only when the login carried none. Passing both and letting a
                // later write overwrite the earlier one would put the same rule in two places and make the
                // outcome depend on their order.
                identity.ExpiresAtUtc is null ? identity.GuestAccessDuration : null,
                // Follow the identity provider's username on an already-linked account (#1138). Read off the
                // provider configuration rather than off the identity, because it is the administrator's
                // policy and not something the login gets to assert.
                config.SyncUsernameFromProvider,
                // The role-selected provisioning profile (#1106), handed down as a NAME so the create arm
                // resolves it against the profile set inside its own locked configuration read. Null when the
                // provider configures no role rows or this login matched none, and the create arm then falls
                // to the provider's own default resolution (#1105) - which is every login before this existed.
                identity.ProvisioningProfile).ConfigureAwait(false);
        }
        catch (AccountLinkForbiddenException)
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.AccountLinkForbidden));
        }

        // Account-expiry gate (#1144), ahead of the pending-approval gate so an account this path already
        // disabled is refused under its own reason rather than reported as awaiting an approval nobody is
        // waiting to give. Opt-in: with no AccountExpiryClaim configured for the provider, nothing here runs
        // and the login takes byte-for-byte its pre-#1144 path.
        if (!string.IsNullOrWhiteSpace(config.AccountExpiryClaim))
        {
            var expiryRefusal = await EnforceAccountExpiryAsync(identity, userId).ConfigureAwait(false);
            if (expiryRefusal is not null)
            {
                return expiryRefusal;
            }
        }

        // Pending-approval gate (#737): a resolved account that is disabled - a brand-new user just
        // provisioned inert under ProvisionNewUsersDisabled, OR any account an administrator disabled - must
        // not be issued a session. This single read-only check fails closed for both the first login (the
        // account was just created disabled above) and every later login of a still-pending account, and it
        // fires BEFORE any SSO-only repoint or mint side effect. It never disables an account; it only refuses
        // to mint for one already disabled. The provisioning event itself is audited at its source
        // (CanonicalLinkService), so this uniform gate refuses silently rather than mislabelling an
        // admin-disabled account's refused login as a fresh provisioning.
        if (_canonicalLinks.IsAccountAwaitingApproval(userId))
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.AwaitingApproval));
        }

        // SSO-only re-assertion on the login path (#165, criterion 5 / T-S1, Findings A/B/H1). While
        // DisablePasswordLogin is on, an SSO login must not leave the account's provider routing in a state
        // that undermines the mode: a non-exempt account is forced onto the SSO (non-password) provider so no
        // residual password door survives, and the break-glass admin is PINNED to the built-in password
        // provider so an SSO login can never strip its own password door (which would risk a total lockout
        // once the IdP fails). The single decision is derived from the RESOLVED account (by userId), not the
        // mutable IdP-supplied identity.Username, so it matches the enable sweep's break-glass basis exactly;
        // it also tracks a first-time non-exempt repoint (so the off-switch/boot reconcile can restore it) and
        // returns whether this is the break-glass admin so the mint can keep it admin/enabled. When the mode
        // is off (the default), the provider's own DefaultProvider is used unchanged and nothing is tracked.
        var configuredDefaultProvider = config.DefaultProvider?.Trim();
        var enforcement = _ssoOnly.ResolveLoginEnforcement(userId, configuredDefaultProvider);

        var sessionParameters = new SessionParameters
        {
            UserId = userId,
            IsAdmin = identity.Admin,
            IsBreakGlassAdmin = enforcement.IsBreakGlassAdmin,
            EnableAuthorization = config.EnableAuthorization,
            EnableAllFolders = config.EnableAllFolders,
            EnabledFolders = identity.Folders.ToArray(),
            EnableLiveTv = identity.EnableLiveTv,
            EnableLiveTvManagement = identity.EnableLiveTvManagement,
            PermissionGrants = identity.PermissionGrants,
            MaxParentalRatingScore = identity.MaxParentalRatingScore,
            SyncPlayAccess = identity.SyncPlayAccess,
            AuthResponse = response,
            DefaultProvider = enforcement.DefaultProvider,
            AvatarUrl = identity.AvatarUrl,
        };

        // Mint under the in-flight revocation gate (#232): the minter re-checks the link is still live both
        // before any user side effect and again as the last act before AuthenticateDirect. The remote-endpoint
        // resolver is passed rather than the value so the minter evaluates it at the exact original point.
        var authenticationResult = await _sessionMinter.MintAsync(
            sessionParameters,
            remoteEndPointResolver,
            () => _canonicalLinks.IsIdentityStillLinked(identity.LinkMode, identity.Provider, identity.Subject, userId)).ConfigureAwait(false);
        SsoAudit.LoginSucceeded(_logger, identity.AuditProtocol, identity.Provider, identity.Username, identity.Admin);

        // #1139: counted beside the audit line rather than at a new hook point, so the counter and the trail
        // cannot come apart. Here rather than in the status mapper because a success reaches the mapper too,
        // and counting at both would double every login.
        SsoMetrics.LoginSucceeded(identity.Provider);

        // Stamp the link the login resolved (#1120), at the one point that knows both that the mint succeeded
        // and which link carried it. Placed AFTER the mint on purpose: a refused or failed login must leave no
        // trace in a field the roster presents as "last SSO login", and a stamp written before the mint would
        // record attempts. Bounded and coalesced inside the service - see RecordLastSsoLogin - so an
        // established user's repeat login still pays no configuration persist.
        _canonicalLinks.RecordLastSsoLogin(identity.LinkMode, identity.Provider, identity.Subject);

        CaptureLogoutState(identity, userId, logoutContext, authenticationResult);

        return LoginStatusMapper.ToActionResult(new LoginOutcome.Success(authenticationResult));
    }

    // Enforces a configured account-expiry deadline against the resolved account (#1144). Returns the
    // refusal to send, or null to let the login continue.
    //
    // THE GUARD (T-D1, mass-lockout defence): an administrator is exempt from the whole gate, not merely
    // from the disable. An identity provider that starts emitting a past instant - or a claim mapped to the
    // wrong attribute - must be able to strand at most the non-admin accounts, so an administrator both
    // stays enabled and stays able to log in and repair the configuration. That is why the exemption is read
    // from the RESOLVED account before anything else happens rather than inferred from a disable that
    // declined to act; the two are not the same, and only the first keeps the recovery door open. The basis
    // is the account, never identity.Admin, which is the identity provider's own say-so.
    //
    // A configured claim that produced no readable instant refuses the login and disables nothing. Granting
    // unlimited access on a claim the reader could not parse would make a transient identity-provider change
    // indistinguishable from an unlimited account, and disabling on it would make that same transient change
    // indistinguishable from a real expiry - so the fail-closed answer is to refuse this login and leave the
    // account exactly as it was.
    private async Task<ActionResult?> EnforceAccountExpiryAsync(VerifiedIdentity identity, Guid userId)
    {
        if (_canonicalLinks.IsAccountAdministrator(userId))
        {
            return null;
        }

        if (identity.ExpiresAtUtc is not { } deadline)
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.AccessExpired));
        }

        if (deadline > DateTime.UtcNow)
        {
            // Persist the still-future deadline beside the link (#1145). This is the ONLY writer of that
            // map, and it is what makes the deadline enforceable between logins: the gate above only fires
            // when the expired user comes back, so a guest who simply stops logging in would otherwise keep
            // an enabled account and any long-lived token for as long as those tokens happen to live. It is
            // deliberately not reached for an administrator, who returned above - the mass-lockout exemption
            // (T-D1) is stated once, and an account the sweep may not act on is one it should not carry a
            // deadline for.
            _canonicalLinks.RecordAccountDeadline(identity.LinkMode, identity.Provider, identity.Subject, deadline);
            return null;
        }

        // Fired at the transition only. A second expired login finds the account already disabled, the
        // disable returns false, and neither the audit line nor the revocation runs again - so a login loop
        // against an expired identity cannot flood the trail or mass-revoke on every attempt.
        if (await _canonicalLinks.DisableExpiredAccountAsync(identity.LinkMode, identity.Provider, identity.Subject, identity.Issuer).ConfigureAwait(false))
        {
            SsoAudit.AccountExpired(_logger, identity.AuditProtocol, identity.Provider);

            // Without this, "time-limited" means only that no NEW session is minted while a token issued
            // before the deadline keeps working until it expires on its own. Scoped strictly to this one
            // user id, which is what separates it from the per-provider disable that deliberately does not
            // revoke (#468): there the id is one of many behind a provider and revoking would be an
            // unscoped mass-logout, here it is the single subject whose access just ended. Runs after the
            // disable is persisted, so a revoke that throws leaves the account already disabled rather than
            // the pair half-done.
            await _sessionManager.RevokeUserTokens(userId, null).ConfigureAwait(false);
        }

        return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.AccessExpired));
    }

    // Persist the per-session Single Logout state (#727, SLO-1b), only when the feature is on. Runs AFTER a
    // successful mint and is fully fail-safe: the session is already live, so a capture problem must never
    // turn a good login into a failure - any error is logged and swallowed. Keyed by the minted session id
    // (never a secret); a missing session id or logout context simply skips capture.
    private void CaptureLogoutState(VerifiedIdentity identity, Guid userId, LogoutContext? logoutContext, AuthenticationResult authenticationResult)
    {
        if (logoutContext is not { } context)
        {
            return;
        }

        try
        {
            if (!_configStore.Read(configuration => configuration.EnableSingleLogout))
            {
                return;
            }

            var sessionKey = authenticationResult.SessionInfo?.Id;
            if (string.IsNullOrEmpty(sessionKey))
            {
                return;
            }

            var state = new LogoutSession
            {
                Protocol = identity.AuditProtocol,
                Provider = identity.Provider,
                Subject = identity.Subject,
                SessionIndex = context.SessionIndex,
                Issuer = identity.Issuer,
                IdToken = context.IdToken,
                EndSessionEndpoint = context.EndSessionEndpoint,
                UserId = userId,
            };

            _configStore.Mutate(configuration => SessionLogoutStore.Capture(configuration, sessionKey, state, DateTime.UtcNow));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to capture the Single Logout session state after a successful login; logout propagation will be unavailable for this session.");
        }
    }
}
