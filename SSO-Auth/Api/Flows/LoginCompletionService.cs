// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Linq;
using System.Threading.Tasks;
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

/// <summary>The one completion path both protocols funnel into once validation has produced a <see cref="VerifiedIdentity"/>: resolve the account, mint the session, audit (#473).</summary>
/// <remarks>
/// It takes a <see cref="VerifiedIdentity"/> and nothing rawer, so a mint without validation is a compile error, and it
/// holds no <c>HttpContext</c>. See <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Login-Flow#the-shape-both-flows-share"/>.
/// </remarks>
internal sealed class LoginCompletionService
{
    private readonly CanonicalLinkService _canonicalLinks;
    private readonly SessionMinter _sessionMinter;
    private readonly SsoOnlyLoginService _ssoOnly;
    private readonly ProviderConfigStore _configStore;
    private readonly ISessionManager _sessionManager;
    private readonly ILogger _logger;

    /// <summary>Initializes a new instance of the <see cref="LoginCompletionService"/> class.</summary>
    /// <param name="canonicalLinks">The account-linking workflow (resolve/adopt/create).</param>
    /// <param name="sessionMinter">The session minter run under the in-flight revocation gate.</param>
    /// <param name="ssoOnly">The SSO-only login enforcement service.</param>
    /// <param name="configStore">The provider configuration store.</param>
    /// <param name="sessionManager">Jellyfin's session manager, which revokes an expired account's live tokens (#1144).</param>
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

    /// <summary>Completes a login from its verified identity: resolve or create the account, build the session parameters, and mint under the revocation gate.</summary>
    /// <param name="identity">The fully-verified login identity and privileges (#473).</param>
    /// <param name="response">The client's auth request context (app/device), carried into the session mint.</param>
    /// <param name="config">The provider configuration governing authorization/folder/default-provider grants.</param>
    /// <param name="adoptionGate">The extra proof a same-named adoption must clear; the one per-protocol input (#218).</param>
    /// <param name="remoteEndPointResolver">Resolves the normalized client IP for the activity log, evaluated inside the minter (#177).</param>
    /// <param name="logoutContext">The Single Logout material captured at the callback, persisted after the mint only when the feature is on (#727).</param>
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
                // An absolute instant from the provider wins over the role-mapped duration, stated once here (#1143, #1146).
                identity.ExpiresAtUtc is null ? identity.GuestAccessDuration : null,
                config.SyncUsernameFromProvider,
                // Handed down as a name, so the create arm resolves it inside its own locked read (#1106).
                identity.ProvisioningProfile).ConfigureAwait(false);
        }
        catch (AccountLinkForbiddenException)
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.AccountLinkForbidden));
        }

        // Ahead of the approval gate, so an account this path disabled is refused under its own reason (#1144).
        if (!string.IsNullOrWhiteSpace(config.AccountExpiryClaim))
        {
            var expiryRefusal = await EnforceAccountExpiryAsync(identity, userId).ConfigureAwait(false);
            if (expiryRefusal is not null)
            {
                return expiryRefusal;
            }
        }

        // A disabled account gets no session, before any repoint or mint side effect; nothing here disables one (#737).
        if (_canonicalLinks.IsAccountAwaitingApproval(userId))
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.AwaitingApproval));
        }

        // Decided on the resolved account rather than the provider-supplied username, so it matches the sweep (#165).
        var configuredDefaultProvider = config.DefaultProvider?.Trim();
        var enforcement = _ssoOnly.ResolveLoginEnforcement(userId, configuredDefaultProvider);

        var sessionParameters = SessionParametersFor(identity, response, config, userId, enforcement);

        // The minter re-checks the link before any side effect and again last before the mint (#232).
        var authenticationResult = await _sessionMinter.MintAsync(
            sessionParameters,
            remoteEndPointResolver,
            () => _canonicalLinks.IsIdentityStillLinked(identity.LinkMode, identity.Provider, identity.Subject, userId)).ConfigureAwait(false);

        // The name and the privilege are the host's own from the same result it publishes; named arguments because the two booleans are opposites (#1551, #1554).
        var mintedUsername = MintedUsername(authenticationResult, identity);
        SsoAudit.LoginSucceeded(
            _logger,
            identity.AuditProtocol,
            identity.Provider,
            mintedUsername,
            grantedAdmin: GrantedAdmin(authenticationResult),
            mappedAdmin: identity.Admin,
            presentedUsername: identity.Username);

        // Counted beside the audit line, so the counter and the trail cannot come apart (#1139).
        SsoMetrics.LoginSucceeded(identity.Provider);

        // After the mint, so a refused login leaves no trace in a field the roster shows as the last login (#1120).
        _canonicalLinks.RecordLastSsoLogin(identity.LinkMode, identity.Provider, identity.Subject);

        // A minted session proves the account is not inert, and this is the only moment the plugin learns it (#1529, #1637).
        _canonicalLinks.ClearPendingApprovalAfterLogin(identity.LinkMode, identity.Provider, identity.Subject);

        CaptureLogoutState(identity, userId, logoutContext, authenticationResult);

        return LoginStatusMapper.ToActionResult(new LoginOutcome.Success(authenticationResult));
    }

    // An administrator is exempt from the whole gate, read off the resolved account, so a bad claim can strand at most the non-admin accounts (#1144).
    private async Task<ActionResult?> EnforceAccountExpiryAsync(VerifiedIdentity identity, Guid userId)
    {
        if (_canonicalLinks.IsAccountAdministrator(userId))
        {
            return null;
        }

        // A configured claim with no readable instant refuses the login and disables nothing.
        if (identity.ExpiresAtUtc is not { } deadline)
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.AccessExpired));
        }

        if (deadline > DateTime.UtcNow)
        {
            // The only writer of the deadline map, which is what makes the deadline enforceable between logins (#1145).
            _canonicalLinks.RecordAccountDeadline(identity.LinkMode, identity.Provider, identity.Subject, deadline);
            return null;
        }

        // At the transition only, so a login loop against an expired identity cannot flood the trail.
        if (await _canonicalLinks.DisableExpiredAccountAsync(identity.LinkMode, identity.Provider, identity.Subject, identity.Issuer).ConfigureAwait(false))
        {
            SsoAudit.AccountExpired(_logger, identity.AuditProtocol, identity.Provider);

            // Scoped to the one account whose access ended, after the disable is persisted (#468).
            await _sessionManager.RevokeUserTokens(userId, null).ConfigureAwait(false);
        }

        return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.AccessExpired));
    }

    // Fail-safe after a successful mint: a capture problem must never turn a live session into a failed login (#727).
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

    // The host's own published name, with the presented name as the fallback because an audit line is never worth failing a login (#1551).
    private static string MintedUsername(AuthenticationResult? authenticationResult, VerifiedIdentity identity)
        => string.IsNullOrEmpty(authenticationResult?.User?.Name) ? identity.Username : authenticationResult.User.Name;

    // Null rather than a guessed false when the host returned no user, which is the under-reporting direction (#1554).
    private static bool? GrantedAdmin(AuthenticationResult? authenticationResult)
        => authenticationResult?.User?.Policy?.IsAdministrator;

    // The mint's inputs, from the verified identity and the resolved account rather than from the request.
    private static SessionParameters SessionParametersFor(VerifiedIdentity identity, AuthResponse response, ProviderConfigBase config, Guid userId, SsoOnlyLoginDecision enforcement) => new SessionParameters
    {
        UserId = userId,
        IsAdmin = identity.Admin,
        IsBreakGlassAdmin = enforcement.IsBreakGlassAdmin,
        EnableAuthorization = config.EnableAuthorization,
        EnableAllFolders = config.EnableAllFolders,
        EnabledFolders = identity.Folders.ToArray(),
        ManagedFolders = config.PreserveUnmanagedFolders ? UnmanagedFolderMerge.ManagedBy(config) : null,
        EnableLiveTv = identity.EnableLiveTv,
        EnableLiveTvManagement = identity.EnableLiveTvManagement,
        PermissionGrants = identity.PermissionGrants,
        MaxParentalRatingScore = identity.MaxParentalRatingScore,
        SyncPlayAccess = identity.SyncPlayAccess,
        AuthResponse = response,
        DefaultProvider = enforcement.DefaultProvider,
        Avatar = identity.Avatar,
    };
}
