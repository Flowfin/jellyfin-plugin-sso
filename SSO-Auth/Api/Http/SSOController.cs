// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Logout;
using Jellyfin.Plugin.SSO_Auth.Api.Metrics;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Api;
using MediaBrowser.Common.Extensions;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Configuration;
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

/// <summary>
/// The sso api controller.
/// </summary>
[ApiController]
[Route("[controller]")]
public class SSOController : ControllerBase
{
    // The uniform-rejection policy and its bodies live on LoginStatusMapper; the direct provider-lookup
    // rejections that stay in the controller reuse its NoMatchingProviderMessage so the wording is
    // defined once (#318).
    private const string NoMatchingProviderMessage = LoginStatusMapper.NoMatchingProviderMessage;

    // The refusal body for an unrecognized {mode} route token (#1399), named here beside the other fixed
    // refusal wordings. It names the two accepted tokens and never echoes the supplied one.
    private const string UnknownModeMessage = "The mode segment must be 'oid' or 'saml'.";

    // Display names for the audit log (the internal link-map mode tokens are the lowercase "oid"/"saml").
    private const string OpenIdProtocol = "OpenID";
    private const string SamlProtocol = "SAML";

    // Hard cap on the config-import request body (#161): a whole plugin configuration is small (kilobytes),
    // so 1 MiB is generous headroom while an oversized document is rejected fail-closed (413) before it is
    // parsed, rather than being deserialized into memory.
    private const long ConfigImportMaxBytes = 1024 * 1024;

    private readonly IUserManager _userManager;
    // The shared login-completion tail (#160, #318): resolve/adopt the link, build the session parameters,
    // mint under the revocation gate, audit, map to a LoginOutcome. The controller passes the
    // HttpContext-derived remote endpoint in and keeps no session/avatar field.
    private readonly LoginCompletionService _loginCompletion;
    // Kept so a hard revoke (Unregister) can also terminate the user's already-issued tokens (#440); the
    // minter takes its own reference for the login path.
    private readonly ISessionManager _sessionManager;
    private readonly IAuthorizationContext _authContext;
    private readonly ILogger<SSOController> _logger;
    private readonly ICryptoProvider _cryptoProvider;
    // Kept so the elevation-gated Test-connection endpoints (#163) can read a provider's OpenID discovery
    // through the SAME hardened reader the login uses; the shared login flow takes its own reference.
    private readonly IHttpClientFactory _httpClientFactory;

    // The account-linking workflow (resolve/adopt/create, legacy re-key, revoke); the controller keeps
    // the authz guards, the one-time-use replay/state consume, and the HTTP mapping (#318).
    private readonly CanonicalLinkService _canonicalLinks;

    // The SSO-only login enforcement (#165): the fail-closed last-admin guard, the per-user provider-id
    // sweep, and the reversible off-switch. The controller keeps the RequiresElevation guards, the actor
    // resolution, and the audit; the service keeps the account enumeration and the mode-flag writes.
    private readonly SsoOnlyLoginService _ssoOnly;
    // The OpenID login flow (#160, #318 step 12): challenge, redirect callback, session-minting
    // authenticate, and manual link. It owns the OpenID-specific process-wide caches (the authorize-state
    // store and the discovery-facts cache) as its own statics; the controller's OpenID endpoints apply the
    // shared rate-limit gate (SsoRateLimitGate) and delegate here. New'd per request like the other collaborators.
    private readonly Flows.OidcLoginService _oidc;
    // The SAML login flow (#160, #318 step 13): challenge, assertion-consumer callback, session-minting
    // authenticate, and manual link. It owns the SAML-specific process-wide caches (the replay cache and
    // the outstanding-AuthnRequest cache) as its own statics; the controller's SAML endpoints apply the
    // shared rate-limit gate (SsoRateLimitGate) and delegate here. New'd per request like the other collaborators.
    private readonly Flows.SamlLoginService _saml;

    // The shared per-client rate limiter and its opt-in check live in SsoRateLimitGate (#160, #318): the last
    // mutable process-wide static moved off the controller into the Shared tier, so the controller now holds
    // no mutable static state. The RateLimitCheck wrapper below supplies the request-scoped inputs.

    /// <summary>
    /// Initializes a new instance of the <see cref="SSOController"/> class.
    /// </summary>
    /// <param name="logger">Instance of the <see cref="ILogger{SSOController}"/> interface.</param>
    /// <param name="loggerFactory">Instance of the <see cref="ILoggerFactory"/> interface.</param>
    /// <param name="sessionManager">Instance of the <see cref="ISessionManager"/> interface.</param>
    /// <param name="authContext">Instance of the <see cref="IAuthorizationContext"/> interface.</param>
    /// <param name="userManager">Instance of the <see cref="IUserManager"/> interface.</param>
    /// <param name="cryptoProvider">Instance of the <see cref="ICryptoProvider"/> interface.</param>
    /// <param name="providerManager">Instance of the <see cref="IProviderManager"/> interface.</param>
    /// <param name="httpClientFactory">Instance of the <see cref="IHttpClientFactory"/> interface.</param>
    /// <param name="serverConfigurationManager">Instance of the <see cref="IServerConfigurationManager"/> interface.</param>
    /// <param name="displayPreferencesManager">Instance of the <see cref="IDisplayPreferencesManager"/> interface, the store a templated home-screen layout is seeded into (#1101).</param>
    public SSOController(
        ILogger<SSOController> logger,
        ILoggerFactory loggerFactory,
        ISessionManager sessionManager,
        IUserManager userManager,
        IAuthorizationContext authContext,
        ICryptoProvider cryptoProvider,
        IProviderManager providerManager,
        IHttpClientFactory httpClientFactory,
        IServerConfigurationManager serverConfigurationManager,
        IDisplayPreferencesManager displayPreferencesManager)
    {
        _userManager = userManager;
        _authContext = authContext;
        _cryptoProvider = cryptoProvider;
        _logger = logger;
        _sessionManager = sessionManager;
        _httpClientFactory = httpClientFactory;
        _canonicalLinks = new CanonicalLinkService(userManager, cryptoProvider, SSOPlugin.Instance.ConfigStore, logger, displayPreferences: displayPreferencesManager);
        _ssoOnly = new SsoOnlyLoginService(userManager, SSOPlugin.Instance.ConfigStore, logger);
        var avatarService = new AvatarService(userManager, providerManager, serverConfigurationManager, logger, SsoHttp.UserAgent);
        var sessionMinter = new SessionMinter(userManager, avatarService, sessionManager, logger);
        _loginCompletion = new LoginCompletionService(_canonicalLinks, sessionMinter, _ssoOnly, SSOPlugin.Instance.ConfigStore, sessionManager, logger);
        _oidc = new Flows.OidcLoginService(_loginCompletion, _canonicalLinks, httpClientFactory, loggerFactory, logger);
        _saml = new Flows.SamlLoginService(_loginCompletion, _canonicalLinks, logger);
        _logger.LogInformation("SSO Controller initialized");
    }

    /// <summary>
    /// The GET endpoint for OpenID provider to callback to. Returns a webpage that parses client data and completes auth.
    /// </summary>
    /// <param name="provider">The ID of the provider which will use the callback information.</param>
    /// <param name="state">The current request state.</param>
    /// <returns>A webpage that will complete the client-side flow.</returns>
    // Actually a GET: https://github.com/IdentityModel/IdentityModel.OidcClient/issues/325
    [HttpGet("OID/r/{provider}")]
    [HttpGet("OID/redirect/{provider}")]
    public async Task<ActionResult> OidCallback(
        [FromRoute] string provider,
        [FromQuery] string state)
    {
        if (RateLimitCheck(SsoRateLimitClass.Callback) is { } throttled)
        {
            return BrowserErrorPage.Wrap(throttled, Request, Response);
        }

        // The OpenID redirect callback lives in the flow service (#160, #318): it validates the
        // browser-bound state, exchanges the code, validates the id_token and RFC 9207 response issuer,
        // applies the role gate, and renders the security-headered intermediate auth page on the response.
        // This endpoint is browser-navigated, so a plain-text rejection is restyled as an HTML page (#668).
        return BrowserErrorPage.Wrap(await _oidc.CallbackAsync(provider, state, Request, Response).ConfigureAwait(false), Request, Response);
    }

    /// <summary>
    /// Initiates the login flow for OpenID. This redirects the user to the auth provider.
    /// </summary>
    /// <param name="provider">The name of the provider.</param>
    /// <param name="isLinking">Whether or not this request is to link accounts (Rather than authenticate).</param>
    /// <returns>An asynchronous result for the authentication.</returns>
    [HttpGet("OID/p/{provider}")]
    [HttpGet("OID/start/{provider}")]
    public async Task<ActionResult> OidChallenge(string provider, [FromQuery] bool isLinking = false)
    {
        if (RateLimitCheck(SsoRateLimitClass.Challenge) is { } throttled)
        {
            return BrowserErrorPage.Wrap(throttled, Request, Response);
        }

        // The OpenID challenge lives in the flow service (#160, #318): it reads discovery, applies the
        // PKCE gate, prepares the authorization request, registers the browser-bound authorize state, and
        // redirects to the identity provider (setting the binding cookie on the response).
        // This endpoint is browser-navigated, so a plain-text rejection is restyled as an HTML page (#668).
        return BrowserErrorPage.Wrap(await _oidc.ChallengeAsync(provider, isLinking, Request, Response).ConfigureAwait(false), Request, Response);
    }

    /// <summary>
    /// RP-initiated OpenID logout (#727, SLO-2). Ends the CALLER's local Jellyfin session, then - when the
    /// caller has a captured OpenID session for this provider (Single Logout enabled) - redirects the browser
    /// to the identity provider's <c>end_session_endpoint</c> with the stored <c>id_token_hint</c>, so the IdP
    /// session is terminated too. Fail-safe: a missing/unsafe endpoint or a disabled feature degrades to a
    /// local-only logout (the browser returns to this server). Authenticated, and every action is scoped
    /// strictly to the caller's own user id - a user can only log THEMSELVES out.
    /// </summary>
    /// <param name="provider">The OpenID provider to end the session at.</param>
    /// <returns>A redirect to the IdP end-session URL, or to this server for a local-only logout.</returns>
    [Authorize]
    [HttpGet("OID/logout/{provider}")]
    public async Task<ActionResult> OidLogout(string provider)
    {
        var auth = await _authContext.GetAuthorizationInfo(HttpContext.Request).ConfigureAwait(false);

        // The caller's most recent captured OpenID session for this provider (an id_token distinguishes an
        // OpenID capture from a SAML one). Scoped to the caller's own user id, read under the config lock.
        // Best-effort with multiple concurrent sessions: "most recent" may differ from the exact session the
        // local Logout below ends, but both belong to the caller and the id_token_hint is a valid token for
        // the same subject at the same issuer, so RP-initiated logout is still correct - a within-user,
        // best-effort SLO, never a cross-user effect (FindByUser is user-id-scoped and empty for Guid.Empty).
        var match = SSOPlugin.Instance.ReadConfiguration(configuration =>
            SessionLogoutStore.FindByUser(configuration, auth.UserId)
                .FirstOrDefault(pair =>
                    string.Equals(pair.Value.Provider, provider, StringComparison.Ordinal)
                    && !string.IsNullOrEmpty(pair.Value.IdToken)));

        // End the caller's local Jellyfin session (their current token only), then drop the consumed entry so
        // the id_token is not retained past the logout.
        if (!string.IsNullOrEmpty(auth.Token))
        {
            await _sessionManager.Logout(auth.Token).ConfigureAwait(false);
        }

        if (match.Value is not null)
        {
            SSOPlugin.Instance.MutateConfiguration(configuration => SessionLogoutStore.Remove(configuration, match.Key));
        }

        var config = SSOPlugin.Instance.ReadConfiguration(configuration =>
            configuration.OidConfigs.TryGetValue(provider, out var oidConfig) ? oidConfig : null);

        // This server's canonical base - the allow-list root for the post-logout return URL, and the
        // local-only fallback target. Derived exactly as the login builds its own external URLs.
        var canonicalBase = CanonicalBaseUrl.Resolve(
            config?.BaseUrlOverride, Request.Scheme, Request.Host.Host, Request.Host.Port, Request.PathBase, config?.SchemeOverride, config?.PortOverride);

        string? endSessionUrl = null;
        if (match.Value is { } captured)
        {
            try
            {
                // Reveal the encrypted id_token only now, at the moment it is sent as the id_token_hint.
                endSessionUrl = OidcLogout.BuildEndSessionUrl(
                    captured.EndSessionEndpoint,
                    captured.Issuer,
                    SSOPlugin.Instance.Secrets.Reveal(captured.IdToken),
                    config?.OidClientId,
                    config?.PostLogoutRedirectUri,
                    canonicalBase);
            }
            catch (Exception ex)
            {
                // Fail-safe: the local logout already completed above. A reveal fault (a missing/corrupt
                // at-rest key, as TryReveal guards on the login path) or a build fault must degrade to a
                // local-only logout, never surface a 500 - honouring the endpoint's stated contract.
                _logger.LogError(ex, "Building the OpenID end-session redirect failed; the local logout stands and the browser returns to this server.");
            }
        }

        // Redirect to the IdP end-session URL (an absolute URL host-bound to the discovered issuer by
        // OidcLogout), or - local-only - back to this server via a LOCAL redirect. The local fallback must NOT
        // reuse the canonical base as an absolute target: with no Base URL Override that base is derived from
        // the request Host header, so a spoofed Host would turn the fallback into an open redirect. A local
        // ("~/") redirect is host-independent and ASP.NET Core rejects any non-local value outright.
        return endSessionUrl is null ? LocalRedirect("~/") : Redirect(endSessionUrl);
    }

    /// <summary>
    /// Inbound OpenID Connect back-channel logout (#962, OIDC Back-Channel Logout 1.0). The identity provider
    /// POSTs a signed <c>logout_token</c> here to propagate an IdP-side session termination into Jellyfin.
    /// The endpoint is ANONYMOUS - the token's signature is the only authenticator - so it is fail-closed at
    /// every step: a disabled feature, an unknown/disabled provider, and a provider without the per-provider
    /// opt-in all collapse to the SAME uniform response WITHOUT parsing the token, and the validated (sub, sid)
    /// revokes only the matched user's OpenID sessions for THIS provider (never cross-provider, never a SAML
    /// capture, never another user). Rate-limited on the Logout class. Every rejection audits a fixed reason
    /// code and discloses no subject identifier.
    /// </summary>
    /// <param name="provider">The OpenID provider the logout_token arrived for.</param>
    /// <param name="logoutToken">The <c>logout_token</c> form field (model-bound; a non-form POST binds null and is rejected).</param>
    /// <returns>200 when a validated token revoked at least one session, else a uniform 400 with no cause detail.</returns>
    [HttpPost("OID/backchannel-logout/{provider}")]
    public async Task<ActionResult> OidBackChannelLogout(string provider, [FromForm(Name = "logout_token")] string? logoutToken = null)
    {
        if (RateLimitCheck(SsoRateLimitClass.Logout) is { } throttled)
        {
            return throttled;
        }

        // Read the master switch, the per-provider opt-in, AND the provider config in one lock acquisition.
        // A disabled feature, a provider without the opt-in, an unknown provider, and a disabled provider all
        // collapse to the ONE uniform 400 below, and NONE of them reads the untrusted token - so the signed-JWT
        // sink is unreachable while the feature is off, and neither the feature state nor the provider set can
        // be probed apart.
        var (enabled, config) = SSOPlugin.Instance.ReadConfiguration(configuration =>
            (configuration.EnableSingleLogout, configuration.OidConfigs.TryGetValue(provider, out var oidConfig) ? oidConfig : null));

        if (!enabled || config is not { Enabled: true, EnableBackChannelLogout: true })
        {
            return UniformBackChannelLogoutRejection();
        }

        // Read discovery for the JWKS + issuer, then validate signature + every §2.6 rule (events member, no
        // nonce, sub/sid present, jti one-time-use) via the SAME hardened basis the id_token uses. On any
        // failure the reason code is a FIXED constant (never token-derived) written only to the audit trail;
        // the caller sees the uniform 400 with no branch-distinguishing detail (no subject oracle).
        var result = await _oidc.ValidateBackChannelLogoutAsync(config, provider, logoutToken).ConfigureAwait(false);
        if (!result.IsValid)
        {
            // Two refusals of opposite kinds leave this one branch, so they are recorded as two events rather
            // than as one line an operator has to read a reason code out of (#1184). A forged, replayed or
            // malformed token is the system working and nothing was meant to be terminated; a provider the
            // plugin could not reach means the IdP ordered a termination that did not happen, and the session
            // it named is still running. The choice is made HERE, at the event source, rather than inside a
            // shared audit gate that would have to re-derive it (#737). The response is the same uniform 400
            // either way - the distinction is for the trail, never for the caller.
            if (string.Equals(result.ReasonCode, OidcLogoutTokenValidator.RejectReason.ProviderUnreachable, StringComparison.Ordinal))
            {
                SsoAudit.BackChannelLogoutNotPerformed(_logger, provider, result.ReasonCode);
            }
            else
            {
                SsoAudit.BackChannelLogoutRejected(_logger, provider, result.ReasonCode);
            }

            return UniformBackChannelLogoutRejection();
        }

        // Resolve the targeted sessions - strictly the SAME provider and subject (ordinal exact), AND only
        // OpenID captures. FindByProviderSubject filters by (provider, subject) as the blast-radius bound; the
        // Protocol filter keeps OpenID and SAML apart (an OpenID and a SAML provider can share a config name
        // and a subject string). When the token names a sid, keep only entries whose captured SessionIndex
        // matches; a token with sub but no sid targets every OpenID session of that subject for this provider
        // (§2.4). A token with sid but no sub is matched by sid alone (subject is then whatever captured it).
        var matches = SSOPlugin.Instance.ReadConfiguration(configuration =>
            SessionLogoutStore
                .FindByProviderSubject(configuration, provider, result.Subject ?? string.Empty, result.SessionIndex ?? string.Empty)
                .Where(pair => string.Equals(pair.Value.Protocol, OpenIdProtocol, StringComparison.Ordinal))
                .ToList());

        // When the token carries no sub (sid-only), FindByProviderSubject's empty-subject guard returns
        // nothing, so match on sid across this provider's OpenID captures directly.
        if (result.Subject is null && result.SessionIndex is not null)
        {
            matches = SSOPlugin.Instance.ReadConfiguration(configuration =>
                configuration.LogoutSessions
                    .Where(pair =>
                        string.Equals(pair.Value.Protocol, OpenIdProtocol, StringComparison.Ordinal)
                        && string.Equals(pair.Value.Provider, provider, StringComparison.Ordinal)
                        && string.Equals(pair.Value.SessionIndex, result.SessionIndex, StringComparison.Ordinal))
                    .ToList());
        }

        // A validated token resolving NO session is the "unknown-subject" case: render the SAME uniform 400.
        // An anonymous attacker can never produce a valid signature to reach here, so this discloses nothing;
        // only the trusted IdP (which already knows its own subjects) can tell it from a 200, which is fine.
        if (matches.Count == 0)
        {
            // Benign, so it stays in the rejection class: the token was good and there was simply nothing of
            // this provider's to end - not a termination that was ordered and skipped.
            SsoAudit.BackChannelLogoutRejected(_logger, provider, "no_matching_session");
            return UniformBackChannelLogoutRejection();
        }

        // Revoke the tokens of each DISTINCT matched user - the SAME user-scoped fail-SAFE loop the inbound
        // SAML logout uses: a revoke fault for one user must not abort the others, and only the entries whose
        // user was actually revoked are consumed (a transient fault leaves the entry for a later retry).
        var succeeded = new HashSet<Guid>();
        foreach (var userId in matches.Select(pair => pair.Value.UserId).Distinct())
        {
            try
            {
                await _sessionManager.RevokeUserTokens(userId, null).ConfigureAwait(false);
                succeeded.Add(userId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Revoking tokens during OpenID back-channel logout failed for one user; the remaining matched users are still logged out.");
            }
        }

        var consumedKeys = matches.Where(pair => succeeded.Contains(pair.Value.UserId)).Select(pair => pair.Key).ToList();
        if (consumedKeys.Count > 0)
        {
            SSOPlugin.Instance.MutateConfiguration(configuration =>
            {
                foreach (var key in consumedKeys)
                {
                    SessionLogoutStore.Remove(configuration, key);
                }
            });
        }

        if (succeeded.Count == 0)
        {
            // A validated token matched sessions and every revoke threw: the clearest instance of the class -
            // the IdP ordered a termination, the plugin agreed it was legitimate, and nothing was terminated.
            SsoAudit.BackChannelLogoutNotPerformed(_logger, provider, "revoke_failed");
            return UniformBackChannelLogoutRejection();
        }

        SsoAudit.LogoutRequested(_logger, provider, succeeded.Count);

        // §2.7: a 200 with no body signals success. The IdP is the only party that can distinguish this from
        // the uniform 400, and it already knows its own subjects - no oracle for an anonymous caller.
        return Ok();
    }

    /// <summary>
    /// SP-initiated outbound SAML Single Logout (#727, SLO-3c). Ends the CALLER's local Jellyfin session, then
    /// - when Single Logout is enabled, the provider has a configured SLO endpoint, a signing key loads, and the
    /// caller has a captured SAML session with a NameID - redirects the browser to the identity provider's
    /// Single-Logout endpoint with a SIGNED <c>LogoutRequest</c>, so the IdP session is terminated too.
    /// Fail-safe: a missing SLO endpoint, a missing/unloadable signing key, or no captured session degrades to a
    /// local-only logout (a host-independent redirect back to this server) - none of those must ever break the
    /// local logout or 500. Authenticated, rate-limited, and every action is scoped strictly to the caller's own
    /// user id - a user can only log THEMSELVES out, and the LogoutRequest can only ever carry the caller's own
    /// NameID.
    /// </summary>
    /// <param name="provider">The SAML provider to end the session at.</param>
    /// <returns>A redirect to the IdP SLO URL, or to this server for a local-only logout.</returns>
    [Authorize]
    [HttpGet("SAML/logout/{provider}")]
    public async Task<ActionResult> SamlSpLogout(string provider)
    {
        // Deliberately NOT rate-limited, matching the authenticated OID/logout route: the Logout rate-limit
        // class guards the ANONYMOUS inbound SAML LogoutRequest endpoint (SLO-3b). Throttling this
        // [Authorize] self-logout would risk leaving the caller's own local session live under throttle -
        // a security action must always be able to end the caller's session, and the route already requires
        // a valid session to reach.
        var auth = await _authContext.GetAuthorizationInfo(HttpContext.Request).ConfigureAwait(false);

        // Read the Single Logout feature flag, the provider config, AND the caller's most recent captured SAML
        // session for this provider in one lock acquisition. Scoped to the caller's own user id (FindByUser is
        // user-id-scoped and empty for Guid.Empty), and filtered to a SAML capture - a SAML session carries no
        // id_token, so the Protocol tag distinguishes it from an OpenID capture for the same provider. The
        // captured Subject is the caller's own NameID; nothing here can read another user's session.
        var (singleLogoutEnabled, config, match) = SSOPlugin.Instance.ReadConfiguration(configuration =>
            (configuration.EnableSingleLogout,
             configuration.SamlConfigs.TryGetValue(provider, out var samlConfig) ? samlConfig : null,
             SessionLogoutStore.FindByUser(configuration, auth.UserId)
                 .FirstOrDefault(pair =>
                     string.Equals(pair.Value.Provider, provider, StringComparison.Ordinal)
                     && string.Equals(pair.Value.Protocol, SamlProtocol, StringComparison.Ordinal))));

        // End the caller's local Jellyfin session (their current token only) in EVERY path, then drop the
        // consumed entry so the captured session state is not retained past the logout.
        if (!string.IsNullOrEmpty(auth.Token))
        {
            await _sessionManager.Logout(auth.Token).ConfigureAwait(false);
        }

        if (match.Value is not null)
        {
            SSOPlugin.Instance.MutateConfiguration(configuration => SessionLogoutStore.Remove(configuration, match.Key));
        }

        // Build the signed LogoutRequest redirect only when everything the SP-initiated path needs is present:
        // the feature is on, the caller has a captured SAML session naming a NameID, the provider is configured
        // with an SLO endpoint, and a signing key loads. ANY missing piece - or any fault building/signing -
        // fails SAFE to a local-only logout, never a 500 (the local logout already completed above).
        string? sloRedirectUrl = null;
        if (singleLogoutEnabled && config is not null && match.Value is { } captured && !string.IsNullOrEmpty(captured.Subject))
        {
            try
            {
                sloRedirectUrl = BuildSamlSloRedirectUrl(config, captured);
            }
            catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or CryptographicException or FormatException)
            {
                // Fail-safe: the local logout already stands. A missing/unloadable signing key
                // (InvalidOperationException/CryptographicException), a corrupt at-rest secret envelope
                // (FormatException), or a signer rejection (ArgumentException) degrades to a local-only logout
                // rather than surfacing a 500. Key material is never part of the message, so nothing sensitive
                // is logged.
                if (_logger.IsEnabled(LogLevel.Error))
                {
                    _logger.LogError("SAML SP-initiated logout for provider {Provider} could not build the signed LogoutRequest: {Reason}; the local logout stands and the browser returns to this server.", provider?.ReplaceLineEndings(string.Empty), ex.Message);
                }
            }
        }

        // Redirect to the IdP SLO URL (the SLO endpoint is validated as an absolute https URL at save), or -
        // local-only - back to this server via a LOCAL redirect. As with the OpenID logout, the local fallback
        // uses a host-independent "~/" redirect rather than a request-Host-derived absolute target, so a spoofed
        // Host can never turn the fallback into an open redirect.
        return sloRedirectUrl is null ? LocalRedirect("~/") : Redirect(sloRedirectUrl);
    }

    // Builds the signed SP-initiated LogoutRequest redirect URL for a captured SAML session (#727, SLO-3c), or
    // null when SP-initiated SLO is not configured (no SLO endpoint). Fail-closed on the signing key: a missing
    // or unloadable key returns null (the caller degrades to local-only) rather than sending an UNSIGNED
    // LogoutRequest - the SLO redirect binding requires a signature, so an unsigned downgrade is never emitted.
    // Reuses the outbound-signing infrastructure verbatim: the encrypted-at-rest signing key is revealed at the
    // point of use (mirroring the challenge), loaded through SamlSigningKey, and handed to the shared
    // SamlRedirectSigner via SamlLogoutRequestBuilder. The subject NameID and SessionIndex come only from the
    // caller's OWN captured session, so the request can never name another user.
    private static string? BuildSamlSloRedirectUrl(SamlConfig config, LogoutSession captured)
    {
        var sloEndpoint = config.SamlSloEndpoint?.Trim();
        if (string.IsNullOrEmpty(sloEndpoint))
        {
            return null;
        }

        // Reveal the encrypted-at-rest signing key only now, at the moment it signs. A missing/unloadable key
        // returns null (local-only), never an unsigned request.
        if (!SamlSigningKey.TryLoad(SSOPlugin.Instance.Secrets.Reveal(config.SamlSigningKeyPfx), out var signingCertificate))
        {
            return null;
        }

        using (signingCertificate)
        using (var signingKey = SamlSigningKey.GetSigningKey(signingCertificate))
        {
            if (signingKey is null)
            {
                return null;
            }

            var request = new SamlLogoutRequestBuilder(config.SamlClientId.Trim(), captured.Subject, captured.SessionIndex);
            return request.GetSignedRedirectUrl(sloEndpoint, relayState: null, signingKey);
        }
    }

    // Rejects a malformed canonical base-URL override (#139) at the OID/SAML Add endpoints. These persist
    // through MutateConfiguration, which passes the live configuration object, so they bypass the
    // config-page save-time validation in ProviderConfigStore.Save (which only runs for a fresh
    // incoming config). Without this, a malformed override set via the Add API would be persisted and then
    // silently fall back to the request Host at login. Throwing keeps it out of the store, so the
    // "rejected at every admin write path" invariant holds. Blank is valid (the feature is off).

    /// <summary>
    /// Rejects a malformed canonical base-URL override at the OID/SAML Add endpoints (#139), the door that
    /// mirrors the config-page save-time check for the Add path that bypasses it. A blank override is valid.
    /// </summary>
    /// <param name="baseUrlOverride">The override value posted to the Add endpoint.</param>
    /// <exception cref="ArgumentException">The override is non-blank and not a valid absolute http(s) URL.</exception>
    internal static void RejectInvalidBaseUrlOverride(string? baseUrlOverride)
    {
        if (CanonicalBaseUrl.IsInvalidOverride(baseUrlOverride))
        {
            throw new ArgumentException("The Base URL override must be an absolute http(s) URL such as https://jellyfin.example.com, or left blank.", nameof(baseUrlOverride));
        }
    }

    // Rejects a non-loadable SAML signing certificate at the SAML/Add endpoint (#206), which persists
    // through MutateConfiguration and so bypasses the config-page save-time validation in
    // ProviderConfigValidator.Validate. Without this, a garbage certificate set via the Add API would be
    // persisted and then throw a CryptographicException on every callback (an unhandled 500). Blank is
    // valid (a half-configured provider).

    /// <summary>
    /// Rejects a non-loadable SAML signing certificate at the SAML/Add endpoint (#206), the Add-path
    /// counterpart to the config-page save-time certificate check. A blank certificate is valid.
    /// </summary>
    /// <param name="certificateStr">The Base64-encoded (DER) X.509 certificate posted to the Add endpoint.</param>
    /// <exception cref="ArgumentException">The certificate is non-blank and not loadable.</exception>
    internal static void RejectInvalidSamlCertificate(string? certificateStr)
    {
        if (SamlCertificate.IsInvalid(certificateStr))
        {
            throw new ArgumentException("The SAML signing certificate must be a Base64-encoded (DER) X.509 certificate, or left blank.", nameof(certificateStr));
        }
    }

    // Rejects a non-loadable inbound secondary verification certificate at the SAML/Add endpoint (#491),
    // the same fail-closed door as the primary certificate guard above and for the same reason: a garbage
    // secondary would persist and then throw a CryptographicException on every callback (an unhandled
    // 500). It is the identity provider's PUBLIC certificate, so it is validated exactly like the primary.
    // Blank is valid (no overlap window configured).

    /// <summary>
    /// Rejects a non-loadable inbound secondary verification certificate at the SAML/Add endpoint (#491) -
    /// the identity provider's public certificate for a key-overlap window, validated like the primary. A
    /// blank value is valid (no overlap window configured).
    /// </summary>
    /// <param name="certificateStr">The Base64-encoded (DER) X.509 certificate posted to the Add endpoint.</param>
    /// <exception cref="ArgumentException">The certificate is non-blank and not loadable.</exception>
    internal static void RejectInvalidSamlSecondaryCertificate(string? certificateStr)
    {
        if (SamlCertificate.IsInvalid(certificateStr))
        {
            throw new ArgumentException("The SAML secondary signing certificate must be a Base64-encoded (DER) X.509 certificate, or left blank.", nameof(certificateStr));
        }
    }

    // Rejects a non-loadable service-provider signing key at the SAML/Add endpoint (#167), the same
    // fail-closed door as the inbound certificate guard above: a garbage or private-key-less PKCS#12 set
    // here would persist and then fail every signed challenge. Blank is valid (signing simply stays off,
    // or the stored key is preserved on save).

    /// <summary>
    /// Rejects a non-loadable service-provider request signing key at the SAML/Add endpoint (#167). A blank
    /// key is valid (signing stays off, or the stored key is preserved on save).
    /// </summary>
    /// <param name="signingKeyPfx">The Base64-encoded PKCS#12 (PFX) signing key posted to the Add endpoint.</param>
    /// <exception cref="ArgumentException">The key is non-blank and not a loadable PFX with an RSA or ECDSA private key.</exception>
    internal static void RejectInvalidSamlSigningKey(string? signingKeyPfx)
    {
        if (SamlSigningKey.IsInvalid(signingKeyPfx))
        {
            throw new ArgumentException("The SAML request signing key must be a Base64-encoded, unencrypted PKCS#12 (PFX) blob containing an RSA or ECDSA private key, or left blank.", nameof(signingKeyPfx));
        }
    }

    // Rejects a malformed SAML SLO endpoint (#727, SLO-3c) at the SAML/Add endpoint, the door that mirrors
    // the config-page save-time SLO-endpoint check in ProviderConfigValidator for the Add path that
    // bypasses it. It must be an absolute https URL - the redirect carries a signed LogoutRequest naming the
    // subject, so it must not traverse plaintext http. Reuses the same CanonicalBaseUrl.TryNormalize
    // absolute-URL predicate the Base URL override guard uses, narrowed to https. Blank is valid (no
    // SP-initiated Single Logout). The message stays generic (never echoes the caller's endpoint back).

    /// <summary>
    /// Rejects a malformed SAML SLO endpoint at the SAML/Add endpoint (#727, SLO-3c), the Add-path
    /// counterpart to the config-page save-time SLO-endpoint check. A blank endpoint is valid.
    /// </summary>
    /// <param name="sloEndpoint">The SAML SLO endpoint posted to the Add endpoint.</param>
    /// <exception cref="ArgumentException">The endpoint is non-blank and not a valid absolute https URL.</exception>
    internal static void RejectInvalidSamlSloEndpoint(string? sloEndpoint)
    {
        if (!string.IsNullOrWhiteSpace(sloEndpoint)
            && (!CanonicalBaseUrl.TryNormalize(sloEndpoint, out var normalized)
                || !normalized.StartsWith("https://", StringComparison.Ordinal)))
        {
            throw new ArgumentException("The SAML SLO Endpoint must be an absolute https URL such as https://idp.example.com/slo, or left blank.", nameof(sloEndpoint));
        }
    }

    // Rejects a null provider body at the Add endpoints (#350). ASP.NET model binding hands a null
    // [FromBody] object for an empty or literal "null" JSON payload; storing it would put a null entry
    // in the config map that then NREs the config-page save (ServerManagedFields.Preserve). Reject at
    // the door so the store never holds a null provider - the same fail-closed posture as the other
    // Add-endpoint gates.

    /// <summary>
    /// Rejects a null provider body at the Add endpoints (#350), so a null or literal "null" JSON payload
    /// can never put a null entry in the config map that would later NRE the config-page save.
    /// </summary>
    /// <param name="config">The model-bound provider configuration body.</param>
    /// <exception cref="ArgumentException">The body is null.</exception>
    internal static void RejectNullProviderBody(object config)
    {
        if (config is null)
        {
            throw new ArgumentException("The provider configuration body must not be empty.", nameof(config));
        }
    }

    // Rejects a provider name containing URI-reserved or control characters when it would register a NEW
    // provider (#336, #360): the name is appended raw to the callback URLs handed to the identity provider
    // (the OIDC/SAML URL builders), so '%' breaks route decoding, '/' dead-ends the IdP redirect on a path no route
    // matches, control characters do not round-trip at all, and the other RFC 3986 delimiters invite
    // proxy/IdP misinterpretation. Updating an
    // EXISTING name stays allowed: its URL bytes are already registered at the IdP, and blocking the
    // update would strand the deployment behind a rename (encoding the built URLs instead is pinned
    // off by SsoUrlBuilderTests).

    /// <summary>
    /// Rejects a NEW provider name containing control characters, a backslash, or a URI-reserved character
    /// (#336, #360), because the name is appended raw to the callback URLs registered with the identity
    /// provider. Updating an existing name stays allowed so a deployment is not stranded behind a rename.
    /// </summary>
    /// <param name="provider">The provider name posted to the Add endpoint.</param>
    /// <param name="providerExists">Whether the name already names a registered provider; only new names are validated.</param>
    /// <exception cref="ArgumentException">The name is new and contains a forbidden character.</exception>
    internal static void RejectInvalidNewProviderName(string provider, bool providerExists)
    {
        if (!providerExists && ProviderNameValidator.IsInvalid(provider))
        {
            throw new ArgumentException("A new provider name must not contain control characters, a backslash, or any of % : / ? # [ ] @ ! $ & ' ( ) * + , ; = because the name becomes part of the callback URL registered with the identity provider.", nameof(provider));
        }
    }

    // The refusal every elevated write door gives for a declaratively managed provider (#1415), defined once
    // so five doors and their tests cannot drift into five wordings. It names the source, because a refusal
    // that does not say where the change belongs leaves an administrator with nowhere to make it.
    private static string ManagedProviderRefusal(string protocol, string provider, string source) =>
        string.Create(
            CultureInfo.InvariantCulture,
            $"The {protocol} provider '{provider}' is managed by the declarative source {source}. Edit that source and restart the server; a change made here would be undone at the next start.");

    private static string ManagedProfileRefusal(string profile, string source) =>
        string.Create(
            CultureInfo.InvariantCulture,
            $"The provisioning profile '{profile}' is defined by the declarative source {source}. Edit that source and restart the server; a change made here would be undone at the next start.");

    /// <summary>
    /// Refuses an elevated single-provider write against a provider a declarative source decided (#1415), and
    /// audits the refusal so an operator reading the log sees why nothing changed.
    /// </summary>
    /// <remarks>
    /// REFUSE rather than the config-page save's ignore-and-keep, and the difference is what the caller asked
    /// for. A settings-page save posts the WHOLE configuration, so a managed provider inside it is almost
    /// always an untouched form field riding along with an unrelated edit, and refusing the save would block
    /// that edit; the freeze there keeps the stored value and lets the rest through. These four doors carry a
    /// single-provider intent and nothing else, so there is no unrelated work to protect: honouring the call
    /// while doing nothing would report success for a change that did not happen.
    /// <para>
    /// Runs BEFORE the body validators on the Add doors, because a managed provider's posted body is never
    /// applied and its shape therefore decides nothing. That also keeps the door from answering a body
    /// complaint an administrator would then fix, only to meet this refusal on the next attempt.
    /// </para>
    /// </remarks>
    /// <param name="door">The route being refused, for the audit line.</param>
    /// <param name="protocol">The protocol label, <c>OpenID</c> or <c>SAML</c>.</param>
    /// <param name="provider">The provider the caller named.</param>
    /// <param name="source">What names the owning source, or null when the provider is not managed and the call proceeds.</param>
    /// <exception cref="ArgumentException">The provider is declaratively managed.</exception>
    private void RejectManagedProviderWrite(string door, string protocol, string provider, string? source)
    {
        if (source is null)
        {
            return;
        }

        SsoAudit.DeclarativeWriteRefused(_logger, door, protocol, provider, source);
        throw new ArgumentException(ManagedProviderRefusal(protocol, provider, source), nameof(provider));
    }

    /// <summary>
    /// Adds an OpenID auth configuration. Requires administrator privileges. If the provider already exists, it will be removed and readded.
    /// </summary>
    /// <param name="provider">The name of the provider to add.</param>
    /// <param name="config">The OID configuration (deserialized from a JSON post).</param>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("OID/Add/{provider}")]
    public void OidAdd(string provider, [FromBody] OidConfig config)
    {
        RejectManagedProviderWrite("OID/Add", OpenIdProtocol, provider, SSOPlugin.Instance.ConfigStore.ManagedProviders.OidSource(provider));
        RejectNullProviderBody(config);
        RejectInvalidBaseUrlOverride(config.BaseUrlOverride);
        // Reject a malformed generic permission-role mapping (#164) at the door, exactly like the base-URL
        // and certificate guards above: the Add endpoints persist through MutateConfiguration and so bypass
        // the config-page save-time validation. Reuses the one shared validator so every admin write path
        // agrees on what a valid mapping is.
        ProviderConfigValidator.ValidatePermissionRoleMappings(OpenIdProtocol, provider, config.PermissionRoleMappings);
        // Reject an invalid parental-rating mapping (#736) at the door too (negative score / no roles), like
        // the permission-role guard above - the Add endpoints bypass the config-page save-time validation.
        ProviderConfigValidator.ValidateParentalRatingMappings(OpenIdProtocol, provider, config.ParentalRatingRoleMappings);
        // And an invalid SyncPlay-access mapping (#827): a level the resolver cannot parse would map nothing
        // at login, so it is refused at every write door rather than only at the config page.
        ProviderConfigValidator.ValidateSyncPlayAccessMappings(OpenIdProtocol, provider, config.SyncPlayAccessRoleMappings);
        // And an invalid access-duration mapping (#1146), for the same reason: a non-positive or out-of-range
        // duration reaching the login path would silently stamp nothing, so it is refused at every write door
        // rather than only at the config page.
        ProviderConfigValidator.ValidateGuestAccessDurations(OpenIdProtocol, provider, config.GuestAccessDurationRoleMappings);
        // Reject RequireAcr with no acr_values at the door too (#757): an empty allow-list would refuse every
        // login for the provider (a silent single-provider lockout). Mirrors the config-page/import validation
        // so this Add path - which persists through MutateConfiguration and bypasses the save-time Validate -
        // shares the same fail-closed guard.
        ProviderConfigValidator.ValidateAcrRequirement(provider, config);
        SSOPlugin.Instance.MutateConfiguration(configuration =>
        {
            // The name guard needs the under-lock existence check (#336) and runs before any mutation,
            // so a throw leaves the live configuration untouched and nothing is persisted.
            var providerExists = configuration.OidConfigs.TryGetValue(provider, out var existing);
            RejectInvalidNewProviderName(provider, providerExists);

            // Re-inject the server-managed fields this API cannot carry - CanonicalLinks ([JsonIgnore],
            // #157) and the write-only secret's blank-means-keep rule (#189) - through the one shared
            // ServerManagedFields.Preserve the config-page save also uses, so every write path agrees.
            if (providerExists)
            {
                ServerManagedFields.Preserve(config, existing);
            }

            configuration.OidConfigs[provider] = config;
        });
        SsoAudit.ProviderConfigured(_logger, OpenIdProtocol, provider);

        // Audit any disabled security check (#140), so enabling an escape hatch (DisableHttps,
        // DoNotValidateIssuerName, DoNotValidateEndpoints) via this API leaves a trace too.
        var insecure = OidcInsecureToggles.Enabled(config);
        if (insecure.Count > 0)
        {
            SsoAudit.InsecureOptionsEnabled(_logger, OpenIdProtocol, provider, insecure);
        }
    }

    /// <summary>
    /// Deletes an OpenID provider.
    /// </summary>
    /// <param name="provider">Name of provider to delete.</param>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("OID/Del/{provider}")]
    public void OidDel(string provider)
    {
        RejectManagedProviderWrite("OID/Del", OpenIdProtocol, provider, SSOPlugin.Instance.ConfigStore.ManagedProviders.OidSource(provider));
        var removed = SSOPlugin.Instance.MutateConfiguration(configuration => configuration.OidConfigs.Remove(provider));
        if (removed)
        {
            SsoAudit.ProviderRemoved(_logger, OpenIdProtocol, provider);
        }
    }

    /// <summary>
    /// Lists the OpenID providers configured. Requires administrator privileges.
    /// </summary>
    /// <returns>The list of OpenID configurations.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("OID/Get")]
    public ActionResult OidProviders()
    {
        return Ok(SSOPlugin.Instance.ReadConfiguration(c => SnapshotConfigs(c.OidConfigs)));
    }

    /// <summary>
    /// Lists the names of the enabled OpenID providers only. Intentionally anonymous - see the
    /// in-body rationale (#540).
    /// </summary>
    /// <returns>The list of enabled OpenID provider names.</returns>
    [HttpGet("OID/GetNames")]
    public ActionResult OidProviderNames()
    {
        // Only enabled providers are offered (#344): this endpoint drives the self-service linking page,
        // and a disabled provider cannot complete a link (the link leg fail-closes on Enabled, #343), so
        // offering it would render an add button that only ever fails. The filter is UX honesty, not the
        // gate - the server-side rejection stays the real defense in depth.
        // Materialize under the lock (#157/F-10): returning a live view lets the JSON formatter enumerate
        // it outside the lock, tearing against a concurrent provider add/remove.
        //
        // No [Authorize] here - deliberate, not an oversight (#540). SSOViewsController, which serves the
        // self-service linking page (linking.html/linking.js, the sole caller of this endpoint), carries no
        // [Authorize] of its own either, so the same provider-name list this endpoint returns is already
        // rendered into that page's visible DOM for an anonymous visitor. Gating GetNames would add no
        // confidentiality (the list is public via the page regardless) while breaking that page's render for
        // any caller who has not first authenticated - including the isLinking=false leg, which is how a
        // brand-new (not-yet-Jellyfin-authenticated) user discovers which providers they can sign in with.
        // Provider names are configuration, not secrets; the identity-provider connection itself (client
        // secret, signing keys) stays behind the elevation-gated OID/Get and SAML/Get.
        return Ok(SSOPlugin.Instance.ReadConfiguration(c => EnabledProviderNames(c.OidConfigs)));
    }

    /// <summary>
    /// Lists the names of the enabled SAML providers only. Intentionally anonymous - see the
    /// in-body rationale (#540).
    /// </summary>
    /// <returns>The list of enabled SAML provider names.</returns>
    [HttpGet("SAML/GetNames")]
    public ActionResult SamlProviderNames()
    {
        // Enabled-only and materialized under the lock, as OID/GetNames does (#344, #157/F-10).
        // Anonymous by the same design as OID/GetNames above (#540) - same caller, same already-public
        // rendering, same rationale.
        return Ok(SSOPlugin.Instance.ReadConfiguration(c => EnabledProviderNames(c.SamlConfigs)));
    }

    // Names of the enabled providers in a config map, materialized to a detached list (the caller holds
    // the config lock). Shared by both GetNames twins so the enabled-only rule lives in one place. A
    // null-valued entry is skipped rather than dereferenced (#538) - the same fail-closed convention
    // CanonicalLinkService already applies to these maps.
    private static List<string> EnabledProviderNames<TConfig>(SerializableDictionary<string, TConfig> configs)
        where TConfig : ProviderConfigBase =>
        configs.Where(kvp => kvp.Value is { Enabled: true }).Select(kvp => kvp.Key).ToList();

    /// <summary>
    /// Tests connectivity and basic config for a stored OpenID provider (#163). Requires administrator
    /// privileges. Reads the provider's discovery document through the SAME hardened reader the login uses
    /// and reports the issuer, endpoints and JWKS reachability - never the client secret. Deliberately
    /// elevation-gated (unlike the anonymous GetNames): the server fetches an admin-configured URL, so an
    /// unauthenticated caller must not be able to drive it as an SSRF probe.
    /// </summary>
    /// <param name="provider">The stored OpenID provider to test.</param>
    /// <returns>The non-secret test result, or 404 when the provider is not configured.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("OID/Test/{provider}")]
    public async Task<ActionResult> OidTest(string provider)
    {
        // Throttle after the elevation guard, before the outbound fetch (mirrors Unregister, #516): the
        // [Authorize] filter rejects a non-elevated caller before the body runs, so an unauthorized request
        // never reaches the limiter (no rate-limit oracle). Once past it, the shared "test" budget caps how
        // fast an authorized admin can drive the probe's outbound discovery fetch.
        if (RateLimitCheck(SsoRateLimitClass.Test) is { } throttled)
        {
            return throttled;
        }

        // Read the stored provider under the config lock, then hand it to the tester (the fetch and any
        // logging live there). The tester never reveals the client secret - discovery needs no credential.
        var config = SSOPlugin.Instance.ReadConfiguration(c => c.OidConfigs.TryGetValue(provider, out var cfg) ? cfg : null);
        if (config is null)
        {
            return NotFound(NoMatchingProviderMessage);
        }

        return Ok(await ProviderConnectionTester.TestOidcAsync(config, provider, _httpClientFactory, _logger).ConfigureAwait(false));
    }

    /// <summary>
    /// Returns the exact OpenID <c>redirect_uri</c> a stored provider's login sends, so the admin config page
    /// can show it for verbatim registration at the identity provider instead of composing a second copy of
    /// it in JavaScript (#1303). The flow service composes it, over the same builder and the same canonical
    /// base the challenge uses, so there is one producer of these bytes.
    /// </summary>
    /// <remarks>
    /// Elevation-gated like the other admin endpoints: the value is not a secret, but it reveals a
    /// provider's configured base-URL override, and only an administrator has any use for it. Read-only -
    /// it starts no flow, writes nothing, and makes no outbound request, so it takes no rate-limit class.
    /// An unknown provider is the same 404 the other per-provider admin reads return; the page turns that
    /// into "save the provider first" rather than showing a value for a provider that does not exist.
    /// </remarks>
    /// <param name="provider">The stored OpenID provider whose redirect_uri to compose.</param>
    /// <returns>The redirect_uri, or 404 when the provider is not configured.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("OID/RedirectUri/{provider}")]
    [Produces(MediaTypeNames.Application.Json)]
    public ActionResult OidRedirectUri(string provider)
    {
        var redirectUri = _oidc.ChallengeRedirectUriDisplay(provider, Request);

        return redirectUri is null
            ? NotFound(NoMatchingProviderMessage)
            : Ok(redirectUri);
    }

    /// <summary>
    /// This is a debug endpoint to list all running OpenID flows. Requires administrator privileges.
    /// </summary>
    /// <returns>The list of OpenID flows in progress.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("OID/States")]
    public ActionResult OidStates()
    {
        // Non-secret summaries only - the flow service projects the in-flight states to redacted summaries.
        return Ok(_oidc.StateSummaries());
    }

    /// <summary>
    /// This endpoint accepts JSON and will authorize the user from the device values passed from the client.
    /// </summary>
    /// <param name="provider">Name of provider to authenticate against.</param>
    /// <param name="response">The data passed to the client to ensure it is the right one.</param>
    /// <returns>JSON for the client to populate information with.</returns>
    [HttpPost("OID/Auth/{provider}")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> OidAuth(string provider, [FromBody] AuthResponse response)
    {
        if (RateLimitCheck(SsoRateLimitClass.Auth) is { } throttled)
        {
            return throttled;
        }

        // The session-minting authenticate leg lives in the flow service (#160, #318): it redeems the
        // browser-bound authorize state once and hands the verified identity to the shared completion tail.
        // The controller passes the presented binding cookie and the HttpContext-derived remote endpoint in,
        // keeping the flow tier HttpContext-free (#177).
        return await _oidc.AuthenticateAsync(
            provider,
            response,
            Request.Cookies[AuthorizeStateBinding.CookieName],
            () => HttpContext.GetNormalizedRemoteIP().ToString()).ConfigureAwait(false);
    }

    /// <summary>
    /// This is the callback for the SAML flow. This creates a webpage to complete auth.
    /// </summary>
    /// <param name="provider">The provider that is calling back.</param>
    /// <param name="relayState">
    ///    RelayState given in the original saml request. If it is equal to "linking",
    ///    We consider this to be a linking request.
    /// </param>
    /// <param name="formSamlResponse">
    ///    The SAMLResponse form field, model-bound so a non-form POST binds null (and is rejected)
    ///    instead of making Request.Form throw an unhandled 500 (#206).
    /// </param>
    /// <returns>A webpage that will complete the client-side flow.</returns>
    [HttpPost("SAML/p/{provider}")]
    [HttpPost("SAML/post/{provider}")]
    public async Task<ActionResult> SamlCallback(string provider, [FromQuery] string? relayState = null, [FromForm(Name = "SAMLResponse")] string? formSamlResponse = null)
    {
        if (RateLimitCheck(SsoRateLimitClass.Callback) is { } throttled)
        {
            return BrowserErrorPage.Wrap(throttled, Request, Response);
        }

        // The SAML assertion-consumer callback lives in the flow service (#160, #318): it validates the
        // signed response and, on a passing role gate, renders the security-headered intermediate auth
        // page on the response.
        // This endpoint is browser-navigated, so a plain-text rejection is restyled as an HTML page (#668).
        return BrowserErrorPage.Wrap(await _saml.CallbackAsync(provider, relayState, formSamlResponse, Request, Response).ConfigureAwait(false), Request, Response);
    }

    /// <summary>
    /// Initializes the SAML flow. This will redirect the user to the SAML provider.
    /// </summary>
    /// <param name="provider">The provider to being the flow with.</param>
    /// <param name="isLinking">Whether this flow intends to link an account, or initiate auth.</param>
    /// <returns>A redirect to the SAML provider's auth page.</returns>
    [HttpGet("SAML/p/{provider}")]
    [HttpGet("SAML/start/{provider}")]
    public ActionResult SamlChallenge(string provider, [FromQuery] bool isLinking = false)
    {
        if (RateLimitCheck(SsoRateLimitClass.Challenge) is { } throttled)
        {
            return BrowserErrorPage.Wrap(throttled, Request, Response);
        }

        // The SAML challenge lives in the flow service (#160, #318): it builds the AuthnRequest, binds it
        // to the initiating browser (setting the binding cookie on the response), signs it when the
        // provider opts in (#167), and redirects to the identity provider.
        // This endpoint is browser-navigated, so a plain-text rejection is restyled as an HTML page (#668).
        return BrowserErrorPage.Wrap(_saml.Challenge(provider, isLinking, Request, Response), Request, Response);
    }

    /// <summary>
    /// Serves this service provider's SAML 2.0 metadata for <paramref name="provider"/> (#162). The
    /// request-free, canonical-Base-URL-only construction and its fail-closed rationale live on the single
    /// authoritative implementation, <see cref="SamlLoginService.Metadata"/>.
    /// </summary>
    /// <param name="provider">The SAML provider whose metadata to serve.</param>
    /// <returns>The SP metadata document, or a fail-closed rejection when the provider is unknown/disabled or its canonical Base URL is unconfigured.</returns>
    [HttpGet("SAML/metadata/{provider}")]
    public ActionResult SamlMetadata(string provider)
    {
        if (RateLimitCheck(SsoRateLimitClass.Metadata) is { } throttled)
        {
            return throttled;
        }

        // The SP metadata flow lives in the flow service (#160, #318): it resolves the entity id and
        // assertion-consumer URL from the configured canonical Base URL (never the request Host) and emits
        // the SPSSODescriptor, advertising the PUBLIC signing certificate only when request signing is on.
        return _saml.Metadata(provider);
    }

    /// <summary>
    /// Inbound IdP-initiated SAML Single Logout (#727, SLO-3b): accepts a signed <c>LogoutRequest</c> and
    /// revokes the linked Jellyfin sessions. This is the UNAUTHENTICATED, session-destructive surface - its
    /// only trust anchor is the request's XML signature against the provider's configured certificate(s), so
    /// it mirrors the login-side hardening (enveloped-signature + wrapping defense, weak-algorithm rejection,
    /// DTD-prohibited parse, replay one-time-use). POST-binding only (the <c>SAMLRequest</c> form field,
    /// Base64). Single Logout is opt-in and off by default: while it is off the whole surface rejects WITHOUT
    /// parsing. Every rejection - feature off, unknown provider, bad signature, replay, unknown subject - is
    /// the SAME uniform 400 with a fixed body, so the causes cannot be told apart (no oracle); only a
    /// validly-signed request that resolves at least one session returns 200.
    /// </summary>
    /// <param name="provider">The SAML provider the LogoutRequest arrived for.</param>
    /// <param name="samlRequest">The <c>SAMLRequest</c> form field (model-bound, so a non-form POST binds null and is rejected).</param>
    /// <param name="relayState">The optional <c>RelayState</c> form field, echoed on the signed <c>LogoutResponse</c> (#727, SLO-3c) when within the 80-byte SAML binding cap.</param>
    /// <returns>A signed <c>LogoutResponse</c> redirect (302) when a validated request revoked at least one session and the provider is configured to sign it, a bare 200 when it cannot be signed, or a uniform 400 otherwise.</returns>
    [HttpPost("SAML/Logout/{provider}")]
    public async Task<ActionResult> SamlLogout(string provider, [FromForm(Name = "SAMLRequest")] string? samlRequest = null, [FromForm(Name = "RelayState")] string? relayState = null)
    {
        if (RateLimitCheck(SsoRateLimitClass.Logout) is { } throttled)
        {
            return throttled;
        }

        // Read the feature flag AND the provider config in one lock acquisition. Single Logout is opt-in/off
        // by default: a disabled feature, an unknown provider, and a disabled provider all collapse to the ONE
        // uniform 400 below, and NONE of them parses the untrusted body - so the inbound signed-XML sink is
        // unreachable while the feature is off, and neither the feature state nor the provider set can be
        // probed apart.
        var (singleLogoutEnabled, config) = SSOPlugin.Instance.ReadConfiguration(configuration =>
            (configuration.EnableSingleLogout, configuration.SamlConfigs.TryGetValue(provider, out var samlConfig) ? samlConfig : null));

        if (!singleLogoutEnabled || config is not { Enabled: true })
        {
            return UniformLogoutRejection();
        }

        // Parse + signature/time-bound validate + one-time-use consume. On any failure the reason code is a
        // FIXED constant (never request-derived) written only to the audit trail; the caller sees the uniform
        // 400 with no branch-distinguishing detail.
        var validator = new SamlLogoutValidator();
        if (!validator.TryValidate(config, provider, samlRequest, DateTime.UtcNow, out var nameId, out var sessionIndexes, out var requestId, out var reasonCode))
        {
            SsoAudit.LogoutRejected(_logger, provider, reasonCode);
            return UniformLogoutRejection();
        }

        // Resolve the targeted sessions - strictly the SAME provider and subject (ordinal exact), AND only
        // SAML captures. This is the blast-radius bound: FindByProviderSubject filters by (provider, subject),
        // so a logout for one subject can never touch another subject's or another provider's sessions. The
        // Protocol filter keeps the SAML and OpenID flows apart exactly as the SP-initiated path does (an
        // OpenID and a SAML provider can share a config name and a subject string): a signed SAML LogoutRequest
        // must never revoke an OpenID capture. When the request names SessionIndex element(s), keep only entries
        // whose captured index is among them; a request with NO SessionIndex targets every session of the
        // subject (SAML core §3.7).
        var matches = SSOPlugin.Instance.ReadConfiguration(configuration =>
            SessionLogoutStore.FindByProviderSubject(configuration, provider, nameId, string.Empty)
                .Where(pair => string.Equals(pair.Value.Protocol, SamlProtocol, StringComparison.Ordinal))
                .ToList());
        if (sessionIndexes.Count > 0)
        {
            matches = matches
                .Where(pair => sessionIndexes.Contains(pair.Value.SessionIndex ?? string.Empty, StringComparer.Ordinal))
                .ToList();
        }

        // A validated request resolving NO session is the "unknown-subject" case: render the SAME uniform 400
        // as a validation failure. An anonymous attacker can never produce a valid signature to reach here, so
        // this discloses nothing; only the trusted IdP (which already knows its own subjects) can distinguish
        // it from a 200, which is acceptable.
        if (matches.Count == 0)
        {
            SsoAudit.LogoutRejected(_logger, provider, "no_matching_session");
            return UniformLogoutRejection();
        }

        // Revoke the tokens of each DISTINCT matched user. RevokeUserTokens is USER-scoped - Jellyfin exposes
        // no per-token revoke - so a SessionIndex-scoped request still revokes the whole matched user's tokens;
        // that is honest and safe (a logout can only ever end sessions, never grant or link). A revoke fault
        // for one user must NOT abort the loop (availability fail-safe): the remaining users are still logged
        // out, and a faulted user's store entry is LEFT in place (not consumed) so nothing is silently dropped.
        var succeeded = new HashSet<Guid>();
        foreach (var userId in matches.Select(pair => pair.Value.UserId).Distinct())
        {
            try
            {
                await _sessionManager.RevokeUserTokens(userId, null).ConfigureAwait(false);
                succeeded.Add(userId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Revoking tokens during SAML logout failed for one user; the remaining matched users are still logged out.");
            }
        }

        // Remove only the entries whose user was actually revoked, so a transient revoke fault leaves that
        // user's entry for a later retry/prune rather than dropping it.
        var consumedKeys = matches.Where(pair => succeeded.Contains(pair.Value.UserId)).Select(pair => pair.Key).ToList();
        if (consumedKeys.Count > 0)
        {
            SSOPlugin.Instance.MutateConfiguration(configuration =>
            {
                foreach (var key in consumedKeys)
                {
                    SessionLogoutStore.Remove(configuration, key);
                }
            });
        }

        // Fail-closed on the destructive action itself: a 200 must mean at least one user was ACTUALLY logged
        // out. Sessions matched but EVERY revoke faulted (succeeded.Count == 0) means no token was invalidated
        // and the user stays authenticated - so we must NOT tell the IdP the logout succeeded. Audit the fault
        // and return the uniform 400; the matched entries were left in the store above (nothing was consumed),
        // so a retry can still act. This is the fail-CLOSED half of the per-user fail-SAFE loop: one user's
        // fault does not abort the others (availability), but zero successful revokes is never reported as done.
        if (succeeded.Count == 0)
        {
            SsoAudit.LogoutRejected(_logger, provider, "revoke_failed");
            return UniformLogoutRejection();
        }

        SsoAudit.LogoutRequested(_logger, provider, succeeded.Count);

        // SLO-3c: answer the IdP with a SIGNED LogoutResponse so its Single-Logout loop completes, redirecting
        // the browser to the IdP SLO endpoint. Emitted ONLY here - on the success path, after a validated
        // request actually revoked a session - so no rejection can ever produce a signed status-bearing
        // response (every failure above keeps the uniform 400, no cause oracle). Fail-SAFE: when no SLO
        // endpoint or signing key is configured, or the build/sign faults, fall back to the bare 200 - the
        // revocation already stands, and a missing response is degraded interop, never a 500 or an unsigned
        // downgrade. The redirect target is the save-validated absolute-https SamlSloEndpoint (never
        // request-derived), so it cannot be an open redirect.
        string? responseRedirectUrl = null;
        try
        {
            responseRedirectUrl = BuildSamlLogoutResponseRedirectUrl(config, requestId, relayState);
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or CryptographicException or FormatException)
        {
            if (_logger.IsEnabled(LogLevel.Error))
            {
                _logger.LogError("SAML inbound logout for provider {Provider} could not build the signed LogoutResponse: {Reason}; the revocation stands and the endpoint answers 200.", provider?.ReplaceLineEndings(string.Empty), ex.Message);
            }
        }

        return responseRedirectUrl is null ? Ok() : Redirect(responseRedirectUrl);
    }

    // Builds the signed outbound SAML LogoutResponse redirect URL answering a validated inbound LogoutRequest
    // (#727, SLO-3c), or null when the response cannot be signed (no SLO endpoint, or no loadable signing key).
    // Fail-closed on the signing key exactly like BuildSamlSloRedirectUrl: a missing/unloadable key returns
    // null (the endpoint degrades to a bare 200) rather than emitting an UNSIGNED response - the redirect
    // binding mandates a signature, so an unsigned downgrade is never sent. Reuses the outbound-signing stack
    // verbatim (revealed-at-use key via SamlSigningKey, the shared SamlRedirectSigner via
    // SamlLogoutResponseBuilder). InResponseTo/Destination are bound to the validated request and the trusted
    // configured endpoint; the inbound RelayState is echoed only when within the 80-byte SAML binding cap.
    private static string? BuildSamlLogoutResponseRedirectUrl(SamlConfig config, string requestId, string? relayState)
    {
        var sloEndpoint = config.SamlSloEndpoint?.Trim();
        if (string.IsNullOrEmpty(sloEndpoint))
        {
            return null;
        }

        // Without an SP entity id there is no valid Issuer for the response. Fail-safe to null (the endpoint
        // degrades to a bare 200) rather than emit a malformed empty-Issuer response - and this also removes
        // any NullReferenceException risk from Trim() on a null-deserialized SamlClientId.
        var issuer = config.SamlClientId?.Trim();
        if (string.IsNullOrEmpty(issuer))
        {
            return null;
        }

        if (!SamlSigningKey.TryLoad(SSOPlugin.Instance.Secrets.Reveal(config.SamlSigningKeyPfx), out var signingCertificate))
        {
            return null;
        }

        using (signingCertificate)
        using (var signingKey = SamlSigningKey.GetSigningKey(signingCertificate))
        {
            if (signingKey is null)
            {
                return null;
            }

            // Echo the inbound RelayState only when it is within the SAML HTTP binding's 80-BYTE cap
            // (saml-bindings-2.0 §3.4.3) - measured in UTF-8 bytes, not UTF-16 chars, so a multi-byte value
            // cannot slip over the wire limit; anything longer is non-conformant and dropped, not reflected.
            var echoedRelayState = !string.IsNullOrEmpty(relayState) && System.Text.Encoding.UTF8.GetByteCount(relayState) <= 80 ? relayState : null;

            var response = new SamlLogoutResponseBuilder(issuer, requestId, sloEndpoint);
            return response.GetSignedRedirectUrl(sloEndpoint, echoedRelayState, signingKey);
        }
    }

    // The single uniform rejection for the inbound SAML logout endpoint: one fixed 400 body for every
    // rejection cause (feature off, unknown/disabled provider, bad signature, replay, unknown subject), so no
    // branch-distinguishing detail leaks to the caller. Plain text, mirroring LoginStatusMapper's Emit shape.
    private static ContentResult UniformLogoutRejection() => new ContentResult
    {
        Content = "SAML logout request could not be processed",
        ContentType = MediaTypeNames.Text.Plain,
        StatusCode = StatusCodes.Status400BadRequest,
    };

    // The ONE response for every back-channel-logout failure (#962) - a disabled feature, a bad token, an
    // unmatched subject, or a revoke fault all return this, so the anonymous caller learns nothing about which
    // branch rejected it (no subject/feature/provider oracle). Distinct wording from the SAML rejection only
    // because the protocols differ; both carry no cause detail.
    private static ContentResult UniformBackChannelLogoutRejection() => new ContentResult
    {
        Content = "Logout token could not be processed",
        ContentType = MediaTypeNames.Text.Plain,
        StatusCode = StatusCodes.Status400BadRequest,
    };

    /// <summary>
    /// Adds a SAML configuration. If the provider already exists, overwrite it.
    /// </summary>
    /// <param name="provider">The provider name to add.</param>
    /// <param name="newConfig">The SAML configuration object (deserialized) from JSON.</param>
    /// <returns>The success result.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("SAML/Add/{provider}")]
    public OkResult SamlAdd(string provider, [FromBody] SamlConfig newConfig)
    {
        RejectManagedProviderWrite("SAML/Add", SamlProtocol, provider, SSOPlugin.Instance.ConfigStore.ManagedProviders.SamlSource(provider));
        RejectNullProviderBody(newConfig);
        RejectInvalidBaseUrlOverride(newConfig.BaseUrlOverride);
        RejectInvalidSamlSloEndpoint(newConfig.SamlSloEndpoint);
        RejectInvalidSamlCertificate(newConfig.SamlCertificate);
        RejectInvalidSamlSecondaryCertificate(newConfig.SamlSecondaryCertificate);
        RejectInvalidSamlSigningKey(newConfig.SamlSigningKeyPfx);
        RejectInvalidSamlSigningKey(newConfig.SamlRolloverSigningKeyPfx);
        // Reject a malformed generic permission-role mapping (#164) at the door, as OidAdd does.
        ProviderConfigValidator.ValidatePermissionRoleMappings(SamlProtocol, provider, newConfig.PermissionRoleMappings);
        ProviderConfigValidator.ValidateParentalRatingMappings(SamlProtocol, provider, newConfig.ParentalRatingRoleMappings);
        ProviderConfigValidator.ValidateGuestAccessDurations(SamlProtocol, provider, newConfig.GuestAccessDurationRoleMappings);
        ProviderConfigValidator.ValidateSyncPlayAccessMappings(SamlProtocol, provider, newConfig.SyncPlayAccessRoleMappings);
        SSOPlugin.Instance.MutateConfiguration(configuration =>
        {
            // The name guard needs the under-lock existence check (#336) and runs before any mutation,
            // so a throw leaves the live configuration untouched and nothing is persisted.
            var providerExists = configuration.SamlConfigs.TryGetValue(provider, out var existing);
            RejectInvalidNewProviderName(provider, providerExists);

            // Preserve the server-managed canonical links (#157), as OidAdd does, through the shared
            // ServerManagedFields.Preserve: the posted config never carries them ([JsonIgnore]), so
            // re-inject the live map before the wholesale replace so an API save cannot wipe links.
            if (providerExists)
            {
                ServerManagedFields.Preserve(newConfig, existing);
            }

            configuration.SamlConfigs[provider] = newConfig;
        });
        SsoAudit.ProviderConfigured(_logger, SamlProtocol, provider);

        // Mirror OidAdd (#140/#672): a SAML provider added with a default-on protection disabled
        // (DoNotValidateAudience) leaves the same auditable [SSO Audit] trace an OpenID escape hatch does.
        var insecure = SamlInsecureToggles.Enabled(newConfig);
        if (insecure.Count > 0)
        {
            SsoAudit.InsecureOptionsEnabled(_logger, SamlProtocol, provider, insecure);
        }

        return Ok();
    }

    /// <summary>
    /// Deletes a provider from the configuration with a given ID.
    /// </summary>
    /// <param name="provider">The ID of the provider to delete.</param>
    /// <returns>The success result.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("SAML/Del/{provider}")]
    public OkResult SamlDel(string provider)
    {
        RejectManagedProviderWrite("SAML/Del", SamlProtocol, provider, SSOPlugin.Instance.ConfigStore.ManagedProviders.SamlSource(provider));
        var removed = SSOPlugin.Instance.MutateConfiguration(configuration => configuration.SamlConfigs.Remove(provider));
        if (removed)
        {
            SsoAudit.ProviderRemoved(_logger, SamlProtocol, provider);
        }

        return Ok();
    }

    /// <summary>
    /// Returns a list of all SAML providers configured. Requires administrator privileges.
    /// </summary>
    /// <returns>A list of all of the Saml providers available.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("SAML/Get")]
    public ActionResult SamlProviders()
    {
        return Ok(SSOPlugin.Instance.ReadConfiguration(c => SnapshotConfigs(c.SamlConfigs)));
    }

    /// <summary>
    /// Tests basic config for a stored SAML provider (#163). Requires administrator privileges. Parses the
    /// configured PUBLIC identity-provider signing certificate and reports its non-secret facts - never the
    /// service-provider signing key. There is no SAML metadata-URL field, so this makes no network call.
    /// Elevation-gated like the other SAML admin endpoints.
    /// </summary>
    /// <param name="provider">The stored SAML provider to test.</param>
    /// <returns>The non-secret test result, or 404 when the provider is not configured.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("SAML/Test/{provider}")]
    public ActionResult SamlTest(string provider)
    {
        var config = SSOPlugin.Instance.ReadConfiguration(c => c.SamlConfigs.TryGetValue(provider, out var cfg) ? cfg : null);
        if (config is null)
        {
            return NotFound(NoMatchingProviderMessage);
        }

        return Ok(ProviderConnectionTester.TestSaml(config));
    }

    /// <summary>
    /// Parses SAML identity-provider metadata into the provider-configuration values an administrator would
    /// otherwise hand-copy - the SSO endpoint and the signing certificate(s) - from EITHER a server-fetched
    /// URL or pasted XML (#735). Requires administrator privileges and is deliberately elevation-gated: the
    /// server fetches an admin-supplied URL, so - like <see cref="OidTest"/> - an unauthenticated caller must
    /// not be able to drive it as an SSRF probe (the fetch also routes through the SSRF-hardened outbound
    /// client, which refuses a private/loopback address). The metadata XML is parsed with fail-closed
    /// hardening (no DTD/XXE, size-bounded). It RETURNS the parsed values for the admin to review and save; it
    /// applies nothing itself, and returns the IdP entityID for reference only (it is NOT the SP SamlClientId).
    /// The request body is size-capped and the endpoint is throttled after the elevation guard.
    /// </summary>
    /// <param name="request">Exactly one of a metadata URL or pasted metadata XML.</param>
    /// <returns>The parsed import values, or 400 when the input or metadata is invalid.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("SAML/ImportMetadata")]
    [RequestSizeLimit(ConfigImportMaxBytes)]
    [Consumes(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> SamlImportMetadata([FromBody] SamlMetadataImportRequest request)
    {
        // Throttle after the elevation guard, before the outbound fetch (mirrors OidTest): the [Authorize]
        // filter rejects a non-elevated caller before the body runs, so an unauthorized request never reaches
        // the limiter or the fetch - no SSRF probe, no rate-limit oracle.
        if (RateLimitCheck(SsoRateLimitClass.Test) is { } throttled)
        {
            return throttled;
        }

        if (request is null)
        {
            return BadRequest("The metadata-import request is missing or is not valid JSON.");
        }

        try
        {
            var import = await SamlMetadataImporter.ImportAsync(_httpClientFactory, request.Url, request.Xml, HttpContext.RequestAborted).ConfigureAwait(false);
            return Ok(import);
        }
        catch (SamlMetadataException ex)
        {
            // The message is an admin-facing fixed string (no IdP/library detail); nothing was applied.
            return BadRequest(ex.Message);
        }
    }

    /// <summary>
    /// Exports the whole plugin configuration as a redacted, importable document (#161). Requires
    /// administrator privileges, like the other config endpoints - the document lists every provider's
    /// settings. The redaction is the config's OWN JSON-boundary withholding, reused: the provider secrets
    /// (OidSecret, the SAML signing keys) are serialized as null by their WriteOnlySecretConverter (#189) and
    /// the server-managed canonical-link maps are dropped by [JsonIgnore] (#157/#186), so the document carries
    /// no plaintext secret, no <c>ssoenc:</c> envelope, and no link map. The at-rest data-encryption key
    /// (sso-secret.key) lives in a separate file and is never part of the configuration object at all.
    /// </summary>
    /// <returns>The redacted export document.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("Config/Export")]
    public ActionResult ExportConfig()
    {
        // Snapshot under the config lock; the JSON formatter redacts the secrets and links as it serializes
        // the returned document (the same withholding OID/Get relies on), after the lock is released.
        return Ok(SSOPlugin.Instance.ReadConfiguration(ConfigExport.Build));
    }

    /// <summary>
    /// Reports which providers, and which provisioning profiles (#1498), a declarative source decided on this
    /// boot, so the config page can render them as managed instead of letting an admin edit a form the next
    /// start wins back (#1104).
    /// Requires administrator privileges, like the other config endpoints. Read-only - it changes nothing,
    /// and it carries provider NAMES only: no field value, no secret and no reference, so nothing here is
    /// sensitive even where the whole set is.
    /// </summary>
    /// <returns>The managed provider set; both lists empty when no declarative source is configured.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("Config/Managed")]
    public ActionResult<ManagedProviderSetDocument> ManagedProviders()
    {
        // The set is process state decided during plugin construction, not configuration, so this reads no
        // provider and takes no config lock beyond the one the store holds for its own field.
        var managed = SSOPlugin.Instance.ConfigStore.ManagedProviders;
        return Ok(new ManagedProviderSetDocument
        {
            OidConfigs = managed.OidConfigs,
            SamlConfigs = managed.SamlConfigs,
            ProvisioningProfiles = managed.Profiles,
        });
    }

    /// <summary>
    /// Publishes the permission names an administrator may map (#1484), so the config page can offer them
    /// instead of letting one be typed and meet a save-time refusal. Requires administrator privileges, like
    /// the other config endpoints. Read-only - it changes nothing, and it reads no configuration at all.
    /// </summary>
    /// <remarks>
    /// The answer is derived by <see cref="MappablePermissions"/> from the same classification the save-time
    /// validator refuses by, so the vocabulary and the refusal cannot disagree. The alternative - a list written into the page - drifts silently in three directions the
    /// moment Jellyfin adds a permission, removes one, or this plugin excludes one more.
    /// </remarks>
    /// <returns>The mappable permission names.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("Config/Permissions")]
    [Produces(MediaTypeNames.Application.Json)]
    public ActionResult<MappablePermissionDocument> PermissionVocabulary()
    {
        // No config read and no lock: the set is Jellyfin's compiled enum minus this plugin's compiled
        // exclusion set, so it is the same answer on every installation and on every request.
        return Ok(MappablePermissions.Build());
    }

    /// <summary>
    /// Answers, for every configured OpenID and SAML provider at once, whether a login against it would get
    /// past the configuration and why not (#1084) - the aggregate "Configuration check" the redesigned
    /// settings page dropped. Requires administrator privileges, like the other config endpoints. Read-only:
    /// it evaluates the configuration already in memory and writes nothing, so running it leaves every
    /// provider's stored values byte-identical.
    /// </summary>
    /// <remarks>
    /// ADVISORY, and it makes no outbound request. Whether an identity provider ANSWERS is what the
    /// per-provider Test routes are for; probing them all from here would spend one shared throttle budget
    /// (both pass <see cref="SsoRateLimitClass.Test"/>) and the 429s that followed would name working
    /// providers as broken. So the report says what it checked and leaves reachability to the consumer to
    /// disclose as unchecked.
    /// </remarks>
    /// <returns>One row per configured provider; an empty list where none is configured.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("Config/Check")]
    public ActionResult<ProviderCheckDocument> CheckProviders()
    {
        return Ok(SSOPlugin.Instance.ReadConfiguration(ProviderCheck.Build));
    }

    /// <summary>
    /// Publishes the auth-path counters as Prometheus text exposition (#1139), so an operator can alert on a
    /// rate of failed logins, provisioning or provider-fetch errors instead of grepping the Jellyfin log.
    /// Requires administrator privileges. Read-only - it changes nothing.
    /// </summary>
    /// <remarks>
    /// <para>
    /// NOT ANONYMOUS, and that is the reason it sits on this controller beside the other operator surfaces
    /// rather than on a conventional unauthenticated <c>/metrics</c>. The exposition names which providers a
    /// server has and how often logins against them fail, which is reconnaissance: a caller who cannot log in
    /// could read the provider inventory and watch their own attempts land. A scraper is given a token like
    /// any other Jellyfin API client.
    /// </para>
    /// <para>
    /// No counter carries a username, a subject or a claim value. Every label is either a configured provider
    /// name or a member of a closed vocabulary, which <see cref="SsoMetrics"/> holds by its signatures and
    /// <c>SsoMetricsStore</c> backstops with a series cap.
    /// </para>
    /// </remarks>
    /// <returns>The exposition text.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("Metrics")]
    [Produces(MediaTypeNames.Text.Plain)]
    public ActionResult Metrics() => new ContentResult
    {
        Content = PrometheusExposition.Render(SsoMetricsStore.Snapshot(), SsoMetricsStore.RefusedSeries),
        ContentType = PrometheusExposition.ContentType,
        StatusCode = StatusCodes.Status200OK,
    };

    /// <summary>
    /// Exports the account-link table as a portable, username-keyed document (#1126). Requires
    /// administrator privileges. Read-only - it changes nothing.
    /// </summary>
    /// <remarks>
    /// A separate download from <c>Config/Export</c> on purpose. That document is defined as carrying no
    /// link map, and this one carries identity data - usernames paired with identity-provider subject
    /// identifiers - so an administrator asks for it explicitly instead of receiving it as a side effect of
    /// exporting provider settings. Keying on the username rather than the Jellyfin user id is what makes
    /// the snapshot survive the user-database rebuild that invalidates every id the links are stored
    /// against; a link whose id no longer resolves to an account is dropped rather than exported dangling.
    /// </remarks>
    /// <returns>The link export document.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("Config/Links/Export")]
    [Produces(MediaTypeNames.Application.Json)]
    public ActionResult ExportLinks()
    {
        // Snapshot under the config lock so the two protocols' link maps are read atomically against each
        // other; the resolution to usernames happens there too, so the document that leaves the lock holds
        // no user id for the formatter to serialize.
        return Ok(SSOPlugin.Instance.ReadConfiguration(
            live => LinkExport.Build(live, userId => _userManager.GetUserById(userId)?.Username)));
    }

    /// <summary>
    /// Lists every Jellyfin account that holds an SSO link, with the provider and canonical name behind
    /// each link (#1119). Requires administrator privileges. Read-only - it changes nothing.
    /// </summary>
    /// <remarks>
    /// The per-user listings (<c>saml/links/{jellyfinUserId}</c>, <c>oid/links/{jellyfinUserId}</c>) answer
    /// only for an id the caller already has, so finding out WHICH accounts are linked meant walking the
    /// whole Jellyfin user list one request at a time. This answers that question in one read. Unlike the
    /// portable export it reports a link whose user id resolves to no account rather than dropping it: an
    /// orphaned link is left behind by a deleted account and is the thing an administrator opens this to
    /// find, and it is invisible from every other surface.
    /// </remarks>
    /// <returns>The linked-account roster.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("Links/Roster")]
    [Produces(MediaTypeNames.Application.Json)]
    public ActionResult LinkedAccountRoster()
    {
        // Snapshot under the config lock so the two protocols' link maps are inverted against each other
        // atomically; the document that leaves the lock holds only strings and ids, so the JSON formatter
        // cannot tear against a concurrent login writing a link.
        return Ok(SSOPlugin.Instance.ReadConfiguration(
            live => LinkRoster.Build(live, userId => _userManager.GetUserById(userId)?.Username)));
    }

    /// <summary>
    /// Exports the SSO linkages held for ONE Jellyfin account, across both protocols, as the same document
    /// shape <c>Config/Links/Export</c> produces (#1091). Requires administrator privileges. Read-only - it
    /// changes nothing.
    /// </summary>
    /// <remarks>
    /// The per-subject counterpart to the whole-table export, and the reason it is a separate route rather
    /// than a filter on the existing one: an operator answering a data-subject access request must be able
    /// to produce that subject's linkages WITHOUT handling every other account's, which the whole-table
    /// document would force them to do and then redact by hand. The two protocol-specific listings
    /// (<c>saml/links/{jellyfinUserId}</c>, <c>oid/links/{jellyfinUserId}</c>) answer for one protocol each
    /// and are unthrottled; this answers for both at once and is throttled, because it is the surface an
    /// authenticated administrator is most likely to drive in a loop over the whole user list.
    /// </remarks>
    /// <param name="jellyfinUserId">The Jellyfin user id to export the linkages of.</param>
    /// <returns>The link export document for that account, or 404 when no such account exists.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("Links/Export/{jellyfinUserId}")]
    [Produces(MediaTypeNames.Application.Json)]
    public ActionResult ExportUserLinks(Guid jellyfinUserId)
    {
        // Throttle before the account lookup, exactly as Unregister does: the 404 an unknown id produces is
        // an existence answer, and an unthrottled one would enumerate the user table for an administrator
        // whose elevation was borrowed rather than earned.
        if (RateLimitCheck(SsoRateLimitClass.Export) is { } throttled)
        {
            return throttled;
        }

        if (_userManager.GetUserById(jellyfinUserId)?.Username is not { } username)
        {
            return NotFound("No Jellyfin account exists with that user id.");
        }

        // The export is the whole-table builder with a resolver that answers for this one id and null for
        // every other, so the filtering falls out of the rule that already drops a link no account resolves
        // to - there is no second walk of the link maps to keep in step with the first. Resolved once here
        // rather than inside the lambda so the user manager is not called under the config lock.
        return Ok(SSOPlugin.Instance.ReadConfiguration(
            live => LinkExport.Build(live, userId => userId == jellyfinUserId ? username : null)));
    }

    /// <summary>
    /// Imports a configuration export document into this instance (#161). Requires administrator privileges.
    /// The import is a fail-closed MERGE: the document is validated through the same ProviderConfigValidator
    /// the config-page save uses, and only if the whole document is valid is it merged - atomically, through
    /// MutateConfiguration - reusing ServerManagedFields.Preserve so a redacted (blank) secret keeps this
    /// instance's stored secret and the server-managed links/issuers are never wiped. A provider new to this
    /// instance arrives with a blank secret and fails its login closed until an administrator re-enters it.
    /// The request body is size-capped so an oversized document is rejected before it is parsed.
    /// </summary>
    /// <param name="document">The export document to import.</param>
    /// <returns>No content on success, or 400 when the document is missing, unsupported, or invalid.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("Config/Import")]
    [RequestSizeLimit(ConfigImportMaxBytes)]
    [Consumes(MediaTypeNames.Application.Json)]
    public ActionResult ImportConfig([FromBody] ConfigExportDocument document)
    {
        if (document is null)
        {
            return BadRequest("The configuration import document is missing or is not valid JSON.");
        }

        // #1415: a document naming a declaratively managed provider refuses the WHOLE import, before anything
        // is merged. The whole document rather than the offending providers, because an import is already
        // all-or-nothing on every other rejection (one invalid provider rejects the document), and because
        // dropping part of a document silently is the worse failure: an administrator restoring a backup
        // would be told it succeeded and would have no way to see which providers did not arrive. Refusing
        // names them, so the repair is to delete those entries from the document and import the rest.
        var managed = SSOPlugin.Instance.ConfigStore.ManagedProviders.NamedIn(document.Configuration);
        if (managed.Count > 0)
        {
            foreach (var (protocol, provider, source) in managed)
            {
                SsoAudit.DeclarativeWriteRefused(_logger, "Config/Import", protocol, provider, source);
            }

            var (firstProtocol, firstProvider, firstSource) = managed[0];
            return BadRequest(string.Create(
                CultureInfo.InvariantCulture,
                $"{ManagedProviderRefusal(firstProtocol, firstProvider, firstSource)} The import names {managed.Count} declaratively managed provider(s) and none of it was applied; remove them from the document and import the rest.").ReplaceLineEndings(string.Empty));
        }

        // #1102: the same refusal for a profile the document REDEFINES. A managed provider is what an
        // administrator sees frozen, but the profile it points at is what that provider actually writes onto
        // a brand-new account, so a document carrying no provider at all can still change what every managed
        // provider grants. The whole document again, for the reason above: a partial import that reported
        // success is the worse failure.
        var managedProfiles = SSOPlugin.Instance.ConfigStore.ManagedProviders.ProfilesNamedIn(document.Configuration);
        if (managedProfiles.Count > 0)
        {
            foreach (var (profile, profileSource) in managedProfiles)
            {
                SsoAudit.DeclarativeProfileWriteRefused(_logger, "Config/Import", profile, profileSource);
            }

            var (firstProfile, firstProfileSource) = managedProfiles[0];
            return BadRequest(string.Create(
                CultureInfo.InvariantCulture,
                $"{ManagedProfileRefusal(firstProfile, firstProfileSource)} The import redefines {managedProfiles.Count} declaratively defined provisioning profile(s) and none of it was applied; remove them from the document and import the rest.").ReplaceLineEndings(string.Empty));
        }

        try
        {
            // Validate-then-merge lives in the Config helper; the mutation persists only if it returns without
            // throwing (an invalid document throws inside the lambda, so MutateConfiguration persists nothing).
            // The break-glass resolver lets Apply run the SSO-only activation guard fail-closed on the import
            // path (#165, T-T2): a document asserting SSO-only with no surviving admin login path is rejected.
            SSOPlugin.Instance.MutateConfiguration(configuration => ConfigImport.Apply(configuration, document, _ssoOnly.DescribeBreakGlass));
        }
        catch (ArgumentException ex)
        {
            // The validator and the import throw ArgumentException for a hostile/malformed document (a bad
            // Base URL override, an unloadable certificate/key, a reserved-character provider name, an
            // unsupported version). Strip line endings from the echoed message so it cannot split a log line.
            return BadRequest(ex.Message?.ReplaceLineEndings(string.Empty));
        }

        // Audit the import and any provider that arrived with a security check disabled (#140), so importing
        // an escape hatch (DisableHttps, DoNotValidateIssuerName, …) leaves the same trace a form save would.
        var oidCount = document.Configuration?.OidConfigs?.Count ?? 0;
        var samlCount = document.Configuration?.SamlConfigs?.Count ?? 0;
        SsoAudit.ConfigImported(_logger, oidCount, samlCount);
        if (document.Configuration?.OidConfigs is { } oidConfigs)
        {
            foreach (var kvp in oidConfigs)
            {
                if (kvp.Value is null)
                {
                    continue;
                }

                var insecure = OidcInsecureToggles.Enabled(kvp.Value);
                if (insecure.Count > 0)
                {
                    SsoAudit.InsecureOptionsEnabled(_logger, OpenIdProtocol, kvp.Key, insecure);
                }
            }
        }

        // A mistaken or hostile import that disables a default-on SAML protection (DoNotValidateAudience)
        // must leave the same [SSO Audit] trace the OpenID escape hatches above do (#672) - the import path
        // is exactly one of the failure scenarios that issue calls out.
        if (document.Configuration?.SamlConfigs is { } samlConfigs)
        {
            foreach (var kvp in samlConfigs)
            {
                if (kvp.Value is null)
                {
                    continue;
                }

                var insecure = SamlInsecureToggles.Enabled(kvp.Value);
                if (insecure.Count > 0)
                {
                    SsoAudit.InsecureOptionsEnabled(_logger, SamlProtocol, kvp.Key, insecure);
                }
            }
        }

        return NoContent();
    }

    /// <summary>
    /// Restores an account-link backup (<c>Config/Links/Export</c>) onto this instance (#1129), rebinding
    /// every link to the user id this server holds for that username today. Requires administrator
    /// privileges. The counterpart to the export, and the half that completes a server migration: a
    /// rebuilt user database issues new ids, so the stored links point at ids that no longer resolve and
    /// only a username-keyed document can be restored against it.
    /// </summary>
    /// <remarks>
    /// Fail-closed and atomic. The whole document is validated before a single link is written, and the
    /// mutation runs inside <c>MutateConfiguration</c>, which persists nothing when the lambda throws, so
    /// a rebuilt server either gets its complete link table back or is left exactly as it was. A
    /// half-applied link table is the worst outcome available here, because it looks restored and is not.
    /// <para>
    /// The refusal that matters is the repoint: a canonical name this instance already links to a
    /// DIFFERENT account is rejected rather than overwritten, so a crafted backup file cannot remap an
    /// identity-provider subject onto an administrator's account. The import also never creates a Jellyfin
    /// account, never creates a provider and never invents a user id, so it cannot bring a new principal
    /// into existence - it only rebinds what both sides already hold.
    /// </para>
    /// </remarks>
    /// <param name="document">The link export document to restore.</param>
    /// <returns>No content on success, or 400 when the document is missing, unsupported, or carries an entry this instance cannot restore.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("Config/Links/Import")]
    [RequestSizeLimit(ConfigImportMaxBytes)]
    [Consumes(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> ImportLinks([FromBody] LinkExportDocument document)
    {
        // Throttle after the elevation guard, before any work (#382, #516): the [Authorize] filter refuses
        // a non-elevated caller before the body runs, so an unauthorized request never reaches the limiter
        // and there is no rate-limit oracle. Past it, this shares the "link" bucket with the single link
        // writes, because it is the same config-XML persist under the global lock - in bulk - and because
        // its refusal names usernames this instance does not hold, which an unthrottled caller could drive
        // in a loop as a user-table oracle.
        if (RateLimitCheck(SsoRateLimitClass.Link) is { } throttled)
        {
            return throttled;
        }

        if (document is null)
        {
            return BadRequest("The link import document is missing or is not valid JSON.");
        }

        // Every username the document names is resolved BEFORE the lock is taken, and the importer then
        // reads this snapshot rather than the user manager. A document can carry thousands of entries, and
        // resolving each one inside MutateConfiguration would hold the global configuration lock across
        // that many user-manager calls - blocking every login for the duration. Same discipline as
        // ExportUserLinks, which resolves its one username outside the lock for the same reason. A name
        // resolved a moment before the lock is the same answer a name resolved inside it would have given,
        // except in a race with an account being renamed or deleted, where the import's own refusal rules
        // are what decide the outcome either way.
        var directory = document.Links
            .Where(entry => !string.IsNullOrWhiteSpace(entry?.Username))
            .Select(entry => entry.Username!)
            .Distinct(StringComparer.Ordinal)
            .ToDictionary(username => username, username => _userManager.GetUserByName(username)?.Id, StringComparer.Ordinal);

        IReadOnlyList<LinkImportCount> restored;
        try
        {
            // Validate-then-write lives in the Config helper; the mutation persists only if it returns
            // without throwing, so a rejected document leaves the stored link table untouched.
            restored = SSOPlugin.Instance.MutateConfiguration(
                configuration => LinkImport.Apply(configuration, document, username => directory.GetValueOrDefault(username)));
        }
        catch (ArgumentException ex)
        {
            // The importer throws ArgumentException for an unsupported version and for every unrestorable
            // entry. Strip line endings from the echoed message so a username inside it cannot split a log
            // line (cs/log-forging is sanitized inline at the emission point, never behind a helper).
            return BadRequest(ex.Message?.ReplaceLineEndings(string.Empty));
        }

        SsoAudit.LinksImported(
            _logger,
            await ResolveActorAsync().ConfigureAwait(false),
            restored.Sum(count => count.Links),
            string.Join(", ", restored.Select(count => $"{count.Protocol} '{count.Provider}': {count.Links.ToString(CultureInfo.InvariantCulture)}")));

        return NoContent();
    }

    /// <summary>
    /// This endpoint accepts JSON and will authorize the user from the device values passed from the client.
    /// </summary>
    /// <param name="provider">The provider to authenticate against.</param>
    /// <param name="response">The data passed to the client to ensure it is the right one.</param>
    /// <returns>JSON for the client to populate information with.</returns>
    [HttpPost("SAML/Auth/{provider}")]
    [Consumes(MediaTypeNames.Application.Json)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> SamlAuth(string provider, [FromBody] AuthResponse response)
    {
        if (RateLimitCheck(SsoRateLimitClass.Auth) is { } throttled)
        {
            return throttled;
        }

        // The SAML session-minting authenticate leg lives in the flow service (#160, #318): it redeems the
        // one-time login-outcome token the ACS callback minted (#251; since #528 the token is the only
        // accepted shape), correlates the carried InResponseTo to an AuthnRequest this server issued (browser
        // binding), and hands the already-verified identity to the shared completion tail. The controller
        // passes the presented binding cookie and the HttpContext-derived remote endpoint in, keeping the flow
        // tier HttpContext-free (#177).
        return await _saml.AuthenticateAsync(
            provider,
            response,
            Request.Cookies[AuthorizeStateBinding.SamlCookieName],
            () => HttpContext.GetNormalizedRemoteIP().ToString()).ConfigureAwait(false);
    }

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
        // valid until it expires. Scoped strictly to this one user's id; null revokes all of their tokens
        // (including the caller's own, when an admin unregisters their own account - the durable revoke above
        // is why that is safe). Runs LAST, after the link removal and provider switch are both persisted, so
        // if the revoke throws the unregister is already complete rather than left half-done. Complement to
        // the #232 in-flight re-check, not a substitute: this kills existing sessions, #232 closes the mint race.
        await _sessionManager.RevokeUserTokens(user.Id, null).ConfigureAwait(false);

        if (_logger.IsEnabled(LogLevel.Information))
        {
            _logger.LogInformation("Unregistered SSO for user {UserId}: removed {Count} canonical link(s) and revoked active tokens.", user.Id, revoked);
        }

        return Ok();
    }

    /// <summary>
    /// Reports the current SSO-only login state (#165): whether the mode is on, which account is the
    /// designated break-glass admin, and whether that designation still satisfies the fail-closed survivor
    /// guard. Requires administrator privileges. Read-only - it changes nothing.
    /// </summary>
    /// <returns>The SSO-only login status.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("SSO-Only/Status")]
    [Produces(MediaTypeNames.Application.Json)]
    public ActionResult SsoOnlyStatus()
    {
        var (disablePasswordLogin, breakGlassAdmin) = SSOPlugin.Instance.ReadConfiguration(
            configuration => (configuration.DisablePasswordLogin, configuration.BreakGlassAdminUsername));

        // The guard is evaluated live against the current account state so the page can warn if the
        // break-glass admin was deleted, demoted, disabled, or lost its password after activation (T-D2).
        var guardSatisfied = SsoOnlyLoginGuard.Evaluate(breakGlassAdmin, _ssoOnly.DescribeBreakGlass(breakGlassAdmin))
            == SsoOnlyGuardVerdict.Allow;

        return Ok(new
        {
            DisablePasswordLogin = disablePasswordLogin,
            BreakGlassAdminUsername = breakGlassAdmin,
            GuardSatisfied = guardSatisfied,
        });
    }

    /// <summary>
    /// Reports whether one Jellyfin account is SSO-managed (#1136), so a provisioning tool can decide in a
    /// single call whether to offer a password field, a reset link, or neither. Requires administrator
    /// privileges. Read-only - it changes nothing.
    /// </summary>
    /// <remarks>
    /// The two facts are reported SEPARATELY because they genuinely differ, and collapsing them is the
    /// inference this endpoint exists to remove. An account can hold a canonical link while its
    /// <c>AuthenticationProviderId</c> still routes password attempts to core's default provider, and an
    /// account can carry the SSO stamp with no link left on it (unregistered, or provisioned and never
    /// linked). Only the first of the two decides whether a password can be used.
    /// </remarks>
    /// <param name="jellyfinUserId">The Jellyfin user to report on.</param>
    /// <returns>The account's SSO posture, or 404 when no such user exists.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("SSO-Managed/Status/{jellyfinUserId}")]
    [Produces(MediaTypeNames.Application.Json)]
    public ActionResult SsoManagedStatus(Guid jellyfinUserId)
    {
        // A user id nobody holds is a 404 rather than a report of two falses: "this account uses passwords"
        // and "this account does not exist" are different answers, and a caller that cannot tell them apart
        // would offer a password field for an account it is about to fail to find.
        if (_userManager.GetUserById(jellyfinUserId) is not { } user)
        {
            return NotFound("No such Jellyfin user.");
        }

        return Ok(new
        {
            // The same detector the SSO-only feature and the login-path re-assertion use, so this report and
            // the enforcement can never disagree about what the stamp means.
            PasswordLoginDisabled = SsoAuthenticationProviders.IsSsoProvider(user.AuthenticationProviderId),
            HasCanonicalLink = HoldsAnyCanonicalLink(jellyfinUserId),
        });
    }

    /// <summary>
    /// Whether the user holds at least one canonical link on any provider of either protocol. Reuses the
    /// same per-mode read the link endpoints answer with, so this cannot report a link set the link
    /// endpoints would not list. A provider present with no link for this user yields an empty list, which
    /// is why the test is on the values rather than on the map being non-empty.
    /// </summary>
    /// <param name="jellyfinUserId">The Jellyfin user to look for.</param>
    /// <returns>True when any provider of either protocol holds a link for that user.</returns>
    private bool HoldsAnyCanonicalLink(Guid jellyfinUserId) =>
        _canonicalLinks.LinksByUser(ProviderMode.Oid, jellyfinUserId).Any(entry => entry.Value.Any())
        || _canonicalLinks.LinksByUser(ProviderMode.Saml, jellyfinUserId).Any(entry => entry.Value.Any());

    /// <summary>
    /// Pre-provisions a canonical link from an identity-provider subject to an existing Jellyfin account
    /// (#1133), with no identity-provider response in the request, so an invite-born account created by a
    /// provisioning tool is already SSO-linked before its first login. Requires administrator privileges.
    /// </summary>
    /// <remarks>
    /// The self-service link write (<c>{mode}/Link/{provider}/{jellyfinUserId}</c>) redeems a live
    /// authorize state or a signed assertion, so it structurally requires the linked human to complete a
    /// flow at the identity provider; a tool holding only an administrator credential cannot drive it. This
    /// route is that write without the round trip, and it differs in exactly one behaviour: a subject
    /// already linked to a DIFFERENT account is refused with 409 and the stored link is left as it was.
    /// Repeating the same mapping succeeds, so a retry after a lost response is safe.
    /// <para>
    /// The link is written unstamped by the OpenID issuer binding (#186), like every other administrator
    /// link: no id_token was redeemed here, so there is no issuer to bind to, and the binding is taken on
    /// the identity's first real login instead.
    /// </para>
    /// </remarks>
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

    /// <summary>
    /// Turns SSO-only login on (#165), designating <paramref name="breakGlassAdminUsername"/> as the account
    /// whose native password login is never disabled. Requires administrator privileges. Fail-closed: the
    /// last-admin guard runs first, and unless the designated account is an existing, enabled administrator
    /// that still has a password, the activation is refused with a clear, non-enumerating message and nothing
    /// is changed. On success every non-exempt account is repointed off the password provider and the
    /// transition is audited.
    /// </summary>
    /// <param name="breakGlassAdminUsername">The administrator account to keep password-capable as the break-glass door.</param>
    /// <returns>Ok on activation, or 400 with the refusal reason when the guard rejects it.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("SSO-Only/Enable")]
    [Consumes(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> EnableSsoOnly([FromBody] string breakGlassAdminUsername)
    {
        var actor = await ResolveActorAsync().ConfigureAwait(false);
        var outcome = await _ssoOnly.TryEnableAsync(breakGlassAdminUsername).ConfigureAwait(false);
        if (outcome.Verdict != SsoOnlyGuardVerdict.Allow)
        {
            // Fail closed: a blocked lockout attempt is audited (reason CODE only, no roster) and refused.
            SsoAudit.SsoOnlyLoginActivationRefused(_logger, actor, outcome.Verdict.ToString());
            return BadRequest(SsoOnlyLoginGuard.PublicRefusalMessage);
        }

        SsoAudit.SsoOnlyLoginEnabled(_logger, actor, outcome.BreakGlassAdmin, outcome.RepointedCount);
        return Ok();
    }

    /// <summary>
    /// Turns SSO-only login off (#165), the reversible no-SSO off-switch: it restores native password
    /// routing for every account the mode repointed, WITHOUT resetting or exposing any password. Requires
    /// administrator privileges. Audited on the transition.
    /// </summary>
    /// <returns>Ok once password routing is restored.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("SSO-Only/Disable")]
    public async Task<ActionResult> DisableSsoOnly()
    {
        var actor = await ResolveActorAsync().ConfigureAwait(false);
        var restored = await _ssoOnly.DisableAsync().ConfigureAwait(false);
        SsoAudit.SsoOnlyLoginDisabled(_logger, actor, restored);
        return Ok();
    }

    /// <summary>
    /// Sets or changes the designated break-glass administrator (#165) - the account SSO-only mode never
    /// repoints. Requires administrator privileges. Fail-closed: the target must be an existing, enabled
    /// administrator that still has a password (the exemption can never point at a non-admin, so it cannot
    /// grant admin - T-E1); an unqualified target is refused and nothing changes. To change the designation
    /// while the mode is on, disable it first (every other admin has already been repointed off the password
    /// provider, so no other account can satisfy the "usable password" guard), then re-designate and re-enable.
    /// Audited.
    /// </summary>
    /// <param name="username">The administrator account to designate as the break-glass admin.</param>
    /// <returns>Ok on success, or 400 with the refusal reason when the target does not qualify.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpPost("SSO-Only/BreakGlassAdmin")]
    [Consumes(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> DesignateBreakGlassAdmin([FromBody] string username)
    {
        var actor = await ResolveActorAsync().ConfigureAwait(false);
        var outcome = _ssoOnly.TryDesignateBreakGlass(username);
        if (outcome.Verdict != SsoOnlyGuardVerdict.Allow)
        {
            SsoAudit.SsoOnlyLoginActivationRefused(_logger, actor, outcome.Verdict.ToString());
            return BadRequest(SsoOnlyLoginGuard.PublicRefusalMessage);
        }

        SsoAudit.BreakGlassAdminDesignated(_logger, actor, outcome.BreakGlassAdmin);
        return Ok();
    }

    // Resolves the elevated caller's own username for the audit "actor" field, fail-soft: every SSO-Only
    // endpoint sits behind [Authorize(RequiresElevation)], so the caller is an administrator, but an
    // unresolved authorization info still yields a non-null placeholder rather than throwing - the audit
    // line must never be the thing that fails a security-relevant transition.
    private async Task<string> ResolveActorAsync()
    {
        var auth = await _authContext.GetAuthorizationInfo(HttpContext.Request).ConfigureAwait(false);
        return auth?.User?.Username ?? "unknown";
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

        var removal = _canonicalLinks.TryRemoveLink(parsed, provider, canonicalName, jellyfinUserId);

        // Terminate the user's already-issued tokens ONLY when this unlink removed their LAST canonical SSO
        // link (#468) - the terminal "can no longer SSO in at all" state that matches the hard-lockdown
        // posture of Unregister (#440). Removing the links only fails FUTURE logins closed; a token minted
        // before the unlink stays valid until it expires, so a security-motivated unlink of a compromised
        // identity must also kill live sessions. A user who unlinks a SECONDARY provider while still holding
        // another link keeps a working SSO identity, so revoking there would be a self-inflicted mass-logout
        // with no security gain - the availability-preserving choice is to revoke only at the last link
        // (UserRetainsAnyLink evaluated atomically with the removal). Scoped strictly to this one user id;
        // null revokes all of their tokens (including the caller's own, when an admin unlinks their own last
        // link - the durable removal above is why that is safe). Runs AFTER the removal is persisted, so a
        // revoke that throws leaves the unlink already complete rather than half-done. Per-provider disable
        // deliberately does NOT revoke: Jellyfin attributes no live session to the originating SSO provider
        // (RevokeUserTokens is per user id, not per provider), so revoking on disable would be an unscoped
        // mass-logout of every linked user's password and other-provider sessions too (#468).
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
            _ => throw new InvalidOperationException($"Unhandled canonical-link remove result: {removal.Result}"),
        };
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

    // A shallow copy of a provider map, taken under the config lock so the admin list endpoints
    // serialize a detached snapshot rather than the live dictionary (#157/F-10): a concurrent
    // provider add/remove cannot then modify the collection mid-serialization. The provider objects
    // are shared, but their CanonicalLinks are [JsonIgnore] (never serialized), and the only other
    // in-place write on the hot path is the NewPath bool flipped by a challenge - a scalar write that
    // cannot tear a JSON serialization or throw "collection modified".
    private static SerializableDictionary<string, TValue> SnapshotConfigs<TValue>(SerializableDictionary<string, TValue> source)
    {
        var copy = new SerializableDictionary<string, TValue>();
        foreach (var kvp in source)
        {
            copy[kvp.Key] = kvp.Value;
        }

        return copy;
    }

    /// <summary>
    /// Validate a saml link request and create the link if it is valid.
    /// </summary>
    /// <param name="provider">The provider to authenticate against.</param>
    /// <param name="jellyfinUserId">
    ///   The ID of the account to be linked to the provider.
    ///   Must be performed by this user, or an admin.
    /// </param>
    /// <param name="response">The data passed to the client to ensure it is the right one.</param>
    /// <returns>JSON for the client to populate information with.</returns>
    // The SAML manual-link redeem (validate the signed response, consume its one-time-use assertion id,
    // create the link on the NameID) lives on the flow service; the controller keeps the caller-authz
    // guard (AddCanonicalLink) and hands the request in (#160). The former [Consumes]/[Produces] on this
    // private helper were inert (AddCanonicalLink owns the content negotiation, #393).
    private ActionResult SamlLink(string provider, Guid jellyfinUserId, AuthResponse response) =>
        _saml.Link(provider, jellyfinUserId, response, Request);

    /// <summary>
    /// Validate an OIDC link request and create the link if it is valid.
    /// </summary>
    /// <param name="provider">The provider to authenticate against.</param>
    /// <param name="jellyfinUserId">
    ///   The ID of the account to be linked to the provider.
    ///   Must be performed by this user, or an admin.
    /// </param>
    /// <param name="response">The data passed to the client to ensure it is the right one.</param>
    /// <returns>JSON for the client to populate information with.</returns>
    // The OID link redeem (which consumes the flow service's authorize state) lives on the flow service;
    // the controller keeps the caller-authz guard (AddCanonicalLink) and hands the binding cookie in. Both
    // flow services now map the write result through the shared FlowResponses home (#160). The former
    // [Consumes]/[Produces] were inert on this private helper (#393).
    private ActionResult OidLink(string provider, Guid jellyfinUserId, AuthResponse response) =>
        _oidc.Link(provider, jellyfinUserId, response, Request.Cookies[AuthorizeStateBinding.CookieName]);

    // Parse the {mode} route token once, at the HTTP boundary (#369): every link endpoint routes its raw
    // route string through here, so the protocol is validated in exactly one place and the typed
    // ProviderMode is threaded inward - no inner layer re-parses or re-compares the string. Fail closed: an
    // unknown token refuses, never defaulting to a protocol.
    //
    // The refusal is a mapped 400 rather than a throw (#1399). Fail-closed is unchanged; what changed is who
    // decides the wire behaviour. A throw left the status and the body to the host's exception middleware,
    // making this the one input on this surface whose answer is not decided in this repository, while every
    // neighbouring refusal renders a chosen status with a chosen body (400 empty key, 400 unknown provider,
    // 404 unknown user id, 409 subject linked elsewhere). A route token typed wrong in a provisioning tool's
    // configuration is the ordinary way this input arrives, so an integrator needs a status they can depend
    // on. The body names the two accepted tokens and never echoes the supplied one, which would reflect
    // caller-controlled text into the response.
    private static BadRequestObjectResult? RefuseUnknownMode(string mode, out ProviderMode parsed) =>
        ProviderModeParser.TryParse(mode, out parsed) ? null : new BadRequestObjectResult(UnknownModeMessage);

    // Fronts a rate-limited endpoint with the shared per-client gate (#128, #160, #382, #516): null when the
    // request may proceed, else the throttled outcome the single mapper renders (#474). The anonymous login
    // endpoints pass their class (challenge/callback/auth); the authenticated link/unlink write surface passes
    // "link" after its own authz guard, and the admin SSO-revoke passes "unregister" after its elevation
    // guard. The gate owns the one process-wide limiter and the whole check (config read,
    // IP classifier, endpoint-class keying, the #195 observability signal); this wrapper only supplies the
    // three request-scoped inputs it needs - the endpoint class, the connection's remote address, and the
    // response the retry-delay header is set on - so the controller keeps no rate-limit state of its own.
    private ActionResult? RateLimitCheck(string endpointClass) =>
        SsoRateLimitGate.Check(endpointClass, HttpContext.Connection.RemoteIpAddress, _logger, Response);
}
