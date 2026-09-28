// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Events;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Logout;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Extensions;
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

/// <summary>The single-logout endpoints for both protocols: RP-initiated, back-channel and IdP-initiated.</summary>
public partial class SSOController
{
    /// <summary>Mints a one-time ticket a browser may spend at <see cref="OidLogout"/> in place of a session (#1768), because the logout route is a top-level navigation that carries no Authorization header.</summary>
    /// <remarks>
    /// A ticket is the short-lived stand-in for the access token a client used to put in the query string: bound
    /// to this caller's user and the named provider, carrying this caller's own session token, worthless after a
    /// minute and accepted once; what the binding covers is the local sign-out (#1794). A POST because it makes
    /// something, so no navigation or prefetch reaches it by accident. The provider name is carried through
    /// unexamined, because the logout route already answers a name it cannot act on with the local-only sign-out.
    /// </remarks>
    /// <param name="provider">The OpenID provider the ticket may be spent at, and at no other.</param>
    /// <returns>The ticket token; 429 when the caller's address is over the Logout budget, 503 when a capacity bound refused it and a retry may clear it, 401 or 400 when this request could never have been issued one.</returns>
    [Authorize]
    [HttpPost("OID/logout-ticket/{provider}")]
    public async Task<ActionResult> OidLogoutTicket(string provider)
    {
        // Rate-limited on the Logout class (#1796): a mint is not a sign-out, so the reason that keeps the
        // session-bearing logout unthrottled does not reach here, and the store's per-account sub-cap is an
        // occupancy bound that never protected this endpoint's cost. The gate sits after the authorization check,
        // so a refused request costs nothing; the limiter is off on a stock install, so on the shipped default only
        // the occupancy bound stands. Behind the Single Logout switch, because a ticket minted with the feature off
        // could never do anything and would add an always-on authenticated surface holding a live session token.
        if (!SSOPlugin.Instance.ReadConfiguration(configuration => configuration.EnableSingleLogout))
        {
            return NotFound();
        }

        var auth = await _authContext.GetAuthorizationInfo(HttpContext.Request).ConfigureAwait(false);
        if (!IsAuthenticatedCaller(auth))
        {
            return Unauthorized();
        }

        if (RateLimitCheck(SsoRateLimitClass.Logout) is { } throttled)
        {
            return throttled;
        }

        // ISSUANCE IS NOT AUDITED, AND THAT IS DECIDED RATHER THAN OMITTED (#1795). The distinction a mint
        // line would buy - a flood of spent tickets from a flood of guesses - is drawn where a ticket is
        // SPENT: a spent one records a completion on the logout route and a guess records a refusal there,
        // so a line here adds nothing to it. What it would add is a line at request rate from any signed-in
        // account, because the gate above is off on a stock install and this endpoint then serves every ask
        // until the account's share is full - the log amplification the refusal placement on the logout route
        // exists to avoid, reachable here by a credential rather than by none. And a mint by itself changes nothing: the
        // ticket can end only the minting caller's own session, and until it is spent no session has ended.
        // The capacity refusals below are the mint's only lines, throttled and naming no account.
        // SSOControllerLogoutTicketTests pins the absence so it cannot drift back in unargued.
        var ticket = _logoutTickets.Mint(auth.UserId, provider, auth.Token, DateTime.UtcNow, out var outcome);
        if (ticket is not null)
        {
            return Ok(new LogoutTicketResponse(ticket));
        }

        // One status per class of answer (#1796): 503 means come back later and only the capacity bound clears by
        // waiting, so it keeps 503 and the body saying the local sign-out still works; a caller this request cannot
        // bind a ticket to is a 401 and a request naming no provider a 400, neither with a body. The
        // unassigned-outcome arm lands in the 401 rather than the retryable answer, which fails closed.
        return outcome switch
        {
            MintOutcome.AtCapacity => StatusCode(StatusCodes.Status503ServiceUnavailable, LogoutTicketUnavailableMessage),
            MintOutcome.NoProvider => BadRequest(),
            _ => Unauthorized(),
        };
    }

    /// <summary>RP-initiated OpenID logout (#727): ends the caller's local Jellyfin session, then, when the caller has a captured OpenID session for this provider and Single Logout is on, redirects the browser to the provider's <c>end_session_endpoint</c> with the stored <c>id_token_hint</c>; anything missing degrades to a local-only logout.</summary>
    /// <remarks>
    /// Two ways to say who is calling (#1768): with no <c>ticket</c> the route is the authenticated self-logout, and
    /// with one the caller is a top-level navigation named by a ticket minted a minute ago by the same user for this
    /// provider. <c>[Authorize]</c> is gone because the ticket path could never satisfy it; <see cref="IsAuthenticatedCaller"/>
    /// stands in its place without a claim of equivalence, and a token resolving to no user is refused on the credential-less arm (#1792).
    /// </remarks>
    /// <param name="provider">The OpenID provider to end the session at.</param>
    /// <param name="ticket">A one-time ticket from <see cref="OidLogoutTicket"/>, for a caller that cannot send a session header. Absent for the authenticated form.</param>
    /// <returns>A redirect to the IdP end-session URL, or to this server for a local-only logout.</returns>
    [HttpGet("OID/logout/{provider}")]
    public async Task<ActionResult> OidLogout(string provider, [FromQuery] string? ticket = null)
    {
        var viaTicket = !string.IsNullOrEmpty(ticket);
        var (refusal, caller) = viaTicket
            ? RedeemLogoutTicket(provider, ticket!)
            : await AuthenticatedLogoutCallerAsync(provider).ConfigureAwait(false);
        if (refusal is not null)
        {
            return refusal;
        }

        var userId = caller.UserId;
        var sessionToken = caller.SessionToken;

        // The caller's most recent captured OpenID session for this provider, scoped to their own user id and read
        // under the config lock; with several sessions the hint may belong to a sibling session of the same
        // subject, a within-user best effort. The ticket arm is inside that hedge (#1794): it binds the local
        // revoke and nothing about this selection, because the entries are keyed by a session id the ticket never
        // captured, and the logout-ticket suite pins the selection so a change rewrites the texts that describe it.
        var match = SSOPlugin.Instance.ReadConfiguration(configuration =>
            SessionLogoutStore.FindByUser(configuration, userId)
                .FirstOrDefault(pair =>
                    string.Equals(pair.Value.Provider, provider, StringComparison.Ordinal)
                    && !string.IsNullOrEmpty(pair.Value.IdToken)));

        // End the caller's local Jellyfin session (their current token only), then drop the consumed entry so
        // the id_token is not retained past the logout. On the ticket path the token is the one the MINTING
        // request carried, so the session that is ended is the session that asked for the ticket, and not
        // merely some session of that user.
        if (!string.IsNullOrEmpty(sessionToken))
        {
            await _sessionManager.Logout(sessionToken).ConfigureAwait(false);
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

        // The completion is audited on the ticket arm only (#1795), because that arm ends a session for a request
        // whose only credential was a bearer string in a query parameter and its refusals were already audited;
        // written after the sign-out and the redirect decision, so the outcome code says what happened, and it
        // carries the provider and a fixed code, never the ticket, the token or the user.
        if (viaTicket)
        {
            SsoAudit.OpenIdTicketLogoutCompleted(_logger, provider, endSessionUrl is null ? "local_only" : "end_session_redirect");
        }

        // Redirect to the IdP end-session URL (an absolute URL host-bound to the discovered issuer by
        // OidcLogout), or - local-only - back to this server via a LOCAL redirect. The local fallback must NOT
        // reuse the canonical base as an absolute target: with no Base URL Override that base is derived from
        // the request Host header, so a spoofed Host would turn the fallback into an open redirect. A local
        // ("~/") redirect is host-independent and ASP.NET Core rejects any non-local value outright.
        return endSessionUrl is null ? LocalRedirect("~/") : Redirect(endSessionUrl);
    }

    // The ticket arm of OidLogout (#1768): the ticket is spent under the Single Logout switch (#1793), then the
    // account behind it is read again, so a ticket minted the second before a disable is refused. Both refusals
    // are throttled before they are audited (#1792); the session token the ticket carries is not re-verified.
    private (ActionResult? Refusal, LogoutCaller Caller) RedeemLogoutTicket(string provider, string ticket)
    {
        var singleLogoutEnabled = SSOPlugin.Instance.ReadConfiguration(configuration => configuration.EnableSingleLogout);
        var redeemed = _logoutTickets.Redeem(ticket, provider, DateTime.UtcNow, singleLogoutEnabled);
        if (redeemed is null)
        {
            if (RateLimitCheck(SsoRateLimitClass.LogoutRefusal) is { } throttledTicket)
            {
                return (throttledTicket, default);
            }

            AuditCredentiallessLogoutRefusal(provider, "logout_ticket_not_redeemable");
            return (Unauthorized(), default);
        }

        if (_userManager.GetUserById(redeemed.UserId) is not { } account || account.HasPermission(PermissionKind.IsDisabled))
        {
            if (RateLimitCheck(SsoRateLimitClass.Logout) is { } throttledAccount)
            {
                return (throttledAccount, default);
            }

            SsoAudit.OpenIdLogoutRefused(_logger, provider, "logout_account_unavailable");
            return (Unauthorized(), default);
        }

        return (null, new LogoutCaller(redeemed.UserId, redeemed.SessionToken));
    }

    // The authenticated arm of OidLogout: what [Authorize] used to answer, throttled first because this is the
    // arm a caller reaches with nothing at all, and audited under the credential-less budget (#1792).
    private async Task<(ActionResult? Refusal, LogoutCaller Caller)> AuthenticatedLogoutCallerAsync(string provider)
    {
        var auth = await _authContext.GetAuthorizationInfo(HttpContext.Request).ConfigureAwait(false);
        if (IsAuthenticatedCaller(auth))
        {
            return (null, new LogoutCaller(auth.UserId, auth.Token));
        }

        if (RateLimitCheck(SsoRateLimitClass.LogoutRefusal) is { } throttledAnonymous)
        {
            return (throttledAnonymous, default);
        }

        AuditCredentiallessLogoutRefusal(provider, "logout_unauthenticated");
        return (Unauthorized(), default);
    }

    /// <summary>Inbound OpenID Connect back-channel logout (#962): the identity provider POSTs a signed <c>logout_token</c> to propagate an IdP-side session termination into Jellyfin.</summary>
    /// <remarks>The endpoint is anonymous and the signature is the only authenticator, so a disabled feature, an unknown or disabled provider and a provider without the opt-in collapse to the same uniform response without parsing the token; the validated (sub, sid) revokes only the matched user's OpenID sessions for this provider, and every rejection audits a fixed reason code.</remarks>
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
        var matches = MatchBackChannelSessions(provider, result.Subject, result.SessionIndex);

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

        ConsumeRevokedSessions(matches, succeeded);

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

    // The blast-radius bound of the back-channel logout: the same provider and subject, OpenID captures only, and
    // the sid when the token names one. A sid-only token is matched on the sid across this provider's captures,
    // because the empty-subject guard of FindByProviderSubject returns nothing for it.
    private static List<KeyValuePair<string, LogoutSession>> MatchBackChannelSessions(string provider, string? subject, string? sessionIndex)
    {
        if (subject is null && sessionIndex is not null)
        {
            return SSOPlugin.Instance.ReadConfiguration(configuration =>
                configuration.LogoutSessions
                    .Where(pair =>
                        string.Equals(pair.Value.Protocol, OpenIdProtocol, StringComparison.Ordinal)
                        && string.Equals(pair.Value.Provider, provider, StringComparison.Ordinal)
                        && string.Equals(pair.Value.SessionIndex, sessionIndex, StringComparison.Ordinal))
                    .ToList());
        }

        return SSOPlugin.Instance.ReadConfiguration(configuration =>
            SessionLogoutStore
                .FindByProviderSubject(configuration, provider, subject ?? string.Empty, sessionIndex ?? string.Empty)
                .Where(pair => string.Equals(pair.Value.Protocol, OpenIdProtocol, StringComparison.Ordinal))
                .ToList());
    }

    // The blast-radius bound of the inbound SAML logout: the same provider and subject, SAML captures only, and
    // the named SessionIndex elements when the request carries any; a request naming none targets every session
    // of the subject (SAML core 3.7).
    private static List<KeyValuePair<string, LogoutSession>> MatchSamlLogoutSessions(string provider, string nameId, IReadOnlyCollection<string> sessionIndexes)
    {
        var matches = SSOPlugin.Instance.ReadConfiguration(configuration =>
            SessionLogoutStore.FindByProviderSubject(configuration, provider, nameId, string.Empty)
                .Where(pair => string.Equals(pair.Value.Protocol, SamlProtocol, StringComparison.Ordinal))
                .ToList());
        return sessionIndexes.Count > 0
            ? matches.Where(pair => sessionIndexes.Contains(pair.Value.SessionIndex ?? string.Empty, StringComparer.Ordinal)).ToList()
            : matches;
    }

    // Drops only the entries whose user was revoked, so a transient revoke fault leaves that user's entry for a
    // later retry rather than dropping it silently.
    private static void ConsumeRevokedSessions(List<KeyValuePair<string, LogoutSession>> matches, HashSet<Guid> succeeded)
    {
        var consumedKeys = matches.Where(pair => succeeded.Contains(pair.Value.UserId)).Select(pair => pair.Key).ToList();
        if (consumedKeys.Count == 0)
        {
            return;
        }

        SSOPlugin.Instance.MutateConfiguration(configuration =>
        {
            foreach (var key in consumedKeys)
            {
                SessionLogoutStore.Remove(configuration, key);
            }
        });
    }

    /// <summary>SP-initiated outbound SAML Single Logout (#727): ends the caller's local Jellyfin session, then, when Single Logout is on and the provider has an SLO endpoint, a signing key and a captured session with a NameID, redirects the browser there with a signed <c>LogoutRequest</c>.</summary>
    /// <remarks>Anything missing degrades to a local-only logout and never a 500; authenticated, rate-limited, and scoped to the caller's own user id, so the request can only ever carry the caller's own NameID.</remarks>
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
                    _logger.LogError("SAML SP-initiated logout for provider {Provider} could not build the signed LogoutRequest: {Reason}; the local logout stands and the browser returns to this server.", provider?.ReplaceLineEndings(string.Empty).Replace('[', '('), ex.Message?.ReplaceLineEndings(string.Empty).Replace('[', '('));
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

    /// <summary>Inbound IdP-initiated SAML Single Logout (#727): accepts a signed <c>LogoutRequest</c> over the POST binding and revokes the linked Jellyfin sessions.</summary>
    /// <remarks>The unauthenticated, session-destructive surface, whose only trust anchor is the XML signature against the provider's configured certificates, so it mirrors the login-side hardening; while Single Logout is off the whole surface rejects without parsing, and every rejection is the same uniform 400, so the causes cannot be told apart.</remarks>
    /// <param name="provider">The SAML provider the LogoutRequest arrived for.</param>
    /// <param name="samlRequest">The <c>SAMLRequest</c> form field (model-bound, so a non-form POST binds null and is rejected).</param>
    /// <param name="relayState">The optional <c>RelayState</c> form field, echoed on the signed <c>LogoutResponse</c> when within the 80-byte SAML binding cap.</param>
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
        var matches = MatchSamlLogoutSessions(provider, nameId, sessionIndexes);

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

        ConsumeRevokedSessions(matches, succeeded);

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
                _logger.LogError("SAML inbound logout for provider {Provider} could not build the signed LogoutResponse: {Reason}; the revocation stands and the endpoint answers 200.", provider?.ReplaceLineEndings(string.Empty).Replace('[', '('), ex.Message?.ReplaceLineEndings(string.Empty).Replace('[', '('));
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

    // The audit line of a credential-less refusal on the RP-initiated OpenID logout, under the budget that
    // bounds it (#1792). The rate-limit gate stands in front of both arms that call this and is the finer
    // instrument where it is on; it is off on a stock install and makes no bucket for a non-public peer,
    // and on that configuration the per-refusal line was the one thing a request with no credential could
    // make this server do without bound. The budget lives on the ticket service, which owns the route's
    // process-wide state, and is keyed on nothing because the source it exists for is not attributable.
    // When the budget reopens, the count of refusals it did not record is written once, before the line
    // that reopened it, so the trail says that lines are missing rather than reading as quiet.
    private void AuditCredentiallessLogoutRefusal(string provider, string reasonCode)
    {
        if (!LogoutTicketService.AdmitRefusalLine(DateTime.UtcNow, out var notRecorded))
        {
            return;
        }

        if (notRecorded > 0)
        {
            SsoAudit.OpenIdLogoutRefusalsNotRecorded(_logger, notRecorded);
        }

        SsoAudit.OpenIdLogoutRefused(_logger, provider, reasonCode);
    }

    // Who a logout is for and the session it ends; on the ticket arm the token is the one the minting request carried.
    private readonly record struct LogoutCaller(Guid UserId, string? SessionToken);
}
