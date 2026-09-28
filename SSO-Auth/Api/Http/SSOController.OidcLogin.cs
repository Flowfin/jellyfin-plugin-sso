// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Mime;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using Jellyfin.Plugin.SSO_Auth.Api.Events;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Logout;
using Jellyfin.Plugin.SSO_Auth.Api.Metrics;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using MediaBrowser.Common.Api;
using MediaBrowser.Common.Extensions;
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

namespace Jellyfin.Plugin.SSO_Auth.Api.Http;

/// <summary>The OpenID Connect sign-in endpoints: challenge, callback, authenticate and the redirect-URI helpers.</summary>
public partial class SSOController
{
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

        if (RefuseWhileServingDefaults() is { } unavailable)
        {
            return BrowserErrorPage.Wrap(unavailable, Request, Response);
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

        if (RefuseWhileServingDefaults() is { } unavailable)
        {
            return BrowserErrorPage.Wrap(unavailable, Request, Response);
        }

        // The OpenID challenge lives in the flow service (#160, #318): it reads discovery, applies the
        // PKCE gate, prepares the authorization request, registers the browser-bound authorize state, and
        // redirects to the identity provider (setting the binding cookie on the response).
        // This endpoint is browser-navigated, so a plain-text rejection is restyled as an HTML page (#668).
        return BrowserErrorPage.Wrap(await _oidc.ChallengeAsync(provider, isLinking, Request, Response).ConfigureAwait(false), Request, Response);
    }

    /// <summary>Returns the exact OpenID <c>redirect_uri</c> a stored provider's login sends, so the admin page can show it for verbatim registration rather than composing a second copy in JavaScript (#1303).</summary>
    /// <remarks>Elevation-gated like the other admin endpoints, because the value reveals a provider's base-URL override; read-only and without outbound request, so it takes no rate-limit class, and an unknown provider is the same 404 the other per-provider reads return.</remarks>
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

        if (RefuseWhileServingDefaults() is { } unavailable)
        {
            return unavailable;
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
}
