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

/// <summary>The SAML sign-in endpoints: challenge, assertion consumer, metadata and authenticate.</summary>
public partial class SSOController
{
    /// <summary>The callback for the SAML flow, which creates a webpage to complete auth.</summary>
    /// <param name="provider">The provider that is calling back.</param>
    /// <param name="relayState">The RelayState given in the original SAML request; equal to "linking", it is a linking request.</param>
    /// <param name="formSamlResponse">The SAMLResponse form field, model-bound so a non-form POST binds null and is rejected instead of throwing an unhandled 500 (#206).</param>
    /// <returns>A webpage that will complete the client-side flow.</returns>
    [HttpPost("SAML/p/{provider}")]
    [HttpPost("SAML/post/{provider}")]
    public async Task<ActionResult> SamlCallback(string provider, [FromQuery] string? relayState = null, [FromForm(Name = "SAMLResponse")] string? formSamlResponse = null)
    {
        if (RateLimitCheck(SsoRateLimitClass.Callback) is { } throttled)
        {
            return BrowserErrorPage.Wrap(throttled, Request, Response);
        }

        if (RefuseWhileServingDefaults() is { } unavailable)
        {
            return BrowserErrorPage.Wrap(unavailable, Request, Response);
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

        if (RefuseWhileServingDefaults() is { } unavailable)
        {
            return BrowserErrorPage.Wrap(unavailable, Request, Response);
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

        if (RefuseWhileServingDefaults() is { } unavailable)
        {
            return unavailable;
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
}
