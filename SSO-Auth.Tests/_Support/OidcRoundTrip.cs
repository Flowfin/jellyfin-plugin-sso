// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The one home for the scaffolding that drives a real OpenID login through the controller - challenge,
/// callback, redeem - against the in-test provider <see cref="OidcTokenFixture"/> serves. It had two homes
/// until #1351: <c>OidcRoundTripTests</c> kept it privately and <c>OidcIdTokenIsNeverACredentialTests</c>
/// repeated it, and a copy that drifts fails quietly, because both copies keep passing while one of them is
/// driving a flow the plugin no longer has.
///
/// It is scaffolding and not a fixture: it holds no state, asserts only what a caller needs true before its
/// own assertions can mean anything (the challenge really redirected, and really minted a state and a
/// binding), and returns the values that pass between the legs. Every claim a test makes stays in the test.
/// </summary>
internal static class OidcRoundTrip
{
    /// <summary>
    /// Builds a controller harness with one enabled provider <c>kc</c> pointed at the fixture's authority.
    /// Pushed authorization is off so the challenge is a plain redirect, profile loading is off so the
    /// id_token claims are the whole identity, and the authorization/link toggles are off so the redeem
    /// takes the first-time-provision path.
    /// </summary>
    /// <param name="fixture">The in-test identity provider the harness points at.</param>
    /// <param name="responder">The stub HTTP responder serving that provider's endpoints.</param>
    /// <param name="provider">Applied to the provider's own configuration before it is stored.</param>
    /// <param name="plugin">Applied to the whole plugin configuration, for options that are not per-provider.</param>
    /// <returns>The harness, with the provider configured.</returns>
    internal static SsoControllerHarness BuildHarness(
        OidcTokenFixture fixture,
        Func<HttpRequestMessage, HttpResponseMessage> responder,
        Action<OidConfig>? provider = null,
        Action<PluginConfiguration>? plugin = null)
    {
        ArgumentNullException.ThrowIfNull(fixture);

        return new SsoControllerHarness(
            configuration =>
            {
                var config = new OidConfig
                {
                    Enabled = true,
                    OidEndpoint = fixture.Issuer,
                    OidClientId = fixture.ClientId,
                    OidScopes = Array.Empty<string>(),
                    DisablePushedAuthorization = true,
                    DoNotLoadProfile = true,
                    EnableAuthorization = false,
                    AllowExistingAccountLink = false,
                };
                provider?.Invoke(config);
                configuration.OidConfigs["kc"] = config;
                plugin?.Invoke(configuration);
            },
            httpResponder: responder);
    }

    /// <summary>
    /// Serves the fixture's discovery, JWKS and token endpoints; any other URL 404s, so a regression that
    /// reaches an unexpected endpoint is caught rather than absorbed. The token endpoint returns the
    /// supplied id_token.
    /// </summary>
    /// <param name="fixture">The in-test identity provider whose endpoints are served.</param>
    /// <param name="request">The outbound request the stub handler intercepted.</param>
    /// <param name="idToken">The id_token the token endpoint returns.</param>
    /// <param name="advertisePar">Whether the discovery document advertises pushed authorization.</param>
    /// <param name="served">When given, every body served is appended to it, so a search can be shown to work against a body that really carries the token.</param>
    /// <returns>The response for that URL.</returns>
    internal static HttpResponseMessage ServeIdp(
        OidcTokenFixture fixture,
        HttpRequestMessage request,
        string idToken,
        bool advertisePar = false,
        List<string>? served = null)
    {
        ArgumentNullException.ThrowIfNull(fixture);
        ArgumentNullException.ThrowIfNull(request);

        var url = request.RequestUri!.AbsoluteUri;
        string body;
        if (url == fixture.DiscoveryUrl)
        {
            body = fixture.Discovery(advertisePar: advertisePar);
        }
        else if (url == fixture.JwksUrl)
        {
            body = fixture.Jwks();
        }
        else if (url == fixture.TokenUrl)
        {
            body = fixture.TokenEndpointJson(idToken);
        }
        else
        {
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }

        served?.Add(body);
        return Json(body);
    }

    /// <summary>
    /// Drives a real <c>OidChallenge</c> on the descriptive start route and returns the state token and
    /// browser-binding cookie value it minted - the exact pair the callback and redeem legs must present.
    /// </summary>
    /// <param name="harness">The harness whose controller is driven.</param>
    /// <param name="fixture">The provider the challenge must redirect to.</param>
    /// <returns>The state token and the browser-binding cookie value.</returns>
    internal static async Task<(string State, string Binding)> DriveChallenge(SsoControllerHarness harness, OidcTokenFixture fixture)
    {
        ArgumentNullException.ThrowIfNull(harness);
        ArgumentNullException.ThrowIfNull(fixture);

        harness.Controller.HttpContext.Request.Path = "/sso/OID/start/kc";
        var challenge = Assert.IsType<RedirectResult>(await harness.Controller.OidChallenge("kc"));
        Assert.StartsWith(fixture.Issuer + "/authorize", challenge.Url, StringComparison.Ordinal);

        // An absent state reads back as empty here, so the assertion below reports it rather than a throw.
        var state = UrlEncodedQuery.Find(challenge.Url, "state") ?? string.Empty;
        Assert.False(string.IsNullOrEmpty(state));
        var binding = BindingCookie(harness.Controller.Response);
        Assert.False(string.IsNullOrEmpty(binding));
        return (state, binding);
    }

    /// <summary>
    /// Re-points the same context at the callback route the identity provider redirects back to, carrying
    /// the browser-binding cookie the challenge set (#326) so the state's binding gate is satisfied, and
    /// sets the callback query.
    /// </summary>
    /// <param name="harness">The harness whose controller is re-pointed.</param>
    /// <param name="binding">The browser-binding cookie value the challenge minted.</param>
    /// <param name="query">The callback query string, leading question mark included.</param>
    internal static void RepointToCallback(SsoControllerHarness harness, string binding, string query)
    {
        ArgumentNullException.ThrowIfNull(harness);

        harness.Controller.HttpContext.Request.Path = "/sso/OID/redirect/kc";
        harness.Controller.HttpContext.Request.QueryString = new QueryString(query);
        harness.Controller.HttpContext.Request.Headers.Cookie = $"{AuthorizeStateBinding.CookieName}={binding}";
    }

    /// <summary>A fully populated redeem request for the given state token.</summary>
    /// <param name="state">The state token the challenge minted.</param>
    /// <returns>The redeem request.</returns>
    internal static AuthResponse Redeem(string state) => new AuthResponse
    {
        Data = state,
        DeviceID = "device-1",
        DeviceName = "Test Device",
        AppName = "Jellyfin Web",
        AppVersion = "1.0",
    };

    /// <summary>Extracts the browser-binding cookie value the challenge wrote to the response's Set-Cookie header.</summary>
    /// <param name="response">The response the challenge wrote to.</param>
    /// <returns>The cookie value, or empty when the header is absent.</returns>
    internal static string BindingCookie(HttpResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);

        var prefix = AuthorizeStateBinding.CookieName + "=";
        foreach (var header in response.Headers.SetCookie)
        {
            if (header is not null && header.StartsWith(prefix, StringComparison.Ordinal))
            {
                var value = header.Substring(prefix.Length);
                var end = value.IndexOf(';', StringComparison.Ordinal);
                return end >= 0 ? value.Substring(0, end) : value;
            }
        }

        return string.Empty;
    }

    /// <summary>An <c>application/json</c> 200 carrying the given body, for a responder serving one endpoint itself.</summary>
    /// <param name="body">The response body.</param>
    /// <returns>The response.</returns>
    internal static HttpResponseMessage Json(string body) =>
        new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
}
