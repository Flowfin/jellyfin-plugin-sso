// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Config;
using Jellyfin.Plugin.SSO_Auth.Tests;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Jellyfin.Plugin.SSO_Auth.Bench;

/// <summary>
/// One caller driving the real OpenID login legs in-process: <c>OidChallenge</c> on the start route, then
/// <c>OidCallback</c> on the redirect route, carrying the state token and the browser-binding cookie the
/// challenge minted. Discovery, JWKS and the token endpoint are served from
/// <see cref="OidcTokenFixture"/> through the harness's stub HTTP handler, so what is timed is the
/// plugin's own work and never a network round-trip.
///
/// Each instance owns its own harness, so a concurrent run is N callers with N contexts rather than one
/// context mutated from N threads. What they cannot own separately is
/// <see cref="SSOPlugin.Instance"/> - the harness constructor swaps that process-wide static, which is
/// why the test project confines harness-based classes to a non-parallel collection. The bench works
/// inside that constraint by constructing every caller before any of them runs and giving them
/// byte-identical provider configuration, so whichever instance won the swap describes them all.
/// </summary>
internal sealed class LoginRoundTrip
{
    private const string Provider = "bench";
    private const string Host = "jf.example.com";

    private readonly SsoControllerHarness _harness;
    private readonly string _authority;

    /// <summary>
    /// Initializes a new instance of the <see cref="LoginRoundTrip"/> class against the given fake IdP.
    /// </summary>
    /// <param name="idp">The signing IdP whose discovery, JWKS and token endpoint are served in-process.</param>
    /// <param name="idToken">Supplies the id_token the token endpoint returns; read per callback so a
    /// long run can re-mint one before it expires.</param>
    internal LoginRoundTrip(OidcTokenFixture idp, Func<string> idToken)
    {
        _authority = idp.Issuer;
        _harness = new SsoControllerHarness(
            c => c.OidConfigs[Provider] = new OidConfig
            {
                Enabled = true,
                OidEndpoint = idp.Issuer,
                OidClientId = idp.ClientId,
                OidScopes = Array.Empty<string>(),
                // A plain front-channel redirect and no userinfo fetch: both keep the measured work to the
                // legs every provider exercises, rather than to an optional round-trip only some do.
                DisablePushedAuthorization = true,
                DoNotLoadProfile = true,
                EnableAuthorization = false,
                AllowExistingAccountLink = false,
            },
            httpResponder: request => Serve(idp, request, idToken));
    }

    /// <summary>
    /// Runs one challenge-then-callback round-trip and returns the two stage durations as
    /// <see cref="Stopwatch"/> timestamp deltas. Every outcome is checked: a run whose callback stopped
    /// succeeding would otherwise report the latency of a rejection as if it were the latency of a login.
    /// </summary>
    /// <returns>The challenge and callback durations.</returns>
    internal async Task<(long Challenge, long Callback)> RunAsync()
    {
        // A fresh context per iteration, as a real request gets: reusing one accumulates a Set-Cookie
        // header per challenge, which both grows without bound and makes the binding cookie ambiguous.
        NewContext("/sso/OID/start/" + Provider);

        var started = Stopwatch.GetTimestamp();
        var challenge = await _harness.Controller.OidChallenge(Provider).ConfigureAwait(false);
        var challenged = Stopwatch.GetTimestamp();

        if (challenge is not RedirectResult redirect || !redirect.Url.StartsWith(_authority, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The challenge did not redirect to the IdP, so there is no login latency to report. Got: " + Describe(challenge));
        }

        var state = UrlEncodedQuery.Find(redirect.Url, "state");
        if (string.IsNullOrEmpty(state))
        {
            throw new InvalidOperationException("The challenge redirect carried no state parameter.");
        }

        var cookies = SetCookies(_harness.Controller.Response);
        NewContext("/sso/OID/redirect/" + Provider);
        _harness.Controller.HttpContext.Request.QueryString = new QueryString(
            string.Create(CultureInfo.InvariantCulture, $"?code=bench-code&state={state}"));
        _harness.Controller.HttpContext.Request.Headers.Cookie = cookies;

        var callbackStarted = Stopwatch.GetTimestamp();
        var callback = await _harness.Controller.OidCallback(Provider, state).ConfigureAwait(false);
        var completed = Stopwatch.GetTimestamp();

        // The signed-in page. A rejection answers text/plain with a 400, so this distinguishes the two
        // without reading a message the plugin deliberately keeps generic.
        if (callback is not ContentResult content || content.ContentType != "text/html")
        {
            throw new InvalidOperationException(
                "The callback did not complete the login, so the measured time is not a login's. Got: " + Describe(callback));
        }

        return (challenged - started, completed - callbackStarted);
    }

    /// <summary>
    /// Serves the fixture's discovery, JWKS and token endpoints; anything else 404s, so a login that
    /// started reaching an endpoint this bench does not stub fails instead of timing a 404.
    /// </summary>
    private static HttpResponseMessage Serve(OidcTokenFixture idp, HttpRequestMessage request, Func<string> idToken)
    {
        var url = request.RequestUri!.AbsoluteUri;
        if (url == idp.DiscoveryUrl)
        {
            return Json(idp.Discovery());
        }

        if (url == idp.JwksUrl)
        {
            return Json(idp.Jwks());
        }

        return url == idp.TokenUrl
            ? Json(idp.TokenEndpointJson(idToken()))
            : new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private static HttpResponseMessage Json(string body) =>
        new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    /// <summary>
    /// Echoes back every cookie the previous leg set, the way a browser does: the attributes after the
    /// first semicolon are dropped and the name=value pairs are joined. Reading the header rather than a
    /// cookie name means the bench keeps working if the plugin renames or adds one.
    /// </summary>
    private static string SetCookies(HttpResponse response)
    {
        var jar = new StringBuilder();
        foreach (var header in response.Headers.SetCookie)
        {
            if (string.IsNullOrEmpty(header))
            {
                continue;
            }

            var end = header.IndexOf(';', StringComparison.Ordinal);
            if (jar.Length > 0)
            {
                jar.Append("; ");
            }

            jar.Append(end >= 0 ? header.AsSpan(0, end) : header.AsSpan());
        }

        return jar.ToString();
    }

    private static string Describe(IActionResult result) => result switch
    {
        ContentResult content => string.Create(
            CultureInfo.InvariantCulture,
            $"{content.StatusCode?.ToString(CultureInfo.InvariantCulture) ?? "200"} {content.ContentType} {content.Content}"),
        RedirectResult redirect => "redirect to " + redirect.Url,
        _ => result.GetType().Name,
    };

    private void NewContext(string path)
    {
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString(Host);
        http.Request.Path = path;
        // Loopback is unattributable to the per-client budget limiter, so a long run is bounded by the
        // authorize-state store's global cap and not by one client's share of it.
        http.Connection.RemoteIpAddress = IPAddress.Loopback;
        _harness.Controller.ControllerContext.HttpContext = http;
    }
}
