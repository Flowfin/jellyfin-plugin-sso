// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Http;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Api;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the admin redirect-URI endpoint (#1303), the one producer of the bytes an
/// administrator registers at an identity provider. The admin config page used to compose those bytes in
/// JavaScript, so the page and the login were two producers of a string RFC 6749 section 4.1.3 compares
/// literally - and the two disagreeing does not fail here, it fails at the identity provider. These pin
/// that the endpoint answers with the same canonical base the challenge uses (base-URL override,
/// scheme/port overrides included), that it invents nothing for a provider the server does not hold, and
/// that its answer equals the redirect_uri an actual authorization request carries.
/// </summary>
[Collection("SSOController")]
public class SSOControllerOidRedirectUriTests
{
    [Fact]
    public void OidRedirectUri_IsGuardedByTheElevationPolicy()
    {
        // The value is not a secret, but it reports a provider's configured base-URL override, so it is
        // administrator-only like every other per-provider admin read. Pinned structurally because the
        // harness calls the action directly and never runs MVC's authorization filter.
        var authorize = typeof(SSOController).GetMethod(nameof(SSOController.OidRedirectUri))!
            .GetCustomAttribute<AuthorizeAttribute>();

        Assert.NotNull(authorize);
        Assert.Equal(Policies.RequiresElevation, authorize!.Policy);
    }

    [Fact]
    public void OidRedirectUri_UnknownProvider_ReturnsNotFound()
    {
        // No value is invented for a provider the server holds nothing about. The page turns this into
        // "save the provider first" rather than displaying a string nothing would ever send.
        var harness = new SsoControllerHarness();

        Assert.IsType<NotFoundObjectResult>(harness.Controller.OidRedirectUri("does-not-exist"));
    }

    [Fact]
    public void OidRedirectUri_UsesTheRequestHostWhenNoOverrideIsConfigured()
    {
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true });

        var ok = Assert.IsType<OkObjectResult>(harness.Controller.OidRedirectUri("kc"));

        Assert.Equal("https://jf.example.com/sso/OID/redirect/kc", ok.Value);
    }

    [Fact]
    public void OidRedirectUri_HonoursTheConfiguredBaseUrlOverride()
    {
        // The override is the reverse-proxy case, and it is the reason the page could not be trusted to
        // compute this: System.Uri canonicalizes it here (scheme and host lowercased, the default port
        // elided, the trailing slash trimmed), and a browser-side re-derivation of those rules is a second
        // definition of them that only has to disagree once.
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            BaseUrlOverride = "HTTPS://Jellyfin.EXAMPLE.com:443/media/",
        });

        var ok = Assert.IsType<OkObjectResult>(harness.Controller.OidRedirectUri("kc"));

        Assert.Equal("https://jellyfin.example.com/media/sso/OID/redirect/kc", ok.Value);
    }

    [Fact]
    public void OidRedirectUri_HonoursTheSchemeAndPortOverrides()
    {
        // The TLS-terminating-proxy shape: an http request on port 8096 answered as the https URL on the
        // default port that the login actually builds.
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc"] = new OidConfig
        {
            Enabled = true,
            SchemeOverride = "https",
            PortOverride = 443,
        });
        harness.Controller.ControllerContext.HttpContext.Request.Scheme = "http";
        harness.Controller.ControllerContext.HttpContext.Request.Host = new HostString("jf.example.com", 8096);

        var ok = Assert.IsType<OkObjectResult>(harness.Controller.OidRedirectUri("kc"));

        Assert.Equal("https://jf.example.com/sso/OID/redirect/kc", ok.Value);
    }

    [Fact]
    public void OidRedirectUri_DoesNotFollowTheStoredNewPathSpelling()
    {
        // NewPath is server-managed runtime state recording the spelling the LAST non-linking login arrived
        // on, and it defaults to the legacy one. Reading it here would show a provider nobody has logged in
        // with yet the "/r/" route its first login does not use, because every sign-in entry point the
        // plugin renders is the "/start/" route. The display is therefore fixed on the new-path spelling,
        // and this pins that a stored legacy value does not move it.
        var harness = new SsoControllerHarness(c => c.OidConfigs["kc"] = new OidConfig { Enabled = true, NewPath = false });

        var ok = Assert.IsType<OkObjectResult>(harness.Controller.OidRedirectUri("kc"));

        Assert.Equal("https://jf.example.com/sso/OID/redirect/kc", ok.Value);
    }

    [Fact]
    public async Task OidRedirectUri_EqualsTheRedirectUriAnAuthorizationRequestCarries()
    {
        // The claim the endpoint exists for, measured against a real authorization request rather than
        // against a second expectation written in this file: drive the challenge on the route the plugin's
        // own sign-in button links, read redirect_uri back out of the authorize URL the browser is sent to,
        // and require the endpoint's answer to equal it byte for byte.
        const string Authority = "https://idp-redirect-uri.example.com";
        var harness = new SsoControllerHarness(
            c => c.OidConfigs["kc"] = new OidConfig
            {
                Enabled = true,
                OidEndpoint = Authority,
                OidClientId = "jf",
                OidScopes = Array.Empty<string>(),
                DisablePushedAuthorization = true,
                BaseUrlOverride = "https://jellyfin.example.com/media",
            },
            httpResponder: Responder);
        harness.Controller.ControllerContext.HttpContext.Request.Path = "/sso/OID/start/kc";

        var redirect = Assert.IsType<RedirectResult>(await harness.Controller.OidChallenge("kc"));
        var sent = RedirectUriOf(redirect.Url);
        var shown = Assert.IsType<OkObjectResult>(harness.Controller.OidRedirectUri("kc")).Value;

        Assert.Equal("https://jellyfin.example.com/media/sso/OID/redirect/kc", sent);
        Assert.Equal(sent, shown);
    }

    [Fact]
    public async Task OidRedirectUri_DoesNotCoverALoginStartedOnTheLegacyRoute()
    {
        // The residual, stated as a test rather than left for somebody to discover at an identity provider.
        // Both start routes stay live, and a login that begins at the legacy "/p/" one sends the legacy
        // "/r/" spelling. The endpoint answers for the route the plugin renders, so for that deployment the
        // shown value is not the sent one, and the field's help text says so and names the other spelling.
        const string Authority = "https://idp-legacy-route.example.com";
        var harness = new SsoControllerHarness(
            c => c.OidConfigs["kc"] = new OidConfig
            {
                Enabled = true,
                OidEndpoint = Authority,
                OidClientId = "jf",
                OidScopes = Array.Empty<string>(),
                DisablePushedAuthorization = true,
            },
            httpResponder: Responder);
        harness.Controller.ControllerContext.HttpContext.Request.Path = "/sso/OID/p/kc";

        var redirect = Assert.IsType<RedirectResult>(await harness.Controller.OidChallenge("kc"));
        var sent = RedirectUriOf(redirect.Url);
        var shown = Assert.IsType<OkObjectResult>(harness.Controller.OidRedirectUri("kc")).Value;

        Assert.Equal("https://jf.example.com/sso/OID/r/kc", sent);
        Assert.Equal("https://jf.example.com/sso/OID/redirect/kc", shown);
        Assert.NotEqual(sent, shown);
    }

    // Reads redirect_uri back out of the authorize URL the challenge redirects the browser to, so the
    // comparison is against the bytes that leave this server rather than against a rebuilt expectation.
    private static string RedirectUriOf(string authorizeUrl)
    {
        foreach (var pair in new Uri(authorizeUrl).Query.TrimStart('?').Split('&'))
        {
            var parts = pair.Split('=', 2);
            if (parts.Length == 2 && string.Equals(parts[0], "redirect_uri", StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(parts[1]);
            }
        }

        throw new InvalidOperationException("The authorization request carries no redirect_uri: " + authorizeUrl);
    }

    // Serves only the discovery document and its JWKS; any other URL fails the request, so a regression
    // that reaches the token endpoint during a challenge is caught rather than silently answered.
    private static HttpResponseMessage Responder(HttpRequestMessage request)
    {
        var url = request.RequestUri!.AbsoluteUri;
        var authority = url.Substring(0, url.IndexOf('/', "https://".Length));

        if (url == authority + "/.well-known/openid-configuration")
        {
            return Json(Discovery(authority));
        }

        return url == authority + "/jwks"
            ? Json("{\"keys\":[]}")
            : new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private static string Discovery(string authority) =>
        $"{{\"issuer\":\"{authority}\","
        + $"\"authorization_endpoint\":\"{authority}/authorize\","
        + $"\"token_endpoint\":\"{authority}/token\","
        + $"\"jwks_uri\":\"{authority}/jwks\","
        + $"\"userinfo_endpoint\":\"{authority}/userinfo\","
        + "\"response_types_supported\":[\"code\"],"
        + "\"subject_types_supported\":[\"public\"],"
        + "\"id_token_signing_alg_values_supported\":[\"RS256\"],"
        + "\"grant_types_supported\":[\"authorization_code\"],"
        + "\"code_challenge_methods_supported\":[\"S256\"]}";

    private static HttpResponseMessage Json(string body) =>
        new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
}
