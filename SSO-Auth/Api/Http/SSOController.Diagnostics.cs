// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
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
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
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

namespace Jellyfin.Plugin.SSO_Auth.Api.Http;

/// <summary>The diagnostic endpoints: provider connection tests, the readiness check and the metrics exposition.</summary>
public partial class SSOController
{
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

        try
        {
            return Ok(await ProviderConnectionTester.TestOidcAsync(config, provider, _httpClientFactory, _logger, HttpContext.RequestAborted).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (HttpContext.RequestAborted.IsCancellationRequested)
        {
            // The admin's browser left before the probe answered (#1558). The host's exception middleware
            // would log a propagated cancellation at Error and answer 500; a probe nobody is waiting for is
            // neither, so it answers a fixed 400 with no log line and no provider verdict.
            return BadRequest("The request was cancelled before the probe finished.");
        }
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

    /// <summary>Answers, for every configured provider at once, whether a login against it would get past the configuration and why not (#1084); elevation-gated and read-only.</summary>
    /// <remarks>Advisory and without outbound request: whether an identity provider answers is what the per-provider Test routes are for, and probing them all from here would spend the shared <see cref="SsoRateLimitClass.Test"/> budget and name working providers as broken.</remarks>
    /// <returns>One row per configured provider; an empty list where none is configured.</returns>
    [Authorize(Policy = Policies.RequiresElevation)]
    [HttpGet("Config/Check")]
    public ActionResult<ProviderCheckDocument> CheckProviders()
    {
        // The serve-defaults state rides along (#1543). Without it a server whose configuration could not
        // be read answers this with an empty provider list, which reads as "nothing is configured" to an
        // operator whose providers are sitting on disk in a file the server refused - the one report that
        // exists to say whether a login would work would be the one hiding why none can.
        var unreadable = SSOPlugin.Instance.ServingDefaultConfiguration;
        return Ok(SSOPlugin.Instance.ReadConfiguration(configuration => ProviderCheck.Build(configuration, unreadable)));
    }

    /// <summary>Publishes the auth-path counters as Prometheus text exposition (#1139), so an operator can alert on failed logins, provisioning or provider-fetch errors; elevation-gated and read-only.</summary>
    /// <remarks>Not anonymous, because the exposition names which providers a server has and how often logins fail, which is reconnaissance; a scraper is given a token like any other client. No counter carries a username, a subject or a claim value, which <see cref="SsoMetrics"/> holds by its signatures and a series cap backstops.</remarks>
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
}
