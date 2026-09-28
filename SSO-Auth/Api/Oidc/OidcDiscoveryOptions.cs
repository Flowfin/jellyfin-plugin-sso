// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>Builds the <see cref="OidcClientOptions"/> authority and discovery policy from a provider config in one place, so the login path and the admin Test-connection probe fetch discovery under the same SSRF and TLS posture (#163).</summary>
/// <remarks>
/// <see cref="Flows.OidcLoginService"/> layers the client credentials, redirect URI, scope and the id_token
/// validator on top; the probe reads discovery only. The client secret is not set here, because discovery and
/// JWKS need no credential, so the probe never reveals the at-rest secret.
/// </remarks>
internal static class OidcDiscoveryOptions
{
    /// <summary>
    /// Builds options carrying only the provider's Authority and discovery policy. Throws
    /// <see cref="UriFormatException"/> / <see cref="ArgumentNullException"/> when the configured endpoint is
    /// null or not an absolute URL - the caller decides whether that is a fail-closed login error (the login
    /// wraps this in its secret-reveal guard) or an actionable Test-connection result.
    /// </summary>
    /// <param name="config">The OpenID provider configuration.</param>
    /// <returns>Options with Authority and Policy.Discovery set from the config.</returns>
    internal static OidcClientOptions Build(OidConfig config)
    {
        var authority = config.OidEndpoint?.Trim();
        var options = new OidcClientOptions { Authority = authority };
        var oidEndpointUri = new Uri(authority!);
        options.Policy.Discovery.AdditionalEndpointBaseAddresses.Add(oidEndpointUri.GetLeftPart(UriPartial.Authority));
        options.Policy.Discovery.ValidateEndpoints = !config.DoNotValidateEndpoints; // For Google and other providers with different endpoints
        options.Policy.Discovery.RequireHttps = !config.DisableHttps;
        options.Policy.Discovery.ValidateIssuerName = !config.DoNotValidateIssuerName;
        return options;
    }
}
