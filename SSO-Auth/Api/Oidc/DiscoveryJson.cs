// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// The one place a provider's OpenID discovery document is turned into a Newtonsoft object graph. Both
/// security facts the challenge reads - PKCE-S256 (#141) and the RFC 9207 response-<c>iss</c> parameter
/// (#210) - are read out of the root this returns, so one discovery response is walked once for both
/// instead of once per fact (#1170).
///
/// Returns <see langword="null"/> rather than throwing for every input that is not a JSON object: a null,
/// empty or blank body, and any document Newtonsoft refuses. Each reader decides for itself what a null
/// root means, and the two answers differ on purpose - PKCE support fails CLOSED, the response-<c>iss</c>
/// flag fails TOLERANT so an unreadable flag never locks out a provider that omits <c>iss</c>.
/// </summary>
internal static class DiscoveryJson
{
    /// <summary>
    /// Parses a discovery document into its root object.
    /// </summary>
    /// <param name="discoveryJson">The raw OpenID discovery document JSON.</param>
    /// <returns>The parsed root, or <see langword="null"/> when the document is absent, blank or malformed.</returns>
    internal static JObject? TryParse(string? discoveryJson)
    {
        if (string.IsNullOrWhiteSpace(discoveryJson))
        {
            return null;
        }

        try
        {
            return JObject.Parse(discoveryJson);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
