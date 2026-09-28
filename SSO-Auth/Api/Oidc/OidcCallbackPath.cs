// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Jellyfin.Plugin.SSO_Auth.Api.Routing;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>Derives the r/redirect path segment for rebuilding the callback's redirect URI, read off the callback's own route suffix.</summary>
/// <remarks>
/// The token request's redirect_uri must match the authorization request's (RFC 6749 section 4.1.3), and the
/// provider delivers the callback on exactly the route the request advertised, so the segment is read off the
/// callback path rather than tested for a challenge-route marker (#98). Reading the <c>{protocol}/{path-kind}/{provider}</c>
/// suffix through <see cref="RouteSuffix"/> means a protocol-like reverse-proxy prefix cannot decide the spelling (#411, #509).
/// </remarks>
internal static class OidcCallbackPath
{
    /// <summary>
    /// Returns the redirect-path segment ("redirect" or "r") matching the callback route in the given path.
    /// </summary>
    /// <param name="path">The callback request path, e.g. <c>/sso/OID/redirect/{provider}</c>.</param>
    /// <returns>"redirect" when the route's <c>OID/{path-kind}/{provider}</c> suffix names the "redirect" path-kind, otherwise "r".</returns>
    internal static string RedirectSegment(string? path)
    {
        if (!RouteSuffix.TryRead(path, out var suffix))
        {
            return "r";
        }

        return string.Equals(suffix.Protocol, "OID", StringComparison.OrdinalIgnoreCase)
            && string.Equals(suffix.PathKind, "redirect", StringComparison.OrdinalIgnoreCase)
                ? "redirect"
                : "r";
    }
}
