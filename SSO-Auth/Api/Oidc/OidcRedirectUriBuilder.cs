// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>Composes the OIDC redirect_uri this service provider hands to identity providers, byte for byte what the call sites produced before (#790).</summary>
/// <remarks>
/// The string is compared for equality on the other side (RFC 6749 section 4.1.3), so the route-decoded provider
/// name is appended raw and never re-encoded. This type only emits a redirect_uri and never compares one; the two
/// places this plugin compares a published URL against an arriving one are <see cref="OidcLogout.IsAllowedPostLogoutRedirect"/>
/// and <see cref="Saml.SamlRecipientValidator.IsBound"/> (#1180).
/// </remarks>
internal static class OidcRedirectUriBuilder
{
    /// <summary>Builds the challenge-time redirect_uri; the spelling follows the route the login started on.</summary>
    /// <param name="baseUrl">The canonical base URL, trailing-slash free (from <see cref="Net.CanonicalBaseUrl.Resolve"/>).</param>
    /// <param name="newPath">Whether the login started on the new-path route, choosing "redirect" over "r".</param>
    /// <param name="provider">The route-decoded provider name, appended raw.</param>
    /// <returns>The absolute redirect_uri to register the authorization request under.</returns>
    internal static string ChallengeRedirectUri(string baseUrl, bool newPath, string provider) =>
        Build(baseUrl, newPath ? "redirect" : "r", provider);

    /// <summary>Builds the token-exchange redirect_uri, echoing the spelling of the callback's own path (#98).</summary>
    /// <param name="baseUrl">The canonical base URL, trailing-slash free.</param>
    /// <param name="callbackPath">The callback request's path, whose OID segment decides the spelling.</param>
    /// <param name="provider">The route-decoded provider name, appended raw.</param>
    /// <returns>The redirect_uri the token request must repeat byte-for-byte.</returns>
    internal static string CallbackRedirectUri(string baseUrl, string? callbackPath, string provider) =>
        Build(baseUrl, OidcCallbackPath.RedirectSegment(callbackPath), provider);

    private static string Build(string baseUrl, string segment, string provider) =>
        baseUrl + "/sso/OID/" + segment + "/" + provider;
}
