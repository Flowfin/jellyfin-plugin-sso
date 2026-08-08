// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using Duende.IdentityModel.OidcClient;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// The outcome of the OpenID challenge's single discovery read (<see cref="OidcDiscoveryReader"/>, #450):
/// the two security-relevant facts and the <see cref="Duende.IdentityModel.OidcClient.ProviderInformation"/>
/// the login itself is fed - both derived from the SAME discovery response, so the enforcement facts and
/// the login can never diverge, and neither can be silently weakened by a failed second probe.
/// <see cref="Available"/> is <see langword="false"/> only when the document could not be read at all; the
/// caller then fails the login closed rather than proceeding on unverified facts.
/// </summary>
/// <param name="Facts">The PKCE-S256 (#141) and RFC 9207 response-<c>iss</c> (#210) facts read from the document.</param>
/// <param name="ProviderInformation">The provider metadata built from the same document, or null when the read failed.</param>
/// <param name="Refusal">
/// Why an unavailable result is unavailable (#1064), for the admin Test-connection probe. The login path
/// never branches on it: <see cref="Available"/> alone decides, so no value of this can open a door.
/// </param>
internal readonly record struct OidcDiscoveryResult(DiscoveryFacts Facts, ProviderInformation ProviderInformation, OidcDiscoveryRefusal Refusal)
{
    /// <summary>Gets a value indicating whether the discovery document was read (the facts and metadata are usable).</summary>
    internal bool Available => ProviderInformation is not null;

    /// <summary>Gets the failed-read result - no facts, no metadata, no named reason - on which the caller fails the login closed.</summary>
    internal static OidcDiscoveryResult Unavailable => default;

    /// <summary>The same failed read, carrying the reason a caller may report to an administrator.</summary>
    /// <param name="refusal">Why the read came back unavailable.</param>
    /// <returns>An unavailable result naming its reason.</returns>
    internal static OidcDiscoveryResult Refused(OidcDiscoveryRefusal refusal) =>
        Unavailable with { Refusal = refusal };

    /// <summary>A successful read: the facts and the provider metadata, both from the one discovery response.</summary>
    /// <param name="facts">The facts parsed from the discovery document.</param>
    /// <param name="providerInformation">The provider metadata built from the same document (never null on success).</param>
    /// <returns>An available result carrying both.</returns>
    internal static OidcDiscoveryResult From(DiscoveryFacts facts, ProviderInformation providerInformation) =>
        new(facts, providerInformation, OidcDiscoveryRefusal.Unnamed);
}
