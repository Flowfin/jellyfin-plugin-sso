// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Net.Http;
using System.Threading.Tasks;
using Duende.IdentityModel.Client;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// Reads a provider's OpenID discovery document ONCE at the challenge and returns both the two
/// security-relevant facts - PKCE-S256 support (#141, RFC 9700 §2.1.1) and whether the authorization
/// server advertises the RFC 9207 response-<c>iss</c> parameter (#210) - AND the
/// <see cref="Duende.IdentityModel.OidcClient.ProviderInformation"/> the OidcClient login is fed. Before
/// #450 the facts came from a SEPARATE best-effort probe, distinct from the discovery
/// <see cref="OidcClient.PrepareLoginAsync"/> performs internally: the two could disagree, and a failed or
/// omitted probe silently downgraded the RFC 9207 requirement. Sourcing both from one response removes that
/// split - the facts and the login can no longer diverge, and there is no second fetch to fail.
///
/// The fetch is IdentityModel's own <see cref="HttpClientDiscoveryExtensions.GetDiscoveryDocumentAsync(System.Net.Http.HttpMessageInvoker, DiscoveryDocumentRequest, System.Threading.CancellationToken)"/>
/// under the caller's <see cref="DiscoveryPolicy"/> (<c>RequireHttps</c> / <c>ValidateIssuerName</c> /
/// <c>ValidateEndpoints</c> / the additional base addresses) - the exact call and policy OidcClient uses,
/// so the plugin-owned read honours the same channel and endpoint validation rather than a bespoke,
/// unvalidated GET (closing the earlier probe's <c>RequireHttps</c> gap). The resulting metadata is fed to
/// PrepareLoginAsync via <see cref="OidcClientOptions.ProviderInformation"/>, which suppresses the library's
/// own second discovery.
///
/// Stateless - a fresh read per challenge, exactly the per-challenge discovery the library performed before
/// this change. Nothing is cached: least of all the JWKS the callback validates the id_token against, whose
/// reuse stays bounded by a single authorize state's lifetime (#247), never widened by a process-wide cache.
/// </summary>
internal static class OidcDiscoveryReader
{
    /// <summary>
    /// How much of the library's error text the fail-closed warning may carry (#1194). The text quotes the
    /// URL the fetch was connecting to, and on the JWKS leg that URL is PROVIDER-AUTHORED - the discovery
    /// document named it in <c>jwks_uri</c>. Measured: a document advertising a 200 KB <c>jwks_uri</c> put a
    /// 205,042-character entry in the log, driven by one anonymous challenge, and the response cap
    /// (<see cref="Net.ProviderResponseSizeLimit.MaxProviderResponseBytes"/>, 1 MB) is the only thing that
    /// bounded it at all.
    ///
    /// 512 is chosen to sit well above every error text a working deployment produces - the longest is
    /// "Error connecting to " plus an endpoint URL plus the transport's reason - and far below the point
    /// where repeating the request fills a disk. An operator who needs the whole string has the exception
    /// itself on the catch-all arm below.
    /// </summary>
    private const int MaxLoggedProviderErrorChars = 512;

    /// <summary>Marks an error text this reader cut, so a truncated entry is not read as the whole error.</summary>
    private const string ErrorTruncationMarker = "[truncated]";

    /// <summary>
    /// The bound on ONE discovery/JWKS fetch, so a slow or hanging authorization server cannot stall the
    /// anonymous challenge endpoint. This is the login-critical discovery (its result is fed to
    /// PrepareLoginAsync), so the bound is tighter than the platform-default ~100s the library's own
    /// in-PrepareLoginAsync discovery ran under before #450 - a deliberate anonymous-endpoint DoS-hardening
    /// trade-off: a pathologically slow IdP (a 10s+ cold start) is refused fail-closed and self-heals on the
    /// next challenge, rather than tying up the endpoint. It keeps the 10s the pre-#450 probe already
    /// applied.
    /// <para>
    /// Per ATTEMPT rather than per caller. A caller that reads more than once - the back-channel logout
    /// path, which retries a transient failure rather than leaving an IdP-ordered revocation undone
    /// (#1183) - multiplies this, and its own total budget is stated as a constant derived from it rather
    /// than left implicit.
    /// </para>
    /// </summary>
    internal static readonly TimeSpan FetchTimeout = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Reads the discovery document named by <paramref name="options"/> (its <c>Authority</c> and
    /// <c>Policy.Discovery</c>) and returns the facts plus the provider metadata built from it, or
    /// <see cref="OidcDiscoveryResult.Unavailable"/> when the document could not be read. Never throws - a
    /// transient failure, a policy rejection (e.g. non-HTTPS under <c>RequireHttps</c>), a malformed document,
    /// or a document refused by <see cref="RepeatedMemberScreen"/> for naming a member twice all return
    /// <c>Unavailable</c> so the caller fails the login closed rather than proceeding on unverified facts.
    /// </summary>
    /// <param name="options">The OidcClient options whose <c>Authority</c> and discovery policy the read uses - the same the login is built with.</param>
    /// <param name="provider">The provider name, for the failure warning only.</param>
    /// <param name="httpClientFactory">The shared HTTP client factory the outbound fetch is built over.</param>
    /// <param name="logger">The logger for the fail-closed read-failure warning.</param>
    /// <param name="allowPrivateNetworkAddresses">
    /// The provider's <c>AllowPrivateNetworkAddresses</c> opt-in, selecting the private-permitted outbound
    /// transport for this one read (#1179). Defaults to <see langword="false"/> - the full guard.
    /// </param>
    /// <returns>The facts and provider metadata from the one discovery response, or <see cref="OidcDiscoveryResult.Unavailable"/>.</returns>
    internal static async Task<OidcDiscoveryResult> ReadAsync(OidcClientOptions options, string provider, IHttpClientFactory httpClientFactory, ILogger logger, bool allowPrivateNetworkAddresses = false)
    {
        try
        {
            using var client = SsoHttp.CreateClient(httpClientFactory, allowPrivateNetworkAddresses);
            client.Timeout = FetchTimeout;

            // Screen both documents this read fetches — the well-known document and the JWKS it points at —
            // on the transport, so a body that names a member twice never reaches the library that would
            // resolve the repeat to its last occurrence (#1005). The screen forwards through the client
            // above rather than replacing it, so the User-Agent, the timeout and the SSRF-hardened transport
            // still apply to every screened request; the client is disposed by its own `using`, and
            // disposeHandler:false keeps the invoker from disposing the screen a second time.
            using var screen = new RepeatedMemberScreen(client, provider, logger);
            using var invoker = new HttpMessageInvoker(screen, disposeHandler: false);

            var discovery = await invoker.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
            {
                Address = options.Authority,
                Policy = options.Policy.Discovery,
            }).ConfigureAwait(false);

            if (discovery.IsError)
            {
                // The provider name and the library error are stripped of line endings inline at the log
                // call so an admin-supplied value or a reflected server string cannot forge or split the
                // entry (the log-forging sanitizer never crosses a helper boundary).
                //
                // The error is BOUNDED here too, for the same reason it is stripped here: it is not the
                // plugin's string. It quotes the URL the library was connecting to, which on the JWKS leg
                // the provider chose, so an unbounded entry lets one anonymous challenge write as much log
                // as the response cap allows. The truncation is inline for the same reason the strip is -
                // moving either into a helper takes the sanitizer out of the call the analyzer reads.
                var error = discovery.Error ?? string.Empty;
                logger.LogWarning(
                    "Could not read the OpenID discovery document for provider {Provider}: {Error}. The login fails closed rather than proceeding on unverified discovery facts.",
                    provider?.ReplaceLineEndings(string.Empty),
                    (error.Length > MaxLoggedProviderErrorChars
                        ? string.Concat(error.AsSpan(0, MaxLoggedProviderErrorChars), ErrorTruncationMarker)
                        : error).ReplaceLineEndings(string.Empty));

                // The screen's own record of what it refused, never a re-reading of the library's error
                // text, so the reason the admin probe reports (#1064) cannot drift from the reason logged
                // above. It is Unnamed when the read failed for any reason the screen did not raise - an
                // unreachable endpoint, a policy rejection, the outbound size bound - and the caller then
                // reports the generic cause rather than a specific wrong one. Nothing on the login path
                // branches on it: that path fails closed on `Available` alone. The bound above is on the
                // TEXT this entry carries, and none of it travels on that record: the reason is an enum.
                return OidcDiscoveryResult.Refused(screen.Refusal);
            }

            // Both facts come from the raw body of THIS response (the same bytes the metadata below is
            // parsed from), read through the two fail-closed/tolerant pure parsers: PKCE-S256 fails closed
            // (#141, caller rejects only under RequirePkce), response-iss stays tolerant (#210, absence
            // never locks out a provider that omits `iss`).
            var facts = FactsFrom(discovery.Raw);

            // The exact discovery -> ProviderInformation mapping OidcClient performs internally, so feeding
            // this back into PrepareLoginAsync reproduces the library's own login setup from the very
            // response the facts were read from (#450). Populated only from this policy-validated fetch, so
            // the DiscoveryPolicy is not bypassed.
            var providerInformation = new ProviderInformation
            {
                IssuerName = discovery.Issuer,
                KeySet = discovery.KeySet,
                AuthorizeEndpoint = discovery.AuthorizeEndpoint,
                PushedAuthorizationRequestEndpoint = discovery.PushedAuthorizationRequestEndpoint,
                TokenEndpoint = discovery.TokenEndpoint,
                EndSessionEndpoint = discovery.EndSessionEndpoint,
                UserInfoEndpoint = discovery.UserInfoEndpoint,
                TokenEndPointAuthenticationMethods = discovery.TokenEndpointAuthenticationMethodsSupported,
            };

            return OidcDiscoveryResult.From(facts, providerInformation);
        }
        catch (Exception e)
        {
            logger.LogWarning(
                e,
                "Could not read the OpenID discovery document for provider {Provider}; the login fails closed rather than proceeding on unverified discovery facts.",
                provider?.ReplaceLineEndings(string.Empty));
            return OidcDiscoveryResult.Unavailable;
        }
    }

    /// <summary>
    /// Reads both discovery facts out of ONE parse of the document (#1170). The two readers used to take
    /// the raw body and each walk it themselves, so one response was parsed twice for two booleans; the
    /// parse now happens here, once, and both readers index the root it produced. The asymmetry between
    /// them is unchanged and deliberate: PKCE-S256 fails closed on a document that cannot be parsed,
    /// the RFC 9207 response-<c>iss</c> flag stays tolerant so an unreadable flag never locks out a
    /// provider that omits <c>iss</c> (#210).
    /// </summary>
    /// <param name="discoveryJson">The raw discovery body of the response the facts are read from.</param>
    /// <returns>The two facts this document advertises.</returns>
    internal static DiscoveryFacts FactsFrom(string? discoveryJson)
    {
        var document = DiscoveryJson.TryParse(discoveryJson);
        return new DiscoveryFacts(
            PkceDiscovery.SupportsS256(document),
            OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer(document));
    }
}
