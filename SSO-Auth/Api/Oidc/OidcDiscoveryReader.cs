// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Duende.IdentityModel.Client;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api.Metrics;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>Reads a provider's OpenID discovery document once at the challenge and returns the PKCE-S256 (#141) and RFC 9207 response-<c>iss</c> (#210) facts together with the <see cref="Duende.IdentityModel.OidcClient.ProviderInformation"/> the login is fed.</summary>
/// <remarks>
/// Sourcing the facts and the login metadata from one response means the two cannot diverge and there is no
/// second fetch to fail (#450). The fetch is the library's own discovery call under the caller's
/// <see cref="DiscoveryPolicy"/>, so the plugin-owned read honours the same channel and endpoint validation, and
/// the metadata is handed to <see cref="OidcClient.PrepareLoginAsync"/> through <see cref="OidcClientOptions.ProviderInformation"/>,
/// which suppresses the library's second discovery. Nothing is cached, least of all the JWKS, whose reuse stays
/// bounded by one authorize state's lifetime (#247).
/// </remarks>
internal static class OidcDiscoveryReader
{
    /// <summary>How much of the library's error text the fail-closed warning may carry (#1194).</summary>
    /// <remarks>
    /// The text quotes the URL the fetch was connecting to, and on the JWKS leg that URL is provider-authored, so
    /// without a bound one anonymous challenge writes as much log as the response cap allows. 512 sits above every
    /// error text a working deployment produces and far below the point where repeating the request fills a disk.
    /// </remarks>
    private const int MaxLoggedProviderErrorChars = 512;

    /// <summary>Marks an error text this reader cut, so a truncated entry is not read as the whole error.</summary>
    private const string ErrorTruncationMarker = "[truncated]";

    /// <summary>The bound on one discovery or JWKS fetch, so a slow or hanging authorization server cannot stall the anonymous challenge endpoint.</summary>
    /// <remarks>
    /// Tighter than the platform default the library's own discovery ran under before #450: a pathologically slow
    /// provider is refused fail-closed and self-heals on the next challenge. It is per attempt, so a caller that
    /// retries, the back-channel logout path (#1183), states its own total budget as a constant derived from it.
    /// </remarks>
    internal static readonly TimeSpan FetchTimeout = TimeSpan.FromSeconds(10);

    /// <summary>Reads the discovery document named by <paramref name="options"/> and returns the facts plus the provider metadata built from it, or <see cref="OidcDiscoveryResult.Unavailable"/> when it could not be read.</summary>
    /// <remarks>It never throws for a provider failure, a policy rejection, a malformed document or a repeated member, so the caller fails the login closed; the one exception is the caller's own <paramref name="cancellationToken"/> (#1558), which propagates as <see cref="OperationCanceledException"/> because an abandoned read is neither a provider failure nor a login decision.</remarks>
    /// <param name="options">The OidcClient options whose <c>Authority</c> and discovery policy the read uses, the same the login is built with.</param>
    /// <param name="provider">The provider name, for the failure warning only.</param>
    /// <param name="httpClientFactory">The shared HTTP client factory the outbound fetch is built over.</param>
    /// <param name="logger">The logger for the fail-closed read-failure warning.</param>
    /// <param name="allowPrivateNetworkAddresses">The provider's <c>AllowPrivateNetworkAddresses</c> opt-in, selecting the private-permitted outbound transport for this one read (#1179).</param>
    /// <param name="cancellationToken">The caller's lifetime, passed to the well-known request and the JWKS request it points at (#1558).</param>
    /// <returns>The facts and provider metadata from the one discovery response, or <see cref="OidcDiscoveryResult.Unavailable"/>.</returns>
    internal static async Task<OidcDiscoveryResult> ReadAsync(OidcClientOptions options, string provider, IHttpClientFactory httpClientFactory, ILogger logger, bool allowPrivateNetworkAddresses = false, CancellationToken cancellationToken = default)
    {
        try
        {
            // A caller that has already gone away opens no outbound connection at all (#1558). The transport
            // would notice the token on its own at the first socket operation; checking here first keeps a
            // dead request from spending a connection, and it is the one place a test can observe the wiring
            // without a transport that honours cancellation.
            cancellationToken.ThrowIfCancellationRequested();

            using var client = SsoHttp.CreateClient(httpClientFactory, allowPrivateNetworkAddresses);
            client.Timeout = FetchTimeout;

            // Screen both documents this read fetches - the well-known document and the JWKS it points at -
            // on the transport, so a body that names a member twice never reaches the library that would
            // resolve the repeat to its last occurrence (#1005). The screen forwards through the client
            // above rather than replacing it, so the User-Agent, the timeout and the SSRF-hardened transport
            // still apply to every screened request; the client is disposed by its own `using`, and
            // disposeHandler:false keeps the invoker from disposing the screen a second time.
            using var screen = new RepeatedMemberScreen(client, provider, logger);
            using var invoker = new HttpMessageInvoker(screen, disposeHandler: false);

            var discovery = await invoker.GetDiscoveryDocumentAsync(
                new DiscoveryDocumentRequest
                {
                    Address = options.Authority,
                    Policy = options.Policy.Discovery,
                },
                cancellationToken).ConfigureAwait(false);

            if (discovery.IsError)
            {
                // Both foreign values, the library error and the refused issuer beside the endpoint it was compared
                // with (#1835), are bounded and stripped of line endings inline at the log call, because the
                // log-forging sanitizer never crosses a helper boundary; the sanitizers run on the foreign text
                // before this reader's own truncation marker is joined to it (#1557).
                var endpoint = options.Authority ?? string.Empty;
                var issuer = RefusedPublishedIssuer(discovery, options);
                if (issuer is not null)
                {
                    logger.LogWarning(
                        "Could not read the OpenID discovery document for provider {Provider}: the issuer it publishes does not match the endpoint configured, and the endpoint field has to carry the published issuer exactly.\nConfigured endpoint: {Endpoint}\nPublished issuer: {Issuer}\nThe login fails closed rather than proceeding on unverified discovery facts.",
                        provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
                        string.Concat(
                            endpoint[..Math.Min(endpoint.Length, MaxLoggedProviderErrorChars)].ReplaceLineEndings(string.Empty).Replace('[', '('),
                            endpoint.Length > MaxLoggedProviderErrorChars ? ErrorTruncationMarker : string.Empty),
                        string.Concat(
                            issuer[..Math.Min(issuer.Length, MaxLoggedProviderErrorChars)].ReplaceLineEndings(string.Empty).Replace('[', '('),
                            issuer.Length > MaxLoggedProviderErrorChars ? ErrorTruncationMarker : string.Empty));
                }
                else
                {
                    var error = discovery.Error ?? string.Empty;
                    logger.LogWarning(
                        "Could not read the OpenID discovery document for provider {Provider}: {Error}. The login fails closed rather than proceeding on unverified discovery facts.",
                        provider?.ReplaceLineEndings(string.Empty).Replace('[', '('),
                        string.Concat(
                            error[..Math.Min(error.Length, MaxLoggedProviderErrorChars)].ReplaceLineEndings(string.Empty).Replace('[', '('),
                            error.Length > MaxLoggedProviderErrorChars ? ErrorTruncationMarker : string.Empty));
                }

                // The refusal is the screen's own record, never a re-reading of the library's text, so the admin
                // probe (#1064) cannot drift from the log; a refused issuer is the one reason this reader names
                // itself (#1837). Counted here as well as on the catch-all (#1139), because the library reports most
                // real failures without throwing and counting only the catch would report a healthy provider through an outage.
                SsoMetrics.ProviderFetchFailed(ProviderFetchStage.Discovery);
                return issuer is null ? OidcDiscoveryResult.Refused(screen.Refusal) : OidcDiscoveryResult.IssuerRefused(issuer);
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
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The caller went away (#1558). Not a fail-closed read and not a provider fetch failure: logging
            // it as one would tell an operator the provider is unhealthy for a browser that closed its tab,
            // and counting it would move the fetch-error gauge for the same non-event. The filter keeps the
            // timeout on its old path: HttpClient ends a slow read with the same exception type, but with
            // THIS token still live, so it falls through to the arm below exactly as before.
            throw;
        }
        catch (Exception e)
        {
            logger.LogWarning(
                e,
                "Could not read the OpenID discovery document for provider {Provider}; the login fails closed rather than proceeding on unverified discovery facts.",
                provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));

            // #1139: the catch-all arm is the fetch-error counter, because it is where every unreadable
            // document ends up - a network failure, a timeout, a body that will not parse.
            SsoMetrics.ProviderFetchFailed(ProviderFetchStage.Discovery);
            return OidcDiscoveryResult.Unavailable;
        }
    }

    /// <summary>Returns the issuer a failed read's document publishes when the policy refused that issuer (#1835), or <see langword="null"/>.</summary>
    /// <remarks>It asks the policy's own comparison rather than the library's error text, so it agrees with the refusal by construction, and reads the raw body through the one discovery parser because the library keeps only the bytes on a policy violation; those bytes already passed <see cref="RepeatedMemberScreen"/>.</remarks>
    /// <param name="discovery">The failed discovery response.</param>
    /// <param name="options">The options the read was made under, their authority and their policy.</param>
    /// <returns>The published issuer the configured authority refuses, or <see langword="null"/>.</returns>
    private static string? RefusedPublishedIssuer(DiscoveryDocumentResponse discovery, OidcClientOptions options)
    {
        var policy = options.Policy.Discovery;
        if (discovery.ErrorType != ResponseErrorType.PolicyViolation
            || !policy.ValidateIssuerName
            || policy.AuthorityValidationStrategy is not { } strategy)
        {
            return null;
        }

        using var document = DiscoveryJson.TryParse(discovery.Raw);
        if (document is null
            || !document.RootElement.TryGetProperty("issuer", out var member)
            || member.ValueKind != JsonValueKind.String
            || member.GetString() is not { } issuer
            || string.IsNullOrWhiteSpace(issuer))
        {
            return null;
        }

        // Policy.Authority is the value the library compared with: it normalises the configured endpoint -
        // the well-known suffix and the trailing slash stripped - into that field before validating, so this
        // is the comparison that refused rather than a stricter neighbour.
        return strategy.IsIssuerNameValid(issuer, policy.Authority).Success ? null : issuer;
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
        using var document = DiscoveryJson.TryParse(discoveryJson);
        var root = document?.RootElement;
        return new DiscoveryFacts(
            PkceDiscovery.SupportsS256(root),
            OidcResponseIssuer.DiscoveryAdvertisesResponseIssuer(root));
    }
}
