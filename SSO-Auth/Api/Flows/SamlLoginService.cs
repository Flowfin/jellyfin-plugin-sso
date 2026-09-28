// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Events;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Localization;
using Jellyfin.Plugin.SSO_Auth.Api.Logout;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Extensions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Flows;

/// <summary>The SAML login flow: the challenge, the assertion-consumer callback, the session-minting leg, the manual link redeem and the SP metadata.</summary>
/// <remarks>
/// The outstanding-request cache and the login-outcome store are process-wide statics, because a fresh controller
/// reconstructs this service per request. Assertion validation lives in <see cref="SamlAssertionValidator"/>. See
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Login-Flow#saml-20"/>.
/// </remarks>
internal sealed class SamlLoginService
{
    // Outstanding AuthnRequest ids, for InResponseTo correlation and the browser binding (#156, #415).
    private static readonly SamlRequestCache SamlRequests = new SamlRequestCache();

    // Matches the OpenID authorize-state lifetime.
    private static readonly TimeSpan SamlRequestLifetime = TimeSpan.FromMinutes(15);

    // The callback validates the assertion once and hands the page a token; not readonly only so a test can install a small-cap store (#251).
    private static SamlOutcomeStore _outcomes = new SamlOutcomeStore();

    private readonly LoginCompletionService _loginCompletion;
    private readonly CanonicalLinkService _canonicalLinks;
    private readonly SsoLoginEvents _loginEvents;
    private readonly SamlAssertionValidator _validator;
    private readonly ILogger _logger;

    /// <summary>Initializes a new instance of the <see cref="SamlLoginService"/> class.</summary>
    /// <param name="loginCompletion">The shared post-validation login completion pipeline.</param>
    /// <param name="canonicalLinks">The account-linking workflow used by the SAML manual-link redeem.</param>
    /// <param name="loginEvents">Publishes the role-mapping denial on Jellyfin's event bus (#1142).</param>
    /// <param name="logger">The logger, also passed to the constructed assertion validator.</param>
    internal SamlLoginService(
        LoginCompletionService loginCompletion,
        CanonicalLinkService canonicalLinks,
        SsoLoginEvents loginEvents,
        ILogger logger)
    {
        _loginCompletion = loginCompletion ?? throw new ArgumentNullException(nameof(loginCompletion));
        _canonicalLinks = canonicalLinks ?? throw new ArgumentNullException(nameof(canonicalLinks));
        _loginEvents = loginEvents ?? throw new ArgumentNullException(nameof(loginEvents));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _validator = new SamlAssertionValidator(logger);
    }

    /// <summary>Test-only. Clears the outstanding-request cache and resets the shared NewPath persist-throttle gate.</summary>
    internal static void ResetSamlRequestsForTests()
    {
        SamlRequests.Clear();
        ChallengeNewPathResolver.ResetForTests();
    }

    /// <summary>Test-only. Installs a fresh login-outcome store, un-swapping any small-cap store a test installed.</summary>
    internal static void ResetSamlOutcomesForTests() => _outcomes = new SamlOutcomeStore();

    /// <summary>Test-only. Swaps in a specific outcome store so a test can reach the cap path the production ceiling makes unreachable.</summary>
    /// <param name="store">The outcome store to install.</param>
    internal static void SetSamlOutcomeStoreForTests(SamlOutcomeStore store) => _outcomes = store;

    /// <summary>Test-only. Seeds a single login outcome so a test can drive the token-redeem leg without the callback.</summary>
    /// <param name="outcome">The login outcome to seed.</param>
    internal static void SeedSamlOutcomeForTests(SamlLoginOutcome outcome) => _outcomes.Seed(outcome);

    /// <summary>Test-only. Seeds an outstanding AuthnRequest so a test can exercise the browser-binding leg.</summary>
    /// <param name="provider">The provider the request belongs to.</param>
    /// <param name="requestId">The AuthnRequest id to register.</param>
    /// <param name="bindingId">The browser-binding id tied to the request.</param>
    /// <param name="expiryUtc">The UTC expiry of the outstanding request.</param>
    internal static void SeedSamlRequestForTests(string provider, string requestId, string bindingId, DateTime expiryUtc) =>
        SamlRequests.Register(ProviderScopedKey.For(provider, requestId), bindingId, expiryUtc, DateTime.UtcNow, clientKey: null, out _);

    /// <summary>The assertion-consumer callback: validates the signed response and, on a passing role gate, renders the intermediate auth page.</summary>
    /// <param name="provider">The provider that is calling back.</param>
    /// <param name="relayState">The RelayState from the original SAML request; "linking" marks a link request.</param>
    /// <param name="formSamlResponse">The SAMLResponse form field (model-bound, so a non-form POST binds null and is rejected).</param>
    /// <param name="request">The current request; read for the assertion-consumer base URL.</param>
    /// <param name="response">The response the auth page's defensive headers are written to.</param>
    /// <returns>The rendered auth page on success, or a fail-closed rejection.</returns>
    internal async Task<ActionResult> CallbackAsync(string provider, string? relayState, string? formSamlResponse, HttpRequest request, HttpResponse response)
    {
        // Unknown and disabled providers share one rejection, so neither can be probed apart.
        var config = FindSamlConfig(provider);
        if (config is not { Enabled: true })
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.UnknownProvider));
        }

        bool isLinking = string.Equals(relayState, "linking", StringComparison.Ordinal);

        if (_logger.IsEnabled(LogLevel.Information))
        {
            _logger.LogInformation(
                "SAML request has relayState of {RelayState}",
                relayState?.ReplaceLineEndings(string.Empty).Replace('[', '('));
        }

        // Model-bound, so a non-form POST binds null and is refused as malformed rather than throwing (#206).
        var requestBase = GetRequestBase(request, config.SchemeOverride, config.PortOverride, config.BaseUrlOverride);
        var culture = AcceptLanguage.Resolve(request.Headers.AcceptLanguage.ToString());
        if (!_validator.TryValidate(config, provider, requestBase, formSamlResponse, out var samlResponse))
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
        }

        // The parsed response owns the certificate handle; the stored outcome copies out only strings (#674).
        using var ownedResponse = samlResponse;

        // The role XPath runs once per response and feeds the gate, the warning and the identity (#479).
        var assertionRoles = SamlAssertionValidator.GetAssertionRoles(samlResponse);

        if (!SamlLoginPolicy.IsLoginAllowed(assertionRoles, config.Roles))
        {
            return await DenyRoleAsync(provider, config, samlResponse, assertionRoles, request).ConfigureAwait(false);
        }

        // Linking keeps the assertion-embedded page, and the link redeem consumes the assertion on its own leg (#251, #614).
        if (isLinking)
        {
            return FlowResponses.AuthPage(response, nonce =>
                WebResponse.Generator(
                    data: Convert.ToBase64String(Encoding.UTF8.GetBytes(samlResponse.Xml)),
                    provider: provider,
                    baseUrl: requestBase,
                    mode: "SAML",
                    nonce: nonce,
                    isLinking: true,
                    culture: culture));
        }

        return StoreOutcomeAndRenderPage(provider, config, samlResponse, assertionRoles, requestBase, culture, request, response);
    }

    /// <summary>Initiates the SAML login flow: builds the AuthnRequest, binds it to the initiating browser, and redirects to the identity provider.</summary>
    /// <param name="provider">The provider to begin the flow with.</param>
    /// <param name="isLinking">Whether this flow intends to link an account rather than authenticate.</param>
    /// <param name="request">The current request; read for the assertion-consumer base URL, the challenge route spelling, and the client IP.</param>
    /// <param name="response">The response the browser-binding cookie is appended to on a login challenge.</param>
    /// <returns>A redirect to the SAML provider's auth page, or a fail-closed rejection/error.</returns>
    internal ActionResult Challenge(string provider, bool isLinking, HttpRequest request, HttpResponse response)
    {
        var config = FindSamlConfig(provider);
        if (config is not { Enabled: true })
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.UnknownProvider));
        }

        bool newPath = ChallengeNewPathResolver.ResolveChallengeNewPath(provider, config, isLinking, request, _logger, c => c.SamlConfigs);

        string redirectUri = SamlAcsUrlBuilder.AcsUrl(GetRequestBase(request, config.SchemeOverride, config.PortOverride, config.BaseUrlOverride), newPath, provider);
        string? relayState = isLinking ? "linking" : null;

        var samlRequest = new SamlAuthnRequest(
            config.SamlClientId.Trim(),
            redirectUri);

        // A login is bound to the initiating browser (#415); the link flow never consumes the request, so it is not registered.
        // See https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model#login-browser-binding-forced-login-defense
        if (!isLinking)
        {
            var bindingId = AuthorizeStateBinding.NewId();

            // The client key bounds how much of the cache one source can occupy (#327).
            var clientKey = SsoRateLimiter.NormalizeClientKey(request.HttpContext.Connection.RemoteIpAddress);
            if (!SamlRequests.Register(
                    ProviderScopedKey.For(provider, samlRequest.Id),
                    bindingId,
                    DateTime.UtcNow + SamlRequestLifetime,
                    DateTime.UtcNow,
                    clientKey,
                    out var shouldWarnCapacity))
            {
                // Refused here rather than at a callback that could no longer correlate (#327).
                if (shouldWarnCapacity)
                {
                    if (_logger.IsEnabled(LogLevel.Warning))
                    {
                        _logger.LogWarning("SAML request refused for provider {Provider}: the per-client sub-cap or the outstanding-request cache is at capacity (warning throttled).", provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
                    }
                }

                return FlowResponses.PlainTextError(StatusCodes.Status500InternalServerError, "Could not start login; please retry.");
            }

            response.Cookies.Append(
                AuthorizeStateBinding.SamlCookieName,
                bindingId,
                AuthorizeStateBinding.CookieOptions(SamlRequestLifetime));
        }

        string redirectUrl;
        try
        {
            redirectUrl = BuildChallengeRedirectUrl(config, samlRequest, relayState);
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or CryptographicException or FormatException)
        {
            // A request that cannot be signed fails closed rather than going out unsigned; no key material is logged (#158).
            if (_logger.IsEnabled(LogLevel.Error))
            {
                _logger.LogError("SAML challenge for provider {Provider} could not sign the AuthnRequest: {Reason}", provider?.ReplaceLineEndings(string.Empty).Replace('[', '('), ex.Message?.ReplaceLineEndings(string.Empty).Replace('[', '('));
            }

            return FlowResponses.PlainTextError(StatusCodes.Status500InternalServerError, "Could not start login; the SAML request signing key is misconfigured.");
        }

        return new RedirectResult(redirectUrl);
    }

    /// <summary>Serves this service provider's SAML metadata, built only from the configured canonical base URL (#162).</summary>
    /// <remarks>
    /// Anonymous, because metadata is public, and request-free, so a spoofable host can never reach the published
    /// consumer URL. See <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Hardening-and-Options-Reference#saml-service-provider-metadata"/>.
    /// </remarks>
    /// <param name="provider">The SAML provider whose metadata to serve.</param>
    /// <returns>The SP metadata document, or a fail-closed rejection.</returns>
    internal ActionResult Metadata(string provider)
    {
        var config = FindSamlConfig(provider);
        if (config is not { Enabled: true })
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.UnknownProvider));
        }

        if (!CanonicalBaseUrl.TryNormalize(config.BaseUrlOverride, out var baseUrl))
        {
            return FlowResponses.PlainTextError(
                StatusCodes.Status409Conflict,
                "SAML metadata is unavailable: configure this provider's canonical Base URL first, so the published assertion-consumer URL cannot be derived from a spoofable request host.");
        }

        var entityId = config.SamlClientId?.Trim();
        if (string.IsNullOrEmpty(entityId))
        {
            return FlowResponses.PlainTextError(
                StatusCodes.Status409Conflict,
                "SAML metadata is unavailable: this provider has no client id (SP entity id) configured.");
        }

        // Both consumer URL spellings the SP honours are advertised, the new path as the default.
        var acsUrl = SamlAcsUrlBuilder.AcsUrl(baseUrl, newPath: true, provider);
        var legacyAcsUrl = SamlAcsUrlBuilder.AcsUrl(baseUrl, newPath: false, provider);

        if (!TryResolveSigningCertificates(config, out var signingCertificateBase64, out var rolloverSigningCertificateBase64))
        {
            // Metadata never advertises signing the challenge would then fail to perform (#491).
            return FlowResponses.PlainTextError(
                StatusCodes.Status409Conflict,
                "SAML metadata is unavailable: request signing is enabled but a configured signing key could not be loaded.");
        }

        return new ContentResult
        {
            Content = SamlSpMetadataBuilder.Build(entityId, acsUrl, signingCertificateBase64, rolloverSigningCertificateBase64, legacyAcsUrl),
            ContentType = "application/samlmetadata+xml",
            StatusCode = StatusCodes.Status200OK,
        };
    }

    // The public certificates to advertise: an unloadable key fails closed, and a rollover identical to the primary is dropped (#491).
    private static bool TryResolveSigningCertificates(SamlConfig config, out string? signingCertificateBase64, out string? rolloverSigningCertificateBase64)
    {
        signingCertificateBase64 = null;
        rolloverSigningCertificateBase64 = null;
        if (!config.SignAuthnRequests)
        {
            return true;
        }

        if (!TryRevealPublicCertificate(config.SamlSigningKeyPfx, out signingCertificateBase64))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(config.SamlRolloverSigningKeyPfx))
        {
            return true;
        }

        if (!TryRevealPublicCertificate(config.SamlRolloverSigningKeyPfx, out rolloverSigningCertificateBase64))
        {
            return false;
        }

        if (string.Equals(rolloverSigningCertificateBase64, signingCertificateBase64, StringComparison.Ordinal))
        {
            rolloverSigningCertificateBase64 = null;
        }

        return true;
    }

    // Exports only the public DER of a stored signing key; the private key never leaves this method (#158).
    private static bool TryRevealPublicCertificate(string? storedPfx, out string? publicCertificateBase64)
    {
        publicCertificateBase64 = null;

        string? revealed;
        try
        {
            revealed = SSOPlugin.Instance.Secrets.Reveal(storedPfx);
        }
        catch (CryptographicException)
        {
            return false;
        }

        if (revealed is null || !SamlSigningKey.TryLoad(revealed, out var certificate))
        {
            return false;
        }

        using (certificate)
        {
            publicCertificateBase64 = Convert.ToBase64String(certificate.RawData);
            return true;
        }
    }

    /// <summary>The session-minting leg: redeems the one-time outcome token the callback minted, correlates the request and browser binding, and hands the identity to the completion tail.</summary>
    /// <remarks>Only a token is accepted; the assertion was validated once at the callback and is never re-parsed here (#251, #528).</remarks>
    /// <param name="provider">The provider to authenticate against.</param>
    /// <param name="response">The client's auth request context (app/device) plus the SAML response in <c>Data</c>.</param>
    /// <param name="bindingCookie">The browser-binding cookie value the redeem presented (#415).</param>
    /// <param name="remoteEndPointResolver">Resolves the normalized client IP for the activity log (#177).</param>
    /// <returns>The minted session, or a fail-closed rejection.</returns>
    public async Task<ActionResult> AuthenticateAsync(string provider, AuthResponse response, string? bindingCookie, Func<string> remoteEndPointResolver)
    {
        var config = FindSamlConfig(provider);
        if (config is not { Enabled: true })
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.UnknownProvider));
        }

        // An atomic one-time redeem: a replayed token, a foreign provider's token or a raw assertion all miss the same way.
        if (response is null || _outcomes.TryRedeem(response.Data, provider, DateTime.UtcNow) is not { } outcome)
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
        }

        if (!CorrelateAndBind(provider, outcome.InResponseTo, bindingCookie, config.ValidateInResponseTo))
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
        }

        // SAML carries no email_verified claim, and the logout context carries the SessionIndex captured at the callback (#727).
        return await _loginCompletion.CompleteAsync(
            outcome.Identity,
            response,
            config,
            AdoptionGate.None,
            remoteEndPointResolver,
            logoutContext: new LogoutContext(outcome.SessionIndex, IdToken: null)).ConfigureAwait(false);
    }

    // A non-empty InResponseTo whose entry is gone is a lost correlation and fails closed, never an unsolicited response (#156, #415).
    private bool CorrelateAndBind(string provider, string inResponseTo, string? bindingCookie, bool validateInResponseTo)
    {
        if (!string.IsNullOrEmpty(inResponseTo))
        {
            var requestKey = ProviderScopedKey.For(provider, inResponseTo);
            if (!SamlRequests.TryConsume(requestKey, DateTime.UtcNow, out var storedBindingId)
                || !AuthorizeStateBinding.Matches(storedBindingId, bindingCookie))
            {
                _logger.LogWarning("SAML login denied: a solicited response did not correlate to a live outstanding request from the initiating browser (binding mismatch, expiry, or lost correlation).");
                return false;
            }
        }
        else if (validateInResponseTo)
        {
            // A genuinely unsolicited response, refused only under the opt-in solicited-only mode.
            _logger.LogWarning("SAML login denied: the response was not solicited by this server (no InResponseTo).");
            return false;
        }

        return true;
    }

    /// <summary>The manual-link redeem: validates the signed response, consumes its one-time assertion id, and links the NameID.</summary>
    /// <param name="provider">The provider to link against.</param>
    /// <param name="jellyfinUserId">The Jellyfin account to link (already authorized by the controller).</param>
    /// <param name="response">The client information carrying the SAML response in <c>Data</c>.</param>
    /// <param name="request">The current request; read for the assertion-consumer base URL (recipient binding).</param>
    /// <returns>The link-creation result, or a fail-closed rejection.</returns>
    internal ActionResult Link(string provider, Guid jellyfinUserId, AuthResponse response, HttpRequest request)
    {
        // A disabled provider neither creates a link nor consumes the assertion (#343).
        var config = FindSamlConfig(provider);
        if (config is not { Enabled: true })
        {
            return new BadRequestObjectResult(LoginStatusMapper.NoMatchingProviderMessage);
        }

        var requestBase = GetRequestBase(request, config.SchemeOverride, config.PortOverride, config.BaseUrlOverride);
        if (!_validator.TryValidate(config, provider, requestBase, response?.Data, out var samlResponse))
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
        }

        using var ownedResponse = samlResponse;

        // The linking flow issues no AuthnRequest, so the replay cache is the one-time-use control here (#219).
        if (!_validator.TryConsumeReplay(samlResponse, provider))
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SamlResponseInvalid));
        }

        // A missing NameID flows as empty into TryCreateLink's fail-closed empty-subject guard (#95).
        var providerUserId = samlResponse.GetNameID();

        return FlowResponses.MapCanonicalLinkWrite(_canonicalLinks.TryCreateLink(ProviderMode.Saml, provider, providerUserId ?? string.Empty, jellyfinUserId));
    }

    // Read under the config lock, so a login cannot race an admin write on the live dictionary (#252).
    private static SamlConfig? FindSamlConfig(string provider) =>
        SSOPlugin.Instance.ReadConfiguration(configuration => configuration.SamlConfigs.TryGetValue(provider, out var config) ? config : null);

    // Signs the outgoing request when the provider opts in; an unloadable key throws rather than downgrading to unsigned (#167).
    private static string BuildChallengeRedirectUrl(SamlConfig config, SamlAuthnRequest request, string? relayState)
    {
        var endpoint = config.SamlEndpoint.Trim();
        if (!config.SignAuthnRequests)
        {
            return request.GetRedirectUrl(endpoint, relayState);
        }

        // Revealed at the point of use; a missing or corrupt at-rest key throws into the caller's fail-closed catch (#158).
        if (!SamlSigningKey.TryLoad(SSOPlugin.Instance.Secrets.Reveal(config.SamlSigningKeyPfx), out var signingCertificate))
        {
            throw new InvalidOperationException("Outgoing SAML request signing is enabled but the signing key could not be loaded.");
        }

        using (signingCertificate)
        using (var signingKey = SamlSigningKey.GetSigningKey(signingCertificate))
        {
            if (signingKey is null)
            {
                throw new InvalidOperationException("Outgoing SAML request signing is enabled but the signing key has no RSA or ECDSA private key.");
            }

            return request.GetSignedRedirectUrl(endpoint, relayState, signingKey);
        }
    }

    private static string GetRequestBase(HttpRequest request, string schemeOverride, int? portOverride, string baseUrlOverride) =>
        CanonicalBaseUrl.Resolve(baseUrlOverride, request.Scheme, request.Host.Host, request.Host.Port, request.PathBase, schemeOverride, portOverride);

    // The role-denied arm: the line keeps the NameID and the roles seen; login-time deprovisioning never touches an
    // administrator (#831); the host raises its own failed-login event only from the mint, which this path never reaches (#1142).
    private async Task<ActionResult> DenyRoleAsync(string provider, SamlConfig config, SamlResponse samlResponse, List<string> assertionRoles, HttpRequest request)
    {
        if (_logger.IsEnabled(LogLevel.Warning))
        {
            _logger.LogWarning(
                "SAML user: {UserId} has insufficient roles: {@Roles}. Expected any one of: {@ExpectedRoles}",
                samlResponse.GetNameID()?.ReplaceLineEndings(string.Empty).Replace('[', '('),
                assertionRoles.Select(r => r?.ReplaceLineEndings(string.Empty).Replace('[', '(')),
                config.Roles);
        }

        if (config.DisableAccountOnRoleDenied
            && await _canonicalLinks.DisableDeniedAccountAsync(ProviderMode.Saml, provider, samlResponse.GetNameID()).ConfigureAwait(false))
        {
            SsoAudit.AccountDeprovisioned(_logger, "SAML", provider);
        }

        await _loginEvents.PublishRoleDeniedAsync(provider, request.HttpContext.GetNormalizedRemoteIP().ToString()).ConfigureAwait(false);

        return LoginStatusMapper.ToActionResult(new LoginOutcome.Denied());
    }

    // The login leg after the gate: a slot is reserved before the one-time replay consume, so a capacity refusal
    // leaves the assertion retryable (#251, #539), and the finally releases the reservation unless a committed
    // outcome took it over, so a slot can never leak.
    private ActionResult StoreOutcomeAndRenderPage(string provider, SamlConfig config, SamlResponse samlResponse, List<string> assertionRoles, string requestBase, string? culture, HttpRequest request, HttpResponse response)
    {
        // The slot is reserved before the one-time replay consume, so a capacity refusal leaves the assertion retryable (#251, #539).
        var clientKey = SsoRateLimiter.NormalizeClientKey(request.HttpContext.Connection.RemoteIpAddress);
        _outcomes.PruneExpired(DateTime.UtcNow);
        if (!_outcomes.TryReserve(clientKey, DateTime.UtcNow, out var shouldWarnCapacity))
        {
            if (shouldWarnCapacity)
            {
                if (_logger.IsEnabled(LogLevel.Warning))
                {
                    _logger.LogWarning("SAML login outcome refused for provider {Provider}: the per-client sub-cap or the outcome store is at capacity (warning throttled); the assertion was not consumed, so the login can be retried.", provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
                }
            }

            return FlowResponses.PlainTextError(StatusCodes.Status500InternalServerError, "Could not start login; please retry.");
        }

        // The finally releases the reservation unless a committed outcome took it over, so a slot can never leak.
        bool committed = false;
        try
        {
            if (!_validator.TryProduceVerifiedIdentity(config, provider, samlResponse, assertionRoles, out var identity, out var rejection))
            {
                return LoginStatusMapper.ToActionResult(rejection);
            }

            var outcome = new SamlLoginOutcome(
                SamlOutcomeStore.NewToken(),
                provider,
                identity,
                samlResponse.GetInResponseTo() ?? string.Empty,
                samlResponse.GetSessionIndex(),
                clientKey,
                DateTime.UtcNow);
            if (!_outcomes.CommitReserved(outcome))
            {
                // A token collision, which fails closed rather than rendering a token that could never redeem.
                return FlowResponses.PlainTextError(StatusCodes.Status500InternalServerError, "Could not start login; please retry.");
            }

            // The committed outcome owns the slot now, and the page renders the token before the finally runs.
            committed = true;
            return FlowResponses.AuthPage(response, nonce =>
                WebResponse.Generator(
                    data: outcome.Token,
                    provider: provider,
                    baseUrl: requestBase,
                    mode: "SAML",
                    nonce: nonce,
                    isLinking: false,
                    culture: culture));
        }
        finally
        {
            if (!committed)
            {
                _outcomes.ReleaseReservation(clientKey);
            }
        }
    }
}
