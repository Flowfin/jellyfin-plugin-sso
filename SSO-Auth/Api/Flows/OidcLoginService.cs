// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Events;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Localization;
using Jellyfin.Plugin.SSO_Auth.Api.Metrics;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Extensions;
using MediaBrowser.Controller.Providers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Flows;

/// <summary>The OpenID login flow: the challenge, the redirect callback, the session-minting leg, the manual link redeem and the back-channel logout validation.</summary>
/// <remarks>
/// The authorize-state store is a process-wide static, because a fresh controller reconstructs this service per
/// request; the mint tail stays HttpContext-free like <see cref="LoginCompletionService"/>. See
/// <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Login-Flow#openid-connect"/>.
/// </remarks>
internal sealed class OidcLoginService
{
    /// <summary>How many discovery reads one inbound back-channel logout may make; a provider that is down bounds it, not the chance of success (#1183).</summary>
    internal const int LogoutDiscoveryAttempts = 2;

    /// <summary>The pause between those attempts.</summary>
    internal static readonly TimeSpan LogoutDiscoveryRetryDelay = TimeSpan.FromSeconds(1);

    /// <summary>The worst-case wall clock one inbound back-channel logout may spend reading discovery, chosen rather than derived so a test can hold it.</summary>
    internal static readonly TimeSpan LogoutDiscoveryBudget = TimeSpan.FromSeconds(21);

    private static readonly OidcStateStore StateStore = new();

    // Separate tokens, so the union can see that a configured "openid" is the same scope (#1612).
    private static readonly string[] BaseScopes = { "openid", "profile" };

    private readonly LoginCompletionService _loginCompletion;
    private readonly CanonicalLinkService _canonicalLinks;
    private readonly SsoLoginEvents _loginEvents;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger _logger;

    /// <summary>Initializes a new instance of the <see cref="OidcLoginService"/> class.</summary>
    /// <param name="loginCompletion">The shared post-validation login completion pipeline.</param>
    /// <param name="canonicalLinks">The account-linking workflow used by the OID manual-link redeem.</param>
    /// <param name="loginEvents">Publishes the role-mapping denial on Jellyfin's event bus (#1142).</param>
    /// <param name="httpClientFactory">The factory for the token-endpoint client.</param>
    /// <param name="loggerFactory">The factory for the underlying OIDC client's logger.</param>
    /// <param name="logger">The service logger.</param>
    internal OidcLoginService(
        LoginCompletionService loginCompletion,
        CanonicalLinkService canonicalLinks,
        SsoLoginEvents loginEvents,
        IHttpClientFactory httpClientFactory,
        ILoggerFactory loggerFactory,
        ILogger logger)
    {
        _loginCompletion = loginCompletion ?? throw new ArgumentNullException(nameof(loginCompletion));
        _canonicalLinks = canonicalLinks ?? throw new ArgumentNullException(nameof(canonicalLinks));
        _loginEvents = loginEvents ?? throw new ArgumentNullException(nameof(loginEvents));
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        _loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>Projects the in-flight authorize states to non-secret summaries for the admin debug endpoint.</summary>
    /// <returns>One redacted summary per in-flight state.</returns>
    internal IEnumerable<OidcStateStore.Summary> StateSummaries() => StateStore.Summaries();

    /// <summary>Test-only. Clears the process-wide authorize-state store and resets the shared NewPath persist-throttle gate.</summary>
    internal static void ResetOidStateForTests()
    {
        StateStore.Clear();
        ChallengeNewPathResolver.ResetForTests();
    }

    /// <summary>Test-only. Seeds a single authorize-state entry so a test can exercise the callback and authenticate legs without the token exchange.</summary>
    /// <param name="token">The state token to key the seeded entry under.</param>
    /// <param name="state">The authorize state to store (a Pending or a promoted Ready).</param>
    internal static void SeedOidStateForTests(string token, AuthorizeSession state) => StateStore.Seed(token, state);

    /// <summary>Initiates the OpenID login flow: prepares the authorization request, registers and browser-binds the authorize state, and redirects.</summary>
    /// <param name="provider">The provider name from the route.</param>
    /// <param name="isLinking">Whether this challenge intends to link an account rather than authenticate.</param>
    /// <param name="request">The current request; read for the base URL, the challenge route spelling, and the client IP.</param>
    /// <param name="response">The response the browser-binding cookie is appended to on a successful registration.</param>
    /// <returns>A redirect to the authorization server, or a fail-closed rejection/error.</returns>
    internal async Task<ActionResult> ChallengeAsync(string provider, bool isLinking, HttpRequest request, HttpResponse response)
    {
        StateStore.PruneExpired(DateTime.UtcNow);
        var config = FindOidConfig(provider);
        if (config is not { Enabled: true })
        {
            // Unknown and disabled providers share one rejection, so neither can be probed apart.
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.UnknownProvider));
        }

        var newPath = ChallengeNewPathResolver.ResolveChallengeNewPath(provider, config, isLinking, request, _logger, c => c.OidConfigs);

        string redirectUri = OidcRedirectUriBuilder.ChallengeRedirectUri(RequestBaseUrl(request, config), newPath, provider);

        // Discovery is read once and feeds both the security facts and the login's metadata (#450); the secret reveal fails closed (#158).
        if (TryReveal(() => BuildOidcOptions(config, redirectUri, BuildScopeString(config)), provider, out var options) is { } secretError)
        {
            return secretError;
        }

        OidcDiscoveryResult discovery;
        try
        {
            discovery = await OidcDiscoveryReader.ReadAsync(options, provider, _httpClientFactory, _logger, config.AllowPrivateNetworkAddresses, request.HttpContext.RequestAborted).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (request.HttpContext.RequestAborted.IsCancellationRequested)
        {
            // The browser left before discovery answered, which is neither a refusal nor an error (#1558).
            return FlowResponses.PlainTextError(StatusCodes.Status400BadRequest, "Error preparing login.");
        }

        if (!discovery.Available)
        {
            // Without discovery there is no authoritative source for the PKCE and issuer facts, so no fallback (#450).
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning("OpenID login refused for provider {Provider}: the authorization server's discovery document could not be read.", provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
            }

            return FlowResponses.PlainTextError(StatusCodes.Status400BadRequest, "Error preparing login: the authorization server's discovery document could not be read.");
        }

        // The library never checks that the server advertises PKCE S256, so a downgrade would be silent (#141).
        if (!discovery.Facts.PkceS256)
        {
            if (config.RequirePkce)
            {
                if (_logger.IsEnabled(LogLevel.Warning))
                {
                    _logger.LogWarning("OpenID login refused for provider {Provider}: RequirePkce is set but the authorization server does not advertise PKCE (S256).", provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
                }

                return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.PkceNotSupported));
            }

            SsoAudit.PkceNotAdvertised(_logger, provider);
        }

        // Assigned before construction, so the client reuses this metadata at the challenge and the callback (#450, #247).
        options.ProviderInformation = discovery.ProviderInformation;
        var oidcClient = new OidcClient(options);

        // Step-up parameters ride along only when set, so an unconfigured provider's request is unchanged (#757).
        var state = await oidcClient.PrepareLoginAsync(OidcFrontChannelParameters.FromConfig(config)).ConfigureAwait(false);

        if (state.IsError)
        {
            // The library's detail stays out of the browser page and goes to the operator's log (#708).
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                // The closing sentence follows the refusal code, and asserts no cause the field cannot substantiate (#1610, #1763).
                switch (OidcChallengeRefusal.Classify(state.Error))
                {
                    case OidcChallengeCause.RedirectUri:
                        _logger.LogWarning("OpenID login refused for provider {Provider}: preparing the authorization request failed ({Error} - {ErrorDescription}). The redirect URI sent was {RedirectUri}, which the provider must have registered exactly as written - scheme, host, port and path.", provider?.ReplaceLineEndings(string.Empty).Replace('[', '('), state.Error?.ReplaceLineEndings(string.Empty).Replace('[', '('), state.ErrorDescription?.ReplaceLineEndings(string.Empty).Replace('[', '('), redirectUri?.ReplaceLineEndings(string.Empty).Replace('[', '('));
                        break;

                    case OidcChallengeCause.ClientAuthentication:
                        _logger.LogWarning("OpenID login refused for provider {Provider}: preparing the authorization request failed ({Error} - {ErrorDescription}). That is a refusal of the client rather than of the request: check the client ID and the client secret this provider is configured with, and whether a secret is sent here while the provider holds the client as public, or the reverse. The provider's own description of this refusal is replaced before it reaches this log, so the provider's log for this request is where a cause other than those would show.", provider?.ReplaceLineEndings(string.Empty).Replace('[', '('), state.Error?.ReplaceLineEndings(string.Empty).Replace('[', '('), state.ErrorDescription?.ReplaceLineEndings(string.Empty).Replace('[', '('));
                        break;

                    default:
                        _logger.LogWarning("OpenID login refused for provider {Provider}: preparing the authorization request failed ({Error} - {ErrorDescription}). This line does not interpret that answer, because the field it arrives in carries three different things: the provider's own error code, the HTTP reason phrase the answer came back with, or the failure that stopped the request arriving. Read it as whichever of the three it is.", provider?.ReplaceLineEndings(string.Empty).Replace('[', '('), state.Error?.ReplaceLineEndings(string.Empty).Replace('[', '('), state.ErrorDescription?.ReplaceLineEndings(string.Empty).Replace('[', '('));
                        break;
                }
            }

            return FlowResponses.PlainTextError(StatusCodes.Status400BadRequest, "Error preparing login.");
        }

        // The state is bound to the browser that started it, the forced-login defence (#326).
        // See https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model#login-browser-binding-forced-login-defense
        var bindingId = AuthorizeStateBinding.NewId();

        // The client key bounds how much of the store one source can occupy (#327).
        var clientKey = SsoRateLimiter.NormalizeClientKey(request.HttpContext.Connection.RemoteIpAddress);

        // Built complete, so registration is one atomic insert and the stored state is never mutated afterwards (#341); UTC throughout (#676).
        var pending = new AuthorizeSession.Pending(state, provider, isLinking, DateTime.UtcNow, bindingId, clientKey, discovery.ProviderInformation, discovery.Facts.ResponseIssuerAdvertised);
        if (!StateStore.TryAdd(pending, out var shouldWarnCapacity))
        {
            if (shouldWarnCapacity)
            {
                if (_logger.IsEnabled(LogLevel.Warning))
                {
                    _logger.LogWarning("OpenID authorize state refused for provider {Provider}: a CSPRNG-token collision (effectively impossible) or the store is at capacity (warning throttled).", provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
                }
            }

            return FlowResponses.PlainTextError(StatusCodes.Status500InternalServerError, "Could not start login; please retry.");
        }

        // Set the cookie only after the state is registered, so a refused challenge leaves no cookie.
        response.Cookies.Append(AuthorizeStateBinding.CookieName, bindingId, AuthorizeStateBinding.CookieOptions(OidcStateStore.DefaultLifetime));

        return new RedirectResult(state.StartUrl);
    }

    /// <summary>The redirect callback: validates the browser-bound state, exchanges the code, validates the id_token and the response issuer, applies the role gate, and renders the auth page.</summary>
    /// <param name="provider">The provider name from the route.</param>
    /// <param name="state">The authorize-state token the callback presented (also the auth-page data).</param>
    /// <param name="request">The current request; read for the base URL, the callback route, the code-exchange query string, the response `iss`, and the binding cookie.</param>
    /// <param name="response">The response the auth page's defensive headers are written to.</param>
    /// <returns>The rendered auth page on success, or a fail-closed rejection.</returns>
    internal async Task<ActionResult> CallbackAsync(string provider, string state, HttpRequest request, HttpResponse response)
    {
        var config = FindOidConfig(provider);
        if (config is not { Enabled: true })
        {
            return new BadRequestObjectResult(LoginStatusMapper.NoMatchingProviderMessage);
        }

        if (string.IsNullOrEmpty(state))
        {
            return new BadRequestObjectResult("Missing state");
        }

        if (StateStore.PeekCurrent(state, provider, DateTime.UtcNow, request.Cookies[AuthorizeStateBinding.CookieName]) is not { } pending)
        {
            // Unknown, expired, another provider's, or another browser's (#326); the shared wording localizes on the error page (#913).
            return new BadRequestObjectResult(LoginStatusMapper.InvalidStateMessage);
        }

        if (TryReveal(() => CreateCallbackOidcClient(config, provider, request, pending.ProviderInformation), provider, out var oidcClient) is { } secretError)
        {
            return secretError;
        }

        var result = await oidcClient.ProcessResponseAsync(request.QueryString.Value, pending.OidcState).ConfigureAwait(false);

        if (result.IsError)
        {
            // The error fields come from the callback query and are attacker-controllable, so the page gets a fixed message (#708).
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning("OpenID login refused for provider {Provider}: the authorization-response processing failed ({Error} - {ErrorDescription}).", provider?.ReplaceLineEndings(string.Empty).Replace('[', '('), result.Error?.ReplaceLineEndings(string.Empty).Replace('[', '('), result.ErrorDescription?.ReplaceLineEndings(string.Empty).Replace('[', '('));
            }

            // Counted apart from discovery, because the two are fixed in different places (#1139).
            SsoMetrics.ProviderFetchFailed(ProviderFetchStage.Token);
            return FlowResponses.PlainTextError(StatusCodes.Status400BadRequest, "Error logging in.");
        }

        // The RFC 9207 mix-up check the library never makes (#210).
        // See https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model#openid-authorization-response-issuer-rfc-9207
        if (!config.DoNotValidateResponseIssuer
            && OidcResponseIssuer.IsRejected(request.Query["iss"], oidcClient.Options.ProviderInformation?.IssuerName, result.IdentityToken, pending.ResponseIssuerRequired))
        {
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning("OpenID login denied for provider {Provider}: the authorization-response issuer was absent-but-required or matched neither the discovery issuer nor the id_token issuer (RFC 9207 mix-up check).", provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
            }

            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.SsoResponseInvalid));
        }

        // The issuer is read from the raw id_token, because the library filters protocol claims out of the principal (#186); the provider's own endpoints bound the avatar's private tier (#1764).
        var derived = OidcAuthorizeStateBuilder.Build(
            result.User.Claims,
            config,
            OidcResponseIssuer.IdTokenIssuer(result.IdentityToken),
            _logger,
            provider,
            new[] { config.OidEndpoint, pending.ProviderInformation?.TokenEndpoint, config.DoNotLoadProfile ? null : pending.ProviderInformation?.UserInfoEndpoint });

        // The logout material rides the state to the mint, where it is persisted only when Single Logout is on; the sid comes from the signed id_token, not the unsigned UserInfo merge (#727).
        var sid = OidcIdTokenSid.Read(result.IdentityToken);
        derived = derived with
        {
            IdToken = result.IdentityToken,
            SessionIndex = sid,
            EndSessionEndpoint = pending.ProviderInformation?.EndSessionEndpoint,
        };

        // A missing sub is a non-conformant provider, refused rather than keyed on the mutable username (#155).
        if (derived.Valid && string.IsNullOrWhiteSpace(derived.Subject))
        {
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning("OpenID login denied for provider {Provider}: the id_token carried no 'sub' claim to key the account link on.", provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
            }

            return LoginStatusMapper.ToActionResult(new LoginOutcome.Denied());
        }

        if (!derived.Valid)
        {
            // The state stays unpromoted and expires; the line keeps every claim type and only the role claim's and sub's values (#1881).
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning(
                    "OpenID login denied for provider {Provider}: {Reason}. Claims: {@Claims}. Roles expected (any one of): {@ExpectedClaims}",
                    provider.ReplaceLineEndings(string.Empty).Replace('[', '('),
                    string.IsNullOrWhiteSpace(derived.Username) ? "the login resolved no username" : "no role matched the allow-list",
                    ClaimsForDenialLog(result.User.Claims, config).Select(o => new { Type = o.Type?.ReplaceLineEndings(string.Empty).Replace('[', '('), Value = o.Value?.ReplaceLineEndings(string.Empty).Replace('[', '(') }),
                    config.Roles);
            }

            // Login-time deprovisioning never touches an administrator, and the issuer binding gates it as it gates the mint (#831).
            if (config.DisableAccountOnRoleDenied
                && await _canonicalLinks.DisableDeniedAccountAsync(ProviderMode.Oid, provider, derived.Subject, derived.Issuer).ConfigureAwait(false))
            {
                SsoAudit.AccountDeprovisioned(_logger, "OpenID", provider);
            }

            // The host raises its own failed-login event only from the mint, and this arm's two refusals are reported apart (#1142).
            var remoteEndPoint = request.HttpContext.GetNormalizedRemoteIP().ToString();
            await (string.IsNullOrWhiteSpace(derived.Username)
                ? _loginEvents.PublishUnresolvedUsernameDeniedAsync(provider, remoteEndPoint)
                : _loginEvents.PublishRoleDeniedAsync(provider, remoteEndPoint)).ConfigureAwait(false);

            return LoginStatusMapper.ToActionResult(new LoginOutcome.Denied());
        }

        // The acr comes from the signed id_token, checked before Promote so a login without the required context is never redeemable (#757).
        if (config.RequireAcr)
        {
            var acr = OidcIdTokenAcr.Read(result.IdentityToken);
            if (!AcrPolicy.IsSatisfied(acr, config.AcrValues))
            {
                if (_logger.IsEnabled(LogLevel.Warning))
                {
                    _logger.LogWarning("OpenID login denied for provider {Provider}: RequireAcr is set but the id_token's acr claim was absent or outside the configured acr_values allow-list.", provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
                }

                return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.AcrNotSatisfied));
            }
        }

        // A missing auth_time is a provider that ignored max_age and is refused, so an old session cannot satisfy a forced re-authentication (#961).
        if (config.MaxAge is int maxAge && maxAge >= 0)
        {
            var authTime = OidcIdTokenAuthTime.Read(result.IdentityToken);
            if (!MaxAgePolicy.IsFresh(authTime, maxAge, DateTimeOffset.UtcNow))
            {
                if (_logger.IsEnabled(LogLevel.Warning))
                {
                    _logger.LogWarning("OpenID login denied for provider {Provider}: max_age is configured but the id_token's auth_time was absent or older than the allowed window (the user authenticated too long ago).", provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
                }

                return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.AuthTooOld));
            }
        }

        // The browser's one-time redeem is the real gate, so the page is returned whether or not this promotion won (#341).
        StateStore.Promote(pending, derived);

        if (_logger.IsEnabled(LogLevel.Information))
        {
            _logger.LogInformation("Is request linking: {IsLinking}", pending.IsLinking);
        }

        var culture = AcceptLanguage.Resolve(request.Headers.AcceptLanguage.ToString());
        return FlowResponses.AuthPage(response, nonce => WebResponse.Generator(data: state, provider: provider, baseUrl: RequestBaseUrl(request, config), mode: "OID", nonce: nonce, isLinking: pending.IsLinking, culture: culture));
    }

    /// <summary>The session-minting leg: redeems the browser-bound authorize state once and hands the verified identity to the completion tail.</summary>
    /// <param name="provider">The provider name from the route.</param>
    /// <param name="response">The client's auth request context (app/device) plus the state token in <c>Data</c>.</param>
    /// <param name="bindingCookie">The browser-binding cookie value the redeem presented (#326).</param>
    /// <param name="remoteEndPointResolver">Resolves the normalized client IP for the activity log (#177).</param>
    /// <returns>The minted session, or a fail-closed rejection.</returns>
    public async Task<ActionResult> AuthenticateAsync(string provider, AuthResponse response, string? bindingCookie, Func<string> remoteEndPointResolver)
    {
        if (string.IsNullOrEmpty(response?.Data))
        {
            return new BadRequestObjectResult("Missing data");
        }

        // A disabled provider does not consume the state, because the guard precedes the redeem.
        var config = FindOidConfig(provider);
        if (config is not { Enabled: true })
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.UnknownProvider));
        }

        // One uniform body, so a replay is indistinguishable from an expiry; a binding mismatch does not consume the state (#326).
        if (StateStore.TryRedeem(response.Data, provider, DateTime.UtcNow, bindingCookie) is not { } redeemed)
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.InvalidState));
        }

        // Absent, false and unparseable all fail this gate, which covers every login rather than only adoption (#166).
        if (config.RequireVerifiedEmailForLogin && redeemed.Identity.EmailVerified != true)
        {
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning("OpenID login denied for provider {Provider}: RequireVerifiedEmailForLogin is set but the login did not carry email_verified == true (absent, false, or unparseable).", provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
            }

            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.EmailNotVerified));
        }

        // From here the OpenID and SAML paths are one (#473).
        return await _loginCompletion.CompleteAsync(
            redeemed.Identity,
            response,
            config,
            new AdoptionGate(config.RequireVerifiedEmailForAdoption, redeemed.Identity.EmailVerified),
            remoteEndPointResolver,
            redeemed.LogoutContext).ConfigureAwait(false);
    }

    /// <summary>The manual-link redeem: consumes the browser-bound authorize state once and links the redeemed identity's stable subject.</summary>
    /// <param name="provider">The provider to link against.</param>
    /// <param name="jellyfinUserId">The Jellyfin account to link (already authorized by the controller).</param>
    /// <param name="response">The client information carrying the state token in <c>Data</c>.</param>
    /// <param name="bindingCookie">The browser-binding cookie value the redeem presented (#326).</param>
    /// <returns>The link-creation result, or a fail-closed rejection.</returns>
    internal ActionResult Link(string provider, Guid jellyfinUserId, AuthResponse response, string? bindingCookie)
    {
        if (string.IsNullOrEmpty(response?.Data))
        {
            return new BadRequestObjectResult("Missing data");
        }

        // A disabled provider neither creates a link nor consumes the state (#343).
        if (FindOidConfig(provider) is not { Enabled: true })
        {
            return new BadRequestObjectResult(LoginStatusMapper.NoMatchingProviderMessage);
        }

        // Consumed once, so one verified identity cannot be linked repeatedly and then reused to mint (#326).
        if (StateStore.TryRedeem(response.Data, provider, DateTime.UtcNow, bindingCookie) is not { } redeemed)
        {
            return LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(PublicReason.InvalidState));
        }

        // Keyed on the stable subject and stamped with the issuer, like an auto-login link (#155, #186).
        return FlowResponses.MapCanonicalLinkWrite(_canonicalLinks.TryCreateLink(ProviderMode.Oid, provider, redeemed.Identity.Subject, jellyfinUserId, redeemed.Identity.Issuer));
    }

    /// <summary>Builds the space-delimited scope string, always leading with the base scopes and carrying each further scope once.</summary>
    /// <remarks>A union rather than a prepend, split on whitespace, with blank entries dropped and ordinal comparison (#368, #407, #1612).</remarks>
    /// <param name="config">The provider configuration whose <c>OidScopes</c> join the base.</param>
    /// <returns>The normalized scope string.</returns>
    internal static string BuildScopeString(OidConfig config)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var scopes = new List<string>();

        foreach (var scope in BaseScopes
            .Concat(config?.OidScopes ?? Array.Empty<string>())
            .Where(entry => !string.IsNullOrWhiteSpace(entry))
            .SelectMany(entry => entry!.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)))
        {
            if (seen.Add(scope))
            {
                scopes.Add(scope);
            }
        }

        return string.Join(" ", scopes);
    }

    // Read under the config lock, so a login cannot race an admin write on the live dictionary (#252).
    private static OidConfig? FindOidConfig(string provider) =>
        SSOPlugin.Instance.ReadConfiguration(configuration => configuration.OidConfigs.TryGetValue(provider, out var config) ? config : null);

    // A build step that reveals the at-rest secret fails closed on a key it cannot decrypt, and logs no key material (#158).
    private ContentResult? TryReveal<T>(Func<T> build, string provider, out T built)
    {
        try
        {
            built = build();
            return null;
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            // Never observed: the fail-closed path returns a non-null result.
            built = default!;
            if (_logger.IsEnabled(LogLevel.Error))
            {
                _logger.LogError("OpenID login refused for provider {Provider}: the stored client secret could not be decrypted ({Reason}); the at-rest key file is missing or corrupt.", provider?.ReplaceLineEndings(string.Empty).Replace('[', '('), ex.Message?.ReplaceLineEndings(string.Empty).Replace('[', '('));
            }

            return FlowResponses.PlainTextError(StatusCodes.Status500InternalServerError, "Could not process login; the OpenID client secret could not be decrypted.");
        }
    }

    /// <summary>Validates an inbound back-channel <c>logout_token</c> against the provider's discovery, with the same hardened parameters the id_token uses (#962).</summary>
    /// <remarks>No client secret is revealed, because verifying a signature needs none; every failure carries a fixed reason code and the caller revokes.</remarks>
    /// <param name="config">The provider configuration.</param>
    /// <param name="provider">The provider name (route input, used only for the SSRF-guarded discovery read).</param>
    /// <param name="logoutToken">The raw <c>logout_token</c> from the anonymous POST body.</param>
    /// <returns>The validation outcome - on success, the (sub, sid) the caller keys its revocation lookup on.</returns>
    internal async Task<OidcLogoutTokenValidator.Result> ValidateBackChannelLogoutAsync(OidConfig config, string provider, string? logoutToken)
    {
        OidcClientOptions options;
        try
        {
            // A malformed endpoint throws here and is a fail-closed reject rather than a 500.
            options = OidcDiscoveryOptions.Build(config);
        }
        catch (Exception ex) when (ex is UriFormatException or ArgumentException)
        {
            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning("OpenID back-channel logout refused for provider {Provider}: the configured endpoint is not a usable URL.", provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
            }

            return new OidcLogoutTokenValidator.Result(false, null, null, OidcLogoutTokenValidator.RejectReason.ProviderUnreachable);
        }

        options.ClientId = config.OidClientId?.Trim();
        options.LoggerFactory = _loggerFactory;
        // Every backchannel leg goes over the provider's own transport tier (#1179).
        options.HttpClientFactory = _ => SsoHttp.CreateClient(_httpClientFactory, config.AllowPrivateNetworkAddresses);

        var discovery = await ReadDiscoveryForLogoutAsync(options, provider, config).ConfigureAwait(false);
        if (!discovery.Available)
        {
            return new OidcLogoutTokenValidator.Result(false, null, null, OidcLogoutTokenValidator.RejectReason.ProviderUnreachable);
        }

        options.ProviderInformation = discovery.ProviderInformation;

        // The validator derives its own basis, so nothing here holds parameters that could be weakened first (#1176).
        return await new OidcLogoutTokenValidator().ValidateAsync(logoutToken, options, DateTime.UtcNow).ConfigureAwait(false);
    }

    /// <summary>Reads discovery for an inbound back-channel logout, retrying inside <see cref="LogoutDiscoveryBudget"/> (#1183).</summary>
    /// <remarks>Here a refusal leaves alive the sessions the provider has ended, so the retry is worth what the login challenge does not need; it relaxes no validation.</remarks>
    private async Task<OidcDiscoveryResult> ReadDiscoveryForLogoutAsync(OidcClientOptions options, string provider, OidConfig config)
    {
        // No caller token on purpose: a provider that aborts its POST early must not turn an ordered termination into a no-op (#1558).
        for (var attempt = 1; ; attempt++)
        {
            var discovery = await OidcDiscoveryReader.ReadAsync(options, provider, _httpClientFactory, _logger, config.AllowPrivateNetworkAddresses).ConfigureAwait(false);
            if (discovery.Available || attempt >= LogoutDiscoveryAttempts)
            {
                return discovery;
            }

            await Task.Delay(LogoutDiscoveryRetryDelay).ConfigureAwait(false);
        }
    }

    // The options both sites share, without ProviderInformation, so the challenge can read discovery once and assign it before construction (#450).
    private OidcClientOptions BuildOidcOptions(OidConfig config, string redirectUri, string scope)
    {
        // The one shared builder, so the login and the admin probe read discovery under one posture (#163).
        var options = OidcDiscoveryOptions.Build(config);
        options.ClientId = config.OidClientId?.Trim();
        // Revealed at the point of use; a missing or corrupt at-rest key throws rather than yielding an empty secret (#158).
        options.ClientSecret = SSOPlugin.Instance.Secrets.Reveal(config.OidSecret)?.Trim();
        options.RedirectUri = redirectUri;
        options.Scope = scope;
        options.DisablePushedAuthorization = config.DisablePushedAuthorization;
        options.LoggerFactory = _loggerFactory;
        options.LoadProfile = !config.DoNotLoadProfile;
        // The token and userinfo legs go over this provider's own transport tier (#1179).
        options.HttpClientFactory = o => SsoHttp.CreateClient(_httpClientFactory, config.AllowPrivateNetworkAddresses);

        // The library validates nothing about the id_token unless a validator is supplied; an unvalidated one is a forgeable login (#134).
        options.Policy.RequireIdentityTokenSignature = true;
        options.IdentityTokenValidator = new OidcIdTokenValidator();

        return options;
    }

    // The redirect URI is rebuilt from the callback's own route, so the token request matches the authorization request (#98).
    private OidcClient CreateCallbackOidcClient(OidConfig config, string provider, HttpRequest request, ProviderInformation providerInformation)
    {
        var redirectUri = OidcRedirectUriBuilder.CallbackRedirectUri(RequestBaseUrl(request, config), request.Path.Value, provider);
        var options = BuildOidcOptions(config, redirectUri, BuildScopeString(config));

        // Unconditional: a client built without the captured metadata would fetch discovery and the JWKS around the repeated-member screen (#247, #1067).
        options.ProviderInformation = providerInformation;

        return new OidcClient(options);
    }

    /// <summary>Composes the challenge <c>redirect_uri</c> for a stored provider, so the settings page displays the bytes the login sends (#1303).</summary>
    /// <param name="provider">The stored provider name, appended raw exactly as the login appends it.</param>
    /// <param name="request">The admin request whose scheme, host and path base the canonical base falls back to.</param>
    /// <returns>The redirect_uri, or <see langword="null"/> when no such provider is configured.</returns>
    public string? ChallengeRedirectUriDisplay(string provider, HttpRequest request)
    {
        var config = FindOidConfig(provider);
        if (config is null)
        {
            return null;
        }

        // The new-path spelling every rendered entry point produces, rather than the last observed one.
        return OidcRedirectUriBuilder.ChallengeRedirectUri(RequestBaseUrl(request, config), true, provider);
    }

    private static string RequestBaseUrl(HttpRequest request, OidConfig config) =>
        CanonicalBaseUrl.Resolve(config.BaseUrlOverride, request.Scheme, request.Host.Host, request.Host.Port, request.PathBase, config.SchemeOverride, config.PortOverride);

    /// <summary>The claims the role-denial warning may print: every claim keeps its type, and only the role claim and <c>sub</c> keep their value (#1881).</summary>
    /// <remarks>Every other value is a profile field that would write the person into the log for as long as it is kept.</remarks>
    /// <param name="claims">The claims of the verified login.</param>
    /// <param name="config">The provider configuration, for the role claim's path.</param>
    /// <returns>The claims with every value but the role claim's and <c>sub</c>'s replaced by <c>&lt;redacted&gt;</c>.</returns>
    internal static IEnumerable<Claim> ClaimsForDenialLog(IEnumerable<Claim> claims, OidConfig config)
    {
        var roleClaimType = OidcAuthorizeStateBuilder.RoleClaimType(config);
        return claims.Select(claim =>
            string.Equals(claim.Type, "sub", StringComparison.Ordinal) || (roleClaimType is not null && string.Equals(claim.Type, roleClaimType, StringComparison.Ordinal))
                ? claim
                : new Claim(claim.Type, "<redacted>"));
    }
}
