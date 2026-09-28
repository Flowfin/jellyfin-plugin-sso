// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using Jellyfin.Plugin.SSO_Auth.Api.Events;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Logout;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Common.Extensions;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Events;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Net;
using MediaBrowser.Controller.Providers;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Http;

/// <summary>
/// The sso api controller.
/// </summary>
[ApiController]
[Route("[controller]")]
public partial class SSOController : ControllerBase
{
    // The uniform-rejection policy and its bodies live on LoginStatusMapper; the direct provider-lookup
    // rejections that stay in the controller reuse its NoMatchingProviderMessage so the wording is
    // defined once (#318).
    private const string NoMatchingProviderMessage = LoginStatusMapper.NoMatchingProviderMessage;

    // How many stranded administrators the mass-lockout refusal names before it summarizes the rest, so a
    // roster-sized body cannot be driven by one request. Ten, matching the link import's own cap.
    private const int NamedStrandedAdministrators = 10;

    // The refusal body for an unrecognized {mode} route token (#1399), named here beside the other fixed
    // refusal wordings. It names the two accepted tokens and never echoes the supplied one.
    private const string UnknownModeMessage = "The mode segment must be 'oid' or 'saml'.";

    // The refusal body served on every SSO sign-in route while the stored configuration could not be read (#1543),
    // a distinct sentence from the no-matching-provider one so an operator looks for a damaged file rather than a
    // deleted provider. It names no path and points at no list, because the audit lines name a category and
    // enumerate no account.
    private const string ServingDefaultsMessage = "Single sign-on is unavailable: its configuration could not be read. See the server log; an administrator with a password can sign in and restore it.";

    // The refusal body a logout-ticket mint answers with when the ticket store is at capacity (#1768). It
    // says what still works, because the caller is a signed-in user pressing sign-out and the honest answer
    // is that the local session can still be ended the ordinary way. It names no capacity figure and no
    // provider: a caller learns that this one convenience is unavailable, and the operator reads the rest
    // in the server log.
    private const string LogoutTicketUnavailableMessage = "A single sign-out ticket could not be issued right now. Signing out of Jellyfin still ends this session.";

    // Display names for the audit log (the internal link-map mode tokens are the lowercase "oid"/"saml").
    private const string OpenIdProtocol = "OpenID";
    private const string SamlProtocol = "SAML";

    // Hard cap on the config-import request body (#161): a whole plugin configuration is small (kilobytes),
    // so 1 MiB is generous headroom while an oversized document is rejected fail-closed (413) before it is
    // parsed, rather than being deserialized into memory.
    private const long ConfigImportMaxBytes = 1024 * 1024;

    private readonly IUserManager _userManager;
    // The shared login-completion tail (#160, #318): resolve/adopt the link, build the session parameters,
    // mint under the revocation gate, audit, map to a LoginOutcome. The controller passes the
    // HttpContext-derived remote endpoint in and keeps no session/avatar field.
    private readonly LoginCompletionService _loginCompletion;
    // Kept so a hard revoke (Unregister) can also terminate the user's already-issued tokens (#440); the
    // minter takes its own reference for the login path.
    private readonly ISessionManager _sessionManager;
    private readonly IAuthorizationContext _authContext;
    private readonly ILogger<SSOController> _logger;
    private readonly ICryptoProvider _cryptoProvider;
    // Kept so the elevation-gated Test-connection endpoints (#163) can read a provider's OpenID discovery
    // through the SAME hardened reader the login uses; the shared login flow takes its own reference.
    private readonly IHttpClientFactory _httpClientFactory;

    // The account-linking workflow (resolve/adopt/create, legacy re-key, revoke); the controller keeps
    // the authz guards, the one-time-use replay/state consume, and the HTTP mapping (#318).
    private readonly CanonicalLinkService _canonicalLinks;

    // The one-time logout tickets the RP-initiated OpenID logout accepts in place of a session (#1768).
    // It owns the process-wide ticket store as its own static, the way the login flows own theirs, so the
    // controller still holds no mutable static state. New'd per request like the other collaborators.
    private readonly LogoutTicketService _logoutTickets;

    // The SSO-only login enforcement (#165): the fail-closed last-admin guard, the per-user provider-id
    // sweep, and the reversible off-switch. The controller keeps the RequiresElevation guards, the actor
    // resolution, and the audit; the service keeps the account enumeration and the mode-flag writes.
    private readonly SsoOnlyLoginService _ssoOnly;
    // The OpenID login flow (#160, #318 step 12): challenge, redirect callback, session-minting
    // authenticate, and manual link. It owns the OpenID-specific process-wide caches (the authorize-state
    // store and the discovery-facts cache) as its own statics; the controller's OpenID endpoints apply the
    // shared rate-limit gate (SsoRateLimitGate) and delegate here. New'd per request like the other collaborators.
    private readonly Flows.OidcLoginService _oidc;
    // The SAML login flow (#160, #318 step 13): challenge, assertion-consumer callback, session-minting
    // authenticate, and manual link. It owns the SAML-specific process-wide caches (the replay cache and
    // the outstanding-AuthnRequest cache) as its own statics; the controller's SAML endpoints apply the
    // shared rate-limit gate (SsoRateLimitGate) and delegate here. New'd per request like the other collaborators.
    private readonly Flows.SamlLoginService _saml;

    // The shared per-client rate limiter and its opt-in check live in SsoRateLimitGate (#160, #318): the last
    // mutable process-wide static moved off the controller into the Shared tier, so the controller now holds
    // no mutable static state. The RateLimitCheck wrapper below supplies the request-scoped inputs.

    /// <summary>Initializes a new instance of the <see cref="SSOController"/> class.</summary>
    /// <param name="logger">Instance of the <see cref="ILogger{SSOController}"/> interface.</param>
    /// <param name="loggerFactory">Instance of the <see cref="ILoggerFactory"/> interface.</param>
    /// <param name="sessionManager">Instance of the <see cref="ISessionManager"/> interface.</param>
    /// <param name="authContext">Instance of the <see cref="IAuthorizationContext"/> interface.</param>
    /// <param name="userManager">Instance of the <see cref="IUserManager"/> interface.</param>
    /// <param name="cryptoProvider">Instance of the <see cref="ICryptoProvider"/> interface.</param>
    /// <param name="providerManager">Instance of the <see cref="IProviderManager"/> interface.</param>
    /// <param name="httpClientFactory">Instance of the <see cref="IHttpClientFactory"/> interface.</param>
    /// <param name="serverConfigurationManager">Instance of the <see cref="IServerConfigurationManager"/> interface.</param>
    /// <param name="displayPreferencesManager">Instance of the <see cref="IDisplayPreferencesManager"/> interface, the store a templated home-screen layout is seeded into (#1101).</param>
    /// <param name="eventManager">Instance of the <see cref="IEventManager"/> interface, the bus the role-mapping denial is published on (#1142). Optional: a host line that does not register one leaves the login path untouched rather than failing every SSO endpoint at controller activation.</param>
    public SSOController(
        ILogger<SSOController> logger,
        ILoggerFactory loggerFactory,
        ISessionManager sessionManager,
        IUserManager userManager,
        IAuthorizationContext authContext,
        ICryptoProvider cryptoProvider,
        IProviderManager providerManager,
        IHttpClientFactory httpClientFactory,
        IServerConfigurationManager serverConfigurationManager,
        IDisplayPreferencesManager displayPreferencesManager,
        IEventManager? eventManager = null)
    {
        _userManager = userManager;
        _authContext = authContext;
        _cryptoProvider = cryptoProvider;
        _logger = logger;
        _sessionManager = sessionManager;
        _httpClientFactory = httpClientFactory;
        _canonicalLinks = new CanonicalLinkService(userManager, cryptoProvider, SSOPlugin.Instance.ConfigStore, logger, displayPreferences: displayPreferencesManager);
        _ssoOnly = new SsoOnlyLoginService(userManager, SSOPlugin.Instance.ConfigStore, logger);
        _logoutTickets = new LogoutTicketService(logger);
        var avatarService = new AvatarService(userManager, providerManager, serverConfigurationManager, logger, SsoHttp.UserAgent);
        var sessionMinter = new SessionMinter(userManager, avatarService, sessionManager, logger);
        _loginCompletion = new LoginCompletionService(_canonicalLinks, sessionMinter, _ssoOnly, SSOPlugin.Instance.ConfigStore, sessionManager, logger);
        // One publisher for both flows (#1142). Jellyfin supplies the event bus through DI; the flows take
        // it rather than the controller publishing for them, because only the flow knows that the refusal was
        // the role allow-list rather than one of the other denials that share the uniform 401.
        var loginEvents = new SsoLoginEvents(eventManager, logger);
        _oidc = new Flows.OidcLoginService(_loginCompletion, _canonicalLinks, loginEvents, httpClientFactory, loggerFactory, logger);
        _saml = new Flows.SamlLoginService(_loginCompletion, _canonicalLinks, loginEvents, logger);
        _logger.LogInformation("SSO Controller initialized");
    }

    // Names of the enabled providers in a config map, materialized to a detached list (the caller holds
    // the config lock). Shared by both GetNames twins so the enabled-only rule lives in one place. A
    // null-valued entry is skipped rather than dereferenced (#538) - the same fail-closed convention
    // CanonicalLinkService already applies to these maps.
    private static List<string> EnabledProviderNames<TConfig>(SerializableDictionary<string, TConfig> configs)
        where TConfig : ProviderConfigBase =>
        configs.Where(kvp => kvp.Value is { Enabled: true }).Select(kvp => kvp.Key).ToList();

    // Resolves the elevated caller's own username for the audit "actor" field, fail-soft: every SSO-Only
    // endpoint sits behind [Authorize(RequiresElevation)], so the caller is an administrator, but an
    // unresolved authorization info still yields a non-null placeholder rather than throwing - the audit
    // line must never be the thing that fails a security-relevant transition.
    private async Task<string> ResolveActorAsync()
    {
        var auth = await _authContext.GetAuthorizationInfo(HttpContext.Request).ConfigureAwait(false);
        return auth?.User?.Username ?? "unknown";
    }

    // A shallow copy of a provider map, taken under the config lock so the admin list endpoints
    // serialize a detached snapshot rather than the live dictionary (#157/F-10): a concurrent
    // provider add/remove cannot then modify the collection mid-serialization. The provider objects
    // are shared, but their CanonicalLinks are [JsonIgnore] (never serialized), and the only other
    // in-place write on the hot path is the NewPath bool flipped by a challenge - a scalar write that
    // cannot tear a JSON serialization or throw "collection modified".
    private static SerializableDictionary<string, TValue> SnapshotConfigs<TValue>(SerializableDictionary<string, TValue> source)
    {
        var copy = new SerializableDictionary<string, TValue>();
        foreach (var kvp in source)
        {
            copy[kvp.Key] = kvp.Value;
        }

        return copy;
    }

    // The {mode} route token is parsed once at the HTTP boundary (#369), so the protocol is validated in one place
    // and the typed ProviderMode is threaded inward; an unknown token refuses rather than defaulting. A mapped 400
    // rather than a throw (#1399), so the status an integrator depends on is decided here rather than by the host's
    // exception middleware, and the body names the two accepted tokens without echoing the supplied one.
    private static BadRequestObjectResult? RefuseUnknownMode(string mode, out ProviderMode parsed) =>
        ProviderModeParser.TryParse(mode, out parsed) ? null : new BadRequestObjectResult(UnknownModeMessage);

    // Fronts a rate-limited endpoint with the shared per-client gate (#128, #160, #382, #516): null when the
    // request may proceed, else the throttled outcome the single mapper renders (#474). The anonymous login
    // endpoints pass their class (challenge/callback/auth); the authenticated link/unlink write surface passes
    // "link" after its own authz guard, and the admin SSO-revoke passes "unregister" after its elevation
    // guard. The gate owns the one process-wide limiter and the whole check (config read,
    // IP classifier, endpoint-class keying, the #195 observability signal); this wrapper only supplies the
    // three request-scoped inputs it needs - the endpoint class, the connection's remote address, and the
    // response the retry-delay header is set on - so the controller keeps no rate-limit state of its own.
    private ActionResult? RateLimitCheck(string endpointClass) =>
        SsoRateLimitGate.Check(endpointClass, HttpContext.Connection.RemoteIpAddress, _logger, Response);

    // What the bare [Authorize] attribute used to answer, spelled out because it had to come off OidLogout for the
    // ticket path to exist (#1768): a resolved User, which subsumes the user-id test because the host derives the
    // id from the user, and IsDisabled, the condition the default policy enforces that an id test misses. A server
    // API key names no user and is refused here, a deliberate narrowing stated in SECURITY.md; IsAuthenticated is
    // deliberately not required, because what it reads for an api_key request is a host fact this tree cannot
    // observe, and the residual is stated at OidLogout rather than claimed as the whole of the host's policy.
    private static bool IsAuthenticatedCaller(AuthorizationInfo auth) =>
        auth is { User: { } user } && !user.HasPermission(PermissionKind.IsDisabled);

    // #1543. The stored configuration could not be read at start, so what a login would resolve against is
    // a default configuration holding no provider, no link and no secret. Refuse the whole sign-in surface
    // with 503 rather than letting each flow answer "no matching provider", which is a true sentence about
    // the wrong thing and sends an operator hunting a deleted provider. 503 because the condition is
    // temporary and the server states it plainly. It gates SSO sign-in ONLY: local Jellyfin sign-in is not
    // this plugin's and is untouched, which is what leaves an administrator a way in to repair (T-D1).
    private ObjectResult? RefuseWhileServingDefaults() =>
        SSOPlugin.Instance.ServingDefaultConfiguration
            ? StatusCode(StatusCodes.Status503ServiceUnavailable, ServingDefaultsMessage)
            : null;
}
