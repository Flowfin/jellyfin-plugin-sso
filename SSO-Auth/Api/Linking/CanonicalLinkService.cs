// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Api.Metrics;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Cryptography;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Linking;

/// <summary>The outcome of a manual link-creation request; closed by convention, so the controller's mapper throws on a new arm rather than falling through.</summary>
internal enum CanonicalLinkWriteResult
{
    /// <summary>The link was created.</summary>
    Created,

    /// <summary>The SSO identity did not resolve a usable key; nothing was written.</summary>
    EmptyKey,

    /// <summary>No provider of that mode/name exists; nothing was written.</summary>
    UnknownProvider,

    /// <summary>The key is already held by a different Jellyfin user; nothing was written (#1133).</summary>
    ConflictingUser,
}

/// <summary>The outcome of a manual unlink request; closed by convention, so the controller's mapper throws on a new arm.</summary>
internal enum CanonicalLinkRemoveResult
{
    /// <summary>The link was removed.</summary>
    Removed,

    /// <summary>No link is registered for that canonical name.</summary>
    NotFound,

    /// <summary>A link exists but is registered to a different Jellyfin user; nothing was removed.</summary>
    Mismatch,

    /// <summary>No provider of that mode/name exists; nothing was removed.</summary>
    UnknownProvider,

    /// <summary>The link carries a provisioned access deadline and the caller is not an administrator; nothing was removed (#1647).</summary>
    TimeLimited,

    /// <summary>Removing this link would leave its holder unable to sign in by any means, and the caller is the holder; nothing was removed (#1720).</summary>
    WouldStrandAccount,
}

/// <summary>The outcome of approving an account this plugin provisioned inert (#1529); closed by convention, so the controller's mapper throws on a new arm.</summary>
/// <remarks>The refusals stay distinct because each tells the administrator something different, and only one sends them elsewhere.</remarks>
internal enum PendingApprovalResult
{
    /// <summary>The account was enabled and its record removed.</summary>
    Approved,

    /// <summary>No provider of that mode/name exists; nothing was changed.</summary>
    UnknownProvider,

    /// <summary>This plugin holds no live record that it provisioned that identity's account inert; nothing was changed.</summary>
    NotPending,

    /// <summary>The recorded account is an administrator and is not approvable here; the record was left as it is.</summary>
    Administrator,

    /// <summary>The recorded account is already enabled; the record it had outlived was removed and nothing else changed.</summary>
    AlreadyEnabled,

    /// <summary>The recorded account no longer exists; the record was removed and nothing else changed.</summary>
    AccountGone,
}

/// <summary>The issuer binding of a resolved subject-keyed OpenID link against the current login's issuer (#186); SAML and a login with no subject link are <see cref="NotBound"/>.</summary>
internal enum IssuerBinding
{
    /// <summary>Issuer binding does not apply (SAML / any non-OpenID mode, or no subject link resolved).</summary>
    NotBound,

    /// <summary>The link's stored issuer ordinally equals the login's issuer - proceed, no write.</summary>
    Match,

    /// <summary>The link carries no stored issuer (a legacy/un-stamped link) - eligible for trust-on-first-use stamping.</summary>
    Absent,

    /// <summary>The link's stored issuer differs from the login's - refuse the login (fail closed).</summary>
    Mismatch,
}

/// <summary>The outcome of a manual unlink, with whether the user still holds any other canonical link after it, read in the same transaction; the controller revokes tokens only when the last link went (#468).</summary>
/// <param name="Result">The remove outcome.</param>
/// <param name="UserRetainsAnyLink">Whether any provider still links the user; defined only when <paramref name="Result"/> is <see cref="CanonicalLinkRemoveResult.Removed"/>, false otherwise.</param>
internal readonly record struct CanonicalLinkRemoval(CanonicalLinkRemoveResult Result, bool UserRetainsAnyLink);

/// <summary>One canonical link whose persisted deadline has passed (#1145), as a detached snapshot from one locked pass; the disable it feeds re-resolves and re-guards it, so a stale entry is a no-op.</summary>
/// <param name="Mode">The provider protocol the link belongs to.</param>
/// <param name="Provider">The provider name.</param>
/// <param name="CanonicalKey">The stable subject key the link and the deadline are stored under.</param>
/// <param name="UserId">The Jellyfin user the link points at, as read in that pass.</param>
internal readonly record struct ExpiredCanonicalLink(ProviderMode Mode, string Provider, string CanonicalKey, Guid UserId);

/// <summary>The account-linking workflow behind the login and admin endpoints: resolves an SSO identity to a Jellyfin account, migrates legacy username-keyed links to the subject key (#155), and removes links.</summary>
/// <remarks>
/// The controller keeps the HTTP boundary and the authorization guards; this service owns every read and write of a provider's link maps, through <see cref="ProviderConfigStore"/> so each check-then-write stays under one lock.
/// The rules behind the guards: <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Linked-Accounts#design-record-links-keys-and-guards"/>.
/// </remarks>
internal sealed partial class CanonicalLinkService
{
    // Process-wide on purpose: the service is built per request, so an instance gate would throttle nothing (#362); one minute matches the sibling cap-warn gates (#246).
    private static readonly IntervalGate SharedLegacyLinkWarnGate = new(TimeSpan.FromMinutes(1));

    private readonly IUserManager _userManager;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly ProviderConfigStore _configStore;
    private readonly ILogger _logger;
    private readonly IntervalGate _legacyLinkWarnGate;
    private readonly Func<DateTime> _clock;
    private readonly IDisplayPreferencesManager? _displayPreferences;

    /// <summary>Initializes a new instance of the <see cref="CanonicalLinkService"/> class.</summary>
    /// <param name="userManager">The Jellyfin user manager.</param>
    /// <param name="cryptoProvider">The crypto provider used for legacy link hashing.</param>
    /// <param name="configStore">The provider configuration store the link maps live in.</param>
    /// <param name="logger">The logger.</param>
    /// <param name="legacyLinkWarnGate">The pending-legacy-link warning throttle; null takes the shared process-wide gate.</param>
    /// <param name="clock">The clock driving the warning throttle; null uses the wall clock.</param>
    /// <param name="displayPreferences">The host's display-preferences store the create arm seeds a home-screen layout into (#1101); null on the paths that never reach the create arm, and a template naming a layout then logs instead of throwing.</param>
    internal CanonicalLinkService(
        IUserManager userManager,
        ICryptoProvider cryptoProvider,
        ProviderConfigStore configStore,
        ILogger logger,
        IntervalGate? legacyLinkWarnGate = null,
        Func<DateTime>? clock = null,
        IDisplayPreferencesManager? displayPreferences = null)
    {
        _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
        _configStore = configStore ?? throw new ArgumentNullException(nameof(configStore));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _displayPreferences = displayPreferences;

        // Production leaves both null; tests pass a fresh gate and a fake clock.
        _legacyLinkWarnGate = legacyLinkWarnGate ?? SharedLegacyLinkWarnGate;
        _clock = clock ?? (() => DateTime.UtcNow);
    }

    // The stored provider object, or null when it is gone or was stored with a null config object (#350).
    private static ProviderConfigBase? ProviderConfigFor(PluginConfiguration configuration, ProviderMode mode, string provider) =>
        mode switch
        {
            ProviderMode.Saml => configuration.SamlConfigs.TryGetValue(provider, out var saml) ? saml : null,
            ProviderMode.Oid => configuration.OidConfigs.TryGetValue(provider, out var oid) ? oid : null,
            _ => null,
        };

    // Both protocols' providers as one sequence, so a walk over them is written once.
    private static IEnumerable<ProviderConfigBase> AllProviders(PluginConfiguration configuration)
        => configuration.SamlConfigs.Values.Concat<ProviderConfigBase>(configuration.OidConfigs.Values);

    // The provider's links map by TryGetValue, so an unknown provider or a null config object (#350) fails closed instead of throwing (#241); with requireEnabled a disabled provider counts as absent (#380), which every grant path passes and removal does not.
    // Callers hold the config lock; the map is self-healing, so mutating it persists.
    private static bool TryGetLinks(PluginConfiguration configuration, ProviderMode mode, string provider, bool requireEnabled, [NotNullWhen(true)] out SerializableDictionary<string, Guid>? links)
    {
        switch (mode)
        {
            case ProviderMode.Saml:
                return TryGetLinks(configuration.SamlConfigs, provider, requireEnabled, out links);

            case ProviderMode.Oid:
                return TryGetLinks(configuration.OidConfigs, provider, requireEnabled, out links);

            default:
                throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unknown provider mode.");
        }
    }

    // One body for both protocols (#204); Enabled is read only after the links proved the config non-null.
    private static bool TryGetLinks<T>(SerializableDictionary<string, T> configs, string provider, bool requireEnabled, [NotNullWhen(true)] out SerializableDictionary<string, Guid>? links)
        where T : ProviderConfigBase
    {
        var ok = configs.TryGetValue(provider, out var config);
        links = config?.CanonicalLinks;
        return ok && links != null && (!requireEnabled || config?.Enabled == true);
    }

    // The provider object itself, for the maps that hang off it; same fail-closed shape as TryGetLinks, and callers hold the lock.
    private static bool TryGetProvider(PluginConfiguration configuration, ProviderMode mode, string provider, [NotNullWhen(true)] out ProviderConfigBase? config)
    {
        config = mode switch
        {
            ProviderMode.Saml => configuration.SamlConfigs.TryGetValue(provider, out var saml) ? saml : null,
            ProviderMode.Oid => configuration.OidConfigs.TryGetValue(provider, out var oid) ? oid : null,
            _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unknown provider mode."),
        };

        return config is not null;
    }
}
