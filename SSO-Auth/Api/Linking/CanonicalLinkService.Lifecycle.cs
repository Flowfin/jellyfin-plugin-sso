// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Api.Metrics;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Cryptography;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Linking;

/// <summary>The account lifecycle after the link: deadlines, last-login stamps, expiry and the shared disable.</summary>
internal sealed partial class CanonicalLinkService
{
    /// <summary>Login-time deprovisioning (#831): disables the existing linked account when the role allow-list denied the login, opt-in per provider (<see cref="ProviderConfigBase.DisableAccountOnRoleDenied"/>).</summary>
    /// <remarks>An administrator is never disabled by this path (T-D1), it acts only on an existing subject-keyed link, and an already disabled account is a no-op.</remarks>
    /// <param name="mode">The provider protocol.</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="canonicalKey">The identity's stable subject key (OpenID sub / SAML NameID) whose login was denied.</param>
    /// <param name="issuer">The denied login's token issuer (OpenID only; null for SAML), checked against the link's stored issuer binding (#186) so a colliding subject from a repointed identity provider cannot disable the prior provider's account.</param>
    /// <returns><see langword="true"/> when an enabled non-admin account was actually disabled (so the caller audits it); otherwise <see langword="false"/>.</returns>
    internal async Task<bool> DisableDeniedAccountAsync(ProviderMode mode, string provider, string? canonicalKey, string? issuer = null) =>
        await DisableLinkedAccountAsync(mode, provider, canonicalKey, issuer, enforceIssuerBinding: true).ConfigureAwait(false) is not null;

    /// <summary>Login-time enforcement of an account-expiry deadline (#1144): disables the existing linked account when the login's expiry instant has passed, opt-in per provider (<see cref="ProviderConfigBase.AccountExpiryClaim"/>).</summary>
    /// <remarks>The same body as <see cref="DisableDeniedAccountAsync"/>, so the two share every guard; the names differ because each caller owes its own audit line.</remarks>
    /// <param name="mode">The provider protocol.</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="canonicalKey">The identity's stable subject key (OpenID sub / SAML NameID) whose deadline has passed.</param>
    /// <param name="issuer">The login's token issuer (OpenID only; null for SAML), checked against the link's stored issuer binding (#186).</param>
    /// <returns><see langword="true"/> when an enabled non-admin account was actually disabled (so the caller audits it once, at the transition); otherwise <see langword="false"/>.</returns>
    internal async Task<bool> DisableExpiredAccountAsync(ProviderMode mode, string provider, string? canonicalKey, string? issuer = null) =>
        await DisableLinkedAccountAsync(mode, provider, canonicalKey, issuer, enforceIssuerBinding: true).ConfigureAwait(false) is not null;

    /// <summary>Between-logins enforcement of an account-expiry deadline (#1145): the sweep's disable for a link whose persisted deadline passed, returning the account it disabled so the caller can revoke its tokens.</summary>
    /// <remarks>Same body and guards as the login paths, without the issuer binding (#186): a sweep has no incoming login to bind against, and a null issuer would read every bound link as a mismatch.</remarks>
    /// <param name="mode">The provider protocol the link belongs to.</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="canonicalKey">The stable subject key whose persisted deadline has passed.</param>
    /// <returns>The Jellyfin user id disabled by this call, or <see langword="null"/> when nothing was disabled (no live link, deleted user, administrator, or already disabled).</returns>
    internal Task<Guid?> DisableExpiredAccountBySweepAsync(ProviderMode mode, string provider, string? canonicalKey) =>
        DisableLinkedAccountAsync(mode, provider, canonicalKey, issuer: null, enforceIssuerBinding: false);

    /// <summary>Persists the expiry instant a login carried for one link (#1145), last writer wins, and only while the link exists; the map is withheld from JSON so a configuration PUT cannot forge a past deadline.</summary>
    /// <param name="mode">The provider protocol the link belongs to.</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="canonicalKey">The stable subject key the link is stored under.</param>
    /// <param name="deadlineUtc">The expiry instant to persist, in UTC.</param>
    internal void RecordAccountDeadline(ProviderMode mode, string provider, string? canonicalKey, DateTime deadlineUtc)
    {
        if (string.IsNullOrWhiteSpace(canonicalKey))
        {
            return;
        }

        _configStore.Mutate(configuration =>
        {
            if (TryGetProvider(configuration, mode, provider, out var config) && config.CanonicalLinks.ContainsKey(canonicalKey))
            {
                config.CanonicalLinkDeadlines[canonicalKey] = deadlineUtc.ToUniversalTime();
            }
        });
    }

    /// <summary>Stamps the instant of a successful login against the link it resolved (#1120), so the roster answers "last SSO login" without an event log.</summary>
    /// <remarks>Bounded by construction: an entry is only ever written beside a live link, and it is rewritten only once it has aged past <see cref="ProviderConfigBase.LastSsoLoginGranularity"/>, so a repeat login pays no write on the hot path.</remarks>
    /// <param name="mode">The provider protocol the link belongs to.</param>
    /// <param name="provider">The provider name.</param>
    /// <param name="canonicalKey">The stable subject key the link is stored under.</param>
    internal void RecordLastSsoLogin(ProviderMode mode, string provider, string? canonicalKey)
    {
        if (string.IsNullOrWhiteSpace(canonicalKey))
        {
            return;
        }

        var nowUtc = _clock().ToUniversalTime();

        // Decided under a locked read, so a repeat login inside the granularity window reaches no write; a stored instant in the future is due too, or a stepped-back clock would freeze it.
        var due = _configStore.Read(configuration =>
            TryGetProvider(configuration, mode, provider, out var config)
            && config.CanonicalLinks.ContainsKey(canonicalKey)
            && (!config.CanonicalLinkLastLogins.TryGetValue(canonicalKey, out var stored)
                || stored.ToUniversalTime() > nowUtc
                || nowUtc - stored.ToUniversalTime() >= ProviderConfigBase.LastSsoLoginGranularity));

        if (!due)
        {
            return;
        }

        // Availability: this runs after the mint, so a failed persist is a warning and a stale roster column, not a failed login; the deadline writer above is deliberately not treated the same.
        try
        {
            _configStore.Mutate(configuration =>
            {
                // Re-tested under the write lock: an unlink between the two acquisitions must not resurrect a stamp.
                if (TryGetProvider(configuration, mode, provider, out var config) && config.CanonicalLinks.ContainsKey(canonicalKey))
                {
                    config.CanonicalLinkLastLogins[canonicalKey] = nowUtc;
                }
            });
        }
        catch (Exception ex)
        {
            // The provider only, never the subject; the sanitizer stays at the call.
            _logger.LogWarning(
                ex,
                "[SSO] Could not record the last SSO login for provider {Provider}. The login itself succeeded; the roster timestamp is stale.",
                provider?.ReplaceLineEndings(string.Empty).Replace('[', '('));
        }
    }

    /// <summary>The canonical links whose persisted deadline is at or before <paramref name="nowUtc"/>, across both protocols, materialized in one locked pass (#1145).</summary>
    /// <remarks>A candidate list, not a verdict: <see cref="DisableExpiredAccountBySweepAsync"/> re-resolves each entry and applies every guard, including the disabled-provider skip, so the test is stated once.</remarks>
    /// <param name="nowUtc">The instant to compare each deadline against.</param>
    /// <returns>The expired links, as a detached snapshot.</returns>
    internal IReadOnlyList<ExpiredCanonicalLink> ExpiredLinks(DateTime nowUtc)
    {
        return _configStore.Read(configuration =>
        {
            var expired = new List<ExpiredCanonicalLink>();
            Collect(configuration.SamlConfigs, ProviderMode.Saml, expired);
            Collect(configuration.OidConfigs, ProviderMode.Oid, expired);
            return (IReadOnlyList<ExpiredCanonicalLink>)expired;
        });

        void Collect<T>(SerializableDictionary<string, T> configs, ProviderMode mode, List<ExpiredCanonicalLink> into)
            where T : ProviderConfigBase
        {
            foreach (var entry in configs)
            {
                // A provider stored with a null config object (#350) holds nothing to sweep.
                if (entry.Value is not { } config)
                {
                    continue;
                }

                foreach (var deadline in config.CanonicalLinkDeadlines)
                {
                    if (deadline.Value <= nowUtc && config.CanonicalLinks.TryGetValue(deadline.Key, out var userId))
                    {
                        into.Add(new ExpiredCanonicalLink(mode, entry.Key, deadline.Key, userId));
                    }
                }
            }
        }
    }

    /// <summary>Every distinct Jellyfin account any provider still links, as a detached snapshot read once under the lock (#1440).</summary>
    /// <remarks>The link is what says an account belongs to this plugin, since the mint overwrites AuthenticationProviderId on every login; a disabled provider is walked too, because this sweep only removes an empty-password door.</remarks>
    /// <returns>The linked account ids, without duplicates.</returns>
    internal IReadOnlyCollection<Guid> LinkedUserIds()
    {
        return _configStore.Read(configuration =>
        {
            var linked = new HashSet<Guid>();
            foreach (var config in configuration.SamlConfigs.Values.Concat<ProviderConfigBase>(configuration.OidConfigs.Values))
            {
                // A provider stored with a null config object (#350) holds no links.
                if (config?.CanonicalLinks is { } links)
                {
                    linked.UnionWith(links.Values);
                }
            }

            return (IReadOnlyCollection<Guid>)linked;
        });
    }

    // The shared body of every disable path (#831, #1144, #1145): PermissionRolePolicy bars IsDisabled from role mapping, and these sanctioned exceptions share one body so the guard below cannot be absent from one of them.
    private async Task<Guid?> DisableLinkedAccountAsync(ProviderMode mode, string provider, string? canonicalKey, string? issuer, bool enforceIssuerBinding)
    {
        if (string.IsNullOrWhiteSpace(canonicalKey))
        {
            return null;
        }

        // Resolve the existing subject link only, never a create or the legacy path; a disabled provider fails closed, and an issuer mismatch (#186) means the account is somebody else's.
        var userId = _configStore.Read(configuration =>
            TryGetLinks(configuration, mode, provider, requireEnabled: true, out var links)
                && links.TryGetValue(canonicalKey, out var linked)
                && (!enforceIssuerBinding || ClassifyIssuer(configuration, mode, provider, canonicalKey, issuer) != IssuerBinding.Mismatch)
                ? (Guid?)linked
                : null);
        if (userId is null)
        {
            return null;
        }

        var user = _userManager.GetUserById(userId.Value);
        if (user is null)
        {
            return null;
        }

        // The guard (T-D1): an administrator is never disabled by SSO, and an already disabled account is not re-audited.
        if (user.HasPermission(PermissionKind.IsAdministrator) || user.HasPermission(PermissionKind.IsDisabled))
        {
            return null;
        }

        user.SetPermission(PermissionKind.IsDisabled, true);
        await _userManager.UpdateUserAsync(user).ConfigureAwait(false);

        // The account was enabled, so a pending-approval record on it was false (#1529); left standing it would put the account straight back onto the approval list.
        RemovePendingApprovalOutsideLock(mode, provider, canonicalKey, userId.Value);
        return userId;
    }

    // The deadline goes with the link (#1145), or a re-link of the subject would be swept at once.
    private static void RemoveDeadline(PluginConfiguration configuration, ProviderMode mode, string provider, string canonicalKey)
    {
        if (TryGetProvider(configuration, mode, provider, out var config))
        {
            config.CanonicalLinkDeadlines.Remove(canonicalKey);
        }
    }

    // Its own step beside RemoveDeadline, because an orphan stamp is retained personal data (#1120), not bookkeeping.
    private static void RemoveLastSsoLogin(PluginConfiguration configuration, ProviderMode mode, string provider, string canonicalKey)
    {
        if (TryGetProvider(configuration, mode, provider, out var config))
        {
            config.CanonicalLinkLastLogins.Remove(canonicalKey);
        }
    }
}
