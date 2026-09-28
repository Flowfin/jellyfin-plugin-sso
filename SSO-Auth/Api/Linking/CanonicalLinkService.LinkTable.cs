// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
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
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Cryptography;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Linking;

/// <summary>The link table: writing, reading and surveying the links a provider holds.</summary>
internal sealed partial class CanonicalLinkService
{
    /// <summary>Creates a manual canonical link from a provider-side identity to a Jellyfin user, under the config lock; the controller maps the result to a response.</summary>
    /// <param name="mode">The protocol the operation applies to, parsed once at the controller boundary (#369).</param>
    /// <param name="provider">The provider the link belongs to.</param>
    /// <param name="providerUserId">The provider-side identity key (OpenID sub / SAML NameID).</param>
    /// <param name="jellyfinUserId">The Jellyfin user to link the identity to.</param>
    /// <param name="issuer">The OpenID id_token issuer to issuer-bind the new link to (#186); null for SAML or an unauthenticated admin link, which leaves the link un-stamped (trust-on-first-use applies on its first login).</param>
    /// <returns>The write outcome.</returns>
    internal CanonicalLinkWriteResult TryCreateLink(ProviderMode mode, string provider, string providerUserId, Guid jellyfinUserId, string? issuer = null)
        => WriteLink(mode, provider, providerUserId, jellyfinUserId, issuer, refuseRebind: false);

    /// <summary>Creates a canonical link for a provisioning tool that holds no identity-provider response (#1133); a key already held by a different user is refused rather than repointed.</summary>
    /// <remarks>The refusal lives inside the same <c>Mutate</c> as the write, so "nothing was written" is true of a conflict rather than likely; <see cref="TryCreateLink"/> keeps its repoint because its callers proved control of the subject in a live flow.</remarks>
    /// <param name="mode">The protocol the operation applies to, parsed once at the controller boundary (#369).</param>
    /// <param name="provider">The provider the link belongs to.</param>
    /// <param name="providerUserId">The provider-side identity key (OpenID sub / SAML NameID).</param>
    /// <param name="jellyfinUserId">The Jellyfin user to link the identity to.</param>
    /// <returns>The write outcome, including <see cref="CanonicalLinkWriteResult.ConflictingUser"/>.</returns>
    internal CanonicalLinkWriteResult TryPreprovisionLink(ProviderMode mode, string provider, string providerUserId, Guid jellyfinUserId)
        => WriteLink(mode, provider, providerUserId, jellyfinUserId, issuer: null, refuseRebind: true);

    /// <summary>The one canonical-link write behind both entry points, so the empty-key guard, the provider lookup and the issuer stamp cannot drift.</summary>
    /// <param name="mode">The protocol the operation applies to.</param>
    /// <param name="provider">The provider the link belongs to.</param>
    /// <param name="providerUserId">The provider-side identity key.</param>
    /// <param name="jellyfinUserId">The Jellyfin user to link the identity to.</param>
    /// <param name="issuer">The OpenID id_token issuer to bind the new link to (#186), or null.</param>
    /// <param name="refuseRebind">Whether a key already held by another Jellyfin user is refused instead of repointed.</param>
    /// <returns>The write outcome.</returns>
    private CanonicalLinkWriteResult WriteLink(ProviderMode mode, string provider, string providerUserId, Guid jellyfinUserId, string? issuer, bool refuseRebind)
    {
        // Fail closed (#95) before the provider lookup, so the two refusals keep their distinct response bodies.
        if (string.IsNullOrWhiteSpace(providerUserId))
        {
            return CanonicalLinkWriteResult.EmptyKey;
        }

        return _configStore.Mutate(configuration =>
        {
            // Link creation is a grant, so a provider disabled between the controller gate and this transaction is refused (#380).
            if (!TryGetLinks(configuration, mode, provider, requireEnabled: true, out var links))
            {
                return CanonicalLinkWriteResult.UnknownProvider;
            }

            // Whether the key changes hands decides the rebind refusal (#1133) and what the write leaves of the key's entries; a repeat of the same mapping is neither.
            var holds = links.TryGetValue(providerUserId, out var held);
            var sameHolder = holds && held == jellyfinUserId;

            if (refuseRebind && holds && !sameHolder)
            {
                return CanonicalLinkWriteResult.ConflictingUser;
            }

            links[providerUserId] = jellyfinUserId;
            StampIssuerInPlace(configuration, mode, provider, providerUserId, issuer);

            // The entries the key carried go only when the key changes hands (#1529, #1638): a same-mapping write keeps them, and a time-limited user cannot shed a deadline by re-linking.
            if (!sameHolder)
            {
                RemovePendingApproval(configuration, mode, provider, providerUserId);
                RemoveDeadline(configuration, mode, provider, providerUserId);
                RemoveLastSsoLogin(configuration, mode, provider, providerUserId);
            }

            return CanonicalLinkWriteResult.Created;
        });
    }

    /// <summary>Projects, for one protocol, a provider to linked-keys map for the user, materialized under the lock so serialization cannot tear against a concurrent write (#157).</summary>
    /// <param name="mode">The protocol the operation applies to, parsed once at the controller boundary (#369).</param>
    /// <param name="jellyfinUserId">The Jellyfin user whose links are listed.</param>
    /// <returns>A provider -> link-key-list map.</returns>
    internal SerializableDictionary<string, IEnumerable<string>> LinksByUser(ProviderMode mode, Guid jellyfinUserId)
    {
        return _configStore.Read(configuration =>
        {
            // A provider stored with a null config object (#350) yields null links and is skipped.
            var providerLinks = mode == ProviderMode.Saml
                ? configuration.SamlConfigs.Select(p => (p.Key, p.Value?.CanonicalLinks))
                : configuration.OidConfigs.Select(p => (p.Key, p.Value?.CanonicalLinks));

            var mappings = new SerializableDictionary<string, IEnumerable<string>>();
            foreach (var (provider, links) in providerLinks)
            {
                if (links != null)
                {
                    mappings[provider] = links
                        .Where(link => link.Value == jellyfinUserId)
                        .Select(link => link.Key)
                        .ToList();
                }
            }

            return mappings;
        });
    }

    /// <summary>Reads what one provider's link table looks like before a bulk unlink (#1519): whether it is stored, how many links it holds, and which accounts would be left with no link anywhere.</summary>
    /// <remarks>A read and not the act: the accounts are resolved through the user manager outside the lock, and <see cref="TryPurgeProviderLinks"/> re-derives the set under the lock and refuses when it moved. A disabled provider is surveyed like an enabled one (#380).</remarks>
    /// <param name="mode">The provider protocol.</param>
    /// <param name="provider">The provider whose links would be removed.</param>
    /// <returns>The snapshot to judge; <c>ProviderExists = false</c> when no such provider is stored.</returns>
    internal ProviderLinkSurvey SurveyProviderLinks(ProviderMode mode, string provider)
    {
        return _configStore.Read(configuration =>
            TryGetLinks(configuration, mode, provider, requireEnabled: false, out var links)
                ? new ProviderLinkSurvey(true, links.Count, links.Values.Distinct().ToList())
                : new ProviderLinkSurvey(false, 0, Array.Empty<Guid>()));
    }

    // One walk over the other providers under the caller's lock: who holds a link elsewhere at all, who holds one on an enabled provider, and whether the target is enabled; the target is excluded by reference, since a SAML and an OpenID provider may share a name.
    private static LinksElsewhere LinksHeldElsewhere(PluginConfiguration configuration, SerializableDictionary<string, Guid> targetLinks)
    {
        var any = new HashSet<Guid>();
        var enabled = new HashSet<Guid>();
        var targetEnabled = false;

        foreach (var config in AllProviders(configuration))
        {
            if (config?.CanonicalLinks is not { } links)
            {
                continue;
            }

            if (ReferenceEquals(links, targetLinks))
            {
                targetEnabled |= config.Enabled;
                continue;
            }

            foreach (var userId in links.Values)
            {
                any.Add(userId);
                if (config.Enabled)
                {
                    enabled.Add(userId);
                }
            }
        }

        return new LinksElsewhere(any, enabled, targetEnabled);
    }

    /// <summary>Whether an enabled provider of either protocol still links the account (#1741); the administrator revoke asks before refusing, because a revoke that takes no way in strands nobody.</summary>
    /// <remarks>The same reading <see cref="AdministratorsWithNoWayIn"/> takes of every other administrator, so the two halves of the guard agree on what a way in is.</remarks>
    /// <param name="userId">The account the revoke would act on.</param>
    /// <returns>True when at least one enabled provider holds a link pointing at the account.</returns>
    internal bool UserHoldsAnEnabledLink(Guid userId)
        => _configStore.Read(configuration => UsersWithAnEnabledLink(configuration).Contains(userId));

    // The after-the-fact form of the guard's reading, with no target to exclude; one walk, under the lock every login takes.
    private static HashSet<Guid> UsersWithAnEnabledLink(PluginConfiguration configuration)
    {
        var linked = new HashSet<Guid>();
        foreach (var config in AllProviders(configuration))
        {
            if (config is { Enabled: true, CanonicalLinks: { } links })
            {
                foreach (var userId in links.Values)
                {
                    linked.Add(userId);
                }
            }
        }

        return linked;
    }

    // Whether any provider still links the user, inside the caller's transaction (#468); a null config object (#350) is skipped.
    private static bool UserHasAnyLink(PluginConfiguration configuration, Guid userId)
    {
        foreach (var config in configuration.SamlConfigs.Values.Concat<ProviderConfigBase>(configuration.OidConfigs.Values))
        {
            if (config?.CanonicalLinks is { } links && links.ContainsValue(userId))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Whether the user would still hold a link that can sign them in after the named one is removed (#1720): a link on an enabled provider other than the one being removed.</summary>
    /// <remarks>Not <see cref="UserHasAnyLink"/>: that one decides the last-link revoke and counts a disabled provider's link, this one decides whether the account can still get in, as the login path reads it.</remarks>
    /// <param name="configuration">The configuration to read, inside the caller's transaction.</param>
    /// <param name="userId">The Jellyfin user whose remaining ways in are being counted.</param>
    /// <param name="mode">The protocol of the link being removed.</param>
    /// <param name="provider">The provider of the link being removed.</param>
    /// <param name="canonicalName">The key of the link being removed, which does not count for itself.</param>
    /// <returns>True when some other enabled provider still links this user.</returns>
    private static bool UserKeepsAnEnabledWayIn(PluginConfiguration configuration, Guid userId, ProviderMode mode, string provider, string canonicalName)
    {
        foreach (var (protocol, providers) in new (ProviderMode Mode, IEnumerable<KeyValuePair<string, ProviderConfigBase>> Providers)[]
        {
            (ProviderMode.Oid, configuration.OidConfigs.Select(entry => new KeyValuePair<string, ProviderConfigBase>(entry.Key, entry.Value))),
            (ProviderMode.Saml, configuration.SamlConfigs.Select(entry => new KeyValuePair<string, ProviderConfigBase>(entry.Key, entry.Value))),
        })
        {
            foreach (var (name, config) in providers)
            {
                if (config is not { Enabled: true, CanonicalLinks: { } links })
                {
                    continue;
                }

                // The link being removed is not its own replacement; matched on protocol, provider and key, since one key may exist on several providers.
                var isTheOneBeingRemoved = protocol == mode && string.Equals(name, provider, StringComparison.Ordinal);
                foreach (var entry in links)
                {
                    if (entry.Value == userId
                        && !(isTheOneBeingRemoved && string.Equals(entry.Key, canonicalName, StringComparison.Ordinal)))
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }
}
