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

/// <summary>The revoke arm: removing one link, one user everywhere, or a whole provider under the stranding guards.</summary>
internal sealed partial class CanonicalLinkService
{
    /// <summary>Removes a manual canonical link when it is registered to the given user, in one read-modify-write under the config lock; the controller maps the result to a response.</summary>
    /// <param name="mode">The protocol the operation applies to, parsed once at the controller boundary (#369).</param>
    /// <param name="provider">The provider the link belongs to.</param>
    /// <param name="canonicalName">The provider-side identity key whose link is removed.</param>
    /// <param name="jellyfinUserId">The Jellyfin user the link must belong to.</param>
    /// <param name="callerIsAdministrator">Whether the caller is an administrator (#1647); a link carrying a deadline is removed only when true, and the default refuses.</param>
    /// <param name="passwordLoginDisabled">Whether the holder's account refuses password sign-in (#1720); the holder's removal of their last way in is refused when true, and the default refuses.</param>
    /// <param name="callerIsTheHolder">Whether the caller is the account named by <paramref name="jellyfinUserId"/> (#1732); narrows the administrator exemption to acts on somebody else's link, and the default refuses.</param>
    /// <param name="anotherAdministratorKeepsAWayIn">Whether another administrator can still sign in, measured at the boundary with <see cref="AdministratorsWithNoWayIn"/> (#1732); the default refuses.</param>
    /// <returns>The remove outcome, plus whether the user retains any other link (#468).</returns>
    internal CanonicalLinkRemoval TryRemoveLink(ProviderMode mode, string provider, string canonicalName, Guid jellyfinUserId, bool callerIsAdministrator = false, bool passwordLoginDisabled = true, bool callerIsTheHolder = true, bool anotherAdministratorKeepsAWayIn = false)
    {
        // One Mutate, so find, ownership check, removal and the last-link check cannot interleave; a no-result outcome still persists the unchanged configuration.
        return _configStore.Mutate(configuration =>
        {
            // Removal revokes a grant, so it keeps working on a disabled provider (#380); only absence is unknown.
            if (!TryGetLinks(configuration, mode, provider, requireEnabled: false, out var links))
            {
                return new CanonicalLinkRemoval(CanonicalLinkRemoveResult.UnknownProvider, UserRetainsAnyLink: false);
            }

            if (!links.TryGetValue(canonicalName, out var linkedId))
            {
                return new CanonicalLinkRemoval(CanonicalLinkRemoveResult.NotFound, UserRetainsAnyLink: false);
            }

            if (linkedId != jellyfinUserId)
            {
                return new CanonicalLinkRemoval(CanonicalLinkRemoveResult.Mismatch, UserRetainsAnyLink: false);
            }

            // A time-limited link is not its holder's to remove (#1647): the unlink would prune the deadline and a re-login could adopt the account with none; decided in this transaction.
            if (!callerIsAdministrator
                && TryGetProvider(configuration, mode, provider, out var config)
                && config.CanonicalLinkDeadlines.ContainsKey(canonicalName))
            {
                return new CanonicalLinkRemoval(CanonicalLinkRemoveResult.TimeLimited, UserRetainsAnyLink: false);
            }

            // A holder may not strand their own account (#1720), and an administrator acting on their own last way in is refused where no other administrator could undo it (#1732).
            // A way in is a link on an enabled provider, the login path's reading, not the any-link reading the revoke below uses; why, and what it costs: https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Linked-Accounts#design-record-links-keys-and-guards.
            // The two facts about the caller come from the boundary, outside this lock; the link reading is taken inside it.
            if ((!callerIsAdministrator || (callerIsTheHolder && !anotherAdministratorKeepsAWayIn))
                && passwordLoginDisabled
                && TryGetProvider(configuration, mode, provider, out var removingFrom)
                && removingFrom.Enabled
                && !UserKeepsAnEnabledWayIn(configuration, jellyfinUserId, mode, provider, canonicalName))
            {
                return new CanonicalLinkRemoval(CanonicalLinkRemoveResult.WouldStrandAccount, UserRetainsAnyLink: false);
            }

            links.Remove(canonicalName);

            // The issuer entry goes with the link (#186); a no-op for SAML.
            RemoveIssuer(configuration, mode, provider, canonicalName);

            // The deadline goes with the link (#1145), so a re-link of the subject starts with none.
            RemoveDeadline(configuration, mode, provider, canonicalName);

            // The last-login stamp goes with the link (#1120): unlinking is the erasure route for that personal data.
            RemoveLastSsoLogin(configuration, mode, provider, canonicalName);

            // The pending-approval mark goes with the link (#1529); it would otherwise keep offering an account with no SSO route.
            RemovePendingApproval(configuration, mode, provider, canonicalName);

            // Read in the same transaction as the removal (#468), so a concurrent link change cannot mislead the last-link revocation.
            var retainsAnyLink = UserHasAnyLink(configuration, jellyfinUserId);
            return new CanonicalLinkRemoval(CanonicalLinkRemoveResult.Removed, retainsAnyLink);
        });
    }

    /// <summary>Removes every canonical link pointing at the user across all providers, under the config lock, and returns how many went.</summary>
    /// <param name="userId">The Jellyfin user whose links are revoked.</param>
    /// <param name="removedFrom">When given, receives every provider a link was removed from, labelled by protocol, filled inside the same lock (#1649).</param>
    /// <param name="alsoForgetProvisionedPassword">When true, the minted-password record goes in the same transaction (#1733); the administrator revoke leaves it, because the account stands.</param>
    /// <returns>The number of links removed.</returns>
    internal int RemoveUserEverywhere(Guid userId, ICollection<string>? removedFrom = null, bool alsoForgetProvisionedPassword = false)
    {
        return _configStore.Mutate(configuration =>
        {
            int removed = 0;

            // Opt-in: the administrator revoke leaves the account standing, and a standing account keeps whatever password it holds.
            if (alsoForgetProvisionedPassword)
            {
                ProvisionedPassword.Forget(configuration, userId);
            }

            // One loop over both protocols, named for the caller's audit line; a null config object (#350) holds no links.
            var providers = configuration.SamlConfigs.Select(p => (p.Key, Protocol: "SAML", Config: (ProviderConfigBase?)p.Value))
                .Concat(configuration.OidConfigs.Select(p => (p.Key, Protocol: "OpenID", Config: (ProviderConfigBase?)p.Value)));
            foreach (var (name, protocol, config) in providers)
            {
                if (config?.CanonicalLinks is { } links)
                {
                    var here = CanonicalLinkRevoker.RemoveUser(links, userId);
                    removed += here;
                    if (here > 0)
                    {
                        removedFrom?.Add(protocol + " '" + name + "'");
                    }
                }

                // Orphaned issuer entries go (#186), so they cannot bind or refuse a future re-link; SAML has no issuer map.
                if (config is OidConfig oid && oid.CanonicalLinks is { } liveLinks)
                {
                    foreach (var staleKey in oid.CanonicalLinkIssuers.Keys.Where(k => !liveLinks.ContainsKey(k)).ToList())
                    {
                        oid.CanonicalLinkIssuers.Remove(staleKey);
                    }
                }

                // Orphaned deadlines go on both protocols (#1145); one left would expire a re-link on the next sweep tick.
                if (config?.CanonicalLinks is { } remaining)
                {
                    foreach (var staleKey in config.CanonicalLinkDeadlines.Keys.Where(k => !remaining.ContainsKey(k)).ToList())
                    {
                        config.CanonicalLinkDeadlines.Remove(staleKey);
                    }

                    // Orphaned last-login stamps go (#1120): Unregister is the erasure route the retention promise names.
                    foreach (var staleKey in config.CanonicalLinkLastLogins.Keys.Where(k => !remaining.ContainsKey(k)).ToList())
                    {
                        config.CanonicalLinkLastLogins.Remove(staleKey);
                    }

                    // Orphaned pending-approval marks go (#1529); one left would offer an account with no SSO route for approval.
                    foreach (var staleKey in config.CanonicalLinkPendingApprovals.Keys.Where(k => !remaining.ContainsKey(k)).ToList())
                    {
                        config.CanonicalLinkPendingApprovals.Remove(staleKey);
                    }
                }
            }

            return removed;
        });
    }

    /// <summary>Names the administrators among the given doors that have no way to sign in, read against the configuration as it stands now (#1519).</summary>
    /// <remarks>The safety net under the purge: an account can lose its password door in the window before the removal took the lock, which no link-table comparison can see, so it is read again afterwards.</remarks>
    /// <param name="doors">The accounts to re-judge, resolved through the user manager after the removal.</param>
    /// <returns>The usernames of administrators with neither a password door nor a link on an enabled provider.</returns>
    internal IReadOnlyList<string> AdministratorsWithNoWayIn(IReadOnlyList<AccountDoors> doors)
    {
        ArgumentNullException.ThrowIfNull(doors);

        return _configStore.Read(configuration =>
        {
            var stillLinked = UsersWithAnEnabledLink(configuration);
            return (IReadOnlyList<string>)doors
                .Where(door => door.IsAdministrator && !door.IsDisabled)
                .Where(door => !stillLinked.Contains(door.UserId))
                .Select(door => door.Username)
                .OrderBy(username => username, StringComparer.OrdinalIgnoreCase)
                .ToList();
        });
    }

    /// <summary>Removes every canonical link one provider holds (#1519), the way back from a link import that restored the wrong document; it refuses when the provider is unknown, the count differs, the table moved since <paramref name="judged"/> was resolved, or an administrator would be left with no way in.</summary>
    /// <remarks>
    /// One <c>Mutate</c>, so the count, the lockout guard (T-D1) and the removal cannot interleave; a stored password does not count as a way in, because the plugin's own seals (#1440) cannot be told from a password somebody holds.
    /// Why, and what the refusal costs: <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Linked-Accounts#design-record-links-keys-and-guards"/>.
    /// </remarks>
    /// <param name="mode">The provider protocol.</param>
    /// <param name="provider">The provider whose links are removed.</param>
    /// <param name="expectedLinkCount">The number of links the caller was shown and expects to remove.</param>
    /// <param name="judged">The doors of every account <see cref="SurveyProviderLinks"/> named, resolved outside this lock.</param>
    /// <returns>What happened, what to revoke, and - on the lockout refusal - who would have been stranded.</returns>
    internal ProviderLinkPurgeOutcome TryPurgeProviderLinks(ProviderMode mode, string provider, int expectedLinkCount, IReadOnlyList<AccountDoors> judged)
    {
        ArgumentNullException.ThrowIfNull(judged);

        return _configStore.Mutate(configuration =>
        {
            if (!TryGetLinks(configuration, mode, provider, requireEnabled: false, out var links))
            {
                return ProviderLinkPurgeOutcome.Refusing(ProviderLinkPurgeResult.UnknownProvider, 0);
            }

            if (links.Count != expectedLinkCount)
            {
                return ProviderLinkPurgeOutcome.Refusing(ProviderLinkPurgeResult.CountMismatch, links.Count);
            }

            // Re-derived here: the survey read an earlier transaction, and an account it never judged means the table moved.
            var linked = links.Values.Distinct().ToList();
            var doors = judged.ToDictionary(door => door.UserId);
            if (linked.Any(userId => !doors.ContainsKey(userId)))
            {
                return ProviderLinkPurgeOutcome.Refusing(ProviderLinkPurgeResult.LinkTableChanged, links.Count);
            }

            // Two questions over the same accounts: who is signed out holds no link anywhere, who is stranded holds none on an enabled provider (#380); both from one walk, because this lock is the one every login takes.
            var elsewhere = LinksHeldElsewhere(configuration, links);
            var losing = linked.Where(userId => !elsewhere.Any.Contains(userId)).ToList();

            // A run strands an administrator only when it takes their last way in; a disabled target was no way in before the run.
            var stranded = elsewhere.TargetEnabled
                ? linked
                    .Select(userId => doors[userId])
                    .Where(door => door.IsAdministrator && !door.IsDisabled)
                    .Where(door => !elsewhere.OnAnEnabledProvider.Contains(door.UserId))
                    .Select(door => door.Username)
                    .OrderBy(username => username, StringComparer.OrdinalIgnoreCase)
                    .ToList()
                : new List<string>();
            if (stranded.Count > 0)
            {
                return new ProviderLinkPurgeOutcome(ProviderLinkPurgeResult.WouldStrandAdministrator, 0, links.Count, Array.Empty<Guid>(), stranded, elsewhere.TargetEnabled);
            }

            var removed = links.Count;
            links.Clear();

            // Every stamp keyed on this provider's links is now an orphan, so the maps are cleared wholesale.
            if (TryGetProvider(configuration, mode, provider, out var config))
            {
                config.CanonicalLinkDeadlines.Clear();
                config.CanonicalLinkLastLogins.Clear();
                config.CanonicalLinkPendingApprovals.Clear();
                if (config is OidConfig oid)
                {
                    oid.CanonicalLinkIssuers.Clear();
                }
            }

            return new ProviderLinkPurgeOutcome(ProviderLinkPurgeResult.Purged, removed, removed, losing, Array.Empty<string>(), elsewhere.TargetEnabled);
        });
    }
}
