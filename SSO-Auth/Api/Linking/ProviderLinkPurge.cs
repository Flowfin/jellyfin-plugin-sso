// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;

namespace Jellyfin.Plugin.SSO_Auth.Api.Linking;

/// <summary>
/// The outcome of a per-provider bulk unlink (#1519). Closed by convention (the controller's mapper
/// throws on an unhandled arm), so a new outcome forces a new mapping rather than a silent
/// fall-through - which on this surface would mean answering success for a run that removed nothing.
/// </summary>
internal enum ProviderLinkPurgeResult
{
    /// <summary>Every link the provider held was removed.</summary>
    Purged,

    /// <summary>No provider of that mode/name exists; nothing was removed.</summary>
    UnknownProvider,

    /// <summary>The provider holds a different number of links than the caller expected; nothing was removed.</summary>
    CountMismatch,

    /// <summary>The run would leave an administrator account with no way to sign in; nothing was removed.</summary>
    WouldStrandAdministrator,

    /// <summary>The link table changed while the accounts were being judged; nothing was removed.</summary>
    LinkTableChanged,
}

/// <summary>
/// What one provider's link table looks like to the bulk unlink before it acts (#1519): how many links
/// the provider holds, and which accounts would be left holding no canonical link at all once those links
/// are gone. A detached snapshot taken under the configuration lock, so the caller can resolve those
/// accounts through the user manager WITHOUT holding it - the same discipline the link import takes for
/// the same reason, since a provider can carry thousands of links and a user-manager call per link inside
/// the lock would block every login for the duration.
/// </summary>
/// <param name="ProviderExists">Whether a provider of that mode and name is stored at all.</param>
/// <param name="LinkCount">How many links the provider holds.</param>
/// <param name="UsersLosingTheirLastLink">
/// The distinct accounts that hold a link on this provider and none on any other, so the purge would take
/// their last one. Re-derived under the lock when the purge runs; this copy exists only to be judged.
/// </param>
internal readonly record struct ProviderLinkSurvey(bool ProviderExists, int LinkCount, IReadOnlyList<Guid> UsersLosingTheirLastLink);

/// <summary>
/// What the tree can read about one account's ways in, resolved through the user manager OUTSIDE the
/// configuration lock and judged inside it (#1519, T-D1). "Can use a password" is not a single field on a
/// Jellyfin account and is not asked of the host: it is the same reading the SSO-only break-glass guard
/// already makes - the account routes to the built-in password provider AND carries a stored password -
/// and the mode-dependent half of it (SSO-only login is on, and this account is not the break-glass
/// admin) is applied by the purge, because only the purge holds the configuration.
/// </summary>
/// <param name="UserId">The account.</param>
/// <param name="Username">The account's own username, the basis the break-glass exemption is judged on.</param>
/// <param name="IsAdministrator">Whether the account holds the administrator permission.</param>
/// <param name="IsDisabled">Whether the account is disabled, and so already has no way in for this run to take.</param>
/// <param name="RoutesToPasswordProvider">Whether the account's authentication provider is Jellyfin's built-in password provider.</param>
/// <param name="HasStoredPassword">Whether the account carries a non-empty stored password.</param>
internal readonly record struct AccountDoors(
    Guid UserId,
    string Username,
    bool IsAdministrator,
    bool IsDisabled,
    bool RoutesToPasswordProvider,
    bool HasStoredPassword);

/// <summary>
/// The outcome of a per-provider bulk unlink (#1519), with everything the controller needs to answer, to
/// audit, and to revoke. Every field except <see cref="Result"/> is meaningful only on the arm that
/// produced it: a refusal removes nothing, so its counts describe the state that refused rather than work
/// done.
/// </summary>
/// <param name="Result">What happened.</param>
/// <param name="RemovedLinks">How many links were removed; zero on every refusal.</param>
/// <param name="ActualLinkCount">How many links the provider actually held, so a count mismatch can say what the real number is.</param>
/// <param name="RevokedUserIds">
/// The accounts whose LAST canonical link this run removed, which the controller revokes the live tokens
/// of - exactly the scope the single unlink revokes at (#468). Empty on every refusal.
/// </param>
/// <param name="StrandedAdministrators">
/// The administrator accounts whose last way in the run would have taken, named so the way out is
/// explicit. Empty on every other arm.
/// </param>
internal readonly record struct ProviderLinkPurgeOutcome(
    ProviderLinkPurgeResult Result,
    int RemovedLinks,
    int ActualLinkCount,
    IReadOnlyList<Guid> RevokedUserIds,
    IReadOnlyList<string> StrandedAdministrators);
