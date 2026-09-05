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
/// What one provider's link table looks like to the bulk unlink before it acts (#1519): whether the
/// provider is stored at all, how many links it holds, and which accounts hold them.
/// </summary>
/// <remarks>
/// A detached snapshot taken under the configuration lock and WITHOUT a write, which is both of the jobs
/// it has. It lets the accounts be resolved through the user manager with the lock released - a provider
/// can carry thousands of links, and a user-manager call per link inside the lock would block every login
/// for the duration - and it lets the two refusals a stale page actually produces be answered without
/// entering a mutation, because every return out of one persists the configuration file even when it
/// changed nothing, and a count that does not match is this endpoint's NORMAL outcome rather than an
/// exceptional one. The authoritative checks stay inside the mutation; this only keeps the routine
/// refusal off the write path.
/// </remarks>
/// <param name="ProviderExists">Whether a provider of that mode and name is stored.</param>
/// <param name="LinkCount">How many links it holds.</param>
/// <param name="LinkedUsers">The distinct accounts holding those links, to be judged before the purge runs.</param>
internal readonly record struct ProviderLinkSurvey(bool ProviderExists, int LinkCount, IReadOnlyList<Guid> LinkedUsers);

/// <summary>
/// What one walk of every provider OTHER than the one being emptied says about the accounts it holds
/// (#1519), plus whether the target itself is enabled.
/// </summary>
/// <remarks>
/// Two sets rather than one, because the purge asks two questions with opposite readings of a disabled
/// provider: who is left holding no link at all decides who is signed out, and who is left holding no
/// link a login could resolve decides who would be stranded. Built once, because it is built inside the
/// process-wide configuration lock every login takes, and a provider can carry thousands of links.
/// </remarks>
/// <param name="Any">Accounts holding a link on some other provider, enabled or not.</param>
/// <param name="OnAnEnabledProvider">Accounts holding a link on some other ENABLED provider, which is what a login can resolve.</param>
/// <param name="TargetEnabled">Whether the provider being emptied is itself enabled, so its links were a way in before the run.</param>
internal readonly record struct LinksElsewhere(HashSet<Guid> Any, HashSet<Guid> OnAnEnabledProvider, bool TargetEnabled);

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
    IReadOnlyList<string> StrandedAdministrators)
{
    /// <summary>
    /// A refusal: nothing was removed, nobody is revoked, and the only fields that carry anything are the
    /// reason and the count that refused. Named rather than written out at each arm, so a new refusal
    /// cannot accidentally report links removed.
    /// </summary>
    /// <param name="result">Why the run refused.</param>
    /// <param name="actualLinkCount">How many links the provider actually holds.</param>
    /// <returns>The refusal outcome.</returns>
    internal static ProviderLinkPurgeOutcome Refusing(ProviderLinkPurgeResult result, int actualLinkCount)
        => new(result, 0, actualLinkCount, Array.Empty<Guid>(), Array.Empty<string>());
}
