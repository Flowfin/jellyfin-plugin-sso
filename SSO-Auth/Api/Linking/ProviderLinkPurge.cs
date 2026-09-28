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

/// <summary>What the tree can read about one account's ways in, resolved through the user manager outside the configuration lock and judged inside it (#1519).</summary>
/// <remarks>A password door is <c>RoutesToPasswordProvider</c> and <c>HoldsAPasswordSomebodySet</c> together, never one alone: an account on a third-party provider can hold a password that reaches no Jellyfin login form, and an account on the built-in provider can hold only a seal this plugin minted. They are reported apart because only the purge can apply the mode-dependent half.</remarks>
/// <param name="UserId">The account.</param>
/// <param name="Username">The account's own username, the basis the break-glass exemption is judged on.</param>
/// <param name="IsAdministrator">Whether the account holds the administrator permission.</param>
/// <param name="IsDisabled">Whether the account is disabled, and so already has no way in for this run to take.</param>
/// <param name="RoutesToPasswordProvider">Whether the account's authentication provider is Jellyfin's built-in password provider.</param>
/// <param name="HoldsAPasswordSomebodySet">Whether the account carries a non-empty stored password that is not one this plugin minted (#1746); pair it with <paramref name="RoutesToPasswordProvider"/>.</param>
internal readonly record struct AccountDoors(
    Guid UserId,
    string Username,
    bool IsAdministrator,
    bool IsDisabled,
    bool RoutesToPasswordProvider,
    bool HoldsAPasswordSomebodySet);

/// <summary>What one provider's link table looks like to the bulk unlink before it acts (#1519): whether the provider is stored, how many links it holds, and which accounts hold them.</summary>
/// <remarks>A detached snapshot taken under the configuration lock without a write, so the accounts can be resolved through the user manager with the lock released and the two routine refusals a stale page produces are answered without entering a mutation, which would persist the file even when nothing changed.</remarks>
/// <param name="ProviderExists">Whether a provider of that mode and name is stored.</param>
/// <param name="LinkCount">How many links it holds.</param>
/// <param name="LinkedUsers">The distinct accounts holding those links, to be judged before the purge runs.</param>
internal readonly record struct ProviderLinkSurvey(bool ProviderExists, int LinkCount, IReadOnlyList<Guid> LinkedUsers);

/// <summary>What one walk of every provider other than the one being emptied says about the accounts it holds (#1519), plus whether the target itself is enabled.</summary>
/// <remarks>Two sets, because a disabled provider reads oppositely for the two questions: who is left holding no link at all is signed out, and who is left holding no link a login could resolve would be stranded. Built once, inside the configuration lock every login takes.</remarks>
/// <param name="Any">Accounts holding a link on some other provider, enabled or not.</param>
/// <param name="OnAnEnabledProvider">Accounts holding a link on some other enabled provider, which is what a login can resolve.</param>
/// <param name="TargetEnabled">Whether the provider being emptied is itself enabled, so its links were a way in before the run.</param>
internal readonly record struct LinksElsewhere(HashSet<Guid> Any, HashSet<Guid> OnAnEnabledProvider, bool TargetEnabled);

/// <summary>The outcome of a per-provider bulk unlink (#1519), with everything the controller needs to answer, audit and revoke; every field except <see cref="Result"/> is meaningful only on the arm that produced it.</summary>
/// <param name="Result">What happened.</param>
/// <param name="RemovedLinks">How many links were removed; zero on every refusal.</param>
/// <param name="ActualLinkCount">How many links the provider actually held, so a count mismatch can say what the real number is.</param>
/// <param name="RevokedUserIds">The accounts whose last canonical link this run removed, whose live tokens the controller revokes (#468); empty on every refusal.</param>
/// <param name="StrandedAdministrators">The administrator accounts whose last way in the run would have taken; empty on every other arm.</param>
/// <param name="TargetWasEnabled">Whether the emptied provider was enabled, so its links were a way in; false means the run took nothing from anybody, so neither the guard nor the after-the-fact check may report a lockout.</param>
internal readonly record struct ProviderLinkPurgeOutcome(
    ProviderLinkPurgeResult Result,
    int RemovedLinks,
    int ActualLinkCount,
    IReadOnlyList<Guid> RevokedUserIds,
    IReadOnlyList<string> StrandedAdministrators,
    bool TargetWasEnabled = false)
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
        => new(result, 0, actualLinkCount, Array.Empty<Guid>(), Array.Empty<string>(), TargetWasEnabled: false);
}
