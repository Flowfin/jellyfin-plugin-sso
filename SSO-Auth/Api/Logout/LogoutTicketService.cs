// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.SSO_Auth.Api.Logout;

/// <summary>
/// Mints and redeems the one-time logout tickets the RP-initiated OpenID logout route accepts in place of a
/// session (#1768). It owns the process-wide <see cref="LogoutTicketStore"/> as its own static, the way the
/// login flows own the authorize-state and outcome stores, so the controller keeps no mutable static state
/// of its own; it is constructed per request like the other collaborators.
/// </summary>
/// <remarks>
/// The whole of the policy is here rather than at the endpoint, so the mint and the redeem cannot drift
/// apart: a mint refuses an unauthenticated or session-less caller and fails closed at the cap, and a redeem
/// is one-time, provider-scoped and time-bounded. What the endpoint decides is what to DO with the answer.
/// </remarks>
internal sealed class LogoutTicketService
{
    // Process-wide, like OidcLoginService's authorize-state store and SamlLoginService's outcome store. A
    // per-request instance would make every ticket unredeemable, since the navigation that spends one
    // arrives as a second request.
    private static readonly LogoutTicketStore Tickets = new();

    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="LogoutTicketService"/> class.
    /// </summary>
    /// <param name="logger">The logger a refused mint is recorded on.</param>
    internal LogoutTicketService(ILogger logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Mints a ticket bound to one caller's user, session and provider, or returns null when it cannot,
    /// saying in <paramref name="outcome"/> which class of answer that was.
    /// </summary>
    /// <remarks>
    /// THE CLASS IS REPORTED BECAUSE THE FOUR REFUSALS ARE NOT ONE EVENT (#1796). Three of them are
    /// permanent for the request that met them - a caller with no user, no access token or no provider name
    /// retries into exactly the same refusal - and only the capacity bound clears on its own. The route
    /// answered all four with the status that means "try again later", so the one caller who could never
    /// succeed was the one being told to keep asking, at an endpoint that is deliberately unthrottled. The
    /// policy stays here and the route maps the class onto a status.
    /// </remarks>
    /// <param name="userId">The authenticated caller's user id. <see cref="Guid.Empty"/> is refused: it is what an unauthenticated request resolves to, and a ticket carrying it would name no user.</param>
    /// <param name="provider">The provider the ticket may be spent at, and at no other.</param>
    /// <param name="sessionToken">The caller's own access token, so the redeem ends that session. An empty token is refused rather than minting a ticket that could end nothing.</param>
    /// <param name="nowUtc">The current UTC time (supplied so the lifetime is deterministic in tests).</param>
    /// <param name="outcome">Which class of answer this was; <see cref="MintOutcome.Issued"/> exactly when a token is returned.</param>
    /// <returns>The ticket token to hand the caller, or null when the mint was refused.</returns>
    internal string? Mint(Guid userId, string provider, string? sessionToken, DateTime nowUtc, out MintOutcome outcome)
    {
        // Fail closed on both halves of "the caller". Guid.Empty is what an unauthenticated request resolves
        // to, and an empty access token is a caller whose session the redeem could not end - a ticket for
        // either would be a ticket that authorises something nobody asked for.
        //
        // SEPARATED RATHER THAN COMBINED, because the answer differs. They are still all refusals and the
        // order between them is not load-bearing: no caller can be short of two of the three and get a
        // better status for it, since every arm here returns null.
        if (userId == Guid.Empty)
        {
            outcome = MintOutcome.NoCaller;
            return null;
        }

        if (string.IsNullOrEmpty(sessionToken))
        {
            outcome = MintOutcome.NoSession;
            return null;
        }

        if (string.IsNullOrEmpty(provider))
        {
            outcome = MintOutcome.NoProvider;
            return null;
        }

        // Swept here rather than on a timer: minting is the only thing that grows this store, so the scan
        // runs exactly where it is owed and the IntervalGate keeps it off the busy path.
        Tickets.PruneExpired(nowUtc);

        var ticket = new LogoutTicket(LogoutTicketStore.NewToken(), provider, userId, sessionToken, nowUtc);
        if (Tickets.TryAdd(ticket, out var refusal))
        {
            outcome = MintOutcome.Issued;
            return ticket.Token;
        }

        // BOTH capacity refusals are one class to the caller, and that is deliberate rather than a loss of
        // detail. Which bound was met changes what an OPERATOR does, which is why the two log lines below
        // stay apart; it changes nothing a caller can act on, and telling one signed-in account that the
        // whole store is full would answer a question about every other account's occupancy.
        outcome = MintOutcome.AtCapacity;

        // TWO SENTENCES, BECAUSE THE TWO REFUSALS ARE DIFFERENT EVENTS. One account holding its whole share
        // is routine and affects that account; a full store affects everybody and is the one an operator
        // acts on. A single sentence asserting the store was full said the wrong thing for the common case
        // and, through a shared throttle, said nothing at all for the serious one.
        //
        // Neither line carries anything provider-authored or caller-authored: no provider, no user, no
        // token. The account line names no account on purpose - what an operator does about it is the same
        // whoever it was, and naming one would put an identifier in a log for no act. The throttle is the
        // store's, one per bound.
        switch (refusal)
        {
            case MintRefusal.AccountShare:
                _logger.LogWarning("Refusing to mint a single sign-on logout ticket: one account already holds its whole share of the ticket store. Other accounts are unaffected, and signing out of Jellyfin still ends that session.");
                break;
            case MintRefusal.Store:
                _logger.LogWarning("Refusing to mint a single sign-on logout ticket: the ticket store is full, so no account can be issued one right now. Signing out of Jellyfin still ends the local session.");
                break;
            default:
                // AccountShareQuiet, StoreQuiet: the same fact with this interval's line already written.
                break;
        }

        return null;
    }

    /// <summary>
    /// Spends a ticket, once. An unknown, expired, already-spent or provider-mismatched token yields null,
    /// and the route then requires a session as it always did.
    /// </summary>
    /// <param name="token">The ticket token presented on the request.</param>
    /// <param name="provider">The provider named in the request's route.</param>
    /// <param name="nowUtc">The current UTC time.</param>
    /// <returns>The redeemed ticket, or null when it was not redeemable.</returns>
    internal LogoutTicket? Redeem(string? token, string provider, DateTime nowUtc) =>
        string.IsNullOrEmpty(provider) ? null : Tickets.TryRedeem(token, provider, nowUtc);

    /// <summary>
    /// Test-only: empties the process-wide store so one test's tickets cannot be seen by the next. A test
    /// calling this belongs in the <c>SSOController</c> collection, because the state it resets is shared
    /// across the whole assembly.
    /// </summary>
    internal static void ResetForTests() => Tickets.Clear();

    /// <summary>Test-only: seeds a ticket straight into the process-wide store, bypassing the mint endpoint.</summary>
    /// <param name="ticket">The ticket to store under its own token.</param>
    internal static void SeedForTests(LogoutTicket ticket) => Tickets.Seed(ticket);
}
