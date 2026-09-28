// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Jellyfin.Plugin.SSO_Auth.Api.Identity;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;

namespace Jellyfin.Plugin.SSO_Auth.Api.Saml;

/// <summary>The in-flight SAML login-outcome store (#251): the callback validates the signed assertion once, stores the outcome under a fresh CSPRNG token, and hands the intermediate page only that token.</summary>
/// <remarks>
/// The same-origin mint leg redeems the token once and completes the login from the stored outcome, so the
/// signed XML no longer round-trips through the browser and is never parsed a second time. It is the SAML
/// analogue of the OpenID authorize-state redeem: cap-bounded registration, an atomic one-time claim and a
/// throttled sweep. A single stored variant rather than the OpenID two-phase swap, because a SAML login is
/// fully verified at the callback, so holding an outcome is proof the assertion passed every gate.
/// </remarks>
internal sealed class SamlOutcomeStore
{
    // An approximate ceiling on outstanding login outcomes, so a flood of validated callbacks cannot grow
    // the store without bound (mirrors OidcStateStore / SamlRequestCache). At the cap a fresh outcome is
    // refused rather than evicting an in-flight one; the callback path is reached only after full signature
    // validation, so it is not anonymously floodable, and rate-limiting at the edge (#128) is the primary
    // defense.

    /// <summary>The production ceiling on outstanding login outcomes; at the cap a fresh outcome is refused, never an in-flight one evicted.</summary>
    internal const int DefaultMaxEntries = 100_000;

    // How long a stored login outcome may live before it is rejected/pruned. It bounds the gap between the
    // ACS callback rendering the page and the browser posting the token back - a fast same-origin round
    // trip - so it matches the sibling in-flight lifetimes (the outstanding-request/authorize-state window).

    /// <summary>How long a stored outcome may live before it is rejected and pruned; bounds the ACS-render-to-mint round trip.</summary>
    internal static readonly TimeSpan DefaultLifetime = TimeSpan.FromMinutes(15);

    // The expired-entry sweep is an O(n) scan; throttling it to at most once per this interval keeps it off
    // the hot path (mirrors the siblings). Throttling only defers memory reclamation - the redeem predicate
    // rejects an expired outcome independently, so a not-yet-swept entry never completes a login.

    /// <summary>The minimum interval between expired-entry sweeps, keeping the O(n) scan off the hot path.</summary>
    internal static readonly TimeSpan DefaultPruneInterval = TimeSpan.FromMinutes(1);

    private readonly int _maxEntries;
    private readonly TimeSpan _lifetime;

    // Concurrent requests add to, redeem from, and prune this map; a plain Dictionary corrupts or throws
    // under that interleaving. The redeem is a single atomic TryRemove, so one outcome completes at most one
    // login even under concurrent posts. Ordinal matches the CSPRNG token's exact-byte comparison.
    private readonly ConcurrentDictionary<string, SamlLoginOutcome> _outcomes = new(StringComparer.Ordinal);

    // Throttles the sweep to one run per interval; the gate owns the atomic cursor. See PruneExpired.
    private readonly IntervalGate _pruneGate;

    // Throttles the capacity-full warning (CWE-400) to one signal per interval, so a flood of refused
    // registrations cannot amplify into unbounded log volume (parity with the siblings).
    private readonly IntervalGate _capWarnGate;

    // Per-client occupancy sub-cap (#327): bounds how much of the global budget one client key can hold, so
    // a single source cannot fill the store and lock out everyone else's logins.
    private readonly PerClientBudgetLimiter _perClient;

    /// <summary>
    /// Initializes a new instance of the <see cref="SamlOutcomeStore"/> class with the production cap,
    /// lifetime and prune interval.
    /// </summary>
    internal SamlOutcomeStore()
        : this(DefaultMaxEntries, DefaultLifetime, DefaultPruneInterval)
    {
    }

    // Test constructor: small caps and lifetimes make the cap and expiry paths reachable in unit tests (the
    // production values are unreachable there). IntervalGate rejects a non-positive interval.

    /// <summary>
    /// Initializes a new instance of the <see cref="SamlOutcomeStore"/> class with explicit bounds, so a
    /// unit test can reach the cap and expiry paths that the production values make unreachable.
    /// </summary>
    /// <param name="maxEntries">The global ceiling on outstanding outcomes.</param>
    /// <param name="lifetime">How long a stored outcome may live before it expires.</param>
    /// <param name="pruneInterval">The minimum interval between expired-entry sweeps.</param>
    internal SamlOutcomeStore(int maxEntries, TimeSpan lifetime, TimeSpan pruneInterval)
    {
        _maxEntries = maxEntries;
        _lifetime = lifetime;
        _pruneGate = new IntervalGate(pruneInterval);
        _capWarnGate = new IntervalGate(pruneInterval);
        _perClient = PerClientBudgetLimiter.FromGlobalCap(maxEntries);
    }

    /// <summary>Gets the live entry count. Test-only, like Clear.</summary>
    internal int Count => _outcomes.Count;

    /// <summary>
    /// A fresh 256-bit CSPRNG token, hex-encoded. A token that misses the store falls through to the
    /// deprecation branch's assertion validation, which fails closed regardless: the hex string may be
    /// Base64-decodable, but its decoded bytes are not a SAML response, so the XML parse rejects it.
    /// </summary>
    /// <returns>The new one-time outcome token.</returns>
    internal static string NewToken() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    /// <summary>Reserves capacity for one outcome before its caller consumes the one-time replay cache, so an at-cap refusal fails closed without the assertion having been burned (#539).</summary>
    /// <remarks>
    /// It reserves the per-client sub-cap (#327), checks the global cap, and on a true return the caller
    /// pairs it with one <see cref="CommitReserved"/> or <see cref="ReleaseReservation"/>. At the cap a
    /// reservation is refused rather than evicting an outcome, which would drop a user mid-login.
    /// </remarks>
    /// <param name="clientKey">The normalized client key whose sub-cap slot is reserved, or null for an exempt source.</param>
    /// <param name="now">The reference time driving the throttled capacity warning.</param>
    /// <param name="shouldWarnCapacity">True when the caller should emit the throttled capacity warning.</param>
    /// <returns>True if a slot was reserved; false if refused by the sub-cap or the global cap.</returns>
    internal bool TryReserve(string? clientKey, DateTime now, out bool shouldWarnCapacity)
    {
        // Per-client sub-cap (#327): reserve this client's slot BEFORE the global check so one source cannot
        // fill the whole budget and lock out every other login. A null key is exempt.
        if (!_perClient.TryReserve(clientKey))
        {
            shouldWarnCapacity = _capWarnGate.TryEnter(now);
            return false;
        }

        // Global cap: at capacity a reservation is refused rather than an in-flight outcome evicted. It is an
        // approximate ceiling, because between this check and the paired commit a concurrent commit can
        // overshoot by the in-flight thread count; the per-client cap, the availability defence, stays exact.
        if (_outcomes.Count >= _maxEntries)
        {
            _perClient.Release(clientKey);
            shouldWarnCapacity = _capWarnGate.TryEnter(now);
            return false;
        }

        shouldWarnCapacity = false;
        return true;
    }

    /// <summary>
    /// Commits a reserved outcome into the store under its token. Reachable only after a successful
    /// <see cref="TryReserve"/> for the same client key, so the capacity is already accounted; this can fail
    /// only on the effectively-impossible CSPRNG-token collision losing the atomic add, in which case the
    /// caller releases the reservation and fails closed.
    /// </summary>
    /// <param name="outcome">The verified outcome whose token keys the entry.</param>
    /// <returns>True if the outcome was stored; false on the ~impossible token collision.</returns>
    internal bool CommitReserved(SamlLoginOutcome outcome) => _outcomes.TryAdd(outcome.Token, outcome);

    /// <summary>
    /// Releases a reservation taken by <see cref="TryReserve"/> that is not being committed - a replayed or
    /// otherwise invalid assertion, an assertion with no NameID, or the ~impossible token collision - so the
    /// client's sub-cap slot does not leak. A null/exempt key reserved nothing, so it releases nothing.
    /// </summary>
    /// <param name="clientKey">The client key whose reserved slot is freed, or null (a no-op).</param>
    internal void ReleaseReservation(string? clientKey) => _perClient.Release(clientKey);

    /// <summary>
    /// Registers a fully-verified login outcome under its CSPRNG token in one atomic step - a convenience for
    /// callers that need no work between the capacity reservation and the store insert; the ACS callback uses
    /// the <see cref="TryReserve"/>/<see cref="CommitReserved"/> primitives directly so it can consume the
    /// one-time replay cache between them (#539). At the cap a NEW token is refused (that one login fails
    /// closed) rather than evicting an in-flight outcome.
    /// </summary>
    /// <param name="outcome">The verified outcome; its token keys the entry and its Created drives the throttled warning.</param>
    /// <param name="shouldWarnCapacity">True when the caller should emit the throttled capacity warning.</param>
    /// <returns>True if the outcome was registered; false if refused (per-client sub-cap, global cap, or token collision).</returns>
    internal bool TryAdd(SamlLoginOutcome outcome, out bool shouldWarnCapacity)
    {
        if (!TryReserve(outcome.ClientKey, outcome.Created, out shouldWarnCapacity))
        {
            return false;
        }

        if (!CommitReserved(outcome))
        {
            // The entry never entered the store (a CSPRNG-token collision losing the atomic add) - release the
            // reservation so the client's bucket does not leak a slot, and warn as for any other refusal.
            ReleaseReservation(outcome.ClientKey);
            shouldWarnCapacity = _capWarnGate.TryEnter(outcome.Created);
            return false;
        }

        return true;
    }

    /// <summary>The one-time atomic claim: the store is keyed by the outcome token the mint leg presents, so only the request that wins the removal proceeds and one outcome completes at most one login.</summary>
    /// <remarks>An outcome is redeemable only while it still belongs to the route provider, so a token cannot be replayed against another provider endpoint, and only within its lifetime; anything else returns null.</remarks>
    /// <param name="token">The outcome token the mint leg presented.</param>
    /// <param name="provider">The provider named in the route of the consuming request.</param>
    /// <param name="now">The current time.</param>
    /// <returns>The redeemed outcome, or null when not redeemable.</returns>
    internal SamlLoginOutcome? TryRedeem(string? token, string provider, DateTime now)
    {
        if (string.IsNullOrEmpty(token)
            || !_outcomes.TryGetValue(token, out var outcome)
            || !IsCurrentFor(outcome, provider, now)
            || !_outcomes.TryRemove(new KeyValuePair<string, SamlLoginOutcome>(token, outcome)))
        {
            return null;
        }

        // Only the winner of the atomic TryRemove reaches here, so the client's slot is released exactly once.
        _perClient.Release(outcome.ClientKey);
        return outcome;
    }

    /// <summary>
    /// Removes every outcome whose lifetime has elapsed, at most once per prune interval so a flood does not
    /// amplify the O(n) scan into CPU load. Safe concurrently with additions and redeems because it operates
    /// on a <see cref="ConcurrentDictionary{TKey,TValue}"/>.
    /// </summary>
    /// <param name="now">The reference time driving both the gate and the expiry evaluation.</param>
    internal void PruneExpired(DateTime now)
    {
        if (!_pruneGate.TryEnter(now))
        {
            return;
        }

        foreach (var kvp in _outcomes.Where(kvp => now.Subtract(kvp.Value.Created) > _lifetime))
        {
            // Release only on the winning removal so a concurrent redeem does not double-release the slot.
            if (_outcomes.TryRemove(kvp.Key, out var removed))
            {
                _perClient.Release(removed.ClientKey);
            }
        }
    }

    /// <summary>Test-only: drops every entry, restoring a fresh store between tests.</summary>
    internal void Clear()
    {
        _outcomes.Clear();
        _perClient.Clear();
    }

    /// <summary>Test-only: seeds one outcome directly, bypassing the callback leg.</summary>
    /// <param name="outcome">The outcome to store under its own token.</param>
    internal void Seed(SamlLoginOutcome outcome) => _outcomes[outcome.Token] = outcome;

    // Whether a stored outcome still belongs to the route provider and has not expired. The provider check
    // is the token-scoping guard: without it, an outcome verified at a low-trust provider could be replayed
    // against a higher-trust provider's mint endpoint. A negative age (Created in the future, e.g. a
    // backward clock step) is rejected too, so a clock anomaly cannot make an outcome effectively never
    // expire.
    private bool IsCurrentFor(SamlLoginOutcome outcome, string provider, DateTime now)
    {
        if (!string.Equals(outcome.Provider, provider, StringComparison.Ordinal))
        {
            return false;
        }

        var age = now.Subtract(outcome.Created);
        return age >= TimeSpan.Zero && age <= _lifetime;
    }
}

/// <summary>One fully verified SAML login, held server-side between the assertion-consumer callback that builds it and the same-origin mint leg that redeems it once; immutable, so a redeemer never observes a torn outcome.</summary>
/// <param name="Token">The CSPRNG token keying the entry, the only value that crosses to the browser.</param>
/// <param name="Provider">The provider that verified the login; a token is redeemable only on its own provider endpoint.</param>
/// <param name="Identity">The verified identity and privileges the mint path is keyed on (#473).</param>
/// <param name="InResponseTo">The assertion InResponseTo, empty for an unsolicited response, correlated and browser-bound at the mint leg (#415).</param>
/// <param name="SessionIndex">The first AuthnStatement SessionIndex (#727), or null when absent; a later Single Logout request resolves the session by it.</param>
/// <param name="ClientKey">The normalized client key that reserved the per-client budget slot (#327), or null for an exempt source.</param>
/// <param name="Created">When the outcome was created, used to time it out.</param>
internal sealed record SamlLoginOutcome(
    string Token,
    string Provider,
    VerifiedIdentity Identity,
    string InResponseTo,
    string? SessionIndex,
    string? ClientKey,
    DateTime Created);
