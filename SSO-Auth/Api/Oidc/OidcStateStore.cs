// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// The in-flight OpenID authorize-state store: cap-bounded registration at challenge, a non-consuming
/// peek at the callback, an atomic Pending -> Ready promotion once the role gate passes, and a one-time
/// atomic redeem at mint/link. Owns the dictionary, the lifetime, the throttled expired-entry sweep, and
/// the throttled capacity-warning signal (#246, #318, #341).
/// </summary>
internal sealed class OidcStateStore
{
    // An approximate ceiling on outstanding OpenID authorize states, so an anonymous challenge flood
    // cannot grow the store without bound (mirrors SamlRequestCache); at the cap a fresh challenge is
    // refused rather than evicting an in-flight state, and rate-limiting at the edge (#128) is the
    // primary defense (#246).

    /// <summary>The production ceiling on outstanding authorize states; at the cap a fresh challenge is refused, never an in-flight state evicted.</summary>
    internal const int DefaultMaxEntries = 100_000;

    // How long an in-flight OpenID authorize state may live before it is rejected/pruned. This bounds
    // the whole interactive leg (OidChallenge -> IdP login/MFA/consent -> callback -> mint), so it
    // must accommodate a real user completing MFA, not just a fast round trip.

    /// <summary>How long an in-flight authorize state may live before it is rejected and pruned; bounds the whole challenge-to-mint interactive leg (including MFA).</summary>
    internal static readonly TimeSpan DefaultLifetime = TimeSpan.FromMinutes(15);

    // The expired-state sweep (PruneExpired) is an O(n) scan; throttling it to at most once per this
    // interval stops an anonymous challenge flood from amplifying into CPU load (mirrors
    // SamlRequestCache). This only defers memory reclamation - the peek/redeem predicates reject an
    // expired state independently, so a not-yet-swept entry never grants a login (#246).

    /// <summary>The minimum interval between expired-state sweeps, keeping the O(n) scan off the anonymous hot path.</summary>
    internal static readonly TimeSpan DefaultPruneInterval = TimeSpan.FromMinutes(1);

    private readonly int _maxEntries;
    private readonly TimeSpan _lifetime;

    // Concurrent requests add to, enumerate, promote, and prune this map (challenge / auth / link /
    // sweep); a plain Dictionary corrupts or throws under that interleaving. The pending -> ready
    // transition is a single atomic TryUpdate and the redeem a single atomic TryRemove, so a state is
    // promoted and claimed exactly once with no torn read. StringComparer.Ordinal is what the default
    // string comparer already is - stated explicitly so the ordinal token matching is visible.
    private readonly ConcurrentDictionary<string, AuthorizeSession> _states = new(StringComparer.Ordinal);

    // Throttles the sweep to one run per interval; the gate owns the atomic cursor. See PruneExpired.
    private readonly IntervalGate _pruneGate;

    // Throttles the capacity-full warning (#246, CWE-400) to one signal per interval: under a flood
    // every refused challenge would otherwise emit a warning, amplifying the flood into unbounded log
    // volume. The gate self-heals a backward wall-clock step of at least the interval (re-anchors); a
    // sub-interval backward step is a stale sample, suppressed with the cursor untouched (#334) - still
    // without stalling like the hand-rolled predecessor.
    private readonly IntervalGate _capWarnGate;

    // Per-client occupancy sub-cap (#327): bounds how much of the global budget one client key can hold,
    // so a single anonymous source cannot fill the store and lock out everyone else's logins.
    private readonly PerClientBudgetLimiter _perClient;

    /// <summary>
    /// Initializes a new instance of the <see cref="OidcStateStore"/> class with the production cap,
    /// lifetime and prune interval.
    /// </summary>
    internal OidcStateStore()
        : this(DefaultMaxEntries, DefaultLifetime, DefaultPruneInterval)
    {
    }

    // Test constructor: small caps and lifetimes make the cap and expiry paths reachable in unit
    // tests (the production values are unreachable there). IntervalGate rejects a non-positive interval.

    /// <summary>
    /// Initializes a new instance of the <see cref="OidcStateStore"/> class with explicit bounds, so a
    /// unit test can reach the cap and expiry paths that the production values make unreachable.
    /// </summary>
    /// <param name="maxEntries">The global ceiling on outstanding authorize states.</param>
    /// <param name="lifetime">How long a stored state may live before it expires.</param>
    /// <param name="pruneInterval">The minimum interval between expired-state sweeps.</param>
    internal OidcStateStore(int maxEntries, TimeSpan lifetime, TimeSpan pruneInterval)
    {
        _maxEntries = maxEntries;
        _lifetime = lifetime;
        _pruneGate = new IntervalGate(pruneInterval);
        _capWarnGate = new IntervalGate(pruneInterval);
        _perClient = PerClientBudgetLimiter.FromGlobalCap(maxEntries);
    }

    /// <summary>Gets the live entry count. Test-only, like Seed/Clear: production code reads _states.Count directly.</summary>
    internal int Count => _states.Count;

    /// <summary>Registers a fresh challenge's fully-formed <see cref="AuthorizeSession.Pending"/>, keyed by its CSPRNG state token, as a single atomic insert with no later mutation of a stored entry (#341).</summary>
    /// <remarks>
    /// At the cap a new key is refused rather than an in-flight state evicted, which would drop a user mid-login
    /// under a flood. The check-then-insert is not serialized on the anonymous hot path, so concurrent adds can
    /// overshoot by the in-flight thread count; the warning line stays at the controller so the log-forging
    /// sanitizer never crosses a helper boundary: <see href="https://github.com/Flowfin/jellyfin-plugin-sso/wiki/Security-Model#openid-authorize-state"/>.
    /// </remarks>
    /// <param name="pending">The challenge's authorize state; its token keys the entry and its Created drives the throttled warning.</param>
    /// <param name="shouldWarnCapacity">True when the caller should emit the throttled capacity warning, at most one caller per interval.</param>
    /// <returns>True if the state was registered; false if refused by the per-client sub-cap, the global cap, or an existing key.</returns>
    internal bool TryAdd(AuthorizeSession.Pending pending, out bool shouldWarnCapacity)
    {
        // Per-client sub-cap (#327): reserve this client's slot BEFORE the global insert so one source
        // cannot fill the whole budget and lock out every other login. A null key is exempt (the shared
        // proxy/private-source bucket, still bounded by the global cap below).
        if (!_perClient.TryReserve(pending.ClientKey))
        {
            shouldWarnCapacity = _capWarnGate.TryEnter(pending.Created);
            return false;
        }

        if ((_states.Count >= _maxEntries && !_states.ContainsKey(pending.Token))
            || !_states.TryAdd(pending.Token, pending))
        {
            // The entry never entered the store (global cap, or a CSPRNG-token collision losing the
            // atomic add) - release the reservation so the client's bucket does not leak a slot.
            _perClient.Release(pending.ClientKey);
            shouldWarnCapacity = _capWarnGate.TryEnter(pending.Created);
            return false;
        }

        shouldWarnCapacity = false;
        return true;
    }

    /// <summary>The callback's non-consuming check: returns the still-pending state only when it exists, is still a <see cref="AuthorizeSession.Pending"/>, was minted for this provider, is within its lifetime and matches the presented browser binding.</summary>
    /// <remarks>A state issued for one provider cannot be validated on another's callback, and a peek structurally cannot mint a session, because only <see cref="Promote"/> produces the redeemable <see cref="AuthorizeSession.Ready"/> (#318, #341); expiry pruning is the sweep's.</remarks>
    /// <param name="token">The state token the callback presented.</param>
    /// <param name="provider">The provider named in the route of the consuming request.</param>
    /// <param name="now">The current time.</param>
    /// <param name="presentedBindingId">The browser-binding id the callback presented, its cookie value (#326).</param>
    /// <returns>The pending state, or null when unknown, already promoted, expired, provider-mismatched, or binding-mismatched.</returns>
    internal AuthorizeSession.Pending? PeekCurrent(string token, string provider, DateTime now, string? presentedBindingId)
    {
        return !string.IsNullOrEmpty(token)
            && _states.TryGetValue(token, out var session)
            && session is AuthorizeSession.Pending pending
            && IsCurrentFor(session, provider, now)
            && AuthorizeStateBinding.Matches(session.BindingId, presentedBindingId)
            ? pending
            : null;
    }

    /// <summary>Atomically swaps the peeked <see cref="AuthorizeSession.Pending"/> for a <see cref="AuthorizeSession.Ready"/> carrying the role-gate result (#341).</summary>
    /// <remarks>The compare-and-set succeeds only while the stored value is still the exact Pending the callback peeked, so a state is promoted at most once under concurrent callbacks and a redeemer never observes a half-built Ready; false is a no-op when the entry already moved on, and the single Ready is consumed once at redeem.</remarks>
    /// <param name="pending">The Pending the callback peeked; the compare-and-set comparand.</param>
    /// <param name="derived">The passed role-gate result to snapshot into the Ready.</param>
    /// <returns>True if this call performed the promotion; false if the entry had already moved on.</returns>
    internal bool Promote(AuthorizeSession.Pending pending, OidcAuthorizeStateBuilder.OidcAuthorizeState derived)
    {
        return _states.TryUpdate(pending.Token, new AuthorizeSession.Ready(pending, derived), pending);
    }

    /// <summary>The one-time atomic claim: the store is keyed by the authorize-state token the caller presents, so only the request that wins the removal proceeds and one state mints at most one session.</summary>
    /// <remarks>Redeemable only once it is a <see cref="AuthorizeSession.Ready"/>, the role gate having passed through <see cref="Promote"/>; a still-pending or already-claimed state returns null (#318, #341).</remarks>
    /// <param name="responseData">The authorization-response value the caller presented.</param>
    /// <param name="provider">The provider named in the route of the consuming request.</param>
    /// <param name="now">The current time.</param>
    /// <param name="presentedBindingId">The browser-binding id the caller presented, its cookie value (#326).</param>
    /// <returns>The redeemed snapshot, or null when not redeemable, already claimed, or binding-mismatched.</returns>
    internal AuthorizeSession.Ready? TryRedeem(string responseData, string provider, DateTime now, string? presentedBindingId)
    {
        if (string.IsNullOrEmpty(responseData)
            || !_states.TryGetValue(responseData, out var session)
            || !IsRedeemableBy(session, responseData, provider, now)
            || !AuthorizeStateBinding.Matches(session.BindingId, presentedBindingId)
            || !_states.TryRemove(new KeyValuePair<string, AuthorizeSession>(responseData, session)))
        {
            return null;
        }

        // Only the winner of the atomic TryRemove reaches here, so the client's slot is released exactly
        // once (#327). IsRedeemableBy already proved the value is a Ready.
        _perClient.Release(session.ClientKey);
        return (AuthorizeSession.Ready)session;
    }

    /// <summary>
    /// Removes every authorize state whose lifetime has elapsed, at most once per prune interval so an
    /// anonymous challenge flood does not amplify the O(n) scan into CPU load; the gate lets exactly
    /// one caller per interval run it (#246). Safe concurrently with additions, promotions, and removals
    /// because it operates on a <see cref="ConcurrentDictionary{TKey,TValue}"/>.
    /// </summary>
    /// <param name="now">The reference time driving both the gate and the expiry evaluation.</param>
    internal void PruneExpired(DateTime now)
    {
        if (!_pruneGate.TryEnter(now))
        {
            return;
        }

        // Strict '>' so an entry exactly at lifetime is kept, matching the <= acceptance in the
        // predicates. Deliberately no negative-age guard here: a future-Created entry (backward clock
        // step) is dead weight the predicates already reject; it is swept once the clock passes it.
        foreach (var kvp in _states.Where(kvp => now.Subtract(kvp.Value.Created) > _lifetime))
        {
            // Release only on the winning removal so a concurrent redeem does not double-release the
            // client's slot (#327).
            if (_states.TryRemove(kvp.Key, out var removed))
            {
                _perClient.Release(removed.ClientKey);
            }
        }
    }

    /// <summary>
    /// Projects the store to non-secret summaries for the admin debug endpoint. The raw store holds
    /// the authorize-state token and the PKCE code_verifier; those must never be serialized
    /// out, even to an admin. It holds no nonce, and said so here until #1157 measured it: the code flow
    /// this plugin drives sends none, and a sentence claiming a stored secret that does not exist is the
    /// kind a later reader builds a validation rule on top of. "Valid" is now which variant the entry is: a promoted
    /// <see cref="AuthorizeSession.Ready"/> is valid, a <see cref="AuthorizeSession.Pending"/> is not.
    /// </summary>
    /// <returns>One summary per in-flight state.</returns>
    internal IEnumerable<Summary> Summaries() =>
        _states.Values.Select(s => new Summary(s.Provider, s.Created, s is AuthorizeSession.Ready, s.IsLinking));

    /// <summary>Test-only: drops every entry, restoring a fresh store between tests.</summary>
    internal void Clear()
    {
        _states.Clear();
        _perClient.Clear();
    }

    /// <summary>Test-only: seeds one entry directly, bypassing the challenge leg.</summary>
    /// <param name="token">The state token to key the entry under.</param>
    /// <param name="session">The entry to store (a Pending or a promoted Ready).</param>
    internal void Seed(string token, AuthorizeSession session) => _states[token] = session;

    // Whether a stored state still belongs to the given provider and has not expired. Used at the
    // OpenID callback before a state is validated: a state minted for one provider must not be
    // accepted on another provider's callback, and a state older than its lifetime is not honored.
    private bool IsCurrentFor(AuthorizeSession session, string provider, DateTime now)
    {
        if (session == null || !string.Equals(session.Provider, provider, StringComparison.Ordinal))
        {
            return false;
        }

        // Reject a negative age (Created in the future, e.g. a backward clock step) as well as an
        // over-lifetime one, so a clock anomaly cannot make a state effectively never expire.
        var age = now.Subtract(session.Created);
        return age >= TimeSpan.Zero && age <= _lifetime;
    }

    // Whether a stored state may be redeemed to mint a session or create a link: it must be a promoted
    // Ready (the role gate passed), its token must match the presented response value, and it must still
    // belong to the route provider and be unexpired. The provider check is the state-scoping guard:
    // without it, a state validated at a low-trust provider could be replayed against a higher-trust
    // provider's endpoint, bypassing that provider's login/role gate (cross-provider state replay).
    private bool IsRedeemableBy(AuthorizeSession session, string responseData, string provider, DateTime now)
    {
        return session is AuthorizeSession.Ready
            && string.Equals(session.Token, responseData, StringComparison.Ordinal)
            && IsCurrentFor(session, provider, now);
    }

    /// <summary>
    /// A non-secret projection of one in-flight state for the admin debug endpoint (property names
    /// and order match the anonymous type it replaces).
    /// </summary>
    /// <param name="Provider">The provider the state was minted for.</param>
    /// <param name="Created">When the state was created.</param>
    /// <param name="Valid">Whether the login has been verified (the entry is a promoted Ready).</param>
    /// <param name="IsLinking">Whether the flow is a linking request.</param>
    internal readonly record struct Summary(string Provider, DateTime Created, bool Valid, bool IsLinking);
}
