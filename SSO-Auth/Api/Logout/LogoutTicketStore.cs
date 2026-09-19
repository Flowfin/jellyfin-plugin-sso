// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;

namespace Jellyfin.Plugin.SSO_Auth.Api.Logout;

/// <summary>
/// The in-flight one-time logout-ticket store (#1768). The RP-initiated logout route has to send the
/// browser on to the identity provider, so it is a top-level navigation, and a navigation carries no
/// Authorization header. Until this existed the only way to reach the route from a client was to put the
/// caller's own access token in the query string, which is a long-lived credential in a URL that lands in
/// history, in a referrer and in every proxy log on the way. A ticket stands in for it: an authenticated
/// call mints one, it is bound to the caller's user, session and provider, it lives for a minute, and the
/// route accepts it exactly once.
/// <para>
/// The same shape as <see cref="Jellyfin.Plugin.SSO_Auth.Api.Saml.SamlOutcomeStore"/> and
/// <see cref="Jellyfin.Plugin.SSO_Auth.Api.Oidc.OidcStateStore"/>: cap-bounded registration, an atomic
/// one-time claim, an <see cref="IntervalGate"/>-throttled expired-entry sweep, and a provider scope that
/// stops a ticket minted for one provider being spent at another's endpoint.
/// </para>
/// </summary>
/// <remarks>
/// IN MEMORY AND NEVER IN THE CONFIGURATION, which is the one place this differs from the Single Logout
/// state beside it. <see cref="SessionLogoutStore"/> persists, because an id_token has to survive a restart
/// to be usable as an <c>id_token_hint</c> later. A ticket has a one-minute life and carries a live session
/// token, so writing it to the plugin configuration would put a bearer credential on disk to buy nothing: a
/// ticket that outlived a restart would be expired before the server finished starting.
/// </remarks>
internal sealed class LogoutTicketStore
{
    // An approximate ceiling on outstanding tickets. Far below the login stores' 100_000 because minting is
    // AUTHENTICATED and the lifetime is a minute. WHAT REACHING IT ACTUALLY TAKES is worth stating exactly,
    // because an earlier sentence here said "tens of thousands of signed-in users" and that is out by the
    // share divisor: the per-account sub-cap is a hundredth of this number, so a hundred accounts holding
    // their full share fill the store, and the mint is deliberately unthrottled. That is the bound to argue
    // with - not the ten thousand - and what it costs when it is reached is the ticket form of sign-out for
    // everybody until the next sweep, while the local Jellyfin sign-out is untouched.
    // At the cap a fresh ticket is refused rather than an outstanding one evicted - evicting would break a
    // sign-out already in flight, and a refused mint degrades to the local sign-out the client already has.

    /// <summary>The production ceiling on outstanding tickets; at the cap a fresh ticket is refused, never an outstanding one evicted.</summary>
    internal const int DefaultMaxEntries = 10_000;

    // How long a ticket may live before it is rejected and pruned. One minute, which is the window the
    // decision on #1768 names: it bounds the gap between the page minting the ticket and the browser
    // navigating with it, a same-origin round trip plus a click, and nothing else. It is deliberately far
    // shorter than the login stores' fifteen minutes, which have to accommodate a user completing MFA at
    // the identity provider; nothing interactive happens between a mint and a redeem.

    /// <summary>How long a ticket may live before it is rejected and pruned; bounds the mint-to-navigate round trip.</summary>
    internal static readonly TimeSpan DefaultLifetime = TimeSpan.FromMinutes(1);

    // The expired-entry sweep is an O(n) scan; throttling it to at most once per this interval keeps it off
    // the request path (mirrors the siblings). WHAT THROTTLING DEFERS IS MEMORY AND THE ACCOUNT'S SLOT, AND
    // THIS COMMENT CLAIMED IT WAS MEMORY ALONE. Correctness is unaffected either way: the redeem predicate
    // rejects an expired ticket independently, so a not-yet-swept entry never completes a logout. But the
    // sweep is the ONLY release of the per-account reservation an expired-unredeemed entry holds - the
    // redeem path cannot reach one, because IsCurrentFor refuses it before the removal that releases - so
    // between two sweeps a dead ticket still occupies its account's share. Measured on a store with a
    // ten-per-account share: ten expired, unredeemable tickets refused that account a fresh mint until the
    // gate reopened. The bound is one prune interval, the cost is one account's ticket mint refused, and
    // the local Jellyfin sign-out is untouched. The sibling stores have the same shape; what differed here
    // is that this comment asserted the opposite.

    /// <summary>The minimum interval between expired-entry sweeps, keeping the O(n) scan off the request path.</summary>
    internal static readonly TimeSpan DefaultPruneInterval = TimeSpan.FromMinutes(1);

    private readonly int _maxEntries;
    private readonly TimeSpan _lifetime;

    // Concurrent requests add to, redeem from and prune this map; a plain Dictionary corrupts or throws
    // under that interleaving. The redeem is a single atomic TryRemove, so one ticket ends at most one
    // session even if a browser fires the navigation twice. Ordinal matches the CSPRNG token's exact-byte
    // comparison.
    private readonly ConcurrentDictionary<string, LogoutTicket> _tickets = new(StringComparer.Ordinal);

    // Throttles the sweep to one run per interval; the gate owns the atomic cursor. See PruneExpired.
    private readonly IntervalGate _pruneGate;

    // Throttles each capacity warning (CWE-400) to one signal per interval, so a run of refused mints cannot
    // amplify into unbounded log volume (parity with the siblings). TWO gates rather than one, because the
    // two refusals are different events and a shared gate lets the routine one silence the serious one -
    // see TryAdd, where the reading that forced the split is written down.
    private readonly IntervalGate _accountWarnGate;
    private readonly IntervalGate _globalWarnGate;

    // Per-user occupancy sub-cap (#327's shape, keyed on the user rather than on a network source): bounds
    // how much of the global budget one account can hold, so a single signed-in user holding the sign-out
    // button down cannot fill the store and refuse everybody else's. The key is a user id because minting
    // is authenticated - there is no anonymous source to bound here, and the account IS the source.
    private readonly PerClientBudgetLimiter _perUser;

    /// <summary>
    /// Initializes a new instance of the <see cref="LogoutTicketStore"/> class with the production cap,
    /// lifetime and prune interval.
    /// </summary>
    internal LogoutTicketStore()
        : this(DefaultMaxEntries, DefaultLifetime, DefaultPruneInterval)
    {
    }

    // Test constructor: small caps and lifetimes make the cap and expiry paths reachable in unit tests (the
    // production values are unreachable there). IntervalGate rejects a non-positive interval.

    /// <summary>
    /// Initializes a new instance of the <see cref="LogoutTicketStore"/> class with explicit bounds, so a
    /// unit test can reach the cap and expiry paths that the production values make unreachable.
    /// </summary>
    /// <param name="maxEntries">The global ceiling on outstanding tickets.</param>
    /// <param name="lifetime">How long a ticket may live before it expires.</param>
    /// <param name="pruneInterval">The minimum interval between expired-entry sweeps.</param>
    internal LogoutTicketStore(int maxEntries, TimeSpan lifetime, TimeSpan pruneInterval)
    {
        _maxEntries = maxEntries;
        _lifetime = lifetime;
        _pruneGate = new IntervalGate(pruneInterval);
        _accountWarnGate = new IntervalGate(pruneInterval);
        _globalWarnGate = new IntervalGate(pruneInterval);
        _perUser = PerClientBudgetLimiter.FromGlobalCap(maxEntries);
    }

    /// <summary>Gets the live entry count. Test-only, like Clear and Seed.</summary>
    internal int Count => _tickets.Count;

    /// <summary>
    /// A fresh 256-bit CSPRNG token, hex-encoded, exactly as the sibling one-time stores mint theirs. This
    /// is the only value that crosses to the browser, and it is the whole of what the route accepts in place
    /// of a session: it names no user, carries no claim, and is worthless a minute after it is made.
    /// </summary>
    /// <returns>The new one-time ticket token.</returns>
    internal static string NewToken() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    /// <summary>
    /// Registers a fresh ticket under its CSPRNG token. At either cap a NEW token is refused - that one mint
    /// fails closed and the caller falls back to the local sign-out - rather than evicting an outstanding
    /// ticket, which would break a sign-out already under way. On refusal <paramref name="refusal"/> names
    /// WHICH bound was met and whether this caller holds that bound's warning throttle for the interval;
    /// the warning line stays at the call site so the log-forging inline sanitizer never crosses a helper
    /// boundary.
    /// </summary>
    /// <param name="ticket">The ticket; its token keys the entry and its Created drives the throttled warning.</param>
    /// <param name="refusal">Which bound refused, so the caller can say which; <see cref="MintRefusal.None"/> on success.</param>
    /// <returns>True if the ticket was registered; false if refused (per-account sub-cap, global cap, or token collision).</returns>
    internal bool TryAdd(LogoutTicket ticket, out MintRefusal refusal)
    {
        ArgumentNullException.ThrowIfNull(ticket);

        // Per-account sub-cap first, so one account cannot fill the whole budget.
        //
        // ITS OWN GATE, AND THAT IS THE POINT RATHER THAN A DETAIL. This refusal and the global one below
        // mean opposite things - one account is out of its share, against every account is out of luck -
        // and they shared one throttle until it was measured: an ordinary account hitting its own share
        // consumed the gate, so the genuine global exhaustion that followed arrived with no signal at all,
        // while the log carried a sentence asserting a capacity state the store was not in. The mint is
        // deliberately unthrottled, so one account can hold a shared gate closed indefinitely.
        if (!_perUser.TryReserve(UserKey(ticket.UserId)))
        {
            refusal = _accountWarnGate.TryEnter(ticket.Created) ? MintRefusal.AccountShare : MintRefusal.AccountShareQuiet;
            return false;
        }

        // Global cap: at capacity a fresh ticket is refused, never an outstanding one evicted. The
        // check-then-insert is not serialized, so concurrent mints can transiently overshoot by at most the
        // in-flight thread count - immaterial for a defence-in-depth memory bound, while the per-account
        // cap, which is the availability defence, stays exact via its own CAS.
        if (_tickets.Count >= _maxEntries || !_tickets.TryAdd(ticket.Token, ticket))
        {
            _perUser.Release(UserKey(ticket.UserId));
            refusal = _globalWarnGate.TryEnter(ticket.Created) ? MintRefusal.Store : MintRefusal.StoreQuiet;
            return false;
        }

        refusal = MintRefusal.None;
        return true;
    }

    /// <summary>
    /// The one-time atomic claim. The store is keyed by the ticket token, which is exactly the value the
    /// navigation presents, so this is an O(1) lookup plus an atomic TryRemove: only the request that wins
    /// the removal proceeds, so one ticket ends at most one session even if the browser fires the navigation
    /// twice. Redeemable only while the ticket still belongs to the route's provider and is inside its
    /// lifetime; an unknown, expired, provider-mismatched or already-claimed token returns null and the
    /// route falls back to requiring a session, which is the fail-closed direction.
    /// </summary>
    /// <param name="token">The ticket token the navigation presented.</param>
    /// <param name="provider">The provider named in the consuming request's route.</param>
    /// <param name="now">The current time.</param>
    /// <returns>The redeemed ticket, or null when not redeemable.</returns>
    internal LogoutTicket? TryRedeem(string? token, string provider, DateTime now)
    {
        // SWEPT HERE TOO, AND NOT ONLY AT THE MINT. The mint is behind the Single Logout switch, so with
        // the feature turned off - which is what an administrator does during an incident - a mint-only
        // sweep never runs again and every outstanding ticket keeps its live session token and its
        // account's slot for the life of the process. The interval gate makes this cheap on the hot path,
        // and the redeem predicate below rejects an expired entry independently, so the sweep is about
        // reclaiming memory rather than about correctness either way.
        PruneExpired(now);

        if (string.IsNullOrEmpty(token)
            || !_tickets.TryGetValue(token, out var ticket)
            || !IsCurrentFor(ticket, provider, now)
            || !_tickets.TryRemove(new KeyValuePair<string, LogoutTicket>(token, ticket)))
        {
            return null;
        }

        // Only the winner of the atomic TryRemove reaches here, so the user's slot is released exactly once.
        _perUser.Release(UserKey(ticket.UserId));
        return ticket;
    }

    /// <summary>
    /// Removes every ticket whose lifetime has elapsed, at most once per prune interval so a burst does not
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

        // BOTH directions, and the second one is the half a lifetime comparison alone misses. A backward
        // wall-clock step - an NTP correction on a drifting host, a snapshot restore, a container resync -
        // leaves every ticket minted during the fast window with a Created in the future. Its age is
        // negative, so IsCurrentFor refuses to redeem it and a `> _lifetime` sweep never reaches it: the
        // entry becomes unredeemable AND unsweepable and holds its account's slot until the clock catches
        // up. Measured on the shipped store before this line existed - a ticket created at T+1h survived
        // PruneExpired(T) with Count unchanged. The two comparisons agree with IsCurrentFor exactly, so
        // what cannot be redeemed cannot outlive a sweep either.
        foreach (var kvp in _tickets.Where(kvp => !IsWithinLifetime(kvp.Value, now)))
        {
            // Release only on the winning removal so a concurrent redeem does not double-release the slot.
            if (_tickets.TryRemove(kvp.Key, out var removed))
            {
                _perUser.Release(UserKey(removed.UserId));
            }
        }
    }

    /// <summary>Test-only: drops every entry, restoring a fresh store between tests.</summary>
    internal void Clear()
    {
        _tickets.Clear();
        _perUser.Clear();
    }

    /// <summary>
    /// Test-only: seeds one ticket directly, bypassing the mint endpoint.
    /// <para>
    /// It RESERVES the account's slot, like the mint it stands in for. TryRedeem releases a slot on every
    /// winning removal without asking how the entry arrived, so a seed that skipped the reservation would
    /// hand back a slot nothing took - the double release PerClientBudgetLimiter.Release warns about, which
    /// under-counts and lets the bucket admit past its cap. This lives in the production assembly and is
    /// reachable through InternalsVisibleTo, so "test-only" is a convention rather than a boundary.
    /// </para>
    /// </summary>
    /// <param name="ticket">The ticket to store under its own token.</param>
    internal void Seed(LogoutTicket ticket)
    {
        ArgumentNullException.ThrowIfNull(ticket);

        // Replacing an existing token would orphan the reservation the previous entry holds, so the old
        // one is released first and the new one reserved, leaving the count where the entries are.
        if (_tickets.TryRemove(ticket.Token, out var replaced))
        {
            _perUser.Release(UserKey(replaced.UserId));
        }

        // REFUSED RATHER THAN STORED UNACCOUNTED. An entry with no reservation behind it is the corrupt
        // state this method exists to avoid: TryRedeem would release a slot nothing took. A seed past the
        // account's share is a test asking for that state, so it is told rather than served.
        if (!_perUser.TryReserve(UserKey(ticket.UserId)))
        {
            throw new InvalidOperationException(
                "Cannot seed a logout ticket: this account already holds its whole share of the store, so the entry would carry no reservation and its redeem would release a slot nothing took.");
        }

        _tickets[ticket.Token] = ticket;
    }

    // The per-user budget key. A Guid's invariant string form, so two tickets for one account always land in
    // one bucket and a ticket for Guid.Empty - which the mint refuses before it gets here - would still be
    // bounded rather than exempt.
    private static string UserKey(Guid userId) => userId.ToString("N", System.Globalization.CultureInfo.InvariantCulture);

    // Whether a stored ticket still belongs to the route's provider and has not expired. The provider check
    // is the scoping guard: without it a ticket minted for one provider could be spent against another
    // provider's endpoint, which would send the browser to an end_session_endpoint the caller never named. A
    // negative age (Created in the future, after a backward clock step) is rejected too, so a clock anomaly
    // cannot make a ticket effectively never expire.
    private bool IsCurrentFor(LogoutTicket ticket, string provider, DateTime now)
    {
        if (!string.Equals(ticket.Provider, provider, StringComparison.Ordinal))
        {
            return false;
        }

        return IsWithinLifetime(ticket, now);
    }

    // The time half, alone, so the redeem and the sweep read one predicate. A negative age - Created in the
    // future, after a backward clock step - is outside the lifetime in the same sense an old ticket is:
    // nothing about it is current, and both callers act on that the same way.
    private bool IsWithinLifetime(LogoutTicket ticket, DateTime now)
    {
        var age = now.Subtract(ticket.Created);
        return age >= TimeSpan.Zero && age <= _lifetime;
    }
}

/// <summary>
/// One outstanding logout ticket (#1768), held server-side between the authenticated mint and the browser
/// navigation that spends it. Immutable: the redeem is an atomic remove of the whole record, so a redeemer
/// never observes a torn ticket.
/// </summary>
/// <param name="Token">The CSPRNG token keying the entry. It is a bearer credential of its own for the minute it lives - whoever holds it can end the bound session - so it carries the same two serializer guards as the session token, and <c>ToString</c> omits it. Nothing in this plugin serializes a whole ticket; what crosses to the browser is <see cref="LogoutTicketResponse"/>, which carries the token deliberately and declares its own wire name. IT CARRIED NO GUARD AT ALL UNTIL THIS SENTENCE, while the field beside it carried two and the record's documentation described the protection as the record's.</param>
/// <param name="Provider">The provider the ticket was minted for; it is redeemable only on that provider's endpoint.</param>
/// <param name="UserId">The minting caller's Jellyfin user id, so the redeem acts on that user and no other.</param>
/// <param name="SessionToken">The minting caller's own Jellyfin access token, so the redeem ends THAT session and not merely some session of that user. Two serializer guards keep it off a wire, and the second is there because the first was measured and found short. <see cref="JsonIgnoreAttribute"/> covers System.Text.Json; <c>Newtonsoft.Json.JsonIgnoreAttribute</c> covers Newtonsoft, which is a direct dependency of this project and honours only its own attribute - measured on the shipped record, a Newtonsoft serialization wrote the live token out in full while the System.Text.Json one hid it. The overridden <c>ToString</c> below is a third guard over a THIRD surface rather than a wider one: interpolation, and a sink that calls <c>ToString</c>. WHAT IT DOES NOT COVER IS THE SINK THIS SENTENCE USED TO NAME. A logger that DESTRUCTURES an object reflects over its properties precisely instead of calling <c>ToString</c>, and honours neither serializer's ignore attribute, so nothing here reaches that case; no call site hands a whole ticket to one. The claim is narrowed rather than the guard widened, because widening it would assert a property no reading of this tree establishes.</param>
/// <param name="Created">When the ticket was minted, used to time it out.</param>
internal sealed record LogoutTicket(
    [property: JsonIgnore]
    [property: Newtonsoft.Json.JsonIgnore] string Token,
    string Provider,
    Guid UserId,
    [property: JsonIgnore]
    [property: Newtonsoft.Json.JsonIgnore] string SessionToken,
    DateTime Created)
{
    /// <summary>
    /// Redacts the bearer <see cref="SessionToken"/> from the record's synthesized string form, so a stray
    /// interpolation or a logger call taking the whole record can never spill the caller's access token into
    /// a log. The same guard <see cref="LogoutContext"/> carries for the id_token, for the same reason.
    /// </summary>
    /// <returns>A diagnostic string with the session token redacted.</returns>
    public override string ToString()
        => $"LogoutTicket {{ Provider = {Provider}, UserId = {UserId}, SessionToken = <redacted>, Created = {Created:O} }}";
}
