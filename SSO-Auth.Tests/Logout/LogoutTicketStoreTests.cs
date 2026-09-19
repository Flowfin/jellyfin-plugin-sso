// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Text.Json;
using Jellyfin.Plugin.SSO_Auth.Api.Logout;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="LogoutTicketStore"/> - the one-time ticket the RP-initiated OpenID logout route
/// accepts in place of a session (#1768). A ticket exists so that a top-level navigation, which carries no
/// Authorization header, does not have to carry the caller's access token in the query string instead. Every
/// property that makes it a safe substitute is pinned here: it is spendable once, only at the provider it
/// was minted for, only inside its lifetime, and the store it lives in is bounded per account and overall.
/// </summary>
public class LogoutTicketStoreTests
{
    private static readonly DateTime Now = new(2026, 9, 19, 20, 0, 0, DateTimeKind.Utc);
    private static readonly Guid Caller = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid Other = Guid.Parse("22222222-2222-2222-2222-222222222222");

    private static LogoutTicket Ticket(string token, string provider = "kc", Guid? user = null, DateTime? created = null) =>
        new(token, provider, user ?? Caller, "caller-token", created ?? Now);

    // A distinct account per number, so a row that has to reach the GLOBAL cap can spread its tickets over
    // as many accounts as the per-account share demands rather than being refused by the share first.
    private static Guid UserNumber(int n) => new(n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

    private static string Text(int n) => n.ToString(System.Globalization.CultureInfo.InvariantCulture);

    [Fact]
    public void AMintedTicket_IsRedeemableOnce()
    {
        // The whole point of the type. A browser can fire the same navigation twice - a double click, a
        // retried request, a prefetch - and the second one must not end a second session or hand a second
        // caller the first one's identity.
        var store = new LogoutTicketStore();
        Assert.True(store.TryAdd(Ticket("t1"), out _));

        var first = store.TryRedeem("t1", "kc", Now);
        Assert.NotNull(first);
        Assert.Equal(Caller, first!.UserId);
        Assert.Equal("caller-token", first.SessionToken);

        Assert.Null(store.TryRedeem("t1", "kc", Now));
        Assert.Equal(0, store.Count);
    }

    [Fact]
    public void ATicketMintedForOneProvider_IsNotSpendableAtAnother()
    {
        // Without this a ticket minted against a provider the user trusts could be spent at another
        // provider's endpoint, which would send the browser to an end_session_endpoint the caller never
        // named. The ticket stays in the store, because a mismatch is somebody else's request and not this
        // caller spending theirs.
        var store = new LogoutTicketStore();
        Assert.True(store.TryAdd(Ticket("t1", provider: "kc"), out _));

        Assert.Null(store.TryRedeem("t1", "entra", Now));
        Assert.Equal(1, store.Count);
        Assert.NotNull(store.TryRedeem("t1", "kc", Now));
    }

    [Fact]
    public void ATicketOlderThanItsLifetime_IsNotRedeemable()
    {
        var store = new LogoutTicketStore(maxEntries: 8, lifetime: TimeSpan.FromMinutes(1), pruneInterval: TimeSpan.FromMinutes(1));
        Assert.True(store.TryAdd(Ticket("t1"), out _));

        // The boundary in both directions, so a row that only tested "much later" would not hide an
        // off-by-one that let a ticket live twice as long as it says it does.
        Assert.NotNull(store.TryRedeem("t1", "kc", Now.AddSeconds(60)));
        Assert.True(store.TryAdd(Ticket("t2"), out _));
        Assert.Null(store.TryRedeem("t2", "kc", Now.AddSeconds(61)));
    }

    [Fact]
    public void ATicketCreatedInTheFuture_IsNotRedeemable()
    {
        // A backward clock step would otherwise make a ticket effectively never expire: its age goes
        // negative and stays below the lifetime for as long as the step lasts. Rejected instead, which is
        // the same guard the SAML outcome store carries for the same reason.
        var store = new LogoutTicketStore();
        Assert.True(store.TryAdd(Ticket("t1", created: Now), out _));

        Assert.Null(store.TryRedeem("t1", "kc", Now.AddSeconds(-1)));
    }

    [Fact]
    public void ATicketCreatedInTheFuture_IsAlsoSwept_AndGivesItsSlotBack()
    {
        // The other half of the row above, and the half that was missing. Refusing to redeem a future-dated
        // ticket is fail-closed and right; leaving it in the map is not. A sweep that only asked whether the
        // age EXCEEDED the lifetime never reached a negative age, so after a backward clock step - an NTP
        // correction, a snapshot restore, a container resync - every ticket minted during the fast window
        // was unredeemable AND unsweepable, holding its account's slot for the whole correction rather than
        // for a minute. Measured on the shipped store: the entry survived PruneExpired with Count unchanged.
        var store = new LogoutTicketStore(maxEntries: 200, lifetime: TimeSpan.FromMinutes(1), pruneInterval: TimeSpan.FromMinutes(1));
        Assert.True(store.TryAdd(Ticket("future", user: Caller, created: Now.AddHours(1)), out _));

        store.PruneExpired(Now);

        Assert.Equal(0, store.Count);

        // And the slot came back with it, which the count alone cannot say: the entry is gone from the map
        // either way, and only a fresh mint says whether the sub-cap knows.
        Assert.True(store.TryAdd(Ticket("fresh", user: Caller, created: Now), out _));
    }

    [Fact]
    public void AnUnknownToken_IsNotRedeemable_AndNeitherIsNoTokenAtAll()
    {
        var store = new LogoutTicketStore();
        Assert.True(store.TryAdd(Ticket("t1"), out _));

        Assert.Null(store.TryRedeem("t2", "kc", Now));
        Assert.Null(store.TryRedeem(null, "kc", Now));
        Assert.Null(store.TryRedeem(string.Empty, "kc", Now));
        Assert.Equal(1, store.Count);
    }

    [Fact]
    public void AtTheGlobalCap_AFreshTicketIsRefused_AndTheOutstandingOnesStand()
    {
        // Refusing the new one rather than evicting an old one: an eviction would break a sign-out already
        // in flight, while a refused mint degrades to the local Jellyfin sign-out the client already has.
        // The per-account sub-cap is a share of the global cap, so reaching the GLOBAL one takes many
        // accounts - this fills it with as many as the share divisor demands, or the row below would be the
        // one doing the refusing and this comment would be describing the wrong branch.
        const int Cap = 300;
        var store = new LogoutTicketStore(maxEntries: Cap, lifetime: TimeSpan.FromMinutes(1), pruneInterval: TimeSpan.FromMinutes(1));

        var filled = 0;
        for (var account = 0; filled < Cap && account < Cap; account++)
        {
            var user = UserNumber(account);
            while (filled < Cap && store.TryAdd(Ticket("t" + Text(filled), user: user), out _))
            {
                filled++;
            }
        }

        Assert.Equal(Cap, filled);
        Assert.Equal(Cap, store.Count);

        // No assertion on the capacity-warning flag here: filling the store walks past a sub-cap refusal
        // for every account on the way, and the warning is throttled to one signal per interval, so by
        // this point the gate is legitimately closed. The row below is where the flag is pinned, on a
        // store whose first refusal is its first refusal.
        Assert.False(store.TryAdd(Ticket("overflow", user: UserNumber(Cap)), out _));
        Assert.Equal(Cap, store.Count);
        Assert.NotNull(store.TryRedeem("t0", "kc", Now));
    }

    [Fact]
    public void TheFirstRefusalAsksForAWarning_AndTheOnesBehindItAreThrottled()
    {
        // An operator has to be able to learn that sign-out tickets are being refused, and must not have
        // the log filled by learning it: a run of refusals under load would otherwise write one line each.
        // Both halves are here because a verdict that were always loud and one that were always quiet each
        // satisfy one of them.
        var store = new LogoutTicketStore(maxEntries: 2, lifetime: TimeSpan.FromMinutes(1), pruneInterval: TimeSpan.FromMinutes(1));
        Assert.True(store.TryAdd(Ticket("t1", user: Caller), out var onSuccess));
        Assert.Equal(MintRefusal.None, onSuccess);

        Assert.False(store.TryAdd(Ticket("t2", user: Caller), out var firstRefusal));
        Assert.Equal(MintRefusal.AccountShare, firstRefusal);

        Assert.False(store.TryAdd(Ticket("t3", user: Caller), out var throttled));
        Assert.Equal(MintRefusal.AccountShareQuiet, throttled);
    }

    [Fact]
    public void OneAccountsOwnRefusal_DoesNotSpeakFor_OrSilence_AFullStore()
    {
        // The two refusals mean opposite things - one account is out of its share, against every account is
        // out of luck - and they shared one throttle until this was measured: an ordinary account hitting
        // its own share consumed the gate, so the genuine global exhaustion that followed arrived with no
        // signal at all, while the log carried a sentence asserting a capacity state the store was not in.
        // The mint is deliberately unthrottled, so one account could hold a shared gate closed indefinitely.
        var store = new LogoutTicketStore(maxEntries: 200, lifetime: TimeSpan.FromMinutes(1), pruneInterval: TimeSpan.FromMinutes(1));

        // Spend the ACCOUNT gate first, which is what a routine caller does.
        while (store.TryAdd(Ticket("c" + Text(store.Count), user: Caller), out _))
        {
        }

        Assert.False(store.TryAdd(Ticket("again", user: Caller), out var accountRefusal));
        Assert.True(accountRefusal is MintRefusal.AccountShare or MintRefusal.AccountShareQuiet);

        // Now fill the store globally and ask a fresh account. The answer must name the STORE, and it must
        // still be loud: the account gate being spent says nothing about this one.
        var filled = store.Count;
        for (var account = 0; filled < 200; account++)
        {
            var user = UserNumber(account);
            while (filled < 200 && store.TryAdd(Ticket("g" + Text(filled), user: user), out _))
            {
                filled++;
            }
        }

        Assert.False(store.TryAdd(Ticket("overflow", user: UserNumber(9999)), out var storeRefusal));
        Assert.Equal(MintRefusal.Store, storeRefusal);
    }

    [Fact]
    public void OneAccountCannotFillTheStore()
    {
        // The availability property. Without the per-account sub-cap one signed-in user holding the sign-out
        // button down would take every slot, and everybody else's sign-out would be refused by a store that
        // one account owns. The sub-cap is a share of the global cap, so this refuses well before the global
        // one does - which is what the count assertion says.
        const int Cap = 400;
        var store = new LogoutTicketStore(maxEntries: Cap, lifetime: TimeSpan.FromMinutes(1), pruneInterval: TimeSpan.FromMinutes(1));

        var accepted = 0;
        while (accepted < Cap && store.TryAdd(Ticket("t" + Text(accepted), user: Caller), out _))
        {
            accepted++;
        }

        Assert.True(accepted > 0, "the sub-cap refused the account's very first ticket");
        Assert.True(accepted < Cap, $"one account filled the whole store: {accepted} of {Cap} accepted");
        Assert.True(store.TryAdd(Ticket("other", user: Other), out _), "the second account was locked out by the first");
    }

    [Fact]
    public void ARedeemedTicket_GivesItsAccountItsSlotBack()
    {
        // Without the release on redeem the sub-cap would be a lifetime quota rather than an occupancy
        // bound: a user who signed out enough times would stop being able to, and nothing would ever give
        // the slots back because the entries are gone from the map already.
        var store = new LogoutTicketStore(maxEntries: 400, lifetime: TimeSpan.FromMinutes(1), pruneInterval: TimeSpan.FromMinutes(1));

        var accepted = 0;
        while (store.TryAdd(Ticket("a" + Text(accepted), user: Caller), out _))
        {
            accepted++;
        }

        Assert.True(accepted > 0);
        Assert.NotNull(store.TryRedeem("a0", "kc", Now));
        Assert.True(store.TryAdd(Ticket("fresh", user: Caller), out _));
    }

    [Fact]
    public void TheSweepDropsExpiredTickets_AndGivesTheirSlotsBack()
    {
        // Two accounts rather than one, because at this cap the per-account share is a single slot and a
        // second ticket for the same user would be refused by the sub-cap before the sweep was ever the
        // subject.
        var store = new LogoutTicketStore(maxEntries: 8, lifetime: TimeSpan.FromMinutes(1), pruneInterval: TimeSpan.FromMinutes(1));
        Assert.True(store.TryAdd(Ticket("t1", user: Caller, created: Now), out _));
        Assert.True(store.TryAdd(Ticket("t2", user: Other, created: Now.AddMinutes(5)), out _));

        // The expired entry goes and the one still inside its lifetime stays, so the sweep is not simply a
        // Clear with extra steps.
        store.PruneExpired(Now.AddMinutes(5));

        Assert.Equal(1, store.Count);
        Assert.Null(store.TryRedeem("t1", "kc", Now.AddMinutes(5)));
        Assert.NotNull(store.TryRedeem("t2", "kc", Now.AddMinutes(5)));

        // The expired ticket's account got its slot back, which is the half a count assertion cannot see:
        // the entry is gone from the map either way, and only a fresh mint says whether the sub-cap knows.
        Assert.True(store.TryAdd(Ticket("t3", user: Caller, created: Now.AddMinutes(5)), out _));
    }

    [Fact]
    public void AnUnsweptExpiredTicket_IsStillNotRedeemable()
    {
        // The sweep is throttled, so an expired entry can sit in the map for up to a prune interval. The
        // redeem predicate has to reject it on its own, or the throttle would become a window in which an
        // expired ticket still works. The first PruneExpired call is what CONSUMES the interval gate - the
        // gate admits its first caller whatever the interval - so the second one below is the throttled
        // call this row is about, and without it the entry would simply be swept and prove nothing.
        var store = new LogoutTicketStore(maxEntries: 8, lifetime: TimeSpan.FromMinutes(1), pruneInterval: TimeSpan.FromHours(1));
        store.PruneExpired(Now);
        Assert.True(store.TryAdd(Ticket("t1", created: Now), out _));

        store.PruneExpired(Now.AddMinutes(5));

        Assert.Equal(1, store.Count);
        Assert.Null(store.TryRedeem("t1", "kc", Now.AddMinutes(5)));
    }

    [Fact]
    public void ASeededTicket_IsAccountedForLikeAMintedOne()
    {
        // Seed is a test hook that lives in the production assembly and is reachable through
        // InternalsVisibleTo, and TryRedeem releases a slot on every winning removal without asking how the
        // entry arrived. A seed that skipped the reservation therefore handed back a slot nothing took -
        // the double release PerClientBudgetLimiter warns about, which under-counts and lets the bucket
        // admit past its cap. This row is what says the two entry points agree.
        var store = new LogoutTicketStore(maxEntries: 200, lifetime: TimeSpan.FromMinutes(1), pruneInterval: TimeSpan.FromMinutes(1));

        var minted = 0;
        while (store.TryAdd(Ticket("m" + Text(minted), user: Caller), out _))
        {
            minted++;
        }

        Assert.True(minted > 1, "the account's share is too small for this row to say anything");

        // Seeding BEYOND the share is refused rather than served: such an entry would carry no
        // reservation, and its redeem would release a slot nothing took - the double release that
        // under-counts the bucket and lets it admit past its cap.
        Assert.Throws<InvalidOperationException>(() => store.Seed(Ticket("past-the-share", user: Caller)));

        // Inside the share it behaves exactly like a mint, redeem included, so the refusal above is
        // about the accounting and not about Seed being unusable.
        Assert.NotNull(store.TryRedeem("m0", "kc", Now));
        store.Seed(Ticket("seeded", user: Caller));
        Assert.NotNull(store.TryRedeem("seeded", "kc", Now));

        // And exactly one slot is free afterwards, which is what says the seed's reservation and the
        // redeem's release matched.
        Assert.True(store.TryAdd(Ticket("fresh", user: Caller), out _));
        Assert.False(store.TryAdd(Ticket("past-the-cap", user: Caller), out _), "the seed and its redeem did not balance");
    }

    [Fact]
    public void TheSweepIsReachableFromTheRedeem_AndNotOnlyFromTheMint()
    {
        // The mint is behind the Single Logout feature switch. If the sweep lived only there, turning the
        // feature off - which is what an administrator does during an incident - would freeze the store:
        // every outstanding ticket would keep its live session token and its account's slot for the life of
        // the process, with nothing left able to reclaim either. The redeem sweeps too, so the store drains
        // on any traffic at all.
        var store = new LogoutTicketStore(maxEntries: 200, lifetime: TimeSpan.FromMinutes(1), pruneInterval: TimeSpan.FromMinutes(1));
        Assert.True(store.TryAdd(Ticket("stale", user: Caller, created: Now), out _));
        Assert.True(store.TryAdd(Ticket("live", user: Other, created: Now.AddMinutes(5)), out _));

        // A redeem that finds nothing still sweeps, which is what says the sweep is not a side effect of a
        // successful claim.
        Assert.Null(store.TryRedeem("no-such-ticket", "kc", Now.AddMinutes(5)));

        Assert.Equal(1, store.Count);
        Assert.True(store.TryAdd(Ticket("fresh", user: Caller, created: Now.AddMinutes(5)), out _), "the swept ticket's account did not get its slot back");
    }

    [Fact]
    public void TwoFreshTokens_AreNotTheSame()
    {
        // A near-worthless-looking row that is the difference between a one-time ticket and a predictable
        // one: a token generator that returned a constant would satisfy every row above, because every one
        // of them mints and redeems the same string it was handed.
        Assert.NotEqual(LogoutTicketStore.NewToken(), LogoutTicketStore.NewToken());
        Assert.Equal(64, LogoutTicketStore.NewToken().Length);
    }

    [Fact]
    public void TheRecordsStringForm_NeverCarriesTheSessionToken()
    {
        // The same guard LogoutContext carries for the id_token. A record's synthesized ToString prints every
        // member, so a stray interpolation or a logger call taking the whole ticket would put the caller's
        // access token in a log line - which is the exact exposure this whole mechanism exists to remove
        // from the URL.
        var text = Ticket("t1").ToString();

        Assert.DoesNotContain("caller-token", text, StringComparison.Ordinal);
        Assert.Contains("<redacted>", text, StringComparison.Ordinal);
    }

    [Fact]
    public void TheRecord_NeverSerializesTheSessionToken()
    {
        // The other half, and the half the ToString guard did not cover while its own documentation claimed
        // it did. SessionToken stayed an ordinary property, so any serializer handed the whole ticket - a
        // diagnostic dump, a metrics payload, a structured-logging sink configured to destructure objects
        // rather than call ToString - wrote the live access token out verbatim. Measured on the shipped
        // record before the attribute existed: JsonSerializer.Serialize emitted "SessionToken":"sess-tok".
        // Both serializer shapes are checked, because a naming policy changes the KEY and would walk a test
        // that only searched for one spelling of it.
        var ticket = Ticket("t1");

        foreach (var options in new[] { new JsonSerializerOptions(), new JsonSerializerOptions(JsonSerializerDefaults.Web) })
        {
            var json = JsonSerializer.Serialize(ticket, options);
            Assert.DoesNotContain("caller-token", json, StringComparison.Ordinal);
            Assert.DoesNotContain("essionToken", json, StringComparison.Ordinal);
        }

        // AND NEWTONSOFT, which is the half a System.Text.Json-only row cannot see. Newtonsoft is a direct
        // dependency of this plugin and honours only its OWN ignore attribute, so a record carrying the
        // System.Text.Json one alone serialized the live access token out in full under it - measured,
        // while every assertion above stayed green. Both attributes are on the property now, and this is
        // the row that says so.
        var newtonsoft = Newtonsoft.Json.JsonConvert.SerializeObject(ticket);
        Assert.DoesNotContain("caller-token", newtonsoft, StringComparison.Ordinal);
        Assert.DoesNotContain("essionToken", newtonsoft, StringComparison.Ordinal);
    }

    [Fact]
    public void TheMintedTicketIsAnswered_UnderOneDeclaredWireName()
    {
        // The mint's response body is what a client integrator reads, and without a declared name the JSON
        // key is whichever naming policy the host serializer happens to carry. Measured on the shipped type
        // before the attribute existed: the same record answered {"Ticket":...} under the default options
        // and {"ticket":...} under the web defaults - two contracts from one type, and the suite pinned
        // neither because it asserted on the OBJECT rather than on its serialization.
        var body = new LogoutTicketResponse("DEADBEEF");

        foreach (var options in new[] { new JsonSerializerOptions(), new JsonSerializerOptions(JsonSerializerDefaults.Web) })
        {
            Assert.Equal("{\"ticket\":\"DEADBEEF\"}", JsonSerializer.Serialize(body, options));
        }
    }
}
