// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Audit;
using Jellyfin.Plugin.SSO_Auth.Api.Logout;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the logout-ticket mint and of the ticket-bearing form of the RP-initiated OpenID
/// logout (#1768), through <see cref="SsoControllerHarness"/>.
/// <para>
/// WHAT THE TICKET IS FOR, because every row below is a property of that. The logout route has to send the
/// browser on to the identity provider, so it is reached by a top-level navigation, and a navigation carries
/// no Authorization header. The only form that worked before was the caller's own access token in the query
/// string - a long-lived credential in a URL that lands in history, in a referrer and in every proxy log on
/// the way. A ticket replaces it with something bound to one user, one session and one provider, good for a
/// minute and for one use. So the rows are: the mint hands back something that is not the access token, the
/// route accepts it once and no more, and every way of presenting a ticket that is not this caller's own is
/// refused rather than degraded into a logout of somebody.
/// </para>
/// </summary>
[Collection("SSOController")]
public class SSOControllerLogoutTicketTests
{
    private static readonly Guid Caller = Guid.Parse("88888888-8888-8888-8888-888888888888");

    private const string CallerToken = "caller-token";

    private static SsoControllerHarness ForCaller(
        string? token,
        Guid? userId = null,
        bool singleLogout = true,
        System.Net.IPAddress? clientIp = null,
        bool rateLimit = false,
        Action<PluginConfiguration>? configure = null)
    {
        var harness = new SsoControllerHarness(
            config =>
        {
            config.EnableSingleLogout = singleLogout;
            config.EnableRateLimit = rateLimit;
            if (rateLimit)
            {
                // A tiny budget so the gate closes inside a handful of requests. The production default
                // would need dozens, and a row that depended on the default would be pinning the default
                // rather than the ordering this row is about.
                config.RateLimitMaxAttempts = 3;
                config.RateLimitWindowSeconds = 60;
            }
            config.OidConfigs["kc"] = new OidConfig { Enabled = true, OidClientId = "client-kc" };
            config.OidConfigs["entra"] = new OidConfig { Enabled = true, OidClientId = "client-entra" };
            config.LogoutSessions["session-1"] = new LogoutSession
            {
                Protocol = "OpenID",
                Provider = "kc",
                Subject = "sub-1",
                Issuer = "https://idp.example",
                EndSessionEndpoint = "https://idp.example/logout",
                IdToken = "raw.id.token", // plaintext round-trips through Reveal unchanged
                UserId = Caller,
            };
            configure?.Invoke(config);
        },
            clientIp);

        // A null user is the unauthenticated shape: AuthorizationInfo resolves UserId to Guid.Empty, which is
        // exactly what the route's own gate reads, so the refusal rows exercise the real predicate rather
        // than a stand-in for it.
        var user = userId is null ? null : TestUsers.Named("caller", userId.Value);
        harness.AuthContext.GetAuthorizationInfo(Arg.Any<HttpRequest>())
            .Returns(Task.FromResult(new AuthorizationInfo { User = user, Token = token }));

        // The account the ticket arm re-reads at the redeem (#1793): present and enabled unless a row says
        // otherwise, so every redeem row below exercises the account check on its positive side.
        harness.UserManager.GetUserById(Caller).Returns(TestUsers.Named("caller", Caller));
        return harness;
    }

    private static string MintedTicket(ActionResult result)
    {
        var ok = Assert.IsType<OkObjectResult>(result);
        var body = Assert.IsType<LogoutTicketResponse>(ok.Value);
        Assert.False(string.IsNullOrEmpty(body.Ticket));
        return body.Ticket;
    }

    [Fact]
    public async Task AMintedTicket_CarriesTheLogoutThroughWithoutTheAccessToken()
    {
        // The whole feature in one row: a signed-in caller asks for a ticket, and the ticket alone - no
        // header, no api_key - reaches the identity provider's end-session redirect and ends the caller's
        // own local session on the way.
        var harness = ForCaller(CallerToken, Caller);

        var ticket = MintedTicket(await harness.Controller.OidLogoutTicket("kc"));

        // What the mint handed back is NOT the credential it replaces. This is the Done-when the issue
        // states, checked on the value rather than on the shape of the URL a client might build from it.
        Assert.NotEqual(CallerToken, ticket);
        Assert.DoesNotContain(CallerToken, ticket, StringComparison.Ordinal);

        // The navigation that spends it carries no session at all. The SAME harness is reused and only its
        // authorization answer is swapped, which is load-bearing rather than tidy: the harness constructor
        // empties the process-wide ticket store, so building a second one here would destroy the ticket
        // that was just minted and the row would end up proving something about a ticket it had seeded
        // itself. Measured - with a second harness, a mint that bound the WRONG session token reddened
        // nothing at all.
        harness.AuthContext.GetAuthorizationInfo(Arg.Any<HttpRequest>())
            .Returns(Task.FromResult(new AuthorizationInfo { User = null, Token = null }));

        var result = await harness.Controller.OidLogout("kc", ticket);

        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.StartsWith("https://idp.example/logout?", redirect.Url, StringComparison.Ordinal);
        Assert.Contains("id_token_hint=raw.id.token", redirect.Url, StringComparison.Ordinal);

        // The session that is ended is the one the MINT was made from, not merely some session of that user
        // and not some other string the mint happened to store.
        await harness.SessionManager.Received(1).Logout(CallerToken);
    }

    [Fact]
    public async Task TheHintTheTicketSends_IsTheCallersNewestCapture_AndNotNecessarilyTheTicketsSession()
    {
        // WHICH HALF OF THE ROUTE THE SESSION BINDING COVERS (#1794). The local revoke is session-bound: the
        // ticket carries the minting session's token and Logout ends exactly that session. The end-session
        // hint is not: the entry that supplies the id_token_hint is the caller's newest capture for the
        // provider, keyed by a Jellyfin session id the ticket never carried, so with a browser and a
        // television signed in to the same provider a ticket minted in the browser ends the browser locally
        // and sends the television's id_token to the provider, removing the television's capture with it.
        // This row pins that selection rather than approving it: the texts that describe the ticket say
        // which half they cover, and a change that makes the hint follow the ticket's session turns this
        // row red and rewrites those texts in the same change.
        var harness = ForCaller(CallerToken, Caller, configure: config =>
        {
            config.LogoutSessions["session-1"].CapturedUtcTicks = 1_000;
            config.LogoutSessions["session-tv"] = new LogoutSession
            {
                Protocol = "OpenID",
                Provider = "kc",
                Subject = "sub-1",
                Issuer = "https://idp.example",
                EndSessionEndpoint = "https://idp.example/logout",
                IdToken = "tv.id.token",
                UserId = Caller,
                CapturedUtcTicks = 2_000,
            };
        });
        var ticket = MintedTicket(await harness.Controller.OidLogoutTicket("kc"));
        harness.AuthContext.GetAuthorizationInfo(Arg.Any<HttpRequest>())
            .Returns(Task.FromResult(new AuthorizationInfo { User = null, Token = null }));

        var redirect = Assert.IsType<RedirectResult>(await harness.Controller.OidLogout("kc", ticket));

        Assert.Contains("id_token_hint=tv.id.token", redirect.Url, StringComparison.Ordinal);
        await harness.SessionManager.Received(1).Logout(CallerToken);
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("session-tv")));
        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("session-1")));
    }

    [Fact]
    public async Task ATicketIsSpentOnce_AndTheSecondNavigationIsRefused()
    {
        // A browser fires a navigation twice often enough - a double tap, a retry, a prefetch - and a ticket
        // that survived the first one would be a credential lying around for the rest of its minute.
        var harness = ForCaller(token: null);
        LogoutTicketService.SeedForTests(new LogoutTicket("t1", "kc", Caller, CallerToken, DateTime.UtcNow));

        Assert.IsType<RedirectResult>(await harness.Controller.OidLogout("kc", "t1"));
        Assert.IsType<UnauthorizedResult>(await harness.Controller.OidLogout("kc", "t1"));

        // The refused second navigation did NOT end a second session. A route that fell back to the
        // session-less local logout here would look identical in its status and be doing work for nobody.
        await harness.SessionManager.Received(1).Logout(CallerToken);
    }

    [Fact]
    public async Task ATicketMintedForOneProvider_IsRefusedAtAnother()
    {
        // Without the provider scope a ticket for a provider the user trusts would send the browser to an
        // end_session_endpoint the caller never named.
        var harness = ForCaller(token: null);
        LogoutTicketService.SeedForTests(new LogoutTicket("t1", "kc", Caller, CallerToken, DateTime.UtcNow));

        Assert.IsType<UnauthorizedResult>(await harness.Controller.OidLogout("entra", "t1"));
        await harness.SessionManager.DidNotReceive().Logout(Arg.Any<string>());

        // Still spendable where it belongs, so the row is about the scope and not about a ticket the route
        // could never redeem.
        Assert.IsType<RedirectResult>(await harness.Controller.OidLogout("kc", "t1"));
    }

    [Fact]
    public async Task AnExpiredTicket_IsRefused()
    {
        var harness = ForCaller(token: null);
        LogoutTicketService.SeedForTests(new LogoutTicket("t1", "kc", Caller, CallerToken, DateTime.UtcNow.AddMinutes(-5)));

        Assert.IsType<UnauthorizedResult>(await harness.Controller.OidLogout("kc", "t1"));
        await harness.SessionManager.DidNotReceive().Logout(Arg.Any<string>());
    }

    [Fact]
    public async Task AnUnknownTicket_IsRefused_AndNotDegradedIntoALocalLogout()
    {
        // The direction that matters. Falling back to the session-less local logout for an unrecognised
        // ticket would make this route do work for a request that named nobody, on a path that is reachable
        // without any credential at all.
        var harness = ForCaller(token: null);

        Assert.IsType<UnauthorizedResult>(await harness.Controller.OidLogout("kc", "no-such-ticket"));
        await harness.SessionManager.DidNotReceive().Logout(Arg.Any<string>());
    }

    [Fact]
    public async Task NoTicketAndNoSession_IsRefused()
    {
        // What the [Authorize] attribute used to answer. The attribute had to go for the ticket path to
        // exist at all, so this is the row that says the refusal it carried is still there.
        var harness = ForCaller(token: null);

        Assert.IsType<UnauthorizedResult>(await harness.Controller.OidLogout("kc"));
        await harness.SessionManager.DidNotReceive().Logout(Arg.Any<string>());
    }

    [Fact]
    public async Task TheSessionBearingForm_IsUnchanged()
    {
        // The positive control for the row above: with no ticket and a real session the route is the
        // authenticated self-logout it has always been. Without this, a gate that refused everything would
        // satisfy every refusal row here while taking the feature away.
        var harness = ForCaller(CallerToken, Caller);

        var redirect = Assert.IsType<RedirectResult>(await harness.Controller.OidLogout("kc"));
        Assert.StartsWith("https://idp.example/logout?", redirect.Url, StringComparison.Ordinal);
        await harness.SessionManager.Received(1).Logout(CallerToken);
    }

    [Fact]
    public async Task ACallerWithNoSessionToken_IsRefusedRatherThanAskedToComeBack()
    {
        // A ticket carries the session it was minted from, so a caller the mint cannot bind one to must get
        // nothing rather than a ticket that would end nothing.
        //
        // 401 AND NOT 503, WHICH IS WHAT THIS ROW ASSERTED UNTIL #1796. 503 is the status that tells a
        // client to come back, and an access token that is empty now is empty on the retry as well: the one
        // caller who could never succeed was the one being told to keep asking, at an endpoint that carried
        // no rate bound then, so each ask cost a configuration read and a store sweep. The status
        // matches the one the gate above this already answers for the neighbouring session shapes.
        var harness = ForCaller(token: null, userId: Caller);

        Assert.IsType<UnauthorizedResult>(await harness.Controller.OidLogoutTicket("kc"));
    }

    [Fact]
    public async Task ARequestNamingNoProvider_IsRefusedRatherThanAskedToComeBack()
    {
        // A ticket is spendable only at the provider it names, so a request naming none is asking for one
        // that could be spent nowhere, and no amount of waiting supplies a name. The route template matches
        // no empty segment, so this shape reaches the action from a caller inside the process rather than
        // off the wire - which is why the arm is here at all instead of being left to the routing table.
        var harness = ForCaller(CallerToken, Caller);

        Assert.IsType<BadRequestResult>(await harness.Controller.OidLogoutTicket(string.Empty));
    }

    [Fact]
    public async Task ACallerHoldingItsWholeShare_IsAskedToComeBack()
    {
        // The one class a retry can clear, and the only one 503 is the true answer for: this account is
        // refused now and is issued a ticket again as soon as one of its own expires. The share is filled
        // through the endpoint rather than through the store's seed, so what the row covers is the route's
        // own mapping and not a state a test arranged behind it.
        var harness = ForCaller(CallerToken, Caller);
        var share = PerClientBudgetLimiter.FromGlobalCap(LogoutTicketStore.DefaultMaxEntries).PerKeyCap;

        for (var i = 0; i < share; i++)
        {
            MintedTicket(await harness.Controller.OidLogoutTicket("kc"));
        }

        var refusal = Assert.IsType<ObjectResult>(await harness.Controller.OidLogoutTicket("kc"));
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, refusal.StatusCode);

        // The 503 keeps a body, because a caller who should come back is the one caller with something to
        // read. The literal is the controller's and is not repeated here, which would be one more copy to
        // drift; what the row holds is that the arm still carries one.
        Assert.False(string.IsNullOrWhiteSpace(Assert.IsType<string>(refusal.Value)));
    }

    [Fact]
    public async Task AMintLoopFromOnePublicAddress_IsThrottled_BeforeItsShareFills()
    {
        // The decision on #1796: the mint carries a rate bound in the Logout class, so a client in a loop is
        // answered 429 before it has filled its own share with tickets nobody redeems and locked its own
        // sign-out for the rest of the minute. A genuinely PUBLIC address, for the reason the redeem rows
        // give: the limiter makes no bucket for a non-public source, and a fixture using one would pass
        // vacuously on a route that gated nothing. The budget here is three, far below the share, so the
        // answer that closes the loop is the throttle's and not the store's.
        var harness = ForCaller(CallerToken, Caller, clientIp: System.Net.IPAddress.Parse("8.8.4.79"), rateLimit: true);
        var share = PerClientBudgetLimiter.FromGlobalCap(LogoutTicketStore.DefaultMaxEntries).PerKeyCap;

        for (var i = 0; i < 3; i++)
        {
            MintedTicket(await harness.Controller.OidLogoutTicket("kc"));
        }

        var throttled = Assert.IsType<ContentResult>(await harness.Controller.OidLogoutTicket("kc"));
        Assert.Equal(StatusCodes.Status429TooManyRequests, throttled.StatusCode);
        Assert.True(3 < share, "the fixture's budget is not below the share, so this row cannot tell the throttle's answer from the store's");
    }

    [Fact]
    public async Task WhereThePeerIsNotAttributable_TheShareIsStillTheBound()
    {
        // The other half of the same decision: the occupancy bound stays the hard limit behind the rate
        // bound. With the limiter on but the peer non-public it makes no bucket, which is its structural
        // mass-lockout defence, and what stands then is the store's own share - the state a stock install is
        // in on every request, since the limiter is off there. So the loop runs the whole share through
        // without a 429 and meets the 503 at the end of it, and never the throttle.
        var harness = ForCaller(CallerToken, Caller, clientIp: System.Net.IPAddress.Loopback, rateLimit: true);
        var share = PerClientBudgetLimiter.FromGlobalCap(LogoutTicketStore.DefaultMaxEntries).PerKeyCap;

        for (var i = 0; i < share; i++)
        {
            MintedTicket(await harness.Controller.OidLogoutTicket("kc"));
        }

        var refusal = Assert.IsType<ObjectResult>(await harness.Controller.OidLogoutTicket("kc"));
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, refusal.StatusCode);
    }

    [Fact]
    public void TheMint_SaysWhichClassOfAnswerItGave()
    {
        // The classes at the service that decides them, because the route collapses two of them onto one
        // status and a row read through the route alone cannot tell those two apart. Without this the
        // outcome could fold back into a single value and every status row above would still pass.
        // The capacity class is not here: reaching it takes a filled share, which the row above does
        // through the endpoint.
        LogoutTicketService.ResetForTests();
        var service = new LogoutTicketService(NullLogger.Instance);
        var now = DateTime.UtcNow;

        Assert.Null(service.Mint(Guid.Empty, "kc", CallerToken, now, out var noCaller));
        Assert.Equal(MintOutcome.NoCaller, noCaller);

        Assert.Null(service.Mint(Caller, "kc", null, now, out var noSession));
        Assert.Equal(MintOutcome.NoSession, noSession);

        Assert.Null(service.Mint(Caller, string.Empty, CallerToken, now, out var noProvider));
        Assert.Equal(MintOutcome.NoProvider, noProvider);

        // The positive control: the same service, asked properly, still issues one. Without it every
        // assertion above is satisfied by a mint that refuses everything.
        Assert.NotNull(service.Mint(Caller, "kc", CallerToken, now, out var issued));
        Assert.Equal(MintOutcome.Issued, issued);
    }

    [Fact]
    public async Task WithSingleLogoutOff_NoTicketIsMinted()
    {
        // The mint is one of the surfaces the feature switch gates. With Single Logout off the logout route
        // captures nothing and degrades to the local sign-out, so a ticket minted here could never do
        // anything - and minting one anyway would add an always-on authenticated surface, holding a live
        // session token in memory, to every server that never turned the feature on.
        var harness = ForCaller(CallerToken, Caller, singleLogout: false);

        Assert.IsType<NotFoundResult>(await harness.Controller.OidLogoutTicket("kc"));
    }

    [Fact]
    public async Task ADisabledAccountsLiveToken_MintsNothing_AndSignsNobodyOut()
    {
        // The gap the [Authorize] removal opened, and the reason the replacement gate reads more than the
        // user id. Jellyfin's default policy refuses a disabled account; a disabled account's token keeps a
        // non-empty user id until it is revoked, so a gate testing only for Guid.Empty admitted a caller the
        // attribute refused. Both halves are checked - the mint and the session-bearing logout - because the
        // attribute covered both and only one gate now stands for it.
        var harness = ForCaller(CallerToken, Caller);
        var disabled = TestUsers.Named("caller", Caller);
        disabled.SetPermission(PermissionKind.IsDisabled, true);
        harness.AuthContext.GetAuthorizationInfo(Arg.Any<HttpRequest>())
            .Returns(Task.FromResult(new AuthorizationInfo { User = disabled, Token = CallerToken }));

        Assert.IsType<UnauthorizedResult>(await harness.Controller.OidLogoutTicket("kc"));
        Assert.IsType<UnauthorizedResult>(await harness.Controller.OidLogout("kc"));
        await harness.SessionManager.DidNotReceive().Logout(Arg.Any<string>());
    }

    [Fact]
    public async Task ATicketForAnAccountDisabledAfterTheMint_IsRefusedAtTheRedeem()
    {
        // The ticket arm decided about the ticket and about nothing else (#1793): a ticket minted in the
        // second before an administrator disabled the account stayed spendable for the rest of its minute,
        // while the attribute this arm replaced refused on the caller's account state. The account is read
        // again at the redeem, on the same two conditions the session-bearing arm reads.
        var harness = ForCaller(CallerToken, Caller);
        var ticket = MintedTicket(await harness.Controller.OidLogoutTicket("kc"));
        var disabled = TestUsers.Named("caller", Caller);
        disabled.SetPermission(PermissionKind.IsDisabled, true);
        harness.UserManager.GetUserById(Caller).Returns(disabled);
        harness.AuthContext.GetAuthorizationInfo(Arg.Any<HttpRequest>())
            .Returns(Task.FromResult(new AuthorizationInfo { User = null, Token = null }));

        Assert.IsType<UnauthorizedResult>(await harness.Controller.OidLogout("kc", ticket));

        await harness.SessionManager.DidNotReceive().Logout(Arg.Any<string>());
        var lines = string.Join(" | ", harness.ControllerLog.Entries.ConvertAll(e => e.Message));
        Assert.Contains("logout_account_unavailable", lines, StringComparison.Ordinal);

        // Spent, not retried: the refused ticket does not become redeemable again when the account does.
        harness.UserManager.GetUserById(Caller).Returns(TestUsers.Named("caller", Caller));
        Assert.IsType<UnauthorizedResult>(await harness.Controller.OidLogout("kc", ticket));
    }

    [Fact]
    public async Task ATicketForAnAccountDeletedAfterTheMint_IsRefused()
    {
        // The other half of "exists and is not disabled": an account the host no longer resolves names
        // nobody, and a ticket for it ends nothing.
        var harness = ForCaller(CallerToken, Caller);
        var ticket = MintedTicket(await harness.Controller.OidLogoutTicket("kc"));
        harness.UserManager.GetUserById(Caller).Returns((Jellyfin.Database.Implementations.Entities.User?)null);
        harness.AuthContext.GetAuthorizationInfo(Arg.Any<HttpRequest>())
            .Returns(Task.FromResult(new AuthorizationInfo { User = null, Token = null }));

        Assert.IsType<UnauthorizedResult>(await harness.Controller.OidLogout("kc", ticket));
        await harness.SessionManager.DidNotReceive().Logout(Arg.Any<string>());
    }

    [Fact]
    public async Task WithSingleLogoutOff_AnOutstandingTicketIsRefused_AndTheStoreIsEmptied()
    {
        // The switch gated the mint and not the redeem (#1793), so turning Single Logout off - what an
        // operator does during an incident - left every outstanding ticket spendable for the rest of its
        // minute while the served page said both surfaces reject. The redeem sits behind the switch too, and
        // it empties the store on the way out, so the tokens those entries hold do not wait for a visitor.
        var harness = ForCaller(CallerToken, Caller);
        var ticket = MintedTicket(await harness.Controller.OidLogoutTicket("kc"));
        Assert.Equal(1, LogoutTicketService.OutstandingForTests);
        SSOPlugin.Instance.MutateConfiguration(c => c.EnableSingleLogout = false);
        harness.AuthContext.GetAuthorizationInfo(Arg.Any<HttpRequest>())
            .Returns(Task.FromResult(new AuthorizationInfo { User = null, Token = null }));

        Assert.IsType<UnauthorizedResult>(await harness.Controller.OidLogout("kc", ticket));

        await harness.SessionManager.DidNotReceive().Logout(Arg.Any<string>());
        Assert.Equal(0, LogoutTicketService.OutstandingForTests);
    }

    [Fact]
    public async Task TurningSingleLogoutOff_EmptiesTheStoreAtTheSave_AndASaveWithItOnDoesNot()
    {
        // The hosted service half of #1793: with no request arriving at either surface, the store still
        // empties at the moment the switch is saved off, and a save that leaves the switch on empties
        // nothing, because an unrelated configuration write must not refuse a sign-out already under way.
        var harness = ForCaller(CallerToken, Caller);
        var watcher = new LogoutTicketSwitchService();
        await watcher.StartAsync(CancellationToken.None);
        try
        {
            MintedTicket(await harness.Controller.OidLogoutTicket("kc"));
            Assert.Equal(1, LogoutTicketService.OutstandingForTests);

            SSOPlugin.Instance.MutateConfiguration(c => c.OidConfigs["kc"].OidClientId = "client-kc-2");
            Assert.Equal(1, LogoutTicketService.OutstandingForTests);

            SSOPlugin.Instance.MutateConfiguration(c => c.EnableSingleLogout = false);
            Assert.Equal(0, LogoutTicketService.OutstandingForTests);
        }
        finally
        {
            await watcher.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task ATokenThatResolvesToNoUser_IsRefused()
    {
        // A token carrying no user names nobody, and both gated paths go on to act on one. A null User with
        // a token present is a different shape from no token at all, and a gate reading the id alone would
        // pass a request that resolved to nobody straight into the route's work.
        var harness = ForCaller(CallerToken, Caller);
        harness.AuthContext.GetAuthorizationInfo(Arg.Any<HttpRequest>())
            .Returns(Task.FromResult(new AuthorizationInfo { User = null, Token = CallerToken }));

        Assert.IsType<UnauthorizedResult>(await harness.Controller.OidLogoutTicket("kc"));
        Assert.IsType<UnauthorizedResult>(await harness.Controller.OidLogout("kc"));
        await harness.SessionManager.DidNotReceive().Logout(Arg.Any<string>());
    }

    [Fact]
    public async Task EveryRefusalOnThisRoute_LeavesAnAuditLine()
    {
        // This route is reachable with no credential and it ends a session, and every other logout refusal
        // beside it records a fixed reason code. It is not the ONLY such route, which is what this comment
        // claimed: the inbound back-channel OpenID logout and the inbound SAML LogoutRequest are reachable
        // with no credential too, authenticating by signature rather than by header. A ticket-guessing flood that
        // left no trace would be invisible to an operator: the limiter's own line is generic, throttled,
        // and off by default. The reason codes are asserted rather than only the count, so the two refusals
        // stay distinguishable in the log.
        var harness = ForCaller(token: null);

        Assert.IsType<UnauthorizedResult>(await harness.Controller.OidLogout("kc", "no-such-ticket"));
        Assert.IsType<UnauthorizedResult>(await harness.Controller.OidLogout("kc"));

        var lines = string.Join(" | ", harness.ControllerLog.Entries.ConvertAll(e => e.Message));
        Assert.Contains("logout_ticket_not_redeemable", lines, StringComparison.Ordinal);
        Assert.Contains("logout_unauthenticated", lines, StringComparison.Ordinal);

        // AND THE SENTENCE, not only the code. The shared LogoutRejected helper is worded for the SAML
        // LogoutRequest sites, and routing an OpenID refusal into it is how #1184's defect - an operator
        // filtering for OpenID logout failures finding every one of them filed under SAML - comes back. An
        // earlier draft of this change did exactly that, and a row asserting reason codes alone was green
        // on it. The back-channel route's own suite pins its wording the same way, for the same reason.
        Assert.Contains("OpenID logout REFUSED", lines, StringComparison.Ordinal);
        Assert.DoesNotContain("SAML", lines, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ARefusedNavigationIsThrottledBeforeItIsAudited()
    {
        // The per-refusal log line has to sit BEHIND the gate. This route is reachable with no credential,
        // so a line written in front of the throttle amplifies the very flood the throttle blunts into
        // unbounded log volume - the hazard SsoRateLimiter states in its own words, and what every
        // neighbouring anonymous logout surface avoids by gating first. An earlier draft audited first.
        // A genuinely PUBLIC address. The limiter deliberately creates no bucket for a non-public source -
        // its structural mass-lockout defence - and the classifier counts the TEST-NET documentation
        // ranges among those, so a fixture using one would never throttle and this row would pass
        // vacuously on a route that gated nothing.
        var harness = ForCaller(token: null, clientIp: System.Net.IPAddress.Parse("8.8.4.77"), rateLimit: true);

        // Drive past the configured budget. Once the gate closes, the answer is the throttle's and the
        // audit trail stops growing, which is the property this row is about.
        ActionResult? last = null;
        for (var i = 0; i < 12; i++)
        {
            last = await harness.Controller.OidLogout("kc", "guess-" + i.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        Assert.IsNotType<UnauthorizedResult>(last);

        var audited = harness.ControllerLog.Entries
            .FindAll(e => e.Message.Contains("logout_ticket_not_redeemable", StringComparison.Ordinal))
            .Count;

        Assert.True(audited > 0, "no refusal was audited at all, so this row would pass on a route that logs nothing");
        Assert.True(audited < 12, $"every one of 12 refusals was audited despite the throttle closing: {audited}");
    }

    [Fact]
    public async Task ACredentiallessNavigationIsThrottledToo()
    {
        // The arm a caller reaches with NO credential and NO ticket at all. The [Authorize] attribute used
        // to refuse such a request before the method ran, at no cost and writing nothing; without a gate
        // here the replacement answers it by writing a warning line, at request rate, for anybody - which
        // is the log amplification this repository's own limiter names as a self-inflicted denial of
        // service on an anonymous endpoint. A caller holding a valid session never reaches this arm, so the
        // throttle cannot leave one of their sessions live.
        var harness = ForCaller(token: null, clientIp: System.Net.IPAddress.Parse("8.8.4.78"), rateLimit: true);

        ActionResult? last = null;
        for (var i = 0; i < 12; i++)
        {
            last = await harness.Controller.OidLogout("kc");
        }

        Assert.IsNotType<UnauthorizedResult>(last);

        var audited = harness.ControllerLog.Entries
            .FindAll(e => e.Message.Contains("logout_unauthenticated", StringComparison.Ordinal))
            .Count;

        Assert.True(audited > 0, "no refusal was audited at all, so this row would pass on a route that logs nothing");
        Assert.True(audited < 12, $"every one of 12 credential-less requests wrote a warning line despite the throttle closing: {audited}");
    }

    [Fact]
    public async Task ACredentiallessFlood_SpendsNothingOfTheMintsBudgetBehindTheSameAddress()
    {
        // The third Done-when of #1792, decided as a class of their own. The two credential-less arms charge
        // LogoutRefusal, so a flood of guesses from one public address closes THAT budget and leaves the
        // Logout budget the mint draws on untouched for the people behind the same address. A genuinely
        // public address, for the reason the throttle rows give, and a budget of three so the flood closes
        // it inside a handful of requests.
        var harness = ForCaller(token: null, clientIp: System.Net.IPAddress.Parse("8.8.4.80"), rateLimit: true);

        ActionResult? last = null;
        for (var i = 0; i < 6; i++)
        {
            last = await harness.Controller.OidLogout("kc", "guess-" + i.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        var throttled = Assert.IsType<ContentResult>(last);
        Assert.Equal(StatusCodes.Status429TooManyRequests, throttled.StatusCode);

        // The same address, now a signed-in caller asking for a ticket: the mint's class was never charged,
        // so it is issued one. With the arms back on the shared class this mint is the throttle's 429.
        harness.AuthContext.GetAuthorizationInfo(Arg.Any<HttpRequest>())
            .Returns(Task.FromResult(new AuthorizationInfo { User = TestUsers.Named("caller", Caller), Token = CallerToken }));

        MintedTicket(await harness.Controller.OidLogoutTicket("kc"));
    }

    [Fact]
    public async Task ACredentiallessFloodWithNoLimiterInFront_WritesABoundedNumberOfLines()
    {
        // The first Done-when of #1792. The gate in front of both credential-less arms is off on a stock
        // install and makes no bucket for a non-public peer, and on that configuration every request with
        // no credential wrote a warning line. This fixture is that configuration: the limiter off and the
        // peer loopback. The answers stay 401 throughout, because the bound is on the line and not on the
        // answer, and the lines stop at the budget.
        var harness = ForCaller(token: null, clientIp: System.Net.IPAddress.Loopback, rateLimit: false);
        var requests = 3 * LogoutTicketService.MaxRefusalLinesPerInterval;

        for (var i = 0; i < requests; i++)
        {
            Assert.IsType<UnauthorizedResult>(await harness.Controller.OidLogout("kc"));
        }

        var audited = harness.ControllerLog.Entries.FindAll(e => e.Message.Contains("logout_unauthenticated", StringComparison.Ordinal)).Count;
        Assert.Equal(LogoutTicketService.MaxRefusalLinesPerInterval, audited);

        // The ticket arm draws on the same budget rather than carrying one of its own, so a flood that
        // alternates between the two shapes is bounded by one ceiling and not by two.
        Assert.IsType<UnauthorizedResult>(await harness.Controller.OidLogout("kc", "guess"));
        Assert.DoesNotContain(harness.ControllerLog.Entries, e => e.Message.Contains("logout_ticket_not_redeemable", StringComparison.Ordinal));
    }

    [Fact]
    public async Task TheProviderARefusalLinePrints_IsBoundedInLength()
    {
        // The second Done-when of #1792. The provider is a route segment a caller with no credential
        // chooses, and the two sanitizers strip and substitute without shortening, so one request could
        // put a request line's worth of chosen text into the log. Driven through the route rather than
        // at the emitter, so what the row holds is that THIS route's line is bounded; the emitter's own
        // rows pin the mark and the cut.
        var harness = ForCaller(token: null);
        var chosen = new string('p', 8 * SsoAudit.MaxLoggedProviderChars);

        Assert.IsType<UnauthorizedResult>(await harness.Controller.OidLogout(chosen));

        var line = Assert.Single(harness.ControllerLog.Entries, e => e.Message.Contains("logout_unauthenticated", StringComparison.Ordinal)).Message;
        Assert.Contains(new string('p', SsoAudit.MaxLoggedProviderChars) + SsoAudit.ProviderCutMark, line, StringComparison.Ordinal);
        Assert.DoesNotContain(new string('p', SsoAudit.MaxLoggedProviderChars + 1), line, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ACompletedTicketLogout_LeavesAnAuditLine_NamingTheProtocolAndProvider()
    {
        // The refusals on this route were audited and its success was not, so a session ended for a request
        // whose only credential was a query-string ticket left no line of its own (#1795). The two inbound
        // logout routes that share the credential-less property both record their success; this row brings
        // the ticket form level with them, and asserts the words an operator filters on rather than a count.
        var harness = ForCaller(CallerToken, Caller);
        var ticket = MintedTicket(await harness.Controller.OidLogoutTicket("kc"));
        harness.AuthContext.GetAuthorizationInfo(Arg.Any<HttpRequest>())
            .Returns(Task.FromResult(new AuthorizationInfo { User = null, Token = null }));

        Assert.IsType<RedirectResult>(await harness.Controller.OidLogout("kc", ticket));

        var entry = Assert.Single(harness.ControllerLog.Entries, e => e.Message.Contains("[SSO Audit]", StringComparison.Ordinal));
        Assert.Equal(LogLevel.Information, entry.Level);
        Assert.Contains("OpenID logout completed", entry.Message, StringComparison.Ordinal);
        Assert.Contains("'kc'", entry.Message, StringComparison.Ordinal);
        Assert.Contains("end_session_redirect", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("SAML", entry.Message, StringComparison.Ordinal);

        // Neither credential reaches the line: not the ticket, which is a bearer for its minute, and not the
        // session token it was bound to.
        Assert.DoesNotContain(ticket, entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(CallerToken, entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ATicketLogoutThatReturnsLocally_SaysSoInItsAuditLine()
    {
        // "entra" has no captured session in the fixture, so the route ends the local session and returns
        // the browser to this server. The line says which of the two happened, as a fixed code, because an
        // operator reading a completion needs to know whether the provider was told.
        var harness = ForCaller(CallerToken, Caller);
        var ticket = MintedTicket(await harness.Controller.OidLogoutTicket("entra"));
        harness.AuthContext.GetAuthorizationInfo(Arg.Any<HttpRequest>())
            .Returns(Task.FromResult(new AuthorizationInfo { User = null, Token = null }));

        Assert.IsType<LocalRedirectResult>(await harness.Controller.OidLogout("entra", ticket));

        var entry = Assert.Single(harness.ControllerLog.Entries, e => e.Message.Contains("OpenID logout completed", StringComparison.Ordinal));
        Assert.Contains("'entra'", entry.Message, StringComparison.Ordinal);
        Assert.Contains("local_only", entry.Message, StringComparison.Ordinal);
        await harness.SessionManager.Received(1).Logout(CallerToken);
    }

    [Fact]
    public async Task AMint_RecordsNoIssuance()
    {
        // Decided rather than forgotten (#1795), and pinned so the decision cannot drift either way unargued.
        // The distinction a mint line would buy - spent tickets from guesses - is already drawn where a
        // ticket is spent, and this endpoint's rate bound is off on a stock install, so there a per-mint line
        // would be writable at request rate by any signed-in account. The reason is written at the endpoint.
        var harness = ForCaller(CallerToken, Caller);

        MintedTicket(await harness.Controller.OidLogoutTicket("kc"));

        Assert.DoesNotContain(harness.ControllerLog.Entries, e => e.Message.Contains("[SSO Audit]", StringComparison.Ordinal));
    }

    [Fact]
    public async Task TheCompletionLine_CarriesNothingTheCallerWrote()
    {
        // The provider is the one caller-authored value the line prints: it is route input, and the mint
        // carries it through unexamined, so a ticket can be minted for a name shaped like a second audit
        // record and spent at that same name. Both sanitizers are asserted on the RENDERED line, which is the
        // property the refusal event beside it already holds: no second physical line, and no second record
        // on this one.
        var harness = ForCaller(CallerToken, Caller);
        const string forged = "kc\r\n[SSO Audit] forged";
        var ticket = MintedTicket(await harness.Controller.OidLogoutTicket(forged));
        harness.AuthContext.GetAuthorizationInfo(Arg.Any<HttpRequest>())
            .Returns(Task.FromResult(new AuthorizationInfo { User = null, Token = null }));

        Assert.IsType<LocalRedirectResult>(await harness.Controller.OidLogout(forged, ticket));

        var entry = Assert.Single(harness.ControllerLog.Entries, e => e.Message.Contains("OpenID logout completed", StringComparison.Ordinal));
        Assert.DoesNotContain("\n", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("\r", entry.Message, StringComparison.Ordinal);

        // Only the OPENING bracket is substituted, because the prefix every entry is filtered on can only
        // begin with one; the closing bracket is left as the caller wrote it.
        Assert.Contains("'kc(SSO Audit] forged'", entry.Message, StringComparison.Ordinal);
        Assert.Equal(
            entry.Message.IndexOf("[SSO Audit]", StringComparison.Ordinal),
            entry.Message.LastIndexOf("[SSO Audit]", StringComparison.Ordinal));
    }

    [Fact]
    public async Task EveryMintIsADifferentTicket()
    {
        // A mint that returned a stable per-user value would satisfy the redeem rows above and would be a
        // long-lived credential in a URL, which is the exact thing this replaces.
        var harness = ForCaller(CallerToken, Caller);

        var first = MintedTicket(await harness.Controller.OidLogoutTicket("kc"));
        var second = MintedTicket(await harness.Controller.OidLogoutTicket("kc"));

        Assert.NotEqual(first, second);
    }
}
