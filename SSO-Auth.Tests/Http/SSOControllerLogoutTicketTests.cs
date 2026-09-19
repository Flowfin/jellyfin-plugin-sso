// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Logout;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
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
        bool rateLimit = false)
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
        },
            clientIp);

        // A null user is the unauthenticated shape: AuthorizationInfo resolves UserId to Guid.Empty, which is
        // exactly what the route's own gate reads, so the refusal rows exercise the real predicate rather
        // than a stand-in for it.
        var user = userId is null ? null : TestUsers.Named("caller", userId.Value);
        harness.AuthContext.GetAuthorizationInfo(Arg.Any<HttpRequest>())
            .Returns(Task.FromResult(new AuthorizationInfo { User = user, Token = token }));
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
    public async Task ACallerWithNoSessionToken_GetsNoTicket()
    {
        // A ticket carries the session it was minted from, so a caller the mint cannot bind one to must get
        // nothing rather than a ticket that would end nothing. 503 and not 500: the condition is temporary
        // from the caller's side and their own sign-out still works.
        var harness = ForCaller(token: null, userId: Caller);

        var result = await harness.Controller.OidLogoutTicket("kc");

        var refusal = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, refusal.StatusCode);
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
