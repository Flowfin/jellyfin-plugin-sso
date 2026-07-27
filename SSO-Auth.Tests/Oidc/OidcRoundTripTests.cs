// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// End-to-end OpenID round-trip tests (#192, layer 3) that drive the FULL plugin login flow —
/// <c>OidChallenge</c> → <c>OidCallback</c> → <c>OidAuth</c> — against a self-consistent in-test identity
/// provider, with NO test-seeded state. Unlike <see cref="SSOControllerOidAuthTests"/> (which seeds a
/// Ready state directly) and <see cref="SSOControllerOidPostTests"/> (whose callback tests seed the
/// Pending state via <c>ArrangeCallback</c>), here the state token, the PKCE <c>code_verifier</c>, and the
/// browser-binding cookie are all minted by the real challenge leg and carried through the redeem — so the
/// test proves those three legs agree on the exact values that pass between them, browser aside.
///
/// The fake IdP is the existing <see cref="OidcTokenFixture"/> (discovery document + JWKS + token endpoint
/// returning a real signed id_token), served in-process through <see cref="SsoControllerHarness"/>'s stub
/// HTTP responder — no new provider fake is introduced, since that fixture already IS a complete,
/// self-consistent OIDC provider surface.
///
/// The happy path asserts a valid signed id_token yields a logged-in outcome (an <see cref="OkObjectResult"/>
/// with the account provisioned exactly once). The negative round-trip signs the id_token with a key that
/// does NOT match the JWKS the same IdP advertises, so the real <see cref="OidcIdTokenValidator"/> rejects
/// it on signature — the callback fails closed with a 400 and the state is never promoted, so the redeem
/// mints nothing.
/// </summary>
[Collection("SSOController")]
public class OidcRoundTripTests
{
    private const string Authority = "https://idp-roundtrip.example.com";

    [Fact]
    public async Task ChallengeToCallbackToAuth_ValidSignedIdToken_YieldsLoggedInOutcome()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        // A valid id_token signed by the IdP's own key, carrying the sub + preferred_username the login keys
        // the account on (DoNotLoadProfile skips the userinfo fetch, so these claims are the whole identity).
        var idToken = fixture.IdToken(subject: "sub-1", username: "alice");
        var harness = BuildHarness(fixture, request => ServeIdp(fixture, request, idToken));

        // Provision hooks the completion tail drives for a first-time login of "alice".
        var user = TestUsers.Named("alice", Guid.Parse("19999999-1111-1111-1111-111111111111"));
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(user.Id).Returns(user);

        var (state, binding) = await DriveChallenge(harness);

        // Callback: OidcClient exchanges the code at the fake token endpoint and the real OidcIdTokenValidator
        // verifies the id_token signature against the fixture's advertised JWKS. Reaching the text/html auth
        // page (rather than a plain-text error) proves the exchange + signature + sub resolution all passed.
        RepointToCallback(harness, state, binding, query: $"?code=test-code&state={state}");
        var callback = Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state));
        Assert.Equal("text/html", callback.ContentType);

        // Authenticate: the browser-bound state minted by the challenge is redeemed once and the account is
        // provisioned. An OkObjectResult is the logged-in outcome the client completes the session from.
        var authed = await harness.Controller.OidAuth("kc", Redeem(state));
        Assert.IsType<OkObjectResult>(authed);
        await harness.UserManager.Received(1).CreateUserAsync("alice");
    }

    [Fact]
    public async Task ChallengeToCallback_IdTokenSignedByWrongKey_RejectedOnSignature_MintsNothing()
    {
        using var idp = new OidcTokenFixture(Authority, "jf");
        // A SECOND fixture with its own throw-away RSA key. Its id_token carries byte-for-byte valid claims
        // (same issuer, audience, lifetime) but is signed by a key the IdP does not advertise in its JWKS —
        // so only the signature is wrong. This is the real signature check under test, isolated from every
        // other validation (iss/aud/exp all match), exercising OidcIdTokenValidator against a self-consistent
        // fake IdP whose token was minted by a foreign key.
        using var foreignSigner = new OidcTokenFixture(Authority, "jf");
        var forgedToken = foreignSigner.IdToken(subject: "sub-1", username: "alice");
        var harness = BuildHarness(idp, request => ServeIdp(idp, request, forgedToken));

        var (state, binding) = await DriveChallenge(harness);

        // The callback must fail closed: the signature does not verify against the advertised JWKS, so the
        // real validator rejects and CallbackAsync returns the plain-text 400 login error (never the
        // text/html auth page). The body is the fixed generic message — the library's error detail
        // (invalid_signature) is logged server-side, not reflected into the browser page (#708) — so this
        // asserts the generic body and that the detail is absent rather than pinning on the reflected reason.
        RepointToCallback(harness, state, binding, query: $"?code=test-code&state={state}");
        var callback = Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state));
        Assert.Equal(400, callback.StatusCode);
        Assert.Equal("text/plain", callback.ContentType);
        Assert.Equal("Error logging in.", callback.Content);
        Assert.DoesNotContain("invalid_signature", callback.Content);

        // End-to-end fail-closed: because the callback never promoted the state to a redeemable Ready, the
        // authenticate leg finds no state to redeem and provisions nothing — no login is minted from a token
        // the IdP's own key did not sign.
        var authed = await harness.Controller.OidAuth("kc", Redeem(state));
        var content = Assert.IsType<ContentResult>(authed);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("Invalid or expired state", content.Content);
        await harness.UserManager.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task Challenge_SendsNoNonce_AndBindsTheCodeWithPkceS256()
    {
        // #1004. The plugin sends no OIDC nonce — neither OidcClient leg (6.0.1 on net9.0, 7.1.0 on net10.0)
        // emits one for the code flow, and the plugin adds none — so RFC 9700's PKCE binding is what ties the
        // code to this authorization request. That is a coherent posture, since OIDC Core 3.1.3.7 rule 11
        // requires validating a nonce only when one was sent; but it is coherent only as a PAIR, and the pair
        // is what this pins. The absence is READ OFF the real authorize URL rather than assumed, so the
        // property is established per TFM instead of resting on a claim about one library version.
        //
        // The regression it guards against is the shape of CVE-2026-42206: a nonce generated on the
        // authorization request and never validated on the callback, which is ID-token replay with a decorative
        // parameter attached. Adding a `nonce` to the authorize URL would fail no other test in this suite, so
        // without this assertion that lands silently. If a nonce is ever wanted, this test failing is the
        // prompt to build its validator in the same change.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var harness = BuildHarness(fixture, request => ServeIdp(fixture, request, fixture.IdToken("sub-1", "alice")));

        harness.Controller.HttpContext.Request.Path = "/sso/OID/start/kc";
        var challenge = Assert.IsType<RedirectResult>(await harness.Controller.OidChallenge("kc"));

        Assert.Equal(string.Empty, QueryValue(challenge.Url, "nonce"));
        Assert.NotEqual(string.Empty, QueryValue(challenge.Url, "code_challenge"));
        Assert.Equal("S256", QueryValue(challenge.Url, "code_challenge_method"));
    }

    [Fact]
    public async Task TokenRequest_RepeatsTheChallengeRedirectUriValue()
    {
        // #1004, RFC 6749 §4.1.3. Exact-string redirect_uri matching is the authorization server's check, and
        // the relying party's obligation is the input to it: the redirect_uri on the token request must be the
        // same value as the one on the authorization request, or the server refuses the exchange. Builder
        // equality is already pinned by OidcRedirectUriBuilderTests; that compares what the two builder methods
        // RETURN, while this compares what actually leaves the process — the authorize URL against the token
        // POST body.
        //
        // The comparison is of DECODED values, not of the wire bytes, and the test claims no more than that: a
        // URL query and an application/x-www-form-urlencoded body legitimately encode the same value
        // differently (a space is %20 in one and + in the other), so a byte-wise comparison across the two
        // carriers would fail on an identical value. What the AS compares is the decoded string, which is what
        // is compared here.
        //
        // What supplies the wire value was measured, not assumed: today it comes from OidcClient replaying the
        // redirect_uri stored on the AuthorizeState at challenge time, NOT from the callback-side builder. So a
        // divergence introduced in CallbackRedirectUri alone is invisible here (verified: a trailing slash
        // added to that builder fails the builder tests and leaves this one green). The regression this DOES
        // catch is the dangerous one — the callback-built value reaching the token request while disagreeing
        // with the challenge's, which is what a library upgrade that honours options.RedirectUri would cause.
        // Verified by making exactly that assignment: the test fails on the trailing slash.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        string? tokenRequestBody = null;
        var harness = BuildHarness(fixture, request =>
        {
            if (request.RequestUri!.AbsoluteUri == fixture.TokenUrl)
            {
                tokenRequestBody = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            }

            return ServeIdp(fixture, request, fixture.IdToken("sub-1", "alice"));
        });
        var user = TestUsers.Named("alice", Guid.Parse("19999999-1111-1111-1111-111111111116"));
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(user.Id).Returns(user);

        harness.Controller.HttpContext.Request.Path = "/sso/OID/start/kc";
        var challenge = Assert.IsType<RedirectResult>(await harness.Controller.OidChallenge("kc"));
        var state = QueryValue(challenge.Url, "state");
        var binding = BindingCookie(harness.Controller.Response);
        var challengeRedirectUri = QueryValue(challenge.Url, "redirect_uri");

        RepointToCallback(harness, state, binding, query: $"?code=test-code&state={state}");
        Assert.Equal("text/html", Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state)).ContentType);

        Assert.NotNull(tokenRequestBody);
        Assert.NotEqual(string.Empty, challengeRedirectUri);
        Assert.Equal(challengeRedirectUri, FormValue(tokenRequestBody, "redirect_uri"));
    }

    [Fact]
    public async Task RedeemResponse_NeverContainsTheIdToken_OnlyTheLocallyMintedSession()
    {
        // #1004. The id_token is a proof of authentication addressed to this plugin, not a bearer credential
        // for anything: handing it to the browser, or storing it as a session token, turns a one-shot login
        // assertion into something replayable against this server and against any other relying party that
        // trusts the same issuer without pinning the audience.
        //
        // Asserted empirically on the real flow rather than by scanning source for a token variable, because a
        // source scan proves only that one spelling of the leak is absent. Here the token is a known string and
        // all THREE places it could escape are inspected directly: the HTML the callback hands the browser,
        // every field of the AuthenticationRequest handed to Jellyfin's session manager, and the body returned
        // to the client. The callback page is inspected because it is the first thing that reaches the browser
        // and the only one an operator would not see in an API response — an id_token embedded in that markup
        // leaks to anything that can read the page. The only credential that may cross any of the three
        // boundaries is the session Jellyfin itself mints.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var idToken = fixture.IdToken(subject: "sub-1", username: "alice");
        var harness = BuildHarness(fixture, request => ServeIdp(fixture, request, idToken));
        var user = TestUsers.Named("alice", Guid.Parse("19999999-1111-1111-1111-111111111117"));
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(user.Id).Returns(user);

        // The session manager is stubbed to return a REAL result carrying a distinctive access token. An
        // unstubbed substitute returns null, and a "the response does not contain the id_token" assertion over
        // a null body passes without inspecting anything — the assertion would read as protection while
        // testing nothing. Pinning the minted token instead makes the test prove both halves: the id_token is
        // absent AND the credential that IS returned is the one Jellyfin minted.
        const string MintedToken = "minted-session-token";
        AuthenticationRequest? mintRequest = null;
        harness.SessionManager
            .AuthenticateDirect(Arg.Do<AuthenticationRequest>(r => mintRequest = r))
            .Returns(new AuthenticationResult { AccessToken = MintedToken });

        var (state, binding) = await DriveChallenge(harness);
        RepointToCallback(harness, state, binding, query: $"?code=test-code&state={state}");
        var callback = Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state));
        Assert.Equal("text/html", callback.ContentType);
        Assert.NotNull(callback.Content);
        Assert.DoesNotContain(idToken, callback.Content, StringComparison.Ordinal);

        var authed = Assert.IsType<OkObjectResult>(await harness.Controller.OidAuth("kc", Redeem(state)));

        // The mint really happened and really belongs to this login, so the field scan below is not walking an
        // empty object.
        Assert.NotNull(mintRequest);
        Assert.Equal("alice", mintRequest.Username);
        foreach (var field in new[]
        {
            mintRequest.Username, mintRequest.App, mintRequest.AppVersion,
            mintRequest.DeviceId, mintRequest.DeviceName, mintRequest.RemoteEndPoint, mintRequest.Password,
        })
        {
            Assert.DoesNotContain(idToken, field ?? string.Empty, StringComparison.Ordinal);
        }

        // The body handed back to the client is the minted Jellyfin session and nothing else.
        var body = JsonSerializer.Serialize(authed.Value);
        Assert.Contains(MintedToken, body, StringComparison.Ordinal);
        Assert.DoesNotContain(idToken, body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Challenge_StepUpConfigured_SendsAcrValuesPromptAndMaxAgeOnTheAuthorizeRequest()
    {
        // #757 part A: the configured acr_values / prompt / max_age appear on the authorization redirect.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var harness = BuildHarness(fixture, request => ServeIdp(fixture, request, fixture.IdToken("sub-1", "alice")), cfg =>
        {
            cfg.AcrValues = "phr mfa";
            cfg.Prompt = "login";
            cfg.MaxAge = 0;
        });

        harness.Controller.HttpContext.Request.Path = "/sso/OID/start/kc";
        var challenge = Assert.IsType<RedirectResult>(await harness.Controller.OidChallenge("kc"));

        Assert.Equal("phr mfa", QueryValue(challenge.Url, "acr_values"));
        Assert.Equal("login", QueryValue(challenge.Url, "prompt"));
        Assert.Equal("0", QueryValue(challenge.Url, "max_age"));
    }

    [Fact]
    public async Task Challenge_NoStepUpConfigured_OmitsTheStepUpParameters()
    {
        // Upgrade-safe: an unconfigured provider's authorize request carries none of the step-up parameters.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var harness = BuildHarness(fixture, request => ServeIdp(fixture, request, fixture.IdToken("sub-1", "alice")));

        harness.Controller.HttpContext.Request.Path = "/sso/OID/start/kc";
        var challenge = Assert.IsType<RedirectResult>(await harness.Controller.OidChallenge("kc"));

        Assert.Equal(string.Empty, QueryValue(challenge.Url, "acr_values"));
        Assert.Equal(string.Empty, QueryValue(challenge.Url, "prompt"));
        Assert.Equal(string.Empty, QueryValue(challenge.Url, "max_age"));
    }

    [Fact]
    public async Task RequireAcr_MatchingAcrClaim_YieldsLoggedInOutcome()
    {
        // #757 part B, happy path: RequireAcr on + the id_token returns an acr within the allow-list ⇒ login.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var idToken = fixture.IdToken(subject: "sub-1", username: "alice", acr: "mfa");
        var harness = BuildHarness(fixture, request => ServeIdp(fixture, request, idToken), cfg =>
        {
            cfg.AcrValues = "phr mfa";
            cfg.RequireAcr = true;
        });
        var user = TestUsers.Named("alice", Guid.Parse("19999999-1111-1111-1111-111111111112"));
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(user.Id).Returns(user);

        var (state, binding) = await DriveChallenge(harness);
        RepointToCallback(harness, state, binding, query: $"?code=test-code&state={state}");
        var callback = Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state));
        Assert.Equal("text/html", callback.ContentType);

        var authed = await harness.Controller.OidAuth("kc", Redeem(state));
        Assert.IsType<OkObjectResult>(authed);
        await harness.UserManager.Received(1).CreateUserAsync("alice");
    }

    [Theory]
    [InlineData("basic")] // an acr outside the allow-list
    [InlineData(null)] // no acr claim at all
    public async Task RequireAcr_MissingOrWrongAcr_RejectsAtCallback_MintsNothing(string? acr)
    {
        // #757 part B, fail-closed: RequireAcr on but the returned acr is absent or not in the allow-list ⇒
        // the callback denies before promoting a Ready, so the redeem finds no state and mints nothing.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var idToken = fixture.IdToken(subject: "sub-1", username: "alice", acr: acr);
        var harness = BuildHarness(fixture, request => ServeIdp(fixture, request, idToken), cfg =>
        {
            cfg.AcrValues = "mfa";
            cfg.RequireAcr = true;
        });

        var (state, binding) = await DriveChallenge(harness);
        RepointToCallback(harness, state, binding, query: $"?code=test-code&state={state}");
        var callback = Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state));
        Assert.Equal(403, callback.StatusCode);

        var authed = await harness.Controller.OidAuth("kc", Redeem(state));
        var content = Assert.IsType<ContentResult>(authed);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("Invalid or expired state", content.Content);
        await harness.UserManager.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task MaxAgeConfigured_FreshAuthTime_YieldsLoggedInOutcome()
    {
        // #961 happy path: MaxAge set + the id_token carries a recent auth_time within the window ⇒ login.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var recent = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 30;
        var idToken = fixture.IdToken(subject: "sub-1", username: "alice", authTimeUnixSeconds: recent);
        var harness = BuildHarness(fixture, request => ServeIdp(fixture, request, idToken), cfg => cfg.MaxAge = 300);
        var user = TestUsers.Named("alice", Guid.Parse("19999999-1111-1111-1111-111111111114"));
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(user.Id).Returns(user);

        var (state, binding) = await DriveChallenge(harness);
        RepointToCallback(harness, state, binding, query: $"?code=test-code&state={state}");
        Assert.Equal("text/html", Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state)).ContentType);
        Assert.IsType<OkObjectResult>(await harness.Controller.OidAuth("kc", Redeem(state)));
        await harness.UserManager.Received(1).CreateUserAsync("alice");
    }

    [Fact]
    public async Task MaxAgeConfigured_MissingAuthTime_RejectsAtCallback_MintsNothing()
    {
        // #961 fail-closed: MaxAge set but the provider ignored max_age and returned no auth_time ⇒ the
        // callback denies before promoting a Ready, so the redeem finds no state and mints nothing. This is
        // the whole point of the gate — a provider that ignores max_age must not pass silently.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var idToken = fixture.IdToken(subject: "sub-1", username: "alice"); // no auth_time
        var harness = BuildHarness(fixture, request => ServeIdp(fixture, request, idToken), cfg => cfg.MaxAge = 300);

        var (state, binding) = await DriveChallenge(harness);
        RepointToCallback(harness, state, binding, query: $"?code=test-code&state={state}");
        Assert.Equal(403, Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state)).StatusCode);

        var content = Assert.IsType<ContentResult>(await harness.Controller.OidAuth("kc", Redeem(state)));
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("Invalid or expired state", content.Content);
        await harness.UserManager.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task MaxAgeConfigured_StaleAuthTime_RejectsAtCallback_MintsNothing()
    {
        // #961 fail-closed: MaxAge set + auth_time older than the window+skew ⇒ the user authenticated too
        // long ago, denied.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var stale = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 3600;
        var idToken = fixture.IdToken(subject: "sub-1", username: "alice", authTimeUnixSeconds: stale);
        var harness = BuildHarness(fixture, request => ServeIdp(fixture, request, idToken), cfg => cfg.MaxAge = 300);

        var (state, binding) = await DriveChallenge(harness);
        RepointToCallback(harness, state, binding, query: $"?code=test-code&state={state}");
        Assert.Equal(403, Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state)).StatusCode);
        await harness.UserManager.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task MaxAgeUnset_NoAuthTime_YieldsLoggedInOutcome()
    {
        // Upgrade-safe: with MaxAge unset, an id_token without auth_time logs in unchanged (no new gate).
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var harness = BuildHarness(fixture, request => ServeIdp(fixture, request, fixture.IdToken("sub-1", "alice")));
        var user = TestUsers.Named("alice", Guid.Parse("19999999-1111-1111-1111-111111111115"));
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(user.Id).Returns(user);

        var (state, binding) = await DriveChallenge(harness);
        RepointToCallback(harness, state, binding, query: $"?code=test-code&state={state}");
        Assert.Equal("text/html", Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state)).ContentType);
        Assert.IsType<OkObjectResult>(await harness.Controller.OidAuth("kc", Redeem(state)));
    }

    [Fact]
    public async Task RequireAcrOff_NoAcrClaim_YieldsLoggedInOutcome()
    {
        // Default: with RequireAcr off, an id_token that carries no acr logs in unchanged (no new gate).
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var harness = BuildHarness(fixture, request => ServeIdp(fixture, request, fixture.IdToken("sub-1", "alice")));
        var user = TestUsers.Named("alice", Guid.Parse("19999999-1111-1111-1111-111111111113"));
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(user.Id).Returns(user);

        var (state, binding) = await DriveChallenge(harness);
        RepointToCallback(harness, state, binding, query: $"?code=test-code&state={state}");
        Assert.Equal("text/html", Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state)).ContentType);
        Assert.IsType<OkObjectResult>(await harness.Controller.OidAuth("kc", Redeem(state)));
    }

    [Fact]
    public async Task LinkingChallenge_ThreadsIsLinkingIntoTheRegisteredState()
    {
        // #928 U6: the OIDC linking-mode challenge was never driven end-to-start — only hand-seeded states
        // carried the flag. isLinking=true through the real OidChallenge must register an authorize state
        // whose summary says linking, which is what the callback later uses to route to the link workflow
        // instead of a login.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var harness = BuildHarness(fixture, request => ServeIdp(fixture, request, fixture.IdToken("sub-1", "alice")));

        harness.Controller.HttpContext.Request.Path = "/sso/OID/start/kc";
        Assert.IsType<RedirectResult>(await harness.Controller.OidChallenge("kc", isLinking: true));

        var ok = Assert.IsType<OkObjectResult>(harness.Controller.OidStates());
        var summaries = Assert.IsAssignableFrom<System.Collections.Generic.IEnumerable<OidcStateStore.Summary>>(ok.Value);
        var summary = Assert.Single(summaries);
        Assert.True(summary.IsLinking);
        Assert.Equal("kc", summary.Provider);
    }

    [Fact]
    public async Task ParAdvertisedAndEnabled_ChallengePushesTheRequest_AndRedirectsByRequestUri()
    {
        // #928 U3: PAR is ON by default in production (DisablePushedAuthorization defaults false), yet no
        // test anywhere exercised the enabled path. With the provider advertising the RFC 9126 endpoint and
        // the default config, the challenge must POST the authorization parameters to the PAR endpoint and
        // redirect with ONLY request_uri + client_id — no code_challenge/redirect_uri/scope in the front
        // channel (that is PAR's confidentiality point).
        using var fixture = new OidcTokenFixture(Authority, "jf");
        string? pushedBody = null;
        var harness = BuildHarness(
            fixture,
            request =>
            {
                if (request.RequestUri!.AbsoluteUri == fixture.ParUrl)
                {
                    pushedBody = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
                    return Json("{\"request_uri\":\"urn:ietf:params:oauth:request_uri:par-1\",\"expires_in\":60}");
                }

                return ServeIdp(fixture, request, fixture.IdToken("sub-1", "alice"), advertisePar: true);
            },
            cfg => cfg.DisablePushedAuthorization = false);

        var challenge = Assert.IsType<RedirectResult>(await harness.Controller.OidChallenge("kc"));

        Assert.NotNull(pushedBody);
        Assert.Contains("code_challenge", pushedBody, StringComparison.Ordinal);
        Assert.Contains("redirect_uri", pushedBody, StringComparison.Ordinal);
        Assert.StartsWith(Authority + "/authorize", challenge.Url, StringComparison.Ordinal);
        Assert.Contains("request_uri=", challenge.Url, StringComparison.Ordinal);
        Assert.DoesNotContain("code_challenge", challenge.Url, StringComparison.Ordinal);
        Assert.DoesNotContain("redirect_uri", challenge.Url, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ParAdvertisedButPushFails_ChallengeFailsClosed_NeverDowngradesToAPlainRedirect()
    {
        // The fail-closed half: when the advertised PAR endpoint errors, the challenge must NOT silently
        // fall back to a plain front-channel redirect (that downgrade would defeat the reason an operator
        // deployed PAR). It fails the login attempt instead.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var harness = BuildHarness(
            fixture,
            request => request.RequestUri!.AbsoluteUri == fixture.ParUrl
                ? new HttpResponseMessage(HttpStatusCode.InternalServerError)
                : ServeIdp(fixture, request, fixture.IdToken("sub-1", "alice"), advertisePar: true),
            cfg => cfg.DisablePushedAuthorization = false);

        var result = await harness.Controller.OidChallenge("kc");

        Assert.IsNotType<RedirectResult>(result);
    }

    [Fact]
    public async Task ParEnabledButNotAdvertised_ChallengeUsesThePlainRedirect()
    {
        // The compatibility half of the production default: a provider that advertises no PAR endpoint
        // still gets the ordinary front-channel redirect — PAR-on is safe against non-PAR providers, which
        // is what makes default-on shippable.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var harness = BuildHarness(
            fixture,
            request => ServeIdp(fixture, request, fixture.IdToken("sub-1", "alice")),
            cfg => cfg.DisablePushedAuthorization = false);

        var challenge = Assert.IsType<RedirectResult>(await harness.Controller.OidChallenge("kc"));

        Assert.StartsWith(Authority + "/authorize", challenge.Url, StringComparison.Ordinal);
        Assert.Contains("code_challenge", challenge.Url, StringComparison.Ordinal);
        Assert.DoesNotContain("request_uri=", challenge.Url, StringComparison.Ordinal);
    }

    // Builds a harness with a single enabled provider "kc" pointed at the fixture's authority, served by the
    // supplied responder. DisablePushedAuthorization keeps the challenge to a plain redirect; DoNotLoadProfile
    // makes the id_token claims the whole identity (no userinfo fetch); EnableAuthorization/AllowExistingAccountLink
    // are off to keep the redeem on the first-time-provision path these round-trips assert.
    private static SsoControllerHarness BuildHarness(OidcTokenFixture fixture, Func<HttpRequestMessage, HttpResponseMessage> responder, Action<OidConfig>? configure = null) =>
        new SsoControllerHarness(
            c =>
            {
                var cfg = new OidConfig
                {
                    Enabled = true,
                    OidEndpoint = fixture.Issuer,
                    OidClientId = fixture.ClientId,
                    OidScopes = Array.Empty<string>(),
                    DisablePushedAuthorization = true,
                    DoNotLoadProfile = true,
                    EnableAuthorization = false,
                    AllowExistingAccountLink = false,
                };
                configure?.Invoke(cfg);
                c.OidConfigs["kc"] = cfg;
            },
            httpResponder: responder);

    // Serves the fixture's discovery, JWKS, and token endpoints; any other URL 404s so a regression that
    // reaches an unexpected endpoint is caught. The token endpoint returns the supplied id_token.
    private static HttpResponseMessage ServeIdp(OidcTokenFixture fixture, HttpRequestMessage request, string idToken, bool advertisePar = false)
    {
        var url = request.RequestUri!.AbsoluteUri;
        if (url == fixture.DiscoveryUrl)
        {
            return Json(fixture.Discovery(advertisePar: advertisePar));
        }

        if (url == fixture.JwksUrl)
        {
            return Json(fixture.Jwks());
        }

        return url == fixture.TokenUrl
            ? Json(fixture.TokenEndpointJson(idToken))
            : new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    // Drives a real OidChallenge on the descriptive start route and returns the state token + browser-binding
    // cookie value it minted — the exact pair the callback and redeem legs must present.
    private static async Task<(string State, string Binding)> DriveChallenge(SsoControllerHarness harness)
    {
        harness.Controller.HttpContext.Request.Path = "/sso/OID/start/kc";
        var challenge = Assert.IsType<RedirectResult>(await harness.Controller.OidChallenge("kc"));
        Assert.StartsWith(Authority + "/authorize", challenge.Url);

        var state = QueryValue(challenge.Url, "state");
        Assert.False(string.IsNullOrEmpty(state));
        var binding = BindingCookie(harness.Controller.Response);
        Assert.False(string.IsNullOrEmpty(binding));
        return (state, binding);
    }

    // Re-points the same context at the callback route the IdP redirects back to, carrying the browser-binding
    // cookie the challenge set (#326) so the state's binding gate is satisfied, and sets the callback query.
    private static void RepointToCallback(SsoControllerHarness harness, string state, string binding, string query)
    {
        harness.Controller.HttpContext.Request.Path = "/sso/OID/redirect/kc";
        harness.Controller.HttpContext.Request.QueryString = new QueryString(query);
        harness.Controller.HttpContext.Request.Headers.Cookie = $"{AuthorizeStateBinding.CookieName}={binding}";
    }

    // A fully-populated redeem request for the given state token.
    private static AuthResponse Redeem(string state) => new AuthResponse
    {
        Data = state,
        DeviceID = "device-1",
        DeviceName = "Test Device",
        AppName = "Jellyfin Web",
        AppVersion = "1.0",
    };

    // Reads a single query-parameter value out of the challenge's authorization redirect URL.
    private static string QueryValue(string url, string key)
    {
        foreach (var pair in new Uri(url).Query.TrimStart('?').Split('&'))
        {
            var kv = pair.Split('=', 2);
            if (kv.Length == 2 && kv[0] == key)
            {
                return Uri.UnescapeDataString(kv[1]);
            }
        }

        return string.Empty;
    }

    // Reads a single value out of an application/x-www-form-urlencoded request body (the token POST). Kept
    // separate from QueryValue because the body is not a URL: the parse must not depend on a Uri that a
    // malformed body would make un-constructible, and the test would then fail for the wrong reason.
    private static string FormValue(string body, string key)
    {
        foreach (var pair in body.Split('&'))
        {
            var kv = pair.Split('=', 2);
            if (kv.Length == 2 && kv[0] == key)
            {
                return Uri.UnescapeDataString(kv[1].Replace('+', ' '));
            }
        }

        return string.Empty;
    }

    // Extracts the browser-binding cookie value the challenge wrote to the response's Set-Cookie header.
    private static string BindingCookie(HttpResponse response)
    {
        var prefix = AuthorizeStateBinding.CookieName + "=";
        foreach (var header in response.Headers.SetCookie)
        {
            if (header is not null && header.StartsWith(prefix, StringComparison.Ordinal))
            {
                var value = header.Substring(prefix.Length);
                var end = value.IndexOf(';');
                return end >= 0 ? value.Substring(0, end) : value;
            }
        }

        return string.Empty;
    }

    private static HttpResponseMessage Json(string body) =>
        new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
}
