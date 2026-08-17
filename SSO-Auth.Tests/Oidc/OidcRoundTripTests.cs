// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// End-to-end OpenID round-trip tests (#192, layer 3) that drive the FULL plugin login flow -
/// <c>OidChallenge</c> → <c>OidCallback</c> → <c>OidAuth</c> - against a self-consistent in-test identity
/// provider, with NO test-seeded state. Unlike <see cref="SSOControllerOidAuthTests"/> (which seeds a
/// Ready state directly) and <see cref="SSOControllerOidPostTests"/> (whose callback tests seed the
/// Pending state via <c>ArrangeCallback</c>), here the state token, the PKCE <c>code_verifier</c>, and the
/// browser-binding cookie are all minted by the real challenge leg and carried through the redeem - so the
/// test proves those three legs agree on the exact values that pass between them, browser aside.
///
/// The fake IdP is the existing <see cref="OidcTokenFixture"/> (discovery document + JWKS + token endpoint
/// returning a real signed id_token), served in-process through <see cref="SsoControllerHarness"/>'s stub
/// HTTP responder - no new provider fake is introduced, since that fixture already IS a complete,
/// self-consistent OIDC provider surface.
///
/// The happy path asserts a valid signed id_token yields a logged-in outcome (an <see cref="OkObjectResult"/>
/// with the account provisioned exactly once). The negative round-trip signs the id_token with a key that
/// does NOT match the JWKS the same IdP advertises, so the real <see cref="OidcIdTokenValidator"/> rejects
/// it on signature - the callback fails closed with a 400 and the state is never promoted, so the redeem
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
        var harness = OidcRoundTrip.BuildHarness(fixture, request => OidcRoundTrip.ServeIdp(fixture, request, idToken));

        // Provision hooks the completion tail drives for a first-time login of "alice".
        var user = TestUsers.Named("alice", Guid.Parse("19999999-1111-1111-1111-111111111111"));
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(user.Id).Returns(user);

        var (state, binding) = await OidcRoundTrip.DriveChallenge(harness, fixture);

        // Callback: OidcClient exchanges the code at the fake token endpoint and the real OidcIdTokenValidator
        // verifies the id_token signature against the fixture's advertised JWKS. Reaching the text/html auth
        // page (rather than a plain-text error) proves the exchange + signature + sub resolution all passed.
        OidcRoundTrip.RepointToCallback(harness, binding, query: $"?code=test-code&state={state}");
        var callback = Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state));
        Assert.Equal("text/html", callback.ContentType);

        // Authenticate: the browser-bound state minted by the challenge is redeemed once and the account is
        // provisioned. An OkObjectResult is the logged-in outcome the client completes the session from.
        var authed = await harness.Controller.OidAuth("kc", OidcRoundTrip.Redeem(state));
        Assert.IsType<OkObjectResult>(authed);
        await harness.UserManager.Received(1).CreateUserAsync("alice");
    }

    [Fact]
    public async Task ChallengeToCallback_IdTokenSignedByWrongKey_RejectedOnSignature_MintsNothing()
    {
        using var idp = new OidcTokenFixture(Authority, "jf");
        // A SECOND fixture with its own throw-away RSA key. Its id_token carries byte-for-byte valid claims
        // (same issuer, audience, lifetime) but is signed by a key the IdP does not advertise in its JWKS -
        // so only the signature is wrong. This is the real signature check under test, isolated from every
        // other validation (iss/aud/exp all match), exercising OidcIdTokenValidator against a self-consistent
        // fake IdP whose token was minted by a foreign key.
        using var foreignSigner = new OidcTokenFixture(Authority, "jf");
        var forgedToken = foreignSigner.IdToken(subject: "sub-1", username: "alice");
        var harness = OidcRoundTrip.BuildHarness(idp, request => OidcRoundTrip.ServeIdp(idp, request, forgedToken));

        var (state, binding) = await OidcRoundTrip.DriveChallenge(harness, idp);

        // The callback must fail closed: the signature does not verify against the advertised JWKS, so the
        // real validator rejects and CallbackAsync returns the plain-text 400 login error (never the
        // text/html auth page). The body is the fixed generic message - the library's error detail
        // (invalid_signature) is logged server-side, not reflected into the browser page (#708) - so this
        // asserts the generic body and that the detail is absent rather than pinning on the reflected reason.
        OidcRoundTrip.RepointToCallback(harness, binding, query: $"?code=test-code&state={state}");
        var callback = Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state));
        Assert.Equal(400, callback.StatusCode);
        Assert.Equal("text/plain", callback.ContentType);
        Assert.Equal("Error logging in.", callback.Content);
        Assert.DoesNotContain("invalid_signature", callback.Content);

        // End-to-end fail-closed: because the callback never promoted the state to a redeemable Ready, the
        // authenticate leg finds no state to redeem and provisions nothing - no login is minted from a token
        // the IdP's own key did not sign.
        var authed = await harness.Controller.OidAuth("kc", OidcRoundTrip.Redeem(state));
        var content = Assert.IsType<ContentResult>(authed);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("Invalid or expired state", content.Content);
        await harness.UserManager.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task Challenge_StepUpConfigured_SendsAcrValuesPromptAndMaxAgeOnTheAuthorizeRequest()
    {
        // #757 part A: the configured acr_values / prompt / max_age appear on the authorization redirect.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var harness = OidcRoundTrip.BuildHarness(fixture, request => OidcRoundTrip.ServeIdp(fixture, request, fixture.IdToken("sub-1", "alice")), cfg =>
        {
            cfg.AcrValues = "phr mfa";
            cfg.Prompt = "login";
            cfg.MaxAge = 0;
        });

        harness.Controller.HttpContext.Request.Path = "/sso/OID/start/kc";
        var challenge = Assert.IsType<RedirectResult>(await harness.Controller.OidChallenge("kc"));

        Assert.Equal("phr mfa", UrlEncodedQuery.Require(challenge.Url, "acr_values"));
        Assert.Equal("login", UrlEncodedQuery.Require(challenge.Url, "prompt"));
        Assert.Equal("0", UrlEncodedQuery.Require(challenge.Url, "max_age"));
    }

    [Fact]
    public async Task Challenge_NoStepUpConfigured_OmitsTheStepUpParameters()
    {
        // Upgrade-safe: an unconfigured provider's authorize request carries none of the step-up parameters.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var harness = OidcRoundTrip.BuildHarness(fixture, request => OidcRoundTrip.ServeIdp(fixture, request, fixture.IdToken("sub-1", "alice")));

        harness.Controller.HttpContext.Request.Path = "/sso/OID/start/kc";
        var challenge = Assert.IsType<RedirectResult>(await harness.Controller.OidChallenge("kc"));

        // Omitted means the name is absent from the query, not present with an empty value: the builder adds
        // each pair only when its setting is set (OidcFrontChannelParameters), and the copy this file used to
        // carry could not tell those two apart.
        Assert.Null(UrlEncodedQuery.Find(challenge.Url, "acr_values"));
        Assert.Null(UrlEncodedQuery.Find(challenge.Url, "prompt"));
        Assert.Null(UrlEncodedQuery.Find(challenge.Url, "max_age"));
    }

    [Fact]
    public async Task RequireAcr_MatchingAcrClaim_YieldsLoggedInOutcome()
    {
        // #757 part B, happy path: RequireAcr on + the id_token returns an acr within the allow-list ⇒ login.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var idToken = fixture.IdToken(subject: "sub-1", username: "alice", acr: "mfa");
        var harness = OidcRoundTrip.BuildHarness(fixture, request => OidcRoundTrip.ServeIdp(fixture, request, idToken), cfg =>
        {
            cfg.AcrValues = "phr mfa";
            cfg.RequireAcr = true;
        });
        var user = TestUsers.Named("alice", Guid.Parse("19999999-1111-1111-1111-111111111112"));
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(user.Id).Returns(user);

        var (state, binding) = await OidcRoundTrip.DriveChallenge(harness, fixture);
        OidcRoundTrip.RepointToCallback(harness, binding, query: $"?code=test-code&state={state}");
        var callback = Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state));
        Assert.Equal("text/html", callback.ContentType);

        var authed = await harness.Controller.OidAuth("kc", OidcRoundTrip.Redeem(state));
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
        var harness = OidcRoundTrip.BuildHarness(fixture, request => OidcRoundTrip.ServeIdp(fixture, request, idToken), cfg =>
        {
            cfg.AcrValues = "mfa";
            cfg.RequireAcr = true;
        });

        var (state, binding) = await OidcRoundTrip.DriveChallenge(harness, fixture);
        OidcRoundTrip.RepointToCallback(harness, binding, query: $"?code=test-code&state={state}");
        var callback = Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state));
        Assert.Equal(403, callback.StatusCode);

        var authed = await harness.Controller.OidAuth("kc", OidcRoundTrip.Redeem(state));
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
        var harness = OidcRoundTrip.BuildHarness(fixture, request => OidcRoundTrip.ServeIdp(fixture, request, idToken), cfg => cfg.MaxAge = 300);
        var user = TestUsers.Named("alice", Guid.Parse("19999999-1111-1111-1111-111111111114"));
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(user.Id).Returns(user);

        var (state, binding) = await OidcRoundTrip.DriveChallenge(harness, fixture);
        OidcRoundTrip.RepointToCallback(harness, binding, query: $"?code=test-code&state={state}");
        Assert.Equal("text/html", Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state)).ContentType);
        Assert.IsType<OkObjectResult>(await harness.Controller.OidAuth("kc", OidcRoundTrip.Redeem(state)));
        await harness.UserManager.Received(1).CreateUserAsync("alice");
    }

    [Fact]
    public async Task MaxAgeConfigured_MissingAuthTime_RejectsAtCallback_MintsNothing()
    {
        // #961 fail-closed: MaxAge set but the provider ignored max_age and returned no auth_time ⇒ the
        // callback denies before promoting a Ready, so the redeem finds no state and mints nothing. This is
        // the whole point of the gate - a provider that ignores max_age must not pass silently.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var idToken = fixture.IdToken(subject: "sub-1", username: "alice"); // no auth_time
        var harness = OidcRoundTrip.BuildHarness(fixture, request => OidcRoundTrip.ServeIdp(fixture, request, idToken), cfg => cfg.MaxAge = 300);

        var (state, binding) = await OidcRoundTrip.DriveChallenge(harness, fixture);
        OidcRoundTrip.RepointToCallback(harness, binding, query: $"?code=test-code&state={state}");
        Assert.Equal(403, Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state)).StatusCode);

        var content = Assert.IsType<ContentResult>(await harness.Controller.OidAuth("kc", OidcRoundTrip.Redeem(state)));
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
        var harness = OidcRoundTrip.BuildHarness(fixture, request => OidcRoundTrip.ServeIdp(fixture, request, idToken), cfg => cfg.MaxAge = 300);

        var (state, binding) = await OidcRoundTrip.DriveChallenge(harness, fixture);
        OidcRoundTrip.RepointToCallback(harness, binding, query: $"?code=test-code&state={state}");
        Assert.Equal(403, Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state)).StatusCode);
        await harness.UserManager.DidNotReceive().CreateUserAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task MaxAgeUnset_NoAuthTime_YieldsLoggedInOutcome()
    {
        // Upgrade-safe: with MaxAge unset, an id_token without auth_time logs in unchanged (no new gate).
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var harness = OidcRoundTrip.BuildHarness(fixture, request => OidcRoundTrip.ServeIdp(fixture, request, fixture.IdToken("sub-1", "alice")));
        var user = TestUsers.Named("alice", Guid.Parse("19999999-1111-1111-1111-111111111115"));
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(user.Id).Returns(user);

        var (state, binding) = await OidcRoundTrip.DriveChallenge(harness, fixture);
        OidcRoundTrip.RepointToCallback(harness, binding, query: $"?code=test-code&state={state}");
        Assert.Equal("text/html", Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state)).ContentType);
        Assert.IsType<OkObjectResult>(await harness.Controller.OidAuth("kc", OidcRoundTrip.Redeem(state)));
    }

    [Fact]
    public async Task RequireAcrOff_NoAcrClaim_YieldsLoggedInOutcome()
    {
        // Default: with RequireAcr off, an id_token that carries no acr logs in unchanged (no new gate).
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var harness = OidcRoundTrip.BuildHarness(fixture, request => OidcRoundTrip.ServeIdp(fixture, request, fixture.IdToken("sub-1", "alice")));
        var user = TestUsers.Named("alice", Guid.Parse("19999999-1111-1111-1111-111111111113"));
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(user.Id).Returns(user);

        var (state, binding) = await OidcRoundTrip.DriveChallenge(harness, fixture);
        OidcRoundTrip.RepointToCallback(harness, binding, query: $"?code=test-code&state={state}");
        Assert.Equal("text/html", Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state)).ContentType);
        Assert.IsType<OkObjectResult>(await harness.Controller.OidAuth("kc", OidcRoundTrip.Redeem(state)));
    }

    [Fact]
    public async Task LinkingChallenge_ThreadsIsLinkingIntoTheRegisteredState()
    {
        // #928 U6: the OIDC linking-mode challenge was never driven end-to-start - only hand-seeded states
        // carried the flag. isLinking=true through the real OidChallenge must register an authorize state
        // whose summary says linking, which is what the callback later uses to route to the link workflow
        // instead of a login.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var harness = OidcRoundTrip.BuildHarness(fixture, request => OidcRoundTrip.ServeIdp(fixture, request, fixture.IdToken("sub-1", "alice")));

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
        // redirect with ONLY request_uri + client_id - no code_challenge/redirect_uri/scope in the front
        // channel (that is PAR's confidentiality point).
        using var fixture = new OidcTokenFixture(Authority, "jf");
        string? pushedBody = null;
        var harness = OidcRoundTrip.BuildHarness(
            fixture,
            request =>
            {
                if (request.RequestUri!.AbsoluteUri == fixture.ParUrl)
                {
                    pushedBody = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
                    return OidcRoundTrip.Json("{\"request_uri\":\"urn:ietf:params:oauth:request_uri:par-1\",\"expires_in\":60}");
                }

                return OidcRoundTrip.ServeIdp(fixture, request, fixture.IdToken("sub-1", "alice"), advertisePar: true);
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
        var harness = OidcRoundTrip.BuildHarness(
            fixture,
            request => request.RequestUri!.AbsoluteUri == fixture.ParUrl
                ? new HttpResponseMessage(HttpStatusCode.InternalServerError)
                : OidcRoundTrip.ServeIdp(fixture, request, fixture.IdToken("sub-1", "alice"), advertisePar: true),
            cfg => cfg.DisablePushedAuthorization = false);

        var result = await harness.Controller.OidChallenge("kc");

        Assert.IsNotType<RedirectResult>(result);
    }

    [Fact]
    public async Task Challenge_SendsNoNonce_AndBindsTheCodeWithPkceS256()
    {
        // The recorded answer to #1157, held by a test rather than by a sentence, because the two halves
        // only mean something together.
        //
        // This plugin's code flow sends NO authentication-request nonce. Every nonce in the source is a
        // different thing - the CSP nonce on the interstitial page, the AES-GCM nonce in the secret
        // envelope, and the logout_token's PROHIBITION under OIDC Back-Channel Logout 2.4 - and none of
        // them is this one. The authorize request is built by the pinned Duende.IdentityModel.OidcClient,
        // so what it emits is a property of that package rather than of this repository, and this row
        // measures it on the real challenge leg instead of quoting a plan comment about the version.
        //
        // OIDC Core 1.0 3.1.3.7 rule 11 requires nonce validation only when a nonce was sent, so with none
        // sent, "missing nonce", "echoed-but-unbound nonce" and "nonce from another request" are assertions
        // with no subject. What binds the code to this browser instead is PKCE S256 (RFC 9700 2.1.1), which
        // is the second half asserted here: the pair is the guard, and a row asserting only the absence
        // would be satisfied by a challenge that bound the code with nothing at all.
        //
        // WHAT MAKES THIS WORTH ITS LINE is the day it fails. A nonce appearing on the authorize request
        // with no validator on the callback is the roadiz shape (CVE-2026-42206): generated, never checked,
        // and worse than absent because it reads as a control. This row goes red on that day, and its
        // failure is the signal to build the negatives rather than to relax the assertion.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var harness = OidcRoundTrip.BuildHarness(fixture, request => OidcRoundTrip.ServeIdp(fixture, request, fixture.IdToken("sub-1", "alice")));

        var challenge = Assert.IsType<RedirectResult>(await harness.Controller.OidChallenge("kc"));

        Assert.StartsWith(Authority + "/authorize", challenge.Url, StringComparison.Ordinal);
        Assert.DoesNotContain("nonce", challenge.Url, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("code_challenge=", challenge.Url, StringComparison.Ordinal);
        Assert.Contains("code_challenge_method=S256", challenge.Url, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ParEnabledButNotAdvertised_ChallengeUsesThePlainRedirect()
    {
        // The compatibility half of the production default: a provider that advertises no PAR endpoint
        // still gets the ordinary front-channel redirect - PAR-on is safe against non-PAR providers, which
        // is what makes default-on shippable.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var harness = OidcRoundTrip.BuildHarness(
            fixture,
            request => OidcRoundTrip.ServeIdp(fixture, request, fixture.IdToken("sub-1", "alice")),
            cfg => cfg.DisablePushedAuthorization = false);

        var challenge = Assert.IsType<RedirectResult>(await harness.Controller.OidChallenge("kc"));

        Assert.StartsWith(Authority + "/authorize", challenge.Url, StringComparison.Ordinal);
        Assert.Contains("code_challenge", challenge.Url, StringComparison.Ordinal);
        Assert.DoesNotContain("request_uri=", challenge.Url, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheCallbackLegFetchesNoDiscoveryOfItsOwn()
    {
        // #1067, the behavioural half. The callback client is constructed with the metadata the challenge
        // captured, which sets the library's internal use-discovery flag to false. Built WITHOUT it, the
        // library performs its own discovery and JWKS fetch inside ProcessResponseAsync, through
        // options.HttpClientFactory - a transport the repeated-member screen (#1061) is not on, because that
        // screen lives inside OidcDiscoveryReader.ReadAsync. So the property is not "one fetch fewer": it is
        // that no fetch on this leg leaves the screened path.
        //
        // Asserted on the wire rather than on the option, because the option is the predicate and the fetch
        // is the property. A row reading oidcClient.Options.ProviderInformation would stay green against a
        // library version that consulted something else.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var idToken = fixture.IdToken(subject: "sub-1", username: "alice");
        var requested = new System.Collections.Generic.List<string>();
        var harness = OidcRoundTrip.BuildHarness(fixture, request =>
        {
            requested.Add(request.RequestUri!.AbsoluteUri);
            return OidcRoundTrip.ServeIdp(fixture, request, idToken);
        });

        var (state, binding) = await OidcRoundTrip.DriveChallenge(harness, fixture);

        // The challenge leg legitimately reads both documents, through the screened reader. Only what the
        // CALLBACK asks for is the subject here.
        Assert.Contains(fixture.DiscoveryUrl, requested);
        requested.Clear();

        OidcRoundTrip.RepointToCallback(harness, binding, query: $"?code=test-code&state={state}");
        var callback = Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state));

        // The leg really ran to completion, so the absences below are absences and not a callback that
        // failed before it could fetch anything.
        Assert.Equal("text/html", callback.ContentType);
        Assert.Contains(fixture.TokenUrl, requested);

        Assert.DoesNotContain(fixture.DiscoveryUrl, requested);
        Assert.DoesNotContain(fixture.JwksUrl, requested);
    }
}
