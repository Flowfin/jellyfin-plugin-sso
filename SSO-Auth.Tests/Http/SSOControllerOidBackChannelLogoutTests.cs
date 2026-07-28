// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the anonymous OpenID back-channel logout endpoint (#962), driving a real signed
/// logout_token against discovery + JWKS served in-process by <see cref="OidcTokenFixture"/>. They pin the
/// fail-closed contract: the feature and per-provider opt-in gate reject WITHOUT reading the token; a valid
/// token revokes only the matched user's OpenID sessions for that provider (never cross-provider, never a
/// SAML capture); and every rejection is the uniform 400 with no subject oracle.
///
/// <see cref="AlgNoneForgery_IsRefusedByTheProductionPath_WhileTheGenuineTokenStillRevokes"/> belongs to the
/// JWT forgery battery (<see cref="OidcTokenForgeryTests"/>) and lives here because this is where the
/// production path is reachable: it is the one forged shape that crosses the real endpoint and the real
/// parameter-building call site, instead of a basis a test built (#1004).
/// </summary>
[Collection("SSOController")]
public sealed class SSOControllerOidBackChannelLogoutTests : IDisposable
{
    private const string Authority = "https://idp-bcl.example.test";
    private static readonly Guid UserA = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private static readonly Guid UserB = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");

    private readonly OidcTokenFixture _fixture = new(Authority, "jf");

    public SSOControllerOidBackChannelLogoutTests() => OidcLogoutTokenValidator.ResetReplaysForTests();

    public void Dispose()
    {
        _fixture.Dispose();
        OidcLogoutTokenValidator.ResetReplaysForTests();
    }

    [Fact]
    public async Task ValidLogoutToken_RevokesTheMatchedUser_AndReturns200()
    {
        var harness = Harness(c =>
        {
            c.EnableSingleLogout = true;
            c.OidConfigs["kc"] = Provider(backChannel: true);
            c.LogoutSessions["a"] = Session("sub-1", "sess-9", UserA);
        });

        var result = await harness.Controller.OidBackChannelLogout("kc", _fixture.LogoutToken("sub-1", "sess-9"));

        Assert.IsType<OkResult>(result);
        await harness.SessionManager.Received(1).RevokeUserTokens(UserA, null);
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("a")));
    }

    [Fact]
    public async Task FeatureDisabled_RejectsWithoutReadingTheToken()
    {
        // EnableSingleLogout off: the endpoint must NOT reach the validator (no discovery fetch), just reject.
        var harness = Harness(c => c.OidConfigs["kc"] = Provider(backChannel: true), withResponder: false);

        var result = await harness.Controller.OidBackChannelLogout("kc", _fixture.LogoutToken("sub-1"));

        AssertUniform400(result);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string>());
    }

    [Fact]
    public async Task PerProviderOptInOff_Rejects()
    {
        var harness = Harness(c =>
        {
            c.EnableSingleLogout = true;
            c.OidConfigs["kc"] = Provider(backChannel: false);
            c.LogoutSessions["a"] = Session("sub-1", "sess-9", UserA);
        }, withResponder: false);

        var result = await harness.Controller.OidBackChannelLogout("kc", _fixture.LogoutToken("sub-1"));

        AssertUniform400(result);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string>());
    }

    [Fact]
    public async Task UnknownProvider_Rejects_NoOracle()
    {
        var harness = Harness(c => c.EnableSingleLogout = true, withResponder: false);

        AssertUniform400(await harness.Controller.OidBackChannelLogout("nope", _fixture.LogoutToken("sub-1")));
    }

    [Fact]
    public async Task ForgedToken_Rejects_MintsNoRevoke()
    {
        using var attacker = new OidcTokenFixture(Authority, "jf");
        var harness = Harness(c =>
        {
            c.EnableSingleLogout = true;
            c.OidConfigs["kc"] = Provider(backChannel: true);
            c.LogoutSessions["a"] = Session("sub-1", "sess-9", UserA);
        });

        // Signed by a DIFFERENT key than the served JWKS.
        var result = await harness.Controller.OidBackChannelLogout("kc", attacker.LogoutToken("sub-1", "sess-9"));

        AssertUniform400(result);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string>());
    }

    [Fact]
    public async Task AlgNoneForgery_IsRefusedByTheProductionPath_WhileTheGenuineTokenStillRevokes()
    {
        // The one forgery driven END TO END: the endpoint, the discovery/JWKS read, and the validation
        // parameters OidcLoginService builds at its own call site. The rest of the battery
        // (OidcTokenForgeryTests) submits against parameters the TEST built, which establishes what the token
        // library refuses under that basis rather than what this endpoint refuses; those are different claims
        // and only one of them is about production.
        //
        // alg:none is the shape chosen for it because it is the one needing no key material at all: the
        // header declares the token needs no signature and the third segment is empty, so anyone who can
        // reach this anonymous URL can mint it, and acceptance would revoke a chosen user's sessions. It is
        // also the shape a mutation of the parameters AFTER the builder returns re-opens, at a call site the
        // conformance rule cannot see (the endpoint's `var parameters = ...` names no type and calls no
        // handler entry point — that rule's doc comment enumerates the gap). This row is what notices.
        //
        // The genuine token goes through the SAME harness afterwards and must be ACCEPTED. Without that
        // control the rejection would prove nothing: an unserved discovery document, a misspelled provider
        // or a wrong audience all produce the identical uniform 400.
        var harness = Harness(c =>
        {
            c.EnableSingleLogout = true;
            c.OidConfigs["kc"] = Provider(backChannel: true);
            c.LogoutSessions["a"] = Session("sub-1", "sess-9", UserA);
        });

        var refused = await harness.Controller.OidBackChannelLogout("kc", AlgNoneLogoutToken("sub-1", "sess-9"));

        AssertUniform400(refused);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string>());

        var accepted = await harness.Controller.OidBackChannelLogout("kc", _fixture.LogoutToken("sub-1", "sess-9"));

        Assert.IsType<OkResult>(accepted);
        await harness.SessionManager.Received(1).RevokeUserTokens(UserA, null);
    }

    [Fact]
    public async Task NeverRevokesASamlCaptureWithTheSameSubject()
    {
        var harness = Harness(c =>
        {
            c.EnableSingleLogout = true;
            c.OidConfigs["kc"] = Provider(backChannel: true);
            // A SAML capture for the SAME provider name + subject must be untouched by an OpenID logout.
            c.LogoutSessions["saml"] = new LogoutSession { Protocol = "SAML", Provider = "kc", Subject = "sub-1", SessionIndex = "sess-9", UserId = UserB };
        });

        var result = await harness.Controller.OidBackChannelLogout("kc", _fixture.LogoutToken("sub-1", "sess-9"));

        // No OpenID capture matched -> uniform 400, and the SAML user is never revoked.
        AssertUniform400(result);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(UserB, Arg.Any<string>());
        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("saml")));
    }

    [Fact]
    public async Task SubOnlyToken_RevokesEveryOpenIdSessionOfThatSubjectForThisProvider()
    {
        var harness = Harness(c =>
        {
            c.EnableSingleLogout = true;
            c.OidConfigs["kc"] = Provider(backChannel: true);
            c.LogoutSessions["a1"] = Session("sub-1", "sess-1", UserA);
            c.LogoutSessions["a2"] = Session("sub-1", "sess-2", UserA);
            c.LogoutSessions["other"] = Session("sub-2", "sess-3", UserB);
        });

        var result = await harness.Controller.OidBackChannelLogout("kc", _fixture.LogoutToken("sub-1"));

        Assert.IsType<OkResult>(result);
        await harness.SessionManager.Received(1).RevokeUserTokens(UserA, null);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(UserB, Arg.Any<string>());
    }

    [Fact]
    public async Task DiscoveryUnavailable_RejectsFailClosed_MintsNoRevoke()
    {
        // Feature + per-provider opt-in ON, so the endpoint reaches the validator — but discovery is
        // unreachable (no HTTP responder). ValidateBackChannelLogoutAsync must fail closed
        // (discovery_unavailable -> uniform 400), never a 500 and never a session revoke.
        var harness = Harness(c =>
        {
            c.EnableSingleLogout = true;
            c.OidConfigs["kc"] = Provider(backChannel: true);
            c.LogoutSessions["a"] = Session("sub-1", "sess-9", UserA);
        }, withResponder: false);

        var result = await harness.Controller.OidBackChannelLogout("kc", _fixture.LogoutToken("sub-1", "sess-9"));

        AssertUniform400(result);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string>());
        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("a")));
    }

    [Fact]
    public async Task MalformedEndpoint_RejectsFailClosed_MintsNoRevoke()
    {
        // The configured endpoint is not a usable URL, so OidcDiscoveryOptions.Build throws while the
        // validator prepares discovery — caught as a fail-closed reject (discovery_unavailable), never a 500
        // and never a session revoke.
        var harness = Harness(c =>
        {
            c.EnableSingleLogout = true;
            c.OidConfigs["kc"] = new OidConfig
            {
                Enabled = true,
                OidEndpoint = "not-a-usable-url",
                OidClientId = "jf",
                EnableBackChannelLogout = true,
            };
            c.LogoutSessions["a"] = Session("sub-1", "sess-9", UserA);
        }, withResponder: false);

        var result = await harness.Controller.OidBackChannelLogout("kc", _fixture.LogoutToken("sub-1", "sess-9"));

        AssertUniform400(result);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string>());
    }

    // An unsigned logout_token whose every claim is acceptable — this provider's issuer and audience, the
    // mandatory events member, a sub/sid pair that matches a captured session — so the empty signature is the
    // only thing left to refuse it on. Composed by hand because a token handler will not emit an `alg` the
    // JWS spec forbids.
    private string AlgNoneLogoutToken(string subject, string sessionIndex)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var payload = "{\"iss\":\"" + Authority + "\",\"aud\":\"" + _fixture.ClientId + "\",\"sub\":\"" + subject + "\","
            + "\"sid\":\"" + sessionIndex + "\",\"jti\":\"" + Guid.NewGuid() + "\","
            + "\"iat\":" + (now - 60) + ",\"exp\":" + (now + 300) + ","
            + "\"events\":{\"http://schemas.openid.net/event/backchannel-logout\":{}}}";
        return Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes("{\"alg\":\"none\",\"typ\":\"JWT\"}"))
            + "." + Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload)) + ".";
    }

    private static void AssertUniform400(ActionResult result)
    {
        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("Logout token could not be processed", content.Content);
    }

    private OidConfig Provider(bool backChannel) => new OidConfig
    {
        Enabled = true,
        OidEndpoint = Authority,
        OidClientId = "jf",
        EnableBackChannelLogout = backChannel,
    };

    private static LogoutSession Session(string subject, string sessionIndex, Guid userId) => new LogoutSession
    {
        Protocol = "OpenID",
        Provider = "kc",
        Subject = subject,
        SessionIndex = sessionIndex,
        UserId = userId,
        IdToken = "raw.id.token",
    };

    private SsoControllerHarness Harness(Action<PluginConfiguration> configure, bool withResponder = true)
        => new SsoControllerHarness(configure, httpResponder: withResponder ? Responder : null);

    // Serves this fixture's discovery document and JWKS; any other URL 404s so an unexpected call is visible.
    private HttpResponseMessage Responder(HttpRequestMessage request)
    {
        var url = request.RequestUri!.AbsoluteUri;
        if (url == _fixture.DiscoveryUrl)
        {
            return Json(_fixture.Discovery());
        }

        if (url == _fixture.JwksUrl)
        {
            return Json(_fixture.Jwks());
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private static HttpResponseMessage Json(string body) => new HttpResponseMessage(HttpStatusCode.OK)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json"),
    };
}
