// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Flows;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the anonymous OpenID back-channel logout endpoint (#962), driving a real signed
/// logout_token against discovery + JWKS served in-process by <see cref="OidcTokenFixture"/>. They pin the
/// fail-closed contract: the feature and per-provider opt-in gate reject WITHOUT reading the token; a valid
/// token revokes only the matched user's OpenID sessions for that provider (never cross-provider, never a
/// SAML capture); and every rejection is the uniform 400 with no subject oracle.
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
        // Feature + per-provider opt-in ON, so the endpoint reaches the validator - but discovery is
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

        // The recorded REASON, not only the absent revoke: the parent asks that a discovery failure leave the
        // session state unchanged AND record why, and until #1184 only the first half was pinned. The entry an
        // operator alerts on is the one saying a termination the IdP ordered did not happen, at Error - not
        // the warning a refused forgery shares.
        var entry = Assert.Single(harness.ControllerLog.Entries, e => e.Message.Contains("could NOT be performed", StringComparison.Ordinal));
        Assert.Equal(LogLevel.Error, entry.Level);
        Assert.Contains(OidcLogoutTokenValidator.RejectReason.ProviderUnreachable, entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnUnreachableProviderAndAForgedToken_AreAuditedApart_BehindOneIdentical400()
    {
        // The two classes the audit trail has to keep apart, driven through the SAME endpoint in one test so
        // the comparison is between records rather than between descriptions. A forged token is the system
        // working and nothing was meant to end; an unreachable provider means the IdP ordered a termination
        // that did not happen, and an attacker who can disrupt the server-to-IdP path can produce it on
        // purpose. Filing both as one warning left the second buried in the first.
        using var attacker = new OidcTokenFixture(Authority, "jf");

        // Signed by a key the served JWKS does not carry, so only the signature differs from a real one.
        var forged = Harness(Configured);
        var forgedResult = await forged.Controller.OidBackChannelLogout("kc", attacker.LogoutToken("sub-1", "sess-9"));

        // The same endpoint and a genuine token, with the provider unreachable (no responder).
        var unreachable = Harness(Configured, withResponder: false);
        var unreachableResult = await unreachable.Controller.OidBackChannelLogout("kc", _fixture.LogoutToken("sub-1", "sess-9"));

        void Configured(PluginConfiguration c)
        {
            c.EnableSingleLogout = true;
            c.OidConfigs["kc"] = Provider(backChannel: true);
            c.LogoutSessions["a"] = Session("sub-1", "sess-9", UserA);
        }

        // Filterable apart by event AND by severity.
        var forgedEntry = Assert.Single(forged.ControllerLog.Entries, e => e.Message.Contains("REJECTED", StringComparison.Ordinal));
        Assert.Equal(LogLevel.Warning, forgedEntry.Level);
        Assert.DoesNotContain("could NOT be performed", forgedEntry.Message, StringComparison.Ordinal);

        var unreachableEntry = Assert.Single(unreachable.ControllerLog.Entries, e => e.Message.Contains("could NOT be performed", StringComparison.Ordinal));
        Assert.Equal(LogLevel.Error, unreachableEntry.Level);
        Assert.DoesNotContain("REJECTED", unreachableEntry.Message, StringComparison.Ordinal);

        // Neither is filed under SAML any more, which is what an operator's OpenID filter used to miss.
        Assert.DoesNotContain("SAML", forgedEntry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("SAML", unreachableEntry.Message, StringComparison.Ordinal);

        // And the wire answer stays one uniform 400 for both, so the trail gained a distinction the caller
        // did not: nothing here became a branch oracle for an anonymous poster.
        AssertUniform400(forgedResult);
        AssertUniform400(unreachableResult);
        var forged400 = Assert.IsType<ContentResult>(forgedResult);
        var unreachable400 = Assert.IsType<ContentResult>(unreachableResult);
        Assert.Equal(forged400.StatusCode, unreachable400.StatusCode);
        Assert.Equal(forged400.Content, unreachable400.Content);
        Assert.Equal(forged400.ContentType, unreachable400.ContentType);
        await forged.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string>());
        await unreachable.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string>());
    }

    [Fact]
    public async Task BackChannelLogout_WithAScreenedDiscovery_NoOpsAndRecordsItsReason()
    {
        // Pins the posture #1060 owns, so the deferral is visible rather than implied. The repeated-member
        // screen (#1005) refuses a discovery document that names `issuer` twice, which on THIS path means the
        // logout token is never validated: the revocation the IdP ordered does not happen and the captured
        // session survives. That is fail-OPEN for a logout while being fail-closed for a login, it predates
        // the screen (any unreadable discovery already does it), and the screen only adds a new cause — so it
        // is pinned here and decided there rather than changed inside this delivery.
        //
        // Both halves are asserted. The revocation does not happen and the session survives — and the refusal
        // states its reason in the log, which on this path is the ONLY place it does: the endpoint answers a
        // deliberately uniform 400, indistinguishable from a legitimate rejection, so without the log entry a
        // suppressed revocation is silent to everyone.
        var harness = new SsoControllerHarness(
            c =>
            {
                c.EnableSingleLogout = true;
                c.OidConfigs["kc"] = Provider(backChannel: true);
                c.LogoutSessions["a"] = Session("sub-1", "sess-9", UserA);
            },
            httpResponder: request =>
            {
                var url = request.RequestUri!.AbsoluteUri;
                if (url == _fixture.DiscoveryUrl)
                {
                    return Json(_fixture.Discovery().Insert(1, "\"issuer\":\"https://attacker.example\","));
                }

                return url == _fixture.JwksUrl ? Json(_fixture.Jwks()) : new HttpResponseMessage(HttpStatusCode.NotFound);
            });

        var result = await harness.Controller.OidBackChannelLogout("kc", _fixture.LogoutToken("sub-1", "sess-9"));

        AssertUniform400(result);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string>());
        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("a")));

        // The reason half: the screen names why it refused, so an operator can tell a suppressed revocation
        // from a rejected forgery. Both answer 400.
        Assert.Contains(
            harness.ControllerLog.Entries,
            e => e.Message.Contains(RepeatedMemberScreen.RefusalReason, StringComparison.Ordinal));
    }

    [Fact]
    public async Task MalformedEndpoint_RejectsFailClosed_MintsNoRevoke()
    {
        // The configured endpoint is not a usable URL, so OidcDiscoveryOptions.Build throws while the
        // validator prepares discovery - caught as a fail-closed reject (discovery_unavailable), never a 500
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

    [Fact]
    public async Task ADiscoveryReadThatFailsOnceIsRetried_AndTheRevocationStillHappens()
    {
        // #1183. The IdP has ordered this revocation, so a single dropped or slow discovery response must
        // not turn it into a no-op. The provider is reachable on the second attempt and the sessions the
        // IdP ended are ended here too - which is the whole difference between this path and the login
        // challenge, where the same refusal creates no session and is the safe direction.
        var discoveryAttempts = 0;
        var harness = new SsoControllerHarness(
            ConfiguredWithSession,
            httpResponder: request =>
            {
                if (request.RequestUri!.AbsoluteUri == _fixture.DiscoveryUrl && ++discoveryAttempts == 1)
                {
                    return new HttpResponseMessage(HttpStatusCode.GatewayTimeout);
                }

                return Responder(request);
            });

        var result = await harness.Controller.OidBackChannelLogout("kc", _fixture.LogoutToken("sub-1", "sess-9"));

        Assert.IsType<OkResult>(result);
        Assert.Equal(2, discoveryAttempts);
        await harness.SessionManager.Received(1).RevokeUserTokens(UserA, null);
        Assert.False(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("a")));
    }

    [Fact]
    public async Task EveryDiscoveryAttemptFailing_StillRefuses_AndStopsAtTheBudgetedCount()
    {
        // The other half of the same change, and the one that keeps it from being a relaxation: when the
        // budget is exhausted nothing is granted. Still the uniform 400, still no revoke, still the
        // ProviderUnreachable reason - acting on a logout_token whose signing keys were never obtained
        // would be a forgery oracle for mass session termination.
        //
        // The count is asserted too. A retry with no ceiling is a way to hold an anonymous endpoint open,
        // and "attempts times timeout" left implicit is how that ceiling goes missing.
        var discoveryAttempts = 0;
        var harness = new SsoControllerHarness(
            ConfiguredWithSession,
            httpResponder: request =>
            {
                if (request.RequestUri!.AbsoluteUri == _fixture.DiscoveryUrl)
                {
                    discoveryAttempts++;
                }

                return new HttpResponseMessage(HttpStatusCode.GatewayTimeout);
            });

        var result = await harness.Controller.OidBackChannelLogout("kc", _fixture.LogoutToken("sub-1", "sess-9"));

        AssertUniform400(result);
        Assert.Equal(OidcLoginService.LogoutDiscoveryAttempts, discoveryAttempts);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string>());
        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("a")));
        Assert.Contains(
            harness.ControllerLog.Entries,
            e => e.Message.Contains(OidcLogoutTokenValidator.RejectReason.ProviderUnreachable.ToString(), StringComparison.Ordinal));
    }

    [Fact]
    public async Task AMalformedEndpoint_IsNotRetried()
    {
        // A configured endpoint that is not a usable URL is a CONFIGURATION fault, not a transient one:
        // repeating it produces the same answer and spends the budget for nothing. It fails before any
        // request leaves the process, so the assertion is that NOTHING was fetched - a retry wrapped one
        // level too high would show here as two attempts at a URL that can never work.
        var requests = 0;
        var harness = new SsoControllerHarness(
            c =>
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
            },
            httpResponder: _ =>
            {
                requests++;
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            });

        var result = await harness.Controller.OidBackChannelLogout("kc", _fixture.LogoutToken("sub-1", "sess-9"));

        AssertUniform400(result);
        Assert.Equal(0, requests);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string>());
    }

    [Fact]
    public void TheLogoutDiscoveryBudgetIsWhatItsPartsAddUpTo()
    {
        // The stated worst case has to keep matching what the parts actually produce. Each attempt is
        // bounded by the reader's own fetch timeout and the pauses sit between them, so raising the attempt
        // count, the delay or that timeout without re-choosing the budget fails here rather than quietly
        // widening how long one anonymous, rate-limited request can hold the endpoint.
        var parts = (OidcDiscoveryReader.FetchTimeout * OidcLoginService.LogoutDiscoveryAttempts)
            + (OidcLoginService.LogoutDiscoveryRetryDelay * (OidcLoginService.LogoutDiscoveryAttempts - 1));

        Assert.Equal(OidcLoginService.LogoutDiscoveryBudget, parts);
    }

    private static void AssertUniform400(ActionResult result)
    {
        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("Logout token could not be processed", content.Content);
    }

    // The single-logout feature on, this provider opted in, and one matching session to revoke - the state
    // the retry rows differ from each other only by their responder against.
    private void ConfiguredWithSession(PluginConfiguration config)
    {
        config.EnableSingleLogout = true;
        config.OidConfigs["kc"] = Provider(backChannel: true);
        config.LogoutSessions["a"] = Session("sub-1", "sess-9", UserA);
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
