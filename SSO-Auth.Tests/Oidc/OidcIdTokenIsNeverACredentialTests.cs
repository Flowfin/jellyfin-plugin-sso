// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Xml.Serialization;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Dto;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The id_token is evidence about who the caller is, and nothing else. It is verified, its claims are read,
/// and the credential the caller leaves with is a Jellyfin session this server minted (#1004). Nothing in the
/// tree asserted that until now, so a change that echoed the token back to the browser, handed it to the
/// session mint, or wrote it into the persisted configuration would have been caught by nobody.
///
/// It matters because the token is a bearer artefact signed by someone else. Anywhere it comes to rest is a
/// place a reader of that store, or of that response, holds an assertion the provider minted for this server -
/// and the plugin has no way to revoke one. A locally minted session is revocable and is bound to this
/// server's own session state, which is the whole reason the exchange happens.
///
/// Proven over a real round trip rather than by scanning source for a variable name: the challenge, callback
/// and redeem legs run against the in-test provider, and the artefacts the flow actually produced are searched
/// for the exact token that provider issued. A source scan would go green on a rename; this goes green only
/// when the token is genuinely absent from the things the flow hands out and keeps.
///
/// Two controls stand behind the absences, because an absence proves nothing on its own. The needle is shown
/// to be findable, by searching a body that really does carry it. And the flow is shown to have completed on
/// the strength of that token, so the artefacts searched are the artefacts of a successful login rather than
/// of a login that never got a token to leak.
///
/// One retention is deliberate and is measured rather than excluded. With Single Logout on, the token is kept
/// as the later RP-initiated logout's <c>id_token_hint</c>, so the third case asserts what is actually owed
/// there: the entry exists, and nothing readable holds the token. Without that case the other two would be
/// measuring a configuration with nothing to keep and would read as a guarantee about the feature that keeps
/// it. What is NOT established here is any property of the token once it leaves this server as an
/// <c>id_token_hint</c> on a logout redirect, which is a different path and is not searched.
/// </summary>
[Collection("SSOController")]
public class OidcIdTokenIsNeverACredentialTests
{
    private const string Authority = "https://idp-credential.example.com";

    [Fact]
    public async Task ALoggedInRoundTrip_LeavesTheIdTokenInNothingItHandsOutAndNothingItKeeps()
    {
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var idToken = fixture.IdToken(subject: "sub-1", username: "alice");
        var served = new List<string>();
        var harness = BuildHarness(fixture, request => Serve(fixture, request, idToken, served));

        var user = TestUsers.Named("alice", Guid.Parse("1a999999-1111-1111-1111-111111111111"));
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(user.Id).Returns(user);

        AuthenticationRequest? mint = null;
        harness.SessionManager
            .AuthenticateDirect(Arg.Do<AuthenticationRequest>(request => mint = request))
            .Returns(new AuthenticationResult());

        var (state, binding) = await DriveChallenge(harness);
        RepointToCallback(harness, state, binding, $"?code=test-code&state={state}");
        var callback = Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state));
        var authed = await harness.Controller.OidAuth("kc", Redeem(state));

        // Control one: the flow really ran on this token. Without this, every absence below would also hold
        // for a login that failed before the token was ever redeemed.
        Assert.Equal("text/html", callback.ContentType);
        Assert.IsType<OkObjectResult>(authed);
        await harness.UserManager.Received(1).CreateUserAsync("alice");
        Assert.NotNull(mint);

        // Control two: the needle is findable. The token endpoint's own body carries the token, so a search
        // that cannot find it there is a broken search rather than a clean result.
        Assert.Contains(served, body => Carries(body, idToken));

        // The page handed to the browser at the end of the callback leg.
        Assert.False(Carries(callback.Content, idToken), "The callback page handed the id_token to the browser.");

        // What the session mint was asked for. The credential the caller leaves with is built from this, so a
        // token that reached it would be a token the caller could be handed.
        foreach (var (name, value) in ReadableStrings(mint!))
        {
            Assert.False(Carries(value, idToken), $"The session mint received the id_token in {name}.");
        }

        // What the server keeps. A token written here outlives the login and is readable by anything that can
        // read the plugin's configuration.
        Assert.False(Carries(Persisted(harness.Configuration), idToken), "The persisted configuration kept the id_token.");
    }

    [Fact]
    public async Task ARejectedRoundTrip_LeavesTheIdTokenInNothingEither()
    {
        // The refusal path reaches different code - the browser error page rather than the auth page - and it
        // is the path where quoting the offending token into a message is the natural mistake to make.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        using var foreign = new OidcTokenFixture(Authority, "jf");
        var idToken = foreign.IdToken(subject: "sub-1", username: "alice");
        var served = new List<string>();
        var harness = BuildHarness(fixture, request => Serve(fixture, request, idToken, served));

        var (state, binding) = await DriveChallenge(harness);
        RepointToCallback(harness, state, binding, $"?code=test-code&state={state}");
        var callback = await harness.Controller.OidCallback("kc", state);

        // The token was signed by a key this provider does not advertise, so the callback must refuse it. If
        // it ever stopped refusing, this test would be searching the wrong path and says so here.
        Assert.IsNotType<OkObjectResult>(callback);
        Assert.Contains(served, body => Carries(body, idToken));

        await harness.SessionManager.DidNotReceive().AuthenticateDirect(Arg.Any<AuthenticationRequest>());
        Assert.False(Carries(Rendered(callback), idToken), "The refusal page quoted the id_token back.");
        Assert.False(Carries(Persisted(harness.Configuration), idToken), "The persisted configuration kept a refused id_token.");
    }

    [Fact]
    public async Task WithSingleLogoutOn_TheTokenIsKeptOnPurpose_AndNeverInTheClear()
    {
        // The one place the token is deliberately retained: Single Logout keeps it as the later RP-initiated
        // logout's id_token_hint. So the property here is not absence, it is that nothing readable holds it -
        // the retention is encrypted at rest, and the client and the session mint still never see it. Without
        // this arm the other two would be measuring a configuration where there was nothing to keep, and would
        // read as a guarantee about the feature that keeps it.
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var idToken = fixture.IdToken(subject: "sub-1", username: "alice");
        var served = new List<string>();
        var harness = BuildHarness(fixture, request => Serve(fixture, request, idToken, served), c => c.EnableSingleLogout = true);

        var user = TestUsers.Named("alice", Guid.Parse("1b999999-1111-1111-1111-111111111111"));
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(user.Id).Returns(user);

        AuthenticationRequest? mint = null;
        harness.SessionManager
            .AuthenticateDirect(Arg.Do<AuthenticationRequest>(request => mint = request))
            .Returns(new AuthenticationResult { SessionInfo = new SessionInfoDto { Id = "session-key-slo" } });

        var (state, binding) = await DriveChallenge(harness);
        RepointToCallback(harness, state, binding, $"?code=test-code&state={state}");
        var callback = Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state));
        Assert.IsType<OkObjectResult>(await harness.Controller.OidAuth("kc", Redeem(state)));
        Assert.NotNull(mint);
        Assert.Contains(served, body => Carries(body, idToken));

        // Control: the retention really happened. The capture needs a session id to key on, so a mint that
        // returned none would store nothing and this arm would be asserting that an empty store is clean.
        Assert.NotEmpty(harness.Configuration.LogoutSessions);
        Assert.NotNull(harness.Configuration.LogoutSessions["session-key-slo"].IdToken);

        Assert.False(Carries(callback.Content, idToken), "The callback page handed the id_token to the browser.");
        Assert.False(Carries(Persisted(harness.Configuration), idToken), "The retained id_token is readable in the persisted configuration.");
        foreach (var (name, value) in ReadableStrings(mint!))
        {
            Assert.False(Carries(value, idToken), $"The session mint received the id_token in {name}.");
        }
    }

    // Searches for the whole token AND for its payload segment on its own. The whole token is what a naive
    // echo would carry; the payload alone is what a well-meaning "let the admin see the claims" change would,
    // and that segment is the part carrying the subject, so it is the half that must not come to rest either.
    private static bool Carries(string? text, string idToken)
    {
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        if (text.Contains(idToken, StringComparison.Ordinal))
        {
            return true;
        }

        var segments = idToken.Split('.');
        return segments.Length == 3 && text.Contains(segments[1], StringComparison.Ordinal);
    }

    // Every readable string on the object handed to the session mint, named, so a failure says which member
    // carried the token rather than only that one did.
    private static IEnumerable<(string Name, string? Value)> ReadableStrings(object instance) =>
        instance.GetType()
            .GetProperties()
            .Where(property => property.CanRead && property.GetIndexParameters().Length == 0)
            .Select(property => (property.Name, Value: property.GetValue(instance) as string));

    // The configuration as it is written to disk. Serialized rather than walked, because what the server keeps
    // is the serialized form and a walk would have to guess which members reach it.
    private static string Persisted(PluginConfiguration configuration)
    {
        using var writer = new StringWriter(CultureInfo.InvariantCulture);
        new XmlSerializer(typeof(PluginConfiguration)).Serialize(writer, configuration);
        return writer.ToString();
    }

    // Whatever the refusal handed back, as text: a rendered page, or the message of a plain result.
    private static string Rendered(ActionResult result) => result switch
    {
        ContentResult content => content.Content ?? string.Empty,
        ObjectResult obj => obj.Value?.ToString() ?? string.Empty,
        _ => result.ToString() ?? string.Empty,
    };

    // The challenge/callback/redeem scaffolding below is the same shape OidcRoundTripTests uses privately.
    // It is repeated here rather than lifted out of that file, because lifting it would rewrite fourteen call
    // sites in a file this change has no other reason to touch. #1351 carries the extraction.

    // A harness with one enabled provider "kc" pointed at the fixture's authority. Pushed authorization off so
    // the challenge is a plain redirect, profile loading off so the id_token claims are the whole identity, and
    // the authorization/link toggles off so the redeem takes the first-time-provision path.
    private static SsoControllerHarness BuildHarness(
        OidcTokenFixture fixture,
        Func<HttpRequestMessage, HttpResponseMessage> responder,
        Action<PluginConfiguration>? configure = null) =>
        new SsoControllerHarness(
            c =>
            {
                c.OidConfigs["kc"] = new OidConfig
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
                configure?.Invoke(c);
            },
            httpResponder: responder);

    // Drives a real challenge and returns the state token and browser-binding cookie it minted.
    private static async Task<(string State, string Binding)> DriveChallenge(SsoControllerHarness harness)
    {
        harness.Controller.HttpContext.Request.Path = "/sso/OID/start/kc";
        var challenge = Assert.IsType<RedirectResult>(await harness.Controller.OidChallenge("kc"));
        Assert.StartsWith(Authority + "/authorize", challenge.Url, StringComparison.Ordinal);

        var state = UrlEncodedQuery.Find(challenge.Url, "state") ?? string.Empty;
        Assert.False(string.IsNullOrEmpty(state));
        var binding = BindingCookie(harness.Controller.Response);
        Assert.False(string.IsNullOrEmpty(binding));
        return (state, binding);
    }

    // Re-points the same context at the callback route, carrying the binding cookie the challenge set (#326).
    private static void RepointToCallback(SsoControllerHarness harness, string state, string binding, string query)
    {
        harness.Controller.HttpContext.Request.Path = "/sso/OID/redirect/kc";
        harness.Controller.HttpContext.Request.QueryString = new QueryString(query);
        harness.Controller.HttpContext.Request.Headers.Cookie = $"{AuthorizeStateBinding.CookieName}={binding}";
    }

    private static AuthResponse Redeem(string state) => new AuthResponse
    {
        Data = state,
        DeviceID = "device-1",
        DeviceName = "Test Device",
        AppName = "Jellyfin Web",
        AppVersion = "1.0",
    };

    private static string BindingCookie(HttpResponse response)
    {
        var prefix = AuthorizeStateBinding.CookieName + "=";
        foreach (var header in response.Headers.SetCookie)
        {
            if (header is not null && header.StartsWith(prefix, StringComparison.Ordinal))
            {
                var value = header.Substring(prefix.Length);
                var end = value.IndexOf(';', StringComparison.Ordinal);
                return end >= 0 ? value.Substring(0, end) : value;
            }
        }

        return string.Empty;
    }

    // The provider's endpoints, recording every body served so the search can be shown to work against one
    // that really carries the token.
    private static HttpResponseMessage Serve(OidcTokenFixture fixture, HttpRequestMessage request, string idToken, List<string> served)
    {
        var url = request.RequestUri!.AbsoluteUri;
        string body;
        if (url == fixture.DiscoveryUrl)
        {
            body = fixture.Discovery();
        }
        else if (url == fixture.JwksUrl)
        {
            body = fixture.Jwks();
        }
        else if (url == fixture.TokenUrl)
        {
            body = fixture.TokenEndpointJson(idToken);
        }
        else
        {
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }

        served.Add(body);
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json"),
        };
    }
}
