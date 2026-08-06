// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// A compact token carrying MORE than three segments is unreadable in a way the readers did not name (#1249).
/// Such a token gets far enough for the token library to base64url-decode a LATER segment, and that decode
/// raises <see cref="FormatException"/> - which is not an <see cref="ArgumentException"/>, so it escaped every
/// defensive catch on the id_token and <c>logout_token</c> paths.
/// <para>
/// Why it is a security test and not a tidiness one: <see cref="OidcSignatureKeys.TokenHasAcceptableKeyId"/> is
/// the <c>kid</c> screen both token paths run BEFORE any signing key is looked up, and the back-channel logout
/// endpoint takes its token straight from an anonymous POST body. The escape therefore replaced the endpoint's
/// deliberately uniform 400 with a 500, which is an availability cost and an oracle: a 500 tells an
/// unauthenticated caller that single-logout is switched on for that provider, which the uniform rejection
/// exists to hide. Nothing is accepted and no session is revoked, so this is fail-stop rather than fail-open.
/// </para>
/// </summary>
public sealed class OidcDegenerateTokenSegmentsTests
{
    /// <summary>
    /// The libFuzzer reproducer from #1249, base64 of the exact bytes. Held encoded on purpose: it carries
    /// literal newlines, and a raw literal would be normalised by this repository's .gitattributes on the way
    /// into git - deleting the very bytes the fixture exists to preserve.
    /// </summary>
    private const string CrasherBase64 =
        "ZXlKaGJHY2lPaUp1YjI1bElpd2lkSGx3SWpvaVNsZFVJbjAuZXlKcGMzTWlPaUpvWTJ4cFpXYjI1bElpd2lkSGx3SWpvaVNsZFVJbjAuZXlKcGMzTWlPaUpvWTJ4cFpXNTBJbjAuCjUwSW4wLgo=";

    /// <summary>The reproducer minimised to the shape that matters: a readable header, then five segments.</summary>
    private const string Minimised = "eyJhbGciOiJub25lIn0.a.b.c.!";

    public static TheoryData<string> DegenerateTokens => new(Crasher(), Minimised);

    /// <summary>
    /// Five-segment tokens whose later segments DO decode, and three-segment tokens with an undecodable
    /// header, take the ordinary unreadable path. They are here so a green suite cannot be read as "any odd
    /// token is now swallowed": the widened catch is aimed at one shape, and these prove the others were
    /// already handled and still are.
    /// </summary>
    public static TheoryData<string> AlreadyHandledTokens => new("a.b.c.d.e", "!!!.eyJpc3MiOiJoIn0.sig", "not-a-jwt", "only.two");

    private static string Crasher() => Encoding.UTF8.GetString(Convert.FromBase64String(CrasherBase64));

    [Theory]
    [MemberData(nameof(DegenerateTokens))]
    [MemberData(nameof(AlreadyHandledTokens))]
    public void KidGate_ReportsAcceptable_RatherThanThrowing(string token)
    {
        // The gate is deliberately not the fail-closed floor: a token it cannot read is the handler's to
        // refuse, on the handler's own terms. "Cannot read" has to mean that whichever exception says so,
        // otherwise the gate leaks the failure to the endpoint as a 500.
        Assert.True(OidcSignatureKeys.TokenHasAcceptableKeyId(token));
    }

    [Theory]
    [MemberData(nameof(DegenerateTokens))]
    [MemberData(nameof(AlreadyHandledTokens))]
    public void IdTokenIssuer_ReadsAsAbsent_RatherThanThrowing(string token)
    {
        // The mix-up check reads the issuer off the token; a degenerate token must leave it absent so the
        // check refuses on a missing issuer instead of the reader raising into the callback.
        Assert.Null(OidcResponseIssuer.IdTokenIssuer(token));
    }

    [Theory]
    [MemberData(nameof(DegenerateTokens))]
    [MemberData(nameof(AlreadyHandledTokens))]
    public void Acr_ReadsAsAbsent_RatherThanThrowing(string token)
        => Assert.Null(OidcIdTokenAcr.Read(token));

    [Theory]
    [MemberData(nameof(DegenerateTokens))]
    [MemberData(nameof(AlreadyHandledTokens))]
    public void Sid_ReadsAsAbsent_RatherThanThrowing(string token)
        => Assert.Null(OidcIdTokenSid.Read(token));

    [Theory]
    [MemberData(nameof(DegenerateTokens))]
    [MemberData(nameof(AlreadyHandledTokens))]
    public void AuthTime_ReadsAsAbsent_RatherThanThrowing(string token)
    {
        // auth_time absent is the fail-closed reading: the caller's max_age check refuses rather than
        // trusting a value it could not parse.
        Assert.Null(OidcIdTokenAuthTime.Read(token));
    }
}

/// <summary>
/// The endpoint half of #1249. The unit rows above pin the readers; this pins the thing an anonymous caller
/// can actually observe, because the oracle lives at the endpoint and not at the helper.
/// </summary>
[Collection("SSOController")]
public sealed class OidcDegenerateTokenSegmentsEndpointTests : IDisposable
{
    private const string Authority = "https://idp-degenerate.example.test";

    private readonly OidcTokenFixture _fixture = new(Authority, "jf");

    public OidcDegenerateTokenSegmentsEndpointTests() => OidcLogoutTokenValidator.ResetReplaysForTests();

    public void Dispose()
    {
        _fixture.Dispose();
        OidcLogoutTokenValidator.ResetReplaysForTests();
    }

    public static TheoryData<string> DegenerateTokens => OidcDegenerateTokenSegmentsTests.DegenerateTokens;

    [Theory]
    [MemberData(nameof(DegenerateTokens))]
    public async Task BackChannelLogout_AnswersTheUniform400_AndMintsNoRevoke(string logoutToken)
    {
        // The feature and the per-provider opt-in are both ON, so the endpoint reads the untrusted token
        // rather than collapsing to the rejection without looking at it - which is what makes this the 500
        // path rather than a repeat of the gate tests.
        var harness = new SsoControllerHarness(
            c =>
            {
                c.EnableSingleLogout = true;
                c.OidConfigs["kc"] = new OidConfig
                {
                    Enabled = true,
                    OidEndpoint = Authority,
                    OidClientId = "jf",
                    EnableBackChannelLogout = true,
                };
            },
            httpResponder: Responder);

        var result = await harness.Controller.OidBackChannelLogout("kc", logoutToken);

        // The uniform rejection, byte for byte - a distinguishable answer here is the oracle the uniform
        // 400 exists to close, and a 500 was one.
        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("Logout token could not be processed", content.Content);
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string>());
    }

    // Serves this fixture's discovery document and JWKS so the refusal is the token's shape and not a
    // failure to reach the provider; any other URL 404s so an unexpected call is visible.
    private HttpResponseMessage Responder(HttpRequestMessage request)
    {
        var url = request.RequestUri!.AbsoluteUri;
        if (url == _fixture.DiscoveryUrl)
        {
            return Json(_fixture.Discovery());
        }

        return url == _fixture.JwksUrl ? Json(_fixture.Jwks()) : new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private static HttpResponseMessage Json(string body) => new HttpResponseMessage(HttpStatusCode.OK)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json"),
    };
}
