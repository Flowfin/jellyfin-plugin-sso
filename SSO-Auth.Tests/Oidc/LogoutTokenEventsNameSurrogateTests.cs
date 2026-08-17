// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// <see cref="OidcLogoutTokenValidator"/>'s events check states a total contract - "any parse failure is a
/// fail-closed 'not a logout_token'" - and read the claim with <c>JsonElement.TryGetProperty</c>, the call
/// that made both discovery flag readers throw in #1340. That method unescapes every candidate member name
/// whose raw form is longer than the name being looked for, and an unpaired surrogate escape has no
/// completion, so the decoder raised <c>InvalidOperationException</c> out of the lookup instead of an answer
/// (#1349).
///
/// The padding is what decides whether the arm is reached at all, so every case here is built from the event
/// name's OWN length rather than from a hand-written constant, and
/// <see cref="TheSweepReachesTheDecoder_RatherThanPassingVacuously"/> pins where the boundary actually falls
/// so a sweep that stopped reaching it could not read as a pass.
///
/// Reachability is narrow and worth saying plainly: this arm runs only after the handler has accepted the
/// signature, issuer, audience and lifetime, so producing one of these tokens means holding the provider's
/// signing key. What was lost is the refusal itself - the uniform 400 and the audited reason - on a path
/// whose whole job is to answer rather than to throw.
/// </summary>
[Collection("SSOController")]
public sealed class LogoutTokenEventsNameSurrogateTests : IDisposable
{
    private const string Issuer = "https://idp-events.example.test";
    private const string ClientId = "jellyfin-client";
    private const string KeyId = "events-name-test-key";
    private const string LogoutEvent = "http://schemas.openid.net/event/backchannel-logout";

    private static readonly Guid UserA = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");

    private readonly RSA _rsa = RSA.Create(2048);
    private readonly OidcLogoutTokenValidator _validator = new();
    private readonly DateTime _now = DateTime.UtcNow;

    public LogoutTokenEventsNameSurrogateTests() => OidcLogoutTokenValidator.ResetReplaysForTests();

    public void Dispose()
    {
        _rsa.Dispose();
        OidcLogoutTokenValidator.ResetReplaysForTests();
    }

    [Fact]
    public async Task EventsNamingOnlyAnUndecodableMember_IsNotALogoutToken_AtEveryPadding()
    {
        // The refuse path, which is the one that threw. Swept rather than pinned at the measured length,
        // because the boundary is arithmetic on the event name and a sweep past it cannot be made vacuous
        // by a later rename of the constant.
        for (var filler = 0; filler <= LogoutEvent.Length + 8; filler++)
        {
            var token = SignedLogoutToken(UndecodableMember(filler));

            var result = await _validator.ValidateAsync(token, Options(), _now);

            Assert.False(result.IsValid);
            Assert.Equal(OidcLogoutTokenValidator.RejectReason.NotALogoutToken, result.ReasonCode);
        }
    }

    [Fact]
    public async Task UndecodableNameBesideTheRealEvent_IsStillALogoutToken_AtEveryPadding()
    {
        // The other direction, and the reason the repair skips the member instead of discarding the claim.
        // A bare catch around the lookup would answer "not a logout_token" for this token too, so an IdP
        // that sends one member nobody asked about would stop being able to terminate a session at all.
        for (var filler = 0; filler <= LogoutEvent.Length + 8; filler++)
        {
            var token = SignedLogoutToken(UndecodableMember(filler) + ",\"" + LogoutEvent + "\":{}");

            var result = await _validator.ValidateAsync(token, Options(), _now);

            Assert.True(result.IsValid);
            Assert.Equal("user-1", result.Subject);
        }
    }

    [Fact]
    public void TheSweepReachesTheDecoder_RatherThanPassingVacuously()
    {
        // The must-catch half, over the call the repair replaced rather than over the repaired method: a
        // sweep whose filler never makes the raw name outrun the name being matched would assert "it did
        // not throw" about bytes that were never going to. The first throwing padding is the event name's
        // length less five - the point at which the six-character escape plus the filler first exceeds it -
        // so this both proves the fixture bites and states the arithmetic the sweeps above rely on.
        var firstThrowing = -1;
        for (var filler = 0; filler <= LogoutEvent.Length + 8; filler++)
        {
            using var document = JsonDocument.Parse("{" + UndecodableMember(filler) + "}");
            try
            {
                document.RootElement.TryGetProperty(LogoutEvent, out _);
            }
            catch (InvalidOperationException)
            {
                firstThrowing = filler;
                break;
            }
        }

        Assert.Equal(LogoutEvent.Length - 5, firstThrowing);
    }

    [Fact]
    public async Task AtTheEndpoint_TheRefusalIsTheUniform400_AndReachesTheAuditTrail()
    {
        // What the throw cost, driven through the endpoint rather than described: the uniform 400 that
        // exists so no branch is distinguishable to the caller, and the audit line an operator watches. The
        // padding is the first one the decoder is asked to complete, from the same arithmetic pinned above.
        var harness = new SsoControllerHarness(
            config =>
            {
                config.EnableSingleLogout = true;
                config.OidConfigs["kc"] = new OidConfig
                {
                    Enabled = true,
                    OidEndpoint = Issuer,
                    OidClientId = ClientId,
                    EnableBackChannelLogout = true,
                };
                config.LogoutSessions["a"] = new LogoutSession
                {
                    Protocol = "OpenID",
                    Provider = "kc",
                    Subject = "user-1",
                    SessionIndex = "sess-9",
                    UserId = UserA,
                    IdToken = "raw.id.token",
                };
            },
            httpResponder: Responder);

        var token = SignedLogoutToken(UndecodableMember(LogoutEvent.Length - 5));

        var result = await harness.Controller.OidBackChannelLogout("kc", token);

        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(400, content.StatusCode);
        Assert.Equal("Logout token could not be processed", content.Content);

        var entry = Assert.Single(harness.ControllerLog.Entries, e => e.Message.Contains("REJECTED", StringComparison.Ordinal));
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains(OidcLogoutTokenValidator.RejectReason.NotALogoutToken, entry.Message, StringComparison.Ordinal);

        // Nothing was terminated on a refusal, and the captured session is still there to terminate later.
        await harness.SessionManager.DidNotReceive().RevokeUserTokens(Arg.Any<Guid>(), Arg.Any<string>());
        Assert.True(SSOPlugin.Instance.ReadConfiguration(c => c.LogoutSessions.ContainsKey("a")));
    }

    // `\ud800` is a high surrogate with no low surrogate after it: six raw characters no unescape can
    // complete. The filler pads the name so the raw member name outruns the name being looked for, which is
    // the only reason the lookup tries to unescape it at all.
    private static string UndecodableMember(int filler) => "\"\\ud800" + new string('a', filler) + "\":{}";

    // Signed by hand rather than through a claims dictionary: the serializer would never emit a member name
    // the decoder cannot complete, and these bytes are the whole point of the fixture. Everything but the
    // events object is an ordinary valid logout_token, so the only thing under test is the events member.
    private string SignedLogoutToken(string eventsMembers)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var payload = "{\"iss\":\"" + Issuer + "\",\"aud\":\"" + ClientId + "\",\"sub\":\"user-1\",\"jti\":\""
            + Guid.NewGuid() + "\",\"iat\":" + now + ",\"nbf\":" + (now - 60) + ",\"exp\":" + (now + 300)
            + ",\"events\":{" + eventsMembers + "}}";

        var header = "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"" + KeyId + "\"}";
        var signingInput = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header))
            + "." + Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload));

        var signature = _rsa.SignData(
            Encoding.UTF8.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return signingInput + "." + Base64UrlEncoder.Encode(signature);
    }

    private string Jwks()
    {
        var p = _rsa.ExportParameters(false);
        return "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"" + KeyId + "\",\"n\":\""
            + Base64UrlEncoder.Encode(p.Modulus) + "\",\"e\":\"" + Base64UrlEncoder.Encode(p.Exponent) + "\"}]}";
    }

    // The provider options the endpoint hands the validator, built here so the unit sweeps run against the
    // same issuer, client and key the endpoint test serves.
    private OidcClientOptions Options() => new OidcClientOptions
    {
        ClientId = ClientId,
        ClockSkew = TimeSpan.FromMinutes(5),
        ProviderInformation = new ProviderInformation
        {
            IssuerName = Issuer,
            KeySet = new Duende.IdentityModel.Jwk.JsonWebKeySet(Jwks()),
        },
    };

    // Serves this test's discovery document and JWKS; any other URL 404s so an unexpected call is visible.
    private HttpResponseMessage Responder(HttpRequestMessage request)
    {
        var url = request.RequestUri!.AbsoluteUri;
        if (url == Issuer + "/.well-known/openid-configuration")
        {
            return Json("{\"issuer\":\"" + Issuer + "\",\"authorization_endpoint\":\"" + Issuer
                + "/auth\",\"token_endpoint\":\"" + Issuer + "/token\",\"jwks_uri\":\"" + Issuer
                + "/jwks\",\"response_types_supported\":[\"code\"],\"subject_types_supported\":[\"public\"],"
                + "\"id_token_signing_alg_values_supported\":[\"RS256\"],"
                + "\"code_challenge_methods_supported\":[\"S256\"]}");
        }

        if (url == Issuer + "/jwks")
        {
            return Json(Jwks());
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private static HttpResponseMessage Json(string body) => new HttpResponseMessage(HttpStatusCode.OK)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json"),
    };
}
