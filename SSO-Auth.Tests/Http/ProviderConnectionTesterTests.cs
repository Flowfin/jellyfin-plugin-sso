// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Http;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="ProviderConnectionTester"/> - the admin Test-connection probe (#163). They pin:
/// the OpenID probe reads discovery through the hardened reader and reports the issuer, endpoints and JWKS
/// reachability; an unreadable document / invalid endpoint / missing endpoint returns a fail-closed,
/// actionable, secret-free result rather than throwing; the SAML probe reports a parsing certificate's
/// public facts and rejects a non-parsing one; and NEITHER path ever leaks a stored secret into the result.
/// </summary>
public class ProviderConnectionTesterTests
{
    private const string Authority = "https://idp-test.example.com";
    private const string OidSecretSentinel = "super-secret-oid-client-secret-value";
    private const string SamlKeySentinel = "super-secret-saml-signing-key-pfx-value";

    private static string FullDiscovery(string authority) =>
        "{"
        + $"\"issuer\":\"{authority}\","
        + $"\"authorization_endpoint\":\"{authority}/authorize\","
        + $"\"token_endpoint\":\"{authority}/token\","
        + $"\"userinfo_endpoint\":\"{authority}/userinfo\","
        + $"\"jwks_uri\":\"{authority}/jwks\","
        + "\"response_types_supported\":[\"code\"],"
        + "\"subject_types_supported\":[\"public\"],"
        + "\"id_token_signing_alg_values_supported\":[\"RS256\"],"
        + "\"code_challenge_methods_supported\":[\"S256\"],"
        + "\"authorization_response_iss_parameter_supported\":true}";

    private static ILogger Logger() => Substitute.For<ILogger>();

    [Fact]
    public async Task TestOidcAsync_ServedDiscovery_ReportsIssuerEndpointsAndJwks()
    {
        var config = new OidConfig { OidEndpoint = Authority, OidClientId = "jf", OidSecret = OidSecretSentinel };
        var factory = FactoryFor(Serve(FullDiscovery(Authority)));

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", factory, Logger());

        Assert.True(result.Ok);
        Assert.Contains(result.Details, d => d.Contains(Authority, StringComparison.Ordinal) && d.StartsWith("Issuer:", StringComparison.Ordinal));
        Assert.Contains(result.Details, d => d.Contains(Authority + "/authorize", StringComparison.Ordinal));
        Assert.Contains(result.Details, d => d.Contains(Authority + "/token", StringComparison.Ordinal));
        // The JWKS was reachable (the reader fetches it as part of discovery) - one key served below.
        Assert.Contains(result.Details, d => d.StartsWith("JWKS: reachable", StringComparison.Ordinal));
        Assert.Contains(result.Details, d => d.StartsWith("PKCE (S256) advertised: yes", StringComparison.Ordinal));
    }

    [Fact]
    public async Task TestOidcAsync_UnreadableDiscovery_FailsClosedWithActionableMessage()
    {
        var config = new OidConfig { OidEndpoint = "https://idp-unreachable.example.com", OidClientId = "jf" };
        var factory = FactoryFor(_ => throw new HttpRequestException("unreachable"));

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", factory, Logger());

        Assert.False(result.Ok);
        Assert.Contains("discovery document", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(result.Details);
    }

    [Fact]
    public async Task TestOidcAsync_ADocumentTheScreenRefused_IsReportedUnderItsOwnCause()
    {
        // The probe is the one in-product diagnostic on the recovery path (#1064). A document the provider
        // served fine and the screen refused used to arrive under the reachability/well-known/HTTPS message,
        // which answers confidently and sends the admin to look at connectivity for a provider defect.
        //
        // The generic sentence's own marker is asserted ABSENT rather than the cause merely being asserted
        // present: a probe that appended the new cause to the old one would satisfy a presence-only check
        // while still telling the admin to go and check their TLS.
        var config = new OidConfig { OidEndpoint = Authority, OidClientId = "jf" };
        var repeated = FullDiscovery(Authority).Insert(1, "\"issuer\":\"https://attacker.example\",");
        var logger = new CapturingLogger();

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", FactoryFor(Serve(repeated)), logger);

        Assert.False(result.Ok);
        Assert.Contains(RepeatedMemberScreen.RefusalReason, result.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("/.well-known/openid-configuration", result.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(RepeatedMemberScreen.UninspectableReason, result.Message, StringComparison.Ordinal);

        // The wording the admin reads on screen is the wording the server log carries, byte for byte, because
        // both render one constant. Reword either side alone and this goes red, which is what keeps an admin
        // matching the UI against the log from having to translate between two paraphrases.
        Assert.Contains(
            logger.Entries,
            e => e.Message.StartsWith("Refused the OpenID", StringComparison.Ordinal)
                && e.Message.Contains(RepeatedMemberScreen.RefusalReason, StringComparison.Ordinal));

        // The member name is a provider-authored string, and every bound and filter it needs sits on the log
        // entry rather than here. This surface is elevation-gated, so the reason it stays out is not the login
        // path's disclosure question - it is that one place stays responsible for bounding it.
        Assert.DoesNotContain("attacker.example", result.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TestOidcAsync_AnUninspectableBody_IsReportedApartFromTheRepeatedMember()
    {
        // The two screened refusals have different remedies - one is a provider defect to report, the other is
        // a truncation or a charset problem - so collapsing them into one message loses the thing the admin
        // came to the probe for. An unknown charset is the provider-reachable instance of the second.
        var config = new OidConfig { OidEndpoint = Authority, OidClientId = "jf" };
        var factory = FactoryFor(_ => JsonWithCharset(FullDiscovery(Authority), "zzMarkerCharsetzz"));

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", factory, Logger());

        Assert.False(result.Ok);
        Assert.Contains(RepeatedMemberScreen.UninspectableReason, result.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(RepeatedMemberScreen.RefusalReason, result.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("/.well-known/openid-configuration", result.Message, StringComparison.Ordinal);

        // The charset is the provider's to choose, so it is one more untrusted string and never reaches an
        // admin-facing field, exactly as it never reaches the log entry.
        Assert.DoesNotContain("zzMarkerCharsetzz", result.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TestOidcAsync_AFailureNoScreenRaised_KeepsTheReachabilityCause()
    {
        // The other direction, and the one that stops the new causes being reported for every failure. An
        // unreachable endpoint is refused before any body exists to screen, so the reason stays Unnamed and
        // the message that names what to CHECK is still the right one. Without this row, a probe that reported
        // a screen refusal unconditionally would pass every assertion above.
        var config = new OidConfig { OidEndpoint = "https://idp-unreachable.example.com", OidClientId = "jf" };
        var factory = FactoryFor(_ => throw new HttpRequestException("unreachable"));

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", factory, Logger());

        Assert.False(result.Ok);
        Assert.Contains("/.well-known/openid-configuration", result.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(RepeatedMemberScreen.RefusalReason, result.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(RepeatedMemberScreen.UninspectableReason, result.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("not-a-url")]
    [InlineData("ftp:///")]
    public async Task TestOidcAsync_InvalidEndpoint_FailsClosed(string endpoint)
    {
        var config = new OidConfig { OidEndpoint = endpoint, OidClientId = "jf" };
        var factory = FactoryFor(Serve(FullDiscovery(Authority)));

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", factory, Logger());

        Assert.False(result.Ok);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task TestOidcAsync_NoEndpoint_FailsClosed_WithoutFetching(string? endpoint)
    {
        var config = new OidConfig { OidEndpoint = endpoint };
        var contacted = false;
        var factory = FactoryFor(request =>
        {
            contacted = true;
            return Json(FullDiscovery(Authority));
        });

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", factory, Logger());

        Assert.False(result.Ok);
        Assert.False(contacted); // no endpoint -> no outbound fetch
    }

    [Fact]
    public async Task TestOidcAsync_NonHttpsUnderRequireHttps_FailsClosed()
    {
        // DisableHttps is off (default), so the discovery policy is RequireHttps; a plaintext endpoint is
        // refused by the reader before any fetch - the probe inherits the login's SSRF/TLS posture (#163).
        const string httpAuthority = "http://idp-plaintext.example.com";
        var config = new OidConfig { OidEndpoint = httpAuthority, OidClientId = "jf" };
        var fetched = false;
        var factory = FactoryFor(request =>
        {
            fetched = true;
            return Json(FullDiscovery(httpAuthority));
        });

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", factory, Logger());

        Assert.False(result.Ok);
        Assert.False(fetched);
    }

    [Fact]
    public async Task TestOidcAsync_NeverLeaksTheStoredClientSecret()
    {
        var config = new OidConfig { OidEndpoint = Authority, OidClientId = "jf", OidSecret = OidSecretSentinel };
        var factory = FactoryFor(Serve(FullDiscovery(Authority)));

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", factory, Logger());

        AssertNoSecret(result, OidSecretSentinel);
    }

    [Fact]
    public async Task TestOidcAsync_SelectsTheTransportTier_PerProvider_OnOneInstance()
    {
        // The claim of #1179 is that the relaxation reaches exactly the provider that asked for it. The
        // transport tests prove a flag selects a client name; this proves the SELECTION, with two providers
        // configured on one instance differing only in the opt-in, at a real backchannel call site.
        //
        // It closes the one leak the conformance roster cannot see: that roster lists the files allowed to
        // name the relaxation, and every backchannel file is on it, so a call site passing a literal true
        // instead of the provider's own setting would relax every provider and stay green. Here it makes
        // the two halves below disagree.
        var requested = new List<string>();
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(call =>
        {
            requested.Add(call.Arg<string>() ?? string.Empty);
            return new HttpClient(new StubHttpMessageHandler(Serve(FullDiscovery(Authority))));
        });

        var strict = new OidConfig { OidEndpoint = Authority, OidClientId = "jf" };
        var optedIn = new OidConfig { OidEndpoint = Authority, OidClientId = "jf", AllowPrivateNetworkAddresses = true };

        await ProviderConnectionTester.TestOidcAsync(strict, "public-idp", factory, Logger());

        Assert.NotEmpty(requested);
        Assert.All(requested, name => Assert.Equal(SsoHttp.OutboundClientName, name));

        requested.Clear();
        await ProviderConnectionTester.TestOidcAsync(optedIn, "lan-idp", factory, Logger());

        Assert.NotEmpty(requested);
        Assert.All(requested, name => Assert.Equal(SsoHttp.PrivateOutboundClientName, name));
    }

    [Fact]
    public void TestSaml_ValidCertificate_ReportsPublicFacts()
    {
        var config = new SamlConfig
        {
            SamlCertificate = SamlTestFactory.Create().CertificateBase64,
            SamlSigningKeyPfx = SamlKeySentinel,
        };

        var result = ProviderConnectionTester.TestSaml(config);

        Assert.True(result.Ok);
        Assert.Contains(result.Details, d => d.StartsWith("Subject:", StringComparison.Ordinal));
        Assert.Contains(result.Details, d => d.StartsWith("SHA-256 thumbprint:", StringComparison.Ordinal));
        // The service-provider signing key (a secret) must never appear in the public-cert report.
        AssertNoSecret(result, SamlKeySentinel);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void TestSaml_BlankCertificate_FailsClosed(string? certificate)
    {
        var result = ProviderConnectionTester.TestSaml(new SamlConfig { SamlCertificate = certificate });

        Assert.False(result.Ok);
        Assert.Empty(result.Details);
    }

    [Theory]
    [InlineData("@@ not base64 @@")]
    [InlineData("QUJD")] // valid base64 ("ABC") but not a certificate
    public void TestSaml_UnparsableCertificate_FailsClosed(string certificate)
    {
        var result = ProviderConnectionTester.TestSaml(new SamlConfig { SamlCertificate = certificate });

        Assert.False(result.Ok);
        Assert.Contains("could not be parsed", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    // Asserts the sentinel secret appears in NO admin-facing field of the result.
    private static void AssertNoSecret(ProviderTestResult result, string secret)
    {
        Assert.DoesNotContain(secret, result.Message, StringComparison.Ordinal);
        Assert.All(result.Details, d => Assert.DoesNotContain(secret, d, StringComparison.Ordinal));
    }

    private static Func<HttpRequestMessage, HttpResponseMessage> Serve(string discoveryJson) => request =>
    {
        var url = request.RequestUri!.AbsoluteUri;
        if (url.EndsWith("/.well-known/openid-configuration", StringComparison.Ordinal))
        {
            return Json(discoveryJson);
        }

        // One RSA key so the JWKS reachability line reports a positive count.
        if (url.EndsWith("/jwks", StringComparison.Ordinal))
        {
            return Json("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"k1\",\"n\":\"abc\",\"e\":\"AQAB\"}]}");
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    };

    // A body the runtime cannot decode, because the Content-Type names a character set it does not know. The
    // charset is provider-chosen, so this is the reachable instance of the screen's uninspectable refusal.
    private static HttpResponseMessage JsonWithCharset(string body, string charset)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = charset };
        return response;
    }

    private static HttpResponseMessage Json(string body) =>
        new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static IHttpClientFactory FactoryFor(Func<HttpRequestMessage, HttpResponseMessage> responder)
    {
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(new StubHttpMessageHandler(responder)));
        return factory;
    }
}
