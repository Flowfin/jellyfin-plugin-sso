// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Http;
using Jellyfin.Plugin.SSO_Auth.Api.Localization;
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
/// public facts and rejects a non-parsing one; NEITHER path ever leaks a stored secret into the result; and
/// every verdict and fact is a catalogue key with a row in every shipped language (#1728), so the page
/// renders it in the administrator's language rather than as English built here.
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

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", factory, Logger(), cancellationToken: TestContext.Current.CancellationToken);

        Assert.True(result.Ok);
        Assert.Equal(ProviderTestKeys.OidcDiscoveryRead, result.Key);
        Assert.Contains(new ProviderTestFact(ProviderTestKeys.Issuer, Authority), result.Facts);
        Assert.Contains(new ProviderTestFact(ProviderTestKeys.AuthorizationEndpoint, Authority + "/authorize"), result.Facts);
        Assert.Contains(new ProviderTestFact(ProviderTestKeys.TokenEndpoint, Authority + "/token"), result.Facts);
        Assert.Contains(new ProviderTestFact(ProviderTestKeys.UserInfoEndpoint, Authority + "/userinfo"), result.Facts);
        // The JWKS was reachable (the reader fetches it as part of discovery) - one key served below.
        Assert.Contains(new ProviderTestFact(ProviderTestKeys.JwksReachable, "1"), result.Facts);
        Assert.Contains(new ProviderTestFact(ProviderTestKeys.PkceAdvertised, null), result.Facts);
        Assert.Contains(new ProviderTestFact(ProviderTestKeys.ResponseIssuerAdvertised, null), result.Facts);
    }

    [Fact]
    public async Task TestOidcAsync_AFactTheDocumentDidNotAdvertise_CarriesNoValue()
    {
        // #1728: the page fills a fact's {value} slot from the value, and a fact with NO value is rendered as the
        // not-advertised row in the administrator's language. So a document that omits an endpoint must send
        // the fact with a null value rather than an empty string or a sentence: an empty string would render
        // "UserInfo endpoint: " and nothing after it, and a sentence would be English on a German page. The
        // two facts that are true-or-false arrive as one of two keys and never as a yes/no word, for the same
        // reason.
        var config = new OidConfig { OidEndpoint = Authority, OidClientId = "jf" };
        var withoutUserInfo = FullDiscovery(Authority).Replace($"\"userinfo_endpoint\":\"{Authority}/userinfo\",", string.Empty, StringComparison.Ordinal);
        var withoutPkce = withoutUserInfo.Replace("\"code_challenge_methods_supported\":[\"S256\"],", string.Empty, StringComparison.Ordinal);

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", FactoryFor(Serve(withoutPkce)), Logger(), cancellationToken: TestContext.Current.CancellationToken);

        Assert.True(result.Ok);
        Assert.Contains(new ProviderTestFact(ProviderTestKeys.UserInfoEndpoint, null), result.Facts);
        Assert.Contains(new ProviderTestFact(ProviderTestKeys.PkceNotAdvertised, null), result.Facts);
        Assert.DoesNotContain(result.Facts, f => f.Key == ProviderTestKeys.PkceAdvertised);
        Assert.All(result.Facts, f => Assert.NotEqual(string.Empty, f.Value));
    }

    [Fact]
    public async Task TestOidcAsync_UnreadableDiscovery_FailsClosedWithActionableVerdict()
    {
        var config = new OidConfig { OidEndpoint = "https://idp-unreachable.example.com", OidClientId = "jf" };
        var factory = FactoryFor(_ => throw new HttpRequestException("unreachable"));

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", factory, Logger(), cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result.Ok);
        Assert.Equal(ProviderTestKeys.OidcUnreadable, result.Key);
        Assert.Contains("discovery document", SsoLocalizer.GetString(result.Key, SsoLocalizer.FallbackCulture), StringComparison.OrdinalIgnoreCase);
        Assert.Empty(result.Facts);
    }

    [Fact]
    public async Task TestOidcAsync_ADocumentTheScreenRefused_IsReportedUnderItsOwnCause()
    {
        // The probe is the one in-product diagnostic on the recovery path (#1064). A document the provider
        // served fine and the screen refused used to arrive under the reachability/well-known/HTTPS verdict,
        // which answers confidently and sends the admin to look at connectivity for a provider defect.
        //
        // The verdict is asserted EQUAL rather than the cause merely being asserted present: a probe that
        // reported the generic verdict for every failure would satisfy a presence-only check on a shared
        // fragment while still telling the admin to go and check their TLS.
        var config = new OidConfig { OidEndpoint = Authority, OidClientId = "jf" };
        var repeated = FullDiscovery(Authority).Insert(1, "\"issuer\":\"https://attacker.example\",");
        var logger = new CapturingLogger();

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", FactoryFor(Serve(repeated)), logger, cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result.Ok);
        Assert.Equal(ProviderTestKeys.OidcRefusedRepeatedMember, result.Key);

        // The English wording the admin reads on screen opens with the wording the server log carries, byte for
        // byte, because the English row and the log entry both render one constant. Reword either side alone
        // and this goes red, which is what keeps an admin matching the UI against the log from having to
        // translate between two paraphrases. A translated dashboard reads its own row, and the log stays the
        // English side of that pairing on purpose (#1728).
        Assert.StartsWith(RepeatedMemberScreen.RefusalReason, SsoLocalizer.GetString(result.Key, SsoLocalizer.FallbackCulture), StringComparison.Ordinal);
        Assert.Contains(
            logger.Entries,
            e => e.Message.StartsWith("Refused the OpenID", StringComparison.Ordinal)
                && e.Message.Contains(RepeatedMemberScreen.RefusalReason, StringComparison.Ordinal));

        // The member name is a provider-authored string, and every bound and filter it needs sits on the log
        // entry rather than here. This surface is elevation-gated, so the reason it stays out is not the login
        // path's disclosure question - it is that one place stays responsible for bounding it.
        Assert.DoesNotContain("attacker.example", JsonSerializer.Serialize(result), StringComparison.Ordinal);
    }

    [Fact]
    public async Task TestOidcAsync_AnUninspectableBody_IsReportedApartFromTheRepeatedMember()
    {
        // The two screened refusals have different remedies - one is a provider defect to report, the other is
        // a truncation or a charset problem - so collapsing them into one verdict loses the thing the admin
        // came to the probe for. An unknown charset is the provider-reachable instance of the second.
        var config = new OidConfig { OidEndpoint = Authority, OidClientId = "jf" };
        var factory = FactoryFor(_ => JsonWithCharset(FullDiscovery(Authority), "zzMarkerCharsetzz"));

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", factory, Logger(), cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result.Ok);
        Assert.Equal(ProviderTestKeys.OidcRefusedUninspectable, result.Key);
        Assert.StartsWith(RepeatedMemberScreen.UninspectableReason, SsoLocalizer.GetString(result.Key, SsoLocalizer.FallbackCulture), StringComparison.Ordinal);

        // The charset is the provider's to choose, so it is one more untrusted string and never reaches an
        // admin-facing field, exactly as it never reaches the log entry.
        Assert.DoesNotContain("zzMarkerCharsetzz", JsonSerializer.Serialize(result), StringComparison.Ordinal);
    }

    [Fact]
    public async Task TestOidcAsync_AFailureNoScreenRaised_KeepsTheReachabilityCause()
    {
        // The other direction, and the one that stops the new causes being reported for every failure. An
        // unreachable endpoint is refused before any body exists to screen, so the reason stays Unnamed and
        // the verdict that names what to CHECK is still the right one. Without this row, a probe that reported
        // a screen refusal unconditionally would pass every assertion above.
        var config = new OidConfig { OidEndpoint = "https://idp-unreachable.example.com", OidClientId = "jf" };
        var factory = FactoryFor(_ => throw new HttpRequestException("unreachable"));

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", factory, Logger(), cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result.Ok);
        Assert.Equal(ProviderTestKeys.OidcUnreadable, result.Key);
        Assert.Contains("/.well-known/openid-configuration", SsoLocalizer.GetString(result.Key, SsoLocalizer.FallbackCulture), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("not-a-url")]
    [InlineData("ftp:///")]
    public async Task TestOidcAsync_InvalidEndpoint_FailsClosed(string endpoint)
    {
        var config = new OidConfig { OidEndpoint = endpoint, OidClientId = "jf" };
        var factory = FactoryFor(Serve(FullDiscovery(Authority)));

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", factory, Logger(), cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result.Ok);
        Assert.Equal(ProviderTestKeys.OidcInvalidEndpoint, result.Key);
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

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", factory, Logger(), cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result.Ok);
        Assert.Equal(ProviderTestKeys.OidcNoEndpoint, result.Key);
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

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", factory, Logger(), cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result.Ok);
        Assert.False(fetched);
    }

    [Fact]
    public async Task TestOidcAsync_NeverLeaksTheStoredClientSecret()
    {
        var config = new OidConfig { OidEndpoint = Authority, OidClientId = "jf", OidSecret = OidSecretSentinel };
        var factory = FactoryFor(Serve(FullDiscovery(Authority)));

        var result = await ProviderConnectionTester.TestOidcAsync(config, "kc", factory, Logger(), cancellationToken: TestContext.Current.CancellationToken);

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

        await ProviderConnectionTester.TestOidcAsync(strict, "public-idp", factory, Logger(), cancellationToken: TestContext.Current.CancellationToken);

        Assert.NotEmpty(requested);
        Assert.All(requested, name => Assert.Equal(SsoHttp.OutboundClientName, name));

        requested.Clear();
        await ProviderConnectionTester.TestOidcAsync(optedIn, "lan-idp", factory, Logger(), cancellationToken: TestContext.Current.CancellationToken);

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
        Assert.Equal(ProviderTestKeys.SamlCertificateParsed, result.Key);
        Assert.Contains(result.Facts, f => f.Key == ProviderTestKeys.CertificateSubject && !string.IsNullOrEmpty(f.Value));
        Assert.Contains(result.Facts, f => f.Key == ProviderTestKeys.CertificateThumbprint && f.Value?.Length == 64);
        // A certificate inside its validity raises no note - the negative of the row below.
        Assert.DoesNotContain(result.Facts, f => f.Key == ProviderTestKeys.CertificateOutsideValidity);
        // The service-provider signing key (a secret) must never appear in the public-cert report.
        AssertNoSecret(result, SamlKeySentinel);
    }

    [Fact]
    public void TestSaml_ACertificateOutsideItsValidity_SaysSo()
    {
        // An expired identity-provider certificate still parses, so the verdict is a pass; the note is the fact
        // an admin acting on that pass needs, and it is a key like every other line so a German page says it in
        // German (#1728).
        var expired = SamlTestFactory.Create(certNotBefore: DateTimeOffset.UtcNow.AddYears(-2), certNotAfter: DateTimeOffset.UtcNow.AddYears(-1));

        var result = ProviderConnectionTester.TestSaml(new SamlConfig { SamlCertificate = expired.CertificateBase64 });

        Assert.True(result.Ok);
        Assert.Contains(new ProviderTestFact(ProviderTestKeys.CertificateOutsideValidity, null), result.Facts);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void TestSaml_BlankCertificate_FailsClosed(string? certificate)
    {
        var result = ProviderConnectionTester.TestSaml(new SamlConfig { SamlCertificate = certificate });

        Assert.False(result.Ok);
        Assert.Equal(ProviderTestKeys.SamlNoCertificate, result.Key);
        Assert.Empty(result.Facts);
    }

    [Theory]
    [InlineData("@@ not base64 @@")]
    [InlineData("QUJD")] // valid base64 ("ABC") but not a certificate
    public void TestSaml_UnparsableCertificate_FailsClosed(string certificate)
    {
        var result = ProviderConnectionTester.TestSaml(new SamlConfig { SamlCertificate = certificate });

        Assert.False(result.Ok);
        Assert.Equal(ProviderTestKeys.SamlCertificateUnparsable, result.Key);
        Assert.Contains("could not be parsed", SsoLocalizer.GetString(result.Key, SsoLocalizer.FallbackCulture), StringComparison.OrdinalIgnoreCase);
    }

    // Asserts the sentinel secret appears in NO admin-facing field of the result - the verdict, and every fact's
    // key and value - by reading the same JSON the controller returns.
    private static void AssertNoSecret(ProviderTestResult result, string secret)
    {
        Assert.DoesNotContain(secret, JsonSerializer.Serialize(result), StringComparison.Ordinal);
        Assert.All(result.Facts, f => Assert.DoesNotContain(secret, f.Value ?? string.Empty, StringComparison.Ordinal));
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
