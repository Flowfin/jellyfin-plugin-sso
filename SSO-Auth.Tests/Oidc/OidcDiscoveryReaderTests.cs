// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="OidcDiscoveryReader"/> — the single, policy-validated discovery read the OpenID
/// challenge performs, sourcing BOTH the two security facts (PKCE-S256 #141, RFC 9207 response-<c>iss</c>
/// #210) AND the <see cref="ProviderInformation"/> the login is fed from ONE response (#450). They pin:
/// a served document yields the facts plus the metadata OidcClient would build; a document that omits a
/// fact reports a definite <c>false</c> (not a silent downgrade); an unreadable document returns
/// <see cref="OidcDiscoveryResult.Unavailable"/> so the caller fails the login closed; and the read honours
/// the <c>DiscoveryPolicy</c> — a non-HTTPS authority under <c>RequireHttps</c> is refused before any fetch,
/// closing the pre-#450 probe's weak-channel gap.
/// </summary>
public class OidcDiscoveryReaderTests
{
    private const string Authority = "https://idp-reader.example.com";
    private const string DiscoveryUrl = Authority + "/.well-known/openid-configuration";
    private const string JwksUrl = Authority + "/jwks";

    // A discovery document that advertises PKCE S256 and the RFC 9207 response-iss parameter and names the
    // endpoints OidcClient maps onto ProviderInformation.
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

    private static OidcClientOptions OptionsFor(string authority, bool requireHttps = true)
    {
        var options = new OidcClientOptions { Authority = authority };
        options.Policy.Discovery.AdditionalEndpointBaseAddresses.Add(new Uri(authority).GetLeftPart(UriPartial.Authority));
        options.Policy.Discovery.RequireHttps = requireHttps;
        options.Policy.Discovery.ValidateIssuerName = true;
        options.Policy.Discovery.ValidateEndpoints = true;
        return options;
    }

    private static ILogger Logger() => Substitute.For<ILogger>();

    [Fact]
    public async Task ReadAsync_ServedDiscovery_ReturnsFactsAndMetadataFromTheOneResponse()
    {
        var http = new CountingFactory(Serve(FullDiscovery(Authority)));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, Logger());

        Assert.True(result.Available);
        // Facts read from the SAME discovery response the metadata is built from (#450).
        Assert.True(result.Facts.PkceS256);
        Assert.True(result.Facts.ResponseIssuerAdvertised);
        // The metadata OidcClient's own discovery would produce, so PrepareLoginAsync can reuse it.
        Assert.Equal(Authority, result.ProviderInformation.IssuerName);
        Assert.Equal(Authority + "/authorize", result.ProviderInformation.AuthorizeEndpoint);
        Assert.Equal(Authority + "/token", result.ProviderInformation.TokenEndpoint);
        Assert.NotNull(result.ProviderInformation.KeySet);
        // Exactly one discovery document was fetched (plus its JWKS) — no second probe (#450).
        Assert.Equal(1, http.DiscoveryRequests);
    }

    [Fact]
    public async Task ReadAsync_DiscoveryWithoutS256_ReportsDefiniteFalse_StillAvailable()
    {
        // A readable document that does not advertise S256: PkceS256 is a definite false, not a null/absent
        // that the caller could misread — the caller then rejects only under RequirePkce.
        var discovery = "{"
            + $"\"issuer\":\"{Authority}\","
            + $"\"authorization_endpoint\":\"{Authority}/authorize\","
            + $"\"token_endpoint\":\"{Authority}/token\","
            + $"\"jwks_uri\":\"{Authority}/jwks\","
            + "\"authorization_response_iss_parameter_supported\":true}";
        var http = new CountingFactory(Serve(discovery));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, Logger());

        Assert.True(result.Available);
        Assert.False(result.Facts.PkceS256);
        Assert.True(result.Facts.ResponseIssuerAdvertised);
    }

    [Fact]
    public async Task ReadAsync_DiscoveryWithoutResponseIssuerParam_ReportsTolerantFalse()
    {
        // The RFC 9207 parameter is absent: ResponseIssuerAdvertised is false (tolerant), so the callback
        // does not require `iss` — an IdP that never emits it keeps working (#210). This false comes from a
        // document that WAS read, so it is authoritative, not a failed-probe downgrade.
        var discovery = "{"
            + $"\"issuer\":\"{Authority}\","
            + $"\"authorization_endpoint\":\"{Authority}/authorize\","
            + $"\"token_endpoint\":\"{Authority}/token\","
            + $"\"jwks_uri\":\"{Authority}/jwks\","
            + "\"code_challenge_methods_supported\":[\"S256\"]}";
        var http = new CountingFactory(Serve(discovery));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, Logger());

        Assert.True(result.Available);
        Assert.True(result.Facts.PkceS256);
        Assert.False(result.Facts.ResponseIssuerAdvertised);
    }

    [Fact]
    public async Task ReadAsync_FetchFailure_ReturnsUnavailable()
    {
        // The document could not be read at all: Unavailable, so the caller fails the login closed rather
        // than proceeding on unverified facts (#450). Never a tolerant default that silently weakens iss.
        var http = new CountingFactory(_ => throw new HttpRequestException("unreachable"));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, Logger());

        Assert.False(result.Available);
        Assert.Null(result.ProviderInformation);
    }

    [Fact]
    public async Task ReadAsync_NonHttpsAuthorityUnderRequireHttps_ReturnsUnavailable_WithoutFetching()
    {
        // The DiscoveryPolicy is honoured: a non-HTTPS authority under RequireHttps is refused by
        // IdentityModel before any request leaves the process, so a network attacker on a plaintext
        // discovery channel cannot strip the advertised facts (the pre-#450 probe issued a raw GET with no
        // such policy). The caller then fails closed.
        const string httpAuthority = "http://idp-plaintext.example.com";
        var http = new CountingFactory(Serve(FullDiscovery(httpAuthority)));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(httpAuthority, requireHttps: true), "kc", http.Factory, Logger());

        Assert.False(result.Available);
        Assert.Equal(0, http.DiscoveryRequests); // policy rejected the address before any fetch
    }

    [Fact]
    public async Task DuplicatedMemberInTheDiscoveryDocument_FailsTheReadClosed()
    {
        // A discovery document whose root names `issuer` twice means two things at once: every reader in the
        // dependency set keeps the LAST occurrence silently, so the anchor the login binds itself to is
        // re-pointed with no error raised anywhere (#1005). The screen refuses it on the transport.
        var duplicated = FullDiscovery(Authority).Insert(1, $"\"issuer\":\"https://attacker.example\",");
        var http = new CountingFactory(Serve(duplicated));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, Logger());

        Assert.False(result.Available);
    }

    [Fact]
    public async Task TheSameDiscoveryDocumentWithoutTheDuplicate_IsStillRead()
    {
        // The positive control on the same subject. Without it, a screen that refused every document would
        // satisfy the rejection above while taking every working provider offline — and it also proves the
        // screen's body read leaves the response readable for the library that parses it afterwards.
        var http = new CountingFactory(Serve(FullDiscovery(Authority)));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, Logger());

        Assert.True(result.Available);
        Assert.Equal(Authority, result.ProviderInformation.IssuerName);
    }

    [Fact]
    public async Task DuplicatedJwksUri_RefusesTheDiscovery_AndNeverFetchesTheJwks()
    {
        // THE named conformance property (#1005). A post-hoc check cannot hold it: the library resolves the
        // repeated `jwks_uri` to its LAST occurrence and dereferences it, so a screen placed after the parse
        // would report the repeat only once the attacker-named URL had already been requested. Screening on
        // the transport means that URL is never requested at all.
        //
        // The fixture models that mechanism exactly, and two earlier spellings of it did not. Planting the
        // URL off-authority made the discovery policy's endpoint validation refuse it before any fetch, so
        // the row stayed green with the screen removed — evidence about ValidateEndpoints wearing this test's
        // name. Planting it FIRST left the honest URL as the last occurrence, so the attacker's URL was the
        // one nothing would ever fetch. Here it is same-authority (the policy accepts it) and last (the
        // occurrence every reader resolves to), so it is the URL a missing screen would actually request.
        var attackerJwks = Authority + "/jwks-attacker";
        var duplicated = FullDiscovery(Authority).TrimEnd('}') + $",\"jwks_uri\":\"{attackerJwks}\"}}";
        var http = new CountingFactory(Serve(duplicated));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, Logger());

        Assert.False(result.Available);
        Assert.Equal(1, http.DiscoveryRequests);

        // The attacker-named URL specifically was never requested, and neither was anything else: the total
        // does not depend on guessing which path a bypass would have chosen.
        Assert.DoesNotContain(attackerJwks, http.RequestedUrls);
        Assert.Equal(1, http.TotalRequests);
    }

    [Fact]
    public async Task DuplicatedMemberInTheJwksDocument_FailsTheReadClosed()
    {
        // The JWKS is the document that actually decides key selection, and it travels the same invoker, so
        // it is screened too: a key entry naming `kty` twice would let the entry mean two things to the
        // reader that materialises it.
        var http = new CountingFactory(Serve(FullDiscovery(Authority), "{\"keys\":[{\"kty\":\"RSA\",\"kty\":\"oct\"}]}"));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, Logger());

        Assert.False(result.Available);
        Assert.Equal(1, http.JwksRequests);
    }

    [Fact]
    public async Task ARealisticMultiKeyJwks_IsStillRead()
    {
        // The scope control at the seam: every JWKS entry legitimately repeats `kty`, `use`, `alg`, `n` and
        // `e` in SIBLING scopes. A screen pooling names document-wide would refuse every real provider here
        // while reporting an attack that is not there.
        const string twoKeys =
            "{\"keys\":["
            + "{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":\"a1\",\"n\":\"xGOr\",\"e\":\"AQAB\"},"
            + "{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":\"b2\",\"n\":\"yHPs\",\"e\":\"AQAB\"}]}";
        var http = new CountingFactory(Serve(FullDiscovery(Authority), twoKeys));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, Logger());

        Assert.True(result.Available);
        Assert.NotNull(result.ProviderInformation.KeySet);
    }

    [Fact]
    public async Task LoneSurrogateDocument_IsRefusedWithoutCrashing()
    {
        // Thirteen bytes both parser families read without complaint, whose member name the decoder cannot
        // complete. An earlier revision of the screen threw InvalidOperationException here, which no caller
        // catches, so a provider could crash the discovery path with a document smaller than this comment.
        //
        // Asserting only that the read failed would NOT pin that: OidcDiscoveryReader catches every exception
        // and returns Unavailable, so a crashing screen and a refusing screen look identical from the result.
        // The refusal REASON is what distinguishes them — the screen can only log it by having walked the
        // document and returned rather than thrown.
        var http = new CountingFactory(Serve("{\"a\\ud800\":1}"));
        var logger = new CapturingLogger();

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, logger);

        Assert.False(result.Available);
        Assert.Contains(logger.Entries, e => e.Message.Contains(RepeatedMemberScreen.UninspectableReason, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("not-json-at-all")]
    [InlineData("{\"issuer\":")]
    public async Task ADocumentTheScreenCannotWalk_IsRefusedAsUninspectable(string body)
    {
        // The Unreadable branch AT THE SEAM, which nothing else covers: a screen that passed an
        // uninspectable body through instead of refusing it would still see the library reject these, so the
        // whole suite stays green under that fail-open mutation unless the reason is asserted here.
        var http = new CountingFactory(Serve(body));
        var logger = new CapturingLogger();

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, logger);

        Assert.False(result.Available);
        Assert.Contains(logger.Entries, e => e.Message.Contains(RepeatedMemberScreen.UninspectableReason, StringComparison.Ordinal));
        Assert.Equal(1, http.TotalRequests);
    }

    [Fact]
    public async Task ABodyWhoseCharsetTheRuntimeDoesNotKnow_IsRefusedRatherThanThrown()
    {
        // Content-Type is the provider's to choose, and an unknown charset makes the decode throw
        // InvalidOperationException — on a body the ANONYMOUS challenge endpoint fetches. Unhandled, that
        // escapes the screen: the read still fails closed via the caller's blanket catch, but the operator
        // loses the reason and this handler becomes the one fail path that reports nothing.
        var http = new CountingFactory(request =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(FullDiscovery(Authority)),
            };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "x-not-a-charset" };
            return response;
        });
        var logger = new CapturingLogger();

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, logger);

        Assert.False(result.Available);
        Assert.Contains(logger.Entries, e => e.Message.Contains(RepeatedMemberScreen.UninspectableReason, StringComparison.Ordinal));
    }

    [Fact]
    public async Task ABodyOverTheScreenedBound_IsRefusedRatherThanBuffered()
    {
        // The screen decodes a second copy of a provider-chosen body on an anonymous path, so that copy is
        // bounded. Without the bound this change would enlarge the exposure #1041 tracks rather than leave it
        // where it was. This is the declared-length half: the provider announces an oversized body.
        var huge = "{\"issuer\":\"" + new string('a', 2 * 1024 * 1024) + "\"}";
        var http = new CountingFactory(Serve(huge));
        var logger = new CapturingLogger();

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, logger);

        Assert.False(result.Available);
        Assert.Contains(logger.Entries, e => e.Message.Contains(RepeatedMemberScreen.UninspectableReason, StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnUndeclaredBodyOverTheScreenedBound_IsRefusedToo()
    {
        // The same bound where the provider declares no length — a chunked body. It is refused after the
        // decode rather than before it, which is the honest limit of a screen sitting above HttpClient: the
        // response is already buffered by the time any handler sees it, so nothing here can stop the FETCH
        // (that is #1041's). What it does stop is the walk running on a document no real provider serves.
        var http = new CountingFactory(_ =>
        {
            var stream = new MemoryStream(Encoding.UTF8.GetBytes("{\"issuer\":\"" + new string('a', 2 * 1024 * 1024) + "\"}"));
            var content = new StreamContent(stream);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            content.Headers.ContentLength = null;
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
        });
        var logger = new CapturingLogger();

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, logger);

        Assert.False(result.Available);
        Assert.Contains(logger.Entries, e => e.Message.Contains(RepeatedMemberScreen.UninspectableReason, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Utf16EncodedCleanDiscovery_IsStillRead()
    {
        // The library reads response bodies charset-honouring, so the screen must too. If it walked the raw
        // bytes as UTF-8 it would find no members here, and a clean UTF-16 document would sail past a screen
        // that had established nothing about it.
        var http = new CountingFactory(ServeWithEncoding(FullDiscovery(Authority), Encoding.Unicode));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, Logger());

        Assert.True(result.Available);
    }

    [Fact]
    public async Task Utf16EncodedDuplicateDiscovery_IsStillRefused()
    {
        // The bypass direction of the same property, and the security-relevant half.
        //
        // The refusal REASON is what this asserts, not merely that the read failed. A screen walking the raw
        // bytes as UTF-8 turns a UTF-16 body into nonsense and refuses it as uninspectable — so an
        // availability-shaped assertion stays green under exactly the defect this row is named for, which is
        // what the weakening probe demonstrated before this assertion was tightened. Requiring the
        // repeated-member reason makes the row depend on the screen having actually READ the document.
        var duplicated = FullDiscovery(Authority).Insert(1, $"\"issuer\":\"https://attacker.example\",");
        var http = new CountingFactory(ServeWithEncoding(duplicated, Encoding.Unicode));
        var logger = new CapturingLogger();

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, logger);

        Assert.False(result.Available);
        Assert.Contains(logger.Entries, e => e.Message.Contains(RepeatedMemberScreen.RefusalReason, StringComparison.Ordinal));
        Assert.DoesNotContain(logger.Entries, e => e.Message.Contains(RepeatedMemberScreen.UninspectableReason, StringComparison.Ordinal));
    }

    [Fact]
    public async Task ScreenRefusalNamesTheRepeatedMember_WithLineEndingsStripped()
    {
        // The member name is provider-authored, so it reaches the log stripped of line endings INLINE at the
        // log call — a forged second entry is the classic log-forging outcome. The name also never travels in
        // the response's reason phrase, whose setter rejects CR/LF outright: putting it there would make the
        // screen throw while building its own refusal.
        var hostile = FullDiscovery(Authority).Insert(1, "\"a\\u000d\\u000ab\":1,\"a\\u000d\\u000ab\":2,");
        var http = new CountingFactory(Serve(hostile));
        var logger = new CapturingLogger();

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, logger);

        Assert.False(result.Available);

        // The screen's own entry is the one that names the member, and it is stripped inline. Warning level,
        // so it reaches an operator's log at the default verbosity rather than only under debug.
        var refusal = Assert.Single(logger.Entries, e => e.Message.StartsWith("Refused the OpenID response", StringComparison.Ordinal));
        Assert.Equal(LogLevel.Warning, refusal.Level);
        Assert.Contains("ab", refusal.Message, StringComparison.Ordinal);
        Assert.DoesNotContain('\n', refusal.Message);
        Assert.DoesNotContain('\r', refusal.Message);

        // The caller's existing fail-closed warning carries the CONSTANT reason through the library's error
        // text — so an operator reading it learns why the read failed — and never the provider-authored name,
        // which is what keeps that string off the transport where the reason-phrase setter would reject it.
        var failClosed = Assert.Single(logger.Entries, e => e.Message.StartsWith("Could not read the OpenID discovery document", StringComparison.Ordinal));
        Assert.Contains(RepeatedMemberScreen.RefusalReason, failClosed.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("ab", failClosed.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ANonSuccessResponse_KeepsItsOwnStatus_AndIsNotScreened()
    {
        // A 404 or an HTML error page is not a document that means two things — it is a provider that served
        // no document. Screening it would replace an honest status with "could not be inspected" and send the
        // operator hunting a duplicate that is not there. The HTML body is deliberately unwalkable, so a
        // screen that inspected non-success responses WOULD report it as uninspectable.
        var http = new CountingFactory(_ => new HttpResponseMessage(HttpStatusCode.NotFound)
        {
            Content = new StringContent("<html><body>nope</body></html>", Encoding.UTF8, "text/html"),
        });
        var logger = new CapturingLogger();

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, logger);

        Assert.False(result.Available);
        Assert.DoesNotContain(logger.Entries, e => e.Message.Contains(RepeatedMemberScreen.UninspectableReason, StringComparison.Ordinal));

        // The status the provider actually returned is what reaches the operator — the half this row was
        // named for and did not assert. A screened non-success response would carry the screen's constant
        // reason here instead, which is exactly what must not happen.
        var failClosed = Assert.Single(logger.Entries, e => e.Message.StartsWith("Could not read the OpenID discovery document", StringComparison.Ordinal));
        Assert.Contains("Not Found", failClosed.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(RepeatedMemberScreen.RefusalReason, failClosed.Message, StringComparison.Ordinal);
    }

    // Serves the given discovery JSON for the well-known document and the given JWKS for the keyset fetch;
    // any other URL 404s so an unexpected request is visible.
    private static Func<HttpRequestMessage, HttpResponseMessage> Serve(string discoveryJson, string jwksJson = "{\"keys\":[]}") =>
        ServeWithEncoding(discoveryJson, Encoding.UTF8, jwksJson);

    private static Func<HttpRequestMessage, HttpResponseMessage> ServeWithEncoding(string discoveryJson, Encoding encoding, string jwksJson = "{\"keys\":[]}") => request =>
    {
        var url = request.RequestUri!.AbsoluteUri;
        if (url.EndsWith("/.well-known/openid-configuration", StringComparison.Ordinal))
        {
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(discoveryJson, encoding, "application/json") };
        }

        if (url.EndsWith("/jwks", StringComparison.Ordinal))
        {
            return Json(jwksJson);
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    };


    private static HttpResponseMessage Json(string body) =>
        new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    // A factory whose every client is backed by the responder and that counts the outbound discovery-document
    // requests (the well-known URL) it serves, so a test can assert a single discovery read.
    private sealed class CountingFactory
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;

        internal CountingFactory(Func<HttpRequestMessage, HttpResponseMessage> responder)
        {
            _responder = responder;
            var factory = Substitute.For<IHttpClientFactory>();
            factory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(new StubHttpMessageHandler(Handle)));
            Factory = factory;
        }

        internal IHttpClientFactory Factory { get; }

        internal int DiscoveryRequests { get; private set; }

        internal int JwksRequests { get; private set; }

        internal int TotalRequests { get; private set; }

        // Every URL actually requested, so a test can name the one a bypass would have fetched instead of
        // inferring it from a count.
        internal System.Collections.Generic.List<string> RequestedUrls { get; } = new();

        private HttpResponseMessage Handle(HttpRequestMessage request)
        {
            var url = request.RequestUri!.AbsoluteUri;
            TotalRequests++;
            RequestedUrls.Add(url);
            if (url.EndsWith("/.well-known/openid-configuration", StringComparison.Ordinal))
            {
                DiscoveryRequests++;
            }

            // Counted so a test can assert the JWKS URL a refused discovery document named was never
            // dereferenced — the property a post-parse screen structurally cannot hold.
            if (url.EndsWith("/jwks", StringComparison.Ordinal))
            {
                JwksRequests++;
            }

            return _responder(request);
        }
    }
}
