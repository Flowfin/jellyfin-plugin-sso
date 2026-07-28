// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Linq;
using System.Net;
using System.Net.Http;
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

    // The endpoints and the jwks_uri a document needs before IdentityModel will accept it at all, so a test
    // can vary only the members it is actually about.
    private static string DiscoveryWith(string members) =>
        "{"
        + $"\"authorization_endpoint\":\"{Authority}/authorize\","
        + $"\"token_endpoint\":\"{Authority}/token\","
        + $"\"jwks_uri\":\"{Authority}/jwks\","
        + members
        + "}";

    // Every member the discovery read takes a value out of (#1005), with the value each is served as — the
    // same list, in the same order, that OidcDiscoveryReader screens. Kept as pairs rather than as one string
    // so a test can repeat any single member verbatim without disturbing the rest of the document.
    private static readonly (string Name, string Value)[] ScreenedMembers = new[]
    {
        ("issuer", $"\"{Authority}\""),
        ("jwks_uri", $"\"{Authority}/jwks\""),
        ("authorization_endpoint", $"\"{Authority}/authorize\""),
        ("pushed_authorization_request_endpoint", $"\"{Authority}/par\""),
        ("token_endpoint", $"\"{Authority}/token\""),
        ("end_session_endpoint", $"\"{Authority}/logout\""),
        ("userinfo_endpoint", $"\"{Authority}/userinfo\""),
        ("token_endpoint_auth_methods_supported", "[\"client_secret_post\"]"),
        ("code_challenge_methods_supported", "[\"S256\"]"),
        ("authorization_response_iss_parameter_supported", "true"),
    };

    // The document naming every screened member once, optionally with one of them served a second time with
    // the identical value, and optionally with further members appended verbatim.
    private static string DiscoveryOfEveryScreenedMember(string? repeat = null, string extra = "")
    {
        var members = ScreenedMembers.Select(member => $"\"{member.Name}\":{member.Value}").ToList();
        if (repeat is not null)
        {
            var repeated = ScreenedMembers.Single(member => string.Equals(member.Name, repeat, StringComparison.Ordinal));
            members.Add($"\"{repeated.Name}\":{repeated.Value}");
        }

        return "{" + string.Join(",", members) + extra + "}";
    }

    private static OidcClientOptions OptionsFor(string authority, bool requireHttps = true, bool validateIssuerName = true)
    {
        var options = new OidcClientOptions { Authority = authority };
        options.Policy.Discovery.AdditionalEndpointBaseAddresses.Add(new Uri(authority).GetLeftPart(UriPartial.Authority));
        options.Policy.Discovery.RequireHttps = requireHttps;
        options.Policy.Discovery.ValidateIssuerName = validateIssuerName;
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
    public async Task ReadAsync_EveryScreenedMember_IsObservedByThisRead()
    {
        // The derivation of the screened-member list, checked instead of asserted in prose (#1005). The list
        // in OidcDiscoveryReader claims to be exactly the members this read takes a value out of, and the
        // mapping from a library field to a wire member name belongs to the library, not to the plugin — so
        // it is pinned here: one assertion per screened member, over a document carrying each of them once.
        // A name that is not the one the library reads, or a member nothing downstream observes, fails here
        // rather than shipping as a list nobody can check. This is also the positive control for the
        // refusals below: the same document, unrepeated, is read in full.
        var http = new CountingFactory(Serve(DiscoveryOfEveryScreenedMember()));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, Logger());

        Assert.True(result.Available);
        var info = result.ProviderInformation;
        Assert.Equal(Authority, info.IssuerName); // issuer
        Assert.NotNull(info.KeySet); // jwks_uri — a document that names none yields a null KeySet
        Assert.Equal(Authority + "/authorize", info.AuthorizeEndpoint); // authorization_endpoint
        Assert.Equal(Authority + "/par", info.PushedAuthorizationRequestEndpoint); // pushed_authorization_request_endpoint
        Assert.Equal(Authority + "/token", info.TokenEndpoint); // token_endpoint
        Assert.Equal(Authority + "/logout", info.EndSessionEndpoint); // end_session_endpoint
        Assert.Equal(Authority + "/userinfo", info.UserInfoEndpoint); // userinfo_endpoint
        Assert.Contains("client_secret_post", info.TokenEndPointAuthenticationMethods); // token_endpoint_auth_methods_supported
        Assert.True(result.Facts.PkceS256); // code_challenge_methods_supported
        Assert.True(result.Facts.ResponseIssuerAdvertised); // authorization_response_iss_parameter_supported
    }

    [Theory]
    [InlineData("issuer")]
    [InlineData("jwks_uri")]
    [InlineData("authorization_endpoint")]
    [InlineData("pushed_authorization_request_endpoint")]
    [InlineData("token_endpoint")]
    [InlineData("end_session_endpoint")]
    [InlineData("userinfo_endpoint")]
    [InlineData("token_endpoint_auth_methods_supported")]
    [InlineData("code_challenge_methods_supported")]
    [InlineData("authorization_response_iss_parameter_supported")]
    public async Task ReadAsync_RepeatOfAnyScreenedMember_ReturnsUnavailable(string member)
    {
        // Every member on the list, repeated in the document the test above proved readable — so a member
        // that is on the list but not actually screened fails here. The second occurrence carries the SAME
        // value on purpose: the screen decides on names, and an identical repeat leaves issuer-name
        // validation, endpoint validation and the JWKS fetch looking at byte-identical facts, so the refusal
        // cannot come from any of them. The opposing-value case — where the repeat changes what the document
        // means — is the issuer test further down.
        var http = new CountingFactory(Serve(DiscoveryOfEveryScreenedMember(repeat: member)));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, Logger());

        Assert.False(result.Available);
        Assert.Null(result.ProviderInformation);
    }

    [Theory]
    // The other side of the bargain, and the one that decides whether this change is worth shipping: what the
    // screen must NOT refuse. A repeat of a member nothing indexes re-points nothing, while refusing on it
    // would take every login for that provider offline over a value the plugin never reads. The first three
    // are TOP-LEVEL repeats — the first cut of this screen refused all of them, which is the availability
    // defect this list closes; `scopes_supported` and `response_types_supported` are members every real
    // discovery document carries. The last is the same point one level down, inside RFC 8705's
    // `mtls_endpoint_aliases`, where the repeated name is even a screened one.
    [InlineData(",\"scopes_supported\":[\"openid\"],\"scopes_supported\":[\"openid\",\"profile\"]")]
    [InlineData(",\"response_types_supported\":[\"code\"],\"response_types_supported\":[\"token\"]")]
    [InlineData(",\"vendor_tenant\":\"a\",\"vendor_tenant\":\"b\"")]
    [InlineData(",\"mtls_endpoint_aliases\":{\"token_endpoint\":\"https://a\",\"token_endpoint\":\"https://b\"}")]
    public async Task ReadAsync_RepeatOfAMemberNoReaderIndexes_IsStillRead(string extra)
    {
        var http = new CountingFactory(Serve(DiscoveryOfEveryScreenedMember(extra: extra)));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, Logger());

        Assert.True(result.Available);
        Assert.Equal(Authority, result.ProviderInformation.IssuerName);
        Assert.True(result.Facts.PkceS256);
    }

    [Fact]
    public async Task ReadAsync_DiscoveryServedWithAByteOrderMark_IsStillRead()
    {
        // The case that decides whether "could not tokenize" may be reported as "repeats a name": a provider
        // serving its well-known document with a UTF-8 preamble. If that reached a screen answering one bool
        // for both, a byte of encoding trivia would refuse every login for that provider under a message
        // telling the admin to hunt a duplicate. It does not reach it — the HTTP layer strips the preamble
        // before either parser sees the body — and this pins that, so the day it stops being true fails here
        // rather than in somebody's logins.
        var body = "\uFEFF" + DiscoveryWith($"\"issuer\":\"{Authority}\",\"code_challenge_methods_supported\":[\"S256\"]");
        var http = new CountingFactory(Serve(body));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, Logger());

        Assert.True(result.Available);
        Assert.True(result.Facts.PkceS256);
    }

    [Fact]
    public async Task ReadAsync_DuplicatedIssuer_IsRefused_NotResolvedToTheLastOccurrence()
    {
        // The sharpest case, and it needs the provider-level DoNotValidateIssuerName hatch to be visible:
        // with issuer-name validation on, a swapped issuer is caught by that check instead, so the gate would
        // look effective while proving nothing. Under the hatch — a supported configuration for templated and
        // multi-tenant IdPs — a document naming `issuer` twice is accepted by the library and resolves to the
        // LAST occurrence, silently re-pointing the issuer anchor this login binds its canonical link to.
        var swapped = DiscoveryWith($"\"issuer\":\"{Authority}\",\"issuer\":\"https://attacker.example.com\"");
        var http = new CountingFactory(Serve(swapped));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority, validateIssuerName: false), "kc", http.Factory, Logger());

        Assert.False(result.Available);
    }

    [Fact]
    public async Task ReadAsync_SingleIssuerUnderTheSameHatch_IsReadAndKeepsThatIssuer()
    {
        // The positive control on the same subject and the same options: the hatch itself still reads a
        // document, and the issuer it carries is the issuer the login is bound to.
        var single = DiscoveryWith("\"issuer\":\"https://tenant.example.com\"");
        var http = new CountingFactory(Serve(single));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority, validateIssuerName: false), "kc", http.Factory, Logger());

        Assert.True(result.Available);
        Assert.Equal("https://tenant.example.com", result.ProviderInformation.IssuerName);
    }

    // Serves the given discovery JSON for the well-known document and an empty JWKS for the keyset fetch;
    // any other URL 404s so an unexpected request is visible.
    private static Func<HttpRequestMessage, HttpResponseMessage> Serve(string discoveryJson) => request =>
    {
        var url = request.RequestUri!.AbsoluteUri;
        if (url.EndsWith("/.well-known/openid-configuration", StringComparison.Ordinal))
        {
            return Json(discoveryJson);
        }

        if (url.EndsWith("/jwks", StringComparison.Ordinal))
        {
            return Json("{\"keys\":[]}");
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

        private HttpResponseMessage Handle(HttpRequestMessage request)
        {
            if (request.RequestUri!.AbsoluteUri.EndsWith("/.well-known/openid-configuration", StringComparison.Ordinal))
            {
                DiscoveryRequests++;
            }

            return _responder(request);
        }
    }
}
