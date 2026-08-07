// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The duplicate-key posture behind the screened discovery seam (#1186, unit 2 of #1005's ladder).
///
/// Two tests that only make sense together. The plugin reads its discovery facts through Newtonsoft
/// (<see cref="DiscoveryJson"/>) while the identity library reads the same bytes through System.Text.Json,
/// so a document naming a member twice is read by two parsers that were never promised to agree about it.
/// <see cref="ParserDuplicateKeyPosture_IsPinned"/> is the measurement of what they actually do, executed
/// rather than quoted, so a dependency bump that flips a row fails here instead of in production;
/// <see cref="EveryReaderOfTheDiscoveryDocument_ReachesTheSameDecision"/> is the property that measurement
/// makes load-bearing - the document is refused at the transport, before either reader observes a value,
/// so the two can never be made to differ.
///
/// Separating them would leave a guard on one side and the evidence that it guards anything on the other.
/// </summary>
public class DuplicateJsonKeyPostureTests
{
    private const string Authority = "https://idp-posture.example.com";

    // One member, two occurrences, two different values. Every row below reads THIS document, so the rows
    // are comparable: a row that keeps "last" and a row that keeps "first" differ about these exact bytes.
    private const string RepeatedMemberDocument = "{\"issuer\":\"first\",\"issuer\":\"last\"}";

    /// <summary>
    /// The measured last-occurrence table. Each row IS its measurement: the parse runs here, so the row
    /// states what this dependency set does today rather than what it did when someone wrote it down.
    ///
    /// The pinned fact is that a repeated member is not an error for six of the seven read paths - it is
    /// silently resolved, to the LAST occurrence, which hands an attacker who can append to a discovery
    /// document the value every reader will act on. The seventh row is the exception and is pinned as one:
    /// <c>JsonNode.Parse</c> refuses. It is in the table because a bump that made it lenient would remove
    /// the only read path that objects on its own, and that is worth a red build.
    /// </summary>
    private static readonly (string Path, string Expected)[] PostureRows =
    {
        ("Newtonsoft JObject.Parse, indexed", "last"),
        ("Newtonsoft JsonConvert.DeserializeObject<IDictionary<string, object>>", "last"),
        ("System.Text.Json JsonDocument.RootElement.GetProperty", "last"),
        ("System.Text.Json JsonDocument.RootElement.EnumerateObject, last value", "last"),
        ("System.Text.Json JsonSerializer.Deserialize<Dictionary<string, string>>", "last"),
        ("System.Text.Json JsonNode.Parse, indexed", "throws:ArgumentException"),
    };

    public static TheoryData<string, string> Posture
    {
        get
        {
            var data = new TheoryData<string, string>();
            foreach (var (path, expected) in PostureRows)
            {
                data.Add(path, expected);
            }

            return data;
        }
    }

    /// <param name="path">The read path being measured, as a reader would name it.</param>
    /// <param name="expected">The measured resolution: the surviving value, or "throws:" and the exception type.</param>
    [Theory]
    [MemberData(nameof(Posture))]
    public void ParserDuplicateKeyPosture_IsPinned(string path, string expected)
    {
        Assert.Equal(expected, Resolve(path, RepeatedMemberDocument));
    }

    [Fact]
    public void ParserDuplicateKeyPosture_TableCoversEveryReadPath()
    {
        // A row nobody can reach is a row nobody measures. Resolve() answers only for the names the table
        // lists, so a renamed row would stop measuring its parser and still pass - "unmeasured" would equal
        // "unmeasured" if anyone ever wrote it into the expected column. This reads the table back and
        // refuses that shape outright, and pins the row count so a deleted row is a red build.
        Assert.Equal(6, PostureRows.Length);
        Assert.Equal(PostureRows.Length, Posture.Count);
        foreach (var (path, expected) in PostureRows)
        {
            Assert.NotEqual("unmeasured", Resolve(path, RepeatedMemberDocument));
            Assert.NotEqual("unmeasured", expected);
        }
    }

    [Fact]
    public void ParserDuplicateKeyPosture_SeesBothOccurrences_WhereTheParserExposesThem()
    {
        // Newtonsoft collapses the repeat into one property; System.Text.Json keeps both and enumerates
        // them. That is the sharpest form of "the two readers were never promised to agree": they do not
        // even see the same NUMBER of members in the same bytes. Measured, not quoted.
        Assert.Single(JObject.Parse(RepeatedMemberDocument).Properties());
        Assert.Equal(2, CountProperties(RepeatedMemberDocument));
    }

    [Fact]
    public async Task EveryReaderOfTheDiscoveryDocument_ReachesTheSameDecision()
    {
        // The property, stated at the seam rather than against any reader's API: a document naming a member
        // twice is refused on the transport, so the plugin's fact readers and the library's typed read never
        // observe a value out of it and cannot be made to disagree.
        //
        // The document repeats jwks_uri, because that is where disagreement costs something: whichever
        // occurrence a reader keeps is the URL whose keys would validate the id_token.
        var hostile = FullDiscovery(Authority).TrimEnd('}')
            + ",\"jwks_uri\":\"" + Authority + "/jwks-attacker\"}";
        var http = new CountingFactory(Serve(hostile));
        var logger = new CapturingLogger();

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", http.Factory, logger);

        // Neither reader produced anything: no metadata for the library's side, no facts for the plugin's.
        Assert.False(result.Available);
        Assert.Null(result.ProviderInformation);
        Assert.Equal(default(DiscoveryFacts), result.Facts);

        // The consequence that would actually hurt: neither jwks_uri was dereferenced. The read stopped at
        // the discovery document, so no key set from either occurrence exists to be disagreed about.
        Assert.Equal(1, http.TotalRequests);
        Assert.DoesNotContain(Authority + "/jwks-attacker", http.RequestedUrls);
        Assert.DoesNotContain(Authority + "/jwks", http.RequestedUrls);

        // The discriminator. Available == false alone proves nothing here - the library rejects plenty of
        // documents unaided - so this pins that the SCREEN is what refused it: the fail-closed warning
        // carries the screen's constant reason through the library's error text, which only a substituted
        // response produces.
        var failClosed = Assert.Single(logger.Entries, e => e.Message.StartsWith("Could not read the OpenID discovery document", StringComparison.Ordinal));
        Assert.Contains(RepeatedMemberScreen.RefusalReason, failClosed.Message, StringComparison.Ordinal);

        // And the property is not true by accident. Handed the same bytes directly, the plugin's own fact
        // reader parses them happily and reports a fact - so what keeps the readers from diverging is the
        // refusal above, not some prior agreement between the parsers.
        Assert.True(OidcDiscoveryReader.FactsFrom(hostile).PkceS256);
    }

    // The measured resolution of the repeated member for one read path, or "unmeasured" for a name the
    // table names but this method does not answer for.
    private static string Resolve(string path, string document)
    {
        try
        {
            return path switch
            {
                "Newtonsoft JObject.Parse, indexed" => JObject.Parse(document)["issuer"]!.Value<string>()!,
                "Newtonsoft JsonConvert.DeserializeObject<IDictionary<string, object>>" =>
                    (string)JsonConvert.DeserializeObject<IDictionary<string, object>>(document)!["issuer"],
                "System.Text.Json JsonDocument.RootElement.GetProperty" =>
                    JsonDocument.Parse(document).RootElement.GetProperty("issuer").GetString()!,
                "System.Text.Json JsonDocument.RootElement.EnumerateObject, last value" => LastEnumerated(document),
                "System.Text.Json JsonSerializer.Deserialize<Dictionary<string, string>>" =>
                    System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(document)!["issuer"],
                "System.Text.Json JsonNode.Parse, indexed" => JsonNode.Parse(document)!["issuer"]!.GetValue<string>(),
                _ => "unmeasured",
            };
        }
        catch (Exception e) when (e is ArgumentException or Newtonsoft.Json.JsonException or System.Text.Json.JsonException)
        {
            return "throws:" + e.GetType().Name;
        }
    }

    private static string LastEnumerated(string document)
    {
        string? value = null;
        foreach (var property in JsonDocument.Parse(document).RootElement.EnumerateObject())
        {
            value = property.Value.GetString();
        }

        return value!;
    }

    private static int CountProperties(string document)
    {
        var count = 0;
        foreach (var property in JsonDocument.Parse(document).RootElement.EnumerateObject())
        {
            count++;
        }

        return count;
    }

    // A discovery document the library accepts, so the only reason a read of it fails is the repeat added
    // to it by the caller.
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
        + "\"code_challenge_methods_supported\":[\"S256\"]}";

    private static OidcClientOptions OptionsFor(string authority)
    {
        var options = new OidcClientOptions { Authority = authority };
        options.Policy.Discovery.AdditionalEndpointBaseAddresses.Add(new Uri(authority).GetLeftPart(UriPartial.Authority));
        options.Policy.Discovery.RequireHttps = true;
        options.Policy.Discovery.ValidateIssuerName = true;
        options.Policy.Discovery.ValidateEndpoints = true;
        return options;
    }

    private static Func<HttpRequestMessage, HttpResponseMessage> Serve(string discoveryJson, string jwksJson = "{\"keys\":[]}") => request =>
    {
        var url = request.RequestUri!.ToString();
        if (url.EndsWith("/.well-known/openid-configuration", StringComparison.Ordinal))
        {
            return Json(discoveryJson);
        }

        return url.Contains("/jwks", StringComparison.Ordinal)
            ? Json(jwksJson)
            : new HttpResponseMessage(HttpStatusCode.NotFound);
    };

    private static HttpResponseMessage Json(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    // Counts and records what the read actually fetched, so "the attacker's URL was never requested" is an
    // observation rather than an inference.
    private sealed class CountingFactory
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _serve;

        internal CountingFactory(Func<HttpRequestMessage, HttpResponseMessage> serve)
        {
            _serve = serve;
            var factory = Substitute.For<IHttpClientFactory>();
            factory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(new StubHttpMessageHandler(Handle)));
            Factory = factory;
        }

        internal IHttpClientFactory Factory { get; }

        internal int TotalRequests { get; private set; }

        internal List<string> RequestedUrls { get; } = new();

        private HttpResponseMessage Handle(HttpRequestMessage request)
        {
            TotalRequests++;
            RequestedUrls.Add(request.RequestUri!.ToString());
            return _serve(request);
        }
    }
}
