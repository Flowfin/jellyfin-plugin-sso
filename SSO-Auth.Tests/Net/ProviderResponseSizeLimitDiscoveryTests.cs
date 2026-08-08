// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api.Net;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The outbound size bound seen from the anonymous challenge path it exists to protect (#1169). The unit rows
/// in <see cref="ProviderResponseSizeLimitTests"/> pin the handler; these pin what an operator and an
/// unauthenticated caller actually get, which is the only place the bound's value can be judged.
/// <para>
/// The client here is built the way the composition root builds it - the limiter in front of the transport -
/// rather than the way the other discovery tests build theirs, which is a bare stub. That difference is the
/// test: a bound registered only in production and never exercised through the reader would be a bound
/// nobody has seen work.
/// </para>
/// </summary>
public sealed class ProviderResponseSizeLimitDiscoveryTests
{
    private const string Authority = "https://idp-size.example.test";

    [Fact]
    public async Task AnOversizeDiscoveryDocument_FailsTheLoginClosed_AndTheWarningNamesTheProviderAndTheLimit()
    {
        // The refusal has to read AS a refusal. Before this bound existed, an over-large body could only
        // surface through the generic "could not read the discovery document" path, which is the same thing
        // an operator sees for malformed JSON - and the two ask different things of them. A malformed
        // document is the provider's bug; an over-large one is a limit this plugin chose and may have set
        // too low for an unusual provider.
        var logger = new CapturingLogger();
        var factory = FactoryServing(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new OversizeJson((int)ProviderResponseSizeLimit.MaxProviderResponseBytes + 4096),
        });

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", factory, logger);

        Assert.Equal(OidcDiscoveryResult.Unavailable, result);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(Microsoft.Extensions.Logging.LogLevel.Warning, entry.Level);
        Assert.Contains("kc", entry.Message, StringComparison.Ordinal);
        Assert.Contains(
            ProviderResponseSizeLimit.MaxProviderResponseBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            entry.Message,
            StringComparison.Ordinal);

        // Where the limit comes from, measured rather than designed. The refusal is raised inside the
        // outbound pipeline, and the identity library converts a transport failure into its own IsError
        // result before the reader ever sees an exception - so the reader cannot catch this refusal apart,
        // and a catch clause added there would never fire. What carries the reason instead is the refusal's
        // MESSAGE, which the library passes through into discovery.Error and the reader logs. That is why
        // ProviderResponseTooLargeException words its message to name the bound, and this row is what stops
        // that wording being "tidied" into something that no longer says it.
        Assert.Contains("exceeds the", entry.Message, StringComparison.Ordinal);
        Assert.Contains("-byte limit", entry.Message, StringComparison.Ordinal);

        // And it is distinguishable from the malformed-document case, which is the whole point of naming it:
        // a parse failure carries no limit, so an operator can tell "your provider sent nonsense" from "this
        // plugin refused a body for its size".
        Assert.DoesNotContain("could not be inspected", entry.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AnOrdinaryDiscoveryDocument_IsUnaffectedByTheBound()
    {
        // The positive control for the row above, through the same reader and the same limiter: the bound
        // must be invisible to every provider that is not attacking anyone.
        var logger = new CapturingLogger();
        var factory = FactoryServing(request =>
            request.RequestUri!.AbsoluteUri.EndsWith("/jwks", StringComparison.Ordinal)
                ? Json("{\"keys\":[]}")
                : Json(FullDiscovery));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", factory, logger);

        Assert.NotEqual(OidcDiscoveryResult.Unavailable, result);
        Assert.Empty(logger.Entries);
    }

    private static readonly string FullDiscovery = "{"
        + $"\"issuer\":\"{Authority}\","
        + $"\"authorization_endpoint\":\"{Authority}/authorize\","
        + $"\"token_endpoint\":\"{Authority}/token\","
        + $"\"userinfo_endpoint\":\"{Authority}/userinfo\","
        + $"\"jwks_uri\":\"{Authority}/jwks\","
        + "\"response_types_supported\":[\"code\"],"
        + "\"subject_types_supported\":[\"public\"],"
        + "\"id_token_signing_alg_values_supported\":[\"RS256\"],"
        + "\"code_challenge_methods_supported\":[\"S256\"],"
        + "\"authorization_response_iss_parameter_supported\":true}";

    private static HttpResponseMessage Json(string body) =>
        new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    // A factory whose clients carry the limiter in front of the stub, exactly as the composition root
    // registers it for both named outbound tiers.
    private static IHttpClientFactory FactoryServing(Func<HttpRequestMessage, HttpResponseMessage> respond)
    {
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(_ =>
            new HttpClient(new ProviderResponseSizeLimit { InnerHandler = new StubHttpMessageHandler(respond) }));
        return factory;
    }

    private static OidcClientOptions OptionsFor(string authority)
    {
        var options = new OidcClientOptions { Authority = authority };
        options.Policy.Discovery.AdditionalEndpointBaseAddresses.Add(new Uri(authority).GetLeftPart(UriPartial.Authority));
        options.Policy.Discovery.RequireHttps = true;
        options.Policy.Discovery.ValidateIssuerName = true;
        options.Policy.Discovery.ValidateEndpoints = true;
        return options;
    }

    // A well-formed JSON object padded past the bound, so the body is refused for its SIZE and not because it
    // failed to parse - otherwise the test could pass for the wrong reason.
    private sealed class OversizeJson : HttpContent
    {
        private readonly int _size;

        internal OversizeJson(int size)
        {
            _size = size;
            Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
        }

        protected override async Task SerializeToStreamAsync(System.IO.Stream stream, System.Net.TransportContext? context)
        {
            var head = Encoding.UTF8.GetBytes("{\"issuer\":\"" + Authority + "\",\"padding\":\"");
            await stream.WriteAsync(head).ConfigureAwait(false);

            var chunk = new byte[8192];
            Array.Fill(chunk, (byte)'p');
            for (var written = 0; written < _size;)
            {
                var next = Math.Min(chunk.Length, _size - written);
                await stream.WriteAsync(chunk.AsMemory(0, next)).ConfigureAwait(false);
                written += next;
            }

            await stream.WriteAsync(Encoding.UTF8.GetBytes("\"}")).ConfigureAwait(false);
        }

        // No advertised length: the interesting path, because the cheap header check cannot see it.
        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }
}
