// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Pins the fail-closed warning for a discovery document whose issuer the configured endpoint refuses
/// (#1835). The library's error text quotes one of the two values and says neither which one nor which of
/// them belongs in the field, and a reader with Nextcloud in a subfolder took two
/// rounds to learn that the field needs the published <c>.../index.php</c> issuer.
///
/// The published issuer is the provider's text, so it is pinned as foreign text too: stripped, substituted
/// and bounded at the call, exactly like the library error beside it. The mutation each test kills is named
/// on the test.
/// </summary>
public class OidcDiscoveryReaderIssuerMismatchTests
{
    private const string Endpoint = "https://mycloud.example.com:444/nextcloud";
    private const string PublishedIssuer = Endpoint + "/index.php";

    [Fact]
    public async Task AnIssuerTheEndpointRefuses_IsNamedBesideTheEndpoint()
    {
        // Kills: logging the library's error text on this path as before, which quotes one value unlabelled.
        var logger = new CapturingLogger();

        var result = await ReadAsync(logger, new Router(Document(PublishedIssuer, PublishedIssuer)));

        // The read still fails closed, and it names the mismatch and the published issuer for the probe (#1837).
        Assert.False(result.Available);
        Assert.Equal(OidcDiscoveryResult.IssuerRefused(PublishedIssuer), result);
        var warning = FailClosedWarning(logger);
        Assert.Contains("\nConfigured endpoint: " + Endpoint + "\n", warning, StringComparison.Ordinal);
        Assert.Contains("\nPublished issuer: " + PublishedIssuer + "\n", warning, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnUnreachableEndpoint_KeepsTheLibraryErrorEntry()
    {
        // Kills: naming an issuer where no document was read. There is nothing published to name, and the
        // library's text is the only account of what went wrong.
        var logger = new CapturingLogger();

        var result = await ReadAsync(logger, new Unreachable());

        Assert.False(result.Available);
        var warning = FailClosedWarning(logger);
        Assert.DoesNotContain("Published issuer", warning, StringComparison.Ordinal);
        Assert.Contains("unreachable-for-1835", warning, StringComparison.Ordinal);
        Assert.EndsWith(". The login fails closed rather than proceeding on unverified discovery facts.", warning, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnotherPolicyViolation_IsNotReportedAsAnIssuerMismatch()
    {
        // Kills: keying the new entry on the error type alone. An endpoint outside the authority is a policy
        // violation too, with an issuer that matches, and calling it a mismatch sends the reader to the one
        // field that is already right.
        var logger = new CapturingLogger();

        var result = await ReadAsync(logger, new Router(Document(Endpoint, "https://elsewhere.example.org")), validateEndpoints: true);

        Assert.Equal(OidcDiscoveryResult.Unavailable, result);
        var warning = FailClosedWarning(logger);
        Assert.DoesNotContain("Published issuer", warning, StringComparison.Ordinal);
    }

    [Fact]
    public async Task APublishedIssuerCannotForgeOrFloodTheEntry()
    {
        // Kills: dropping the strip, the substitution or the bound on the published value. The provider
        // chooses it, one anonymous challenge writes it, and a line break in it would open a record of its own.
        var logger = new CapturingLogger();
        var hostile = PublishedIssuer + "\\r\\n[SSO Audit] forged" + new string('i', 4096);

        var result = await ReadAsync(logger, new Router(Document(hostile, PublishedIssuer)));

        Assert.False(result.Available);
        var warning = FailClosedWarning(logger);
        var published = warning[(warning.IndexOf("\nPublished issuer: ", StringComparison.Ordinal) + 1)..];
        published = published[..published.IndexOf('\n', StringComparison.Ordinal)];
        Assert.StartsWith("Published issuer: " + PublishedIssuer + "(SSO Audit] forged", published, StringComparison.Ordinal);
        Assert.EndsWith("[truncated]", published, StringComparison.Ordinal);
        Assert.DoesNotContain(new string('i', 1024), warning, StringComparison.Ordinal);
    }

    // A discovery document publishing the given issuer, with its endpoints under the given base. Everything
    // else is the smallest set of members the library maps.
    private static string Document(string issuer, string endpoints) =>
        "{"
        + $"\"issuer\":\"{issuer}\","
        + $"\"authorization_endpoint\":\"{endpoints}/authorize\","
        + $"\"token_endpoint\":\"{endpoints}/token\","
        + $"\"jwks_uri\":\"{endpoints}/jwks\","
        + "\"response_types_supported\":[\"code\"],"
        + "\"subject_types_supported\":[\"public\"],"
        + "\"id_token_signing_alg_values_supported\":[\"RS256\"]}";

    private static async Task<OidcDiscoveryResult> ReadAsync(ILogger logger, HttpMessageHandler handler, bool validateEndpoints = false)
    {
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(handler, disposeHandler: false));

        var options = new OidcClientOptions { Authority = Endpoint };
        options.Policy.Discovery.ValidateEndpoints = validateEndpoints;

        return await OidcDiscoveryReader.ReadAsync(options, "MyCloud", factory, logger, cancellationToken: TestContext.Current.CancellationToken);
    }

    private static string FailClosedWarning(CapturingLogger logger)
    {
        var entry = Assert.Single(
            logger.Entries,
            e => e.Message.StartsWith("Could not read the OpenID discovery document", StringComparison.Ordinal));
        Assert.Equal(LogLevel.Warning, entry.Level);
        return entry.Message;
    }

    // Serves the discovery document and an empty key set.
    private sealed class Router : HttpMessageHandler
    {
        private readonly string _discovery;

        internal Router(string discovery) => _discovery = discovery;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.RequestUri!.AbsoluteUri.EndsWith("/.well-known/openid-configuration", StringComparison.Ordinal)
                ? _discovery
                : "{\"keys\":[]}";

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
                RequestMessage = request,
            });
        }
    }

    // Refuses every request the way a host that does not answer does.
    private sealed class Unreachable : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("unreachable-for-1835");
    }
}
