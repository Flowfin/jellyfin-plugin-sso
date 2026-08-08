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
/// Pins the bound on the provider-authored text in <see cref="OidcDiscoveryReader"/>'s fail-closed warning
/// (#1194).
///
/// The value under test is NOT the plugin's. The library's error text quotes the URL it was connecting to,
/// and on the JWKS leg the provider chose that URL: the discovery document named it in <c>jwks_uri</c>. So a
/// hostile authorization server writes as much log as it likes, once per anonymous challenge, with nothing
/// but the 1 MB response cap in the way. Measured before the bound existed: a document advertising a 200 KB
/// <c>jwks_uri</c> produced a 205,042-character entry.
///
/// The screen's own refusal entry is a different call and needs no bound - it carries no provider-authored
/// text at all, which the same measurement showed (211 characters against an 800 KB repeated member name).
/// That is why the bound lives here and not there.
///
/// Both directions are pinned, because a ceiling-only test passes against a bound tightened to a stub, and a
/// stub would throw away the endpoint an operator reads the entry to find. The mutation each test kills is
/// named on the test.
/// </summary>
public class OidcDiscoveryReaderErrorBoundTests
{
    private const string Authority = "https://idp-bound.example.com";

    // Comfortably past the 512-character bound, and past any URL a working deployment produces, so the
    // fixture actually reaches the truncation rather than sitting under it - which is how the first attempt
    // at this bound shipped something no test could kill.
    private const int LongSegmentChars = 8192;

    [Fact]
    public async Task AProviderAuthoredJwksUrl_DoesNotReachTheWarningUnbounded()
    {
        // Kills: deleting the truncation and logging discovery.Error whole.
        var segment = new string('u', LongSegmentChars);
        var logger = new CapturingLogger();

        var result = await ReadAsync(logger, JwksUri(Authority + "/" + segment));

        Assert.False(result.Available);
        var warning = FailClosedWarning(logger);

        // The entry is bounded, and bounded well below what the provider sent rather than merely "shorter".
        Assert.True(
            warning.Length < LongSegmentChars,
            $"the fail-closed warning carries {warning.Length} characters against an {LongSegmentChars}-character provider-authored URL");
        Assert.Contains("[truncated]", warning, StringComparison.Ordinal);

        // And the provider cannot get a long run of its own bytes in even below the total length: a bound
        // applied to the wrong operand, or applied after concatenation, would still let a long run through.
        Assert.DoesNotContain(new string('u', 1024), warning, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnOrdinaryErrorText_ReachesTheWarningWhole()
    {
        // Kills: tightening the bound to a stub. A two-character ceiling passes the test above and destroys
        // the entry an operator reads to find WHICH endpoint failed, so the floor is pinned separately.
        var logger = new CapturingLogger();

        var result = await ReadAsync(logger, JwksUri(Authority + "/jwks"));

        Assert.False(result.Available);
        var warning = FailClosedWarning(logger);

        // The endpoint the read failed on survives intact, and so does the marker's absence: an untruncated
        // entry must not claim to have been cut.
        Assert.Contains(Authority + "/jwks", warning, StringComparison.Ordinal);
        Assert.DoesNotContain("[truncated]", warning, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnEightHundredKilobyteMemberName_ReachesNoLogEntryAtAll()
    {
        // The other value #1194 names, and the reason the bound above is not also applied to the screen's
        // refusal entry: that entry carries no provider-authored text, so there is nothing there to bound.
        // Asserted rather than assumed, because "satisfied by exclusion" stops being true the moment
        // something starts logging the member name, and #1068 is the issue that may decide to. This row goes
        // red on that day and makes the bound owed at that call too.
        var name = new string('m', 800 * 1024);
        var logger = new CapturingLogger();

        var result = await ReadAsync(logger, RepeatedMember(name));

        Assert.False(result.Available);

        var refusal = Assert.Single(
            logger.Entries,
            e => e.Message.StartsWith("Refused the OpenID", StringComparison.Ordinal));
        Assert.True(
            refusal.Message.Length < 1024,
            $"the refusal entry carries {refusal.Message.Length} characters against an {name.Length}-character provider-authored member name");
        Assert.DoesNotContain(new string('m', 1024), refusal.Message, StringComparison.Ordinal);

        // And no other entry carries it either, so the name is not merely absent from the entry this row
        // reads while travelling on the one beside it.
        Assert.DoesNotContain(
            logger.Entries,
            e => e.Message.Contains(new string('m', 1024), StringComparison.Ordinal));
    }

    // A discovery document naming one member twice, so the screen refuses it on the FIRST leg and the name
    // is the only thing in it a provider chose to make large.
    private static string RepeatedMember(string name) =>
        "{"
        + $"\"{name}\":\"a\","
        + $"\"{name}\":\"b\","
        + $"\"issuer\":\"{Authority}\"}}";

    // A discovery document naming the given jwks_uri. Everything else is the smallest set of members the
    // library maps, so the only thing that varies between the two tests is the provider-authored URL.
    private static string JwksUri(string jwks) =>
        "{"
        + $"\"issuer\":\"{Authority}\","
        + $"\"authorization_endpoint\":\"{Authority}/authorize\","
        + $"\"token_endpoint\":\"{Authority}/token\","
        + $"\"jwks_uri\":\"{jwks}\","
        + "\"response_types_supported\":[\"code\"],"
        + "\"subject_types_supported\":[\"public\"],"
        + "\"id_token_signing_alg_values_supported\":[\"RS256\"]}";

    private static async Task<OidcDiscoveryResult> ReadAsync(ILogger logger, string discovery)
    {
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(new Router(discovery)));

        var options = new OidcClientOptions { Authority = Authority };
        options.Policy.Discovery.AdditionalEndpointBaseAddresses.Add(new Uri(Authority).GetLeftPart(UriPartial.Authority));
        options.Policy.Discovery.ValidateEndpoints = false;

        return await OidcDiscoveryReader.ReadAsync(options, "bound", factory, logger);
    }

    private static string FailClosedWarning(CapturingLogger logger)
    {
        var entry = Assert.Single(
            logger.Entries,
            e => e.Message.StartsWith("Could not read the OpenID discovery document", StringComparison.Ordinal));
        Assert.Equal(LogLevel.Warning, entry.Level);
        return entry.Message;
    }

    // Serves the discovery document and refuses the JWKS leg with a repeated member, so the read fails at
    // the JWKS fetch and the library's error names the provider-chosen URL it was connecting to.
    private sealed class Router : HttpMessageHandler
    {
        private readonly string _discovery;

        internal Router(string discovery) => _discovery = discovery;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var url = request.RequestUri!.AbsoluteUri;
            var body = url.EndsWith("/.well-known/openid-configuration", StringComparison.Ordinal)
                ? _discovery
                : "{\"keys\":[],\"keys\":[]}";

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
                RequestMessage = request,
            });
        }
    }
}
