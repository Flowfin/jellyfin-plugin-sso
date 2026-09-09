// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api.Http;
using Jellyfin.Plugin.SSO_Auth.Api.Metrics;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// The caller's lifetime reaches the hardened discovery read (#1558). Before this, <c>ReadAsync</c> took no
/// token and the only bound on a read whose caller had gone away was <see cref="OidcDiscoveryReader.FetchTimeout"/>,
/// per request rather than per call - and the library makes a second request for the JWKS, so an abandoned
/// challenge held its outbound connection for up to two of them. The rows here pin three things apart: the
/// token reaches the request and ends the read well inside the timeout; a read the caller abandoned is
/// neither logged as a fail-closed read nor counted against the provider; and a read the caller is still
/// waiting on, ended by the transport with the same exception type, still fails closed exactly as before.
/// Two rows read the process-wide metrics store, so the class sits in the non-parallel controller collection.
/// </summary>
[Collection("SSOController")]
public class OidcDiscoveryReaderCancellationTests
{
    private const string Authority = "https://idp-cancel.example.com";

    [Fact]
    public async Task ACallerThatWentAway_EndsTheReadInsideTheTimeout_AndItPropagates()
    {
        // Kills: dropping the token from the GetDiscoveryDocumentAsync call. The transport answers only when
        // the token it was handed fires, so a read that never handed it down waits for FetchTimeout instead.
        SsoMetricsStore.ResetForTests();
        var logger = new CapturingLogger();
        var factory = FactoryFor(new WaitsForCancellationHandler());
        using var caller = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        var clock = Stopwatch.StartNew();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", factory, logger, cancellationToken: caller.Token));

        clock.Stop();
        Assert.True(
            clock.Elapsed < OidcDiscoveryReader.FetchTimeout / 2,
            $"the read took {clock.Elapsed} to notice a caller that left after 200 ms; FetchTimeout is {OidcDiscoveryReader.FetchTimeout}");

        // Not a provider failure: no fail-closed warning for a browser that closed its tab, and the fetch
        // error counter an operator alerts on does not move for it.
        Assert.DoesNotContain(logger.Entries, e => e.Level >= LogLevel.Warning);
        Assert.Equal(0, DiscoveryFetchErrors());
    }

    [Fact]
    public async Task ATransportCancellation_WithTheCallerStillWaiting_StillFailsClosed()
    {
        // Kills: widening the rethrow to every OperationCanceledException. HttpClient ends a read that hit its
        // timeout with the same exception type, and THAT read is a provider failure: it returns Unavailable,
        // logs the fail-closed warning and counts against the provider, exactly as before the token arrived.
        SsoMetricsStore.ResetForTests();
        var logger = new CapturingLogger();
        var factory = FactoryFor(new StubHttpMessageHandler(_ => throw new TaskCanceledException("the request timed out")));

        var result = await OidcDiscoveryReader.ReadAsync(OptionsFor(Authority), "kc", factory, logger, cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(result.Available);
        Assert.Contains(logger.Entries, e => e.Level == LogLevel.Warning && e.Message.Contains("fails closed", StringComparison.Ordinal));
        Assert.Equal(1, DiscoveryFetchErrors());
    }

    [Fact]
    public async Task TheAdminProbe_PassesItsRequestLifetimeDown()
    {
        // The probe is the second caller with a request lifetime the issue names. A pre-cancelled token
        // must surface as the cancellation rather than as a Failure result naming connectivity.
        var config = new OidConfig { OidEndpoint = Authority, OidClientId = "jf" };
        var factory = FactoryFor(new WaitsForCancellationHandler());

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ProviderConnectionTester.TestOidcAsync(config, "kc", factory, new CapturingLogger(), new CancellationToken(canceled: true)));
    }

    private static long DiscoveryFetchErrors() =>
        SsoMetricsStore.Snapshot()
            .Where(entry => entry.Series.Equals(new SsoMetricSeries(SsoMetrics.ProviderFetchErrorTotal, "stage", nameof(ProviderFetchStage.Discovery))))
            .Select(entry => entry.Value)
            .FirstOrDefault();

    private static OidcClientOptions OptionsFor(string authority)
    {
        var options = new OidcClientOptions { Authority = authority };
        options.Policy.Discovery.RequireHttps = true;
        return options;
    }

    private static IHttpClientFactory FactoryFor(HttpMessageHandler handler)
    {
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(handler, disposeHandler: false));
        return factory;
    }

    // Answers only when the token the transport was handed fires. A read that did not pass the caller's token
    // down reaches this handler with HttpClient's own timeout token alone, and waits for FetchTimeout.
    private sealed class WaitsForCancellationHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
            throw new InvalidOperationException("unreachable: the delay above ends only by cancellation");
        }
    }
}
