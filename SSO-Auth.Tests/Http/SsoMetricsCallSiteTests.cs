// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Jellyfin.Plugin.SSO_Auth.Api.Metrics;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Provider;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Library;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Drives the REAL paths the counters are attached to (#1139), so each call site is proven by the thing it
/// counts actually happening.
/// </summary>
/// <remarks>
/// <see cref="SSOControllerMetricsTests"/> is about the store and the exposition and reaches the counter
/// facade directly, which says nothing about whether a login moves a counter. That is this file: a full
/// OpenID round trip against the in-test identity provider, a failed code exchange, an unreadable discovery
/// document, and both provisioning arms through the linking service. Deleting any one of those call sites
/// reddens a row here, which is the only reason to pay for the heavier fixtures.
/// </remarks>
[Collection("SSOController")]
public class SsoMetricsCallSiteTests
{
    private const string Authority = "https://idp-metrics.example.com";

    [Fact]
    public async Task AFullOpenIdRoundTrip_MovesTheSuccessAndProvisioningCounters()
    {
        SsoMetricsStore.ResetForTests();
        using var fixture = new OidcTokenFixture(Authority, "jf");
        var idToken = fixture.IdToken(subject: "sub-1", username: "alice");
        var harness = OidcRoundTrip.BuildHarness(fixture, request => OidcRoundTrip.ServeIdp(fixture, request, idToken));

        var user = TestUsers.Named("alice", Guid.Parse("1a999999-1111-1111-1111-111111111111"));
        harness.UserManager.CreateUserAsync("alice").Returns(user);
        harness.UserManager.GetUserById(user.Id).Returns(user);

        var (state, binding) = await OidcRoundTrip.DriveChallenge(harness, fixture);
        OidcRoundTrip.RepointToCallback(harness, binding, query: $"?code=test-code&state={state}");
        await harness.Controller.OidCallback("kc", state);
        Assert.IsType<OkObjectResult>(await harness.Controller.OidAuth("kc", OidcRoundTrip.Redeem(state)));

        Assert.Equal(1, Counter(SsoMetrics.LoginSuccessTotal, "provider", "kc"));
        Assert.Equal(1, Counter(SsoMetrics.AccountProvisionedTotal, "outcome", nameof(ProvisioningOutcome.Created)));
        Assert.Equal(0, Counter(SsoMetrics.ProviderFetchErrorTotal, "stage", nameof(ProviderFetchStage.Token)));
    }

    [Fact]
    public async Task AFailedCodeExchange_MovesTheTokenFetchCounter_AndNotTheSuccessOne()
    {
        // The id_token is signed by a key the identity provider does not advertise, so the exchange fails
        // inside the library and the callback returns the fixed generic error. Nothing is minted, which is
        // what makes this the right row for "a failed fetch is counted and a login is not".
        SsoMetricsStore.ResetForTests();
        using var idp = new OidcTokenFixture(Authority, "jf");
        using var foreignSigner = new OidcTokenFixture(Authority, "jf");
        var forged = foreignSigner.IdToken(subject: "sub-1", username: "alice");
        var harness = OidcRoundTrip.BuildHarness(idp, request => OidcRoundTrip.ServeIdp(idp, request, forged));

        var (state, binding) = await OidcRoundTrip.DriveChallenge(harness, idp);
        OidcRoundTrip.RepointToCallback(harness, binding, query: $"?code=test-code&state={state}");
        var callback = Assert.IsType<ContentResult>(await harness.Controller.OidCallback("kc", state));

        Assert.Equal(400, callback.StatusCode);
        Assert.Equal(1, Counter(SsoMetrics.ProviderFetchErrorTotal, "stage", nameof(ProviderFetchStage.Token)));
        Assert.Equal(0, Counter(SsoMetrics.LoginSuccessTotal, "provider", "kc"));
    }

    [Fact]
    public async Task AnUnreachableAuthorizationServer_MovesTheDiscoveryFetchCounter()
    {
        SsoMetricsStore.ResetForTests();
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(new StubHttpMessageHandler(
            _ => throw new HttpRequestException("the authorization server is unreachable"))));

        var result = await OidcDiscoveryReader.ReadAsync(
            new OidcClientOptions { Authority = Authority },
            "kc",
            factory,
            new CapturingLogger());

        Assert.False(result.Available);
        Assert.Equal(1, Counter(SsoMetrics.ProviderFetchErrorTotal, "stage", nameof(ProviderFetchStage.Discovery)));
    }

    [Fact]
    public async Task AnAdoptedAccount_AndACreatedOne_AreCountedApart()
    {
        // Both arms through the linking service itself. They are one branch away from each other, and a
        // counter attached to only one of them would read as a deployment that never adopts - which is the
        // exact signal an operator would want an alert on.
        SsoMetricsStore.ResetForTests();

        Assert.NotEqual(Guid.Empty, await Provision("alice", adopting: true));
        Assert.NotEqual(Guid.Empty, await Provision("bob", adopting: false));

        Assert.Equal(1, Counter(SsoMetrics.AccountProvisionedTotal, "outcome", nameof(ProvisioningOutcome.Adopted)));
        Assert.Equal(1, Counter(SsoMetrics.AccountProvisionedTotal, "outcome", nameof(ProvisioningOutcome.Created)));
    }

    private static long Counter(string metric, string label, string value) =>
        SsoMetricsStore.Snapshot()
            .Where(entry => entry.Series.Equals(new SsoMetricSeries(metric, label, value)))
            .Select(entry => entry.Value)
            .FirstOrDefault();

    private static async Task<Guid> Provision(string username, bool adopting)
    {
        var id = Guid.Parse(adopting
            ? "2a999999-1111-1111-1111-111111111111"
            : "3a999999-1111-1111-1111-111111111111");
        var user = TestUsers.Named(username, id);
        var users = Substitute.For<IUserManager>();
        if (adopting)
        {
            users.GetUserByName(username).Returns(user);
        }

        users.CreateUserAsync(username).Returns(user);
        users.GetUserById(id).Returns(user);

        var configuration = new PluginConfiguration();
        configuration.OidConfigs["kc"] = new OidConfig { Enabled = true, AllowExistingAccountLink = adopting };
        var store = new ProviderConfigStore(() => configuration, _ => { }, new CapturingLogger());
        var service = new CanonicalLinkService(users, new FakeCryptoProvider(), store, new CapturingLogger());

        return await service.ResolveOrCreateAsync(
            ProviderMode.Oid,
            "kc",
            "sub-" + username,
            username,
            allowExistingAccountLink: adopting);
    }
}
