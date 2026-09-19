// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api.Logout;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Drives the RP-initiated OpenID logout route over the wire, through the real ASP.NET Core routing,
/// authentication and authorization pipeline hosted by <see cref="SsoAuthorizationServerFixture"/> (#1768).
/// <para>
/// WHY THESE ROWS ARE NOT THE ONES IN <c>SSOControllerLogoutTicketTests</c>. Those call the action in
/// process with <c>IAuthorizationContext</c> substituted per row, which is the right shape for the ticket
/// store's own properties and the wrong shape for the one property this route acquired when
/// <c>[Authorize]</c> came off it. The attribute was enforced by middleware, ahead of the method; what
/// replaced it runs inside the method and depends on what the host's authorization context answers for a
/// request that carried nothing. A row that programs that answer itself has assumed the thing under test.
/// Here the request is an HTTP request at a listening socket, routing selects the action, and the
/// authorization context answers from what the request carried.
/// </para>
/// <para>
/// WHAT WAS MEASURED BEFORE THESE ROWS EXISTED, because it is the reason they do. An unauthenticated
/// GET at this route through this pipeline answered 302 - the action ran to completion for a request that
/// carried nothing - and deleting the route's refusal reddened nothing in the suite that walks this host.
/// The fixture's authorization context handed every request one fixed resolved administrator; it reads the
/// request now, and the reason is written where it is built.
/// </para>
/// </summary>
[Collection("SSOController")]
public sealed class SSOControllerLogoutRoutingTests : IClassFixture<SsoAuthorizationServerFixture>
{
    // A provider name no configuration in this suite carries, so the route finds no captured OpenID session
    // and no OpenID configuration and takes its local-only exit. That exit is a redirect, which is what
    // separates "admitted" from "refused" here without depending on any identity-provider state.
    private const string Provider = "logout-routing-probe";

    private const string Route = "/SSO/OID/logout/" + Provider;

    private static readonly int Unauthorized = (int)HttpStatusCode.Unauthorized;

    private readonly SsoAuthorizationServerFixture _fixture;

    public SSOControllerLogoutRoutingTests(SsoAuthorizationServerFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task AnUnauthenticatedNavigationAtTheLogoutRoute_IsRefusedByTheRouteItself()
    {
        // The row the removal of [Authorize] owes. A top-level navigation carrying no Authorization header,
        // no api_key and no ticket reaches the action - nothing refuses it earlier any more - and the action
        // refuses it. Remove the in-method refusal and this answers 302 instead, because the rest of the
        // method is a local sign-out that asks the caller for nothing.
        using var client = NoRedirectClient();

        using var response = await client.GetAsync(Route, TestContext.Current.CancellationToken);

        Assert.Equal(Unauthorized, (int)response.StatusCode);
    }

    [Fact]
    public async Task ATicketBearingNavigation_IsAdmittedWithNoCredential_AndOnlyOnce()
    {
        // The other half of the same decision, over the same wire: the ticket is what names the caller when
        // the request cannot carry a header, so a request holding one must pass where the request above is
        // refused. Then the same URL again, which is the one-time claim observed end to end rather than on
        // the store - a browser that fires the navigation twice ends one session, not two.
        // The account behind the ticket has to resolve, because the redeem reads it again (#1793): a ticket
        // for an account the host no longer resolves is refused, which is a different row.
        var userId = Guid.NewGuid();
        _fixture.UserManager.GetUserById(userId).Returns(TestUsers.Named("routing-probe", userId));
        var ticket = LogoutTicketStore.NewToken();
        LogoutTicketService.SeedForTests(
            new LogoutTicket(ticket, Provider, userId, "routing-probe-session", DateTime.UtcNow));

        using var client = NoRedirectClient();

        // The redeem sits behind the Single Logout switch (#1793), and this host's configuration is the
        // default, where it is off; under the switch every ticket is refused, which is a different row.
        SSOPlugin.Instance.MutateConfiguration(c => c.EnableSingleLogout = true);
        try
        {
            using var admitted = await client.GetAsync($"{Route}?ticket={ticket}", TestContext.Current.CancellationToken);
            using var spent = await client.GetAsync($"{Route}?ticket={ticket}", TestContext.Current.CancellationToken);

            Assert.Equal((int)HttpStatusCode.Found, (int)admitted.StatusCode);
            Assert.Equal(Unauthorized, (int)spent.StatusCode);
        }
        finally
        {
            SSOPlugin.Instance.MutateConfiguration(c => c.EnableSingleLogout = false);
        }
    }

    [Fact]
    public async Task ASessionBearingNavigationAtTheSameRoute_IsNotRefused()
    {
        // The positive control, without which the refusal above says nothing: the same route, the same
        // pipeline, a caller the host resolves, and no refusal. A 401 here would mean the route is broken
        // rather than that it is guarding, and the first row would be green for the wrong reason.
        using var client = NoRedirectClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, Route);
        request.Headers.Add(TestRoles.Header, TestRoles.User);

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.NotEqual(Unauthorized, (int)response.StatusCode);
        Assert.Equal((int)HttpStatusCode.Found, (int)response.StatusCode);
    }

    // The fixture's own client follows redirects, so the local-only exit would be reported as whatever the
    // host answers at "/" - a 404 - and an admitted request would read as a refusal of something else. The
    // status of the route's own answer is the subject here, so this client is told not to follow it.
    private HttpClient NoRedirectClient() =>
        new(new HttpClientHandler { AllowAutoRedirect = false, CheckCertificateRevocationList = true })
        {
            BaseAddress = _fixture.Client.BaseAddress,
            Timeout = TimeSpan.FromSeconds(30),
        };
}
