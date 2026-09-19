// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Proves the elevation guard on the SSO admin surface is genuinely ENFORCED, not merely present. The
/// production <see cref="Jellyfin.Plugin.SSO_Auth.Api.SSOController"/> is hosted in a real in-process Kestrel
/// server (see <see cref="SsoAuthorizationServerFixture"/>); requests travel through the same ASP.NET Core
/// routing + authentication + authorization middleware that runs inside Jellyfin. A non-elevated caller is
/// rejected before the action body executes, on EVERY <c>[Authorize(RequiresElevation)]</c> endpoint,
/// enumerated from the live routing table rather than a hand-maintained list.
///
/// This complements the reflection checks (which assert the attribute is on the method) by exercising the
/// enforcement path end to end: a stray <c>[AllowAnonymous]</c>, a wrong/absent policy name, a controller-level
/// override, or a new unguarded admin endpoint would all fail here where a reflection check on the old set
/// would pass.
/// </summary>
[Collection("SSOController")]
public sealed class SSOControllerAuthorizationTests : IClassFixture<SsoAuthorizationServerFixture>
{
    private static readonly int[] Rejections = { StatusCodes401, StatusCodes403 };

    private const int StatusCodes401 = (int)HttpStatusCode.Unauthorized;
    private const int StatusCodes403 = (int)HttpStatusCode.Forbidden;

    // The admin surface expected to be elevation-gated. The dynamic theories below cover whatever the live
    // table exposes; this fixed set is the completeness anchor - an endpoint silently losing its guard drops
    // out of the discovered set and fails CoversExactlyTheKnownElevationSurface.
    private static readonly string[] ExpectedElevationActions =
    {
        "OidAdd", "OidDel", "OidProviders", "OidTest", "OidStates",
        // The redirect_uri the admin page displays (#1303): read-only, and elevation-gated because it
        // answers with a provider's configured base-URL override and only an administrator has a use for it.
        "OidRedirectUri",
        "SamlAdd", "SamlDel", "SamlProviders", "SamlTest", "SamlImportMetadata",
        "ExportConfig", "ImportConfig", "ManagedProviders", "Unregister", "ExportLinks", "ExportUserLinks",
        // The aggregate configuration check (#1084): read-only, and elevation-gated because it names every
        // configured provider and what is wrong with it, which is an inventory an unauthenticated caller has
        // no business reading.
        "CheckProviders",
        // The SSO-only login admin surface (#165): the mode toggle, the break-glass designation, and status.
        "EnableSsoOnly", "DisableSsoOnly", "DesignateBreakGlassAdmin", "SsoOnlyStatus",
        // The per-account SSO-managed report (#1136): read-only, and elevation-gated because it answers for
        // an account other than the caller's.
        "SsoManagedStatus",
        // The linked-account roster (#1119): read-only, and elevation-gated because it names every linked
        // account on the server.
        "LinkedAccountRoster",
        // The link-backup restore (#1129): it rebinds identity-provider subjects onto accounts other than
        // the caller's, in bulk, with no identity-provider response behind any of them.
        "ImportLinks",
        // The pre-provision link write (#1133): it grants an identity-provider subject the ability to sign
        // in as an account other than the caller's, with no identity-provider response behind it.
        "PreprovisionCanonicalLink",
        // The per-provider bulk unlink (#1519): it removes canonical links on accounts other than the
        // caller's, every one of them at once, and it is the only route here that can take a whole server
        // off SSO in one call. There is no single subject a per-user authorization check could name.
        "PurgeProviderLinks",
        // The approve action (#1529): it ENABLES a Jellyfin account, which is a grant of access to somebody
        // other than the caller. It acts only on this plugin's own record of having provisioned that account
        // inert, and refuses an administrator outright, but the grant itself is why it sits here rather than
        // behind a bare [Authorize] - there is no user whose own account this is.
        "ApproveProvisionedAccount",
        // The mappable permission vocabulary (#1484): read-only and installation-independent, and
        // elevation-gated because the config page is the only caller it exists for - an anonymous route
        // would be a new unauthenticated surface bought for nothing.
        "PermissionVocabulary",
        // The auth-path counter exposition (#1139): read-only, and elevation-gated because the counters name
        // which providers the server has and how often logins against them fail, which is reconnaissance for
        // an unauthenticated caller and would let one watch their own attempts land.
        "Metrics",
    };

    // The endpoints guarded by a bare [Authorize] (any authenticated caller, no elevation) - the canonical
    // link management surface, plus the SP-initiated SAML logout (#727) and the logout-ticket mint (#1768),
    // where a user acts on THEMSELVES (every action is scoped to the caller's own user id), so they are
    // deliberately non-elevated.
    //
    // OidLogout LEFT THIS LIST IN #1768 AND DID NOT BECOME AN UNGUARDED ROUTE, which is the one line in
    // this file a reviewer should stop at. That route has to be reachable by a top-level NAVIGATION, so it
    // can accept a one-time ticket in place of a session header, and [Authorize] refuses a request the
    // ticket would have authorised before the method ever runs. So the attribute came off and the method
    // took the decision itself, refusing in every case the attribute refused: no ticket and no session is
    // 401, and a ticket that is unknown, expired, already spent or minted for another provider is 401 too.
    // What holds that is SSOControllerLogoutTicketTests, one row per refusal, with a positive control for
    // the session-bearing form beside them - because a list this route has left cannot say anything about
    // it, and a reader of this comment should be sent to the rows rather than to the sentence.
    private static readonly string[] ExpectedAuthenticatedActions =
    {
        "AddCanonicalLink", "DeleteCanonicalLink", "GetSamlLinksByUser", "GetOidLinksByUser", "OidLogoutTicket", "SamlSpLogout",
    };

    // The actions on THIS controller that carry no authorization attribute at all. Every login-path endpoint
    // is here by design - a challenge, a callback and a metadata read are reached before anybody is signed in -
    // and so, since #1768, is the RP-initiated OpenID logout, which has to be reachable by a top-level
    // navigation carrying a one-time ticket instead of a session header.
    //
    // THIS ROSTER EXISTS BECAUSE ITS ABSENCE WAS THE GAP. EndpointCatalog skipped an endpoint with no
    // AuthorizeAttribute, so such a route landed in neither bucket above and the two rules over them said
    // nothing about it. Taking [Authorize] off an action therefore did not move it between rosters, it
    // removed it from the only suite that exercises authorization through real ASP.NET routing - silently,
    // and at exactly the moment the decision most deserved a reader. Every neighbouring decision in this
    // repository carries a roster with a completeness rule (RateLimitExemptRoutes, ProviderNameExemptRoutes);
    // "this route is deliberately anonymous" was the one that did not, so the next removal failed nothing.
    // It does now.
    private static readonly string[] ExpectedAnonymousActions =
    {
        // The login path, reached before anybody is signed in: a challenge, the identity provider's callback,
        // the session-minting leg, and the SAML service-provider metadata a provider fetches.
        "OidChallenge", "OidCallback", "OidAuth",
        "SamlChallenge", "SamlCallback", "SamlAuth", "SamlMetadata",

        // The inbound Single Logout endpoints, where the identity provider is the caller and a signature is
        // the only authenticator.
        "OidBackChannelLogout", "SamlLogout",

        // The RP-initiated OpenID logout (#1768). It has to be reachable by a top-level navigation, which
        // carries no Authorization header, so it accepts a one-time ticket instead and refuses in the method.
        // This is the entry to read twice: it is the only one here that ends a session.
        "OidLogout",

        // The enabled-provider name lists, anonymous by the decision recorded at their own call sites (#540):
        // the same names are already in the served linking page's DOM for an anonymous visitor.
        "OidProviderNames", "SamlProviderNames",

        // The served pages and their UI strings, on SSOViewsController rather than SSOController: a
        // read-only embedded asset and the catalog that localizes it (#913).
        "GetView", "GetLocalizationCatalog",
    };

    private readonly SsoAuthorizationServerFixture _fixture;

    public SSOControllerAuthorizationTests(SsoAuthorizationServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public void CoversExactlyTheKnownElevationSurface()
    {
        // The live routing table's elevation-gated actions must be exactly the known admin surface. A NEW
        // guarded endpoint (uncovered) or a guard REMOVED from a known one both break this, forcing a review.
        var discovered = _fixture.Endpoints.ElevationGated.Select(e => e.Action).Distinct().OrderBy(n => n, StringComparer.Ordinal);
        Assert.Equal(ExpectedElevationActions.OrderBy(n => n, StringComparer.Ordinal), discovered);
    }

    [Fact]
    public void PlainAuthorizeSurfaceIsDistinctFromElevation()
    {
        var discovered = _fixture.Endpoints.AuthenticatedOnly.Select(e => e.Action).Distinct().OrderBy(n => n, StringComparer.Ordinal);
        Assert.Equal(ExpectedAuthenticatedActions.OrderBy(n => n, StringComparer.Ordinal), discovered);
    }

    [Fact]
    public void TheAnonymousSurfaceIsExactlyTheDeclaredOne()
    {
        // The third bucket, asserted set-equal like the other two. A route that loses its authorization
        // attribute now has to be added here in the same change, where a reader meets the decision; a route
        // that gains one has to be removed. Neither can happen in silence.
        var discovered = _fixture.Endpoints.Anonymous.Select(e => e.Action).Distinct().OrderBy(n => n, StringComparer.Ordinal);
        Assert.Equal(ExpectedAnonymousActions.OrderBy(n => n, StringComparer.Ordinal), discovered);
    }

    [Fact]
    public async Task UnauthenticatedCaller_IsRejectedOnEveryElevationEndpoint()
    {
        await AssertAllAsync(
            _fixture.Endpoints.ElevationGated,
            role: null,
            expected: status => status == StatusCodes401,
            because: "an unauthenticated caller must get 401");
    }

    [Fact]
    public async Task AuthenticatedNonAdmin_IsForbiddenOnEveryElevationEndpoint()
    {
        await AssertAllAsync(
            _fixture.Endpoints.ElevationGated,
            role: TestRoles.User,
            expected: status => status == StatusCodes403,
            because: "an authenticated non-administrator must get 403");
    }

    [Fact]
    public async Task Administrator_PassesTheAuthorizationStageOnEveryElevationEndpoint()
    {
        // An administrator clears the guard, so the response is whatever the action body produces - never a
        // 401/403. Proving "not rejected" is the point: the guard admits the elevated caller.
        await AssertAllAsync(
            _fixture.Endpoints.ElevationGated,
            role: TestRoles.Admin,
            expected: status => !Rejections.Contains(status),
            because: "an administrator must pass the elevation guard (no 401/403)");
    }

    [Fact]
    public async Task UnauthenticatedCaller_IsRejectedOnEveryAuthenticatedEndpoint()
    {
        await AssertAllAsync(
            _fixture.Endpoints.AuthenticatedOnly,
            role: null,
            expected: status => status == StatusCodes401,
            because: "a bare [Authorize] endpoint must reject an unauthenticated caller with 401");
    }

    [Fact]
    public async Task AuthenticatedNonAdmin_PassesTheAuthorizationStageOnEveryAuthenticatedEndpoint()
    {
        // The distinction matters: a plain [Authorize] endpoint must NOT be treated as elevation-gated, so a
        // non-admin authenticated caller passes the authorization stage (no 401/403).
        await AssertAllAsync(
            _fixture.Endpoints.AuthenticatedOnly,
            role: TestRoles.User,
            expected: status => !Rejections.Contains(status),
            because: "a bare [Authorize] endpoint must admit any authenticated caller (no 401/403)");
    }

    [Fact]
    public async Task TheHostCountersMoveByOneAcrossOneRealRequest()
    {
        // What makes the numbers in a no-status line readable. The walk reports the DIFFERENCE across one
        // request, so the pair is only worth printing if a request that the host both took and finished moves
        // each side by exactly one. The facts of this class run one after the other - measured, not assumed -
        // so nothing else is in flight to inflate it. Remove the middleware and this goes red at 0.
        var before = _fixture.Traffic;

        using var request = new HttpRequestMessage(HttpMethod.Get, _fixture.Endpoints.ElevationGated[0].Url);
        using var response = await _fixture.Client.SendAsync(request, TestContext.Current.CancellationToken);

        var after = _fixture.Traffic;
        Assert.Equal(1, after.Entered - before.Entered);
        Assert.Equal(1, after.Completed - before.Completed);
    }

    private async Task AssertAllAsync(
        IReadOnlyList<GatedEndpoint> endpoints,
        string? role,
        Func<int, bool> expected,
        string because)
    {
        Assert.NotEmpty(endpoints);

        // The walk itself lives in AuthorizationProbe so a red run reports EVERY endpoint's outcome rather
        // than stopping at the first request that produced no status (#1444). What the assertion needs from
        // it is only the list; the host counters go with it so a no-status line says whether the host ever
        // saw that request, and so that a request the host never took is retried rather than reddening a
        // guard it never reached.
        var report = await AuthorizationProbe.CollectFailuresAsync(
            _fixture.Client, endpoints, role, expected, () => _fixture.Traffic).ConfigureAwait(false);

        // A stall that the retry survived leaves the assertion green, so this line is the only place the run
        // says it happened at all. It is a warning rather than a failure because the endpoint answered, and
        // the alternative - dropping it - is how the evidence was lost in the first place.
        foreach (var note in report.Notes)
        {
            TestContext.Current.AddWarning(note);
        }

        Assert.True(report.Failures.Count == 0, $"{because}, but these did not: {string.Join("; ", report.Failures)}");
    }
}
