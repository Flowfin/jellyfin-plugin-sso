// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Net;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// 429 response-shape pins for the login-path and outbound-fetch endpoints that were wired to the
/// shared rate-limit gate but not individually characterised (#928 U2). Each drives its endpoint over
/// the single-attempt budget and asserts the throttled response is byte-identical to the mapper's
/// contract: a 429 with the fixed plain-text body and a Retry-After within the window. The structural
/// "every such endpoint actually calls the gate" guarantee is <c>ArchitectureConformanceTests.
/// EveryMustThrottleEndpoint_CallsTheRateLimitGate</c>; these prove the wiring produces the right wire
/// response at each route. The already-pinned endpoints (SamlChallenge, OidCallback, Link, Unregister)
/// keep their own tests; this fills the remainder.
///
/// It also carries the forwarded-header attribution battery (#1035). Those rows are about a different
/// property on the same gate: not what a throttled response looks like, but WHICH bucket an attempt is
/// counted against when the request carries an <c>X-Forwarded-For</c> the plugin never asked for. They
/// live here rather than in a file of their own because the subject is the same endpoint and the same
/// single-attempt budget, and a second home for one property is how the next reader loses it.
/// </summary>
[Collection("SSOController")]
public class SSOControllerRateLimitTests
{
    private const string ThrottledBody = "Too many attempts. Please wait a moment and try again.";

    private static SsoControllerHarness Throttling(IPAddress clientIp) => new SsoControllerHarness(
        c =>
        {
            c.EnableRateLimit = true;
            c.RateLimitMaxAttempts = 1;
            c.RateLimitWindowSeconds = 60;
        },
        clientIp);

    private static void AssertThrottled(SsoControllerHarness harness, ActionResult result)
    {
        var throttled = Assert.IsType<ContentResult>(result);
        Assert.Equal(429, throttled.StatusCode);
        Assert.Equal(ThrottledBody, throttled.Content);
        Assert.Equal("text/plain", throttled.ContentType);

        var retryAfter = harness.Controller.Response.Headers.RetryAfter.ToString();
        Assert.True(
            int.TryParse(retryAfter, out var seconds) && seconds >= 1 && seconds <= 60,
            $"Retry-After must be whole seconds within the 60s window; was '{retryAfter}'.");
    }

    [Fact]
    public async Task OidChallenge_OverRateLimit_Returns429()
    {
        // A dedicated public address per test so the process-static limiter counter is this test's alone.
        var harness = Throttling(IPAddress.Parse("8.8.8.1"));

        // The first call spends the single-attempt budget (the unknown provider then 400s, after the spend).
        await harness.Controller.OidChallenge("does-not-exist");

        AssertThrottled(harness, await harness.Controller.OidChallenge("does-not-exist"));
    }

    [Fact]
    public async Task OidAuth_OverRateLimit_Returns429()
    {
        var harness = Throttling(IPAddress.Parse("8.8.8.2"));

        await harness.Controller.OidAuth("does-not-exist", new AuthResponse());

        AssertThrottled(harness, await harness.Controller.OidAuth("does-not-exist", new AuthResponse()));
    }

    [Fact]
    public async Task OidTest_OverRateLimit_Returns429()
    {
        var harness = Throttling(IPAddress.Parse("8.8.8.3"));

        await harness.Controller.OidTest("does-not-exist");

        AssertThrottled(harness, await harness.Controller.OidTest("does-not-exist"));
    }

    [Fact]
    public async Task SamlCallback_OverRateLimit_Returns429()
    {
        var harness = Throttling(IPAddress.Parse("8.8.8.4"));

        await harness.Controller.SamlCallback("does-not-exist");

        AssertThrottled(harness, await harness.Controller.SamlCallback("does-not-exist"));
    }

    [Fact]
    public void SamlMetadata_OverRateLimit_Returns429()
    {
        var harness = Throttling(IPAddress.Parse("8.8.8.5"));

        harness.Controller.SamlMetadata("does-not-exist");

        AssertThrottled(harness, harness.Controller.SamlMetadata("does-not-exist"));
    }

    [Fact]
    public async Task SamlLogout_OverRateLimit_Returns429()
    {
        var harness = Throttling(IPAddress.Parse("8.8.8.6"));

        await harness.Controller.SamlLogout("does-not-exist");

        AssertThrottled(harness, await harness.Controller.SamlLogout("does-not-exist"));
    }

    [Fact]
    public async Task SamlAuth_OverRateLimit_Returns429()
    {
        var harness = Throttling(IPAddress.Parse("8.8.8.7"));

        await harness.Controller.SamlAuth("does-not-exist", new AuthResponse());

        AssertThrottled(harness, await harness.Controller.SamlAuth("does-not-exist", new AuthResponse()));
    }

    [Fact]
    public async Task ARotatingSpoofedForwardedFor_NeverBuysAFreshBucket()
    {
        // #1035, the attacker-chooses-your-bucket case. A forwarded header arriving at this plugin is
        // client-supplied: Jellyfin's own middleware resolves and STRIPS the entries it was told to trust
        // ("Known proxies"), so whatever survives to here came from a hop nobody trusted. If any of it
        // reached the rate-limit key, an attacker would rotate the header to get a fresh budget on every
        // attempt - unlimited attempts - and could equally pin a victim's address to spend the victim's
        // budget for them.
        //
        // A different spoofed value on each attempt, one unchanging socket address. The second attempt
        // must still be throttled: the budget belongs to the connection, not to anything the client wrote.
        var harness = Throttling(IPAddress.Parse("8.8.9.1"));
        harness.Controller.ControllerContext.HttpContext.Request.Headers["X-Forwarded-For"] = "203.0.113.1";
        await harness.Controller.OidChallenge("does-not-exist");

        harness.Controller.ControllerContext.HttpContext.Request.Headers["X-Forwarded-For"] = "203.0.113.2";

        AssertThrottled(harness, await harness.Controller.OidChallenge("does-not-exist"));
    }

    [Theory]
    [InlineData("", "8.8.9.10")]
    [InlineData("not-an-ip", "8.8.9.11")]
    [InlineData("203.0.113.9, 198.51.100.4, 192.0.2.7", "8.8.9.12")]
    [InlineData("::1", "8.8.9.13")]
    public async Task AMalformedEmptyOrChainedForwardedFor_FallsBackToNothing_ItWasNeverRead(string forwarded, string socket)
    {
        // The fail-closed direction of the same rule, and the reason it is four rows rather than one: an
        // empty header, a value that is not an address at all, a chain longer than any configured depth,
        // and a loopback claim that would land in the never-throttled class if it were believed. Every one
        // of them has to leave attribution exactly where it was, because "the parse failed" and "trust this"
        // are the two answers a header parser can give and only one of them is safe to default to.
        //
        // A distinct socket address per row so the process-static counter is this row's alone.
        var harness = Throttling(IPAddress.Parse(socket));
        harness.Controller.ControllerContext.HttpContext.Request.Headers["X-Forwarded-For"] = forwarded;

        await harness.Controller.OidChallenge("does-not-exist");

        AssertThrottled(harness, await harness.Controller.OidChallenge("does-not-exist"));
    }

    [Fact]
    public async Task RepeatedForwardedForHeaders_DoNotMoveTheBucketEither()
    {
        // The multiply-supplied case, which is a different input from a comma chain inside one header: two
        // header lines, which some proxies emit and which a parser reading only the first or only the last
        // would disagree about.
        var harness = Throttling(IPAddress.Parse("8.8.9.2"));
        harness.Controller.ControllerContext.HttpContext.Request.Headers["X-Forwarded-For"] =
            new StringValues(new[] { "203.0.113.5", "198.51.100.6" });

        await harness.Controller.OidChallenge("does-not-exist");

        AssertThrottled(harness, await harness.Controller.OidChallenge("does-not-exist"));
    }

    [Fact]
    public async Task TheSameForwardedHeaderFromTwoConnections_GetsTwoBuckets()
    {
        // The positive control the three rows above need. Each of them passes trivially if the endpoint
        // throttles everything - which would be a mass-lockout, not a guard - so this asserts the other
        // direction on the same subject: one identical, unchanging forwarded header and two DIFFERENT
        // socket addresses, and the second connection's first attempt goes through.
        //
        // Together the pair says what the plugin's attribution actually is: the connection decides the
        // bucket and the header decides nothing, in both directions.
        const string SameClaim = "203.0.113.77";

        var first = Throttling(IPAddress.Parse("8.8.9.3"));
        first.Controller.ControllerContext.HttpContext.Request.Headers["X-Forwarded-For"] = SameClaim;
        await first.Controller.OidChallenge("does-not-exist");
        AssertThrottled(first, await first.Controller.OidChallenge("does-not-exist"));

        var second = Throttling(IPAddress.Parse("8.8.9.4"));
        second.Controller.ControllerContext.HttpContext.Request.Headers["X-Forwarded-For"] = SameClaim;

        var result = await second.Controller.OidChallenge("does-not-exist");

        Assert.False(
            result is ContentResult { StatusCode: 429 },
            "a second connection claiming the same forwarded address was throttled, so the header - not the connection - is deciding the bucket");
    }
}
