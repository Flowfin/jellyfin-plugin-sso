// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Pins what a red <see cref="SSOControllerAuthorizationTests"/> run is able to say about itself.
///
/// <para>
/// #1444 recorded one run in which all five request-driving authorization tests went red at once and the
/// evidence was gone by the time anybody read it. Which of the two remaining readings applies - one endpoint
/// stalled, or the host answered nothing - is decided by how many of the ~25 endpoints in each loop produced
/// a status, and a walk that throws at the first transport failure never asks the other 24. These units drive
/// the walk against a scripted transport, so that answer does not depend on catching the occurrence again.
/// </para>
///
/// <para>
/// The transport is scripted rather than a real host on purpose: a request that produces no status is the
/// subject, and there is no way to make a live loopback server reliably not answer.
/// </para>
/// </summary>
public sealed class AuthorizationProbeTests
{
    private static readonly Func<int, bool> ExpectUnauthorized = status => status == (int)HttpStatusCode.Unauthorized;

    [Fact]
    public async Task ATransportFailureDoesNotStopTheWalk()
    {
        // The property #1444 needs: the endpoints AFTER a dead one are still driven, so their statuses reach
        // the message. Without them the reader cannot tell a single stall from a host that stopped answering,
        // which is the fork that issue is stuck on. Take the continuation out of the probe and this goes red -
        // the exception leaves the walk and the two answers below are never observed.
        var answered = new List<string>();

        var failures = await Walk(
            Endpoints(3),
            request =>
            {
                answered.Add(request.RequestUri!.AbsolutePath);
                return request.RequestUri!.AbsolutePath.EndsWith("/e0", StringComparison.Ordinal)
                    ? throw new HttpRequestException("no connection")
                    : new HttpResponseMessage(HttpStatusCode.Unauthorized);
            });

        Assert.Equal(3, answered.Count);
        var only = Assert.Single(failures);
        Assert.Contains("the request produced no status", only, StringComparison.Ordinal);
        Assert.Contains("/e0", only, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheNoStatusLineNamesTheEndpointTheCallerAndTheBoundInForce()
    {
        // The line is the whole deliverable of a red run: which endpoint, as which caller, after how long, and
        // against which bound. A transport exception on its own names an address and, on this host, says so in
        // German.
        var failures = await Walk(
            Endpoints(1),
            _ => throw new HttpRequestException("keine Verbindung"),
            role: TestRoles.Admin);

        var line = Assert.Single(failures);
        Assert.Contains("GET /e0 [RequiresElevation] (A0)", line, StringComparison.Ordinal);
        Assert.Contains("as admin", line, StringComparison.Ordinal);
        Assert.Contains("client timeout 00:00:30", line, StringComparison.Ordinal);
        Assert.Contains("HttpRequestException: keine Verbindung", line, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheNoStatusLineSaysWhatTheHostSawWhileTheRequestRan()
    {
        // The last thing the elapsed time cannot say. An accepted connection Kestrel never dispatched and a
        // pipeline that took the request and never answered both cost the whole client timeout and are
        // different faults; only the host's own counters separate them. Take the counters out of the line and
        // this goes red, and the next occurrence of #1444 is back to being unable to say which happened.
        var entered = 7L;
        var completed = 7L;

        var failures = await Walk(
            Endpoints(1),
            _ =>
            {
                entered++;
                throw new HttpRequestException("no connection");
            },
            traffic: () => (entered, completed));

        var line = Assert.Single(failures);
        Assert.Contains("the host pipeline took 1 request(s) and finished 0 while it ran", line, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheNoStatusLineNamesTheThreadPoolItFailedUnder()
    {
        // A saturated pool produces exactly the fault the host counters report as "took 0": the connection is
        // accepted and the request never dispatched, and it dies at the client timeout. Measured on this host,
        // a request under a saturated pool read 63 threads with 229 work items pending against 5 and 0 for one
        // that answered - while GetAvailableThreads still reported 32735 of 32766 free, which is why the
        // pending count is the number in the line and the available count is not. Take the reading out and this
        // goes red, and a red run says the request never reached the pipeline without saying why.
        var failures = await Walk(
            Endpoints(1),
            _ => throw new HttpRequestException("no connection"));

        var line = Assert.Single(failures);
        Assert.Contains("thread pool ", line, StringComparison.Ordinal);
        Assert.Contains(" work item(s) pending", line, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AWalkWithNoHostBehindItReportsNoCountersRatherThanZeroes()
    {
        // A scripted transport has no host, so a pair of zeroes here would read as "Kestrel never saw it" and
        // mean nothing of the sort. Absent is the honest answer and the units above depend on it.
        var failures = await Walk(
            Endpoints(1),
            _ => throw new HttpRequestException("no connection"));

        var line = Assert.Single(failures);
        Assert.DoesNotContain("the host pipeline", line, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConsecutiveTransportFailuresStopTheWalkAndSayWhatWasLeftUndriven()
    {
        // The bound the continuation is bought with. At the fixture's 30-second client timeout, walking every
        // dead endpoint of five loops costs an hour of a suite that otherwise takes half a minute; three in a
        // row already says the host is not answering. Remove the limit and this goes red at ten lines.
        var driven = 0;

        var failures = await Walk(
            Endpoints(10),
            _ =>
            {
                driven++;
                throw new HttpRequestException("no connection");
            });

        Assert.Equal(AuthorizationProbe.ConsecutiveNoStatusLimit, driven);
        Assert.Equal(AuthorizationProbe.ConsecutiveNoStatusLimit + 1, failures.Count);
        Assert.Equal(
            "stopped after 3 consecutive requests that produced no status, leaving 7 of 10 endpoints undriven",
            failures[^1]);
    }

    [Fact]
    public async Task IsolatedTransportFailuresBetweenAnsweredRequestsWalkToTheEnd()
    {
        // Consecutive, not total. An endpoint that fails between two that answered is the case worth walking
        // out, because its neighbours are what prove the host was alive around it - counted together, the walk
        // would stop on the third scattered stall and destroy exactly that evidence.
        var failures = await Walk(
            Endpoints(6),
            request => IsOdd(request.RequestUri!.AbsolutePath)
                ? throw new HttpRequestException("no connection")
                : new HttpResponseMessage(HttpStatusCode.Unauthorized));

        Assert.Equal(3, failures.Count);
        Assert.All(failures, line => Assert.Contains("the request produced no status", line, StringComparison.Ordinal));
    }

    [Fact]
    public async Task AStatusThatMissesTheExpectationIsReportedForEveryEndpointItMisses()
    {
        var failures = await Walk(
            Endpoints(3),
            _ => new HttpResponseMessage(HttpStatusCode.OK));

        Assert.Equal(
            new[]
            {
                "GET /e0 [RequiresElevation] (A0) -> 200",
                "GET /e1 [RequiresElevation] (A1) -> 200",
                "GET /e2 [RequiresElevation] (A2) -> 200",
            },
            failures);
    }

    [Fact]
    public async Task AWalkInWhichEveryStatusMeetsTheExpectationReportsNothing()
    {
        var failures = await Walk(
            Endpoints(4),
            _ => new HttpResponseMessage(HttpStatusCode.Unauthorized));

        Assert.Empty(failures);
    }

    private static bool IsOdd(string path) => (path[^1] - '0') % 2 == 1;

    private static string N(int i) => i.ToString(CultureInfo.InvariantCulture);

    private static IReadOnlyList<GatedEndpoint> Endpoints(int count) =>
        Enumerable.Range(0, count)
            .Select(i => new GatedEndpoint("GET", "/e" + N(i), "RequiresElevation", "A" + N(i)))
            .ToList();

    private static async Task<IReadOnlyList<string>> Walk(
        IReadOnlyList<GatedEndpoint> endpoints,
        Func<HttpRequestMessage, HttpResponseMessage> answer,
        string? role = null,
        Func<(long Entered, long Completed)>? traffic = null)
    {
        using var handler = new ScriptedTransport(answer);

        // The same 30 seconds the fixture sets, so the bound this walk reports is the one the suite runs under
        // rather than a number invented here.
        using var client = new HttpClient(handler)
        {
            BaseAddress = new Uri("http://127.0.0.1:1/"),
            Timeout = TimeSpan.FromSeconds(30),
        };

        return await AuthorizationProbe.CollectFailuresAsync(client, endpoints, role, ExpectUnauthorized, traffic);
    }

    /// <summary>A transport that answers, or refuses to, exactly as the unit calling it says.</summary>
    private sealed class ScriptedTransport : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _answer;

        public ScriptedTransport(Func<HttpRequestMessage, HttpResponseMessage> answer) => _answer = answer;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(_answer(request));
    }
}
