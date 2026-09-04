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
///
/// <para>
/// They also pin the repair that issue asks for: a red result from those five tests should mean the endpoints
/// lost their attributes and nothing else, so a request the host pipeline never took is retried within a
/// budget rather than reddening a guard it never reached, while one the pipeline took and did not finish stays
/// red at the first occurrence.
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

    [Fact]
    public async Task ARequestTheHostNeverTookIsRetriedAndTheAnswerIsWhatCounts()
    {
        // The repair #1444 asks for. The authorization stage cannot answer with NO status - an endpoint that
        // lost its attribute answers with the wrong one - so a request the counters place before the dispatch
        // reddens these five tests for a fault of the harness. Measured on this host, a saturated pool produces
        // exactly that: accepted, never dispatched, dead at the client timeout. Take the retry out and this
        // goes red with a no-status line for an endpoint that answered 401 the moment it was asked again.
        var driven = 0;

        var report = await Report(
            Endpoints(1),
            _ => ++driven == 1
                ? throw new HttpRequestException("no connection")
                : new HttpResponseMessage(HttpStatusCode.Unauthorized),
            traffic: () => (11L, 11L));

        Assert.Equal(2, driven);
        Assert.Empty(report.Failures);
        var note = Assert.Single(report.Notes);
        Assert.Contains("answered 401 on retry 1", note, StringComparison.Ordinal);
        Assert.Contains("GET /e0 [RequiresElevation] (A0)", note, StringComparison.Ordinal);
        Assert.Contains(" work item(s) pending", note, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ARetriedRequestThatAnswersWrongIsStillAFailure()
    {
        // The retry must not become an escape. It buys the endpoint another chance to ANSWER; what it answers
        // is judged exactly as before, so a guard that admits an unauthenticated caller cannot be rescued by
        // having stalled first.
        var driven = 0;

        var report = await Report(
            Endpoints(1),
            _ => ++driven == 1
                ? throw new HttpRequestException("no connection")
                : new HttpResponseMessage(HttpStatusCode.OK),
            traffic: () => (11L, 11L));

        Assert.Equal("GET /e0 [RequiresElevation] (A0) -> 200", Assert.Single(report.Failures));
        Assert.Single(report.Notes);
    }

    [Fact]
    public async Task ARequestTheHostTookAndDidNotFinishIsReportedAtOnce()
    {
        // The other side of the same reading, and the reason the retry is granted on evidence rather than on
        // the exception type. A pipeline that TOOK the request and never answered is the endpoint hanging,
        // which is a real fault and must stay red at the first occurrence. Retry it and this goes red at two
        // attempts for a fault that asking again cannot change.
        var entered = 4L;
        var driven = 0;

        var report = await Report(
            Endpoints(1),
            _ =>
            {
                driven++;
                entered++;
                throw new HttpRequestException("no connection");
            },
            traffic: () => (entered, 4L));

        Assert.Equal(1, driven);
        var line = Assert.Single(report.Failures);
        Assert.Contains("the host pipeline took 1 request(s) and finished 0 while it ran", line, StringComparison.Ordinal);
        Assert.DoesNotContain("retried", line, StringComparison.Ordinal);
    }

    [Fact]
    public async Task NoCountersMeansNoRetry()
    {
        // Fail closed where the question cannot be asked. Without the host's counters nothing separates a stall
        // in front of the dispatch from an endpoint that hung inside it, and retrying on the exception type
        // alone would quietly re-ask a request that a real fault killed.
        var driven = 0;

        var report = await Report(
            Endpoints(1),
            _ =>
            {
                driven++;
                throw new HttpRequestException("no connection");
            });

        Assert.Equal(1, driven);
        Assert.DoesNotContain("retried", Assert.Single(report.Failures), StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheRetryBudgetIsSpentOnceForTheWholeWalk()
    {
        // The bound the retry is bought with, and it is per WALK rather than per endpoint. A walk in which
        // every request dies before the dispatch is not something a retry rescues, and at the fixture's
        // 30-second timeout an allowance per endpoint would multiply the worst case by three. So the first
        // endpoint spends the budget, and the two after it are failed on their first attempt.
        var driven = 0;

        var report = await Report(
            Endpoints(3),
            _ =>
            {
                driven++;
                throw new HttpRequestException("no connection");
            },
            traffic: () => (11L, 11L));

        Assert.Equal(AuthorizationProbe.NoStatusRetryBudget + 3, driven);
        Assert.Contains("retried 2 time(s) because the host pipeline never took the request", report.Failures[0], StringComparison.Ordinal);
        Assert.DoesNotContain("retried", report.Failures[1], StringComparison.Ordinal);
        Assert.Equal(
            "stopped after 3 consecutive requests that produced no status, leaving 0 of 3 endpoints undriven",
            report.Failures[^1]);
        Assert.Empty(report.Notes);
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
        return (await Report(endpoints, answer, role, traffic)).Failures;
    }

    private static async Task<ProbeReport> Report(
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
