// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// What one walk of a gated endpoint set produced: the endpoints that did not meet the expectation, and the
/// stalls that were survived rather than failed on.
/// </summary>
/// <param name="Failures">
/// One line per endpoint whose outcome did not satisfy the expectation. Empty means the walk met it everywhere.
/// </param>
/// <param name="Notes">
/// One line per request that produced no status and answered on a retry. These are not failures - the endpoint
/// answered - but a run in which one happened is not the same run as one in which none did, and a green result
/// that says nothing about it destroys the only trace.
/// </param>
public sealed record ProbeReport(IReadOnlyList<string> Failures, IReadOnlyList<string> Notes);

/// <summary>
/// Drives one caller across a gated endpoint set and collects, per endpoint, whatever did not meet the
/// expectation - an unexpected status, or no status at all.
///
/// <para>
/// The walk CONTINUES past a request that produced no status, which is the property this type exists for
/// (#1444). A transport failure thrown out of the loop ends the test at the first endpoint it hits, so a red
/// run reports one endpoint and says nothing about the other two dozen - and "one endpoint stalled" and
/// "every request failed" are the two readings that issue is left choosing between. Collecting them
/// separates the two: one line means one, twenty-five lines mean the host stopped answering.
/// </para>
///
/// <para>
/// It stops after <see cref="ConsecutiveNoStatusLimit"/> CONSECUTIVE no-status results, because the wall
/// clock is the price of continuing: at the fixture's 30-second client timeout, walking twenty-five dead
/// endpoints in each of five tests costs an hour of a suite that otherwise takes half a minute. Three in a
/// row already says the host is not answering; a fourth buys nothing and costs another timeout. Consecutive
/// rather than total is deliberate - an isolated failure between answered requests is the case worth walking
/// to the end, since its neighbours are what prove the host was alive around it.
/// </para>
///
/// <para>
/// A request the host pipeline NEVER TOOK is retried rather than failed on, within
/// <see cref="NoStatusRetryBudget"/> for the whole walk (#1444). The authorization stage cannot produce that
/// outcome: an endpoint that lost its attribute answers with the wrong STATUS, and every reading in which the
/// guard answered wrongly leaves at least one of the five tests green, which is the elimination recorded on
/// that issue. So a no-status result the counters place before the dispatch is the harness failing, and a run
/// reddened by it says something about this machine rather than about the endpoints. The retry is granted only
/// on that evidence: where the pipeline TOOK the request and did not finish it the endpoint itself hung and
/// the walk reports it at once, and where no counters are available nothing separates the two, so nothing is
/// retried.
/// </para>
/// </summary>
public static class AuthorizationProbe
{
    /// <summary>
    /// The number of CONSECUTIVE requests producing no status after which the walk stops and says how many
    /// endpoints it left undriven.
    /// </summary>
    public const int ConsecutiveNoStatusLimit = 3;

    /// <summary>
    /// The number of retries the WHOLE walk may spend on requests the host pipeline never took. A budget for
    /// the walk rather than an allowance per endpoint: the fault this covers is an isolated stall, and a walk
    /// whose every request dies before the dispatch is not something a retry rescues - paying a client timeout
    /// per endpoint for it is exactly the cost <see cref="ConsecutiveNoStatusLimit"/> exists to bound.
    /// </summary>
    public const int NoStatusRetryBudget = 2;

    /// <summary>
    /// The pause before a retry. The pool that produced the stall is drained by work items completing rather
    /// than by asking again immediately, and it is short enough that spending the whole budget costs a second.
    /// </summary>
    private static readonly TimeSpan RetryBackoff = TimeSpan.FromMilliseconds(500);

    /// <summary>
    /// Sends one request per endpoint as <paramref name="role"/> and returns one line for each endpoint whose
    /// outcome did not satisfy <paramref name="expected"/>. An empty failure list means every endpoint answered
    /// as expected.
    /// </summary>
    /// <param name="client">The client bound to the running fixture host.</param>
    /// <param name="endpoints">The endpoints to drive, in order.</param>
    /// <param name="role">The <see cref="TestRoles"/> header value, or <c>null</c> for an unauthenticated caller.</param>
    /// <param name="expected">The predicate the returned status has to satisfy.</param>
    /// <param name="traffic">
    /// Reads the host's entered/completed request counters, or <c>null</c> where no host is being driven. It is
    /// read either side of each request that produces no status, and the difference goes into that line and
    /// decides whether the request is retried.
    /// </param>
    /// <returns>The failures and the survived stalls, in the order the endpoints were driven.</returns>
    public static async Task<ProbeReport> CollectFailuresAsync(
        HttpClient client,
        IReadOnlyList<GatedEndpoint> endpoints,
        string? role,
        Func<int, bool> expected,
        Func<(long Entered, long Completed)>? traffic = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(expected);

        var failures = new List<string>();
        var notes = new List<string>();
        var consecutiveNoStatus = 0;
        var retriesLeft = NoStatusRetryBudget;

        for (var i = 0; i < endpoints.Count; i++)
        {
            var endpoint = endpoints[i];
            var status = -1;
            var retried = 0;
            var lastNoStatus = string.Empty;

            while (true)
            {
                var before = traffic?.Invoke();
                var elapsed = Stopwatch.StartNew();

                try
                {
                    using var response = await SendAsync(client, endpoint, role).ConfigureAwait(false);
                    status = (int)response.StatusCode;
                    break;
                }
                catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
                {
                    // A request that never produced a status carries none of that in its own text: the transport
                    // exception names an address and, on a non-English host, says so in that host's language.
                    // The endpoint, the caller, the elapsed time and the bound that was in force are what the
                    // reader of a red run needs and cannot reconstruct - which is the evidence #1444 lost.
                    // The host counters are the last thing the elapsed time cannot say: an accepted connection
                    // Kestrel never dispatched and a pipeline that took the request and never answered cost the
                    // same wall clock and are different faults. The thread pool goes with them because a
                    // saturated pool produces the first of those exactly - measured on this host, a request
                    // under one was accepted, never dispatched and died at the client timeout - and
                    // ThreadPool.GetAvailableThreads does not show it, while the pending count does.
                    var after = traffic?.Invoke();
                    lastNoStatus = FormattableString.Invariant(
                        $"the request produced no status: {endpoint} as {Caller(role)} after {elapsed.ElapsedMilliseconds} ms, client timeout {client.Timeout}, {ex.GetType().Name}: {ex.Message}{Seen(before, after)}{Pool()}");

                    if (Entered(before, after) == 0 && retriesLeft > 0)
                    {
                        retriesLeft--;
                        retried++;
                        await Task.Delay(RetryBackoff).ConfigureAwait(false);
                        continue;
                    }

                    break;
                }
            }

            if (status >= 0)
            {
                consecutiveNoStatus = 0;

                if (retried > 0)
                {
                    notes.Add(FormattableString.Invariant(
                        $"a request produced no status and answered {status} on retry {retried}: {endpoint} as {Caller(role)}, the host pipeline having taken none of the {retried} failed attempt(s){Pool()}"));
                }

                if (!expected(status))
                {
                    failures.Add(FormattableString.Invariant($"{endpoint} -> {status}"));
                }

                continue;
            }

            failures.Add(retried == 0
                ? lastNoStatus
                : FormattableString.Invariant($"{lastNoStatus}, retried {retried} time(s) because the host pipeline never took the request"));

            if (++consecutiveNoStatus >= ConsecutiveNoStatusLimit)
            {
                failures.Add(FormattableString.Invariant(
                    $"stopped after {ConsecutiveNoStatusLimit} consecutive requests that produced no status, leaving {endpoints.Count - i - 1} of {endpoints.Count} endpoints undriven"));
                break;
            }
        }

        return new ProbeReport(failures, notes);
    }

    /// <summary>How a caller is named in a line, so the unauthenticated one reads as a caller rather than as nothing.</summary>
    private static string Caller(string? role) => role ?? "an unauthenticated caller";

    /// <summary>
    /// Renders the thread pool as it stands at the moment a request produced no status. A pool with work
    /// queued and no thread free to run it accepts a connection and never dispatches it, which is one of the
    /// two faults the host counters distinguish and the only one this reading names.
    /// </summary>
    private static string Pool() => FormattableString.Invariant(
        $", thread pool {ThreadPool.ThreadCount} thread(s) with {ThreadPool.PendingWorkItemCount} work item(s) pending");

    /// <summary>
    /// How many requests the host pipeline took while the failed request ran, or <c>null</c> where no host is
    /// being driven and the question cannot be asked. Zero is the reading that separates a stall in front of
    /// the dispatch from an endpoint that hung inside it.
    /// </summary>
    private static long? Entered((long Entered, long Completed)? before, (long Entered, long Completed)? after)
        => before is null || after is null ? null : after.Value.Entered - before.Value.Entered;

    /// <summary>
    /// Renders what the host saw during ONE request, as the difference between the counters either side of it.
    /// Empty where no host is being driven, so a scripted transport reports nothing rather than zeroes it cannot
    /// know the meaning of.
    /// </summary>
    private static string Seen((long Entered, long Completed)? before, (long Entered, long Completed)? after)
    {
        if (before is null || after is null)
        {
            return string.Empty;
        }

        return FormattableString.Invariant(
            $", the host pipeline took {after.Value.Entered - before.Value.Entered} request(s) and finished {after.Value.Completed - before.Value.Completed} while it ran");
    }

    private static async Task<HttpResponseMessage> SendAsync(HttpClient client, GatedEndpoint endpoint, string? role)
    {
        using var request = new HttpRequestMessage(new HttpMethod(endpoint.Method), endpoint.Url);
        if (role is not null)
        {
            request.Headers.Add(TestRoles.Header, role);
        }

        // A minimal JSON body for methods that carry one, so a [FromBody] action does not 415 before running.
        // Irrelevant to the assertions (they only care whether the guard produced a 401/403), but it keeps the
        // authorized-path responses to genuine action outcomes.
        if (HttpMethod.Post.Method.Equals(endpoint.Method, StringComparison.OrdinalIgnoreCase)
            || HttpMethod.Put.Method.Equals(endpoint.Method, StringComparison.OrdinalIgnoreCase))
        {
            request.Content = new StringContent("null", Encoding.UTF8, "application/json");
        }

        return await client.SendAsync(request).ConfigureAwait(false);
    }
}
