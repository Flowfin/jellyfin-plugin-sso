// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

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
/// </summary>
public static class AuthorizationProbe
{
    /// <summary>
    /// The number of CONSECUTIVE requests producing no status after which the walk stops and says how many
    /// endpoints it left undriven.
    /// </summary>
    public const int ConsecutiveNoStatusLimit = 3;

    /// <summary>
    /// Sends one request per endpoint as <paramref name="role"/> and returns one line for each endpoint whose
    /// outcome did not satisfy <paramref name="expected"/>. An empty result means every endpoint answered as
    /// expected.
    /// </summary>
    /// <param name="client">The client bound to the running fixture host.</param>
    /// <param name="endpoints">The endpoints to drive, in order.</param>
    /// <param name="role">The <see cref="TestRoles"/> header value, or <c>null</c> for an unauthenticated caller.</param>
    /// <param name="expected">The predicate the returned status has to satisfy.</param>
    /// <param name="traffic">
    /// Reads the host's entered/completed request counters, or <c>null</c> where no host is being driven. It is
    /// read either side of each request that produces no status, and the difference goes into that line.
    /// </param>
    /// <returns>The failure lines, in the order the endpoints were driven.</returns>
    public static async Task<IReadOnlyList<string>> CollectFailuresAsync(
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
        var consecutiveNoStatus = 0;

        for (var i = 0; i < endpoints.Count; i++)
        {
            var endpoint = endpoints[i];
            var before = traffic?.Invoke();
            var elapsed = Stopwatch.StartNew();
            int status;

            try
            {
                using var response = await SendAsync(client, endpoint, role).ConfigureAwait(false);
                status = (int)response.StatusCode;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                // A request that never produced a status carries none of that in its own text: the transport
                // exception names an address and, on a non-English host, says so in that host's language.
                // The endpoint, the caller, the elapsed time and the bound that was in force are what the
                // reader of a red run needs and cannot reconstruct - which is the evidence #1444 lost.
                // The host counters are the last thing the elapsed time cannot say: an accepted connection
                // Kestrel never dispatched and a pipeline that took the request and never answered cost the
                // same wall clock and are different faults.
                failures.Add(FormattableString.Invariant(
                    $"the request produced no status: {endpoint} as {role ?? "an unauthenticated caller"} after {elapsed.ElapsedMilliseconds} ms, client timeout {client.Timeout}, {ex.GetType().Name}: {ex.Message}{Seen(before, traffic)}"));

                if (++consecutiveNoStatus >= ConsecutiveNoStatusLimit)
                {
                    failures.Add(FormattableString.Invariant(
                        $"stopped after {ConsecutiveNoStatusLimit} consecutive requests that produced no status, leaving {endpoints.Count - i - 1} of {endpoints.Count} endpoints undriven"));
                    break;
                }

                continue;
            }

            consecutiveNoStatus = 0;
            if (!expected(status))
            {
                failures.Add(FormattableString.Invariant($"{endpoint} -> {status}"));
            }
        }

        return failures;
    }

    /// <summary>
    /// Renders what the host saw during ONE request, as the difference between the counters either side of it.
    /// Empty where no host is being driven, so a scripted transport reports nothing rather than zeroes it cannot
    /// know the meaning of.
    /// </summary>
    private static string Seen((long Entered, long Completed)? before, Func<(long Entered, long Completed)>? traffic)
    {
        if (before is null || traffic is null)
        {
            return string.Empty;
        }

        var after = traffic();
        return FormattableString.Invariant(
            $", the host pipeline took {after.Entered - before.Value.Entered} request(s) and finished {after.Completed - before.Value.Completed} while it ran");
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
