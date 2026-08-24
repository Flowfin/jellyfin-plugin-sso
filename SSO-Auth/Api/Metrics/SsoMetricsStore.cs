// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;

namespace Jellyfin.Plugin.SSO_Auth.Api.Metrics;

/// <summary>
/// The counter tallies the metrics endpoint reads (#1139). Process-wide and monotonic: a counter only ever
/// rises, and the whole set is lost on restart, which is what a scraper expects of a process-local counter
/// and is why nothing here is persisted.
/// </summary>
/// <remarks>
/// <para>
/// THE SERIES COUNT IS CAPPED AND THE CAP REFUSES, because an unbounded label vocabulary is the way a
/// metrics surface turns into a memory amplifier. Every label value the plugin passes comes from the
/// configured provider set or from a closed enum, so the cap is a backstop rather than a working limit; what
/// it buys is that a future call site passing a caller-controlled value costs a dropped counter and one log
/// line instead of a series per request. A series already known keeps counting after the cap is reached - the
/// refusal falls on NEW series only, so the counters an operator is alerting on do not go silent when the cap
/// is hit.
/// </para>
/// <para>
/// No lock. A counter is a <see cref="StrongBox{T}"/> the dictionary hands out once, incremented through
/// <see cref="Interlocked"/>, which is the same shape the rate limiter's throttled tally already uses. The
/// snapshot is a moving read: two counters in one exposition may be a few increments apart, which is true of
/// every scrape of every counter and is not worth a lock on the login path.
/// </para>
/// </remarks>
internal static class SsoMetricsStore
{
    /// <summary>
    /// The most distinct series the store will hold. Two orders of magnitude above what a large deployment
    /// reaches - a server with 20 providers publishes roughly 20 provider series plus the closed reason,
    /// outcome, fetch-kind and throttle-class vocabularies - so a run that meets this cap has a defect
    /// rather than a big configuration.
    /// </summary>
    internal const int MaxSeries = 512;

    private static readonly ConcurrentDictionary<SsoMetricSeries, StrongBox<long>> Counters = new();

    private static long _refusedSeries;

    /// <summary>
    /// Gets the number of increments that were dropped because they named a series beyond
    /// <see cref="MaxSeries"/>. Published as its own counter, so a scrape that is missing a breakdown says
    /// so rather than looking complete.
    /// </summary>
    internal static long RefusedSeries => Interlocked.Read(ref _refusedSeries);

    /// <summary>
    /// Adds one to the counter <paramref name="series"/> names, creating it at zero the first time.
    /// </summary>
    /// <param name="series">The series to increment.</param>
    /// <returns><see langword="true"/> when the increment was recorded; <see langword="false"/> when it named a new series and the cap refused it.</returns>
    internal static bool Increment(SsoMetricSeries series)
    {
        if (Counters.TryGetValue(series, out var known))
        {
            Interlocked.Increment(ref known.Value);
            return true;
        }

        // Checked before the add rather than trimmed after it: a store that admits the series and then
        // evicts one has decided which counter to break, and there is no honest answer to that question.
        if (Counters.Count >= MaxSeries)
        {
            Interlocked.Increment(ref _refusedSeries);
            return false;
        }

        Interlocked.Increment(ref Counters.GetOrAdd(series, _ => new StrongBox<long>(0)).Value);
        return true;
    }

    /// <summary>
    /// Reads every counter, ordered by metric then label then value so one state renders identically on two
    /// scrapes. A dictionary promises no order at all, and an exposition whose lines moved between scrapes
    /// would make a diff of two scrapes unreadable.
    /// </summary>
    /// <returns>The series and their values.</returns>
    internal static IReadOnlyList<(SsoMetricSeries Series, long Value)> Snapshot() =>
        Counters
            .Select(entry => (Series: entry.Key, Value: Interlocked.Read(ref entry.Value.Value)))
            .OrderBy(entry => entry.Series.Metric, StringComparer.Ordinal)
            .ThenBy(entry => entry.Series.Label, StringComparer.Ordinal)
            .ThenBy(entry => entry.Series.Value, StringComparer.Ordinal)
            .ToList();

    /// <summary>
    /// Clears every counter. For tests only: the counters are process-wide, so one test's login would
    /// otherwise be counted by the next test's assertion.
    /// </summary>
    internal static void ResetForTests()
    {
        Counters.Clear();
        Interlocked.Exchange(ref _refusedSeries, 0);
    }
}
