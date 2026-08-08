// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;

namespace Jellyfin.Plugin.SSO_Auth.Bench;

/// <summary>
/// A collected set of wall-clock durations for one measured stage, and the distribution read off it.
/// Percentiles rather than a mean, because the login path's interesting number is the tail a user waits
/// through: a mean hides the one request in fifty that pays for a discovery fetch or a lock.
/// </summary>
internal sealed class LatencySamples
{
    // Timestamps rather than milliseconds while collecting, so the per-iteration cost is one subtraction
    // and the conversion happens once at report time.
    private readonly List<long> _ticks = new();

    /// <summary>Gets the number of measured iterations.</summary>
    internal int Count => _ticks.Count;

    /// <summary>Records one stage duration, as a raw <see cref="Stopwatch"/> timestamp delta.</summary>
    /// <param name="elapsedTicks">The timestamp delta for the stage.</param>
    internal void Add(long elapsedTicks) => _ticks.Add(elapsedTicks);

    /// <summary>Takes over another set's samples, for merging the per-caller sets of a concurrent run.</summary>
    /// <param name="other">The set to absorb.</param>
    internal void AddRange(LatencySamples other) => _ticks.AddRange(other._ticks);

    /// <summary>
    /// Formats one report row: the sample count and the p50/p95/p99/max of the distribution, in
    /// milliseconds. Sorting is done here rather than on every insert - the set is read once.
    /// </summary>
    /// <param name="scenario">The scenario name for the row's first column.</param>
    /// <param name="stage">The measured stage for the row's second column.</param>
    /// <returns>A single fixed-width row.</returns>
    internal string Row(string scenario, string stage)
    {
        var sorted = _ticks.ToArray();
        Array.Sort(sorted);
        return string.Create(
            CultureInfo.InvariantCulture,
            $"{scenario,-11}{stage,-11}{sorted.Length,7}{Percentile(sorted, 0.50),10:F3}{Percentile(sorted, 0.95),10:F3}{Percentile(sorted, 0.99),10:F3}{Percentile(sorted, 1.00),10:F3}");
    }

    /// <summary>The header the rows above line up under.</summary>
    /// <returns>The column header line.</returns>
    internal static string Header() =>
        string.Create(
            CultureInfo.InvariantCulture,
            $"{"scenario",-11}{"stage",-11}{"n",7}{"p50 ms",10}{"p95 ms",10}{"p99 ms",10}{"max ms",10}");

    /// <summary>
    /// The nearest-rank percentile of a sorted sample set, in milliseconds. Nearest-rank returns an
    /// observed sample rather than an interpolation between two, so every number printed is a duration
    /// some iteration actually took.
    /// </summary>
    private static double Percentile(long[] sorted, double quantile)
    {
        if (sorted.Length == 0)
        {
            return 0;
        }

        var rank = (int)Math.Ceiling(quantile * sorted.Length) - 1;
        return Milliseconds(sorted[Math.Clamp(rank, 0, sorted.Length - 1)]);
    }

    /// <summary>Converts a <see cref="Stopwatch"/> timestamp delta into milliseconds.</summary>
    private static double Milliseconds(long ticks) => ticks * 1000.0 / Stopwatch.Frequency;
}
