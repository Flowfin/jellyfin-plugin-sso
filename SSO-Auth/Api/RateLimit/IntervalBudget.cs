// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;

namespace Jellyfin.Plugin.SSO_Auth.Api.RateLimit;

/// <summary>
/// Admits at most a fixed number of actions per interval and counts the ones it refused, so a log line
/// written on an anonymously reachable refusal has a ceiling that holds with no rate limiter in front of it
/// (#1792). <see cref="IntervalGate"/> is the once-per-interval form of the same idea and is what the
/// throttle notice and the sweeps use; this one keeps the first few lines of an interval, because an
/// operator reading a handful of refusals wants each of them, and it is the flood past that handful which
/// must not reach the log at request rate. The interval is fixed rather than sliding, like the limiter's
/// own window, so a boundary burst can reach twice the budget across two adjacent intervals; what it
/// bounds is sustained volume. The caller owns the clock, as with the gate.
/// </summary>
/// <remarks>
/// WHY THIS IS NOT THE RATE LIMITER'S JOB. The limiter is off unless the operator turns it on, and it keys
/// on a public peer only, so behind an unresolved reverse proxy it creates no bucket at all. A line that
/// is bounded only by the limiter is unbounded on a stock install, which is the shape #1792 measured. This
/// budget is keyed on nothing: it is one ceiling for the whole process, because the source of a flood
/// through a proxy is not attributable and a per-source budget would be the limiter again.
/// </remarks>
internal sealed class IntervalBudget
{
    private readonly int _maxPerInterval;
    private readonly long _intervalTicks;
    private readonly object _lock = new();

    private long _windowStartTicks = DateTime.MinValue.Ticks;
    private int _admitted;
    private long _refused;

    /// <summary>
    /// Initializes a new instance of the <see cref="IntervalBudget"/> class.
    /// </summary>
    /// <param name="maxPerInterval">How many actions an interval admits; must be strictly positive.</param>
    /// <param name="interval">The interval length; must be strictly positive.</param>
    /// <exception cref="ArgumentOutOfRangeException">Either bound is zero or negative, which would silently disable the ceiling.</exception>
    internal IntervalBudget(int maxPerInterval, TimeSpan interval)
    {
        // A budget of zero would refuse everything and an interval of zero would admit everything; both
        // read as a working ceiling from the call site, so both fail here instead.
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxPerInterval);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(interval.Ticks);
        _maxPerInterval = maxPerInterval;
        _intervalTicks = interval.Ticks;
    }

    /// <summary>
    /// Reports whether the caller may perform the action now. The first admission of a new interval also
    /// hands back how many actions the previous interval refused, so the caller can write one summary of
    /// what was not written; every other admission reports zero.
    /// </summary>
    /// <param name="now">The current time, from a source consistent with prior calls on this budget.</param>
    /// <param name="refusedBefore">How many actions were refused since the last admission that opened an interval; zero unless this call opened one.</param>
    /// <returns>True when the action is within this interval's budget; false when it is not.</returns>
    internal bool TryEnter(DateTime now, out long refusedBefore)
    {
        refusedBefore = 0;
        lock (_lock)
        {
            // A backward clock step of at least the interval reopens the window too, the same self-heal
            // the gate carries: a window anchored in the future would otherwise refuse until the clock
            // caught up with it.
            if (Math.Abs(now.Ticks - _windowStartTicks) >= _intervalTicks)
            {
                _windowStartTicks = now.Ticks;
                _admitted = 0;
                refusedBefore = _refused;
                _refused = 0;
            }

            if (_admitted < _maxPerInterval)
            {
                _admitted++;
                return true;
            }

            _refused++;
            return false;
        }
    }
}
