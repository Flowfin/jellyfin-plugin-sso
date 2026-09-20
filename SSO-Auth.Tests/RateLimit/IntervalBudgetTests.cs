// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using Jellyfin.Plugin.SSO_Auth.Api.RateLimit;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Pins <see cref="IntervalBudget"/>: at most a fixed number of admissions per interval, a count of what
/// the interval refused handed to the first admission of the next one, and a self-heal on a backward
/// clock step (#1792). The budget is the ceiling on the audit lines an anonymously reachable refusal
/// writes, so a row here is what makes "bounded with no rate limiter in front of it" a property rather
/// than a sentence.
/// </summary>
public class IntervalBudgetTests
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(1);

    private static DateTime At(int minute, int second = 0) =>
        new DateTime(2026, 1, 1, 0, minute, second, DateTimeKind.Utc);

    [Fact]
    public void AdmitsTheBudget_AndRefusesThePartPastIt()
    {
        var budget = new IntervalBudget(3, Interval);

        Assert.True(budget.TryEnter(At(0), out _));
        Assert.True(budget.TryEnter(At(0, 10), out _));
        Assert.True(budget.TryEnter(At(0, 20), out _));
        Assert.False(budget.TryEnter(At(0, 30), out _));
        Assert.False(budget.TryEnter(At(0, 59), out _));
    }

    [Fact]
    public void TheNextInterval_ReopensTheBudget_AndReportsWhatTheLastOneRefused()
    {
        // The count of refusals is handed to exactly one admission, the first of the new interval, so a
        // caller writes one summary of what was not written and never a second copy of it.
        var budget = new IntervalBudget(2, Interval);
        budget.TryEnter(At(0), out _);
        budget.TryEnter(At(0, 1), out _);
        budget.TryEnter(At(0, 2), out _);
        budget.TryEnter(At(0, 3), out _);
        budget.TryEnter(At(0, 4), out _);

        Assert.True(budget.TryEnter(At(1), out var refused));
        Assert.Equal(3, refused);

        Assert.True(budget.TryEnter(At(1, 1), out var second));
        Assert.Equal(0, second);
    }

    [Fact]
    public void AQuietInterval_ReportsNothingRefused()
    {
        var budget = new IntervalBudget(2, Interval);
        budget.TryEnter(At(0), out _);

        Assert.True(budget.TryEnter(At(1), out var refused));
        Assert.Equal(0, refused);
    }

    [Fact]
    public void ABackwardClockStepOfAtLeastTheInterval_ReopensTheBudget()
    {
        // A window anchored in the future would otherwise refuse until the clock caught up with it; the
        // gate beside this one self-heals the same way and for the same reason.
        var budget = new IntervalBudget(1, Interval);
        Assert.True(budget.TryEnter(At(10), out _));
        Assert.False(budget.TryEnter(At(10, 30), out _));

        Assert.True(budget.TryEnter(At(5), out _));
    }

    [Fact]
    public void ABackwardStepShorterThanTheInterval_DoesNotReopenIt()
    {
        var budget = new IntervalBudget(1, Interval);
        Assert.True(budget.TryEnter(At(10), out _));

        Assert.False(budget.TryEnter(At(9, 30), out _));
    }

    [Theory]
    [InlineData(0, 60L)]
    [InlineData(-1, 60L)]
    [InlineData(1, 0L)]
    [InlineData(1, -1L)]
    public void Ctor_ANonPositiveBound_ThrowsInsteadOfSilentlyDisablingTheCeiling(int max, long seconds)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new IntervalBudget(max, TimeSpan.FromSeconds(seconds)));
    }
}
