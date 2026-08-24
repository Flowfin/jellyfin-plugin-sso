// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Reflection;
using Jellyfin.Plugin.SSO_Auth.Api.Metrics;
using Jellyfin.Plugin.SSO_Auth.Api.Session;
using Jellyfin.Plugin.SSO_Auth.Api.Shared;
using Jellyfin.Plugin.SSO_Auth.Config;
using MediaBrowser.Controller.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// In-process tests of the auth-path counters and the exposition they are served as (#1139), through
/// <see cref="SsoControllerHarness"/> so the endpoint reads the real store rather than a stand-in.
/// </summary>
/// <remarks>
/// <para>
/// What is pinned here is what an operator's alerting rests on and what a disclosure review rests on: the
/// counters move when the thing they name happens, no label carries an identity, the label vocabularies are
/// the closed ones, the series count is bounded, and the exposition parses.
/// </para>
/// <para>
/// The counters are process-wide statics, so every test starts by clearing them. That is also why this class
/// is in the non-parallel controller collection: a login driven by a sibling test running at the same time
/// would land in this one's assertion.
/// </para>
/// </remarks>
[Collection("SSOController")]
public class SSOControllerMetricsTests
{
    private static string Exposition(SsoControllerHarness harness)
    {
        var result = Assert.IsType<ContentResult>(harness.Controller.Metrics());
        Assert.Equal(PrometheusExposition.ContentType, result.ContentType);
        Assert.Equal(StatusCodes.Status200OK, result.StatusCode);
        return result.Content!;
    }

    private static IReadOnlyList<string> Samples(string exposition) =>
        exposition.Split('\n')
            .Where(line => line.Length > 0 && !line.StartsWith('#'))
            .ToList();

    private static long Value(string exposition, string sample)
    {
        var line = Assert.Single(Samples(exposition), s => s.StartsWith(sample + " ", StringComparison.Ordinal));
        return long.Parse(line[(sample.Length + 1)..], CultureInfo.InvariantCulture);
    }

    private static SsoControllerHarness Harness()
    {
        SsoMetricsStore.ResetForTests();
        return new SsoControllerHarness();
    }

    // The same single-attempt budget the rate-limit response-shape tests use, so a throttle is one call away
    // and the counter under test is reached without a loop nobody would read.
    private static SsoControllerHarness Throttling(IPAddress clientIp)
    {
        SsoMetricsStore.ResetForTests();
        return new SsoControllerHarness(
            c =>
            {
                c.EnableRateLimit = true;
                c.RateLimitMaxAttempts = 1;
                c.RateLimitWindowSeconds = 60;
            },
            clientIp);
    }

    [Fact]
    public void AFreshProcess_StillServesAParseableExposition()
    {
        // The answer a server that has served no login gets, which is every server for its first minute. An
        // empty body or an error here would make a scraper report the target down rather than idle.
        var exposition = Exposition(Harness());

        Assert.Equal(0, Value(exposition, SsoMetrics.SeriesRefusedTotal));
        Assert.EndsWith("\n", exposition, StringComparison.Ordinal);
        Assert.All(Samples(exposition), line => Assert.Matches(@"^[a-z_]+(\{[a-z_]+=""[^""]*""\})? -?\d+$", line));
    }

    [Fact]
    public void EveryRefusalTheMapperRenders_IsCounted_UnderItsOwnReason()
    {
        // The ~14 rejection branches upstream all render through the mapper, so counting there is the claim
        // that no branch can be added later and go uncounted. Driven over the whole closed vocabulary rather
        // than one member, because a switch that counted only the reasons somebody remembered is the defect.
        var harness = Harness();

        foreach (var reason in Enum.GetValues<PublicReason>())
        {
            LoginStatusMapper.ToActionResult(new LoginOutcome.Rejected(reason));
        }

        var exposition = Exposition(harness);
        foreach (var reason in Enum.GetValues<PublicReason>())
        {
            Assert.Equal(1, Value(exposition, $"{SsoMetrics.LoginFailureTotal}{{reason=\"{reason}\"}}"));
        }
    }

    [Fact]
    public void ADeniedLogin_IsCountedApartFromAStatedReason()
    {
        var harness = Harness();

        LoginStatusMapper.ToActionResult(new LoginOutcome.Denied());

        Assert.Equal(1, Value(Exposition(harness), $"{SsoMetrics.LoginFailureTotal}{{reason=\"Denied\"}}"));
    }

    [Fact]
    public void ASuccessfulOutcomeReachingTheMapper_IsNotCountedAsALogin()
    {
        // Success is counted at the mint, which is the only place that knows a session was issued. Counting
        // it here too would double every login on the dashboard, and a doubled success rate is worse than no
        // success rate: it reads as healthy while it is wrong.
        var harness = Harness();

        LoginStatusMapper.ToActionResult(new LoginOutcome.Success(new AuthenticationResult()));

        Assert.DoesNotContain(SsoMetrics.LoginSuccessTotal, Exposition(harness), StringComparison.Ordinal);
    }

    [Fact]
    public void AThrottledRequest_IsCountedUnderItsEndpointClass()
    {
        // A dedicated public address per test, because the limiter is one process-wide instance and a
        // sibling test spending the same bucket would decide this one's answer.
        var harness = Throttling(IPAddress.Parse("8.8.4.1"));

        var response = new DefaultHttpContext().Response;
        var client = IPAddress.Parse("8.8.4.1");
        Assert.Null(SsoRateLimitGate.Check(SsoRateLimitClass.Challenge, client, harness.ControllerLog, response));
        Assert.NotNull(SsoRateLimitGate.Check(SsoRateLimitClass.Challenge, client, harness.ControllerLog, response));

        Assert.Equal(
            1,
            Value(Exposition(harness), $"{SsoMetrics.RequestThrottledTotal}{{class=\"{SsoRateLimitClass.Challenge}\"}}"));
    }

    [Fact]
    public void EveryThrottleClassLabel_IsOneOfTheNamedConstants()
    {
        // The one string label on the surface, so it gets the check the enum labels get for free. Driven over
        // the whole constant set: a class the gate could emit that is not in this vocabulary would be a label
        // value nobody declared, which is where unbounded cardinality starts.
        var harness = Throttling(IPAddress.Parse("8.8.5.1"));

        var declared = typeof(SsoRateLimitClass)
            .GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)
            .Where(f => f.IsLiteral)
            .Select(f => (string)f.GetRawConstantValue()!)
            .ToHashSet(StringComparer.Ordinal);

        var response = new DefaultHttpContext().Response;
        var octet = 1;
        foreach (var endpointClass in declared)
        {
            // A fresh client per class so each one is throttled by its own second attempt rather than by a
            // budget an earlier class already spent.
            var client = IPAddress.Parse("8.8.5." + octet.ToString(CultureInfo.InvariantCulture));
            octet++;
            SsoRateLimitGate.Check(endpointClass, client, harness.ControllerLog, response);
            SsoRateLimitGate.Check(endpointClass, client, harness.ControllerLog, response);
        }

        var emitted = Samples(Exposition(harness))
            .Where(line => line.StartsWith(SsoMetrics.RequestThrottledTotal + "{", StringComparison.Ordinal))
            .Select(line => line.Split('"')[1])
            .ToHashSet(StringComparer.Ordinal);

        Assert.Equal(declared, emitted);
    }

    [Fact]
    public void NoLabelCarriesAUsernameASubjectOrAClaimValue()
    {
        // The disclosure claim, asserted over the whole rendered body rather than per call site: a counter
        // added later that passed an identity would land in this exposition and redden here.
        var harness = Harness();

        SsoMetrics.LoginSucceeded("keycloak");
        SsoMetrics.LoginFailed(PublicReason.EmailNotVerified);
        SsoMetrics.AccountProvisioned(ProvisioningOutcome.Created);
        SsoMetrics.ProviderFetchFailed(ProviderFetchStage.Discovery);

        var exposition = Exposition(harness);

        Assert.Contains("keycloak", exposition, StringComparison.Ordinal);
        foreach (var forbidden in new[] { "@", "sub=", "ssoenc:", "alice", "S-1-5-", "urn:" })
        {
            Assert.DoesNotContain(forbidden, exposition, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void TheSeriesCountIsCapped_AndTheRefusalIsPublishedRatherThanSilent()
    {
        // A metrics surface with an unbounded label vocabulary is a memory amplifier, and the shape that
        // matters is not only that it stops growing: a scrape that dropped a breakdown has to SAY so on the
        // same scrape, or the gap is indistinguishable from nothing having happened.
        var harness = Harness();

        for (var i = 0; i < SsoMetricsStore.MaxSeries + 25; i++)
        {
            SsoMetrics.LoginSucceeded("provider-" + i.ToString(CultureInfo.InvariantCulture));
        }

        var exposition = Exposition(harness);
        var series = Samples(exposition).Count(line => line.StartsWith(SsoMetrics.LoginSuccessTotal, StringComparison.Ordinal));

        Assert.Equal(SsoMetricsStore.MaxSeries, series);
        Assert.Equal(25, Value(exposition, SsoMetrics.SeriesRefusedTotal));
    }

    [Fact]
    public void AKnownSeriesKeepsCounting_AfterTheCapIsReached()
    {
        // The half that decides whether the cap is safe. If reaching it silenced the counters an operator is
        // already alerting on, a burst of junk labels would take the alerting down - which is worse than the
        // memory the cap exists to protect.
        var harness = Harness();
        SsoMetrics.LoginSucceeded("keycloak");

        for (var i = 0; i < SsoMetricsStore.MaxSeries + 10; i++)
        {
            SsoMetrics.LoginSucceeded("junk-" + i.ToString(CultureInfo.InvariantCulture));
        }

        SsoMetrics.LoginSucceeded("keycloak");

        Assert.Equal(2, Value(Exposition(harness), $"{SsoMetrics.LoginSuccessTotal}{{provider=\"keycloak\"}}"));
    }

    [Fact]
    public void ALabelValueCannotForgeALine()
    {
        // Every value the plugin passes today is an enum name or a validated provider name, so this is the
        // escape being a property of the renderer rather than of every current call site. A quote or a
        // newline reaching a scrape unescaped would let one series be read as several.
        var harness = Harness();

        SsoMetrics.LoginSucceeded("ev\"il\nsso_login_success_total{provider=\"forged\"} 99");

        var exposition = Exposition(harness);
        Assert.Equal(1, Samples(exposition).Count(line => line.StartsWith(SsoMetrics.LoginSuccessTotal, StringComparison.Ordinal)));
        Assert.DoesNotContain("forged\"} 99", exposition, StringComparison.Ordinal);
    }

    [Fact]
    public void EveryCounterCarriesAHelpAndATypeLine()
    {
        var harness = Harness();
        SsoMetrics.LoginSucceeded("keycloak");
        SsoMetrics.LoginFailed(PublicReason.InvalidState);

        var exposition = Exposition(harness);

        foreach (var metric in new[] { SsoMetrics.LoginSuccessTotal, SsoMetrics.LoginFailureTotal, SsoMetrics.SeriesRefusedTotal })
        {
            Assert.Contains($"# HELP {metric} ", exposition, StringComparison.Ordinal);
            Assert.Contains($"# TYPE {metric} counter", exposition, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void TwoScrapesOfOneStateRenderIdentically()
    {
        // A dictionary promises no order. An exposition whose lines moved between scrapes would make a diff
        // of two scrapes unreadable, which is the first thing anybody does with one.
        var harness = Harness();
        foreach (var name in new[] { "zulu", "alpha", "mike" })
        {
            SsoMetrics.LoginSucceeded(name);
        }

        Assert.Equal(Exposition(harness), Exposition(harness));
    }

    [Fact]
    public void TheProvisioningCounter_TellsAdoptionApartFromCreation()
    {
        var harness = Harness();

        SsoMetrics.AccountProvisioned(ProvisioningOutcome.Adopted);
        SsoMetrics.AccountProvisioned(ProvisioningOutcome.Created);
        SsoMetrics.AccountProvisioned(ProvisioningOutcome.Created);

        var exposition = Exposition(harness);
        Assert.Equal(1, Value(exposition, $"{SsoMetrics.AccountProvisionedTotal}{{outcome=\"Adopted\"}}"));
        Assert.Equal(2, Value(exposition, $"{SsoMetrics.AccountProvisionedTotal}{{outcome=\"Created\"}}"));
    }

    [Fact]
    public void TheFetchCounter_TellsDiscoveryApartFromTheTokenExchange()
    {
        var harness = Harness();

        SsoMetrics.ProviderFetchFailed(ProviderFetchStage.Discovery);
        SsoMetrics.ProviderFetchFailed(ProviderFetchStage.Token);

        var exposition = Exposition(harness);
        Assert.Equal(1, Value(exposition, $"{SsoMetrics.ProviderFetchErrorTotal}{{stage=\"Discovery\"}}"));
        Assert.Equal(1, Value(exposition, $"{SsoMetrics.ProviderFetchErrorTotal}{{stage=\"Token\"}}"));
    }

    [Fact]
    public void AProviderWithNoName_IsRenderedAsANamedSeries_NotAsABlankLabel()
    {
        var harness = Harness();

        SsoMetrics.LoginSucceeded(null);
        SsoMetrics.LoginSucceeded("   ");

        Assert.Equal(2, Value(Exposition(harness), $"{SsoMetrics.LoginSuccessTotal}{{provider=\"unnamed\"}}"));
    }
}
