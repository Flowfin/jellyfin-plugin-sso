// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Tests;

namespace Jellyfin.Plugin.SSO_Auth.Bench;

/// <summary>
/// Entry point for the OpenID login-latency characterization (#1117): a serial scenario for the latency a
/// single user waits through, and a concurrent one for what that becomes under N callers at once. It
/// prints a distribution and returns a non-zero exit code only when a round-trip failed to be a login -
/// there is deliberately no latency threshold here, because a number that fails a build has to be a
/// number the build machine can reproduce, and this measures whatever box it runs on.
/// </summary>
internal static class Program
{
    private const string Authority = "https://bench-idp.example.com";
    private const string ClientId = "jellyfin-bench";

    private const int DefaultIterations = 500;
    private const int DefaultWarmup = 50;
    private const int DefaultConcurrency = 8;

    // Their own defaults, and small on purpose: one ten-thousand-entry import already builds ten thousand
    // mocked accounts and writes twenty thousand map entries, so five hundred of them would measure the
    // patience of whoever started the run rather than the endpoint.
    private const int DefaultLinkImportIterations = 20;
    private const int DefaultLinkImportWarmup = 3;

    private static async Task<int> Main(string[] args)
    {
        int iterations = DefaultIterations, warmup = DefaultWarmup, concurrency = DefaultConcurrency;
        var linkImport = false;
        bool iterationsGiven = false, warmupGiven = false;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--iterations": iterations = Number(args, ++i); iterationsGiven = true; break;
                case "--warmup": warmup = Number(args, ++i); warmupGiven = true; break;
                case "--concurrency": concurrency = Number(args, ++i); break;
                case "--link-import": linkImport = true; break;
                case "--help" or "-h": Usage(); return 0;
                default:
                    Console.Error.WriteLine("Unknown argument: " + args[i]);
                    Usage();
                    return 2;
            }
        }

        if (iterations < 1 || warmup < 0 || concurrency < 1)
        {
            Console.Error.WriteLine("--iterations and --concurrency must be at least 1, --warmup at least 0.");
            return 2;
        }

        // The second scenario is a separate run rather than a section of this one (#1522). It measures a
        // different subject - how long one bulk admin write holds the configuration lock - and its own
        // defaults are two orders of magnitude smaller, because a ten-thousand-entry import is not a
        // thing to do five hundred times. Behind a flag, so the invocation the perf workflow makes is
        // byte-for-byte the run it has always made.
        if (linkImport)
        {
            return await LinkImportCost.RunAsync(
                iterationsGiven ? iterations : DefaultLinkImportIterations,
                warmupGiven ? warmup : DefaultLinkImportWarmup).ConfigureAwait(false);
        }

        using var idp = new OidcTokenFixture(Authority, ClientId);
        // Re-minted before each scenario rather than once for the run: the fixture's id_token is valid for
        // five minutes, and a token that expired mid-run would turn measured logins into measured
        // rejections. RunAsync refuses a rejection, so this is belt as well as braces.
        var idToken = idp.IdToken("bench-subject", "bench-user");
        string Current() => idToken;

        Console.WriteLine("SSO-Auth OpenID login-latency benchmark");
        Console.WriteLine(Setting("runtime", Environment.Version.ToString() + "  " + System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture));
        Console.WriteLine(Setting("iterations", iterations.ToString(CultureInfo.InvariantCulture) + " measured, " + warmup.ToString(CultureInfo.InvariantCulture) + " warmup discarded"));
        Console.WriteLine(Setting("concurrency", concurrency.ToString(CultureInfo.InvariantCulture) + " caller(s) in the concurrent scenario"));
        Console.WriteLine();

        var nominal = new[] { new LatencySamples(), new LatencySamples() };
        var concurrent = new[] { new LatencySamples(), new LatencySamples() };

        idToken = idp.IdToken("bench-subject", "bench-user");
        var serial = new LoginRoundTrip(idp, Current);
        await Drive(serial, warmup, null).ConfigureAwait(false);
        await Drive(serial, iterations, nominal).ConfigureAwait(false);

        // Every caller is constructed before any of them runs: the harness constructor swaps the
        // process-wide SSOPlugin.Instance and clears the OpenID state cache, so constructing one while
        // another is mid-login would pull the state out from under it.
        var callers = new List<LoginRoundTrip>(concurrency);
        for (var i = 0; i < concurrency; i++)
        {
            callers.Add(new LoginRoundTrip(idp, Current));
        }

        idToken = idp.IdToken("bench-subject", "bench-user");
        var perCaller = (iterations + concurrency - 1) / concurrency;
        await Task.WhenAll(callers.ConvertAll(c => Drive(c, warmup, null))).ConfigureAwait(false);

        var samples = new List<LatencySamples[]>(concurrency);
        for (var i = 0; i < concurrency; i++)
        {
            samples.Add(new[] { new LatencySamples(), new LatencySamples() });
        }

        var wallClock = Stopwatch.StartNew();
        var runs = new List<Task>(concurrency);
        for (var i = 0; i < concurrency; i++)
        {
            runs.Add(Drive(callers[i], perCaller, samples[i]));
        }

        await Task.WhenAll(runs).ConfigureAwait(false);
        wallClock.Stop();

        foreach (var pair in samples)
        {
            concurrent[0].AddRange(pair[0]);
            concurrent[1].AddRange(pair[1]);
        }

        Console.WriteLine(LatencySamples.Header());
        Console.WriteLine(nominal[0].Row("nominal", "challenge"));
        Console.WriteLine(nominal[1].Row("nominal", "callback"));
        Console.WriteLine(concurrent[0].Row("concurrent", "challenge"));
        Console.WriteLine(concurrent[1].Row("concurrent", "callback"));
        Console.WriteLine();

        var roundTrips = perCaller * concurrency;
        Console.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"concurrent throughput  {roundTrips / wallClock.Elapsed.TotalSeconds,10:F1} round-trips/s ({roundTrips} round-trips over {wallClock.Elapsed.TotalSeconds:F3} s wall clock)"));
        return 0;
    }

    /// <summary>
    /// Runs one caller for the given number of round-trips, recording into <paramref name="into"/> or
    /// discarding when it is null (the warmup pass, which pays for JIT and the first configuration read).
    /// </summary>
    private static async Task Drive(LoginRoundTrip caller, int rounds, LatencySamples[]? into)
    {
        for (var i = 0; i < rounds; i++)
        {
            var (challenge, callback) = await caller.RunAsync().ConfigureAwait(false);
            if (into is not null)
            {
                into[0].Add(challenge);
                into[1].Add(callback);
            }
        }
    }

    private static int Number(string[] args, int index)
    {
        if (index >= args.Length || !int.TryParse(args[index], NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
        {
            throw new ArgumentException("Expected a number after " + args[index - 1], nameof(args));
        }

        return value;
    }

    private static string Setting(string name, string value) =>
        string.Create(CultureInfo.InvariantCulture, $"{name,-13}{value}");

    private static void Usage()
    {
        Console.WriteLine("Usage: dotnet run --project SSO-Auth.Bench -c Release -- [options]");
        Console.WriteLine("  --iterations N   measured round-trips per scenario (default " + DefaultIterations.ToString(CultureInfo.InvariantCulture) + ")");
        Console.WriteLine("  --warmup N       discarded round-trips per caller before measuring (default " + DefaultWarmup.ToString(CultureInfo.InvariantCulture) + ")");
        Console.WriteLine("  --concurrency N  concurrent callers in the second scenario (default " + DefaultConcurrency.ToString(CultureInfo.InvariantCulture) + ")");
        Console.WriteLine("  --link-import    measure the account-link import instead (#1522); --iterations defaults to " + DefaultLinkImportIterations.ToString(CultureInfo.InvariantCulture) + ", --warmup to " + DefaultLinkImportWarmup.ToString(CultureInfo.InvariantCulture));
    }
}
