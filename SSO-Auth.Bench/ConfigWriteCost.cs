// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Diagnostics;
using System.Globalization;
using Jellyfin.Plugin.SSO_Auth.Config;
using Jellyfin.Plugin.SSO_Auth.Tests;

namespace Jellyfin.Plugin.SSO_Auth.Bench;

/// <summary>
/// What the undo behind a configuration write costs, against the write it is paid on (#1532). Since #1521
/// every write takes a persisted-form snapshot of the whole configuration before the mutation, so a persist
/// that throws can be rolled back out of the running server. It is paid inside the process-wide
/// configuration lock, on top of the serialization the write itself does, and it is paid by writes on the
/// LOGIN path - the canonical link a first login writes, the hourly last-login stamp, the single-logout
/// session capture - not only by an administrator saving a form.
/// </summary>
/// <remarks>
/// Two stages per size, on one fixture, in one run:
/// <list type="bullet">
/// <item><c>snapshot</c> - <c>PluginConfiguration.ToPersistedForm()</c>, which is exactly what
/// <c>ProviderConfigStore.Snapshot</c> calls and the whole of the undo's cost.</item>
/// <item><c>write</c> - the production path, <c>SSOPlugin.MutateConfiguration</c>, snapshot included.</item>
/// </list>
/// THE NO-SNAPSHOT BASELINE IS THE DIFFERENCE, AND THAT IS A READING OF THE SOURCE RATHER THAN AN
/// ESTIMATE. <c>ProviderConfigStore.Mutate</c> calls <c>Snapshot</c> once, at the top, and nothing else in
/// that method depends on the result except the rollback on the failure path. So removing the undo removes
/// exactly the first row from the second, and no third measurement would say more than that subtraction
/// does. There is deliberately no switch in production that turns the undo off for a benchmark to read.
/// <para>
/// The persist behind the write row is the real one - the plugin's own, through a mocked serializer - so
/// the host's write to <c>SSO-Auth.xml</c> is outside every figure and each of them is a floor.
/// </para>
/// </remarks>
internal static class ConfigWriteCost
{
    // Link counts spanning a small installation to a large one. The top of the range is where the
    // persisted-form string is far past the large-object-heap threshold, so it is one LOH allocation per
    // write - which is the shape of the concern rather than the milliseconds alone.
    private static readonly int[] Sizes = { 0, 100, 1000, 5000 };

    private const string Provider = "bench-idp";
    private const string Issuer = "https://bench-idp.example.com";

    internal static int Run(int iterations, int warmup)
    {
        Console.WriteLine("SSO-Auth configuration-write cost");
        Console.WriteLine(Setting("runtime", Environment.Version.ToString() + "  " + System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture));
        Console.WriteLine(Setting("iterations", iterations.ToString(CultureInfo.InvariantCulture) + " measured, " + warmup.ToString(CultureInfo.InvariantCulture) + " warmup discarded"));
        Console.WriteLine();
        Console.WriteLine("The host's own write to SSO-Auth.xml is NOT in these numbers - the harness persists");
        Console.WriteLine("through a mocked serializer - so every figure is a floor. The no-snapshot baseline is");
        Console.WriteLine("write minus snapshot: Mutate calls Snapshot once and nothing else reads it.");
        Console.WriteLine();
        Console.WriteLine(LatencySamples.Header());

        foreach (var size in Sizes)
        {
            var label = size.ToString(CultureInfo.InvariantCulture) + " links";
            Console.WriteLine(Measure(size, warmup, iterations, snapshotOnly: true).Row("snapshot", label));
            Console.WriteLine(Measure(size, warmup, iterations, snapshotOnly: false).Row("write", label));
        }

        return 0;
    }

    private static LatencySamples Measure(int size, int warmup, int iterations, bool snapshotOnly)
    {
        var samples = new LatencySamples();

        // One harness for the whole stage. The plugin it builds is the process-wide singleton, so a fresh
        // one per iteration would be measuring construction; the mutation below is idempotent, so
        // repeating it against one configuration measures the write rather than a growing table.
        var harness = new SsoControllerHarness(configuration => Seed(configuration, size));
        var live = harness.Configuration;

        for (var i = 0; i < warmup + iterations; i++)
        {
            var started = Stopwatch.GetTimestamp();
            if (snapshotOnly)
            {
                _ = live.ToPersistedForm();
            }
            else
            {
                SSOPlugin.Instance.MutateConfiguration(Touch);
            }

            var elapsed = Stopwatch.GetTimestamp() - started;
            if (i >= warmup)
            {
                samples.Add(elapsed);
            }
        }

        return samples;
    }

    // The smallest real write there is: one boolean nothing in the loop reads back. Anything larger would
    // put the mutation's own cost into a measurement about the write around it.
    private static void Touch(PluginConfiguration configuration) =>
        configuration.EnableSingleLogout = !configuration.EnableSingleLogout;

    // One OpenID provider carrying `size` links, each with an issuer stamp (#186) and a last-login stamp
    // (#1120) - the shape a server that has been running a while actually has, and the shape whose
    // serialization the undo pays for.
    private static void Seed(PluginConfiguration configuration, int size)
    {
        var provider = new OidConfig { Enabled = true, OidEndpoint = Issuer, OidClientId = "bench" };
        for (var i = 0; i < size; i++)
        {
            var canonical = "sub-" + i.ToString(CultureInfo.InvariantCulture);
            provider.CanonicalLinks[canonical] = UserId(i);
            provider.CanonicalLinkIssuers[canonical] = Issuer;
            provider.CanonicalLinkLastLogins[canonical] = DateTime.UtcNow;
        }

        configuration.OidConfigs[Provider] = provider;
    }

    private static Guid UserId(int index) =>
        new Guid(0x7a19e700, 0, 0, 0, 0, 0, 0, 0, (byte)(index >> 16), (byte)(index >> 8), (byte)index);

    private static string Setting(string name, string value) =>
        string.Create(CultureInfo.InvariantCulture, $"{name,-13}{value}");
}
