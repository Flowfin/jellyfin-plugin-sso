// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.Threading.Tasks;
using Jellyfin.Plugin.SSO_Auth.Config;
using Jellyfin.Plugin.SSO_Auth.Tests;
using NSubstitute;

namespace Jellyfin.Plugin.SSO_Auth.Bench;

/// <summary>
/// What one account-link import costs at a realistic migration size (#1522). Nothing bounds how many
/// entries a document may carry except the one-mebibyte request-size limit, and a minimal entry is small,
/// so a single body holds on the order of ten thousand of them. The writes and the configuration persist
/// run inside the process-wide configuration lock - the lock every login waits on - so the number that
/// matters to an operator planning a migration is how long that lock is held, and nothing said what it was.
/// </summary>
/// <remarks>
/// It measures the endpoint, in process, through the same harness the login benchmark uses, so what is
/// timed is the real <c>ImportLinks</c> and not a re-implementation of it.
/// <para>
/// TWO BOUNDS, PRINTED ON EVERY RUN RATHER THAN LEFT FOR A READER TO INFER. The harness persists through a
/// mocked <c>IXmlSerializer</c>, so the host's own write to <c>SSO-Auth.xml</c> is not in these numbers and
/// every figure is a FLOOR. And the username resolution is deliberately outside the lock in
/// <c>ImportLinks</c>, so the harness resolves from a dictionary rather than a user database: the
/// per-username cost a real server pays there is real, and it is not lock-held time.
/// </para>
/// </remarks>
internal static class LinkImportCost
{
    // The sizes an operator actually plans for. The top of the range is roughly what the one-mebibyte
    // request-size limit admits, so it is the ceiling this endpoint has today rather than a round number.
    private static readonly int[] Sizes = { 100, 1000, 5000, 10000 };

    private const string Provider = "bench-idp";

    internal static async Task<int> RunAsync(int iterations, int warmup)
    {
        Console.WriteLine("SSO-Auth account-link import cost");
        Console.WriteLine(Setting("runtime", Environment.Version.ToString() + "  " + System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture));
        Console.WriteLine(Setting("iterations", iterations.ToString(CultureInfo.InvariantCulture) + " measured, " + warmup.ToString(CultureInfo.InvariantCulture) + " warmup discarded"));
        Console.WriteLine();
        Console.WriteLine("The host's own write to SSO-Auth.xml is NOT in these numbers - the harness persists");
        Console.WriteLine("through a mocked serializer - so every figure is a floor. The username resolution is");
        Console.WriteLine("outside the configuration lock in ImportLinks and is not lock-held time.");
        Console.WriteLine();
        Console.WriteLine(LatencySamples.Header());

        foreach (var size in Sizes)
        {
            var samples = new LatencySamples();
            for (var i = 0; i < warmup + iterations; i++)
            {
                // A fresh target per iteration. An import onto a configuration that already holds the
                // links writes the same keys again, which is a different and cheaper shape than the
                // restore this measures - and it is the restore an operator runs once, onto an empty
                // target, that decides how long the lock is held.
                var harness = Harness();
                var document = Document(size);

                var started = Stopwatch.GetTimestamp();
                await harness.Controller.ImportLinks(document).ConfigureAwait(false);
                var elapsed = Stopwatch.GetTimestamp() - started;

                if (i >= warmup)
                {
                    samples.Add(elapsed);
                }
            }

            Console.WriteLine(samples.Row("import", size.ToString(CultureInfo.InvariantCulture) + " entries"));
        }

        return 0;
    }

    // One provider holding every link, which is the shape a migration off one identity provider has.
    // Spreading the entries over several providers would move work into the grouping and out of the two
    // maps the writes go through, and it is not the case an operator plans for.
    private static SsoControllerHarness Harness()
    {
        var harness = new SsoControllerHarness(configuration =>
            configuration.OidConfigs[Provider] = new OidConfig { Enabled = true });

        // ONE configured call answering every username, and the shape is load-bearing rather than
        // tidy. Configuring one return per username makes the substitute match an invocation against a
        // list that grows with the size, so the harness itself becomes quadratic and the numbers it
        // prints are its own. Measured on the way to this line: a ten-thousand-entry run read 1871 ms at
        // p50 with per-username returns, against 40 ms with this one - the difference is the mock.
        harness.UserManager.GetUserByName(Arg.Any<string>()).Returns(call =>
        {
            var name = (string)call[0]!;
            return TestUsers.Named(name, UserId(int.Parse(name[UsernamePrefix.Length..], CultureInfo.InvariantCulture)));
        });

        return harness;
    }

    private static LinkExportDocument Document(int size)
    {
        var links = new Collection<LinkExportEntry>();
        for (var i = 0; i < size; i++)
        {
            links.Add(new LinkExportEntry
            {
                // The literal rather than LinkExport.OpenIdProtocol: that class is internal to the
                // plugin and this project is not one of its two friends. The protocol name is part of
                // the document format an operator posts, so it is stable in the same way the field
                // names around it are.
                Protocol = "OpenID",
                Provider = Provider,
                CanonicalName = "sub-" + i.ToString(CultureInfo.InvariantCulture),
                Username = Username(i),

                // Carried, because a document taken from a server running any build since #186 carries it
                // and it is a second map write per entry. A document without it would measure the cheaper
                // half of the population.
                Issuer = "https://bench-idp.example.com",
            });
        }

        return new LinkExportDocument { FormatVersion = 1, Links = links };
    }

    private const string UsernamePrefix = "bench-user-";

    private static string Username(int index) => UsernamePrefix + index.ToString(CultureInfo.InvariantCulture);

    // Deterministic and distinct: the import refuses a document mapping one identity to two accounts, and
    // a fixture that reused an id would be measuring the refusal path instead of the write.
    private static Guid UserId(int index) =>
        new Guid(0x7a19e700, 0, 0, 0, 0, 0, 0, 0, (byte)(index >> 16), (byte)(index >> 8), (byte)index);

    private static string Setting(string name, string value) =>
        string.Create(CultureInfo.InvariantCulture, $"{name,-13}{value}");
}
