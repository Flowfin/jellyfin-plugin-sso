// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>Binds the repeated-member screen to the transport rather than to a call site (#1067).</summary>
/// <remarks>
/// Assigning <c>ProviderInformation</c> before the client is constructed is what sets the internal
/// use-discovery flag to false; a client built without it fetches discovery and the JWKS through a factory
/// the screen is not on, and the same flag disables the JWKS-refresh retry behind it. The screen stays where
/// it is and every construction site pre-assigns, rather than moving the screen onto that factory, which
/// also carries the token and UserInfo legs and is an open scope question (#1069). The behavioural half is
/// <c>OidcRoundTripTests.TheCallbackLegFetchesNoDiscoveryOfItsOwn</c>.
/// </remarks>
public class CallbackClientMetadataTests
{
    [Fact]
    public void EveryOidcClientInTheFlowTierIsBuiltWithItsMetadataAlready()
    {
        var flowTier = Path.Combine(RepoTree.Root, "SSO-Auth", "Api", "Flows");

        // Sentinel first. A scan over a folder that is not there reports the same all-clear as a scan that
        // found two correct sites, and a moved repository root is how that happens.
        Assert.True(Directory.Exists(flowTier), "the flow tier is not where this rule looks for it");

        var sites = 0;
        foreach (var file in Directory.EnumerateFiles(flowTier, "*.cs", SearchOption.AllDirectories))
        {
            var lines = File.ReadAllLines(file);
            for (var i = 0; i < lines.Length; i++)
            {
                if (!IsConstructionSite(lines[i]))
                {
                    continue;
                }

                sites++;
                Assert.True(
                    PreAssignsAt(lines, i),
                    $"{Path.GetFileName(file)}:{i + 1} builds an OidcClient with no unconditional ProviderInformation assignment before it, so the library keeps discovery enabled and fetches the discovery document and the JWKS off the screened path");
            }
        }

        Assert.True(sites >= 2, $"the scan found {sites} OidcClient construction sites; it expects the challenge leg and the callback leg at least");
    }

    [Fact]
    public void TheRuleRefusesAConditionalAssignment()
    {
        // The must-catch / adjacent-must-not-catch pair for the rule's own predicate, in the shape the
        // callback leg actually had. A rule with no red fixture is decorative, and a text scan is the kind
        // most easily written so that nothing can fail it.
        var conditional = new[]
        {
            "    private OidcClient Build()",
            "    {",
            "        var options = new OidcClientOptions();",
            "        if (providerInformation is not null)",
            "        {",
            "            options.ProviderInformation = providerInformation;",
            "        }",
            "",
            "        return new OidcClient(options);",
            "    }",
        };

        var unconditional = new[]
        {
            "    private OidcClient Build()",
            "    {",
            "        var options = new OidcClientOptions();",
            "        options.ProviderInformation = providerInformation;",
            "",
            "        return new OidcClient(options);",
            "    }",
        };

        // A neighbour's assignment must not be borrowed across a method boundary, which is the other way a
        // scan like this passes on code it should refuse.
        var borrowed = new[]
        {
            "    private void Other()",
            "    {",
            "        options.ProviderInformation = providerInformation;",
            "    }",
            "",
            "    private OidcClient Build()",
            "    {",
            "        return new OidcClient(new OidcClientOptions());",
            "    }",
        };

        Assert.False(PreAssignsAt(conditional, IndexOfSite(conditional)), "the rule accepts the conditional shape it was written to refuse");
        Assert.True(PreAssignsAt(unconditional, IndexOfSite(unconditional)), "the rule refuses the shape the flow tier ships, so it would fail on correct code");
        Assert.False(PreAssignsAt(borrowed, IndexOfSite(borrowed)), "the rule borrows an assignment from the method next door");
    }

    // The rule's predicate. The assignment must stand at method-body indentation: eight spaces is the only
    // depth at which it is unconditional, because a statement inside a braced `if` sits at twelve and
    // StyleCop requires the braces. The indentation IS the conditionality test.
    private static bool PreAssignsAt(IReadOnlyList<string> lines, int siteIndex)
    {
        for (var back = siteIndex - 1; back >= 0 && back > siteIndex - 40; back--)
        {
            if (lines[back].StartsWith("        options.ProviderInformation = ", StringComparison.Ordinal))
            {
                return true;
            }

            // A method boundary ends the search before it can borrow a neighbour's assignment.
            if (lines[back].StartsWith("    }", StringComparison.Ordinal))
            {
                return false;
            }
        }

        return false;
    }

    // A construction, not a sentence about one. The comment above CreateCallbackOidcClient explains why the
    // assignment has to precede `new OidcClient(options)`, and the first version of this rule read that
    // sentence as a site and failed on it. Prose is where a text scan goes wrong first.
    private static bool IsConstructionSite(string line) =>
        line.Contains("new OidcClient(", StringComparison.Ordinal)
        && !line.TrimStart().StartsWith("//", StringComparison.Ordinal);

    private static int IndexOfSite(IReadOnlyList<string> lines)
    {
        for (var i = 0; i < lines.Count; i++)
        {
            if (IsConstructionSite(lines[i]))
            {
                return i;
            }
        }

        Assert.Fail("the fixture carries no OidcClient construction site, so it tests nothing");
        return -1;
    }
}
