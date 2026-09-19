// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <content>
/// Conformance rules for what a refused authorization request tells the administrator (#1610, #1763).
/// </content>
public partial class ArchitectureConformanceTests
{
    private const string ChallengeRefusalFlow = "OidcLoginService.cs";

    [Fact]
    public void TheChallengeRefusalNamesTheRedirectUriItSent()
    {
        // The provider's answer to a redirect URI it does not have registered is a bare code and a message
        // that names nothing: `invalid_request - Failed to push authorization parameters` is the whole of
        // it. With pushed authorization on, that exchange is server to server, so the administrator never
        // reaches the provider's own error page, which is the only place the URL would otherwise appear.
        //
        // Measured, on a live Pocket ID 2.14.0 reproducing #1608: the provider logged
        // `fosite.MatchRedirectURIWithClientRedirectURIs` on its side and returned nothing but the code on
        // ours, and the difference between the two URIs was one scheme. Registering the right callback
        // turned the same login into 201 from the push and 302 from the plugin.
        //
        // A source rule rather than a behaviour test on purpose. Reaching this branch needs a provider whose
        // discovery succeeds and whose authorize preparation then fails, which is a fake identity provider
        // stood up for one log line. What the rule protects is the property that costs when it is absent -
        // the string being in the message - and that is visible in the text.
        var line = ChallengeRefusalArm("OidcChallengeCause.RedirectUri");

        Assert.True(
            line.Contains("The redirect URI sent was", StringComparison.Ordinal)
            && line.Contains("{RedirectUri}", StringComparison.Ordinal),
            "The refused-challenge line names the redirect URI it sent (#1610), because the provider's own "
            + "answer names nothing and the administrator cannot reach the page that would. This arm does "
            + "not: " + line.Trim());

        Assert.True(
            line.Contains("redirectUri?.ReplaceLineEndings(string.Empty).Replace(", StringComparison.Ordinal),
            "The redirect URI is composed from the request's host header, so it carries both sanitizers "
            + "inline at the call like every other foreign value this tree logs (#1557). This arm does "
            + "not: " + line.Trim());
    }

    [Fact]
    public void EachChallengeRefusalArmSaysWhatItsOwnCauseIs()
    {
        // #1763. The sentence above was written for one refusal and was emitted for every one of them. At
        // the pushed-authorization endpoint a 401 is the client being refused, and a reporter who had
        // already confirmed the redirect URI was sent back to check it (#1762).
        //
        // WHICH ANSWER REACHES WHICH ARM is a behaviour test, on OidcChallengeRefusal.Classify. WHICH
        // SENTENCE AN ARM CARRIES is only in the text, and it is what this rule holds - per arm, keyed on
        // the case label, so exchanging two bodies is refused rather than passing because the sentences are
        // all still somewhere in the file.
        var uri = ChallengeRefusalArm("OidcChallengeCause.RedirectUri");
        var client = ChallengeRefusalArm("OidcChallengeCause.ClientAuthentication");
        var neither = ChallengeRefusalArm("default");

        Assert.True(
            client.Contains("refusal of the client rather than of the request", StringComparison.Ordinal)
            && client.Contains("client secret", StringComparison.Ordinal)
            && client.Contains("client ID", StringComparison.Ordinal),
            "The arm for a refused client says so and names the client ID and secret (#1763). It does not: "
            + client.Trim());

        foreach (var (label, arm) in new[] { ("ClientAuthentication", client), ("default", neither) })
        {
            Assert.True(
                !arm.Contains("{RedirectUri}", StringComparison.Ordinal)
                && !arm.Contains("The redirect URI sent was", StringComparison.Ordinal),
                "Only the arm for the one measured redirect-URI code asserts the redirect URI as the thing "
                + "to check (#1763); the " + label + " arm answers something that says nothing about it, "
                + "and it does: " + arm.Trim());
        }

        // The third sentence is the one that must not guess. An HTTP reason phrase, a provider's code and a
        // transport failure all arrive in the same field, so a line that named a cause here would be naming
        // one the answer does not carry - and one that called the answer meaningless would be wrong in the
        // other direction, for the refusals where that field does hold the provider's own code.
        Assert.True(
            neither.Contains("does not interpret that answer", StringComparison.Ordinal),
            "The arm for an answer this line cannot read says that it does not read it, rather than "
            + "borrowing a neighbour's instruction or calling the answer empty (#1763). It does not: "
            + neither.Trim());

        Assert.True(
            !uri.Contains("client secret", StringComparison.Ordinal)
            && !neither.Contains("client secret", StringComparison.Ordinal),
            "Only the client arm sends the administrator to the client secret (#1763).");
    }

    [Fact]
    public void TheChallengeRefusalClassifiesTheProvidersAnswerAndNotItsNeighbour()
    {
        // The field beside it is a constant. `AuthorizeState.ErrorDescription` is overwritten by the
        // identity library with the literal "Failed to push authorization parameters" before the plugin
        // sees it, in both pinned versions, so a switch fed that field instead would classify every refusal
        // identically and emit one sentence forever - with every behaviour test on OidcChallengeRefusal
        // still green, because those call it directly.
        //
        // That is why this rule reads the ARGUMENT rather than the presence of the call.
        var source = File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Api", "Flows", ChallengeRefusalFlow));

        var calls = SourceLines(source)
            .Where(candidate => candidate.Contains("OidcChallengeRefusal.Classify(", StringComparison.Ordinal))
            .Select(candidate => candidate.Trim())
            .ToList();

        Assert.True(
            calls.Count == 1,
            "The refusal classifies the provider's answer once, where it branches (#1763). Found "
            + calls.Count.ToString(System.Globalization.CultureInfo.InvariantCulture) + ": "
            + string.Join(" | ", calls));

        Assert.True(
            calls[0].Contains("OidcChallengeRefusal.Classify(state.Error)", StringComparison.Ordinal),
            "The classification reads state.Error, which is the only field of the refusal that varies: the "
            + "identity library replaces state.ErrorDescription with one constant before the plugin sees it "
            + "(#1763). This call does not: " + calls[0]);
    }

    /// <summary>
    /// The refused-challenge logging call of one arm of the cause switch in the OpenID login flow, named by
    /// the case label above it. Keying on the label is the point: a rule that only counted sentences across
    /// the whole switch would pass a change that exchanged two bodies.
    /// </summary>
    private static string ChallengeRefusalArm(string label)
    {
        var arms = ChallengeRefusalArms();

        Assert.True(
            arms.ContainsKey(label),
            "The challenge refusal branches on OidcChallengeRefusal.Classify in " + ChallengeRefusalFlow
            + " and this rule is written against the arm for " + label + " (#1763). The arms found are: "
            + (arms.Count == 0 ? "none" : string.Join(", ", arms.Keys)));

        return arms[label];
    }

    /// <summary>
    /// Every arm of that switch, keyed by its case label, with the arm's logging call as the value. An arm
    /// carrying more than one such call is refused rather than reduced to its first, because a second line
    /// can contradict the first and a rule that read only one would never see it.
    /// </summary>
    private static Dictionary<string, string> ChallengeRefusalArms()
    {
        var source = File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Api", "Flows", ChallengeRefusalFlow));

        var arms = new Dictionary<string, string>(StringComparer.Ordinal);
        string? label = null;

        foreach (var raw in SourceLines(source))
        {
            var trimmed = raw.Trim();

            if (trimmed.StartsWith("case OidcChallengeCause.", StringComparison.Ordinal) && trimmed.EndsWith(":", StringComparison.Ordinal))
            {
                label = trimmed["case ".Length..^1];
            }
            else if (string.Equals(trimmed, "default:", StringComparison.Ordinal))
            {
                label = "default";
            }
            else if (label is not null
                && trimmed.Contains("preparing the authorization request failed", StringComparison.Ordinal)
                && trimmed.Contains("LogWarning", StringComparison.Ordinal))
            {
                Assert.True(
                    !arms.ContainsKey(label),
                    "The arm for " + label + " logs the refusal more than once, so what it tells the "
                    + "administrator is not one sentence and this rule cannot judge it (#1763).");

                arms[label] = raw;
            }
        }

        return arms;
    }

    /// <summary>
    /// The source lines that are code. A commented-out copy of a logging call reads to a text rule exactly
    /// like the call it replaced, so leaving comments in would let an arm lose its sentence while the rules
    /// above stayed green - which is the failure they exist to prevent, one level up.
    /// </summary>
    private static IEnumerable<string> SourceLines(string source) =>
        source
            .Split('\n')
            .Select(candidate => candidate.TrimEnd())
            .Where(candidate => !candidate.TrimStart().StartsWith("//", StringComparison.Ordinal));
}
