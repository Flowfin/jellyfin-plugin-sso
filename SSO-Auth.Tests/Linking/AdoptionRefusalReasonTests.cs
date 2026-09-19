// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.IO;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Linking;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="CanonicalLinkService.DescribeAdoptionRefusal"/> - the reason phrase the refusal
/// line carries when a first SSO login is not allowed to adopt a same-named account (#218, #1765).
/// <para>
/// The administrator arm is the one that costs when it is vague. The rule it states is right and is not
/// in question: an administrator account is never adopted by name, so a first SSO login cannot turn into
/// administrator access. What the reader needs after it is a way in, and the phrase pointed at "the admin
/// endpoints" - an API, named as a category - so the reporter on #1762 searched the documentation before
/// finding the page that does it.
/// </para>
/// <para>
/// These are contract tests on a message rather than on behaviour, and that is what they are for: the
/// wording IS the deliverable of #1765, and nothing else in the suite would notice it changing back. The
/// rule at the bottom binds the phrase to the log line an operator reads, so the contract cannot be kept
/// while the line stops carrying it.
/// </para>
/// </summary>
public class AdoptionRefusalReasonTests
{
    [Fact]
    public void AdministratorTarget_NamesBothWaysIn()
    {
        // There are two, and the line names both. The self-service page acts on whoever is signed in, so
        // it needs that account's own password; the pre-provision route is elevation-gated and is the way
        // through on a server where that account has no password door left.
        var reason = CanonicalLinkService.DescribeAdoptionRefusal(AdoptionVerdict.RefusePrivileged);

        Assert.Contains("/SSOViews/linking", reason, StringComparison.Ordinal);
        Assert.Contains("its own password", reason, StringComparison.Ordinal);
        Assert.Contains("pre-provision", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AdministratorTarget_NoLongerSendsTheReaderToACategoryOfEndpoint()
    {
        // The phrase this replaced. "The admin endpoints" names a category rather than a route or a page,
        // and neither of the two ways in can be found from it without a documentation search.
        var reason = CanonicalLinkService.DescribeAdoptionRefusal(AdoptionVerdict.RefusePrivileged);

        Assert.DoesNotContain("admin endpoints", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AdministratorTarget_StillStatesTheRuleBeforeTheRemedy()
    {
        // The refusal reads as one sentence in the log: what was refused, then what to do. Losing the
        // first half would leave a line that offers a remedy for a condition it never named.
        var reason = CanonicalLinkService.DescribeAdoptionRefusal(AdoptionVerdict.RefusePrivileged);

        Assert.StartsWith("the target account is an administrator", reason, StringComparison.Ordinal);
    }

    [Fact]
    public void UnverifiedEmail_IsUnchangedAndNamesNoPage()
    {
        // The other refusal arm is a provider policy rather than a privilege rule, and its remedy is at
        // the provider. It must not acquire the linking page by proximity.
        var reason = CanonicalLinkService.DescribeAdoptionRefusal(AdoptionVerdict.RefuseUnverifiedEmail);

        Assert.Equal("the provider requires a verified email for adoption and the login carried none", reason);
    }

    [Fact]
    public void AnyOtherVerdict_FallsBackWithoutNamingACause()
    {
        // The belt arm for a verdict value added later: it must not inherit either remedy.
        var reason = CanonicalLinkService.DescribeAdoptionRefusal((AdoptionVerdict)int.MaxValue);

        Assert.Equal("the account is not eligible for name-based adoption", reason);
    }

    [Fact]
    public void EveryAdministratorRefusalOnThisPathGivesTheSameTwoWaysIn()
    {
        // #1765 is about one refusal, and the same rule is stated twice on the same login path: the
        // adoption arm above, and the legacy username-keyed link that points at an administrator. Two
        // remedies for one rule in one log is the defect the issue is about, arriving a second time, so
        // the rule is written over both rather than over the one that was reported.
        //
        // A source rule, because the second site is a message template rather than a value: its bytes are
        // in the text and nowhere else, which is the same reason the arms above are contract tests.
        var source = File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Api", "Linking", "CanonicalLinkService.cs"));

        var lines = source
            .Split('\n')
            .Select(candidate => candidate.TrimEnd())
            .Where(candidate => !candidate.TrimStart().StartsWith("//", StringComparison.Ordinal))
            .ToList();

        var privileged = lines
            .Where(candidate => candidate.Contains("\"", StringComparison.Ordinal))
            .Where(candidate => candidate.Contains("the target account is an administrator", StringComparison.Ordinal)
                || candidate.Contains("points at an administrator account", StringComparison.Ordinal))
            .Select(candidate => candidate.Trim())
            .ToList();

        Assert.True(
            privileged.Count >= 2,
            "The two administrator refusals this rule is written over are in this file (#1765). Found "
            + privileged.Count.ToString(System.Globalization.CultureInfo.InvariantCulture)
            + ", so the rule below would pass for the wrong reason.");

        foreach (var line in privileged)
        {
            Assert.True(
                line.Contains("/SSOViews/linking", StringComparison.Ordinal)
                && line.Contains("pre-provision", StringComparison.Ordinal),
                "Every administrator refusal names both ways in (#1765). This one does not: " + line);

            Assert.True(
                !line.Contains("admin endpoint", StringComparison.OrdinalIgnoreCase),
                "An administrator refusal names the page and the pre-provision route rather than a "
                + "category of endpoint (#1765). This one still names the category: " + line);
        }
    }

    [Fact]
    public void TheAdoptionRefusalLineCarriesTheseWords()
    {
        // The arms above are a contract on a string, and a string nothing prints is a contract with
        // nobody. This holds the one connection between them: the refusal line's reason placeholder is
        // fed by DescribeAdoptionRefusal, so the phrase tested above is the phrase the operator reads.
        var source = File.ReadAllText(Path.Combine(RepoTree.Root, "SSO-Auth", "Api", "Linking", "CanonicalLinkService.cs"));

        var lines = source.Split('\n').Select(candidate => candidate.TrimEnd()).ToList();

        var at = lines.FindIndex(candidate =>
            candidate.Contains("refused adoption of a pre-existing account: {Reason}", StringComparison.Ordinal));

        Assert.True(
            at >= 0,
            "The adoption refusal is logged with a {Reason} placeholder in CanonicalLinkService, and this "
            + "rule is written against it (#1765).");

        var call = string.Join(" ", lines.Skip(at).Take(6));

        Assert.True(
            call.Contains("DescribeAdoptionRefusal(verdict)", StringComparison.Ordinal),
            "The reason placeholder is fed by DescribeAdoptionRefusal, so what the tests above pin is what "
            + "the log line says (#1765). It is not: " + call.Trim());
    }
}
