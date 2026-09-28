// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>What the repeated-member walk and the own reader of the role path each make of the same claim value (#1053).</summary>
/// <remarks>
/// The role claim decides privileges, so what an unreadable verdict should mean there cannot be settled
/// without knowing what refusing on it would cost, which is exactly the set of grammars the walk cannot read
/// and the reader can; this table is that measurement, taken rather than remembered. #1324 put the walk in
/// front of the reader, so the outcome column now records what each grammar produces with that screen, and the
/// two-column form is kept because it makes a reopening visible. Each row feeds one value to both and pins
/// both answers, alongside the controls that make the table readable. A null claim value is deliberately
/// absent, because the caller cannot produce one.
/// </remarks>
public class UnreadableRoleClaimPostureTests
{
    // The role-claim path every row is read along: segment 0 names the claim, segment 1 is the terminal key
    // whose array holds the roles. Two segments is the shape that parses the claim value at all - a
    // one-segment path takes the value verbatim and never reaches a parser, so it could not show a divergence.
    private static readonly string[] Path = { "realm_access", "roles" };

    // A body that resolves, embedded in every row, so a row that refuses is refusing because of the grammar
    // wrapped around it and not because there was nothing to find.
    private const string ResolvingBody = "\"roles\":[\"admin\"]";

    // The BOM as an escape rather than as a character in this file: a document prefixed with one is the
    // subject of a row, and writing it raw would put the byte into the source instead of into the fixture.
    private const string Bom = "\uFEFF";

    private static string NestedTo(int depth) =>
        string.Concat(Enumerable.Repeat("{\"a\":", depth)) + "1" + new string('}', depth);

    // The one source the theory and its coverage sentinel both read, so a row cannot be dropped from the run
    // while the count that guards the table stays green.
    private static readonly (string Grammar, string ClaimValue, StrictJson.Verdict Verdict, OidcRoleExtractor.Outcome Outcome)[] Measured =
    {
        // The controls. Without them a walk that refused everything would satisfy every refusal row.
        ("clean", "{" + ResolvingBody + "}", StrictJson.Verdict.Clean, OidcRoleExtractor.Outcome.Resolved),
        ("a nested sibling object", "{" + ResolvingBody + ",\"deep\":{\"a\":1}}", StrictJson.Verdict.Clean, OidcRoleExtractor.Outcome.Resolved),

        // The attack the walk exists for, on this path. What the repeat used to resolve to is pinned in its
        // own test below, because the outcome column alone would not show what the refusal replaced.
        ("the role member named twice", "{" + ResolvingBody + ",\"roles\":[\"user\"]}", StrictJson.Verdict.Repeated, OidcRoleExtractor.Outcome.RepeatedMember),

        // Every grammar the walk calls Unreadable and the reader ALSO refuses. Refusing on Unreadable costs
        // these rows nothing: they already carry no roles.
        ("empty", "", StrictJson.Verdict.Unreadable, OidcRoleExtractor.Outcome.Unreadable),
        ("whitespace", "   ", StrictJson.Verdict.Unreadable, OidcRoleExtractor.Outcome.Unreadable),
        ("truncated", "{" + ResolvingBody, StrictJson.Verdict.Unreadable, OidcRoleExtractor.Outcome.Unreadable),
        ("not json at all", "not-json", StrictJson.Verdict.Unreadable, OidcRoleExtractor.Outcome.Unreadable),
        ("a bare scalar", "17", StrictJson.Verdict.Unreadable, OidcRoleExtractor.Outcome.Unreadable),
        ("an array of scalars", "[1,2,3]", StrictJson.Verdict.Unreadable, OidcRoleExtractor.Outcome.Unreadable),

        // WHAT WAS THE DIVERGENCE, and the point the table was taken for: two grammars the walk cannot read
        // and the reader read perfectly well, roles and all. They were the entire availability price of
        // treating Unreadable as a refusal here, the price was accepted on #1053, and #1324 charged it - the
        // reader now consults the walk instead of a second parser, so these two rows carry no roles either.
        // Kept as rows rather than deleted: they are what the price WAS, and a later edit that let a
        // surrogate through would put them back on the divergent side where the sentinel below reddens.
        ("an escaped unpaired surrogate in a member name", "{" + ResolvingBody + ",\"a\\ud800\":1}", StrictJson.Verdict.Unreadable, OidcRoleExtractor.Outcome.Unreadable),
        ("a raw unpaired surrogate in a member name", "{" + ResolvingBody + ",\"a\uD800\":1}", StrictJson.Verdict.Unreadable, OidcRoleExtractor.Outcome.Unreadable),

        // The divergence in the OTHER direction. The walk strips one leading BOM and reports an affirmative
        // Clean, while the reader on this path refuses the same bytes. It is not exploitable - the reader's
        // refusal is what decides the roles and it grants none - but it is the walk saying something
        // affirmative about a document its consumer cannot read, which is the shape the walk exists to
        // prevent, and it is recorded here rather than left to be rediscovered.
        ("a leading BOM", Bom + "{" + ResolvingBody + "}", StrictJson.Verdict.Clean, OidcRoleExtractor.Outcome.ValueNotJson),
    };

    public static TheoryData<string> Grammars()
    {
        var data = new TheoryData<string>();
        foreach (var row in Measured)
        {
            data.Add(row.Grammar);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Grammars))]
    public void TheWalkAndTheRolePathReader_AgreeExceptWhereThisTableSaysTheyDoNot(string grammar)
    {
        var (_, claimValue, expectedVerdict, expectedOutcome) = Measured.Single(row => row.Grammar == grammar);

        var verdict = StrictJson.Inspect(claimValue, out _);
        Assert.True(expectedVerdict == verdict, $"{grammar}: the walk answered {verdict}, the table says {expectedVerdict}");

        var outcome = OidcRoleExtractor.ExtractRoles(Path, claimValue, false).Outcome;
        Assert.True(expectedOutcome == outcome, $"{grammar}: the role path answered {outcome}, the table says {expectedOutcome}");
    }

    [Fact]
    public void NestingPastTheDepthCap_IsUnreadableToBothOfThem()
    {
        // Kept out of the table because the fixture is generated rather than written, and a 65-deep literal
        // in a row would be unreadable in the sense this file is not about. Both sides refuse it, so it joins
        // the rows where a refusal on Unreadable costs nothing.
        var deep = "{" + ResolvingBody + ",\"deep\":" + NestedTo(65) + "}";

        Assert.Equal(StrictJson.Verdict.Unreadable, StrictJson.Inspect(deep, out _));
        Assert.Equal(OidcRoleExtractor.Outcome.Unreadable, OidcRoleExtractor.ExtractRoles(Path, deep, false).Outcome);
    }

    [Fact]
    public void ARepeatedRoleMember_GrantsNothing_AndTheLastOccurrenceIsWhatItUsedToGrant()
    {
        // Why the repeat matters at all, in one place: appending a second member REPLACED the role set rather
        // than adding to it, so a provider - or anyone who can answer as one - decided the roles by putting
        // its own member last. The screen refuses that value now, and the two halves are asserted together so
        // the refusal cannot be read as a document that was harmless anyway.
        const string Repeated = "{\"roles\":[\"admin\"],\"roles\":[\"user\"]}";

        var result = OidcRoleExtractor.ExtractRoles(Path, Repeated, false);

        Assert.Equal(OidcRoleExtractor.Outcome.RepeatedMember, result.Outcome);
        Assert.Empty(result.Roles);

        // What the refused document would have granted, taken from the parser the reader no longer reaches on
        // it rather than from memory. Without this the row above says only "no roles", which is also what a
        // typo in the configured path produces.
        var lastOccurrence = JsonConvert.DeserializeObject<IDictionary<string, object>>(Repeated)!["roles"];
        Assert.Equal(new List<string> { "user" }, ((JArray)lastOccurrence).Select(token => token.Value<string>()!).ToList());
    }

    [Fact]
    public void TheDivergenceSetIsEmpty_AndWasTwoGrammars()
    {
        // The number this table exists to produce, derived from the rows rather than restated in prose: the
        // grammars where the walk establishes nothing and the reader still hands back roles. An earlier round
        // put it at six and used that as the argument for handling Unreadable as "proceed", which is the
        // fail-open direction on a privilege path; the measurement put it at two, #1053 decided to pay it, and
        // #1324 closed it. Zero is now the assertion, so a future edit that lets any grammar the walk cannot
        // read hand back roles again reddens here rather than going unnoticed.
        var divergent = Measured
            .Where(row => row.Verdict == StrictJson.Verdict.Unreadable && row.Outcome == OidcRoleExtractor.Outcome.Resolved)
            .Select(row => row.Grammar)
            .ToList();

        Assert.Empty(divergent);

        // And the two that used to be in it are still in the table, on the refusing side. Asserting the empty
        // set alone would also pass on a table somebody had deleted the surrogate rows from, which is the
        // cheapest way to make a divergence disappear without closing it.
        Assert.Equal(
            2,
            Measured.Count(row => row.Grammar.Contains("surrogate", StringComparison.Ordinal)
                && row.Verdict == StrictJson.Verdict.Unreadable
                && row.Outcome == OidcRoleExtractor.Outcome.Unreadable));
    }
}
