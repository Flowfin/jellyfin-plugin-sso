// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using System.Linq;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// What the repeated-member walk and the role path's own reader each make of the same claim value (#1053).
/// The role claim decides privileges, so what an <c>Unreadable</c> verdict should MEAN there cannot be
/// settled without knowing what refusing on it would cost, and that cost is exactly the set of grammars the
/// walk cannot read and the reader can. This table is that measurement, taken rather than remembered: the
/// issue carried an assertion of six such grammars from an earlier round and named none of them.
/// <para>
/// Each row feeds one claim value to <see cref="StrictJson.Inspect"/> and to
/// <see cref="OidcRoleExtractor.ExtractRoles"/> along the same two-segment path, and pins both answers. The
/// rows are the input classes the walk's own contract calls <c>Unreadable</c> - no body, malformed, past the
/// depth cap, an unpaired surrogate in a member name spelled raw and spelled as an escape, and a document
/// carrying no object - plus the controls that make the table readable: a clean document, the boundary below
/// the depth cap, a leading BOM, and the repeat itself.
/// </para>
/// <para>
/// A null claim value is deliberately absent. <c>Claim.Value</c> is never null, so the row would pin the
/// behaviour of an input the caller cannot produce; fed one, the reader raises out of Newtonsoft rather than
/// refusing, which is worth knowing and is not worth a permanent row.
/// </para>
/// </summary>
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

        // The attack the walk exists for, on this path. What the repeat resolves TO is pinned in its own
        // test below, because the outcome column alone would not show it.
        ("the role member named twice", "{" + ResolvingBody + ",\"roles\":[\"user\"]}", StrictJson.Verdict.Repeated, OidcRoleExtractor.Outcome.Resolved),

        // Every grammar the walk calls Unreadable and the reader ALSO refuses. Refusing on Unreadable costs
        // these rows nothing: they already carry no roles.
        ("empty", "", StrictJson.Verdict.Unreadable, OidcRoleExtractor.Outcome.ValueNotJson),
        ("whitespace", "   ", StrictJson.Verdict.Unreadable, OidcRoleExtractor.Outcome.ValueNotJson),
        ("truncated", "{" + ResolvingBody, StrictJson.Verdict.Unreadable, OidcRoleExtractor.Outcome.ValueNotJson),
        ("not json at all", "not-json", StrictJson.Verdict.Unreadable, OidcRoleExtractor.Outcome.ValueNotJson),
        ("a bare scalar", "17", StrictJson.Verdict.Unreadable, OidcRoleExtractor.Outcome.ValueNotJson),
        ("an array of scalars", "[1,2,3]", StrictJson.Verdict.Unreadable, OidcRoleExtractor.Outcome.ValueNotJson),

        // THE DIVERGENCE, and the point of the table: two grammars the walk cannot read and the reader reads
        // perfectly well, roles and all. These rows are the entire availability price of treating Unreadable
        // as a refusal on this path.
        ("an escaped unpaired surrogate in a member name", "{" + ResolvingBody + ",\"a\\ud800\":1}", StrictJson.Verdict.Unreadable, OidcRoleExtractor.Outcome.Resolved),
        ("a raw unpaired surrogate in a member name", "{" + ResolvingBody + ",\"a\uD800\":1}", StrictJson.Verdict.Unreadable, OidcRoleExtractor.Outcome.Resolved),

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
        Assert.Equal(OidcRoleExtractor.Outcome.ValueNotJson, OidcRoleExtractor.ExtractRoles(Path, deep, false).Outcome);
    }

    [Fact]
    public void ARepeatedRoleMember_GrantsTheLastOccurrence()
    {
        // The table pins that a repeat RESOLVES; this pins what it resolves TO, which is why the repeat
        // matters at all. The first occurrence's roles are gone, so a provider - or anyone who can answer as
        // one - appends a second member and REPLACES the role set rather than adding to it.
        var result = OidcRoleExtractor.ExtractRoles(Path, "{\"roles\":[\"admin\"],\"roles\":[\"user\"]}", false);

        Assert.Equal(new List<string> { "user" }, result.Roles);
        Assert.DoesNotContain("admin", result.Roles);
    }

    [Fact]
    public void TheDivergenceSetIsTwoGrammars_NotSix()
    {
        // The number this table exists to produce, derived from the rows rather than restated in prose: the
        // grammars where the walk establishes nothing and the reader still hands back roles. An earlier round
        // put it at six and used that as the argument for handling Unreadable as "proceed", which is the
        // fail-open direction on a privilege path. If a future edit to the walk widens or narrows the set,
        // this is the row that says so instead of the argument silently going stale.
        var divergent = Measured
            .Where(row => row.Verdict == StrictJson.Verdict.Unreadable && row.Outcome == OidcRoleExtractor.Outcome.Resolved)
            .Select(row => row.Grammar)
            .ToList();

        Assert.Equal(2, divergent.Count);
        Assert.All(divergent, grammar => Assert.Contains("surrogate", grammar));
    }
}
