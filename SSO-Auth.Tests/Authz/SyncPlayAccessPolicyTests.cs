// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="SyncPlayAccessPolicy"/> - the role → SyncPlay-access reducer (#827). Fail closed
/// toward the LESS permissive outcome: the feature off, no mapping matched, an empty role list or an
/// unparseable level all yield null (leave the existing level), and when several mappings match the MOST
/// RESTRICTIVE level wins, never the loosest.
/// </summary>
public class SyncPlayAccessPolicyTests
{
    private static OidConfig Config(bool enabled, params SyncPlayAccessRoleMap[] maps) => new OidConfig
    {
        EnableSyncPlayAccessRoles = enabled,
        SyncPlayAccessRoleMappings = new List<SyncPlayAccessRoleMap>(maps),
    };

    private static SyncPlayAccessRoleMap Map(string? access, params string[] roles) => new SyncPlayAccessRoleMap { Access = access, Roles = roles };

    [Fact]
    public void Resolve_FeatureOff_ReturnsNull()
        => Assert.Null(SyncPlayAccessPolicy.Resolve(new[] { "hosts" }, Config(enabled: false, Map("CreateAndJoinGroups", "hosts"))));

    [Fact]
    public void Resolve_NullMappings_ReturnsNull()
        => Assert.Null(SyncPlayAccessPolicy.Resolve(new[] { "hosts" }, new OidConfig { EnableSyncPlayAccessRoles = true, SyncPlayAccessRoleMappings = null }));

    [Fact]
    public void Resolve_NoRoleMatches_ReturnsNull()
        => Assert.Null(SyncPlayAccessPolicy.Resolve(new[] { "guests" }, Config(enabled: true, Map("JoinGroups", "hosts"))));

    [Fact]
    public void Resolve_SingleMatch_ReturnsItsLevel()
        => Assert.Equal(SyncPlayUserAccessType.JoinGroups, SyncPlayAccessPolicy.Resolve(new[] { "hosts" }, Config(enabled: true, Map("JoinGroups", "hosts"))));

    [Fact]
    public void Resolve_MultipleMatches_ReturnsTheMostRestrictive()
    {
        // THE TRAP THIS TEST EXISTS FOR. SyncPlayUserAccessType numbers the LOOSEST level zero
        // (CreateAndJoinGroups = 0, JoinGroups = 1, None = 2), the opposite way round from the parental-rating
        // score ParentalRatingPolicy reduces. So the Math.Min shape copied from that policy would resolve this
        // login to CreateAndJoinGroups - the WIDEST access its groups allow - and read as correct while doing
        // it. Deleting the ranking in SyncPlayAccessPolicy.Restrictiveness, or replacing it with the enum's
        // own ordering, turns this assertion red.
        var resolved = SyncPlayAccessPolicy.Resolve(
            new[] { "hosts", "guests" },
            Config(enabled: true, Map("CreateAndJoinGroups", "hosts"), Map("None", "guests")));

        Assert.Equal(SyncPlayUserAccessType.None, resolved);
    }

    [Fact]
    public void Resolve_MatchAcrossSeparateEntries_TakesTheStricter_EvenWhenTheLooserComesFirst()
        => Assert.Equal(
            SyncPlayUserAccessType.JoinGroups,
            SyncPlayAccessPolicy.Resolve(new[] { "a", "b" }, Config(enabled: true, Map("CreateAndJoinGroups", "a"), Map("JoinGroups", "b"))));

    [Fact]
    public void Resolve_MatchAcrossSeparateEntries_TakesTheStricter_EvenWhenTheStricterComesFirst()
        => Assert.Equal(
            SyncPlayUserAccessType.JoinGroups,
            SyncPlayAccessPolicy.Resolve(new[] { "a", "b" }, Config(enabled: true, Map("JoinGroups", "a"), Map("CreateAndJoinGroups", "b"))));

    [Fact]
    public void Resolve_NullEntry_IsSkipped_OtherMatchesStillApply()
        => Assert.Equal(
            SyncPlayUserAccessType.None,
            SyncPlayAccessPolicy.Resolve(new[] { "guests" }, Config(enabled: true, null!, Map("None", "guests"))));

    [Fact]
    public void Resolve_MappingWithNoRoles_NeverMatches()
        => Assert.Null(SyncPlayAccessPolicy.Resolve(new[] { "hosts" }, Config(enabled: true, Map("JoinGroups"))));

    [Fact]
    public void Resolve_ConfiguredRoleIsTrimmed()
        => Assert.Equal(SyncPlayUserAccessType.JoinGroups, SyncPlayAccessPolicy.Resolve(new[] { "hosts" }, Config(enabled: true, Map("JoinGroups", "  hosts  "))));

    [Fact]
    public void Resolve_MatchingIsOrdinalCaseSensitive()
        => Assert.Null(SyncPlayAccessPolicy.Resolve(new[] { "hosts" }, Config(enabled: true, Map("JoinGroups", "Hosts"))));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("joingroups")]
    [InlineData("Join Groups")]
    [InlineData("Everything")]
    public void Resolve_UnparseableLevel_IsSkipped(string? access)
        => Assert.Null(SyncPlayAccessPolicy.Resolve(new[] { "hosts" }, Config(enabled: true, Map(access, "hosts"))));

    [Fact]
    public void Resolve_NumericLevel_IsSkipped_NotCastToAnUndeclaredMember()
    {
        // Both numerals are refused, and they were refused by DIFFERENT checks - which is why this test has
        // two lines rather than one. "57" parses to an undeclared (SyncPlayUserAccessType)57 that Enum.IsDefined
        // rejects. "1" parses to the DECLARED JoinGroups, so IsDefined passed it: this assertion was red on the
        // first run and the name round-trip in TryParseAccess is what was added to answer it. A level is a name
        // here, so a reorder of the enum upstream cannot silently change what a stored "1" means.
        Assert.Null(SyncPlayAccessPolicy.Resolve(new[] { "hosts" }, Config(enabled: true, Map("1", "hosts"))));
        Assert.Null(SyncPlayAccessPolicy.Resolve(new[] { "hosts" }, Config(enabled: true, Map("57", "hosts"))));
    }

    [Fact]
    public void Resolve_UnparseableLevelBesideAValidOne_LeavesTheValidOneStanding()
        => Assert.Equal(
            SyncPlayUserAccessType.None,
            SyncPlayAccessPolicy.Resolve(new[] { "hosts", "guests" }, Config(enabled: true, Map("nonsense", "hosts"), Map("None", "guests"))));

    [Fact]
    public void EveryDeclaredLevelIsRanked()
    {
        // The ranking is hand-written, so a member added upstream would fall to the fail-closed default arm
        // and be treated as maximally restrictive. This asserts the three members the plugin was built
        // against are each reachable by name, so a rename upstream is a red test rather than a silent
        // fall-through to "most restrictive" on every mapping.
        foreach (var name in new[] { "CreateAndJoinGroups", "JoinGroups", "None" })
        {
            Assert.True(SyncPlayAccessPolicy.TryParseAccess(name, out var level), name);
            Assert.Equal(name, level.ToString());
        }
    }
}
