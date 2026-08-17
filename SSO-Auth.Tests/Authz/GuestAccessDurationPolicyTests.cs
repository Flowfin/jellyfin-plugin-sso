// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="GuestAccessDurationPolicy"/> - the role → fixed access duration reducer (#1146).
/// Fail closed toward the SHORTER outcome: when several mappings match, the smallest duration wins, so a
/// user who happens to hold a second, looser group never has their deadline pushed out by it.
/// <para>
/// The skip rows are the ones worth reading twice. Every one of them is a value the save-time validator
/// refuses, so the only way it reaches here is a config XML edited by hand - and the answer to all of them
/// is to map NOTHING rather than to throw, because throwing on this path would turn a bad line in a config
/// file into a failed login for a provider that is otherwise fine.
/// </para>
/// </summary>
public class GuestAccessDurationPolicyTests
{
    private static OidConfig Config(params GuestAccessDurationRoleMap[] maps) => new OidConfig
    {
        GuestAccessDurationRoleMappings = new List<GuestAccessDurationRoleMap>(maps),
    };

    private static GuestAccessDurationRoleMap Map(int hours, params string[] roles)
        => new GuestAccessDurationRoleMap { DurationHours = hours, Roles = roles };

    [Fact]
    public void Resolve_NoMappingsConfigured_ReturnsNull()
        => Assert.Null(GuestAccessDurationPolicy.Resolve(new[] { "guest" }, new OidConfig()));

    [Fact]
    public void Resolve_EmptyMappingList_ReturnsNull()
        => Assert.Null(GuestAccessDurationPolicy.Resolve(new[] { "guest" }, Config()));

    [Fact]
    public void Resolve_NoRoleMatches_ReturnsNull()
        => Assert.Null(GuestAccessDurationPolicy.Resolve(new[] { "staff" }, Config(Map(24, "guest"))));

    [Fact]
    public void Resolve_NoRolesAtAll_ReturnsNull()
        => Assert.Null(GuestAccessDurationPolicy.Resolve(Array.Empty<string>(), Config(Map(24, "guest"))));

    [Fact]
    public void Resolve_SingleMatch_ReturnsItsDuration()
        => Assert.Equal(TimeSpan.FromHours(24), GuestAccessDurationPolicy.Resolve(new[] { "guest" }, Config(Map(24, "guest"))));

    [Fact]
    public void Resolve_TwoMappedRoles_TakesTheShorter()
    {
        // The parent's rule that expiry disables and never silently extends (#832), at the resolver. A user
        // in both "trial" and "guest" gets the trial's day, not the guest's month.
        var resolved = GuestAccessDurationPolicy.Resolve(new[] { "guest", "trial" }, Config(Map(720, "guest"), Map(24, "trial")));

        Assert.Equal(TimeSpan.FromHours(24), resolved);
    }

    [Fact]
    public void Resolve_TwoMappedRoles_TakesTheShorter_EvenWhenTheLongerComesSecond()
    {
        // The same claim with the entries swapped. Without both rows a min() written as a max() passes one
        // of them, which is exactly the one-character mistake this pair exists to catch.
        var resolved = GuestAccessDurationPolicy.Resolve(new[] { "guest", "trial" }, Config(Map(24, "trial"), Map(720, "guest")));

        Assert.Equal(TimeSpan.FromHours(24), resolved);
    }

    [Fact]
    public void Resolve_OneRoleListedOnSeveralMappings_TakesTheShortest()
        => Assert.Equal(TimeSpan.FromHours(6), GuestAccessDurationPolicy.Resolve(new[] { "guest" }, Config(Map(48, "guest"), Map(6, "guest"), Map(72, "guest"))));

    [Fact]
    public void Resolve_ZeroDuration_IsSkipped_NotTreatedAsAnInstantExpiry()
    {
        // A zero-hour mapping would resolve to a deadline equal to the provisioning instant, which the sweep
        // reads as already expired: the account would be created and disabled minutes later with no
        // explanation. It is refused on save and skipped here, so the user gets no deadline instead.
        Assert.Null(GuestAccessDurationPolicy.Resolve(new[] { "guest" }, Config(Map(0, "guest"))));
    }

    [Fact]
    public void Resolve_NegativeDuration_IsSkipped_NeverAPastDeadline()
        => Assert.Null(GuestAccessDurationPolicy.Resolve(new[] { "guest" }, Config(Map(-1, "guest"))));

    [Fact]
    public void Resolve_DurationAboveTheGuard_IsSkipped()
    {
        // The overflow near-miss. int.MaxValue hours added to the provisioning instant leaves DateTime's
        // range and AddHours THROWS, so an unbounded value hand-written into the config XML would turn every
        // provisioning login for the provider into a 500. Skipping is what keeps that a no-deadline account.
        Assert.Null(GuestAccessDurationPolicy.Resolve(new[] { "guest" }, Config(Map(int.MaxValue, "guest"))));
    }

    [Fact]
    public void Resolve_TheGuardBoundaryItself_IsAccepted()
        => Assert.Equal(
            TimeSpan.FromHours(GuestAccessDurationRoleMap.MaxDurationHours),
            GuestAccessDurationPolicy.Resolve(new[] { "guest" }, Config(Map(GuestAccessDurationRoleMap.MaxDurationHours, "guest"))));

    [Fact]
    public void Resolve_AnOutOfRangeEntry_DoesNotSuppressAValidOne()
        => Assert.Equal(TimeSpan.FromHours(12), GuestAccessDurationPolicy.Resolve(new[] { "guest", "trial" }, Config(Map(0, "guest"), Map(12, "trial"))));

    [Fact]
    public void Resolve_NullEntry_IsSkipped_OtherMatchesStillApply()
        => Assert.Equal(TimeSpan.FromHours(8), GuestAccessDurationPolicy.Resolve(new[] { "guest" }, Config(null!, Map(8, "guest"))));

    [Fact]
    public void Resolve_MappingWithNoRoles_NeverMatches()
        => Assert.Null(GuestAccessDurationPolicy.Resolve(new[] { "guest" }, Config(new GuestAccessDurationRoleMap { DurationHours = 8, Roles = null })));

    [Fact]
    public void Resolve_MappingWithAnEmptyRoleList_NeverMatches()
        => Assert.Null(GuestAccessDurationPolicy.Resolve(new[] { "guest" }, Config(Map(8))));

    [Fact]
    public void Resolve_BlankRoleEntry_IsSkipped_AndDoesNotMatchABlankLoginRole()
        => Assert.Null(GuestAccessDurationPolicy.Resolve(new[] { "   " }, Config(Map(8, "   "))));

    [Fact]
    public void Resolve_ConfiguredRoleIsTrimmed_BeforeMatching()
        => Assert.Equal(TimeSpan.FromHours(8), GuestAccessDurationPolicy.Resolve(new[] { "guest" }, Config(Map(8, "  guest  "))));

    [Fact]
    public void Resolve_RoleMatchingIsCaseSensitive()
    {
        // Ordinal, exactly like every other role policy in the tree. Recorded so a later change to one
        // matcher cannot quietly leave this one on a different rule.
        Assert.Null(GuestAccessDurationPolicy.Resolve(new[] { "Guest" }, Config(Map(8, "guest"))));
    }

    [Fact]
    public void Resolve_ReadsTheSamlProviderShapeToo()
        => Assert.Equal(
            TimeSpan.FromHours(24),
            GuestAccessDurationPolicy.Resolve(
                new[] { "guest" },
                new SamlConfig { GuestAccessDurationRoleMappings = new List<GuestAccessDurationRoleMap> { Map(24, "guest") } }));
}
