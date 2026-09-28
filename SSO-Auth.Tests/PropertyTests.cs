// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using FsCheck;
using FsCheck.Fluent;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Authz;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>Property-based tests over the pure login-decision helpers, each pinning a security invariant that has to hold for all inputs rather than for the hand-picked characterization cases.</summary>
/// <remarks>
/// Driven by FsCheck core from ordinary xUnit v3 facts, so there is no xunit-version coupling. The generators
/// bias toward the meaningful tokens mixed with random noise, because purely random strings would almost
/// never match a configured role or claim type and the interesting branches would pass vacuously.
/// </remarks>
public class PropertyTests
{
    private static readonly string[] KnownClaimTypes = { "preferred_username", "sub", "email", "role", "groups" };
    private static readonly string[] KnownRoles = { "admin", "user", "tv", "tvadmin", "media", "outsider", "" };

    // A token that is usually one of the meaningful values but sometimes arbitrary noise.
    private static Gen<string> TokenGen(string[] known) =>
        Gen.OneOf(new[]
        {
            Gen.Elements(known),
            ArbMap.Default.GeneratorFor<string>().Where(s => s != null),
        });

    private static Gen<List<string>> RolesGen =>
        TokenGen(KnownRoles).ListOf().Select(rs => rs.ToList());

    private static Gen<List<Claim>> ClaimsGen =>
        TokenGen(KnownClaimTypes)
            .Zip(ArbMap.Default.GeneratorFor<string>())
            .Select(pair => new Claim(pair.Item1, pair.Item2 ?? string.Empty))
            .ListOf()
            .Select(cs => cs.ToList());

    [Fact]
    public void OidcBuild_ValidLoginAlwaysResolvesAUsername()
    {
        // The #95 invariant, universally: a login the OID builder marks Valid must always carry a
        // non-whitespace username. Roles is a non-null empty allow-list so the sub fallback does not
        // hit its documented null-Roles throw.
        Prop.ForAll(ClaimsGen.ToArbitrary(), claims =>
        {
            var config = new OidConfig { Roles = Array.Empty<string>() };
            var result = OidcAuthorizeStateBuilder.Build(claims, config);
            return !result.Valid || !string.IsNullOrWhiteSpace(result.Username);
        }).QuickCheckThrowOnFailure();
    }

    [Fact]
    public void SamlEvaluate_GrantsAreMonotonicInRoles()
    {
        // Adding roles can only ever ADD privileges (the mapper OR-s across roles); it can never
        // revoke a grant. So the grants for a superset of roles dominate those for the subset.
        Prop.ForAll(RolesGen.ToArbitrary(), RolesGen.ToArbitrary(), (roles, extra) =>
        {
            var config = SamlGrantConfig();
            var superset = roles.Concat(extra).ToList();

            var g1 = RolePrivilegeMapper.Evaluate(roles, config);
            var g2 = RolePrivilegeMapper.Evaluate(superset, config);

            return (!g1.Admin || g2.Admin)
                && (!g1.EnableLiveTv || g2.EnableLiveTv)
                && (!g1.EnableLiveTvManagement || g2.EnableLiveTvManagement)
                && g1.Folders.All(g2.Folders.Contains);
        }).QuickCheckThrowOnFailure();
    }

    [Fact]
    public void OidcEvaluate_GrantsAreMonotonicInRoles()
    {
        // Same monotonicity for the OpenID mapper: more roles never remove a granted privilege.
        Prop.ForAll(RolesGen.ToArbitrary(), RolesGen.ToArbitrary(), (roles, extra) =>
        {
            var config = OidGrantConfig();
            var superset = roles.Concat(extra).ToList();

            var g1 = RolePrivilegeMapper.Evaluate(roles, config);
            var g2 = RolePrivilegeMapper.Evaluate(superset, config);

            return (!g1.Valid || g2.Valid)
                && (!g1.Admin || g2.Admin)
                && (!g1.EnableLiveTv || g2.EnableLiveTv)
                && (!g1.EnableLiveTvManagement || g2.EnableLiveTvManagement)
                && g1.Folders.All(g2.Folders.Contains);
        }).QuickCheckThrowOnFailure();
    }

    private static SamlConfig SamlGrantConfig() => new SamlConfig
    {
        AdminRoles = new[] { "admin" },
        EnableFolderRoles = true,
        FolderRoleMapping = new List<FolderRoleMap>
        {
            new FolderRoleMap { Role = "media", Folders = new List<string> { "movies" } },
        },
        EnableLiveTvRoles = true,
        LiveTvRoles = new[] { "tv" },
        LiveTvManagementRoles = new[] { "tvadmin" },
    };

    private static OidConfig OidGrantConfig() => new OidConfig
    {
        Roles = new[] { "user" },
        AdminRoles = new[] { "admin" },
        EnableFolderRoles = true,
        FolderRoleMapping = new List<FolderRoleMap>
        {
            new FolderRoleMap { Role = "media", Folders = new List<string> { "movies" } },
        },
        EnableLiveTvRoles = true,
        LiveTvRoles = new[] { "tv" },
        LiveTvManagementRoles = new[] { "tvadmin" },
    };
}
