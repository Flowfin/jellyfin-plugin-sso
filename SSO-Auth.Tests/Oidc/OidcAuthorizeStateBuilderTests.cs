// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Security.Claims;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Api.Avatar;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Characterization tests for <see cref="OidcAuthorizeStateBuilder.Build"/> - the username/validity/
/// avatar/folder derivation extracted from the OID callback. These pin the exact behavior (including
/// the last-claim-wins username, the sub-claim fallback, and the fail-closed null-Roles throw) so the
/// extraction is a proven no-op and the derivation is testable in isolation.
/// </summary>
public class OidcAuthorizeStateBuilderTests
{
    private static OidConfig Config(Action<OidConfig> configure)
    {
        var config = new OidConfig();
        configure(config);
        return config;
    }

    private static List<Claim> Claims(params (string Type, string Value)[] claims)
    {
        var list = new List<Claim>();
        foreach (var (type, value) in claims)
        {
            list.Add(new Claim(type, value));
        }

        return list;
    }

    [Fact]
    public void NoClaims_NoRolesConfigured_NotValid()
    {
        var result = OidcAuthorizeStateBuilder.Build(Claims(), Config(_ => { }));

        Assert.Null(result.Username);
        Assert.False(result.Valid);
        Assert.False(result.Admin);
        Assert.False(result.EnableLiveTv);
        Assert.False(result.EnableLiveTvManagement);
        Assert.Empty(result.Folders);
        Assert.Null(result.AvatarUrl);
    }

    [Fact]
    public void Issuer_PassedFromTheRawToken_IsCarriedForTheLinkBinding()
    {
        // #186: the validated id_token's issuer is passed in by the callback (read from the raw token, since
        // OidcClient filters `iss` out of result.User) and carried onto the derived state so the canonical
        // link can be issuer-bound.
        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("sub", "sub-1")),
            Config(_ => { }),
            issuer: "https://issuer.example");

        Assert.Equal("https://issuer.example", result.Issuer);
    }

    [Fact]
    public void NoIssuerPassed_ResolvesToNull_SoTheLinkStaysUnstamped()
    {
        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("sub", "sub-1")),
            Config(_ => { }));

        Assert.Null(result.Issuer);
    }

    [Fact]
    public void PreferredUsernameClaim_NoRolesConfigured_IsValid()
    {
        var result = OidcAuthorizeStateBuilder.Build(Claims(("preferred_username", "alice")), Config(_ => { }));

        Assert.Equal("alice", result.Username);
        Assert.True(result.Valid);
    }

    [Fact]
    public void CustomUsernameClaim_IsRespected()
    {
        var config = Config(c => c.DefaultUsernameClaim = "email");
        var result = OidcAuthorizeStateBuilder.Build(Claims(("email", "alice@example.com")), config);

        Assert.Equal("alice@example.com", result.Username);
        Assert.True(result.Valid);
    }

    [Fact]
    public void LastMatchingUsernameClaimWins()
    {
        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "first"), ("preferred_username", "second")),
            Config(_ => { }));

        Assert.Equal("second", result.Username);
    }

    [Fact]
    public void EmailVerified_Absent_IsNull()
    {
        // No email_verified claim (the IdP omits it, or the "email" scope was not requested) surfaces as
        // null, which the adoption gate (#218) fails closed on when a verified email is required.
        var result = OidcAuthorizeStateBuilder.Build(Claims(("preferred_username", "alice")), Config(_ => { }));

        Assert.Null(result.EmailVerified);
    }

    [Theory]
    [InlineData("true", true)]
    [InlineData("false", false)]
    [InlineData("True", true)]   // bool.TryParse is case-insensitive
    [InlineData("FALSE", false)]
    public void EmailVerified_BooleanClaim_IsParsed(string claimValue, bool expected)
    {
        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("email_verified", claimValue)),
            Config(_ => { }));

        Assert.Equal(expected, result.EmailVerified);
    }

    [Theory]
    [InlineData("yes")]
    [InlineData("1")]
    [InlineData("")]
    public void EmailVerified_NonBooleanClaim_IsNull(string claimValue)
    {
        // A non-boolean value is treated as absent (null) rather than coerced to true - fail closed.
        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("email_verified", claimValue)),
            Config(_ => { }));

        Assert.Null(result.EmailVerified);
    }

    [Fact]
    public void EmailVerified_LastBooleanClaimWins()
    {
        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("email_verified", "false"), ("email_verified", "true")),
            Config(_ => { }));

        Assert.True(result.EmailVerified);
    }

    [Fact]
    public void AllowListConfigured_MatchingRole_IsValid()
    {
        var config = Config(c =>
        {
            c.Roles = new[] { "jellyfin-users" };
            c.RoleClaim = "role";
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("role", "jellyfin-users")),
            config);

        Assert.Equal("alice", result.Username);
        Assert.True(result.Valid);
    }

    [Fact]
    public void AllowListConfigured_NoMatchingRole_NotValid()
    {
        var config = Config(c =>
        {
            c.Roles = new[] { "jellyfin-users" };
            c.RoleClaim = "role";
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("role", "outsiders")),
            config);

        Assert.Equal("alice", result.Username);
        Assert.False(result.Valid);
    }

    [Fact]
    public void PermissionRoles_AreThreadedFromClaimsOntoTheDerivedState()
    {
        // #164 wiring: the generic role→permission grants derived from the login's role claims and the
        // provider configuration are carried on the derived state (and thence to the mint). Here the login
        // carries the mapped role, so the permission is granted; another configured-but-unmatched permission
        // is explicitly revoked.
        var config = Config(c =>
        {
            c.RoleClaim = "role";
            c.EnablePermissionRoles = true;
            c.PermissionRoleMappings = new System.Collections.Generic.List<PermissionRoleMap>
            {
                new PermissionRoleMap { Permission = "EnableContentDownloading", Roles = new[] { "downloaders" } },
                new PermissionRoleMap { Permission = "EnableContentDeletion", Roles = new[] { "deleters" } },
            };
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("role", "downloaders")),
            config);

        Assert.NotNull(result.PermissionGrants);
        Assert.Contains(result.PermissionGrants!, g => g.Kind == Jellyfin.Database.Implementations.Enums.PermissionKind.EnableContentDownloading && g.Granted);
        Assert.Contains(result.PermissionGrants!, g => g.Kind == Jellyfin.Database.Implementations.Enums.PermissionKind.EnableContentDeletion && !g.Granted);
    }

    [Fact]
    public void PermissionRoles_FeatureOff_LeavesTheGrantsEmpty()
    {
        var config = Config(c =>
        {
            c.RoleClaim = "role";
            c.EnablePermissionRoles = false;
            c.PermissionRoleMappings = new System.Collections.Generic.List<PermissionRoleMap>
            {
                new PermissionRoleMap { Permission = "EnableContentDownloading", Roles = new[] { "downloaders" } },
            };
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("role", "downloaders")),
            config);

        Assert.Empty(result.PermissionGrants!);
    }

    [Fact]
    public void ParentalRating_MatchedRole_CarriesTheMinimumCeilingOnTheState()
    {
        // #736 wiring: the role→parental-rating ceiling derived from the login's roles is carried on the
        // derived state (and thence to the mint). The login matches two mappings; the minimum (most
        // restrictive) wins.
        var config = Config(c =>
        {
            c.RoleClaim = "role";
            c.EnableParentalRatingRoles = true;
            c.ParentalRatingRoleMappings = new System.Collections.Generic.List<ParentalRatingRoleMap>
            {
                new ParentalRatingRoleMap { Score = 10, Roles = new[] { "teens" } },
                new ParentalRatingRoleMap { Score = 3, Roles = new[] { "kids" } },
            };
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("role", "teens"), ("role", "kids")),
            config);

        Assert.Equal(3, result.MaxParentalRatingScore);
    }

    [Fact]
    public void ParentalRating_FeatureOff_LeavesTheCeilingNull()
    {
        var config = Config(c =>
        {
            c.RoleClaim = "role";
            c.EnableParentalRatingRoles = false;
            c.ParentalRatingRoleMappings = new System.Collections.Generic.List<ParentalRatingRoleMap>
            {
                new ParentalRatingRoleMap { Score = 3, Roles = new[] { "kids" } },
            };
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("role", "kids")),
            config);

        Assert.Null(result.MaxParentalRatingScore);
    }

    [Fact]
    public void SyncPlayAccess_MatchedRole_CarriesTheMostRestrictiveLevelOnTheState()
    {
        // #827 wiring on the OpenID side: the SAME role list the other reductions read resolves the SyncPlay
        // level, and the most restrictive matched level wins - the LARGER enum value, not the smaller one.
        var config = Config(c =>
        {
            c.RoleClaim = "role";
            c.EnableSyncPlayAccessRoles = true;
            c.SyncPlayAccessRoleMappings = new System.Collections.Generic.List<SyncPlayAccessRoleMap>
            {
                new SyncPlayAccessRoleMap { Access = "CreateAndJoinGroups", Roles = new[] { "hosts" } },
                new SyncPlayAccessRoleMap { Access = "JoinGroups", Roles = new[] { "guests" } },
            };
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("role", "hosts"), ("role", "guests")),
            config);

        Assert.Equal(SyncPlayUserAccessType.JoinGroups, result.SyncPlayAccess);
    }

    [Fact]
    public void SyncPlayAccess_FeatureOff_LeavesTheLevelNull()
    {
        var config = Config(c =>
        {
            c.RoleClaim = "role";
            c.EnableSyncPlayAccessRoles = false;
            c.SyncPlayAccessRoleMappings = new System.Collections.Generic.List<SyncPlayAccessRoleMap>
            {
                new SyncPlayAccessRoleMap { Access = "None", Roles = new[] { "guests" } },
            };
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("role", "guests")),
            config);

        Assert.Null(result.SyncPlayAccess);
    }

    [Fact]
    public void AdminRole_GrantsAdmin_ViaNestedJsonRoleClaim()
    {
        var config = Config(c =>
        {
            c.AdminRoles = new[] { "admins" };
            c.RoleClaim = "realm_access.roles";
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("realm_access", "{\"roles\":[\"admins\"]}")),
            config);

        Assert.True(result.Admin);
    }

    [Fact]
    public void ARepeatedObjectValuedRoleClaim_WhoseCopiesDisagree_GrantsNeitherCopysRoles()
    {
        // With LoadProfile on (the default) OidcClient merges the UNSIGNED UserInfo response into the
        // principal, so a UserInfo body naming the role claim twice arrives here as two claims of one type.
        // Each copy is individually clean, so the value-level screen (#1005) never fires on it, and
        // appending them granted the UNION - the second copy's "admins" among them.
        //
        // The fixture is the exact document from #1040: {"realm_access": {...}, "realm_access": {...}}.
        var config = Config(c =>
        {
            c.AdminRoles = new[] { "admins" };
            c.RoleClaim = "realm_access.roles";
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(
                ("preferred_username", "alice"),
                ("realm_access", "{\"roles\":[\"users\"]}"),
                ("realm_access", "{\"roles\":[\"admins\"]}")),
            config);

        // Neither copy's roles are granted, not merely the second one's: a document that says two things
        // about the roles says nothing this login can act on.
        Assert.False(result.Admin);
        Assert.Empty(result.Folders);
    }

    [Fact]
    public void ARepeatedObjectValuedRoleClaim_WhoseCopiesAgree_StillGrants()
    {
        // The positive control for the row above, and the reason it compares rather than counts. A provider
        // that emits the role claim in BOTH the id_token and the UserInfo response produces two claims of
        // one type saying the same thing. Refusing on the count alone would take every role from that
        // ordinary deployment.
        var config = Config(c =>
        {
            c.AdminRoles = new[] { "admins" };
            c.RoleClaim = "realm_access.roles";
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(
                ("preferred_username", "alice"),
                ("realm_access", "{\"roles\":[\"admins\"]}"),
                ("realm_access", "{\"roles\":[\"admins\"]}")),
            config);

        Assert.True(result.Admin);
    }

    [Fact]
    public void ARepeatedObjectMapRoleClaim_WhoseCopiesDisagree_GrantsNothing()
    {
        // The object-map opt-in (#934) reads the roles from the property NAMES, and a one-segment path there
        // is still object-valued: the claim value IS the terminal object. So the same comparison applies,
        // and the row exists because the shape reaches a different branch of the extractor.
        var config = Config(c =>
        {
            c.AdminRoles = new[] { "admins" };
            c.RoleClaim = "urn:zitadel:iam:org:project:roles";
            c.RoleClaimIsObjectMap = true;
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(
                ("preferred_username", "alice"),
                ("urn:zitadel:iam:org:project:roles", "{\"users\":{\"7364\":\"example.com\"}}"),
                ("urn:zitadel:iam:org:project:roles", "{\"admins\":{\"7364\":\"example.com\"}}")),
            config);

        Assert.False(result.Admin);
    }

    [Fact]
    public void AProviderEmittingOneClaimPerGroup_KeepsBeingUnioned()
    {
        // The shape the comparison must NOT catch: a one-segment path over plain string values, where a
        // provider emits the claim once per group. Those copies are meant to be unioned - they are a list
        // written as repeated claims, not two statements about one object - so a rule that refused every
        // repeated role-claim type would silently strip the roles of every provider that emits groups this
        // way. Deliberately disagreeing values, which is exactly what makes the shape legitimate.
        var config = Config(c =>
        {
            c.AdminRoles = new[] { "admins" };
            c.RoleClaim = "groups";
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("groups", "users"), ("groups", "admins")),
            config);

        Assert.True(result.Admin);
    }

    [Fact]
    public void SubFallback_WhenNotValidAndRolesEmpty_UsesSubAndIsValid()
    {
        // No preferred-username claim, an empty (non-null) allow-list → the sub claim is the username
        // and, because the allow-list is empty, the login is valid.
        var config = Config(c => c.Roles = Array.Empty<string>());
        var result = OidcAuthorizeStateBuilder.Build(Claims(("sub", "subject-123")), config);

        Assert.Equal("subject-123", result.Username);
        Assert.True(result.Valid);
    }

    [Fact]
    public void SubFallback_NotReached_WhenAlreadyValid()
    {
        // A preferred-username claim with no allow-list makes the login valid, so the sub fallback
        // (which would overwrite the username) is not entered.
        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("sub", "subject-123")),
            Config(_ => { }));

        Assert.Equal("alice", result.Username);
        Assert.True(result.Valid);
    }

    [Fact]
    public void RoleClaimValidatesLoginButNoUsername_IsNotValid()
    {
        // The exact #95 role path: a role claim matching the allow-list makes the login valid via the
        // role-grant merge (not the username branch), but with no username/sub claim there is no
        // identity - the final clamp must reject it. Exercises grants.Valid=true with a null username.
        var config = Config(c =>
        {
            c.Roles = new[] { "jellyfin-users" };
            c.RoleClaim = "role";
        });

        var result = OidcAuthorizeStateBuilder.Build(Claims(("role", "jellyfin-users")), config);

        Assert.Null(result.Username);
        Assert.False(result.Valid);
    }

    [Fact]
    public void RoleGrantValid_NoUsernameClaim_IsNotValid()
    {
        // Fail closed (#95): a role matching the allow-list makes the login valid, but with no
        // username claim (and no sub claim) there is no identity to log in - previously this minted
        // a valid state whose null username failed downstream with a 500.
        var config = Config(c =>
        {
            c.Roles = new[] { "jellyfin-users" };
            c.RoleClaim = "role";
        });

        var result = OidcAuthorizeStateBuilder.Build(Claims(("role", "jellyfin-users")), config);

        Assert.Null(result.Username);
        Assert.False(result.Valid);
    }

    [Fact]
    public void RoleGrantValid_OnlySubClaim_IsNotValid()
    {
        // Fail closed (#95): the sub fallback only runs when the login is NOT yet valid, so a
        // role-grant-valid login with only a sub claim never resolves a username - it is rejected,
        // and the sub claim is deliberately NOT adopted (that would widen the fallback's semantics).
        var config = Config(c =>
        {
            c.Roles = new[] { "jellyfin-users" };
            c.RoleClaim = "role";
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("role", "jellyfin-users"), ("sub", "subject-123")),
            config);

        Assert.Null(result.Username);
        Assert.False(result.Valid);
    }

    [Fact]
    public void EmptyUsernameClaimValue_IsNotValid()
    {
        // Fail closed (#95): an empty username claim value is no identity either.
        var result = OidcAuthorizeStateBuilder.Build(Claims(("preferred_username", string.Empty)), Config(_ => { }));

        Assert.False(result.Valid);
    }

    [Fact]
    public void WhitespaceUsernameClaimValue_IsNotValid()
    {
        // Fail closed (#95): whitespace-only is no identity - Jellyfin's own username validation
        // rejects it, so accepting it here could only ever produce a downstream 500.
        var result = OidcAuthorizeStateBuilder.Build(Claims(("preferred_username", "   ")), Config(_ => { }));

        Assert.False(result.Valid);
    }

    [Fact]
    public void SubFallback_LastSubClaimWins()
    {
        var config = Config(c => c.Roles = Array.Empty<string>());
        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("sub", "first"), ("sub", "second")),
            config);

        Assert.Equal("second", result.Username);
        Assert.True(result.Valid);
    }

    [Fact]
    public void ValidViaRoleGrant_SubClaimDoesNotOverwriteUsername()
    {
        // Validity granted by the allow-list match keeps the fallback out, so the sub claim must not
        // replace the preferred-username value.
        var config = Config(c =>
        {
            c.Roles = new[] { "jellyfin-users" };
            c.RoleClaim = "role";
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("role", "jellyfin-users"), ("sub", "subject-123")),
            config);

        Assert.Equal("alice", result.Username);
        Assert.True(result.Valid);
    }

    [Fact]
    public void InvalidLogin_SubClaimStillOverwritesUsername()
    {
        // Faithful quirk: the sub fallback runs whenever the login is not (yet) valid, even though
        // a preferred-username claim already set the username - so a failed allow-list match with a
        // sub claim present ends invalid AND with the sub value as the username. Easily misread as
        // "fallback only when no username claim exists"; pinned here so a change is deliberate.
        var config = Config(c =>
        {
            c.Roles = new[] { "jellyfin-users" };
            c.RoleClaim = "role";
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("role", "outsiders"), ("sub", "subject-123")),
            config);

        Assert.Equal("subject-123", result.Username);
        Assert.False(result.Valid);
    }

    [Fact]
    public void EscapedDotInRoleClaim_IsTreatedAsLiteralDot()
    {
        // "realm\.access" is one segment named "realm.access", not a two-segment path.
        var config = Config(c =>
        {
            c.Roles = new[] { "jellyfin-users" };
            c.RoleClaim = "realm\\.access";
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("realm.access", "jellyfin-users")),
            config);

        Assert.True(result.Valid);
    }

    [Fact]
    public void SubFallback_NullRolesArray_Throws()
    {
        // Faithful to the original: the sub fallback does not null-check config.Roles, so when RBAC is
        // off (Roles == null) and only a sub claim is present, it throws (fails closed). Tracked in #89.
        var config = Config(c => c.Roles = null);

        Assert.Throws<NullReferenceException>(() => OidcAuthorizeStateBuilder.Build(Claims(("sub", "subject-123")), config));
    }

    [Fact]
    public void Subject_ExtractedFromSubClaim_IndependentOfUsername()
    {
        // The link key (#155) is the sub claim, derived independently of the username: a valid login
        // via preferred_username still surfaces the sub so the account can be keyed on it.
        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("sub", "subject-123")),
            Config(_ => { }));

        Assert.Equal("alice", result.Username);
        Assert.Equal("subject-123", result.Subject);
        Assert.True(result.Valid);
    }

    [Fact]
    public void Subject_NullWhenNoSubClaim()
    {
        // A provider that sends no sub leaves Subject null; the callback rejects such a valid login
        // (fail closed) rather than keying on the mutable username.
        var result = OidcAuthorizeStateBuilder.Build(Claims(("preferred_username", "alice")), Config(_ => { }));

        Assert.Equal("alice", result.Username);
        Assert.Null(result.Subject);
    }

    [Fact]
    public void Subject_LastSubWins()
    {
        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("sub", "first"), ("sub", "second")),
            Config(_ => { }));

        Assert.Equal("second", result.Subject);
    }

    [Fact]
    public void Subject_SurfacedEvenWhenLoginInvalid()
    {
        // Subject extraction does not depend on validity: a role-gated login that fails still carries
        // its sub (the callback rejects on validity, not on a missing subject here).
        var config = Config(c =>
        {
            c.Roles = new[] { "jellyfin-users" };
            c.RoleClaim = "role";
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("role", "outsiders"), ("sub", "subject-123")),
            config);

        Assert.False(result.Valid);
        Assert.Equal("subject-123", result.Subject);
    }

    [Fact]
    public void AvatarUrlFormat_ResolvedFromClaims()
    {
        var config = Config(c => c.AvatarUrlFormat = "https://avatars.example.com/@{sub}.png");
        var result = OidcAuthorizeStateBuilder.Build(Claims(("preferred_username", "alice"), ("sub", "123")), config);

        Assert.Equal("https://avatars.example.com/123.png", result.AvatarUrl);
    }

    [Fact]
    public void AvatarUrlFormat_ConfiguredTemplateWinsOverPictureClaim()
    {
        // The template always wins when configured; the picture-claim fallback is only for the no-template
        // case (#723), so a configured format is never silently overridden by a picture claim.
        var config = Config(c => c.AvatarUrlFormat = "https://avatars.example.com/@{sub}.png");
        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("sub", "123"), ("picture", "https://idp.example.com/pic.jpg")),
            config);

        Assert.Equal("https://avatars.example.com/123.png", result.AvatarUrl);
    }

    [Fact]
    public void NoAvatarUrlFormat_FallsBackToStandardPictureClaim()
    {
        // Zero-config parity (#723): with no template the resolver uses the standard OIDC `picture` claim,
        // so a standards-compliant IdP yields an avatar candidate without any configuration.
        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("picture", "https://idp.example.com/alice.jpg")),
            Config(_ => { }));

        Assert.Equal("https://idp.example.com/alice.jpg", result.AvatarUrl);
    }

    [Fact]
    public void EmptyAvatarUrlFormat_FallsBackToStandardPictureClaim()
    {
        // An empty template is treated the same as no template (null/empty → picture fallback, #723),
        // rather than resolving to an empty URL the way the pre-#723 aggregate did.
        var config = Config(c => c.AvatarUrlFormat = string.Empty);
        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("picture", "https://idp.example.com/alice.jpg")),
            config);

        Assert.Equal("https://idp.example.com/alice.jpg", result.AvatarUrl);
    }

    [Fact]
    public void NoAvatarUrlFormat_LastPictureClaimWins()
    {
        // Last wins, matching the subject/username/email_verified derivations.
        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("picture", "https://idp.example.com/old.jpg"), ("picture", "https://idp.example.com/new.jpg")),
            Config(_ => { }));

        Assert.Equal("https://idp.example.com/new.jpg", result.AvatarUrl);
    }

    [Fact]
    public void NoAvatarUrlFormat_NoPictureClaim_YieldsNull()
    {
        // No template and no picture claim: nothing to fetch, so the candidate is null (no fetch attempted).
        var result = OidcAuthorizeStateBuilder.Build(Claims(("preferred_username", "alice")), Config(_ => { }));
        Assert.Null(result.AvatarUrl);
    }

    [Fact]
    public void NoAvatarUrlFormat_PictureFallbackDisabled_YieldsNull()
    {
        // The admin opt-out (#723): with the picture fallback disabled and no template, no candidate is
        // produced even when the IdP sends a picture claim - nothing is fetched.
        var config = Config(c => c.DisableAvatarFromPictureClaim = true);
        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("picture", "https://idp.example.com/alice.jpg")),
            config);

        Assert.Null(result.AvatarUrl);
    }

    [Fact]
    public void AvatarUrlFormat_TemplateUnaffectedByPictureFallbackToggle()
    {
        // The opt-out only gates the no-template picture fallback; a configured template still resolves,
        // so disabling the fallback never silently drops an explicitly-configured avatar.
        var config = Config(c =>
        {
            c.AvatarUrlFormat = "https://avatars.example.com/@{sub}.png";
            c.DisableAvatarFromPictureClaim = true;
        });
        var result = OidcAuthorizeStateBuilder.Build(Claims(("preferred_username", "alice"), ("sub", "123")), config);

        Assert.Equal("https://avatars.example.com/123.png", result.AvatarUrl);
    }

    [Fact]
    public void NoAvatarUrlFormat_EmptyPictureClaim_YieldsNull()
    {
        // An empty picture value is treated as absent, so the caller skips the fetch rather than handing
        // an empty URL to AvatarUrlValidator.
        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("picture", string.Empty)),
            Config(_ => { }));

        Assert.Null(result.AvatarUrl);
    }

    [Fact]
    public void FolderRolesOff_CopiesEnabledFolders()
    {
        var config = Config(c =>
        {
            c.EnableFolderRoles = false;
            c.EnabledFolders = new[] { "movies", "shows" };
        });

        var result = OidcAuthorizeStateBuilder.Build(Claims(("preferred_username", "alice")), config);
        Assert.Equal(new List<string> { "movies", "shows" }, result.Folders);
    }

    [Fact]
    public void FolderRolesOn_AppendsRoleGrantedFolders()
    {
        var config = Config(c =>
        {
            c.EnableFolderRoles = true;
            c.RoleClaim = "role";
            c.FolderRoleMapping = new List<FolderRoleMap>
            {
                new FolderRoleMap { Role = "media", Folders = new List<string> { "movies" } },
            };
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("role", "media")),
            config);

        Assert.Equal(new List<string> { "movies" }, result.Folders);
    }

    [Fact]
    public void LiveTv_DefaultsFromConfig_ThenRoleGrantsAdd()
    {
        var config = Config(c =>
        {
            c.EnableLiveTv = true;
            c.EnableLiveTvManagement = false;
            c.EnableLiveTvRoles = true;
            c.RoleClaim = "role";
            c.LiveTvManagementRoles = new[] { "tv-admin" };
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(("preferred_username", "alice"), ("role", "tv-admin")),
            config);

        Assert.True(result.EnableLiveTv);            // from config default
        Assert.True(result.EnableLiveTvManagement);  // granted by the role
    }

    [Fact]
    public void ObjectMapRoleClaim_MatchesTheAllowList_WhenTheProviderOptsIn()
    {
        // #934, Zitadel's shape end to end: the role claim's property NAMES are the roles.
        var config = Config(c =>
        {
            c.Roles = new[] { "jellyfin-access" };
            c.RoleClaim = "urn:zitadel:iam:org:project:roles";
            c.RoleClaimIsObjectMap = true;
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(
                ("preferred_username", "alice"),
                ("urn:zitadel:iam:org:project:roles", "{\"jellyfin-access\":{\"orgid\":\"example.com\"}}")),
            config);

        Assert.Equal("alice", result.Username);
        Assert.True(result.Valid);
    }

    [Fact]
    public void ObjectMapRoleClaim_UnmatchedRole_IsRefused()
    {
        var config = Config(c =>
        {
            c.Roles = new[] { "jellyfin-access" };
            c.RoleClaim = "urn:zitadel:iam:org:project:roles";
            c.RoleClaimIsObjectMap = true;
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(
                ("preferred_username", "bob"),
                ("urn:zitadel:iam:org:project:roles", "{\"some-other-role\":{\"orgid\":\"example.com\"}}")),
            config);

        Assert.False(result.Valid);
    }

    [Fact]
    public void ObjectMapRoleClaim_WithoutOptIn_IsRefused()
    {
        // The default is unchanged: without the opt-in the same object claim grants nothing, so no existing
        // provider silently starts accepting a shape it did not before.
        var config = Config(c =>
        {
            c.Roles = new[] { "jellyfin-access" };
            c.RoleClaim = "urn:zitadel:iam:org:project:roles";
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(
                ("preferred_username", "alice"),
                ("urn:zitadel:iam:org:project:roles", "{\"jellyfin-access\":{\"orgid\":\"example.com\"}}")),
            config);

        Assert.False(result.Valid);
    }

    [Fact]
    public void ObjectMapRoleClaim_DoesNotReadTheValues()
    {
        // Only the property names are roles. Zitadel puts the granting org's id→domain map in the VALUE;
        // reading it would turn an org domain the user never had granted into a matching role.
        var config = Config(c =>
        {
            c.Roles = new[] { "jellyfin-access" };
            c.RoleClaim = "urn:zitadel:iam:org:project:roles";
            c.RoleClaimIsObjectMap = true;
        });

        var result = OidcAuthorizeStateBuilder.Build(
            Claims(
                ("preferred_username", "mallory"),
                ("urn:zitadel:iam:org:project:roles", "{\"nothing\":{\"orgid\":\"jellyfin-access\"}}")),
            config);

        Assert.False(result.Valid);
    }

    // --- the refused-role-claim audit trail (#1149) ---

    [Fact]
    public void AnUnreadableValue_AndAPathThatDoesNotResolve_AreAuditedApartByReasonCode()
    {
        // The whole point of the trail. Both logins end with no roles, and under a configured allow-list
        // both are denied, so from the operator's side they are one symptom with two very different causes:
        // a provider sending something the screen cannot read, and a role-claim path that does not match what
        // the provider actually emits. One entry each, and the codes must differ - a trail that gave both the
        // same code would be no better than the empty role set they already share.
        var unreadable = Audit(c => c.RoleClaim = "realm_access.roles", ("realm_access", "not-json-at-all"));
        var unresolved = Audit(c => c.RoleClaim = "realm_access.missing", ("realm_access", "{\"roles\":[\"a\"]}"));

        var first = Assert.Single(unreadable.Entries, e => e.Message.Contains("[SSO Audit]", StringComparison.Ordinal));
        var second = Assert.Single(unresolved.Entries, e => e.Message.Contains("[SSO Audit]", StringComparison.Ordinal));

        Assert.Equal(LogLevel.Warning, first.Level);
        Assert.Contains(OidcRoleExtractor.Outcome.Unreadable.ToString(), first.Message, StringComparison.Ordinal);
        Assert.Contains(OidcRoleExtractor.Outcome.PathNotResolved.ToString(), second.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(OidcRoleExtractor.Outcome.PathNotResolved.ToString(), first.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ARepeatedRoleMember_ReachesTheOperatorAsItsOwnReasonCode()
    {
        // A repeat is the one refusal an operator cannot diagnose from the outside: the document looks fine,
        // the path is right, and the login is simply denied. It gets its own code rather than sharing
        // Unreadable's, because the two ask for different actions - one is a provider serving bytes nobody can
        // read, the other is a provider serving a document that means two things (#1324).
        // The repeated member is named distinctively rather than being the role member itself, so the last
        // assertion is about a string that could only have come from the claim value.
        const string ProviderAuthoredName = "zzRepeatedMemberMarkerzz";
        var repeated = Audit(
            c => c.RoleClaim = "realm_access.roles",
            ("realm_access", "{\"roles\":[\"a\"],\"" + ProviderAuthoredName + "\":1,\"" + ProviderAuthoredName + "\":2}"));

        var entry = Assert.Single(repeated.Entries, e => e.Message.Contains("[SSO Audit]", StringComparison.Ordinal));

        Assert.Contains(OidcRoleExtractor.Outcome.RepeatedMember.ToString(), entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(OidcRoleExtractor.Outcome.Unreadable.ToString(), entry.Message, StringComparison.Ordinal);

        // The member name is provider-authored and must not travel: it is the one string in this refusal the
        // claim decides, and the trail carries reason codes only.
        Assert.DoesNotContain(ProviderAuthoredName, entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ALoginThatSimplyCarriedNoRoles_IsAuditedNotAtAll()
    {
        // Both directions of the positive control, and this is what keeps the trail a signal. A provider
        // that sends no role claim, and one that sends the claim with an empty terminal array, are both
        // working exactly as configured. An entry on either would land on ordinary logins, and an operator
        // who sees the warning on every login stops reading it.
        var noClaim = Audit(c => c.RoleClaim = "realm_access.roles", ("preferred_username", "alice"));
        var emptyArray = Audit(c => c.RoleClaim = "realm_access.roles", ("realm_access", "{\"roles\":[]}"));

        Assert.DoesNotContain(noClaim.Entries, e => e.Message.Contains("[SSO Audit]", StringComparison.Ordinal));
        Assert.DoesNotContain(emptyArray.Entries, e => e.Message.Contains("[SSO Audit]", StringComparison.Ordinal));
    }

    [Fact]
    public void TheRefusedClaimValueNeverReachesTheLog()
    {
        // A role claim carries group memberships, distinguished names and sometimes e-mail addresses. The
        // provider name and the reason code are the whole permitted payload, so the refusal is driven with a
        // value nothing else in the entry could produce and every captured record is searched for it.
        const string Marker = "CN=payroll-secret,OU=groups,DC=corp,DC=example";

        var log = Audit(c => c.RoleClaim = "realm_access.roles", ("realm_access", Marker));

        Assert.Contains(log.Entries, e => e.Message.Contains("[SSO Audit]", StringComparison.Ordinal));
        Assert.DoesNotContain(log.Records, r => r.Message.Contains(Marker, StringComparison.Ordinal));
        Assert.DoesNotContain(log.Records, r => r.Message.Contains("payroll-secret", StringComparison.Ordinal));
    }

    [Fact]
    public void RepeatedCopiesOfOneFailingClaim_AreAuditedOnce_AndTwoDIFFERENTFailuresAreBothKept()
    {
        // The chosen behaviour, stated so it is a decision rather than a side effect: once per distinct
        // reason per login. A provider that repeats its role claim - which happens on every login where
        // LoadProfile merges an UNSIGNED UserInfo response beside the id_token - would otherwise write one
        // entry per copy, and the number of copies is the provider's choice, not this plugin's.
        var repeated = Audit(
            c => c.RoleClaim = "realm_access.roles",
            ("realm_access", "not-json-at-all"),
            ("realm_access", "also-not-json"));

        Assert.Single(repeated.Entries, e => e.Message.Contains("[SSO Audit]", StringComparison.Ordinal));

        // And the bound is per REASON, not per login: two claims failing for different reasons are two
        // different things an operator has to fix, and collapsing them would hide one behind the other.
        var mixed = Audit(
            c => c.RoleClaim = "realm_access.roles",
            ("realm_access", "not-json-at-all"),
            ("realm_access", "{\"roles\":\"a-string-not-an-array\"}"));

        Assert.Equal(2, mixed.Entries.FindAll(e => e.Message.Contains("[SSO Audit]", StringComparison.Ordinal)).Count);
    }

    // Drives one login through the builder with a capturing logger, and hands back what it recorded.
    private static CapturingLogger Audit(Action<OidConfig> configure, params (string Type, string Value)[] claims)
    {
        var logger = new CapturingLogger();
        OidcAuthorizeStateBuilder.Build(Claims(claims), Config(configure), issuer: null, logger, "kc");
        return logger;
    }
}
