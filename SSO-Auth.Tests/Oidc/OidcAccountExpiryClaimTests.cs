// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Security.Claims;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests the OpenID half of the account-expiry read (#1143): the configured claim reaches the derived
/// authorize state as a UTC instant, a dotted path walks into the claim's JSON exactly as the role claim's
/// does, and a provider that configures no claim derives the state it derived before.
/// </summary>
public class OidcAccountExpiryClaimTests
{
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
    public void NoExpiryClaimConfigured_DerivesNoInstant()
    {
        // The regression that matters most here: the feature is off by default, so a provider that never
        // heard of it must derive exactly what it derived before. A claim that WOULD parse is present, so
        // this fails if the reader ever guesses a claim name instead of being told one.
        var derived = OidcAuthorizeStateBuilder.Build(
            Claims(("sub", "alice"), ("exp_at", "1893456000")),
            new OidConfig { Roles = Array.Empty<string>() });

        Assert.Null(derived.ExpiresAtUtc);
    }

    [Theory]
    [InlineData("1893456000")]
    [InlineData("2030-01-01T00:00:00Z")]
    [InlineData("2030-01-01T01:00:00+01:00")]
    [InlineData("2030-01-01T00:00:00")]
    public void AConfiguredClaim_IsReadInEveryShapeAProviderEmits(string value)
    {
        var derived = OidcAuthorizeStateBuilder.Build(
            Claims(("sub", "alice"), ("expires_at", value)),
            new OidConfig { Roles = Array.Empty<string>(), AccountExpiryClaim = "expires_at" });

        Assert.Equal(new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc), derived.ExpiresAtUtc);
    }

    [Fact]
    public void AnInstantInThePast_IsCarriedRatherThanDroppedAtTheRead()
    {
        // Nothing here decides anything, so an already-passed deadline has to survive the read intact:
        // dropping it would leave the enforcement step (#1144) unable to tell "expired" from "no deadline".
        var derived = OidcAuthorizeStateBuilder.Build(
            Claims(("expires_at", "946684800")),
            new OidConfig { Roles = Array.Empty<string>(), AccountExpiryClaim = "expires_at" });

        Assert.Equal(new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc), derived.ExpiresAtUtc);
    }

    [Fact]
    public void AnInstantFarInTheFuture_IsCarried()
    {
        var derived = OidcAuthorizeStateBuilder.Build(
            Claims(("expires_at", "9999999999")),
            new OidConfig { Roles = Array.Empty<string>(), AccountExpiryClaim = "expires_at" });

        Assert.Equal(new DateTime(2286, 11, 20, 17, 46, 39, DateTimeKind.Utc), derived.ExpiresAtUtc);
    }

    [Fact]
    public void AConfiguredClaimTheLoginDoesNotCarry_DerivesNoInstant()
    {
        var derived = OidcAuthorizeStateBuilder.Build(
            Claims(("sub", "alice")),
            new OidConfig { Roles = Array.Empty<string>(), AccountExpiryClaim = "expires_at" });

        Assert.Null(derived.ExpiresAtUtc);
    }

    [Theory]
    [InlineData("never")]
    [InlineData("")]
    [InlineData("2030-13-45T99:99:99Z")]
    public void AClaimValueThatIsNeitherShape_DerivesNoInstantAndDoesNotThrow(string value)
    {
        var derived = OidcAuthorizeStateBuilder.Build(
            Claims(("expires_at", value)),
            new OidConfig { Roles = Array.Empty<string>(), AccountExpiryClaim = "expires_at" });

        Assert.Null(derived.ExpiresAtUtc);
    }

    [Fact]
    public void NestedNumericDate_IsReadThroughThePath()
    {
        var derived = OidcAuthorizeStateBuilder.Build(
            Claims(("attrs", "{\"account\":{\"expires_at\":1893456000}}")),
            new OidConfig { Roles = Array.Empty<string>(), AccountExpiryClaim = "attrs.account.expires_at" });

        Assert.Equal(new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc), derived.ExpiresAtUtc);
    }

    [Fact]
    public void NestedIsoTimestamp_IsReadThroughThePath()
    {
        // The case Newtonsoft's default date handling silently breaks: it would turn this member into a
        // DateTime token, and reading that back as a string yields the round-trip form rather than the
        // provider's bytes, which this reader refuses. Delete DateParseHandling.None and this goes red.
        var derived = OidcAuthorizeStateBuilder.Build(
            Claims(("attrs", "{\"account\":{\"expires_at\":\"2030-01-01T00:00:00Z\"}}")),
            new OidConfig { Roles = Array.Empty<string>(), AccountExpiryClaim = "attrs.account.expires_at" });

        Assert.Equal(new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc), derived.ExpiresAtUtc);
    }

    [Theory]
    [InlineData("{\"account\":{\"other\":1893456000}}")]
    [InlineData("{\"account\":\"not-an-object\"}")]
    [InlineData("{\"account\":{\"expires_at\":{\"at\":1893456000}}}")]
    [InlineData("{\"account\":{\"expires_at\":[1893456000]}}")]
    [InlineData("not json at all")]
    [InlineData("[1893456000]")]
    public void ANestedPathThatDoesNotResolveToAScalar_DerivesNoInstantAndDoesNotThrow(string claimValue)
    {
        var derived = OidcAuthorizeStateBuilder.Build(
            Claims(("attrs", claimValue)),
            new OidConfig { Roles = Array.Empty<string>(), AccountExpiryClaim = "attrs.account.expires_at" });

        Assert.Null(derived.ExpiresAtUtc);
    }

    [Fact]
    public void AScopeTheWalkEntersNamingAMemberTwice_DerivesNoInstant()
    {
        // Two statements about the same deadline, and which one wins would be Newtonsoft's choice rather
        // than the document's, so the screen refuses ahead of the parse - the same posture the role claim
        // takes for #1324. Remove the StrictJson.Inspect call and this goes red.
        var derived = OidcAuthorizeStateBuilder.Build(
            Claims(("attrs", "{\"account\":{\"expires_at\":1893456000,\"expires_at\":253370764800}}")),
            new OidConfig { Roles = Array.Empty<string>(), AccountExpiryClaim = "attrs.account.expires_at" });

        Assert.Null(derived.ExpiresAtUtc);
    }

    [Fact]
    public void ARepeatOutsideTheScopesTheWalkEnters_StillReadsTheInstant()
    {
        // The other half of #1324's rule, and the reason the screen is given the entered scopes rather than
        // the whole document: a vendor extension repeating a name somewhere this walk never goes decides
        // nothing here, and refusing on it would take a working provider's deadline away for no reason.
        var derived = OidcAuthorizeStateBuilder.Build(
            Claims(("attrs", "{\"account\":{\"expires_at\":1893456000},\"other\":{\"x\":1,\"x\":2}}")),
            new OidConfig { Roles = Array.Empty<string>(), AccountExpiryClaim = "attrs.account.expires_at" });

        Assert.Equal(new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc), derived.ExpiresAtUtc);
    }

    [Fact]
    public void SeveralCopiesOfTheClaim_TheLastOneWins()
    {
        // The rule the subject, email_verified and picture resolvers in this builder already follow. Stated
        // as a test so the expiry read cannot drift into a different one unnoticed.
        var derived = OidcAuthorizeStateBuilder.Build(
            Claims(("expires_at", "946684800"), ("expires_at", "1893456000")),
            new OidConfig { Roles = Array.Empty<string>(), AccountExpiryClaim = "expires_at" });

        Assert.Equal(new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc), derived.ExpiresAtUtc);
    }

    [Fact]
    public void AnUnreadableLaterCopy_LeavesTheReadableOneStanding()
    {
        // Last-wins is over the instants the reader RESOLVED, not over the raw copies: a later copy that
        // parses to nothing is absent rather than a statement that the deadline was withdrawn.
        var derived = OidcAuthorizeStateBuilder.Build(
            Claims(("expires_at", "1893456000"), ("expires_at", "never")),
            new OidConfig { Roles = Array.Empty<string>(), AccountExpiryClaim = "expires_at" });

        Assert.Equal(new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc), derived.ExpiresAtUtc);
    }

    [Fact]
    public void ConfiguringAnExpiryClaim_ChangesNothingElseAboutTheDerivedState()
    {
        // The claim is read and nothing more: no privilege, no validity, no username moves because a
        // deadline was carried. Comparing the two states field by field is what makes "pure reading" a
        // property rather than a sentence in a commit message.
        var claims = Claims(("preferred_username", "alice"), ("sub", "alice-sub"), ("expires_at", "1893456000"));
        var without = OidcAuthorizeStateBuilder.Build(claims, new OidConfig { Roles = Array.Empty<string>() });
        var with = OidcAuthorizeStateBuilder.Build(claims, new OidConfig { Roles = Array.Empty<string>(), AccountExpiryClaim = "expires_at" });

        Assert.Equal(without.Username, with.Username);
        Assert.Equal(without.Subject, with.Subject);
        Assert.Equal(without.Issuer, with.Issuer);
        Assert.Equal(without.EmailVerified, with.EmailVerified);
        Assert.Equal(without.Valid, with.Valid);
        Assert.Equal(without.Admin, with.Admin);
        Assert.Equal(without.EnableLiveTv, with.EnableLiveTv);
        Assert.Equal(without.EnableLiveTvManagement, with.EnableLiveTvManagement);
        Assert.Equal(without.Folders, with.Folders);
        Assert.Equal(without.AvatarUrl, with.AvatarUrl);
        Assert.Equal(without.PermissionGrants, with.PermissionGrants);
        Assert.Equal(without.MaxParentalRatingScore, with.MaxParentalRatingScore);
        Assert.Null(without.ExpiresAtUtc);
        Assert.NotNull(with.ExpiresAtUtc);
    }
}
