// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api.Saml;
using Jellyfin.Plugin.SSO_Auth.Config;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests the SAML half of the account-expiry read (#1143). The instant is read from a SIGNED assertion
/// attribute, so every fixture here goes through the real signature path rather than a hand-built response,
/// and the same two-sided property holds as on the OpenID side: the shapes an identity provider emits are
/// read, everything else resolves to no instant and nothing throws.
/// </summary>
[Collection("SSOController")]
public class SamlAccountExpiryAttributeTests
{
    private static readonly DateTime ExpectedUtc = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private static DateTime? ReadExpiry(string? configuredAttribute, params string[] values)
    {
        SamlAssertionValidator.ResetReplaysForTests();
        var fixture = SamlTestFactory.Create(
            nameId: "alice",
            extraAttributeName: values.Length == 0 ? null : "expiresAt",
            extraAttributeValues: values);
        var response = new SamlResponse(fixture.CertificateBase64, fixture.EncodeResponse());

        var produced = new SamlAssertionValidator(Substitute.For<ILogger>()).TryProduceVerifiedIdentity(
            new SamlConfig { AccountExpiryClaim = configuredAttribute },
            "adfs",
            response,
            new List<string> { "jellyfin-users" },
            out var identity,
            out _);

        Assert.True(produced);
        Assert.NotNull(identity);
        return identity.ExpiresAtUtc;
    }

    [Fact]
    public void NoExpiryAttributeConfigured_ReadsNoInstant()
    {
        // Off by default: an assertion that happens to carry the attribute changes nothing for a provider
        // that never configured one. This is the regression the rest of the SAML suite would not catch.
        Assert.Null(ReadExpiry(null, "1893456000"));
    }

    [Theory]
    [InlineData("1893456000")]
    [InlineData("2030-01-01T00:00:00Z")]
    [InlineData("2030-01-01T01:00:00+01:00")]
    [InlineData("2030-01-01T00:00:00")]
    public void AConfiguredAttribute_IsReadInEveryShapeAProviderEmits(string value)
    {
        Assert.Equal(ExpectedUtc, ReadExpiry("expiresAt", value));
    }

    [Fact]
    public void AnInstantInThePast_IsCarriedRatherThanDroppedAtTheRead()
    {
        Assert.Equal(new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc), ReadExpiry("expiresAt", "946684800"));
    }

    [Fact]
    public void AnInstantFarInTheFuture_IsCarried()
    {
        Assert.Equal(new DateTime(2286, 11, 20, 17, 46, 39, DateTimeKind.Utc), ReadExpiry("expiresAt", "9999999999"));
    }

    [Fact]
    public void AConfiguredAttributeTheAssertionDoesNotCarry_ReadsNoInstant()
    {
        Assert.Null(ReadExpiry("expiresAt"));
    }

    [Theory]
    [InlineData("never")]
    [InlineData("2030-13-45T99:99:99Z")]
    [InlineData("<expires>2030</expires>")]
    public void AnAttributeValueThatIsNeitherShape_ReadsNoInstantAndDoesNotThrow(string value)
    {
        // The third case is the one worth keeping: an attribute value is administrator-named and
        // provider-supplied, and the reader must treat markup as text it does not understand rather than as
        // anything to resolve.
        Assert.Null(ReadExpiry("expiresAt", value));
    }

    [Fact]
    public void SeveralValuesUnderOneAttribute_TheLastOneWins()
    {
        // A multi-valued attribute is a shape real identity providers emit, and the rule is the OpenID one
        // so a deployment note covers both protocols rather than one each.
        Assert.Equal(ExpectedUtc, ReadExpiry("expiresAt", "946684800", "1893456000"));
    }

    [Fact]
    public void AnUnreadableLaterValue_LeavesTheReadableOneStanding()
    {
        Assert.Equal(ExpectedUtc, ReadExpiry("expiresAt", "1893456000", "never"));
    }

    [Fact]
    public void AnAttributeNameCarryingAnXPathPayload_SelectsNothingAndReadsNoInstant()
    {
        // The attribute name comes from configuration and reaches GetCustomAttributes, which compares @Name
        // in C# against a CONSTANT XPath for exactly this reason (#678). A name that would break out of a
        // quoted predicate must therefore select nothing rather than every Attribute node - and the
        // assertion below does carry a readable deadline, so a selector that matched anything at all would
        // return one and redden this.
        Assert.Null(ReadExpiry("'] | //*['", "1893456000"));
    }

    [Fact]
    public void ConfiguringAnExpiryAttribute_ChangesNothingElseAboutTheVerifiedIdentity()
    {
        SamlAssertionValidator.ResetReplaysForTests();
        var fixture = SamlTestFactory.Create(nameId: "alice", extraAttributeName: "expiresAt", extraAttributeValues: new[] { "1893456000" });
        var encoded = fixture.EncodeResponse();
        var validator = new SamlAssertionValidator(Substitute.For<ILogger>());

        validator.TryProduceVerifiedIdentity(
            new SamlConfig(),
            "adfs",
            new SamlResponse(fixture.CertificateBase64, encoded),
            new List<string> { "jellyfin-users" },
            out var without,
            out _);

        SamlAssertionValidator.ResetReplaysForTests();
        validator.TryProduceVerifiedIdentity(
            new SamlConfig { AccountExpiryClaim = "expiresAt" },
            "adfs",
            new SamlResponse(fixture.CertificateBase64, encoded),
            new List<string> { "jellyfin-users" },
            out var with,
            out _);

        Assert.NotNull(without);
        Assert.NotNull(with);
        Assert.Equal(without.Subject, with.Subject);
        Assert.Equal(without.Username, with.Username);
        Assert.Equal(without.Admin, with.Admin);
        Assert.Equal(without.EnableLiveTv, with.EnableLiveTv);
        Assert.Equal(without.EnableLiveTvManagement, with.EnableLiveTvManagement);
        Assert.Equal(without.Folders, with.Folders);
        Assert.Equal(without.EmailVerified, with.EmailVerified);
        Assert.Equal(without.AvatarUrl, with.AvatarUrl);
        Assert.Equal(without.MaxParentalRatingScore, with.MaxParentalRatingScore);
        Assert.Null(without.ExpiresAtUtc);
        Assert.Equal(ExpectedUtc, with.ExpiresAtUtc);
    }
}
