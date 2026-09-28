// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="OidcIdTokenAcr"/> - the step-up gate reads the acr claim from the RAW, signature-
/// verified id_token (#757), never the UserInfo-merged principal, so a UserInfo-supplied acr cannot satisfy
/// the requirement. A degenerate token yields null (fail-closed at the gate) rather than throwing.
/// </summary>
public class OidcIdTokenAcrTests
{
    [Fact]
    public void Read_TokenCarryingAcr_ReturnsTheClaimValue()
        => Assert.Equal("mfa", OidcIdTokenAcr.Read(TokenWith(("sub", "user-1"), ("acr", "mfa"))));

    [Fact]
    public void Read_TokenWithoutAcr_ReturnsNull()
        => Assert.Null(OidcIdTokenAcr.Read(TokenWith(("sub", "user-1"))));

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("not-a-jwt")]
    [InlineData("only.two")]
    [InlineData("...")]
    public void Read_AbsentOrDegenerateToken_ReturnsNullWithoutThrowing(string? token)
        => Assert.Null(OidcIdTokenAcr.Read(token));

    [Fact]
    public void Read_MultiValuedAcr_TakesTheLastElement()
    {
        // The same shape as the sid row, on the claim the step-up gate compares (#757): an array-valued acr
        // reaches this reader as two claims of the same type, and which one is taken decides whether the
        // session satisfies the requirement, while OIDC Core gives acr as one string. This is the reader where
        // a refusal would have been the fail-closed answer, and it is still pinned to the last element so all
        // three readers say the same thing; the row exists so that making acr the exception is a deliberate
        // change with a red test. Nothing here asserts that last-wins is the right answer for a gate.
        Assert.Equal("acr-b", OidcIdTokenAcr.Read(TokenWithArray("acr", "acr-a", "acr-b")));
    }

    private static string TokenWithArray(string type, params string[] values)
        => new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object> { ["sub"] = "user-1", [type] = values },
        });

    private static string TokenWith(params (string Type, string Value)[] claims)
    {
        var dict = new Dictionary<string, object>();
        foreach (var (type, value) in claims)
        {
            dict[type] = value;
        }

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor { Claims = dict });
    }
}
