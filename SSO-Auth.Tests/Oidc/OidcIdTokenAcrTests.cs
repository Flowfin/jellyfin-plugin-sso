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
        // session satisfies the requirement. OIDC Core gives acr as one string, so a provider sending an
        // array is already outside the spec.
        //
        // This is the reader where a refusal would have been the fail-closed answer, since refusing an
        // ambiguous assurance level denies rather than grants. It is still pinned to the last element, so all
        // three readers say the same thing about the same shape, and the row exists so that turning acr into
        // the exception is a deliberate change with a red test rather than a silent divergence. Nothing here
        // asserts that last-wins is the RIGHT answer for a gate - only that it is the answer, and that it can
        // no longer change unnoticed.
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
