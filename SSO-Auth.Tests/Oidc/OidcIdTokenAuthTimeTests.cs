// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="OidcIdTokenAuthTime"/> - the max_age gate reads auth_time from the RAW, signature-
/// verified id_token (#961), never the UserInfo-merged principal. A numeric auth_time parses; an absent,
/// non-numeric, negative, or degenerate one yields null so the caller's fail-closed check refuses it.
/// </summary>
public class OidcIdTokenAuthTimeTests
{
    [Fact]
    public void Read_TokenCarryingAuthTime_ReturnsTheSeconds()
        => Assert.Equal(1_700_000_000L, OidcIdTokenAuthTime.Read(TokenWith(("sub", "user-1"), ("auth_time", 1_700_000_000L))));

    [Fact]
    public void Read_TokenWithoutAuthTime_ReturnsNull()
        => Assert.Null(OidcIdTokenAuthTime.Read(TokenWith(("sub", "user-1"))));

    [Fact]
    public void Read_NegativeAuthTime_ReadsAsNull_Malformed()
        => Assert.Null(OidcIdTokenAuthTime.Read(TokenWith(("auth_time", -5L))));

    [Fact]
    public void Read_NonNumericAuthTime_ReadsAsNull()
        => Assert.Null(OidcIdTokenAuthTime.Read(TokenWith(("auth_time", "yesterday"))));

    [Theory]
    [InlineData(253_402_300_800L)] // one past the DateTimeOffset upper bound
    [InlineData(1_700_000_000_000L)] // auth_time in MILLISECONDS (a common provider mistake)
    [InlineData(long.MaxValue)]
    public void Read_OutOfRangeAuthTime_ReadsAsNull_NoThrow(long value)
        => Assert.Null(OidcIdTokenAuthTime.Read(TokenWith(("auth_time", value))));

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("not-a-jwt")]
    [InlineData("only.two")]
    [InlineData("...")]
    public void Read_AbsentOrDegenerateToken_ReturnsNullWithoutThrowing(string? token)
        => Assert.Null(OidcIdTokenAuthTime.Read(token));

    [Fact]
    public void Read_MultiValuedAuthTime_TakesTheLastElement()
    {
        // The third reader over the same shape: an array-valued auth_time arrives as two claims, and which
        // one is taken decides the moment the max_age gate measures freshness from (#961) - here the later
        // element is also the more permissive one, which is why it is pinned rather than left implicit.
        //
        // This reader parses what it takes, so an array whose last element is not a whole number of seconds
        // still reads as absent and the caller still fails closed; the row below is that half.
        Assert.Equal(1_700_000_200L, OidcIdTokenAuthTime.Read(TokenWithArray("auth_time", 1_700_000_100L, 1_700_000_200L)));
    }

    [Fact]
    public void Read_MultiValuedAuthTimeEndingInANonNumber_ReadsAsNull()
        => Assert.Null(OidcIdTokenAuthTime.Read(TokenWithArray("auth_time", 1_700_000_100L, "yesterday")));

    private static string TokenWithArray(string type, params object[] values)
        => new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object> { ["sub"] = "user-1", [type] = values },
        });

    private static string TokenWith(params (string Type, object Value)[] claims)
    {
        var dict = new Dictionary<string, object>();
        foreach (var (type, value) in claims)
        {
            dict[type] = value;
        }

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor { Claims = dict });
    }
}
