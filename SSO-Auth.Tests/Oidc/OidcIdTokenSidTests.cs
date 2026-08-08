// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using Jellyfin.Plugin.SSO_Auth.Api.Oidc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="OidcIdTokenSid"/> - the Single Logout capture reads the sid claim from the RAW,
/// signature-verified id_token (#727), never the UserInfo-merged principal, so a UserInfo-supplied sid
/// cannot poison the persisted logout key. A degenerate token yields null rather than throwing.
/// </summary>
public class OidcIdTokenSidTests
{
    [Fact]
    public void Read_TokenCarryingSid_ReturnsTheClaimValue()
        => Assert.Equal("sess-42", OidcIdTokenSid.Read(TokenWith(("sub", "user-1"), ("sid", "sess-42"))));

    [Fact]
    public void Read_TokenWithoutSid_ReturnsNull()
        => Assert.Null(OidcIdTokenSid.Read(TokenWith(("sub", "user-1"))));

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("not-a-jwt")]
    [InlineData("only.two")]
    [InlineData("...")]
    public void Read_AbsentOrDegenerateToken_ReturnsNullWithoutThrowing(string? token)
        => Assert.Null(OidcIdTokenSid.Read(token));

    [Fact]
    public void Read_MultiValuedSid_TakesTheLastElement()
    {
        // OIDC Core gives sid as a single string, so an array is a document the spec does not describe - and
        // it is a different shape from the repeated MEMBER of #1192, which folds to one claim before any
        // reader runs. An array reaches the reader as TWO claims of the same type, so the reader's choice
        // between them is real and, until this row, nothing in the suite could tell which one it made.
        //
        // Last rather than a refusal, and the same choice in all three readers. Refusing here would leave the
        // Single Logout capture (#727) with no sid at all, so a logout the IdP later orders for that session
        // would find no key and terminate nothing - the fail direction #1060 names as the wrong one on a
        // revocation path. Nothing is widened by taking a value: both elements arrived inside one
        // signature-verified token, so the IdP asserted both.
        Assert.Equal("sess-b", OidcIdTokenSid.Read(TokenWithArray("sid", "sess-a", "sess-b")));
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
