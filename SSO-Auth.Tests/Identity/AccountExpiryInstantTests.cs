// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Globalization;
using Jellyfin.Plugin.SSO_Auth.Api.Identity;
using Xunit;

namespace Jellyfin.Plugin.SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="AccountExpiryInstant"/>, the reader both protocols take an account-expiry claim
/// value through (#1143). The value is attacker-influenced and arrives on a public callback, so the
/// property under test is two-sided: every shape an identity provider really emits resolves to the right
/// UTC instant, and every shape the reader does not understand resolves to no instant at all, without
/// throwing.
/// </summary>
public class AccountExpiryInstantTests
{
    [Fact]
    public void NumericDate_IsReadAsSecondsSinceTheUnixEpoch()
    {
        // RFC 7519 NumericDate, the shape a JWT claim carries: 2030-01-01T00:00:00Z.
        Assert.Equal(new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc), AccountExpiryInstant.Read("1893456000"));
    }

    [Fact]
    public void NumericDate_ResolvesAUtcInstant()
    {
        // #676 was a local-time read of an expiry giving early expiry across a DST step. A deadline whose
        // Kind is Unspecified compares against DateTime.UtcNow as if it were local, so the Kind is the
        // property and not an incidental detail of how it was parsed.
        Assert.Equal(DateTimeKind.Utc, AccountExpiryInstant.Read("1893456000")!.Value.Kind);
    }

    [Theory]
    [InlineData("2030-01-01T00:00:00Z")]
    [InlineData("2030-01-01T01:00:00+01:00")]
    [InlineData("2029-12-31T23:00:00-01:00")]
    [InlineData("2030-01-01T00:00:00")]
    [InlineData("2030-01-01T00:00:00.000Z")]
    public void IsoTimestamps_WithAndWithoutAnOffset_NormaliseToTheSameUtcInstant(string raw)
    {
        // The offset-less case is the one worth stating: it is read as UTC rather than as this server's
        // local time, so the same assertion holds on a machine in any zone (#676).
        var read = AccountExpiryInstant.Read(raw);

        Assert.Equal(new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc), read);
        Assert.Equal(DateTimeKind.Utc, read!.Value.Kind);
    }

    [Fact]
    public void AnInstantInThePast_IsReadRatherThanRefused()
    {
        // A deadline that has passed is exactly the case the enforcement step exists for, so the reader
        // must hand it over rather than treat it as nonsense. Reading is not deciding (#1144 decides).
        Assert.Equal(new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc), AccountExpiryInstant.Read("946684800"));
    }

    [Fact]
    public void AnInstantFarInTheFuture_IsReadRatherThanRefused()
    {
        Assert.Equal(new DateTime(2286, 11, 20, 17, 46, 39, DateTimeKind.Utc), AccountExpiryInstant.Read("9999999999"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("never")]
    [InlineData("2030-13-45T99:99:99Z")]
    [InlineData("{\"exp\":1893456000}")]
    [InlineData("1893456000; DROP")]
    [InlineData("99999999999999999999999")]
    public void AValueTheReaderDoesNotUnderstand_YieldsNoInstantAndDoesNotThrow(string? raw)
    {
        // The whole set in one place, because the contract is "null on anything else" rather than a list of
        // named refusals: a claim value is attacker-influenced and a throw here is a 500 on a public
        // callback (#216). The last entry is a digit string past every calendar's range, which is the case
        // an unchecked FromUnixTimeSeconds throws on.
        Assert.Null(AccountExpiryInstant.Read(raw));
    }

    [Theory]
    [InlineData("١٨٩٣٤٥٦٠٠٠")]
    [InlineData("１８９３４５６０００")]
    public void DigitsOfAnotherScript_AreNotReadAsANumericDate(string raw)
    {
        // char.IsDigit is true for the decimal digits of every script and long.TryParse accepts several of
        // them, so a homoglyph deadline would parse to a real instant under the obvious spelling of this
        // reader. The digits are matched one by one against '0'..'9' for that reason, and this is the test
        // that goes red if that is ever relaxed to char.IsDigit.
        Assert.Null(AccountExpiryInstant.Read(raw));
    }

    [Theory]
    [InlineData("23:59")]
    [InlineData("2030-01")]
    [InlineData("01/01/2030")]
    public void GeneralParseShapes_ThisReaderRefuses(string raw)
    {
        // Measured rather than assumed, and the reason the reader parses against an explicit format list
        // instead of DateTimeOffset.TryParse: the general parse accepts every one of these. A bare time is
        // completed against TODAY, a bare year-month against the first of that month, and the slash form is
        // a locale convention no protocol here defines - each would hand the enforcement step a deadline the
        // provider never stated.
        Assert.True(DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.None, out _), $"The general parse was expected to accept {raw}.");
        Assert.Null(AccountExpiryInstant.Read(raw));
    }

    [Fact]
    public void SurroundingWhitespace_DoesNotHideAnInstant()
    {
        Assert.Equal(new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc), AccountExpiryInstant.Read("  2030-01-01T00:00:00Z  "));
    }
}
