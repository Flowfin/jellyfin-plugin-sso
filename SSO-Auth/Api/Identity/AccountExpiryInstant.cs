// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Globalization;

namespace Jellyfin.Plugin.SSO_Auth.Api.Identity;

/// <summary>
/// Reads an account-expiry instant out of one raw identity-provider claim or attribute value (#1143), in
/// the two shapes an identity provider actually emits: a JWT <c>NumericDate</c> (RFC 7519, seconds since
/// the Unix epoch) and an ISO-8601 / RFC 3339 timestamp with or without an offset. Pure reading - it makes
/// no access decision, and what a missing instant MEANS for a configured claim is the enforcement step's
/// question (#1144), not this one's.
/// </summary>
/// <remarks>
/// The value is attacker-influenced and arrives on a public callback, so every shape this reader does not
/// understand yields <c>null</c> and nothing throws - the same contract <c>OidcRoleExtractor</c> documents
/// for #216. The instant is always UTC: #676 was exactly the bug a local-time read produces, an authorize
/// state expiring early across a DST step, so an offset-less value is read as UTC rather than as server
/// local time and every parsed result carries <see cref="DateTimeKind.Utc"/>.
/// <para>
/// This is a SECOND date reader in the tree, beside <c>SamlAssertionTime.TryParseUtc</c>, and that is
/// deliberate rather than an oversight. The module DAG gives <c>Identity</c> no import of <c>Saml</c>, and
/// <c>Oidc</c> may not import <c>Saml</c> either, so a reader both protocols can call cannot reach the SAML
/// one where it sits. Moving that parser down into this module is possible in principle and is NOT done
/// here: <c>TryParseUtc</c> is what the SAML <c>NotBefore</c>/<c>NotOnOrAfter</c> bounds are read through
/// and its <c>XmlConvert</c> choice is argued for #677, so moving it belongs in a change of its own with
/// the SAML time-bound suite as its oracle, not inside a feature branch. The two readers also answer
/// different questions: one reads a SIGNED SAML condition the plugin enforces, this one reads a claim value
/// that decides nothing on its own and yields null on anything it does not understand.
/// </para>
/// </remarks>
internal static class AccountExpiryInstant
{
    // ISO-8601 / RFC 3339 with a "T" separator, optional fractional seconds, and an offset that may be
    // "Z", "+hh:mm"/"-hh:mm", or absent. Parsing against an EXPLICIT format list rather than the general
    // DateTimeOffset.TryParse is the fail-closed choice on an attacker-influenced value: the general parse
    // also accepts shapes that are not instants at all - a bare time is completed against TODAY'S date, a
    // bare "yyyy-MM" against the first of that month - and each of those would hand the enforcement step a
    // confident deadline the provider never stated. Measured, not assumed: see
    // AccountExpiryInstantTests.GeneralParseShapes_ThisReaderRefuses.
    private static readonly string[] TimestampFormats =
    {
        "yyyy-MM-dd'T'HH:mm:ssK",
        "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFK",
    };

    /// <summary>
    /// Reads the expiry instant a raw claim value carries.
    /// </summary>
    /// <param name="raw">The raw claim or attribute value; null, blank, and every unrecognised shape yield null.</param>
    /// <returns>The expiry instant in UTC, or null when the value carries none this reader understands.</returns>
    internal static DateTime? Read(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var value = raw.Trim();
        return ReadNumericDate(value) ?? ReadTimestamp(value);
    }

    // A JWT NumericDate: seconds since 1970-01-01T00:00:00Z, serialised as a JSON number and reaching a
    // claim as its digits. An all-digit value is read here and never as a separator-less calendar date,
    // because NumericDate is the only all-digit instant either protocol defines and a compact "20261231"
    // is neither RFC 3339 nor xsd:dateTime.
    //
    // NumberStyles.None is the shape check: it refuses a sign, a thousands separator and surrounding
    // whitespace, so only bare digits are read as an instant. The invariant culture is stated for the
    // separator conventions None would otherwise take from the server's locale, and NOT as a guard against
    // digits of another script - .NET's integer parse takes ASCII digits under every culture, which is
    // measured in AccountExpiryInstantTests.DigitsOfAnotherScript_AreNotReadAsANumericDate rather than
    // assumed here.
    private static DateTime? ReadNumericDate(string value)
    {
        if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds))
        {
            return null;
        }

        // FromUnixTimeSeconds throws outside the representable range, and a claim is free to carry a
        // number no calendar can hold, so the range is checked rather than caught.
        if (seconds > DateTimeOffset.MaxValue.ToUnixTimeSeconds())
        {
            return null;
        }

        return DateTimeOffset.FromUnixTimeSeconds(seconds).UtcDateTime;
    }

    // AssumeUniversal reads an offset-less value as UTC (never as server local time, #676) and
    // AdjustToUniversal normalises a stated offset onto the same basis, so both branches return a
    // Kind=Utc instant that a downstream comparison against DateTime.UtcNow cannot mismatch.
    private static DateTime? ReadTimestamp(string value)
    {
        return DateTimeOffset.TryParseExact(
            value,
            TimestampFormats,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var parsed)
            ? parsed.UtcDateTime
            : null;
    }
}
