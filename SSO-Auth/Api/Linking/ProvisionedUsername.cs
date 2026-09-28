// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Globalization;
using System.Text;

namespace Jellyfin.Plugin.SSO_Auth.Api.Linking;

/// <summary>Maps an identity-provider-supplied username to the name a brand-new Jellyfin account is created under (#1137); name presentation only, because resolution stays keyed on the subject.</summary>
/// <remarks>
/// Jellyfin's <c>CreateUserAsync</c> refuses a name outside its own allowlist, which lives off the surface the
/// plugin compiles against, so this is a hand copy pinned by a conformance rule to the one in-repo record of it,
/// taken in the conservative direction. Rejected characters are dropped rather than substituted, so a name made
/// only of them is visible as an empty result rather than an invented name, and the map is idempotent. An
/// all-dots result is treated as no result, because <c>.</c> and <c>..</c> escape the profile directory (#447).
/// </remarks>
internal static class ProvisionedUsername
{
    /// <summary>
    /// The characters Jellyfin's username check accepts that are not matched by the Unicode
    /// <c>\w</c> class - the literal members of <c>[\w \-'._@+]</c>. Kept as one string so the
    /// conformance rule can read it back out of the source and compare it to the recorded regex.
    /// </summary>
    internal const string AllowedPunctuation = " -'._@+";

    /// <summary>
    /// Maps an IdP-supplied username to the name a new account may be provisioned under, dropping every
    /// character Jellyfin's own check refuses.
    /// </summary>
    /// <param name="raw">The raw IdP-supplied username. Null, empty and whitespace-only all yield no name.</param>
    /// <param name="provisioned">
    /// On success, the sanitized name - non-empty, made only of accepted characters, with no leading or
    /// trailing space, and not made only of dots. Otherwise the empty string.
    /// </param>
    /// <returns>True when a name survived sanitization; false when nothing usable is left.</returns>
    internal static bool TrySanitize(string? raw, out string provisioned)
    {
        provisioned = string.Empty;
        if (string.IsNullOrEmpty(raw))
        {
            return false;
        }

        var kept = new StringBuilder(raw.Length);
        foreach (var character in raw)
        {
            if (IsAccepted(character))
            {
                kept.Append(character);
            }
        }

        // The host anchors forbid a leading or trailing whitespace character. Space is the only whitespace
        // the allowlist admits, so trimming it is the whole of that rule after the filter has run.
        var trimmed = kept.ToString().Trim(' ');
        if (trimmed.Length == 0 || IsOnlyDots(trimmed))
        {
            return false;
        }

        provisioned = trimmed;
        return true;
    }

    // Unicode \w, which .NET resolves to letters, non-spacing marks, decimal digits and connector
    // punctuation, plus the literal members of the host's set. Non-ASCII letters and digits are therefore
    // PRESERVED rather than transliterated: they are already inside \w, so the host takes them, and
    // transliterating a name the host accepts would rename an account for no reason the host asked for.
    private static bool IsAccepted(char character) =>
        AllowedPunctuation.Contains(character, StringComparison.Ordinal)
        || CharUnicodeInfo.GetUnicodeCategory(character) is UnicodeCategory.UppercaseLetter
            or UnicodeCategory.LowercaseLetter
            or UnicodeCategory.TitlecaseLetter
            or UnicodeCategory.ModifierLetter
            or UnicodeCategory.OtherLetter
            or UnicodeCategory.NonSpacingMark
            or UnicodeCategory.DecimalDigitNumber
            or UnicodeCategory.ConnectorPunctuation;

    // "." and ".." are accepted by the host and are path traversal at the profile directory (#447); a name
    // of any other all-dots shape is equally not a name. Treated as an empty result rather than returned.
    private static bool IsOnlyDots(string candidate)
    {
        foreach (var character in candidate)
        {
            if (character != '.')
            {
                return false;
            }
        }

        return true;
    }
}
