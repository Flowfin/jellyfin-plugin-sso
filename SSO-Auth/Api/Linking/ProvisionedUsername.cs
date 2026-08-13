// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Globalization;
using System.Text;

namespace Jellyfin.Plugin.SSO_Auth.Api.Linking;

/// <summary>
/// Maps an identity-provider-supplied username to the name a brand-new Jellyfin account is created
/// under (#1137). Pure and deterministic: it makes no authorization decision, reads no configuration,
/// and never decides which account a login resolves to - resolution stays keyed on the subject
/// (OpenID <c>sub</c> / SAML <c>NameID</c>), so this is name PRESENTATION only.
/// </summary>
/// <remarks>
/// <para>
/// Jellyfin's own <c>CreateUserAsync</c> refuses a name outside <c>^(?!\s)[\w \-'._@+]+(?&lt;!\s)$</c>,
/// and the plugin cannot reference that check: it lives in the server, off the Controller/Model surface
/// the plugin compiles against, so this allowlist is a hand-copy of the one in-repo record of it (the
/// comment in <c>AvatarService.IsUsernameSafeForProfilePath</c>) and a conformance rule pins the two
/// together. Nothing can pin either against the server, which is the residual: an IdP name this class
/// narrows that the host would in fact have taken costs a cosmetic rename of a brand-new account, while
/// a name it passed that the host refused would be the host-shaped login failure this class exists to
/// remove. The allowlist is therefore deliberately the conservative direction of that trade.
/// </para>
/// <para>
/// The rejected characters are DROPPED rather than substituted. A substitution would turn a name made
/// entirely of rejected characters into an invented one (<c>!!!</c> becoming <c>___</c>), which reads as
/// a real name an administrator never chose; dropping makes that case visible as an empty result the
/// caller has to decide about. Dropping also makes the map idempotent - the output holds only accepted
/// characters and no leading or trailing space, so a second pass changes nothing.
/// </para>
/// <para>
/// The host's set admits <c>.</c>, so it admits <c>.</c> and <c>..</c> as whole names, and those escape
/// the per-user configuration directory when they reach a profile path (#447, the reason
/// <c>AvatarService.IsUsernameSafeForProfilePath</c> exists). An all-dots result is therefore treated as
/// no result rather than handed back.
/// </para>
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
