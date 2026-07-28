// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// The repeated-member screen for the OpenID discovery document (#1005). A repeated property name is
/// accepted by every JSON reader this plugin depends on, each of which silently keeps the LAST occurrence,
/// so one document can mean two things: the reader that indexes a name sees the last value while the reader
/// that enumerates the object sees both. Measured rather than assumed — <c>DuplicateJsonKeyPostureTests</c>
/// pins Newtonsoft, <c>JsonWebToken</c> and Duende's <c>JsonWebKeySet</c> each taking the last occurrence
/// with no error — so an authorization server can hand one body to two consumers that disagree about it.
///
/// THREAT MODEL. The harm is a security-relevant value the plugin ACTS ON being readable two ways: a
/// duplicated <c>issuer</c> re-points the anchor a login binds itself to, a duplicated <c>jwks_uri</c>
/// re-points the keys an id_token is validated against. A repeat in a member NOTHING indexes carries no such
/// value — <c>scopes_supported</c>, a vendor extension, anything nested inside a member — and refusing on it
/// would take a working provider's logins offline to defend a decision nobody makes. So the caller names the
/// members it indexes, and only a repeat of one of those is reported.
///
/// What this screen does NOT cover, stated so nothing downstream reads more into it: a repeat below the root
/// object (a nested object, an array element) is not inspected, and neither is any document read through a
/// parser this screen does not precede. The only caller today is <see cref="OidcDiscoveryReader"/>; the role
/// claim is deliberately not screened, because what an unreadable claim should mean on a privilege path is
/// an open design question and not a patch (#1053).
///
/// Deliberately a raw <see cref="Utf8JsonReader"/> walk rather than a <c>JsonSerializerOptions</c> setting.
/// The plugin binds the HOST's System.Text.Json — .NET 9's in the Jellyfin 10.11 line, .NET 10's in the 12.0
/// line — and the <c>Strict</c> preset with its <c>AllowDuplicateProperties</c> switch exists only on the
/// latter: referencing it fails the net9.0 build with CS0117. A tokenizer carries no duplicate policy of its
/// own, so this one code path reaches the same decision on both targets, and that decision does not move
/// when the host's System.Text.Json does.
/// </summary>
internal static class StrictJson
{
    // Matches the System.Text.Json reader default rather than raising it, so a document this walk cannot
    // reach the bottom of is one its consumers could not read either.
    private const int MaxDepth = 64;

    /// <summary>
    /// What <see cref="Inspect"/> found. Three outcomes and not a <c>bool</c>, because "this document repeats
    /// a member the caller indexes" and "this document is not JSON at all" are different facts with different
    /// remedies, and a caller handed one flag for both has to treat every tokenizer failure as an attack —
    /// which turns a byte-order mark or a vendor grammar quirk into a refused login and tells the operator to
    /// hunt a duplicate that is not there.
    /// </summary>
    internal enum Verdict
    {
        /// <summary>No member the caller indexes is named twice in the root object.</summary>
        Clean,

        /// <summary>A member the caller indexes is named twice, so the document means two things.</summary>
        Repeated,

        /// <summary>The document could not be tokenized, so nothing was inspected. Not a duplicate.</summary>
        Unreadable,
    }

    /// <summary>
    /// Inspects the root object for a repeat of one of the members <paramref name="readMembers"/> names.
    /// </summary>
    /// <param name="json">The raw document, as received from the provider.</param>
    /// <param name="readMembers">
    /// The root-object members the caller indexes, and the whole of that list — a repeat of anything else is
    /// admitted. Deliberately not a <c>params</c> array: a caller that names nothing screens nothing, and
    /// that has to be written down at the call site rather than reached by leaving an argument off.
    /// </param>
    /// <param name="repeatedMember">
    /// The repeated member's name when the verdict is <see cref="Verdict.Repeated"/>; otherwise null. It is
    /// always one of <paramref name="readMembers"/>, since no other name is compared, so a caller logging it
    /// is logging its own constant rather than a provider-authored string.
    /// </param>
    /// <returns>
    /// <see cref="Verdict.Repeated"/> when the root object names one of <paramref name="readMembers"/> twice;
    /// <see cref="Verdict.Unreadable"/> when the document cannot be tokenized (malformed, truncated, or
    /// nested past the reader's depth cap), which the caller decides about on its own terms rather than
    /// having it collapsed into a duplicate; <see cref="Verdict.Clean"/> otherwise, including for a null,
    /// empty or whitespace input, which carries no members to repeat. Names are compared ordinally, because
    /// JSON member names are case-sensitive and every consumer of these documents compares them ordinally
    /// too; they are compared AFTER unescaping, so a name spelled with a <c>\u</c> escape counts as the same
    /// name as its plain spelling. Never throws a <see cref="JsonException"/>.
    /// </returns>
    internal static Verdict Inspect(string? json, string[] readMembers, out string? repeatedMember)
    {
        repeatedMember = null;
        if (string.IsNullOrWhiteSpace(json))
        {
            return Verdict.Clean;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(json), new JsonReaderOptions { MaxDepth = MaxDepth });
            while (reader.Read())
            {
                // Depth 1 is a member of the root object and nothing else: a member of a nested object sits
                // deeper, a member of an object inside an array deeper still, and an array-rooted document
                // has no member at this depth at all. That is the whole scope rule — sibling objects
                // legitimately reuse names (every JWKS entry repeats `kty` and `kid`), so a screen that
                // pooled names document-wide would refuse real documents while claiming to have found an
                // attack.
                if (reader.TokenType != JsonTokenType.PropertyName || reader.CurrentDepth != 1)
                {
                    continue;
                }

                var name = reader.GetString() ?? string.Empty;
                if (Array.IndexOf(readMembers, name) >= 0 && !seen.Add(name))
                {
                    repeatedMember = name;
                    return Verdict.Repeated;
                }
            }
        }
        catch (JsonException)
        {
            return Verdict.Unreadable;
        }

        return Verdict.Clean;
    }
}
