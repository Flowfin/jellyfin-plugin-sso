// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// The repeated-property-name screen for provider-supplied JSON (#1005). A repeated property name is
/// accepted by every JSON reader this plugin depends on, each of which silently keeps the LAST occurrence,
/// so one document can mean two things: the reader that indexes a name sees the last value while the reader
/// that enumerates the object sees both. Measured on both target frameworks — <c>JsonDocument</c> keeps both
/// properties and indexes the last, Newtonsoft keeps one, <c>JsonWebToken</c> and Duende's
/// <c>JsonWebKeySet</c> keep the last — so an authorization server can hand one body to two consumers that
/// disagree about it.
///
/// THREAT MODEL. The harm is a security-relevant value that the plugin ACTS ON being readable two ways: a
/// duplicated <c>issuer</c> re-points the anchor a login binds itself to, a duplicated role key decides which
/// privileges are granted. A repeat the plugin never indexes — a vendor extension, a nested
/// <c>mtls_endpoint_aliases</c>, an unwalked subtree of a role claim — carries no such value and is outside
/// this screen's job: refusing on it would take a working provider's logins offline to defend a decision
/// nobody makes. So the caller names the object scopes it reads and only those are inspected. What lies
/// outside them is left to the reader that owns it.
///
/// This is deliberately a raw <see cref="Utf8JsonReader"/> walk rather than a
/// <c>JsonSerializerOptions</c> setting. The plugin binds the HOST's System.Text.Json — .NET 9's in the
/// Jellyfin 10.11 line, .NET 10's in the 12.0 line — and the <c>Strict</c> preset with its
/// <c>AllowDuplicateProperties</c> switch exists only on the latter: referencing it fails the net9.0 build
/// with CS0117. A tokenizer carries no duplicate policy of its own, so this one code path reaches the same
/// decision on both targets, and that decision does not move when the host's System.Text.Json does.
/// </summary>
internal static class StrictJson
{
    // Matches the System.Text.Json reader default rather than raising it, so a document this walk cannot
    // reach the bottom of is one its consumers could not read either.
    private const int MaxDepth = 64;

    /// <summary>
    /// What <see cref="Inspect"/> found. Three outcomes and not a <c>bool</c>, because "this document repeats
    /// a name the caller reads" and "this document is not JSON at all" are different facts with different
    /// remedies, and a caller handed one flag for both has to treat every tokenizer failure as an attack —
    /// which turns a byte-order mark or a vendor grammar quirk into a refused login and tells the operator to
    /// hunt a duplicate that is not there.
    /// </summary>
    internal enum Verdict
    {
        /// <summary>No inspected scope names the same member twice.</summary>
        Clean,

        /// <summary>An inspected scope names the same member twice, so the document means two things.</summary>
        Repeated,

        /// <summary>The document could not be tokenized, so nothing was inspected. Not a duplicate.</summary>
        Unreadable,
    }

    /// <summary>
    /// Inspects the object scopes <paramref name="readPath"/> names for a repeated property name.
    /// </summary>
    /// <param name="json">The raw document, as received from the provider.</param>
    /// <param name="readPath">
    /// The member names leading from the root object to the deepest object the caller indexes, outermost
    /// first. The root object is always inspected; each further object is inspected only when it is the one
    /// reached by descending this path. Empty — the default — inspects the root object alone, which is what a
    /// caller reading only top-level members wants.
    /// </param>
    /// <returns>
    /// <see cref="Verdict.Repeated"/> when an inspected scope names the same member twice;
    /// <see cref="Verdict.Unreadable"/> when the document cannot be tokenized (malformed, truncated, or
    /// nested past the reader's depth cap), which the caller decides about on its own terms rather than
    /// having it collapsed into a duplicate; <see cref="Verdict.Clean"/> otherwise, including for a null,
    /// empty or whitespace input, which carries no properties to repeat. Names are compared ordinally,
    /// because JSON member names are case-sensitive and every consumer of these documents compares them
    /// ordinally too; they are compared AFTER unescaping, so a name spelled with a <c>\u</c> escape counts as
    /// the same name as its plain spelling. Never throws.
    /// </returns>
    internal static Verdict Inspect(string? json, params string[] readPath)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return Verdict.Clean;
        }

        // One entry per open object, null for a scope the caller does not read: sibling objects legitimately
        // reuse names (every JWKS key entry repeats "kty" and "kid"), and a single document-wide set would
        // refuse every real discovery document while claiming to have found an attack.
        var scopes = new Stack<HashSet<string>?>();
        string? introducedBy = null;
        try
        {
            var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(json), new JsonReaderOptions { MaxDepth = MaxDepth });
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                        scopes.Push(IsRead(scopes, introducedBy, readPath) ? new HashSet<string>(StringComparer.Ordinal) : null);
                        introducedBy = null;
                        break;

                    case JsonTokenType.EndObject:
                        scopes.Pop();
                        introducedBy = null;
                        break;

                    case JsonTokenType.PropertyName:
                        introducedBy = null;
                        if (scopes.Peek() is { } names)
                        {
                            introducedBy = reader.GetString() ?? string.Empty;
                            if (!names.Add(introducedBy))
                            {
                                return Verdict.Repeated;
                            }
                        }

                        break;

                    default:
                        // Any other token is the member's value, so the name no longer introduces anything —
                        // clearing it here is what stops an object inside an ARRAY from being mistaken for the
                        // object the path descends into.
                        introducedBy = null;
                        break;
                }
            }
        }
        catch (JsonException)
        {
            return Verdict.Unreadable;
        }

        return Verdict.Clean;
    }

    // Whether the object now being opened is one the caller reads: the root always, and a nested object only
    // when its parent is read and it is the member the path descends into at that step.
    private static bool IsRead(Stack<HashSet<string>?> scopes, string? introducedBy, string[] readPath)
    {
        if (scopes.Count == 0)
        {
            return true;
        }

        var step = scopes.Count - 1;
        return scopes.Peek() is not null
            && step < readPath.Length
            && string.Equals(introducedBy, readPath[step], StringComparison.Ordinal);
    }
}
