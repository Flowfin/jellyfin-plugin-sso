// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// Decides whether a JSON document names any member twice inside one object scope (#1005). Every JSON reader
/// this plugin depends on accepts a repeated member and silently keeps the LAST occurrence, while an
/// enumerating reader sees both — measured, not assumed — so one document can mean two things depending on
/// which reader looks at it.
///
/// THREAT MODEL. This stops an authorization server, or anyone who can answer as one, from handing the
/// plugin and its identity library a single document they read differently: a repeated <c>issuer</c>
/// re-points the anchor a login binds itself to, a repeated <c>jwks_uri</c> re-points the keys an id_token is
/// validated against, and a repeated member inside a JWKS entry re-points a key. Deliberately out of scope:
/// an operator who edits the plugin's own configuration, and any document that does not reach a consumer
/// through <see cref="RepeatedMemberScreen"/> — this walk defends against a hostile provider, not against the
/// person who administers the server, and review and branch protection are what cover the latter.
///
/// Every member at every object scope is compared, rather than a caller-supplied list of the members the
/// caller happens to index. The screen sits ahead of the identity library, whose own typed mapping and key-set
/// materialisation are consumers too, and their indexed-member sets are internal to two pinned versions —
/// an allowlist would have to enumerate them and would go quietly wrong at the next bump. It is also the rule
/// .NET 10's <c>JsonSerializerOptions.Strict</c> preset already enforces, so this converges on the platform
/// posture rather than inventing one.
///
/// Deliberately a raw <see cref="Utf8JsonReader"/> walk rather than a <c>JsonSerializerOptions</c> setting.
/// The plugin binds the HOST's System.Text.Json — .NET 9's in the Jellyfin 10.11 line, .NET 10's in the 12.0
/// line — and <c>Strict</c> exists only on the latter: referencing it fails the net9.0 build with CS0117. A
/// tokenizer carries no duplicate policy of its own, so one code path reaches the same decision on both
/// targets, and that decision does not move when the host's System.Text.Json does.
/// </summary>
internal static class StrictJson
{
    // Matches the System.Text.Json reader default rather than raising it, so a document this walk cannot
    // reach the bottom of is one its consumers could not read either.
    private const int MaxDepth = 64;

    /// <summary>
    /// What <see cref="Inspect"/> found. Three outcomes and not a <c>bool</c>, because "this document names a
    /// member twice" and "this document could not be inspected" are different facts: the first is the attack
    /// this walk exists for, the second is everything from a truncated body to a hostile escape, and a caller
    /// handed one flag for both cannot report the reason it refused.
    /// </summary>
    internal enum Verdict
    {
        /// <summary>No object scope names a member twice.</summary>
        Clean,

        /// <summary>An object scope names a member twice, so the document means two things.</summary>
        Repeated,

        /// <summary>The document could not be walked to the end, so nothing was established about it.</summary>
        Unreadable,
    }

    /// <summary>
    /// Walks <paramref name="json"/> and reports whether any object scope names a member twice.
    /// </summary>
    /// <param name="json">The raw document, as received from the provider.</param>
    /// <param name="repeatedMember">
    /// The repeated member's name when the verdict is <see cref="Verdict.Repeated"/>; otherwise null. It is
    /// provider-authored, so a caller that logs it strips line endings inline at its own log call.
    /// </param>
    /// <returns>
    /// <see cref="Verdict.Repeated"/> when one object scope names a member twice;
    /// <see cref="Verdict.Unreadable"/> when the walk could not complete — malformed, truncated, nested past
    /// the depth cap, or carrying a member name the decoder refuses (an unpaired surrogate escape is the
    /// measured instance); <see cref="Verdict.Clean"/> otherwise, including for a null, empty or whitespace
    /// input, which carries no member to repeat. Names are compared ordinally, because JSON member names are
    /// case-sensitive and every consumer of these documents compares them ordinally too, and AFTER
    /// unescaping, so a name spelled with a <c>\u</c> escape counts as the same name as its plain spelling.
    /// Never throws.
    /// </returns>
    internal static Verdict Inspect(string? json, out string? repeatedMember)
    {
        repeatedMember = null;
        if (string.IsNullOrWhiteSpace(json))
        {
            return Verdict.Clean;
        }

        // One name set per open object, so sibling scopes may reuse a name — every JWKS entry repeats `kty`
        // and `kid`, so a walk pooling names document-wide would refuse real documents while reporting an
        // attack. Only a repeat within the SAME object is a document that means two things.
        var scopes = new Stack<HashSet<string>>();
        try
        {
            var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(json), new JsonReaderOptions { MaxDepth = MaxDepth });
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                        scopes.Push(new HashSet<string>(StringComparer.Ordinal));
                        break;

                    case JsonTokenType.EndObject:
                        scopes.Pop();
                        break;

                    case JsonTokenType.PropertyName:
                        var name = reader.GetString() ?? string.Empty;
                        if (!scopes.Peek().Add(name))
                        {
                            repeatedMember = name;
                            return Verdict.Repeated;
                        }

                        break;

                    default:
                        break;
                }
            }
        }
        catch (JsonException)
        {
            return Verdict.Unreadable;
        }
        catch (InvalidOperationException)
        {
            // GetString raises this — not JsonException — on a member name the decoder cannot complete, e.g.
            // an unpaired surrogate escape: thirteen bytes both parser families read without complaint. An
            // earlier revision of this walk let it escape into callers that catch only JsonException, so a
            // provider could crash the discovery path. Reported as Unreadable, which the caller refuses on,
            // so the fail-closed direction holds even if some future path reaches it for another reason.
            return Verdict.Unreadable;
        }

        return Verdict.Clean;
    }
}
