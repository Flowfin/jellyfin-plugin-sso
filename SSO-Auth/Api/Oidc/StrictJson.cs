// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// Decides whether a JSON document names any member twice inside one object scope (#1005). A repeated member
/// is accepted silently by every reader these documents reach, none of which raises an error, so which of the
/// two values a consumer acts on is decided by parser internals rather than by anything this plugin controls.
///
/// What was MEASURED, so the claim stays the size of its evidence: on both target frameworks every reader in
/// the dependency set - System.Text.Json, Newtonsoft, <c>JsonWebToken</c>, Duende's <c>JsonWebKeySet</c> -
/// keeps the LAST occurrence when a name is indexed. They therefore agree today, and no divergence between
/// two readers of these documents has been demonstrated. What differs is indexing versus ENUMERATION:
/// <c>JsonDocument</c> indexes the last occurrence while <c>EnumerateObject</c> yields both properties, and
/// Newtonsoft drops one at parse time, so a document carrying a repeat has no single answer to "what members
/// does it have".
///
/// THREAT MODEL. This stops an authorization server, or anyone who can answer as one, from serving a document
/// whose meaning rests on that unpinned last-wins behaviour rather than on the document itself - RFC 8259
/// §4 leaves the handling of repeated names unspecified and calls such objects interoperability-unsafe, so
/// the agreement measured above is a property of the current dependency set and not a guarantee any of them
/// documents. A repeat in <c>issuer</c>, <c>jwks_uri</c>, or a JWKS entry is where that would decide a login
/// anchor or a validation key. Deliberately out of scope: an operator who edits the plugin's own
/// configuration, and any document nothing routes through this walk before parsing it - a decision function
/// stops nothing on its own, and placing it on a path is the caller's job (#1061). This walk defends against
/// a hostile provider, not against the person who administers the server, and
/// review and branch protection are what cover the latter. Also out of scope, and worth stating because the
/// two are easily conflated: this is not the control that stops a hostile <c>issuer</c> VALUE, which is
/// <c>ValidateIssuerName</c>'s job whether that value is repeated or not.
///
/// Every member at every object scope is compared, rather than a caller-supplied list of the members the
/// caller happens to index. The screen sits ahead of the identity library, whose own typed mapping and key-set
/// materialisation are consumers too, and their indexed-member sets are internal to two pinned versions -
/// an allowlist would have to enumerate them and would go quietly wrong at the next bump. It is also the rule
/// .NET 10's <c>JsonSerializerOptions.Strict</c> preset already enforces, so this converges on the platform
/// posture rather than inventing one.
///
/// Deliberately a raw <see cref="Utf8JsonReader"/> walk rather than a <c>JsonSerializerOptions</c> setting.
/// The plugin binds the HOST's System.Text.Json - .NET 9's in the Jellyfin 10.11 line, .NET 10's in the 12.0
/// line - and <c>Strict</c> exists only on the latter: referencing it fails the net9.0 build with CS0117. A
/// tokenizer carries no duplicate policy of its own, so one code path reaches the same decision on both
/// targets, and that decision does not move when the host's System.Text.Json does.
/// </summary>
internal static class StrictJson
{
    // What this cannot do, stated because a decision function invites the assumption that it protects the
    // path it decides for: it bounds nothing. It is handed a string that is already in memory and allocates
    // a UTF-8 copy of it, so a document large enough to hurt has already hurt before this runs. Bounding
    // belongs at the position that reads the bytes, which is the caller's, and #1041 owns it there.

    // Matches the System.Text.Json reader default rather than raising it, so a document this walk cannot
    // reach the bottom of is one its consumers could not read either.
    //
    // Because it EQUALS that default, no behavioural test can tell this constant from its absence: deleting
    // it and the reader options leaves every verdict identical. It is kept for what it pins against - a
    // future runtime moving its default - and that is a property no test in this repository can observe, so
    // none claims to. An earlier test asserted it was pinned "from both directions"; it was not, and the
    // claim is gone rather than reworded.
    private const int MaxDepth = 64;

    /// <summary>
    /// What <see cref="Inspect"/> found. Three outcomes and not a <c>bool</c>, because "this document names a
    /// member twice" and "this document could not be inspected" are different facts: the first is the attack
    /// this walk exists for, the second is everything from a truncated body to a hostile escape, and a caller
    /// handed one flag for both cannot report the reason it refused.
    /// </summary>
    internal enum Verdict
    {
        /// <summary>
        /// Nothing was established about the document - it could not be walked to the end, or it carries no
        /// object to walk. Deliberately the ZERO value: <c>default(Verdict)</c> is what an uninitialised
        /// field or a silently skipped assignment produces, and on a fail-closed component that default must
        /// be the refusal rather than the approval.
        /// </summary>
        Unreadable,

        /// <summary>No object scope names a member twice.</summary>
        Clean,

        /// <summary>An object scope names a member twice, so the document means two things.</summary>
        Repeated,
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
    /// <see cref="Verdict.Unreadable"/> when the walk could not complete - malformed, truncated, nested past
    /// the depth cap, carrying a member name the decoder refuses (an unpaired surrogate escape is the
    /// measured instance), carrying a char with no UTF-8 encoding at all (a RAW unpaired surrogate, refused
    /// before the walk starts), or carrying no object at all - a null, empty or whitespace body, and equally a
    /// bare scalar or a document whose root is not and contains no object. None of those establishes
    /// anything, which is what <see cref="Verdict.Unreadable"/> means, and reporting <c>Clean</c> for them
    /// would hand a caller an affirmative answer about a document nothing read.
    /// <see cref="Verdict.Clean"/> otherwise. Names are compared ordinally - a decision about this plugin's
    /// readers rather than a fact about consumers, see below - and AFTER unescaping, so a name spelled with a
    /// <c>\u</c> escape counts as the same name as its plain spelling.
    ///
    /// Ordinal is a DECISION about this plugin's readers (#1191), not a fact about JSON consumers in general,
    /// and the difference matters: a deserializer configured case-insensitively - which is what
    /// <c>JsonSerializerDefaults.Web</c> gives you - resolves <c>ISSUER</c> onto <c>Issuer</c> and keeps the
    /// last occurrence, while an indexing reader over the same bytes returns the first. Both readings are
    /// measured, on those bytes, in <c>WhatAdmittingACaseVariantPairLeavesOpen_IsMeasuredRatherThanAssumed</c>.
    ///
    /// A case-variant pair is therefore ADMITTED, and what each direction costs is this. Refusing one takes
    /// offline a provider whose document no reader on this login path misreads - every one of them indexes a
    /// name it spells itself - and because every member at every scope is compared, the pair that took the
    /// provider down need not be a member a login rests on at all; two unrelated vendor extensions differing
    /// in case would do it. Admitting one costs nothing to any reader present today and leaves one thing
    /// open: a future consumer on this path that folds case would answer differently from the indexing
    /// readers beside it, and the divergence it would inherit is written down in that same row rather than
    /// left to be rediscovered. Not established, and so not claimed: that no consumer anywhere folds case.
    ///
    /// .NET 10's <c>JsonSerializerOptions.Strict</c>, which #1043 replaces this walk with once net9.0 is
    /// dropped, takes the same decision in both directions - it refuses a member named twice and does not
    /// treat a case-variant pair as one. Measured on net10.0 in <c>TheStrictPresetTakesTheSameDecisionOnCase</c>,
    /// so the replacement inherits this posture rather than contradicting it.
    ///
    /// Never throws.
    /// </returns>
    internal static Verdict Inspect(string? json, out string? repeatedMember)
    {
        repeatedMember = null;
        if (string.IsNullOrWhiteSpace(json))
        {
            // Nothing was established about a body carrying no members, so this is Unreadable and not Clean.
            // Clean is an affirmative "no scope names a member twice", which a caller reads as approval -
            // and every reader these documents reach rejects an empty body outright, so reporting Clean would
            // make this walk disagree with its own consumers about one document, which is what it exists to
            // prevent.
            return Verdict.Unreadable;
        }

        // A UTF-8 BOM is a provider's to emit and Utf8JsonReader treats it as content, so a document that is
        // otherwise perfect reads as malformed and - since Unreadable is a refusal at every seam that
        // consumes this - locks that provider out. Stripped here rather than left to the caller: the one
        // caller that exists today happens to strip it while decoding, but that is an undocumented property
        // of a consumer this function does not have and cannot require.
        // ONE leading BOM, not a run of them: TrimStart would strip any number, and a document prefixed
        // with several is one no consumer can parse, so admitting it would be this walk disagreeing with its
        // readers in the permissive direction. A BOM that is not first - after whitespace, say - is left
        // alone and the document reads as malformed, which is the honest answer for it.
        var document = json!.StartsWith('\uFEFF') ? json.Substring(1) : json;

        // One name set per open object, so sibling scopes may reuse a name - every JWKS entry repeats `kty`
        // and `kid`, so a walk pooling names document-wide would refuse real documents while reporting an
        // attack. Only a repeat within the SAME object is a document that means two things.
        var scopes = new Stack<HashSet<string>>();
        var sawObject = false;
        try
        {
            // Throw-on-invalid rather than the default replacement fallback: replacement maps every unpaired
            // surrogate to U+FFFD, so two genuinely different member names would re-encode to the same key and
            // the walk would report a repeat in a document that has none. The throw is caught below and
            // reported as Unreadable, which is the honest answer for bytes that cannot round-trip.
            var bytes = new UTF8Encoding(false, true).GetBytes(document);
            var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = MaxDepth });
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                        sawObject = true;
                        scopes.Push(new HashSet<string>(StringComparer.Ordinal));
                        break;

                    case JsonTokenType.EndObject:
                        scopes.Pop();
                        break;

                    case JsonTokenType.PropertyName:
                        // GetString returns null only for a JSON null, which cannot be a member name, so the fallback is
                        // unreachable - but folding it to "" would make the empty name and "no name" the same
                        // key, and the empty name is a legal member a provider can repeat.
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
        catch (EncoderFallbackException)
        {
            // The document cannot be re-encoded without loss, so no verdict about its members would be about
            // the document the consumer sees.
            return Verdict.Unreadable;
        }
        catch (InvalidOperationException)
        {
            // This arm is broader than its main cause, and the breadth is deliberate rather than
            // overlooked: it also covers a stack operation on an empty stack, which would be a defect in
            // this walk rather than anything the provider did. A walk bug therefore reports as an
            // uninspectable document - the fail-closed direction, which is why the breadth is acceptable,
            // but it does mean a verdict of Unreadable is not by itself evidence about the document.
            //
            // GetString raises this - NOT JsonException - on a member name the decoder cannot complete: an
            // unpaired surrogate escape is thirteen bytes both parser families read without complaint. A
            // caller catching only JsonException would therefore take the crash, so this arm is what keeps a
            // provider from crashing the discovery path. Reported as Unreadable, which the caller refuses on.
            return Verdict.Unreadable;
        }

        // A well-formed document that contains no object at all - a bare scalar, an array of scalars - has
        // no scope in which a member could repeat, so the walk established nothing about it and says so. An
        // EMPTY object is different and stays Clean: it has a scope, and that scope genuinely repeats nothing.
        return sawObject ? Verdict.Clean : Verdict.Unreadable;
    }
}
