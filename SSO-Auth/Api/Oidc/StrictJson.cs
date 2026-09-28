// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>Decides whether a JSON document names any member twice inside one object scope (#1005), so a provider document's meaning never rests on which occurrence a parser happens to keep.</summary>
/// <remarks>
/// Every reader in the dependency set keeps the last occurrence today, and RFC 8259 §4 calls such objects
/// interoperability-unsafe, so that agreement is a property of the pinned versions and not a guarantee. Every
/// member is compared rather than a caller-supplied allowlist, because the library's indexed-member sets are
/// internal to it; which scopes are compared is the caller's to narrow (#1324). It stays a raw
/// <see cref="Utf8JsonReader"/> walk rather than the .NET 10 <c>JsonSerializerOptions.Strict</c> preset, which has no BOM strip, cannot
/// narrow to scopes, signals by throwing and admits an objectless document (#1043). Out of scope: the operator who
/// edits the configuration, and a hostile issuer value, which is <c>ValidateIssuerName</c>'s job (#1061).
/// </remarks>
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
    /// What <see cref="Inspect(string?, out string?)"/> found. Three outcomes and not a <c>bool</c>, because "this document names a
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

    /// <summary>Walks <paramref name="json"/> and reports whether any object scope names a member twice; never throws.</summary>
    /// <remarks>
    /// Names are compared ordinally and after unescaping, so an escaped spelling counts as its plain one. Ordinal is a
    /// decision about this plugin's readers, all of which index a name they spell themselves, so a case-variant pair
    /// is admitted and what that leaves open is written in the test row that measures it (#1191). An invalid escape
    /// establishes no name, so the walk reports <see cref="Verdict.Unreadable"/> rather than accusing the provider of a repeat it did not write (#1197).
    /// </remarks>
    /// <param name="json">The raw document, as received from the provider.</param>
    /// <param name="repeatedMember">The repeated member's name when the verdict is <see cref="Verdict.Repeated"/>, otherwise null; it is provider-authored, so a caller that logs it strips line endings inline at its own log call.</param>
    /// <returns><see cref="Verdict.Repeated"/> when one object scope names a member twice; <see cref="Verdict.Unreadable"/> when the walk could not complete or the document holds no object at all, because reporting Clean for them would hand a caller an affirmative answer about a document nothing read; <see cref="Verdict.Clean"/> otherwise.</returns>
    internal static Verdict Inspect(string? json, out string? repeatedMember) =>
        Inspect(json, null, out repeatedMember);

    /// <summary>Walks <paramref name="json"/> and reports whether a member is named twice in an object scope the caller's reader actually enters (#1324).</summary>
    /// <remarks>Naming scopes rather than members is the whole of the narrowing: inside a scope the reader enters, which members it indexes is not a thing this walk can know, but where the reader goes the caller states. A repeat in a sibling the reader never opens is admitted, because refusing it would let an unrelated vendor extension take a login offline.</remarks>
    /// <param name="json">The raw document, as received from the provider.</param>
    /// <param name="enteredScopeKeys">The member names the caller's reader descends through, in order, from the root object, which is entered by definition; null means every scope is entered, the discovery posture.</param>
    /// <param name="repeatedMember">The repeated member's name when the verdict is <see cref="Verdict.Repeated"/>, otherwise null; it is provider-authored, so a caller that logs it strips line endings inline at its own log call.</param>
    /// <returns>The same three verdicts over a narrower set of scopes; <see cref="Verdict.Unreadable"/> is not narrowed and stays a fact about the whole document, because bytes the walk cannot finish leave it unable to say where the scopes are.</returns>
    internal static Verdict Inspect(string? json, IReadOnlyList<string>? enteredScopeKeys, out string? repeatedMember)
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
        //
        // Arrays are pushed too, and carry no name set. They hold no members of their own, and an object
        // inside one was not reached by naming a member, so an array frame ends the descent through it -
        // otherwise the objects in an on-path array would each inherit that key's position.
        var scopes = new Stack<Scope>();
        var sawObject = false;
        string? memberName = null;
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
                        scopes.Push(Open(scopes, memberName, enteredScopeKeys));
                        break;

                    case JsonTokenType.StartArray:
                        scopes.Push(default);
                        break;

                    case JsonTokenType.EndObject:
                    case JsonTokenType.EndArray:
                        scopes.Pop();
                        break;

                    case JsonTokenType.PropertyName:
                        // GetString returns null only for a JSON null, which cannot be a member name, so the fallback is
                        // unreachable - but folding it to "" would make the empty name and "no name" the same
                        // key, and the empty name is a legal member a provider can repeat.
                        //
                        // It is read on EVERY property, entered scope or not, and that is what keeps Unreadable a
                        // fact about the document: a name the decoder cannot complete raises here rather than
                        // being skipped because nobody indexes it.
                        var name = reader.GetString() ?? string.Empty;
                        var scope = scopes.Peek();
                        if (scope.Names is not null && !scope.Names.Add(name))
                        {
                            repeatedMember = name;
                            return Verdict.Repeated;
                        }

                        // Only ever consulted by the StartObject one token later. A stale value cannot admit a
                        // scope: the sole frame that reads it is an object whose parent is an entered OBJECT,
                        // and an object in that position is always immediately preceded by its own name.
                        memberName = name;
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

    // Decides whether the object now opening is one the caller's reader enters, and how far along the key
    // chain it sits. The root is entered whatever the caller named, because that is where any reading starts;
    // below it, an object is entered only when its own member name is the next key the parent still owes, so
    // the chain is followed in order rather than matched anywhere it happens to appear.
    private static Scope Open(Stack<Scope> scopes, string? memberName, IReadOnlyList<string>? enteredScopeKeys)
    {
        if (enteredScopeKeys is null || scopes.Count == 0)
        {
            return new Scope(0, new HashSet<string>(StringComparer.Ordinal));
        }

        var parent = scopes.Peek();
        var entered = parent.Names is not null
            && parent.Descended < enteredScopeKeys.Count
            && string.Equals(memberName, enteredScopeKeys[parent.Descended], StringComparison.Ordinal);

        return entered ? new Scope(parent.Descended + 1, new HashSet<string>(StringComparer.Ordinal)) : default;
    }

    /// <summary>
    /// One open object or array. A frame with no name set is one whose members are not compared - an array,
    /// which has none, or an object the caller's reader never opens - and <c>default</c> is deliberately that
    /// frame, so a frame pushed without a decision compares nothing rather than everything.
    /// </summary>
    /// <param name="Descended">How many of the caller's keys the chain down to this frame has consumed.</param>
    /// <param name="Names">The names seen in this scope, or null when this scope is not compared.</param>
    private readonly record struct Scope(int Descended, HashSet<string>? Names);
}
