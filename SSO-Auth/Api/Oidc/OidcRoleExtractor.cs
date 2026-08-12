// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// Reads the role values out of an OpenID claim according to the configured role-claim path.
/// The path is the pre-split <c>RoleClaim</c> (see the controller): its first segment names the
/// claim, and any further segments walk into the claim's JSON object to the node that holds the roles -
/// an array of role strings, or, for a provider that opts into <c>RoleClaimIsObjectMap</c> (#934), an
/// object whose property names are the roles. A one-segment path takes the claim value as the role
/// verbatim, except in object-map mode, where that value IS the object. This is pure parsing - it makes
/// no authorization decision; the caller maps the returned role strings to privileges.
/// </summary>
internal static class OidcRoleExtractor
{
    /// <summary>
    /// Why a walk produced the role set it produced (#1147). Before this existed every failure collapsed to
    /// an empty list, which an operator could not tell from a provider that legitimately sent no roles - so
    /// a mistyped path and a correct path over an empty array looked identical from outside.
    /// <para>
    /// The set is deliberately OPEN: a later reason may be added (a repeated member inside the role claim,
    /// #1053) without the existing members changing meaning. Only <see cref="Resolved"/> is not a refusal.
    /// </para>
    /// </summary>
    internal enum Outcome
    {
        /// <summary>
        /// The path resolved to the configured shape. The role set may still be EMPTY and that is not a
        /// refusal: an empty terminal array, an empty object map, and an array whose elements are all
        /// non-strings all resolved correctly and simply carry no roles.
        /// </summary>
        Resolved,

        /// <summary>The claim value did not parse as a JSON object, or parsed to null.</summary>
        ValueNotJson,

        /// <summary>An intermediate key was missing, an intermediate node was not an object, or the terminal key was absent.</summary>
        PathNotResolved,

        /// <summary>The terminal node was reached but is not the configured shape - a non-array where an array was expected, or a non-object in object-map mode.</summary>
        TerminalWrongShape,

        /// <summary>
        /// An object scope this walk enters names a member twice, so the claim value means two things and
        /// which of them decides the roles is a parser's choice rather than the document's (#1324).
        /// </summary>
        RepeatedMember,

        /// <summary>
        /// The screen could not read the claim value to the end, so nothing about it was established (#1053).
        /// Distinct from <see cref="ValueNotJson"/>, which is Newtonsoft's answer AFTER it ran: this one is
        /// returned instead of consulting it, so the two names also say which reader spoke.
        /// </summary>
        Unreadable,
    }

    /// <summary>
    /// Extracts the role values from a claim value for the given role-claim path.
    /// </summary>
    /// <param name="roleClaimSegments">
    /// The role-claim path already split on unescaped dots and un-escaped (segment[0] is the claim
    /// name). Must be non-empty; the caller only invokes this for the claim whose type equals segment[0].
    /// </param>
    /// <param name="claimValue">The matched claim's value (a raw role, or a JSON object for a nested path).</param>
    /// <param name="terminalIsObjectMap">
    /// The provider's <c>RoleClaimIsObjectMap</c>: the terminal node is a JSON object whose property NAMES
    /// are the roles (Zitadel, #934) instead of an array of role strings. Deliberately has no default so
    /// every call site has to state which shape it reads.
    /// </param>
    /// <returns>
    /// The extracted roles and why (#1147): for an array terminal, the string elements of the array reached
    /// by walking the JSON path (non-string elements are ignored); for an object-map terminal, that object's
    /// property names; and, only when the path is one segment and the terminal is not an object map, the raw
    /// claim value as a single role. Every non-resolving shape (missing segment, non-object node, wrong
    /// terminal type) and a malformed claim value carry no roles AND a refusal reason - a parse failure
    /// fails closed rather than throwing (#216). The refusal reasons exist so a caller can tell a broken
    /// path from a provider that legitimately sent no roles.
    /// <para>
    /// Two shapes carry no roles that once did, and both are #1324 rather than an accident. A claim value
    /// naming a member twice in a scope this walk enters is refused instead of resolving to whichever
    /// occurrence a parser happens to keep, and a claim value the screen cannot read to the end is refused
    /// instead of being handed to a second parser that can. Everything else returns what it always returned.
    /// </para>
    /// </returns>
    internal static Result ExtractRoles(string[] roleClaimSegments, string claimValue, bool terminalIsObjectMap)
    {
        // A single-segment path is not JSON: the claim value itself is the role. An object-map claim is the
        // exception - there the claim value IS the terminal object, so it falls through to the parse below.
        if (roleClaimSegments.Length == 1 && !terminalIsObjectMap)
        {
            return Resolved(new List<string> { claimValue });
        }

        // The screen runs BEFORE Newtonsoft, and that ordering is the substance of #1324 rather than a
        // preference. The round-2 finding on PR #1032 was not that an unreadable document produced no roles,
        // it was that it produced "proceed" and the code then fell through to a second parser, which granted
        // the attacker's last-occurrence roles. A refusal here consults no second reader, so the value's
        // meaning never becomes a question of which parser read it.
        //
        // Only the scopes this walk enters are screened. A repeat anywhere the walk does not go changes
        // nothing it reads, and refusing on one would let an unrelated sibling in the provider's own claim -
        // a vendor extension repeating a name - wipe the role set of every login (#1324).
        //
        // The repeated member's NAME is deliberately dropped. This value carries group DNs and e-mail
        // addresses, the audit trail below records the outcome's own name and never anything derived from the
        // claim, and a member name is derived from the claim.
        var screened = StrictJson.Inspect(claimValue, EnteredScopeKeys(roleClaimSegments, terminalIsObjectMap), out _);
        if (screened != StrictJson.Verdict.Clean)
        {
            return Refused(screened == StrictJson.Verdict.Repeated ? Outcome.RepeatedMember : Outcome.Unreadable);
        }

        // Everything else parses the claim value as a JSON object and walks it. The claim value is
        // attacker-influenced, so it must never throw an unhandled 500 on the public callback (#216): any
        // malformed or non-resolving shape (non-object root, non-object node, wrong terminal type) fails
        // closed to an empty role set, and an array terminal is filtered to its string elements - a mixed
        // array keeps its strings, an array with no strings yields none.
        try
        {
            var json = JsonConvert.DeserializeObject<IDictionary<string, object>>(claimValue);
            if (json is null)
            {
                return Refused(Outcome.ValueNotJson);
            }

            // A one-segment object-map path has no key to look under: the parsed claim value IS the terminal
            // object, so its property names are the roles. An empty object yields NO roles, never "any role"
            // - and it RESOLVED, so it is not a refusal.
            if (roleClaimSegments.Length == 1)
            {
                return Resolved(json.Keys.ToList());
            }

            // Walk the intermediate segments; any missing key or non-object node yields no roles.
            for (int i = 1; i < roleClaimSegments.Length - 1; i++)
            {
                var segment = roleClaimSegments[i];
                if (!json.TryGetValue(segment, out var nextToken) || nextToken is not JObject nextObject)
                {
                    return Refused(Outcome.PathNotResolved);
                }

                json = nextObject.ToObject<IDictionary<string, object>>();
                if (json is null)
                {
                    return Refused(Outcome.PathNotResolved);
                }
            }

            if (!json.TryGetValue(roleClaimSegments[^1], out var rolesToken))
            {
                return Refused(Outcome.PathNotResolved);
            }

            // The terminal must resolve to the configured shape - anything else is no roles, not a guess,
            // and it is a distinct refusal from a path that never reached a terminal at all.
            if (terminalIsObjectMap)
            {
                // Property NAMES only: the values are provider bookkeeping (Zitadel puts the granting org
                // there), and reading them, or recursing, would turn unrelated data into granted roles.
                return rolesToken is JObject rolesObject
                    ? Resolved(rolesObject.Properties().Select(property => property.Name).ToList())
                    : Refused(Outcome.TerminalWrongShape);
            }

            // Take only the array's string elements so a terminal array of objects or numbers cannot throw.
            // An array with no string elements RESOLVED and carries no roles; it is not a refusal.
            return rolesToken is JArray rolesArray
                ? Resolved(rolesArray.Where(token => token.Type == JTokenType.String).Select(token => token.Value<string>()!).ToList())
                : Refused(Outcome.TerminalWrongShape);
        }
        catch (JsonException)
        {
            return Refused(Outcome.ValueNotJson);
        }
    }

    // The object scopes the walk below opens, named for the screen, in the order it descends them. The root
    // is not listed because every reader starts there and the screen enters it by definition.
    //
    // Read off the walk rather than off the configuration's shape: the intermediates are exactly the segments
    // the loop descends, and the terminal joins them only in object-map mode, where the roles ARE that
    // object's member names. In array mode the terminal is an array, whose elements carry no names to repeat,
    // and an object among them is skipped by the string filter - so entering it would screen a scope no role
    // is ever read out of.
    private static List<string> EnteredScopeKeys(string[] roleClaimSegments, bool terminalIsObjectMap)
    {
        var keys = new List<string>();
        for (int i = 1; i < roleClaimSegments.Length - 1; i++)
        {
            keys.Add(roleClaimSegments[i]);
        }

        // A one-segment object-map path has no key: the claim value's root IS the terminal object.
        if (terminalIsObjectMap && roleClaimSegments.Length > 1)
        {
            keys.Add(roleClaimSegments[^1]);
        }

        return keys;
    }

    private static Result Resolved(List<string> roles) => new(Outcome.Resolved, roles);

    // Every refusal carries an EMPTY role set, in one place, so no future reason can be added with roles
    // attached to it by accident.
    private static Result Refused(Outcome outcome) => new(outcome, new List<string>());

    /// <summary>
    /// The classified result of a role-claim walk: the roles it produced, and why.
    /// </summary>
    /// <param name="Outcome">Whether the walk resolved, and if not, what refused it.</param>
    /// <param name="Roles">The extracted role strings; empty on every refusal, and possibly empty on a resolution.</param>
    internal readonly record struct Result(Outcome Outcome, List<string> Roles);
}
