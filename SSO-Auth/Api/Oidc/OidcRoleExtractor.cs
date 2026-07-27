// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// Reads the role values out of an OpenID claim according to the configured role-claim path.
/// The path is the pre-split <c>RoleClaim</c> (see the controller): its first segment names the
/// claim, and any further segments walk into the claim's JSON object to the node that holds the roles —
/// an array of role strings, or, for a provider that opts into <c>RoleClaimIsObjectMap</c> (#934), an
/// object whose property names are the roles. A one-segment path takes the claim value as the role
/// verbatim, except in object-map mode, where that value IS the object. This is pure parsing — it makes
/// no authorization decision; the caller maps the returned role strings to privileges.
/// </summary>
internal static class OidcRoleExtractor
{
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
    /// The extracted roles: for an array terminal, the string elements of the array reached by walking the
    /// JSON path (non-string elements are ignored); for an object-map terminal, that object's property
    /// names; and, only when the path is one segment and the terminal is not an object map, the raw claim
    /// value as a single role. Returns an empty list when the path does not resolve to the expected shape
    /// (missing segment, non-object node, wrong terminal type), when the claim value is malformed
    /// JSON — a parse failure fails closed to no roles rather than throwing (#216) — and when one of the
    /// objects this walk indexes names the same member twice, which makes the claim mean two things (#1005).
    /// </returns>
    internal static List<string> ExtractRoles(string[] roleClaimSegments, string claimValue, bool terminalIsObjectMap)
    {
        // A single-segment path is not JSON: the claim value itself is the role. An object-map claim is the
        // exception — there the claim value IS the terminal object, so it falls through to the parse below.
        if (roleClaimSegments.Length == 1 && !terminalIsObjectMap)
        {
            return new List<string> { claimValue };
        }

        // Everything else parses the claim value as a JSON object and walks it. The claim value is
        // attacker-influenced, so it must never throw an unhandled 500 on the public callback (#216): any
        // malformed or non-resolving shape (non-object root, non-object node, wrong terminal type) fails
        // closed to an empty role set, and an array terminal is filtered to its string elements — a mixed
        // array keeps its strings, an array with no strings yields none.
        try
        {
            // This claim decides which privileges the login is granted, and the parser below resolves a
            // repeated property name to its LAST occurrence without complaint, so a claim naming the key this
            // walk indexes twice grants whatever the second one says while anything reading the first sees
            // something else (#1005). No role set is derivable from such a claim, so it yields none — the
            // same closed outcome as a malformed value, and never "any role".
            //
            // Only a repeat refuses. A value this screen cannot tokenize is NOT one: the parser below accepts
            // grammars System.Text.Json rejects outright — comments, single quotes, a trailing comma, NaN —
            // and discarding every role of a provider that emits one of them would be an outage wearing a
            // guard's clothes. Such a value falls through to the parse, which fails closed on its own if it
            // is genuinely malformed. The call sits inside this try so the #216 never-throw guarantee covers
            // the screen too, not merely the parse it precedes.
            if (StrictJson.Inspect(claimValue, IndexedScopes(roleClaimSegments)) == StrictJson.Verdict.Repeated)
            {
                return new List<string>();
            }

            var json = JsonConvert.DeserializeObject<IDictionary<string, object>>(claimValue);
            if (json is null)
            {
                return new List<string>();
            }

            // A one-segment object-map path has no key to look under: the parsed claim value IS the terminal
            // object, so its property names are the roles. An empty object yields NO roles, never "any role".
            if (roleClaimSegments.Length == 1)
            {
                return json.Keys.ToList();
            }

            // Walk the intermediate segments; any missing key or non-object node yields no roles.
            for (int i = 1; i < roleClaimSegments.Length - 1; i++)
            {
                var segment = roleClaimSegments[i];
                if (!json.TryGetValue(segment, out var nextToken) || nextToken is not JObject nextObject)
                {
                    return new List<string>();
                }

                json = nextObject.ToObject<IDictionary<string, object>>();
                if (json is null)
                {
                    return new List<string>();
                }
            }

            if (!json.TryGetValue(roleClaimSegments[^1], out var rolesToken))
            {
                return new List<string>();
            }

            // The terminal must resolve to the configured shape — anything else is no roles, not a guess.
            if (terminalIsObjectMap)
            {
                // Property NAMES only: the values are provider bookkeeping (Zitadel puts the granting org
                // there), and reading them, or recursing, would turn unrelated data into granted roles.
                return rolesToken is JObject rolesObject
                    ? rolesObject.Properties().Select(property => property.Name).ToList()
                    : new List<string>();
            }

            // Take only the array's string elements so a terminal array of objects or numbers cannot throw.
            return rolesToken is JArray rolesArray
                ? rolesArray.Where(token => token.Type == JTokenType.String).Select(token => token.Value<string>()!).ToList()
                : new List<string>();
        }
        catch (JsonException)
        {
            return new List<string>();
        }
    }

    // The objects the walk above descends into, outermost first — the intermediate segments only. The claim
    // value IS the object segment[0] named, so segment[0] never appears here, and the terminal segment names
    // a member of the last object rather than a further object to enter. Everything else in the claim is a
    // subtree this walk never opens, and a repeat there decides nothing.
    private static string[] IndexedScopes(string[] roleClaimSegments) =>
        roleClaimSegments.Length > 2 ? roleClaimSegments[1..^1] : Array.Empty<string>();
}
