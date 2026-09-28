// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Text.Json;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>The one member lookup on a <see cref="JsonElement"/> object that cannot throw, which <see cref="JsonElement.TryGetProperty(string, out JsonElement)"/> does not promise (#1340, #1349).</summary>
/// <remarks>
/// That method unescapes any candidate name long enough to still match, and an unpaired surrogate escape has no
/// completion, so the decoder throws and the whole lookup is abandoned. An undecodable name is skipped and the
/// walk continues, because each caller's fact refuses something and one member nobody asked about must not take
/// a working provider offline; a name that does not decode cannot equal the ASCII names these callers look for,
/// so skipping it loses no match.
/// </remarks>
internal static class JsonMember
{
    /// <summary>
    /// Looks a member up on a JSON object without ever throwing.
    /// </summary>
    /// <param name="owner">The object to look the member up on.</param>
    /// <param name="name">The member name to find, compared ordinally against each decodable member.</param>
    /// <param name="value">The first matching member's value; <see langword="default"/> when none matches.</param>
    /// <returns><see langword="true"/> when a member of that name is present.</returns>
    internal static bool TryGet(JsonElement owner, string name, out JsonElement value)
    {
        // Walked by hand rather than delegating to TryGetProperty and catching around it: one path answers
        // for every input, so there is no second comparison that could disagree with the first about the
        // same bytes. First match wins, exactly as TryGetProperty does - a repeated member in a discovery
        // document is refused upstream by the screen (#1054) and is not this method's decision.
        foreach (var member in owner.EnumerateObject())
        {
            try
            {
                if (!member.NameEquals(name))
                {
                    continue;
                }
            }
            catch (InvalidOperationException)
            {
                // This member's name carries an escape the decoder cannot complete. It is not the name being
                // looked for; the next member still can be.
                continue;
            }

            value = member.Value;
            return true;
        }

        value = default;
        return false;
    }
}
