// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Text.Json;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// The one member lookup on a <see cref="JsonElement"/> object that cannot throw, which is what
/// <see cref="JsonElement.TryGetProperty(string, out JsonElement)"/> does not promise. That method unescapes
/// any candidate member name long enough to still match after unescaping, and an unpaired surrogate escape
/// has no completion, so the decoder raises <see cref="InvalidOperationException"/> and the whole lookup is
/// abandoned.
///
/// Every reader that states a total contract over provider-supplied JSON reads through here, so none of them
/// carries that throw and the padding that decides which one is hit stops being a property of the lookup
/// name's length. It was written for the two discovery flag readers (#1340) and is not about discovery: the
/// back-channel <c>logout_token</c>'s <c>events</c> member is read through it too (#1349), which is why it
/// lives in a type of its own rather than beside the discovery parse.
///
/// An undecodable name is SKIPPED and the walk CONTINUES, which is the load-bearing half rather than a
/// detail. Answering "absent" for the whole object would let one member nobody asked about decide the
/// caller's fact, and each of those facts refuses something: false on the PKCE flag refuses the login
/// wherever <c>RequirePkce</c> is on, and false on the logout event refuses a termination the identity
/// provider ordered. A document or token carrying an undecodable name BESIDE the real member would otherwise
/// take a working provider offline. This is the same reasoning <c>PkceDiscovery.IsS256</c> already applies
/// one level down, on the value side of the same decoder failure.
///
/// A name that does not decode also cannot equal the ASCII names these callers look for, so skipping it
/// loses no match: what is dropped is a candidate that could only ever have answered no.
/// </summary>
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
