// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System;
using System.Text.Json;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>
/// The one place a provider's OpenID discovery document is turned into an object graph. Both security facts
/// the challenge reads - PKCE-S256 (#141) and the RFC 9207 response-<c>iss</c> parameter (#210) - are read
/// out of the root this returns, so one discovery response is walked once for both instead of once per fact
/// (#1170).
///
/// It parses with System.Text.Json, the same family <see cref="StrictJson"/> tokenizes the body with on its
/// way through <see cref="RepeatedMemberScreen"/> (#1054). Before that it was Newtonsoft, which put a second
/// parser family behind the screen: the screen and the reader could be made to disagree about the same bytes,
/// and every such disagreement is a document one of them admits and the other does not. The disagreement was
/// fail-closed in both directions and so was never a bypass, but a screen whose verdict does not bind the
/// reader it screens for is a guard that has to be argued about rather than one that holds by construction.
/// Same family, same grammar, same escape handling: what the screen refuses, this refuses.
///
/// Returns <see langword="null"/> rather than throwing for every input that is not a JSON object: a null,
/// empty or blank body, any document the reader refuses, and a well-formed document whose root is an array or
/// a scalar. Each reader decides for itself what a null root means, and the two answers differ on purpose -
/// PKCE support fails CLOSED, the response-<c>iss</c> flag fails TOLERANT so an unreadable flag never locks
/// out a provider that omits <c>iss</c>.
/// </summary>
internal static class DiscoveryJson
{
    /// <summary>
    /// Parses a discovery document into its root object.
    /// </summary>
    /// <param name="discoveryJson">The raw OpenID discovery document JSON.</param>
    /// <returns>
    /// The parsed document, whose root is an object, or <see langword="null"/> when the document is absent,
    /// blank, malformed, or rooted at anything but an object. The caller owns the returned document and
    /// disposes it; its <see cref="JsonDocument.RootElement"/> is only readable until it does.
    /// </returns>
    internal static JsonDocument? TryParse(string? discoveryJson)
    {
        if (string.IsNullOrWhiteSpace(discoveryJson))
        {
            return null;
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(discoveryJson);
        }
        catch (JsonException)
        {
            return null;
        }

        if (document.RootElement.ValueKind == JsonValueKind.Object)
        {
            return document;
        }

        // A well-formed array or scalar is not a discovery document, and the readers below index a root by
        // member name. Disposed here rather than handed back, so "not an object" and "did not parse" are one
        // answer to the caller and neither leaks a document nobody closes.
        document.Dispose();
        return null;
    }

    /// <summary>
    /// Looks a member up on a discovery root without ever throwing, which is what
    /// <see cref="JsonElement.TryGetProperty(string, out JsonElement)"/> does not promise. That method
    /// unescapes any candidate member name long enough to still match after unescaping, and an unpaired
    /// surrogate escape has no completion, so the decoder raises <see cref="InvalidOperationException"/>
    /// and the whole lookup is abandoned (#1340). Both discovery facts are read through here so neither
    /// reader carries the throw, and the padding that selects which one is hit stops being a property of
    /// the lookup name's length.
    ///
    /// An undecodable name is SKIPPED and the walk CONTINUES, which is the load-bearing half rather than a
    /// detail. Answering "absent" for the whole document would let one member nobody asked about decide the
    /// PKCE fact, and false there refuses the login wherever <c>RequirePkce</c> is on - so a document
    /// carrying both an undecodable name and a real <c>code_challenge_methods_supported</c> would take an
    /// otherwise-working provider offline. This is the same reasoning <c>PkceDiscovery.IsS256</c> already
    /// applies one level down, on the value side of the same decoder failure.
    ///
    /// A name that does not decode also cannot equal the ASCII name being looked for, so skipping it loses
    /// no match: what is dropped is a candidate that could only ever have answered no.
    /// </summary>
    /// <param name="root">The discovery document's root object.</param>
    /// <param name="name">The member name to find, compared ordinally against each decodable member.</param>
    /// <param name="value">The first matching member's value; <see langword="default"/> when none matches.</param>
    /// <returns><see langword="true"/> when a member of that name is present.</returns>
    internal static bool TryGetMember(JsonElement root, string name, out JsonElement value)
    {
        // Walked by hand rather than delegating to TryGetProperty and catching around it: one path answers
        // for every document, so there is no second comparison that could disagree with the first about the
        // same bytes. First match wins, exactly as TryGetProperty does - repeated members are refused
        // upstream by the screen (#1054) and are not this method's decision.
        foreach (var member in root.EnumerateObject())
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
