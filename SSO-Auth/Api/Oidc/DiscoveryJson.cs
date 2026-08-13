// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

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
}
