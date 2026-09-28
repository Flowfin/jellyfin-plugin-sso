// SPDX-FileCopyrightText: The jellyfin-plugin-sso authors
// SPDX-License-Identifier: GPL-3.0-only

using System.Text.Json;

namespace Jellyfin.Plugin.SSO_Auth.Api.Oidc;

/// <summary>The one place a provider's OpenID discovery document is turned into an object graph, so one response is walked once for both facts the challenge reads (#1170).</summary>
/// <remarks>
/// It parses with System.Text.Json, the family <see cref="StrictJson"/> tokenizes the body with on its way through
/// <see cref="RepeatedMemberScreen"/>, so what the screen refuses this refuses (#1054). It returns
/// <see langword="null"/> rather than throwing for every input that is not a JSON object, and each reader decides
/// what a null root means: PKCE support fails closed, the response-<c>iss</c> flag fails tolerant so an unreadable
/// flag never locks out a provider that omits <c>iss</c>.
/// </remarks>
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
